package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// forwarder serves one upstream's local listener.
type forwarder struct {
	up      Upstream
	pool    *pool
	m       *upstreamMetrics
	timeout time.Duration
	ka      time.Duration
	retries int
}

// dialTarget tries up to retries+1 distinct targets.
func (f *forwarder) dialTarget(ctx context.Context, network string) (net.Conn, Target, error) {
	var tried []Target
	var lastErr error
	for attempt := 0; attempt <= f.retries; attempt++ {
		t, ok := f.pool.pick(f.up.Balance, tried)
		if !ok {
			break
		}
		if attempt > 0 {
			f.m.retries.Add(1)
		}
		tried = append(tried, t)
		d := net.Dialer{Timeout: f.timeout, KeepAlive: f.ka}
		if f.ka == 0 {
			d.KeepAlive = -1
		}
		c, err := d.DialContext(ctx, network, t.String())
		if err == nil {
			f.m.lastTarget.Store(t.String())
			return c, t, nil
		}
		f.m.connectFails.Add(1)
		logf("upstream %s: connect to %s failed: %v", f.up.Name, t, err)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no healthy target")
	}
	return nil, Target{}, lastErr
}

func (f *forwarder) serveTCP(ctx context.Context, ln net.Listener) {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("upstream %s: accept: %v", f.up.Name, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); f.handleTCP(ctx, c.(*net.TCPConn)) }()
	}
}

// overLimit reports whether max_conns is reached (and counts the refusal).
func (f *forwarder) overLimit() bool {
	if f.up.MaxConns > 0 && f.m.active.Load() >= int64(f.up.MaxConns) {
		f.m.limitRejects.Add(1)
		return true
	}
	return false
}

func (f *forwarder) handleTCP(ctx context.Context, client *net.TCPConn) {
	defer client.Close()
	if f.overLimit() {
		if ok, _ := limitLog.allow(f.up.Name, time.Now()); ok {
			logf("upstream %s: refusing client %s: max_conns %d reached", f.up.Name, client.RemoteAddr(), f.up.MaxConns)
		}
		return
	}
	if f.ka > 0 {
		client.SetKeepAlive(true)
		client.SetKeepAlivePeriod(f.ka)
	}
	sc, t, err := f.dialTarget(ctx, "tcp")
	if err != nil {
		f.m.noTarget.Add(1)
		logf("upstream %s: refusing client %s: %v", f.up.Name, client.RemoteAddr(), err)
		return
	}
	server := sc.(*net.TCPConn)
	defer server.Close()
	var once sync.Once
	closeBoth := func() { once.Do(func() { client.Close(); server.Close() }) }
	fc := f.pool.acquire(t, closeBoth)
	defer f.pool.release(fc)
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{}, 2)
	pipe := func(dst, src *net.TCPConn, ctr *atomic.Int64) {
		n, _ := io.Copy(countWriter{dst, ctr}, src)
		_ = n
		dst.CloseWrite()
		done <- struct{}{}
	}
	go pipe(server, client, &f.m.bytesUp)
	go pipe(client, server, &f.m.bytesDown)
	<-done
	<-done
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// UDP: one connected socket per client address (a session), replies relayed back through
// the listener. Sessions end after udp_idle without traffic or when drained.
type udpSession struct {
	conn net.Conn
	fc   *fconn
	last atomic.Int64 // unix nanos
}

func (f *forwarder) serveUDP(ctx context.Context, ln *net.UDPConn) {
	var mu sync.Mutex
	sessions := map[netip.AddrPort]*udpSession{}
	end := func(k netip.AddrPort, s *udpSession) {
		mu.Lock()
		if sessions[k] == s {
			delete(sessions, k)
			f.m.udpSessions.Add(-1)
		}
		mu.Unlock()
		s.conn.Close()
		f.pool.release(s.fc)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		tick := time.NewTicker(f.up.UDPIdle / 4)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, s := range sessions {
					s.conn.Close()
				}
				mu.Unlock()
				return
			case <-tick.C:
			}
			cut := time.Now().Add(-f.up.UDPIdle).UnixNano()
			mu.Lock()
			var idle []netip.AddrPort
			for k, s := range sessions {
				if s.last.Load() < cut {
					idle = append(idle, k)
				}
			}
			mu.Unlock()
			for _, k := range idle {
				mu.Lock()
				s := sessions[k]
				mu.Unlock()
				if s != nil {
					s.conn.Close() // reader goroutine ends the session
				}
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, client, err := ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		mu.Lock()
		s := sessions[client]
		mu.Unlock()
		if s == nil {
			if f.overLimit() {
				continue
			}
			c, t, err := f.dialTarget(ctx, "udp")
			if err != nil {
				f.m.noTarget.Add(1)
				continue
			}
			s = &udpSession{conn: c}
			s.fc = f.pool.acquire(t, func() { c.Close() })
			s.last.Store(time.Now().UnixNano())
			mu.Lock()
			sessions[client] = s
			mu.Unlock()
			f.m.udpSessions.Add(1)
			go func(k netip.AddrPort, s *udpSession) {
				defer end(k, s)
				rb := make([]byte, 65535)
				for {
					n, err := s.conn.Read(rb)
					if err != nil {
						return
					}
					s.last.Store(time.Now().UnixNano())
					if _, err := ln.WriteToUDPAddrPort(rb[:n], k); err == nil {
						f.m.bytesDown.Add(int64(n))
					}
				}
			}(client, s)
		}
		s.last.Store(time.Now().UnixNano())
		if _, err := s.conn.Write(buf[:n]); err == nil {
			f.m.bytesUp.Add(int64(n))
		}
	}
}

var limitLog = newNameLimiter(time.Minute, 256)
