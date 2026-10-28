//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const soOriginalDst = 80 // SO_ORIGINAL_DST, linux/netfilter_ipv4.h

// tcpOrigDst is the address the client connected to before netblock's REDIRECT.
func tcpOrigDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var out netip.AddrPort
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		// struct sockaddr_in fits the 16 bytes of ipv6_mreq; family, port (big endian), addr.
		m, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
		if err != nil {
			gerr = err
			return
		}
		b := m.Multiaddr
		out = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), uint16(b[2])<<8|uint16(b[3]))
	}); err != nil {
		return out, err
	}
	return out, gerr
}

// origDstFn is replaced in tests that connect without the nft redirect.
var origDstFn = tcpOrigDst

func (o *onDemand) serveTCP(ctx context.Context, ln *net.TCPListener) {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("ondemand: accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst, err := origDstFn(c)
			var e *odEntry
			if err == nil {
				e = o.lookupIP(dst.Addr())
			}
			if e == nil {
				o.m.OnDemandRefused("unassigned")
				if ok, _ := limitLog.allow("ondemand-unassigned", time.Now()); ok {
					logf("ondemand: refusing %s -> %s: no service assigned to that address (%v)", c.RemoteAddr(), dst, err)
				}
				c.Close()
				return
			}
			e.fwd.handleTCP(ctx, c)
		}()
	}
}

// UDP. netblock's TPROXY rule hands datagrams for the pool to the listener without changing
// the destination; IP_RECVORIGDSTADDR tells us which on-demand IP the client used. Replies
// must come from that IP, so each session gets its own socket bound to it and connected to
// the client. Later datagrams from the client go to that socket by normal lookup (TPROXY
// only takes transparent sockets, so it lets them through unchanged).
type odUDPSession struct {
	reply *net.UDPConn // bound to the on-demand IP:port, connected to the client
	up    net.Conn     // to the target
	fc    *fconn
	e     *odEntry
	last  atomic.Int64
}

// getUDPListener asks netblock watch for the transparent socket (it needs CAP_NET_ADMIN).
func (o *onDemand) getUDPListener(ctx context.Context, link *netblockLink) *net.UDPConn {
	for ctx.Err() == nil {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		line, f, err := link.request(rctx, "udp-tproxy")
		cancel()
		if err == nil && (line != "fd" || f == nil) {
			err = errors.New("unexpected answer " + line)
		}
		if err == nil {
			pc, cerr := net.FilePacketConn(f)
			f.Close()
			if cerr == nil {
				return pc.(*net.UDPConn)
			}
			err = cerr
		}
		if ok, _ := limitLog.allow("ondemand-udp-listener", time.Now()); ok {
			logf("ondemand: no UDP listener from netblock watch: %v (retrying)", err)
		}
		sleepCtx(ctx, 5*time.Second)
	}
	return nil
}

func (o *onDemand) serveUDP(ctx context.Context, ln *net.UDPConn) {
	type key struct{ src, dst netip.AddrPort }
	var mu sync.Mutex
	sessions := map[key]*odUDPSession{}
	end := func(k key, s *odUDPSession) {
		mu.Lock()
		if sessions[k] == s {
			delete(sessions, k)
			s.e.fwd.m.udpSessions.Add(-1)
		}
		mu.Unlock()
		s.reply.Close()
		s.up.Close()
		s.e.fwd.pool.release(s.fc)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, s := range sessions {
					s.up.Close()
					s.reply.Close()
				}
				mu.Unlock()
				return
			case <-tick.C:
			}
			now := time.Now().UnixNano()
			mu.Lock()
			for _, s := range sessions {
				if now-s.last.Load() > int64(s.e.fwd.up.UDPIdle) {
					s.up.Close() // its reader ends the session
				}
			}
			mu.Unlock()
		}
	}()
	buf, oob := make([]byte, 65535), make([]byte, 128)
	for {
		n, oobn, _, src, err := ln.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dst, ok := origDstFromOOB(oob[:oobn])
		if !ok {
			continue
		}
		k := key{src, dst}
		mu.Lock()
		s := sessions[k]
		mu.Unlock()
		if s == nil {
			e := o.lookupIP(dst.Addr())
			if e == nil {
				o.m.OnDemandRefused("unassigned")
				continue
			}
			f := e.fwd
			if f.overLimit() {
				continue
			}
			reply, err := udpReplySocket(dst, src)
			if err != nil {
				logf("ondemand: %s: UDP reply socket %s -> %s: %v", e.name, dst, src, err)
				continue
			}
			up, t, err := f.dialTarget(ctx, "udp")
			if err != nil {
				f.m.noTarget.Add(1)
				reply.Close()
				continue
			}
			s = &odUDPSession{reply: reply, up: up, e: e}
			s.fc = f.pool.acquire(t, func() { up.Close() })
			s.last.Store(time.Now().UnixNano())
			mu.Lock()
			sessions[k] = s
			mu.Unlock()
			f.m.udpSessions.Add(1)
			go func() { // target -> client
				defer end(k, s)
				rb := make([]byte, 65535)
				for {
					n, err := s.up.Read(rb)
					if err != nil {
						return
					}
					s.last.Store(time.Now().UnixNano())
					if _, err := s.reply.Write(rb[:n]); err == nil {
						f.m.bytesDown.Add(int64(n))
					}
				}
			}()
			go func() { // later client datagrams arrive on the reply socket
				rb := make([]byte, 65535)
				for {
					n, err := s.reply.Read(rb)
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return
						}
						if ctx.Err() != nil {
							return
						}
						continue // ECONNREFUSED from an ICMP error: keep the session
					}
					s.last.Store(time.Now().UnixNano())
					if _, err := s.up.Write(rb[:n]); err == nil {
						f.m.bytesUp.Add(int64(n))
					}
				}
			}()
		}
		s.last.Store(time.Now().UnixNano())
		if _, err := s.up.Write(buf[:n]); err == nil {
			s.e.fwd.m.bytesUp.Add(int64(n))
		}
	}
}

// origDstFromOOB reads IP_ORIGDSTADDR.
func origDstFromOOB(oob []byte) (netip.AddrPort, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.SOL_IP && m.Header.Type == syscall.IP_ORIGDSTADDR && len(m.Data) >= syscall.SizeofSockaddrInet4 {
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&sa.Port))
			return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(p[0])<<8|uint16(p[1])), true
		}
	}
	return netip.AddrPort{}, false
}

// udpReplySocket is bound to local (an on-demand IP; loopback, so no capability needed) and
// connected to the client.
func udpReplySocket(local, client netip.AddrPort) (*net.UDPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: int(local.Port()), Addr: local.Addr().As4()}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: int(client.Port()), Addr: client.Addr().As4()}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ondemand-reply")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}
