package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Minimal DNS responder (RFC 1035 wire format, stdlib only). Names of declared upstreams
// (optionally followed by one of dns_suffixes) get their loopback bind IP: A (TTL 5 s), SRV
// pointing at the same name and the bind port, empty NOERROR for other types (no AAAA).
// Everything else is passed to dns_upstream unchanged (dns_default = passthrough, the
// standalone mode) or answered NXDOMAIN (dns_default = nxdomain).
type dnsServer struct {
	names    map[string]Upstream // lower-case FQDN without trailing dot
	upstream []netip.Addr
	nxdomain bool
	m        *NetpushMetrics
	timeout  time.Duration
	port     uint16 // upstream DNS port (53; tests override)
	od       *onDemand
}

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTypeSRV  = 33
	dnsClassIN  = 1
)

func newDNSServer(c NetpushConfig, m *NetpushMetrics) *dnsServer {
	d := &dnsServer{names: map[string]Upstream{}, upstream: c.DNSUpstreams, nxdomain: c.DNSDefault == "nxdomain", m: m, timeout: 3 * time.Second, port: 53}
	for _, u := range c.Upstreams {
		d.names[u.Name] = u
		for _, s := range c.DNSSuffixes {
			d.names[u.Name+"."+s] = u
		}
	}
	return d
}

type dnsQuestion struct {
	name        string // lower case, no trailing dot
	qtype       uint16
	qclass      uint16
	end         int // offset after the question
	rawQuestion []byte
}

var errDNSFormat = errors.New("dns: bad message")

func parseDNSQuery(msg []byte) (dnsQuestion, error) {
	var q dnsQuestion
	if len(msg) < 12 || msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return q, errDNSFormat
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return q, errDNSFormat
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || off+l > len(msg) || l > 63 {
			return q, errDNSFormat
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}
	if off+4 > len(msg) {
		return q, errDNSFormat
	}
	q.name = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(msg[off:])
	q.qclass = binary.BigEndian.Uint16(msg[off+2:])
	q.end = off + 4
	q.rawQuestion = msg[12:q.end]
	return q, nil
}

// reply builds a response with the query's ID, RD bit and question.
func dnsReply(query []byte, q dnsQuestion, rcode byte, answers [][]byte, additional [][]byte) []byte {
	out := make([]byte, 12, 512)
	copy(out[0:2], query[0:2])
	out[2] = 0x84 | (query[2] & 0x01) // QR, AA, RD copied
	out[3] = 0x80 | rcode             // RA
	binary.BigEndian.PutUint16(out[4:], 1)
	binary.BigEndian.PutUint16(out[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(out[10:], uint16(len(additional)))
	out = append(out, q.rawQuestion...)
	for _, a := range answers {
		out = append(out, a...)
	}
	for _, a := range additional {
		out = append(out, a...)
	}
	return out
}

func encodeName(n string) []byte {
	var b []byte
	for _, l := range strings.Split(n, ".") {
		if l != "" {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

func rr(name []byte, typ uint16, ttl uint32, rdata []byte) []byte {
	b := append([]byte{}, name...)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// answer returns the response, or nil to pass the query through.
func (d *dnsServer) answer(msg []byte) ([]byte, string) {
	q, err := parseDNSQuery(msg)
	if err != nil {
		if len(msg) >= 12 {
			out := make([]byte, 12)
			copy(out, msg[:2])
			out[2], out[3] = 0x80, 1 // FORMERR
			return out, "refused"
		}
		return nil, ""
	}
	u, ok := d.names[q.name]
	if !ok && d.od != nil && q.qclass == dnsClassIN {
		if svc := d.od.serviceName(q.name); svc != "" {
			return d.answerOnDemand(msg, q, svc)
		}
	}
	if !ok || q.qclass != dnsClassIN {
		if d.nxdomain || len(d.upstream) == 0 {
			if !d.nxdomain {
				return dnsReply(msg, q, 2, nil, nil), "servfail" // passthrough wanted but no upstream
			}
			if ok, suppressed := nxLog.allow(q.name, time.Now()); ok {
				if suppressed > 0 {
					logf("dns: NXDOMAIN %s (type %d; %d more for this name in the last minute)", q.name, q.qtype, suppressed)
				} else {
					logf("dns: NXDOMAIN %s (type %d)", q.name, q.qtype)
				}
			}
			return dnsReply(msg, q, 3, nil, nil), "nxdomain"
		}
		return nil, "passthrough"
	}
	name := []byte{0xC0, 12} // pointer to the question name
	ip := u.Bind.Addr().As4()
	switch q.qtype {
	case dnsTypeA:
		return dnsReply(msg, q, 0, [][]byte{rr(name, dnsTypeA, 5, ip[:])}, nil), "upstream"
	case dnsTypeSRV:
		srv := binary.BigEndian.AppendUint16(nil, 0)
		srv = binary.BigEndian.AppendUint16(srv, 0)
		srv = binary.BigEndian.AppendUint16(srv, u.Bind.Port())
		srv = append(srv, encodeName(q.name)...)
		return dnsReply(msg, q, 0, [][]byte{rr(name, dnsTypeSRV, 5, srv)}, [][]byte{rr(encodeName(q.name), dnsTypeA, 5, ip[:])}), "upstream"
	default:
		return dnsReply(msg, q, 0, nil, nil), "upstream_nodata"
	}
}

func (d *dnsServer) forward(ctx context.Context, msg []byte, tcp bool) ([]byte, error) {
	var lastErr error
	for _, a := range d.upstream {
		addr := netip.AddrPortFrom(a, d.port).String()
		r, err := dnsExchange(ctx, addr, msg, tcp, d.timeout)
		if err == nil {
			return r, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dnsExchange(ctx context.Context, addr string, msg []byte, tcp bool, timeout time.Duration) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if tcp {
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		r := make([]byte, binary.BigEndian.Uint16(l[:]))
		_, err := io.ReadFull(c, r)
		return r, err
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	r := make([]byte, 65535)
	for {
		n, err := c.Read(r)
		if err != nil {
			return nil, err
		}
		if n >= 2 && r[0] == msg[0] && r[1] == msg[1] {
			return r[:n], nil
		}
	}
}

func (d *dnsServer) handle(ctx context.Context, msg []byte, tcp bool) []byte {
	r, kind := d.answer(msg)
	if r == nil && kind == "passthrough" {
		var err error
		if r, err = d.forward(ctx, msg, tcp); err != nil {
			logf("dns: upstream: %v", err)
			q, _ := parseDNSQuery(msg)
			r, kind = dnsReply(msg, q, 2, nil, nil), "servfail"
		}
	}
	if kind != "" {
		d.m.DNS(kind)
	}
	if !tcp && len(r) > 512 && kind != "passthrough" {
		r[2] |= 0x02 // TC; upstream answers are relayed as received
	}
	return r
}

func (d *dnsServer) serveUDP(ctx context.Context, pc net.PacketConn) {
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		msg := append([]byte{}, buf[:n]...)
		go func() {
			if r := d.handle(ctx, msg, false); r != nil {
				pc.WriteTo(r, from)
			}
		}()
	}
}

func (d *dnsServer) serveTCP(ctx context.Context, ln net.Listener) {
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				r := d.handle(ctx, msg, true)
				if r == nil {
					return
				}
				if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...)); err != nil {
					return
				}
			}
		}()
	}
}

// nameLimiter allows one log line per name per interval and counts what it suppressed.
// The map is capped; when full, names not yet seen are only counted (summary line).
type nameLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	max      int
	last     map[string]time.Time
	count    map[string]uint64
	overflow uint64
	overLog  time.Time
}

var nxLog = newNameLimiter(time.Minute, 1024)

func newNameLimiter(interval time.Duration, max int) *nameLimiter {
	return &nameLimiter{interval: interval, max: max, last: map[string]time.Time{}, count: map[string]uint64{}}
}

func (l *nameLimiter) allow(name string, now time.Time) (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[name]; ok {
		if now.Sub(t) < l.interval {
			l.count[name]++
			return false, 0
		}
		n := l.count[name]
		l.last[name], l.count[name] = now, 0
		return true, n
	}
	if len(l.last) >= l.max {
		for k, t := range l.last { // drop expired entries
			if now.Sub(t) >= l.interval {
				delete(l.last, k)
				delete(l.count, k)
			}
		}
	}
	if len(l.last) >= l.max {
		l.overflow++
		if now.Sub(l.overLog) >= l.interval {
			logf("dns: NXDOMAIN log limiter full (%d names); %d more NXDOMAIN answers not logged", l.max, l.overflow)
			l.overflow, l.overLog = 0, now
		}
		return false, 0
	}
	l.last[name] = now
	return true, 0
}
