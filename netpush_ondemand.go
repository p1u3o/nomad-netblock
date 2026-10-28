package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// On-demand mode (ondemand = true): a DNS lookup of a service that is not a declared
// upstream gets the next free IP of ondemand_pool, kept for the life of the alloc. netblock
// redirects traffic to the pool (any port) to netpush's on-demand listener, which reads the
// original destination IP and forwards to the service's current instances on their own
// ports. The service is added to netblock's allow sets before the DNS answer goes out.

// odEntry is one assigned service.
type odEntry struct {
	name string
	ip   netip.Addr
	fwd  *forwarder
}

type odCall struct {
	done   chan struct{}
	ip     netip.Addr
	reason string
}

type onDemand struct {
	c     NetpushConfig
	m     *NetpushMetrics
	ctx   context.Context
	start func(func()) // runs a goroutine that ends with ctx

	// source returns the upstream and its discovery for a service name.
	source func(name string) (Upstream, discoverFunc, error)
	// allow asks netblock to add the service to its allow sets (nil = no netblock, tests).
	allow func(ctx context.Context, u Upstream) error

	mu       sync.Mutex
	byName   map[string]*odEntry
	byIP     map[netip.Addr]*odEntry
	inflight map[string]*odCall
	next     netip.Addr
	max      int
}

var odLookupTimeout = 15 * time.Second

func newOnDemand(ctx context.Context, c NetpushConfig, m *NetpushMetrics, d netpushDeps, start func(func())) *onDemand {
	o := &onDemand{c: c, m: m, ctx: ctx, start: start, byName: map[string]*odEntry{}, byIP: map[netip.Addr]*odEntry{}, inflight: map[string]*odCall{}}
	o.next = c.OnDemandPool.Masked().Addr().Next()
	o.max = min(c.OnDemandMax, poolHosts(c.OnDemandPool))
	m.setOnDemand(o.max, func() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.byName) })
	o.source = func(name string) (Upstream, discoverFunc, error) {
		u := Upstream{Name: name, Protocol: "tcp", Balance: BalanceLeastConn, OnlyPassing: true, UDPIdle: c.OnDemandUDPIdle, MaxConns: c.OnDemandMaxConns}
		if c.OnDemandSource == "nomad" {
			u.Nomad = &NomadRef{Name: name, Namespace: c.OnDemandNomadNS}
		} else {
			u.Consul = &ServiceRef{Name: name}
		}
		fn, err := discoverer(u, d)
		return u, fn, err
	}
	return o
}

// poolHosts is the number of usable addresses (network and broadcast left out).
func poolHosts(p netip.Prefix) int {
	bits := 32 - p.Bits()
	if bits >= 16 {
		return 65534
	}
	return 1<<bits - 2
}

// serviceName maps a query name to an on-demand service name ("" = not on-demand): a bare
// label, or a label followed by one of dns_suffixes.
func (o *onDemand) serviceName(q string) string {
	for _, s := range o.c.DNSSuffixes {
		if t, ok := strings.CutSuffix(q, "."+s); ok {
			q = t
			break
		}
	}
	if validDNSName(q) {
		return q
	}
	return ""
}

// resolve returns the service's IP, or the refusal reason: pattern and unknown are
// answered NXDOMAIN, pool_full and error SERVFAIL.
func (o *onDemand) resolve(name string) (netip.Addr, string) {
	ip, reason := o.resolve1(name)
	if reason != "" {
		o.m.OnDemandRefused(reason)
	}
	return ip, reason
}

func (o *onDemand) resolve1(name string) (netip.Addr, string) {
	if !matchAny(o.c.OnDemandAllow, name) {
		return netip.Addr{}, "pattern"
	}
	o.mu.Lock()
	if e := o.byName[name]; e != nil {
		o.mu.Unlock()
		return e.ip, ""
	}
	if call := o.inflight[name]; call != nil {
		o.mu.Unlock()
		<-call.done
		return call.ip, call.reason
	}
	if len(o.byName)+len(o.inflight) >= o.max {
		o.mu.Unlock()
		logf("ondemand: %s refused: pool full (%d services)", name, o.max)
		return netip.Addr{}, "pool_full"
	}
	call := &odCall{done: make(chan struct{})}
	o.inflight[name] = call
	o.mu.Unlock()
	call.ip, call.reason = o.create(name)
	o.mu.Lock()
	delete(o.inflight, name)
	o.mu.Unlock()
	close(call.done)
	return call.ip, call.reason
}

func (o *onDemand) create(name string) (netip.Addr, string) {
	u, fn, err := o.source(name)
	if err != nil {
		logf("ondemand: %s: %v", name, err)
		return netip.Addr{}, "error"
	}
	ctx, cancel := context.WithTimeout(o.ctx, odLookupTimeout)
	defer cancel()
	ts, _, err := fn(ctx, 0, time.Second)
	if err != nil {
		logf("ondemand: %s: discovery %s: %v", name, u.SourceString(), err)
		return netip.Addr{}, "error"
	}
	ts = dedupe(ts)
	if len(ts) == 0 {
		logf("ondemand: %s: no healthy instances in %s (NXDOMAIN)", name, u.SourceString())
		return netip.Addr{}, "unknown"
	}
	if o.allow != nil {
		if err := o.allow(ctx, u); err != nil {
			logf("ondemand: %s: netblock allow failed: %v", name, err)
			return netip.Addr{}, "error"
		}
	}
	m := o.m.Upstream(name, "ondemand")
	p := newPool(name, o.c.DrainTimeout, m)
	p.update(ts)
	f := &forwarder{up: u, pool: p, m: m, timeout: o.c.ConnectTimeout, ka: o.c.KeepAlive, retries: o.c.ConnectRetries}
	o.mu.Lock()
	e := &odEntry{name: name, ip: o.next, fwd: f}
	o.next = o.next.Next()
	o.byName[name], o.byIP[e.ip] = e, e
	o.mu.Unlock()
	logf("ondemand: %s -> %s (%s: %s)", name, e.ip, u.SourceString(), targetsDesc(ts))
	o.start(func() { watchUpstream(o.ctx, u, fn, p, m) })
	return e.ip, ""
}

func (o *onDemand) lookupIP(ip netip.Addr) *odEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.byIP[ip]
}

// replay re-sends every assigned service to netblock (after watch restarted: its on-demand
// sources are gone; the IPs here stay).
func (o *onDemand) replay() {
	if o.allow == nil {
		return
	}
	o.mu.Lock()
	var es []*odEntry
	for _, e := range o.byName {
		es = append(es, e)
	}
	o.mu.Unlock()
	for _, e := range es {
		ctx, cancel := context.WithTimeout(o.ctx, odLookupTimeout)
		if err := o.allow(ctx, e.fwd.up); err != nil {
			logf("ondemand: re-adding %s to netblock failed: %v", e.name, err)
		}
		cancel()
	}
	if len(es) > 0 {
		logf("ondemand: re-added %d services to netblock", len(es))
	}
}

// allowLine is the peer request for u.
func allowLine(u Upstream) string {
	if u.Nomad != nil {
		return "allow nomad " + strings.TrimPrefix(u.Nomad.String(), "nomad:")
	}
	return "allow consul " + u.Consul.String()
}

// answerOnDemand answers a query for an on-demand name.
func (d *dnsServer) answerOnDemand(msg []byte, q dnsQuestion, svc string) ([]byte, string) {
	ip, reason := d.od.resolve(svc)
	switch reason {
	case "":
	case "pattern", "unknown":
		if ok, _ := nxLog.allow(q.name, time.Now()); ok {
			logf("dns: NXDOMAIN %s (on-demand: %s)", q.name, reason)
		}
		return dnsReply(msg, q, 3, nil, nil), "nxdomain"
	default:
		return dnsReply(msg, q, 2, nil, nil), "servfail"
	}
	if q.qtype != dnsTypeA {
		return dnsReply(msg, q, 0, nil, nil), "ondemand_nodata"
	}
	a := ip.As4()
	return dnsReply(msg, q, 0, [][]byte{rr([]byte{0xC0, 12}, dnsTypeA, 5, a[:])}, nil), "ondemand"
}

func (o *onDemand) String() string {
	return fmt.Sprintf("pool=%s max=%d source=%s listen=127.0.0.1:%d", o.c.OnDemandPool, o.max, o.c.OnDemandSource, o.c.OnDemandPort)
}
