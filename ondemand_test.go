package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnDemandNetblockConfig(t *testing.T) {
	c, err := parse(t, `
netpush_socket = /alloc/netblock.sock
netpush_uid = 65533
consul_addr = 10.0.0.1:8501
ondemand_pool = 127.0.3.0/24
ondemand_allow = mx-*, smtp
ondemand_max = 8
dns_redirect = 53
egress_lockdown = netpush
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.OnDemandPool.String() != "127.0.3.0/24" || c.OnDemandPort != 15001 || c.OnDemandMax != 8 || c.DNSRedirect != 53 || !c.EgressLockdown {
		t.Fatalf("%+v", c)
	}
	if !matchAny(c.OnDemandAllow, "mx-a") || matchAny(c.OnDemandAllow, "db") || !matchAny(nil, "x") {
		t.Fatal("patterns")
	}
	for _, bad := range []string{
		"allow_cidrs = tcp 1.2.3.4\ndns_redirect = 53\n",                       // needs netpush_uid
		"allow_cidrs = tcp 1.2.3.4\negress_lockdown = netpush\n",               // needs netpush_uid
		"allow_cidrs = tcp 1.2.3.4\nondemand_pool = 127.0.3.0/24\n",            // needs netpush_socket
		"netpush_socket = /s\nnetpush_uid = 1\nondemand_pool = 127.0.0.0/24\n", // contains 127.0.0.1
		"netpush_socket = /s\nnetpush_uid = 1\nondemand_pool = 10.0.0.0/24\n",  // not loopback
		"netpush_socket = /s\nnetpush_uid = 1\nondemand_pool = 127.0.3.0/24\nondemand_allow = [\n",
	} {
		if _, err := parse(t, bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

func TestOnDemandRuleset(t *testing.T) {
	c, _ := parse(t, "allow_cidrs = tcp 10.1.0.0/16 443\nnetpush_socket = /s\nnetpush_uid = 65533\nondemand_pool = 127.0.3.0/24\ndns_redirect = 5353\negress_lockdown = netpush\n")
	// Not registered yet (auto): lockdown rules are left out, nothing but loopback gets out.
	rs := RenderRuleset(c, nil, Exempt{})
	if strings.Contains(rs, "@svc4 counter") || strings.Contains(rs, "10.1.0.0/16") || strings.Contains(rs, "10.0.0.53") || !strings.Contains(rs, "waiting for the netpush task") {
		t.Fatalf("lockdown not closed before netpush registered:\n%s", rs)
	}
	// Registered by cgroup: cgroup of the peer fd plus the uid on every lockdown rule.
	cg := Exempt{Kind: ExemptCgroup, CgroupPath: "/", Peer: &PeerExempt{ID: 7, UID: 65533}}
	rs = RenderRuleset(c, nil, cg)
	pm := `socket cgroupv2 level 0 "../../../proc/self/fd/3" meta skuid 65533 `
	for _, want := range []string{"meta l4proto { tcp, udp } ip daddr . th dport @svc4", "ip daddr 10.1.0.0/16 tcp dport 443 counter accept", "ip daddr { 10.0.0.53 }"} {
		if !strings.Contains(rs, pm+want) {
			t.Errorf("cgroup lockdown: missing %q in\n%s", pm+want, rs)
		}
	}
	if lockdownUIDOnly(c, cg) {
		t.Error("cgroup lockdown reported as uid only")
	}
	// uid fallback (peer registered by uid).
	uf := Exempt{Kind: ExemptUID, UID: 65532, Peer: &PeerExempt{ByUID: true, UID: 65533}}
	rs = RenderRuleset(c, nil, uf)
	if !lockdownUIDOnly(c, uf) {
		t.Error("uid fallback not reported")
	}
	for _, want := range []string{
		"type nat hook output priority -100",
		"ip daddr 127.0.3.0/24 meta l4proto tcp counter name \"ondemand_tcp\" redirect to :15001",
		"meta skuid != 65533 ip daddr != 127.0.0.0/8 meta l4proto { tcp, udp } th dport 53 counter name \"dns_redirect\" redirect to :5353",
		"ct status dnat ip daddr 127.0.0.1 meta l4proto { tcp, udp } th dport 5353 accept",
		"type filter hook prerouting priority mangle",
		"iif \"lo\" ip daddr 127.0.3.0/24 meta l4proto udp counter name \"ondemand_udp\" tproxy ip to 127.0.0.1:15001",
		"meta skuid 65533 meta l4proto { tcp, udp } ip daddr . th dport @svc4",
		"meta skuid 65533 ip daddr 10.1.0.0/16 tcp dport 443 counter accept",
		"meta skuid 65533 ip daddr { 10.0.0.53 }",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in\n%s", want, rs)
		}
	}
	c.OnDemandPool, c.DNSRedirect, c.EgressLockdown = netip.Prefix{}, 0, false
	rs = RenderRuleset(c, nil, Exempt{})
	if strings.Contains(rs, "nat") || strings.Contains(rs, "tproxy") || strings.Contains(rs, "skuid 65533 ip daddr 10.1") {
		t.Fatalf("on-demand rules without the options:\n%s", rs)
	}
}

func TestOnDemandNetpushConfig(t *testing.T) {
	c, err := parseNP(t, `
consul_addrs = 10.0.0.10:8501
netblock_exempt_socket = /alloc/netblock.sock
dns_listen = 127.0.0.1:53
ondemand = true
ondemand_allow = mx-*
ondemand_max = 10
ondemand_max_conns = 100
upstream = db source=consul:db port=3306 max_conns=5
`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.OnDemand || c.OnDemandMax != 10 || c.OnDemandPool.String() != "127.0.3.0/24" || c.OnDemandMaxConns != 100 || c.Upstreams[0].MaxConns != 5 {
		t.Fatalf("%+v", c)
	}
	if _, err := parseNP(t, "consul_addrs = 10.0.0.10:8501\nnetblock_exempt_socket = /s\ndns_listen = 127.0.0.1:53\nondemand = true\n"); err != nil {
		t.Fatalf("on-demand without upstreams: %v", err)
	}
	c, err = parseNP(t, "nomad_addr = http://x\nnetblock_exempt_socket = /s\ndns_listen = 127.0.0.1:53\nondemand = true\nondemand_source = nomad@apps\n")
	if err != nil || c.OnDemandSource != "nomad" || c.OnDemandNomadNS != "apps" {
		t.Fatalf("nomad source: %v %+v", err, c)
	}
	for _, bad := range []string{
		"consul_addrs = 10.0.0.10:8501\ndns_listen = 127.0.0.1:53\nondemand = true\n",                                                       // no netblock
		"consul_addrs = 10.0.0.10:8501\nnetblock_exempt_socket = /s\nondemand = true\n",                                                     // no dns
		"netblock_exempt_socket = /s\ndns_listen = 127.0.0.1:53\nondemand = true\n",                                                         // consul source, no consul
		"consul_addrs = 1.2.3.4:1\nnetblock_exempt_socket = /s\ndns_listen = 127.0.0.1:53\nondemand = true\nondemand_pool = 127.0.1.0/25\n", // overlaps bind_pool
		"consul_addrs = 1.2.3.4:1\nnetblock_exempt_socket = /s\ndns_listen = 127.0.0.1:53\nondemand = true\nondemand_source = dns\n",
		"consul_addrs = 1.2.3.4:1\nupstream = db source=consul:db port=1 max_conns=-1\n",
	} {
		if _, err := parseNP(t, bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

// fakeOD is an onDemand with a scripted source.
type fakeOD struct {
	*onDemand
	mu      sync.Mutex
	targets map[string][]Target
	fail    map[string]error
	calls   atomic.Int32
	allowed []string
}

func newFakeOD(t *testing.T, max int, allow ...string) *fakeOD {
	c := defaultNetpushConfig()
	c.OnDemand, c.OnDemandMax, c.OnDemandAllow = true, max, allow
	c.DNSSuffixes = []string{"service.consul"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fakeOD{targets: map[string][]Target{}, fail: map[string]error{}}
	f.onDemand = newOnDemand(ctx, c, NewNetpushMetrics(), netpushDeps{}, func(fn func()) { go fn() })
	f.source = func(name string) (Upstream, discoverFunc, error) {
		u := Upstream{Name: name, Consul: &ServiceRef{Name: name}, UDPIdle: time.Minute}
		return u, func(ctx context.Context, idx uint64, _ time.Duration) ([]Target, uint64, error) {
			f.calls.Add(1)
			if idx > 0 {
				<-ctx.Done()
				return nil, 0, ctx.Err()
			}
			time.Sleep(20 * time.Millisecond)
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.targets[name], 1, f.fail[name]
		}, nil
	}
	f.allow = func(_ context.Context, u Upstream) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.allowed = append(f.allowed, allowLine(u))
		return nil
	}
	return f
}

func TestOnDemandResolve(t *testing.T) {
	f := newFakeOD(t, 2, "mx-*")
	f.targets["mx-a"] = []Target{tg("10.0.0.1:2525")}
	f.targets["mx-b"] = []Target{tg("10.0.0.2:2525")}
	f.targets["mx-c"] = []Target{tg("10.0.0.3:2525")}
	f.fail["mx-err"] = errors.New("boom")

	// Concurrent lookups of one name share one discovery and get one IP.
	var wg sync.WaitGroup
	ips := make([]netip.Addr, 8)
	for i := range ips {
		wg.Add(1)
		go func(i int) { defer wg.Done(); ips[i], _ = f.resolve("mx-a") }(i)
	}
	wg.Wait()
	for _, ip := range ips {
		if ip != netip.MustParseAddr("127.0.3.1") {
			t.Fatalf("ips %v", ips)
		}
	}
	if n := f.calls.Load(); n > 2 { // one lookup + the watch's first query
		t.Fatalf("%d discovery calls", n)
	}
	if ip, r := f.resolve("mx-a"); r != "" || ip.String() != "127.0.3.1" {
		t.Fatal("not stable")
	}
	if _, r := f.resolve("db"); r != "pattern" {
		t.Fatalf("pattern: %q", r)
	}
	if _, r := f.resolve("mx-none"); r != "unknown" {
		t.Fatalf("unknown: %q", r)
	}
	if _, r := f.resolve("mx-err"); r != "error" {
		t.Fatalf("error: %q", r)
	}
	if ip, r := f.resolve("mx-b"); r != "" || ip.String() != "127.0.3.2" {
		t.Fatalf("mx-b %v %q", ip, r)
	}
	if _, r := f.resolve("mx-c"); r != "pool_full" {
		t.Fatalf("pool_full: %q", r)
	}
	if e := f.lookupIP(netip.MustParseAddr("127.0.3.2")); e == nil || e.name != "mx-b" {
		t.Fatal("lookupIP")
	}
	if strings.Join(f.allowed, ",") != "allow consul mx-a,allow consul mx-b" {
		t.Fatalf("allowed %v", f.allowed)
	}
	f.allowed = nil
	f.replay()
	if len(f.allowed) != 2 {
		t.Fatalf("replay %v", f.allowed)
	}
	var b strings.Builder
	f.m.Write(&b)
	for _, want := range []string{"netpush_ondemand_pool_size 2", "netpush_ondemand_pool_used 2", `netpush_ondemand_refused_total{reason="pattern"} 1`, `netpush_ondemand_refused_total{reason="pool_full"} 1`, `netpush_targets{upstream="mx-a",protocol="ondemand"} 1`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestOnDemandAllowFailureIsServfail(t *testing.T) {
	f := newFakeOD(t, 4)
	f.targets["mx-a"] = []Target{tg("10.0.0.1:2525")}
	f.allow = func(context.Context, Upstream) error { return errors.New("watch down") }
	if _, r := f.resolve("mx-a"); r != "error" {
		t.Fatalf("got %q", r)
	}
	if f.lookupIP(netip.MustParseAddr("127.0.3.1")) != nil {
		t.Fatal("address assigned although netblock refused")
	}
}

func TestOnDemandDNS(t *testing.T) {
	f := newFakeOD(t, 4, "mx-*")
	f.targets["mx-a"] = []Target{tg("10.0.0.1:2525")}
	c := defaultNetpushConfig()
	c.Upstreams = []Upstream{{Name: "db", Bind: netip.MustParseAddrPort("127.0.1.1:3306")}}
	c.DNSSuffixes = []string{"service.consul"}
	d := newDNSServer(c, f.m)
	d.od = f.onDemand
	d.upstream = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if r, kind := d.answer(dnsQuery("db", dnsTypeA)); kind != "upstream" || string(r[len(r)-4:]) != string([]byte{127, 0, 1, 1}) {
		t.Fatal("declared upstream must win")
	}
	r, kind := d.answer(dnsQuery("mx-a.service.consul", dnsTypeA))
	if kind != "ondemand" || string(r[len(r)-4:]) != string([]byte{127, 0, 3, 1}) || binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Fatalf("%s % x", kind, r)
	}
	if _, kind := d.answer(dnsQuery("mx-a", dnsTypeAAAA)); kind != "ondemand_nodata" {
		t.Fatal(kind)
	}
	if r, kind := d.answer(dnsQuery("web", dnsTypeA)); kind != "nxdomain" || r[3]&0xF != 3 {
		t.Fatal("pattern refusal must be NXDOMAIN")
	}
	if _, kind := d.answer(dnsQuery("www.example.com", dnsTypeA)); kind != "passthrough" {
		t.Fatal("dotted names pass through")
	}
}

func TestOnDemandSourcesWatchSide(t *testing.T) {
	c, _ := parse(t, "allow_services = db\nconsul_addr = 10.0.0.1:8501\nnetpush_socket = /s\nnetpush_uid = 1\nondemand_pool = 127.0.3.0/24\nondemand_allow = mx-*\nondemand_max = 1\n")
	o := &onDemandSources{c: c, cc: &ConsulClient{}, have: map[string]bool{"db": true}, pending: map[string][]chan error{}}
	req := func(kind, name string) (odRequest, bool, error) {
		r := odRequest{kind: kind, name: name, reply: make(chan error, 1)}
		_, isNew, err := o.add(r)
		return r, isNew, err
	}
	if _, _, err := req("consul", "db"); err == nil {
		t.Fatal("db does not match ondemand_allow")
	}
	r1, isNew, err := req("consul", "mx-a")
	if err != nil || !isNew {
		t.Fatal(err)
	}
	if _, isNew, err := req("consul", "mx-a"); err != nil || isNew {
		t.Fatal("duplicate must join, not add")
	}
	if _, _, err := req("consul", "mx-b"); err == nil || !strings.Contains(err.Error(), "ondemand_max") {
		t.Fatalf("max: %v", err)
	}
	if _, _, err := req("consul", "mx-a@dc2"); err == nil {
		t.Fatal("dc not allowed")
	}
	if _, _, err := req("dns", "mx-a"); err == nil {
		t.Fatal("bad kind")
	}
	o.answer(map[string]bool{}, nil)
	select {
	case <-r1.reply:
		t.Fatal("answered before the service reported")
	default:
	}
	o.answer(map[string]bool{"mx-a": true}, nil)
	if err := <-r1.reply; err != nil {
		t.Fatal(err)
	}
}

func TestMaxConns(t *testing.T) {
	m := &upstreamMetrics{}
	f := &forwarder{up: Upstream{Name: "x", MaxConns: 2}, m: m}
	m.active.Store(1)
	if f.overLimit() {
		t.Fatal("under limit")
	}
	m.active.Store(2)
	if !f.overLimit() || m.limitRejects.Load() != 1 {
		t.Fatal("at limit")
	}
	f.up.MaxConns = 0
	if f.overLimit() {
		t.Fatal("0 = unlimited")
	}
}

func TestListenDNSPortZero(t *testing.T) {
	for i := 0; i < 50; i++ {
		pc, tl, err := listenDNS("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if pc.LocalAddr().String() != tl.Addr().String() {
			t.Fatal("ports differ")
		}
		pc.Close()
		tl.Close()
	}
}
