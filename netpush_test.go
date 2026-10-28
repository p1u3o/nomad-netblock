package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers --------------------------------------------------------------

// tcpEcho answers each line with "<id>:<line>".
func tcpEcho(t *testing.T, id string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s := bufio.NewScanner(c)
				for s.Scan() {
					fmt.Fprintf(c, "%s:%s\n", id, s.Text())
				}
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func udpEcho(t *testing.T, id string) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo([]byte(id+":"+string(b[:n])), a)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// fakeConsul serves /v1/health/service/<name> with blocking queries.
type fakeConsul struct {
	mu    sync.Mutex
	index uint64
	svcs  map[string][]netip.AddrPort
	crit  map[netip.AddrPort]bool
	ch    chan struct{}
	ts    *httptest.Server
	token string
}

func newFakeConsul(t *testing.T) *fakeConsul {
	f := &fakeConsul{index: 10, svcs: map[string][]netip.AddrPort{}, crit: map[netip.AddrPort]bool{}, ch: make(chan struct{})}
	f.ts = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeConsul) set(svc string, ts ...netip.AddrPort) {
	f.mu.Lock()
	f.svcs[svc] = ts
	f.index++
	close(f.ch)
	f.ch = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeConsul) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.token = r.Header.Get("X-Consul-Token")
	idx, ch := f.index, f.ch
	f.mu.Unlock()
	if want, _ := strconv.ParseUint(r.URL.Query().Get("index"), 10, 64); want >= idx {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
			return
		}
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/health/service/")
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, ap := range f.svcs[name] {
		st := "passing"
		if f.crit[ap] {
			st = "critical"
		}
		out = append(out, map[string]any{
			"Node":    map[string]any{"Node": "n1", "Address": ap.Addr().String()},
			"Service": map[string]any{"Service": name, "Address": ap.Addr().String(), "Port": ap.Port()},
			"Checks":  []map[string]any{{"Status": st}},
		})
	}
	w.Header().Set("X-Consul-Index", strconv.FormatUint(f.index, 10))
	json.NewEncoder(w).Encode(out)
}

func (f *fakeConsul) client() *ConsulClient {
	return newConsulClient([]string{f.ts.URL}, "", f.ts.Client().Transport)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type lineConn struct {
	net.Conn
	r *bufio.Reader
}

func dialLine(t *testing.T, a net.Addr) *lineConn {
	t.Helper()
	c, err := net.Dial("tcp", a.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &lineConn{c, bufio.NewReader(c)}
}

func (l *lineConn) say(s string) (string, error) {
	l.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintln(l, s); err != nil {
		return "", err
	}
	r, err := l.r.ReadString('\n')
	return strings.TrimSpace(r), err
}

func metricsText(rt *netpushRuntime) string {
	var b strings.Builder
	rt.metrics.Write(&b)
	return b.String()
}

func dnsQuery(name string, qtype uint16) []byte {
	m := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	m = append(m, encodeName(name)...)
	m = binary.BigEndian.AppendUint16(m, qtype)
	return binary.BigEndian.AppendUint16(m, 1)
}

// --- integration ------------------------------------------------------------

func TestNetpushIntegration(t *testing.T) {
	logName = "netpush-test"
	tA, tB := tcpEcho(t, "A"), tcpEcho(t, "B")
	uA, uB := udpEcho(t, "A"), udpEcho(t, "B")
	fc := newFakeConsul(t)
	fc.set("web", tA)
	fc.set("dnsd", uA)

	// Fake resolver for passthrough: answers every query with an empty NOERROR + marker ID.
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := up.ReadFrom(b)
			if err != nil {
				return
			}
			r := append([]byte{}, b[:n]...)
			r[2] |= 0x80
			r[3] = 0x80 | 3 // NXDOMAIN from the "real" resolver
			up.WriteTo(r, a)
		}
	}()
	dnsTestPort = uint16(up.LocalAddr().(*net.UDPAddr).Port)
	defer func() { dnsTestPort = 0 }()

	lo := netip.MustParseAddr("127.0.0.1")
	cfg := defaultNetpushConfig()
	cfg.DrainTimeout = 400 * time.Millisecond
	cfg.ConnectTimeout = time.Second
	cfg.MetricsAddr = "127.0.0.1:0"
	cfg.DNSListen = "127.0.0.1:0"
	cfg.DNSUpstreams = []netip.Addr{lo}
	cfg.DNSSuffixes = []string{"service.consul"}
	cfg.Upstreams = []Upstream{
		{Name: "web", Consul: &ServiceRef{Name: "web"}, Bind: netip.AddrPortFrom(lo, 0), Protocol: "tcp", Balance: BalanceLeastConn, OnlyPassing: true},
		{Name: "dnsd", Consul: &ServiceRef{Name: "dnsd"}, Bind: netip.AddrPortFrom(lo, 0), Protocol: "udp", Balance: BalanceLeastConn, OnlyPassing: true, UDPIdle: 5 * time.Second},
	}
	ctx, cancel := context.WithCancel(context.Background())
	rt, err := startNetpush(ctx, cfg, netpushDeps{consul: fc.client()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); rt.Wait() }()
	eventually(t, "discovery", func() bool { return rt.pools["web"].ready() && rt.pools["dnsd"].ready() })

	// TCP forward.
	old := dialLine(t, rt.listenAddrs["web"])
	if r, err := old.say("hi"); err != nil || r != "A:hi" {
		t.Fatalf("tcp via netpush: %q %v", r, err)
	}
	// UDP forward.
	ou, err := net.Dial("udp", rt.listenAddrs["dnsd"].String())
	if err != nil {
		t.Fatal(err)
	}
	defer ou.Close()
	udpSay := func(c net.Conn, s string) string {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte(s))
		b := make([]byte, 100)
		n, err := c.Read(b)
		if err != nil {
			return "err:" + err.Error()
		}
		return string(b[:n])
	}
	if r := udpSay(ou, "ping"); r != "A:ping" {
		t.Fatalf("udp via netpush: %q", r)
	}

	// Target change: A -> B.
	fc.set("web", tB)
	fc.set("dnsd", uB)
	eventually(t, "targets switched", func() bool {
		s := rt.pools["web"].snapshot()
		u := rt.pools["dnsd"].snapshot()
		return len(s) == 1 && s[0].Port == tB.Port() && len(u) == 1 && u[0].Port == uB.Port()
	})
	// Existing connection still talks to A while draining.
	if r, err := old.say("still"); err != nil || r != "A:still" {
		t.Fatalf("draining conn: %q %v", r, err)
	}
	if r := udpSay(ou, "still"); r != "A:still" {
		t.Fatalf("draining udp session: %q", r)
	}
	// New connections go to B.
	nc := dialLine(t, rt.listenAddrs["web"])
	if r, err := nc.say("new"); err != nil || r != "B:new" {
		t.Fatalf("new conn: %q %v", r, err)
	}
	nu, _ := net.Dial("udp", rt.listenAddrs["dnsd"].String())
	defer nu.Close()
	if r := udpSay(nu, "new"); r != "B:new" {
		t.Fatalf("new udp session: %q", r)
	}
	if m := metricsText(rt); !strings.Contains(m, `netpush_connections_draining{upstream="web",protocol="tcp"} 1`) {
		t.Fatalf("draining gauge missing:\n%s", m)
	}
	// After drain_timeout the old TCP connection is closed; the new one is not.
	time.Sleep(600 * time.Millisecond)
	old.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := old.r.ReadString('\n'); err != io.EOF && !isClosedErr(err) {
		t.Fatalf("old conn after drain: want EOF/reset, got %v", err)
	}
	if r, err := nc.say("again"); err != nil || r != "B:again" {
		t.Fatalf("new conn after drain: %q %v", r, err)
	}
	// Old UDP session was closed; the same client now gets a fresh session to B.
	if r := udpSay(ou, "after"); r != "B:after" {
		t.Fatalf("udp after drain: %q", r)
	}
	m := metricsText(rt)
	for _, want := range []string{
		`netpush_drain_forced_closes_total{upstream="web",protocol="tcp"} 1`,
		`netpush_drain_forced_closes_total{upstream="dnsd",protocol="udp"} 1`,
		`netpush_targets{upstream="web",protocol="tcp"} 1`,
		`netpush_connections_draining{upstream="web",protocol="tcp"} 0`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	// Critical instance is filtered (only_passing).
	fc.mu.Lock()
	fc.crit[tB] = true
	fc.mu.Unlock()
	fc.set("web", tA, tB)
	eventually(t, "critical filtered", func() bool {
		s := rt.pools["web"].snapshot()
		return len(s) == 1 && s[0].Port == tA.Port()
	})

	// DNS: upstream name, suffixed name, SRV, AAAA, passthrough.
	dc, err := net.Dial("udp", rt.dnsUDP.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	ask := func(name string, qt uint16) []byte {
		dc.SetDeadline(time.Now().Add(2 * time.Second))
		dc.Write(dnsQuery(name, qt))
		b := make([]byte, 600)
		n, err := dc.Read(b)
		if err != nil {
			t.Fatalf("dns %s: %v", name, err)
		}
		return b[:n]
	}
	for _, n := range []string{"web", "WEB.service.consul"} {
		r := ask(n, dnsTypeA)
		if r[3]&0xF != 0 || binary.BigEndian.Uint16(r[6:]) != 1 || !strings.HasSuffix(string(r), string([]byte{127, 0, 0, 1})) {
			t.Fatalf("A %s: % x", n, r)
		}
	}
	if r := ask("web", dnsTypeAAAA); r[3]&0xF != 0 || binary.BigEndian.Uint16(r[6:]) != 0 {
		t.Fatalf("AAAA: % x", r)
	}
	if r := ask("web", dnsTypeSRV); binary.BigEndian.Uint16(r[6:]) != 1 || binary.BigEndian.Uint16(r[10:]) != 1 {
		t.Fatalf("SRV: % x", r)
	}
	if r := ask("example.org", dnsTypeA); r[3]&0xF != 3 {
		t.Fatalf("passthrough: want upstream NXDOMAIN, got % x", r)
	}
	// DNS over TCP.
	tc, err := net.Dial("tcp", rt.dnsTCP.String())
	if err != nil {
		t.Fatal(err)
	}
	q := dnsQuery("web", dnsTypeA)
	tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	var l [2]byte
	if _, err := io.ReadFull(tc, l[:]); err != nil {
		t.Fatal(err)
	}
	r := make([]byte, binary.BigEndian.Uint16(l[:]))
	io.ReadFull(tc, r)
	tc.Close()
	if binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Fatalf("dns tcp: % x", r)
	}

	// Metrics endpoint.
	resp, err := http.Get("http://" + rt.metricsLn.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `netpush_dns_answers_total{kind="passthrough"} 1`) || !strings.Contains(string(body), `netpush_bytes_up_total{upstream="web"`) {
		t.Fatalf("metrics:\n%s", body)
	}
}

func isClosedErr(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "closed"))
}

// --- units ------------------------------------------------------------------

func newTestPool(drain time.Duration) *pool {
	return newPool("t", drain, NewNetpushMetrics().Upstream("t", "tcp"))
}

func ntg(s string) Target {
	ap := netip.MustParseAddrPort(s)
	return Target{Addr: ap.Addr(), Port: ap.Port()}
}

func TestPoolDrainNever(t *testing.T) {
	p := newTestPool(0)
	p.update([]Target{ntg("10.0.0.1:80")})
	closed := make(chan struct{})
	c := p.acquire(ntg("10.0.0.1:80"), func() { close(closed) })
	p.update([]Target{ntg("10.0.0.2:80")})
	if p.m.draining.Load() != 1 {
		t.Fatal("not draining")
	}
	select {
	case <-closed:
		t.Fatal("drain_timeout=0 must never force-close")
	case <-time.After(200 * time.Millisecond):
	}
	p.release(c)
	if p.m.draining.Load() != 0 || p.m.active.Load() != 0 {
		t.Fatal("gauges not reset")
	}
}

func TestPoolDrainCancelledWhenTargetReturns(t *testing.T) {
	p := newTestPool(100 * time.Millisecond)
	a := ntg("10.0.0.1:80")
	p.update([]Target{a})
	closed := make(chan struct{}, 1)
	c := p.acquire(a, func() { closed <- struct{}{} })
	p.update(nil)
	p.update([]Target{a})
	select {
	case <-closed:
		t.Fatal("closed although target came back")
	case <-time.After(250 * time.Millisecond):
	}
	if p.m.draining.Load() != 0 {
		t.Fatal("draining gauge")
	}
	p.release(c)
}

func TestPoolBalance(t *testing.T) {
	p := newTestPool(time.Second)
	a, b, c := ntg("10.0.0.1:1"), ntg("10.0.0.2:1"), ntg("10.0.0.3:1")
	p.update([]Target{c, a, b})
	if got, _ := p.pick(BalanceFirst, nil); got != a {
		t.Fatalf("first: %v", got)
	}
	if got, _ := p.pick(BalanceFirst, []Target{a}); got != b {
		t.Fatalf("first excluding a: %v", got)
	}
	seen := map[Target]int{}
	for range 30 {
		x, _ := p.pick(BalanceRoundRobin, nil)
		seen[x]++
	}
	if seen[a] != 10 || seen[b] != 10 || seen[c] != 10 {
		t.Fatalf("round robin: %v", seen)
	}
	p.acquire(a, func() {})
	p.acquire(a, func() {})
	p.acquire(b, func() {})
	for range 10 {
		if x, _ := p.pick(BalanceLeastConn, nil); x != c {
			t.Fatalf("least_conn: %v", x)
		}
	}
	if _, ok := p.pick(BalanceLeastConn, []Target{a, b, c}); ok {
		t.Fatal("pick with all tried")
	}
}

func TestForwarderRetriesNextTarget(t *testing.T) {
	good := tcpEcho(t, "G")
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAP := netip.MustParseAddrPort(dead.Addr().String())
	dead.Close()
	m := NewNetpushMetrics().Upstream("r", "tcp")
	p := newPool("r", time.Second, m)
	p.update([]Target{{Addr: deadAP.Addr(), Port: deadAP.Port()}, {Addr: good.Addr(), Port: good.Port()}})
	// Sorted by port; force the dead one first by excluding nothing and using "first"
	// only if it sorts first, otherwise the test is still valid with least_conn below.
	f := &forwarder{up: Upstream{Name: "r", Balance: BalanceFirst}, pool: p, m: m, timeout: time.Second, retries: 1}
	if deadAP.Port() > good.Port() {
		f.up.Balance = BalanceLeastConn
		p.pick(BalanceLeastConn, nil) // rotate
	}
	ok := 0
	for range 4 {
		c, tgt, err := f.dialTarget(context.Background(), "tcp")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if tgt.Port == good.Port() {
			ok++
		}
	}
	if ok != 4 || m.connectFails.Load() == 0 || m.retries.Load() == 0 {
		t.Fatalf("ok=%d fails=%d retries=%d", ok, m.connectFails.Load(), m.retries.Load())
	}
	f.retries = 0
	p.update([]Target{{Addr: deadAP.Addr(), Port: deadAP.Port()}})
	if _, _, err := f.dialTarget(context.Background(), "tcp"); err == nil {
		t.Fatal("want error with only a dead target")
	}
}

func TestDNSAnswers(t *testing.T) {
	c := defaultNetpushConfig()
	c.Upstreams = []Upstream{{Name: "db", Bind: netip.MustParseAddrPort("127.0.1.7:3306")}}
	c.DNSDefault = "nxdomain"
	d := newDNSServer(c, NewNetpushMetrics())
	r, kind := d.answer(dnsQuery("db", dnsTypeA))
	if kind != "upstream" || binary.BigEndian.Uint16(r[0:]) != 0x1234 || r[2]&0x80 == 0 || r[2]&1 == 0 {
		t.Fatalf("A header: % x", r)
	}
	if got := r[len(r)-4:]; string(got) != string([]byte{127, 0, 1, 7}) {
		t.Fatalf("A rdata: % x", got)
	}
	if ttl := binary.BigEndian.Uint32(r[len(r)-10:]); ttl != 5 {
		t.Fatalf("ttl %d", ttl)
	}
	r, _ = d.answer(dnsQuery("db", dnsTypeSRV))
	if !strings.Contains(string(r), string(binary.BigEndian.AppendUint16(nil, 3306))) {
		t.Fatalf("SRV port: % x", r)
	}
	if r, kind = d.answer(dnsQuery("nope.example", dnsTypeA)); kind != "nxdomain" || r[3]&0xF != 3 {
		t.Fatalf("nxdomain: %s % x", kind, r)
	}
	d.nxdomain = false
	if r, kind = d.answer(dnsQuery("nope.example", dnsTypeA)); kind != "servfail" || r[3]&0xF != 2 {
		t.Fatalf("passthrough without upstream: %s % x", kind, r)
	}
	d.upstream = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if r, kind = d.answer(dnsQuery("nope.example", dnsTypeA)); r != nil || kind != "passthrough" {
		t.Fatalf("passthrough: %s", kind)
	}
	if r, _ := d.answer([]byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0}); r == nil || r[3]&0xF != 1 {
		t.Fatalf("formerr: % x", r)
	}
	if _, err := parseDNSQuery([]byte{1}); err == nil {
		t.Fatal("short")
	}
}
