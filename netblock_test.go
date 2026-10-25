package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func parse(t *testing.T, s string) (Config, error) {
	t.Helper()
	return ParseConfig(strings.NewReader(s), func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.0.0.53")} })
}

func TestParseConfigFull(t *testing.T) {
	c, err := parse(t, `
# comment
mode = audit
allow_cidrs = tcp 192.0.2.10/32 16034; tcp 10.0.0.0/8 8000-8100, udp 100.64.0.0/10
allow_services = proxysql-beta, primary.redis@fsn1;mysql
dns_resolver = none
include_critical = false
removal_grace = 90s
consul_addr = 192.0.2.20:8501
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeAudit || !c.DNSNone || c.IncludeCritical || c.RemovalGrace != 90*time.Second {
		t.Fatalf("unexpected %+v", c)
	}
	if len(c.AllowCIDRs) != 3 || len(c.AllowServices) != 3 {
		t.Fatalf("cidrs %+v", c.AllowCIDRs)
	}
}

func TestParseConfigContinuationRejected(t *testing.T) {
	_, err := parse(t, "allow_cidrs = tcp 1.2.3.4 80\ntcp 5.6.7.8 80\n")
	if err == nil {
		t.Fatal("bare continuation line must be an error (fail closed)")
	}
}

func TestParseConfigEntries(t *testing.T) {
	c, err := parse(t, "allow_cidrs = tcp 10.1.2.3 5432; udp 10.0.0.0/8 1000-2000; tcp 2001:db8::/32\nallow_services = a, t.b@dc2, c@dc1\nconsul_addr = 127.0.0.1:8501\n")
	if err != nil {
		t.Fatal(err)
	}
	r := c.AllowCIDRs
	if r[0].Prefix.String() != "10.1.2.3/32" || r[0].PortLo != 5432 || r[1].PortHi != 2000 || r[2].PortLo != 0 {
		t.Fatalf("%+v", r)
	}
	s := c.AllowServices
	if s[0] != (ServiceRef{Name: "a"}) || s[1] != (ServiceRef{Name: "b", Tag: "t", DC: "dc2"}) || s[2].String() != "c@dc1" {
		t.Fatalf("%+v", s)
	}
	if len(c.DNSResolvers) != 1 || c.DNSResolvers[0].String() != "10.0.0.53" || c.Mode != ModeEnforce || !c.IncludeCritical || c.RemovalGrace != time.Minute {
		t.Fatalf("defaults %+v", c)
	}
	c, err = parse(t, "egress_allow = tcp 1.2.3.4 80\n")
	if err != nil || len(c.AllowCIDRs) != 1 {
		t.Fatalf("v0.1 key alias: %v", err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	bad := []string{
		"",
		"mode = open\nallow_cidrs = tcp 1.2.3.4\n",
		"allow_cidrs = tcp 0.0.0.0/0\n",
		"allow_cidrs = icmp 1.2.3.4\n",
		"allow_cidrs = tcp 1.2.3.4 0\n",
		"allow_cidrs = tcp 1.2.3.4 90-80\n",
		"allow_cidrs = tcp nope\n",
		"allow_services = a\n",
		"allow_services = a b\nconsul_addr = 1.2.3.4:8501\n",
		"allow_services = a\nconsul_addr = consul:8501\n",
		"allow_cidrs = tcp 1.2.3.4\nfoo = bar\n",
		"allow_cidrs = tcp 1.2.3.4\nallow_cidrs = tcp 1.2.3.5\n",
		"allow_cidrs = tcp 1.2.3.4\ndns_resolver = dns.google\n",
		"allow_cidrs = tcp 1.2.3.4\nremoval_grace = -1s\n",
		"just garbage\n",
	}
	for _, b := range bad {
		if _, err := parse(t, b); err == nil {
			t.Errorf("expected error for %q", b)
		}
	}
}

func TestResolvConf(t *testing.T) {
	a := ParseResolvConf(strings.NewReader("search x\nnameserver 10.0.0.1\nnameserver fd00::1\nnameserver bad\n"))
	if len(a) != 2 || !a[1].Is6() {
		t.Fatal(a)
	}
}

func TestRenderRulesetEnforce(t *testing.T) {
	c, _ := parse(t, "allow_cidrs = tcp 192.0.2.10/32 16034; udp 100.64.0.0/10; tcp 2001:db8::/32 80-90\ndns_resolver = 1.1.1.1 2606:4700::1111\nallow_services = x\nconsul_addr = 192.0.2.20:8501\n")
	s := RenderRuleset(c, []Target{{netip.MustParseAddr("10.0.0.2"), 3306}, {netip.MustParseAddr("fd00::2"), 6379}, {netip.MustParseAddr("10.0.0.1"), 3306}}, Exempt{Kind: ExemptOpen})
	for _, want := range []string{
		"add table inet netblock\ndelete table inet netblock\n",
		"policy drop;",
		`icmpv6 type nd-router-solicit counter name "ipv6_rs" drop`,
		"ip daddr { 1.1.1.1 } meta l4proto { tcp, udp } th dport 53 counter accept",
		"ip6 daddr { 2606:4700::1111 }",
		"ip daddr 192.0.2.20 tcp dport 8501 counter name \"consul_exempt\" accept",
		"ip daddr 192.0.2.10/32 tcp dport 16034 counter accept",
		"ip daddr 100.64.0.0/10 meta l4proto udp counter accept",
		"ip6 daddr 2001:db8::/32 tcp dport 80-90 counter accept",
		"ip daddr . th dport @svc4",
		"add element inet netblock svc4 { 10.0.0.1 . 3306, 10.0.0.2 . 3306 }",
		"add element inet netblock svc6 { fd00::2 . 6379 }",
		"reject with tcp reset",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "audit mode") {
		t.Error("enforce must not accept at the end")
	}
}

func TestRenderRulesetAuditAndNoDNS(t *testing.T) {
	c, _ := parse(t, "mode = audit\nallow_cidrs = tcp 1.2.3.4\ndns_resolver = none\n")
	s := RenderRuleset(c, nil, Exempt{Kind: ExemptOpen})
	if !strings.Contains(s, `accept comment "audit mode"`) || strings.Contains(s, "dport 53") || strings.Contains(s, "reject") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "policy drop;") {
		t.Fatal("audit still has policy drop")
	}
	if strings.Contains(s, "add element") {
		t.Fatal("no targets -> no elements")
	}
}

func TestRenderSetUpdateAndFailClosed(t *testing.T) {
	u := RenderSetUpdate(nil)
	if u != "flush set inet netblock svc4\nflush set inet netblock svc6\n" {
		t.Fatal(u)
	}
	fc := RenderFailClosed([]netip.Addr{netip.MustParseAddr("10.0.0.53")})
	if !strings.Contains(fc, "policy drop;") || !strings.Contains(fc, "10.0.0.53") || strings.Contains(fc, "@svc") {
		t.Fatal(fc)
	}
}

const dropJSON = `{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"set": {"family": "inet", "name": "drop4", "table": "netblock", "type": ["inet_proto", "ipv4_addr", "inet_service"], "elem": [{"elem": {"val": {"concat": ["udp", "8.8.8.8", 53]}, "expires": 86397, "counter": {"packets": 1, "bytes": 29}}}, {"elem": {"val": {"concat": ["tcp", "1.2.3.4", 443]}, "counter": {"packets": 2, "bytes": 120}}}, {"elem": {"val": "junk"}}]}}]}`

func TestParseDropSetAndCounter(t *testing.T) {
	d, err := ParseDropSet([]byte(dropJSON))
	if err != nil || len(d) != 2 || d[1].Dest.String() != "1.2.3.4:443" || d[1].Packets != 2 || d[0].Proto != "udp" {
		t.Fatalf("%v %+v", err, d)
	}
	p, b, err := ParseNamedCounter([]byte(`{"nftables":[{"metainfo":{}},{"counter":{"name":"would_drop","packets":5,"bytes":229}}]}`))
	if err != nil || p != 5 || b != 229 {
		t.Fatal(p, b, err)
	}
	if _, err := ParseDropSet([]byte("nope")); err == nil {
		t.Fatal("want error")
	}
}

func tg(s string) Target {
	ap := netip.MustParseAddrPort(s)
	return Target{ap.Addr(), ap.Port()}
}

func TestTrackerGrace(t *testing.T) {
	tr := NewTracker(60 * time.Second)
	t0 := time.Unix(1000, 0)
	tr.Update("a", []Target{tg("10.0.0.1:1"), tg("10.0.0.2:1")}, t0)
	tr.Update("b", []Target{tg("10.0.0.2:1")}, t0)
	tr.Update("a", []Target{tg("10.0.0.1:1")}, t0.Add(10*time.Second)) // .2 still live via b
	if e, g := tr.Effective(t0.Add(100 * time.Second)); len(e) != 2 || g != 0 {
		t.Fatal(e, g)
	}
	tr.Update("a", nil, t0.Add(20*time.Second)) // .1 removed at t+20
	if e, g := tr.Effective(t0.Add(79 * time.Second)); len(e) != 2 || g != 1 {
		t.Fatal("inside grace", e, g)
	}
	if e, _ := tr.Effective(t0.Add(81 * time.Second)); len(e) != 1 || e[0] != tg("10.0.0.2:1") {
		t.Fatal("after grace", e)
	}
	if tr.ServiceFor(tg("10.0.0.2:1")) != "a,b" || tr.ServiceFor(tg("9.9.9.9:1")) != "" {
		t.Fatal(tr.ServiceFor(tg("10.0.0.2:1")))
	}
	if tr.SetSizes()["a"] != 0 || tr.SetSizes()["b"] != 1 {
		t.Fatal(tr.SetSizes())
	}
}

func TestTrackerZeroGrace(t *testing.T) {
	tr := NewTracker(0)
	tr.Update("a", []Target{tg("10.0.0.1:1")}, time.Unix(0, 0))
	tr.Update("a", nil, time.Unix(1, 0))
	if e, _ := tr.Effective(time.Unix(1, 0)); len(e) != 0 {
		t.Fatal(e)
	}
}

const healthJSON = `[
 {"Node":{"Node":"n1","Address":"10.0.0.1"},"Service":{"Service":"db","Address":"","Port":3306},"Checks":[{"Status":"passing"}]},
 {"Node":{"Node":"n2","Address":"10.0.0.2"},"Service":{"Service":"db","Address":"100.64.0.2","Port":3306},"Checks":[{"Status":"critical"}]},
 {"Node":{"Node":"n3","Address":"10.0.0.3"},"Service":{"Service":"db","Address":"","Port":3307},"Checks":[{"Status":"warning"}]},
 {"Node":{"Node":"n4","Address":"10.0.0.4"},"Service":{"Service":"db","Address":"db.example","Port":3306},"Checks":[]}
]`

func TestHealthQueryAndCritical(t *testing.T) {
	var gotURL, gotTok string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL, gotTok = r.URL.String(), r.Header.Get("X-Consul-Token")
		w.Header().Set("X-Consul-Index", "42")
		fmt.Fprint(w, healthJSON)
	}))
	defer srv.Close()
	tok := t.TempDir() + "/tok"
	os.WriteFile(tok, []byte("secret-token\n"), 0o600)
	cc := newConsulClient([]string{srv.URL}, tok, http.DefaultTransport)
	ts, idx, err := cc.Health(context.Background(), ServiceRef{Name: "db", Tag: "primary", DC: "fsn1"}, 7, 5*time.Minute, true)
	if err != nil || idx != 42 || len(ts) != 3 {
		t.Fatal(ts, idx, err)
	}
	if strings.Contains(gotURL, "passing") || !strings.Contains(gotURL, "index=7") || !strings.Contains(gotURL, "wait=300s") || !strings.Contains(gotURL, "tag=primary") || !strings.Contains(gotURL, "dc=fsn1") {
		t.Fatal(gotURL)
	}
	if gotTok != "secret-token" {
		t.Fatal("token header")
	}
	ts, _, _ = cc.Health(context.Background(), ServiceRef{Name: "db"}, 0, 0, false)
	if len(ts) != 2 || ts[0] != tg("10.0.0.1:3306") || ts[1] != tg("10.0.0.3:3307") {
		t.Fatal("exclude critical", ts)
	}
}

func TestHealthErrorAndIndex(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ACL not found", http.StatusForbidden)
	}))
	defer srv.Close()
	cc := newConsulClient([]string{srv.URL}, "", http.DefaultTransport)
	if _, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatal(err)
	}
	if nextIndex(10, 5) != 0 || nextIndex(10, 0) != 0 || nextIndex(10, 11) != 11 {
		t.Fatal("index rules")
	}
}

// fakeNFT records scripts and serves canned list output.
type fakeNFT struct {
	mu      sync.Mutex
	scripts []string
	fail    atomic.Bool
}

func (f *fakeNFT) Apply(s string) error {
	if f.fail.Load() {
		return fmt.Errorf("boom")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, s)
	return nil
}
func (f *fakeNFT) ListJSON(args ...string) ([]byte, error) {
	if args[0] == "counter" {
		return []byte(`{"nftables":[{"counter":{"packets":3,"bytes":1}}]}`), nil
	}
	if args[3] == "drop4" {
		return []byte(dropJSON), nil
	}
	return []byte(`{"nftables":[]}`), nil
}
func (f *fakeNFT) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func TestWatcherSyncKeepsLastGoodOnApplyError(t *testing.T) {
	c, _ := parse(t, "allow_cidrs = tcp 1.2.3.4\n")
	f := &fakeNFT{}
	w := &watcher{c: c, nft: f, tr: NewTracker(time.Minute), m: NewMetrics(ModeEnforce), seenDrops: map[string]uint64{}}
	w.tr.Update("db", []Target{tg("10.0.0.1:3306")}, time.Now())
	w.sync(time.Now())
	if !strings.Contains(f.last(), "10.0.0.1 . 3306") {
		t.Fatal(f.last())
	}
	n := len(f.scripts)
	w.sync(time.Now())
	if len(f.scripts) != n {
		t.Fatal("no-op sync must not re-apply")
	}
	f.fail.Store(true)
	w.tr.Update("db", []Target{tg("10.0.0.9:3306")}, time.Now())
	w.sync(time.Now())
	if w.m.nftErrors != 1 || len(w.applied) != 1 || w.applied[0] != tg("10.0.0.1:3306") {
		t.Fatal("apply error must keep previous", w.applied)
	}
	f.fail.Store(false)
	w.sync(time.Now())
	if !strings.Contains(f.last(), "10.0.0.9 . 3306") || !strings.Contains(f.last(), "10.0.0.1 . 3306") {
		t.Fatal("retry should apply new + graced old:", f.last())
	}
	w.scanDrops()
	var b strings.Builder
	w.m.Write(&b)
	for _, want := range []string{`netblock_drops_packets_total{proto="tcp",dest="1.2.3.4:443",service=""} 2`, "netblock_would_drop_packets_total 3", `netblock_set_elements{set="svc4"} 2`, `netblock_service_instances{service="db"} 1`, "netblock_nft_errors_total 1"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q\n%s", want, b.String())
		}
	}
}

// End to end: a fake Consul with blocking semantics drives watchService -> tracker.
func TestWatchServiceBlockingAndErrors(t *testing.T) {
	var mu sync.Mutex
	body, idx, failNext := `[{"Node":{"Address":"10.0.0.1"},"Service":{"Service":"db","Port":1}}]`, 5, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if failNext > 0 {
			failNext--
			http.Error(w, "down", 500)
			return
		}
		w.Header().Set("X-Consul-Index", fmt.Sprint(idx))
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	cc := newConsulClient([]string{srv.URL}, "", http.DefaultTransport)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan update, 4)
	m := NewMetrics(ModeEnforce)
	src := source{"db", func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
		return cc.Health(ctx, ServiceRef{Name: "db"}, i, w, true)
	}}
	go watchService(ctx, src, m, out)
	u := <-out
	if len(u.targets) != 1 || u.service != "db" {
		t.Fatal(u)
	}
	mu.Lock()
	failNext, body, idx = 1, `[{"Node":{"Address":"10.0.0.2"},"Service":{"Service":"db","Port":1}}]`, 6
	mu.Unlock()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case u = <-out:
		case <-deadline:
			t.Fatal("no update")
		}
		if u.targets[0] == tg("10.0.0.2:1") {
			break
		}
	}
	m.with(func() {
		if m.consulErrors["db"] < 1 {
			t.Error("error not counted")
		}
	})
}

func TestRunInitFailClosed(t *testing.T) {
	f := &fakeNFT{}
	if rc := runInit(t.TempDir()+"/missing.conf", f); rc != 1 || !strings.Contains(f.last(), "failclosed") {
		t.Fatal(rc, f.last())
	}
	p := t.TempDir() + "/c"
	os.WriteFile(p, []byte("allow_cidrs = tcp 1.2.3.4 443\ndns_resolver = none\n"), 0o600)
	if rc := runInit(p, f); rc != 0 || !strings.Contains(f.last(), "1.2.3.4/32 tcp dport 443") {
		t.Fatal(rc, f.last())
	}
	f.fail.Store(true)
	if rc := runInit(p, f); rc != 3 {
		t.Fatal("apply failure of both rulesets must be 3, got", rc)
	}
}

// Real nftables in a throwaway network namespace (needs root + nft): NETBLOCK_NFT_IT=1.
func TestNFTIntegration(t *testing.T) {
	if os.Getenv("NETBLOCK_NFT_IT") != "1" {
		t.Skip("set NETBLOCK_NFT_IT=1 inside 'unshare -n' as root")
	}
	bin, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("no nft")
	}
	r := execRunner{bin: bin}
	for _, mode := range []string{"enforce", "audit"} {
		c, err := parse(t, "mode = "+mode+"\nallow_cidrs = tcp 192.0.2.10/32 16034; udp 100.64.0.0/10; tcp 2001:db8::/32 80-90\ndns_resolver = 1.1.1.1 2606:4700::1111\nallow_services = x\nconsul_addr = 192.0.2.20:8501\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Apply(RenderRuleset(c, []Target{tg("10.0.0.1:3306"), tg("[fd00::1]:6379")}, Exempt{Kind: ExemptCgroup, UID: 65532, CgroupPath: "/", CgroupLevel: 0})); err != nil {
			t.Fatal(mode, err)
		}
		if err := r.Apply(RenderSetUpdate([]Target{tg("10.0.0.2:3306")})); err != nil {
			t.Fatal(err)
		}
		out, err := r.ListJSON("set", "inet", tableName, "svc4")
		if err != nil || !strings.Contains(string(out), "10.0.0.2") || strings.Contains(string(out), "10.0.0.1") {
			t.Fatal(string(out), err)
		}
		if ts, err := ParseServiceSet(out); err != nil || len(ts) != 1 || ts[0] != tg("10.0.0.2:3306") {
			t.Fatal("parse svc set", ts, err)
		}
		if _, err := r.ListJSON("set", "inet", tableName, "drop4"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Apply(RenderFailClosed([]netip.Addr{netip.MustParseAddr("1.1.1.1")})); err != nil {
		t.Fatal(err)
	}
}

func TestParseServiceSet(t *testing.T) {
	ts, err := ParseServiceSet([]byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"svc4","elem":[{"concat":["10.0.0.1",3306]},{"concat":["fd00::1",6379]},"junk"]}}]}`))
	if err != nil || len(ts) != 2 || ts[1] != tg("[fd00::1]:6379") {
		t.Fatal(ts, err)
	}
}

func TestRunWatchCarriesTargetsAndExitsOnCancel(t *testing.T) {
	oldF, oldR := selfCgroupFile, cgroupRoot
	defer func() { selfCgroupFile, cgroupRoot = oldF, oldR }()
	selfCgroupFile, cgroupRoot = fakeCgroupFS(t, "0::/\n")
	p := t.TempDir() + "/c"
	os.WriteFile(p, []byte("mode = audit\nallow_cidrs = tcp 1.2.3.4 443\nmetrics_addr =\n"), 0o600)
	f := &carryNFT{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- runWatch(ctx, p, f) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	if rc := <-done; rc != 0 {
		t.Fatal(rc)
	}
	if !strings.Contains(f.first(), "add element inet netblock svc4 { 10.0.0.7 . 3306 }") || !strings.Contains(f.first(), "audit mode") {
		t.Fatal(f.first())
	}
}

type carryNFT struct{ fakeNFT }

func (c *carryNFT) ListJSON(args ...string) ([]byte, error) {
	if len(args) == 4 && args[3] == "svc4" {
		return []byte(`{"nftables":[{"set":{"elem":[{"concat":["10.0.0.7",3306]}]}}]}`), nil
	}
	return c.fakeNFT.ListJSON(args...)
}
func (f *fakeNFT) first() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[0]
}
