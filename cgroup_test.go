package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeCgroupFS(t *testing.T, self string, dirs ...string) (procFile, root string) {
	t.Helper()
	d := t.TempDir()
	root = filepath.Join(d, "cgroup")
	for _, sub := range append([]string{""}, dirs...) {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	procFile = filepath.Join(d, "self-cgroup")
	if err := os.WriteFile(procFile, []byte(self), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func runAs(t *testing.T, extra string) Config {
	t.Helper()
	c, err := parse(t, "allow_services = a\nconsul_addrs = 192.0.2.1:8501, [2001:db8::1]:8501\nrun_as = 65532\n"+extra)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseSelfCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::/\n": "/",
		"12:pids:/docker/x\n0::/nomad.slice/4e7788fb-6ec0-4177-e8b0-a6b8c9fc63d9.netblock-watch.scope\n": "/nomad.slice/4e7788fb-6ec0-4177-e8b0-a6b8c9fc63d9.netblock-watch.scope",
	} {
		got, err := ParseSelfCgroup(strings.NewReader(in))
		if err != nil || got != want {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "12:pids:/x\n", "0::\n", "0::relative\n"} {
		if _, err := ParseSelfCgroup(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCgroupForNft(t *testing.T) {
	scope := "nomad.slice/4e7788fb-6ec0-4177-e8b0-a6b8c9fc63d9.netblock-watch.scope"
	_, root := fakeCgroupFS(t, "", scope)
	if p, l, err := CgroupForNft("/", root); err != nil || p != "/" || l != 0 {
		t.Fatalf("root ns: %q %d %v", p, l, err)
	}
	if p, l, err := CgroupForNft("/"+scope, root); err != nil || p != scope || l != 2 {
		t.Fatalf("host ns: %q %d %v", p, l, err)
	}
	// Not created yet / gone / unsafe / not cgroup2.
	for _, bad := range []string{"/nomad.slice/other.scope", "/" + scope + " (deleted)", "/a\"b"} {
		if _, _, err := CgroupForNft(bad, root); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, _, err := CgroupForNft("/", t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a cgroup v2 mount") {
		t.Errorf("want not-cgroup2 error, got %v", err)
	}
}

func TestResolveExempt(t *testing.T) {
	c := runAs(t, "")
	proc, root := fakeCgroupFS(t, "0::/\n")
	ex, err := resolveExempt(c, proc, root)
	if err != nil || ex.Kind != ExemptCgroup || ex.CgroupPath != "/" || ex.CgroupLevel != 0 || ex.UID != 65532 {
		t.Fatalf("%+v %v", ex, err)
	}
	// Missing cgroup: uid fallback with an error to log.
	proc, root = fakeCgroupFS(t, "0::/nomad.slice/x.scope\n")
	if ex, err := resolveExempt(c, proc, root); err == nil || ex.Kind != ExemptUID || ex.UID != 65532 {
		t.Fatalf("missing cgroup: %+v %v", ex, err)
	}
	if ex, err := resolveExempt(c, filepath.Join(t.TempDir(), "nope"), root); err == nil || ex.Kind != ExemptUID {
		t.Fatalf("no proc file: %+v %v", ex, err)
	}
	if ex, err := resolveExempt(runAs(t, "exempt_match = uid\n"), proc, root); err == nil || ex.Kind != ExemptUID {
		t.Fatalf("exempt_match=uid: %+v %v", ex, err)
	}
	// No run_as: cgroup only, fallback is the open v0.2 rule.
	c2, _ := parse(t, "allow_services = a\nconsul_addr = 192.0.2.1:8501\n")
	proc, root = fakeCgroupFS(t, "0::/\n")
	if ex, _ := resolveExempt(c2, proc, root); ex.Kind != ExemptCgroup || ex.UID != 0 {
		t.Fatalf("no run_as: %+v", ex)
	}
	if fb := uidFallback(c2); fb.Kind != ExemptOpen {
		t.Fatalf("fallback without run_as: %+v", fb)
	}
	if _, err := parse(t, "allow_services = a\nexempt_match = cgroup\n"); err == nil {
		t.Error("accepted exempt_match = cgroup")
	}
}

func TestRenderRulesetCgroupExempt(t *testing.T) {
	c := runAs(t, "")
	rs := RenderRuleset(c, nil, Exempt{Kind: ExemptCgroup, UID: 65532, CgroupPath: "/", CgroupLevel: 0})
	for _, want := range []string{
		"counter consul_exempt {}",
		`socket cgroupv2 level 0 "/" meta skuid 65532 ip daddr 192.0.2.1 tcp dport 8501 counter name "consul_exempt" accept comment "consul"`,
		`socket cgroupv2 level 0 "/" meta skuid 65532 ip6 daddr 2001:db8::1 tcp dport 8501 counter name "consul_exempt" accept`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in\n%s", want, rs)
		}
	}
	// Every Consul accept carries the cgroup match: no uid-only rule left to bypass.
	for _, l := range strings.Split(rs, "\n") {
		if strings.Contains(l, "8501") && !strings.Contains(l, "socket cgroupv2") {
			t.Errorf("consul rule without cgroup match: %q", l)
		}
	}
	host := RenderRuleset(c, nil, Exempt{Kind: ExemptCgroup, CgroupPath: "nomad.slice/a.netblock-watch.scope", CgroupLevel: 2})
	if !strings.Contains(host, `socket cgroupv2 level 2 "nomad.slice/a.netblock-watch.scope" ip daddr 192.0.2.1`) || strings.Contains(host, "skuid") {
		t.Errorf("host path rule:\n%s", host)
	}
}

func TestInitInstallsNoConsulExemptWithRunAs(t *testing.T) {
	c := runAs(t, "")
	rs := RenderRuleset(c, nil, initExempt(c))
	if strings.Contains(rs, "8501") || strings.Contains(rs, "skuid") {
		t.Errorf("init must not exempt anything for Consul when run_as is set:\n%s", rs)
	}
	c2, _ := parse(t, "allow_services = a\nconsul_addr = 192.0.2.1:8501\n")
	if rs := RenderRuleset(c2, nil, initExempt(c2)); !strings.Contains(rs, `    ip daddr 192.0.2.1 tcp dport 8501 counter name "consul_exempt" accept`) {
		t.Errorf("no run_as keeps the open rule:\n%s", rs)
	}
}

// counterNFT returns a fixed consul_exempt packet count.
type counterNFT struct {
	fakeNFT
	packets string
}

func (f *counterNFT) ListJSON(args ...string) ([]byte, error) {
	if args[0] == "counter" && args[3] == "consul_exempt" {
		return []byte(`{"nftables":[{"counter":{"packets":` + f.packets + `,"bytes":0}}]}`), nil
	}
	return f.fakeNFT.ListJSON(args...)
}

func TestVerifyExempt(t *testing.T) {
	old := probe
	defer func() { probe = old }()
	var probed []netip.AddrPort
	probe = func(_ context.Context, a []netip.AddrPort) { probed = a }
	c := runAs(t, "")
	cg := Exempt{Kind: ExemptCgroup, UID: 65532, CgroupPath: "/"}

	ok := &counterNFT{packets: "2"}
	if got := verifyExempt(context.Background(), c, ok, nil, cg); got != cg || len(ok.scripts) != 0 || len(probed) != 2 {
		t.Fatalf("matched: %+v scripts=%d probed=%v", got, len(ok.scripts), probed)
	}
	miss := &counterNFT{packets: "0"}
	got := verifyExempt(context.Background(), c, miss, []Target{tg("10.0.0.1:3306")}, cg)
	if got.Kind != ExemptUID || len(miss.scripts) != 1 {
		t.Fatalf("no match should fall back to uid: %+v scripts=%d", got, len(miss.scripts))
	}
	if s := miss.last(); !strings.Contains(s, "meta skuid 65532 ip daddr 192.0.2.1") || strings.Contains(s, "cgroupv2") || !strings.Contains(s, "10.0.0.1 . 3306") {
		t.Errorf("fallback ruleset:\n%s", s)
	}
}

// Full watch start: resolves its own cgroup, applies the cgroupv2 rule in the first re-apply,
// probes, sees the counter move (fakeNFT counters return 3) and keeps the cgroup rule.
func TestRunWatchAppliesCgroupExempt(t *testing.T) {
	oldF, oldR, oldP := selfCgroupFile, cgroupRoot, probe
	defer func() { selfCgroupFile, cgroupRoot, probe = oldF, oldR, oldP }()
	selfCgroupFile, cgroupRoot = fakeCgroupFS(t, "0::/\n")
	probe = func(context.Context, []netip.AddrPort) {}
	p := t.TempDir() + "/c"
	os.WriteFile(p, []byte("mode = audit\nallow_cidrs = tcp 1.2.3.4 443\nmetrics_addr =\nconsul_addrs = 192.0.2.1:8501\nrun_as = 65532\n"), 0o600)
	f := &carryNFT{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- runWatch(ctx, p, f) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if !strings.Contains(f.first(), `socket cgroupv2 level 0 "/" meta skuid 65532 ip daddr 192.0.2.1 tcp dport 8501`) {
		t.Fatal(f.first())
	}
	f.mu.Lock()
	n := len(f.scripts)
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected no fallback re-apply, got %d scripts", n)
	}
}
