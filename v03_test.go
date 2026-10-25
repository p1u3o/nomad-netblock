package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const oneEntry = `[{"Node":{"Address":"10.0.0.1"},"Service":{"Address":"10.0.0.5","Port":80},"Checks":[]}]`

func deadAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return "http://" + a
}

func TestConsulFailoverDeadFirst(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("X-Consul-Index", "7")
		w.Write([]byte(oneEntry))
	}))
	defer srv.Close()
	cc := newConsulClient([]string{deadAddr(t), srv.URL}, "", http.DefaultTransport)
	ts, idx, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true)
	if err != nil || idx != 7 || len(ts) != 1 {
		t.Fatalf("got %v %d %v", ts, idx, err)
	}
	if cc.Current() != srv.URL || cc.Failovers() != 1 {
		t.Fatalf("current %s failovers %d", cc.Current(), cc.Failovers())
	}
	// Sticky: second call goes straight to the good endpoint.
	if _, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true); err != nil || cc.Failovers() != 1 {
		t.Fatalf("second call err=%v failovers=%d", err, cc.Failovers())
	}
}

func TestConsulFailover5xxAndBackoff(t *testing.T) {
	var bad, good int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&bad, 1)
		http.Error(w, "No cluster leader", 500)
	}))
	defer b.Close()
	g := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&good, 1)
		w.Write([]byte(oneEntry))
	}))
	defer g.Close()
	cc := newConsulClient([]string{b.URL, g.URL}, "", http.DefaultTransport)
	now := time.Unix(1000, 0)
	cc.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if _, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true); err != nil {
			t.Fatal(err)
		}
	}
	if bad != 1 || good != 3 {
		t.Fatalf("bad=%d good=%d", bad, good)
	}
	// good dies; bad is in backoff but is still tried as last resort.
	g.Close()
	if _, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true); err == nil || !strings.Contains(err.Error(), "all 2 endpoints failed") {
		t.Fatalf("want all failed, got %v", err)
	}
	if bad != 2 {
		t.Fatalf("bad=%d", bad)
	}
}

func TestConsul403NoFailover(t *testing.T) {
	var second int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "Permission denied", 403) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&second, 1) }))
	defer b.Close()
	cc := newConsulClient([]string{a.URL, b.URL}, "", http.DefaultTransport)
	if _, _, err := cc.Health(context.Background(), ServiceRef{Name: "x"}, 0, 0, true); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
	if second != 0 || cc.Failovers() != 0 {
		t.Fatal("403 must not fail over")
	}
}

func TestConfigConsulAddrsRunAs(t *testing.T) {
	c, err := parse(t, "allow_services = a\nconsul_addrs = 192.0.2.1:8501, [2001:db8::1]:8501, 192.0.2.10:8501\nrun_as = 65532\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ConsulAddrs) != 3 || c.RunAsUID != 65532 || c.RunAsGID != 65532 {
		t.Fatalf("%+v", c)
	}
	rs := RenderRuleset(c, nil)
	for _, want := range []string{
		`meta skuid 65532 ip daddr 192.0.2.1 tcp dport 8501 counter accept comment "consul"`,
		`meta skuid 65532 ip6 daddr 2001:db8::1 tcp dport 8501 counter accept`,
		`meta skuid 65532 ip daddr 192.0.2.10 tcp dport 8501`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in\n%s", want, rs)
		}
	}
	for _, bad := range []string{
		"allow_services = a\nconsul_addr = 1.2.3.4:8501\nconsul_addrs = 1.2.3.5:8501\n",
		"allow_services = a\nconsul_addrs = 1.2.3.4:8501, consul:8501\n",
		"allow_services = a\nconsul_addrs = 1.2.3.4:8501\nrun_as = 0\n",
		"allow_services = a\nconsul_addrs = 1.2.3.4:8501\nrun_as = 65532:x\n",
	} {
		if _, err := parse(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	c, _ = parse(t, "allow_services = a\nconsul_addr = 1.2.3.4:8501\n")
	if strings.Contains(RenderRuleset(c, nil), "skuid") {
		t.Error("skuid without run_as")
	}
}
