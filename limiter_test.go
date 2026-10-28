package main

import (
	"testing"
	"time"
)

func TestNameLimiter(t *testing.T) {
	l := newNameLimiter(time.Minute, 2)
	t0 := time.Unix(0, 0)
	if ok, _ := l.allow("a", t0); !ok {
		t.Fatal("first a")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("a", t0.Add(time.Second)); ok {
			t.Fatal("a within interval")
		}
	}
	if ok, n := l.allow("a", t0.Add(61*time.Second)); !ok || n != 5 {
		t.Fatalf("a after interval: %v %d", ok, n)
	}
	l.allow("b", t0)
	if ok, _ := l.allow("c", t0.Add(time.Second)); ok {
		t.Fatal("c over cap")
	}
	if ok, _ := l.allow("c", t0.Add(2*time.Minute)); !ok {
		t.Fatal("c after expiry")
	}
}

func TestPeerRuleRender(t *testing.T) {
	c := defaultConfig()
	c.ConsulAddrs = mustAddrPorts(t, "192.0.2.10:8501")
	ex := Exempt{Kind: ExemptCgroup, CgroupPath: "/", CgroupLevel: 0, UID: 65532, Peer: &PeerExempt{ID: 7, UID: 65534}}
	r := RenderRuleset(c, nil, ex)
	want := `socket cgroupv2 level 0 "../../../proc/self/fd/3" meta skuid 65534 ip daddr 192.0.2.10 tcp dport 8501 counter name "netpush_exempt" accept`
	if !contains(r, want) {
		t.Fatalf("missing peer rule:\n%s", r)
	}
	ex.Peer = &PeerExempt{ByUID: true, UID: 65534}
	if r := RenderRuleset(c, nil, ex); !contains(r, `meta skuid 65534 ip daddr 192.0.2.10 tcp dport 8501 counter name "netpush_exempt"`) {
		t.Fatalf("missing uid peer rule:\n%s", r)
	}
	ex.Peer = nil
	if r := RenderRuleset(c, nil, ex); contains(r, `name "netpush_exempt" accept`) {
		t.Fatal("peer rule without peer")
	}
}
