//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOnDemandNft runs on-demand mode end to end against the real kernel: the ruleset is
// applied with nft in a private network namespace. Run as root:
//
//	go test -c -race -o /tmp/np.test && sudo NETBLOCK_NFT_TEST=1 unshare -n /tmp/np.test -test.run OnDemandNft -test.v
func TestOnDemandNft(t *testing.T) {
	if os.Getenv("NETBLOCK_NFT_TEST") != "1" || os.Getuid() != 0 {
		t.Skip("needs root in a throwaway netns and NETBLOCK_NFT_TEST=1 (see comment)")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(cgroupRoot, &fs); err != nil || fs.Type != cgroup2Magic {
		t.Skip("no cgroup2")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "10.9.0.1/16", "dev", "lo"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	defer func(o uint64) { rootCgroupID = o }(rootCgroupID)
	rootCgroupID = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := newFakeConsul(t)
	b1, b2 := tcpEcho(t, "b1"), tcpEcho(t, "b2")
	u1 := udpEcho(t, "u1")
	fake.set("mx-a", b1)
	fake.set("mx-u", u1)
	fake.set("mx-b", tcpEcho(t, "bb"))
	fake.set("mx-c", tcpEcho(t, "bc"))
	fake.set("db", tcpEcho(t, "db"))

	odPort, dnsPort := freePort(t), freePort(t)
	sock := filepath.Join(t.TempDir(), "netblock.sock")

	// netblock side.
	nc := defaultConfig()
	nc.Mode = ModeEnforce
	nc.DNSNone = true
	nc.NetpushSocket = sock
	nc.NetpushUID = 65533 // not us: the port-53 redirect applies to this test
	nc.OnDemandPool = netip.MustParsePrefix("127.0.3.0/24")
	nc.OnDemandPort = odPort
	nc.OnDemandAllow = []string{"mx-*"}
	nc.OnDemandMax = 64
	nc.DNSRedirect = dnsPort
	nc.EgressLockdown = true
	nc.ConsulAddrs = []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:8501")}
	nft := execRunner{"nft"}
	if err := nft.Apply(RenderRuleset(nc, nil, Exempt{})); err != nil {
		t.Fatal(err)
	}
	reqs := make(chan odRequest)
	peerCfg := nc
	peerCfg.NetpushUID = os.Getuid()
	go servePeer(ctx, peerCfg, 0, make(chan peerReg, 4), reqs)
	go miniWatch(ctx, t, nc, nft, fake.client(), reqs)
	waitSock(t, sock)

	// netpush side.
	c := defaultNetpushConfig()
	c.OnDemand, c.OnDemandMax, c.OnDemandAllow, c.OnDemandPort = true, 3, []string{"mx-*"}, odPort
	c.NetblockSocket = sock
	c.DNSListen = fmt.Sprintf("127.0.0.1:%d", dnsPort)
	c.DNSDefault = "nxdomain"
	c.DrainTimeout = time.Second
	c.MetricsAddr = ""
	c.ConsulAddrs = nc.ConsulAddrs
	rt, err := startNetpush(ctx, c, netpushDeps{consul: fake.client()})
	if err != nil {
		t.Fatal(err)
	}
	rt.linkOnDemand(ctx, sock)
	dns := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dnsPort)

	// Lookup assigns an address and puts the target into the allow set.
	ipA := mustResolve(t, dns, "mx-a")
	if !nc.OnDemandPool.Contains(ipA) {
		t.Fatalf("mx-a -> %s", ipA)
	}
	if out, _ := exec.Command("nft", "list", "set", "inet", tableName, "svc4").Output(); !strings.Contains(string(out), b1.Addr().String()+" . "+fmt.Sprint(b1.Port())) {
		t.Fatalf("svc4 lacks %s:\n%s", b1, out)
	}
	// Any port works.
	conns := map[uint16]*lineConn{}
	for _, port := range []uint16{443, 5555, 25} {
		lc := dialLine(t, &net.TCPAddr{IP: ipA.AsSlice(), Port: int(port)})
		if r, err := lc.say("hi"); err != nil || r != "b1:hi" {
			t.Fatalf("tcp port %d: %q %v", port, r, err)
		}
		conns[port] = lc
	}
	// UDP: replies come from the on-demand address (the connected client socket only
	// accepts those), and later datagrams go through the session's reply socket.
	ipU := mustResolve(t, dns, "mx-u")
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ipU, 7777)))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	for _, msg := range []string{"ping", "ping2", "ping3"} {
		uc.SetDeadline(time.Now().Add(3 * time.Second))
		uc.Write([]byte(msg))
		b := make([]byte, 100)
		n, err := uc.Read(b)
		if err != nil || string(b[:n]) != "u1:"+msg {
			t.Fatalf("udp %s: %q %v", msg, b[:n], err)
		}
	}
	// Port-53 redirect: a query to any resolver reaches netpush.
	if ip := mustResolve(t, netip.MustParseAddrPort("10.9.0.53:53"), "mx-a"); ip != ipA {
		t.Fatalf("redirected query: %s", ip)
	}
	// Pattern refusal and pool exhaustion.
	if rc, _ := dnsUDP(t, dns, "db"); rc != 3 {
		t.Fatalf("db: rcode %d, want NXDOMAIN", rc)
	}
	mustResolve(t, dns, "mx-b")
	if rc, _ := dnsUDP(t, dns, "mx-c"); rc != 2 {
		t.Fatalf("mx-c: rcode %d, want SERVFAIL (pool full)", rc)
	}
	// An address nobody was given is refused.
	if lc, err := net.DialTimeout("tcp", "127.0.3.200:80", time.Second); err == nil {
		lc.SetDeadline(time.Now().Add(time.Second))
		if n, _ := lc.Read(make([]byte, 1)); n != 0 {
			t.Fatal("unassigned address served")
		}
		lc.Close()
	}
	// Target change: new connections go to b2; the old one drains, then is closed.
	fake.set("mx-a", b2)
	eventually(t, "new target", func() bool {
		lc := dialLine(t, &net.TCPAddr{IP: ipA.AsSlice(), Port: 80})
		r, _ := lc.say("x")
		lc.Close()
		return r == "b2:x"
	})
	if out, _ := exec.Command("nft", "list", "set", "inet", tableName, "svc4").Output(); !strings.Contains(string(out), fmt.Sprintf("%s . %d", b2.Addr(), b2.Port())) {
		t.Fatalf("svc4 lacks the new target:\n%s", out)
	}
	if r, err := conns[443].say("still"); err != nil || r != "b1:still" {
		t.Fatalf("draining conn: %q %v", r, err)
	}
	eventually(t, "drain timeout close", func() bool {
		_, err := conns[5555].say("gone?")
		return err != nil
	})
	var b strings.Builder
	rt.metrics.Write(&b)
	for _, want := range []string{"netpush_ondemand_pool_used 3", `netpush_ondemand_refused_total{reason="pattern"} 1`, `netpush_ondemand_refused_total{reason="pool_full"} 1`, `netpush_ondemand_refused_total{reason="unassigned"} 1`, `netpush_drain_forced_closes_total{upstream="mx-a",protocol="ondemand"}`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q\n%s", want, b.String())
		}
	}
	for _, ctr := range []string{"ondemand_tcp", "ondemand_udp", "dns_redirect"} {
		raw, err := nft.ListJSON("counter", "inet", tableName, ctr)
		p, _, perr := ParseNamedCounter(raw)
		if err != nil || perr != nil || p == 0 {
			t.Errorf("counter %s: %d %v %v", ctr, p, err, perr)
		}
	}
}

// miniWatch is watch's on-demand path: requests start Consul watches and are answered
// once the targets are in the real sets.
func miniWatch(ctx context.Context, t *testing.T, c Config, nft Runner, cc *ConsulClient, reqs <-chan odRequest) {
	od := &onDemandSources{c: c, cc: cc, have: map[string]bool{}, pending: map[string][]chan error{}}
	m := NewMetrics(ModeEnforce)
	w := &watcher{c: c, nft: nft, tr: NewTracker(0), m: m, seenDrops: map[string]uint64{}}
	updates := make(chan update, 16)
	ready := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-reqs:
			s, isNew, err := od.add(r)
			if err != nil {
				r.reply <- err
				continue
			}
			if isNew {
				go watchService(ctx, s, m, updates)
			}
		case u := <-updates:
			w.tr.Update(u.service, u.targets, time.Now())
			ready[u.service] = true
		}
		od.answer(ready, w.sync(time.Now()))
	}
}

func freePort(t *testing.T) uint16 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func dnsUDP(t *testing.T, server netip.AddrPort, name string) (int, netip.Addr) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	c.Write(dnsQuery(name, dnsTypeA))
	b := make([]byte, 512)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("dns %s via %s: %v", name, server, err)
	}
	b = b[:n]
	rc := int(b[3] & 0xF)
	if rc == 0 && binary.BigEndian.Uint16(b[6:]) > 0 {
		return rc, netip.AddrFrom4([4]byte(b[n-4:]))
	}
	return rc, netip.Addr{}
}

func mustResolve(t *testing.T, server netip.AddrPort, name string) netip.Addr {
	t.Helper()
	rc, ip := dnsUDP(t, server, name)
	if rc != 0 || !ip.IsValid() {
		t.Fatalf("%s: rcode %d", name, rc)
	}
	return ip
}
