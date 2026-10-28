package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func parseNP(t *testing.T, s string) (NetpushConfig, error) {
	t.Helper()
	return ParseNetpushConfig(strings.NewReader(s), func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.0.0.2")}
	})
}

func TestNetpushConfigParse(t *testing.T) {
	c, err := parseNP(t, `
# comment
consul_addrs = 10.0.0.10:8501, 10.0.0.11:8501
upstream = mysql source=consul:mysql-prod@fi port=3306
upstream = cache source=nomad:redis@apps port=6379 bind=127.0.1.50 balance=first
upstream = metrics source=consul:statsd port=8125 protocol=udp udp_idle=30s
upstream = web source=consul:web port=80 only_passing=false balance=round_robin
drain_timeout = 0
dns_listen = 127.0.0.1:53
dns_upstream = auto
dns_suffixes = service.consul
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Upstreams) != 4 || c.DrainTimeout != 0 || len(c.ConsulAddrs) != 2 {
		t.Fatalf("%+v", c)
	}
	u := c.Upstreams
	if u[0].Consul == nil || u[0].Consul.Name != "mysql-prod" || u[0].Consul.DC != "fi" || u[0].Balance != BalanceLeastConn || !u[0].OnlyPassing || u[0].Protocol != "tcp" {
		t.Fatalf("mysql: %+v", u[0])
	}
	if u[1].Nomad == nil || u[1].Bind != netip.MustParseAddrPort("127.0.1.50:6379") || u[1].Balance != BalanceFirst {
		t.Fatalf("cache: %+v", u[1])
	}
	if u[2].Protocol != "udp" || u[2].UDPIdle != 30*time.Second {
		t.Fatalf("udp: %+v", u[2])
	}
	if u[3].OnlyPassing || u[3].Balance != BalanceRoundRobin {
		t.Fatalf("web: %+v", u[3])
	}
	// Auto binds come from the pool in order and skip the pinned .50.
	for _, x := range u {
		if !c.BindPool.Contains(x.Bind.Addr()) {
			t.Fatalf("%s bind %s outside pool", x.Name, x.Bind)
		}
	}
	if u[0].Bind.Addr() != netip.MustParseAddr("127.0.1.1") {
		t.Fatalf("first auto bind %s", u[0].Bind)
	}
	if len(c.DNSUpstreams) != 1 || c.DNSUpstreams[0].String() != "10.0.0.2" {
		t.Fatalf("dns auto must skip loopback: %v", c.DNSUpstreams)
	}
}

func TestNetpushConfigErrors(t *testing.T) {
	for _, bad := range []string{
		"upstream = x source=consul:a port=1",                                                                  // consul without consul_addrs
		"upstream = x source=nomad:a port=1 only_passing=false",                                                // nomad has no health
		"upstream = x source=nomad:a",                                                                          // no port
		"upstream = x source=nomad:a port=1\nupstream = x source=nomad:b port=2",                               // dup name
		"upstream = x source=nomad:a port=1 bind=127.0.1.9\nupstream = y source=nomad:b port=1 bind=127.0.1.9", // clash
		"upstream = Bad_Name! source=nomad:a port=1",
		"upstream = x source=nomad:a port=1 balance=random",
		"upstream = x source=nomad:a port=1 protocol=sctp",
		"bogus = 1",
		"dns_default = maybe",
	} {
		if _, err := parseNP(t, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// Same ip:port on tcp and udp is fine.
	if _, err := parseNP(t, "upstream = d source=nomad:a port=53 bind=127.0.1.9\nupstream = du source=nomad:a port=53 bind=127.0.1.9 protocol=udp"); err != nil {
		t.Errorf("tcp+udp on same ip:port: %v", err)
	}
}
