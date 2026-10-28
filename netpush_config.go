package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const defaultNetpushConf = "/local/netpush.conf"

// Balance is the per-upstream target selection policy.
type Balance string

const (
	BalanceLeastConn  Balance = "least_conn"
	BalanceRoundRobin Balance = "round_robin"
	BalanceFirst      Balance = "first"
)

// Upstream is one declared upstream: a local listener forwarded to a discovered service.
type Upstream struct {
	Name        string         // DNS name the app uses, also the metrics label
	Consul      *ServiceRef    // source = consul:name[@dc] or consul:tag.name[@dc]
	Nomad       *NomadRef      // source = nomad:name[@namespace]
	Bind        netip.AddrPort // local listener; IP auto-assigned from bind_pool when not given
	BindAuto    bool
	Protocol    string // tcp or udp
	Balance     Balance
	OnlyPassing bool
	UDPIdle     time.Duration
	MaxConns    int // open connections/sessions at once (0 = no limit)
}

func (u Upstream) SourceString() string {
	if u.Consul != nil {
		return "consul:" + u.Consul.String()
	}
	return u.Nomad.String()
}

// NetpushConfig is /local/netpush.conf. Same key = value format as netblock.conf; the
// upstream key may repeat (one line per upstream).
type NetpushConfig struct {
	Upstreams       []Upstream
	BindPool        netip.Prefix
	ConsulAddrs     []netip.AddrPort
	ConsulCAFile    string
	ConsulTokenFile string // Consul token file (read on every request; SIGHUP restarts blocking queries)
	NetblockSocket  string // netblock watch socket for the Consul exemption ("" = off)
	ConsulServer    string
	NomadAddr       string
	NomadTokenFile  string
	DrainTimeout    time.Duration // 0 = never force-close draining connections
	ConnectTimeout  time.Duration
	KeepAlive       time.Duration
	ConnectRetries  int
	MetricsAddr     string
	DNSListen       string       // "" = no DNS resolver
	DNSUpstreams    []netip.Addr // for names that are not upstreams
	DNSDefault      string       // passthrough (standalone) or nxdomain
	DNSSuffixes     []string     // extra suffixes answered for upstream names, e.g. service.consul

	// On-demand mode (netpush_ondemand.go).
	OnDemand         bool
	OnDemandPool     netip.Prefix
	OnDemandMax      int
	OnDemandAllow    []string // name patterns (path.Match); empty = any
	OnDemandSource   string   // consul or nomad
	OnDemandNomadNS  string
	OnDemandPort     uint16 // listener on 127.0.0.1 (TCP here, UDP socket from netblock watch)
	OnDemandUDPIdle  time.Duration
	OnDemandMaxConns int
}

func defaultNetpushConfig() NetpushConfig {
	return NetpushConfig{
		BindPool:        netip.MustParsePrefix("127.0.1.0/24"),
		ConsulCAFile:    "/local/consul-ca.pem",
		ConsulTokenFile: "/secrets/consul_token",
		NomadTokenFile:  "/secrets/nomad_token",
		DrainTimeout:    5 * time.Minute,
		ConnectTimeout:  3 * time.Second,
		KeepAlive:       30 * time.Second,
		ConnectRetries:  2,
		MetricsAddr:     "127.0.0.1:9811",
		DNSDefault:      "passthrough",
		OnDemandPool:    netip.MustParsePrefix("127.0.3.0/24"),
		OnDemandMax:     64,
		OnDemandSource:  "consul",
		OnDemandPort:    15001,
		OnDemandUDPIdle: 60 * time.Second,
	}
}

// ParseNetpushConfig reads the config. Unknown keys are an error. readResolv supplies
// resolv.conf nameservers for dns_upstream = auto (loopback entries are skipped, since in
// standalone mode resolv.conf points at netpush itself).
func ParseNetpushConfig(r io.Reader, readResolv func() []netip.Addr) (NetpushConfig, error) {
	c := defaultNetpushConfig()
	seen := map[string]bool{}
	dnsUp := "auto"
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("line %d: expected key=value", ln)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "upstream" && seen[k] {
			return c, fmt.Errorf("line %d: duplicate key %q", ln, k)
		}
		seen[k] = true
		var err error
		switch k {
		case "upstream":
			var u Upstream
			if u, err = parseUpstream(v); err == nil {
				c.Upstreams = append(c.Upstreams, u)
			}
		case "bind_pool":
			c.BindPool, err = netip.ParsePrefix(v)
			if err == nil && (!c.BindPool.Addr().Is4() || !c.BindPool.Addr().IsLoopback()) {
				err = fmt.Errorf("bind_pool must be an IPv4 loopback prefix")
			}
		case "consul_addrs", "consul_addr":
			c.ConsulAddrs = nil
			for _, e := range splitList(v) {
				var ap netip.AddrPort
				if ap, err = netip.ParseAddrPort(e); err != nil {
					break
				}
				c.ConsulAddrs = append(c.ConsulAddrs, ap)
			}
		case "consul_ca_file":
			c.ConsulCAFile = v
		case "consul_token_file":
			c.ConsulTokenFile = v
		case "netblock_exempt_socket":
			c.NetblockSocket = v
		case "consul_tls_server_name":
			c.ConsulServer = v
		case "nomad_addr":
			c.NomadAddr = v
		case "nomad_token_file":
			c.NomadTokenFile = v
		case "drain_timeout":
			c.DrainTimeout, err = parseDur(v, true)
		case "connect_timeout":
			c.ConnectTimeout, err = parseDur(v, false)
		case "tcp_keepalive":
			c.KeepAlive, err = parseDur(v, true)
		case "connect_retries":
			c.ConnectRetries, err = strconv.Atoi(v)
			if err == nil && (c.ConnectRetries < 0 || c.ConnectRetries > 10) {
				err = fmt.Errorf("connect_retries must be 0..10")
			}
		case "metrics_addr":
			c.MetricsAddr = v
		case "dns_listen":
			if v != "" && v != "none" {
				if _, err = netip.ParseAddrPort(v); err == nil {
					c.DNSListen = v
				}
			}
		case "dns_upstream":
			dnsUp = v
		case "dns_default":
			if v != "passthrough" && v != "nxdomain" {
				err = fmt.Errorf("dns_default must be passthrough or nxdomain")
			}
			c.DNSDefault = v
		case "dns_suffixes":
			for _, s := range splitList(v) {
				c.DNSSuffixes = append(c.DNSSuffixes, strings.Trim(strings.ToLower(s), "."))
			}
		case "ondemand":
			c.OnDemand, err = strconv.ParseBool(v)
		case "ondemand_pool":
			c.OnDemandPool, err = parseOnDemandPool(v)
		case "ondemand_max":
			c.OnDemandMax, err = strconv.Atoi(v)
			if err == nil && (c.OnDemandMax < 1 || c.OnDemandMax > 4096) {
				err = fmt.Errorf("must be 1..4096")
			}
		case "ondemand_allow":
			c.OnDemandAllow, err = parsePatterns(v)
		case "ondemand_source":
			src, ns, hasNS := strings.Cut(v, "@")
			switch {
			case src == "consul" && !hasNS:
			case src == "nomad" && (!hasNS || validName(ns)):
				c.OnDemandNomadNS = ns
			default:
				err = fmt.Errorf("want consul, nomad or nomad@namespace")
			}
			c.OnDemandSource = src
		case "ondemand_port":
			c.OnDemandPort, err = parsePort(v)
		case "ondemand_udp_idle":
			c.OnDemandUDPIdle, err = parseDur(v, false)
		case "ondemand_max_conns":
			c.OnDemandMaxConns, err = strconv.Atoi(v)
			if err == nil && c.OnDemandMaxConns < 0 {
				err = fmt.Errorf("must be >= 0")
			}
		default:
			err = fmt.Errorf("unknown key")
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %s: %v", ln, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	switch dnsUp {
	case "auto":
		for _, a := range readResolv() {
			if !a.IsLoopback() {
				c.DNSUpstreams = append(c.DNSUpstreams, a)
			}
		}
	case "none":
	default:
		for _, e := range splitList(dnsUp) {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return c, fmt.Errorf("dns_upstream: %v", err)
			}
			c.DNSUpstreams = append(c.DNSUpstreams, a)
		}
	}
	if len(c.Upstreams) == 0 && !c.OnDemand {
		return c, fmt.Errorf("no upstream configured")
	}
	if c.OnDemand {
		switch {
		case c.NetblockSocket == "":
			return c, fmt.Errorf("ondemand needs netblock (netblock_exempt_socket): netblock redirects the pool to netpush")
		case c.DNSListen == "":
			return c, fmt.Errorf("ondemand needs dns_listen")
		case c.OnDemandPool.Overlaps(c.BindPool):
			return c, fmt.Errorf("ondemand_pool %s overlaps bind_pool %s", c.OnDemandPool, c.BindPool)
		case c.OnDemandSource == "consul" && len(c.ConsulAddrs) == 0:
			return c, fmt.Errorf("ondemand_source = consul but consul_addrs is not set")
		}
	}
	if err := assignBinds(&c); err != nil {
		return c, err
	}
	for _, u := range c.Upstreams {
		if u.Consul != nil && len(c.ConsulAddrs) == 0 {
			return c, fmt.Errorf("upstream %s uses consul but consul_addrs is not set", u.Name)
		}
	}
	return c, nil
}

func parseDur(v string, zeroOK bool) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, err
	}
	if d < 0 || (d == 0 && !zeroOK) {
		return 0, fmt.Errorf("bad duration %q", v)
	}
	return d, nil
}

// parseUpstream parses "name source=consul:svc[@dc] port=3306 [bind=127.0.1.5]
// [protocol=tcp|udp] [balance=least_conn|round_robin|first] [only_passing=true|false] [udp_idle=60s]
// [max_conns=N]".
func parseUpstream(v string) (Upstream, error) {
	f := strings.Fields(v)
	if len(f) == 0 || strings.Contains(f[0], "=") {
		return Upstream{}, fmt.Errorf("want: name source=... port=...")
	}
	u := Upstream{Name: strings.ToLower(f[0]), Protocol: "tcp", Balance: BalanceLeastConn, OnlyPassing: true, UDPIdle: 60 * time.Second, BindAuto: true}
	if !validDNSName(u.Name) {
		return u, fmt.Errorf("bad upstream name %q", f[0])
	}
	var port int
	for _, kv := range f[1:] {
		k, val, ok := strings.Cut(kv, "=")
		if !ok {
			return u, fmt.Errorf("%s: expected key=value, got %q", u.Name, kv)
		}
		var err error
		switch k {
		case "source":
			kind, ref, _ := strings.Cut(val, ":")
			switch kind {
			case "consul":
				var s ServiceRef
				if s, err = parseService(ref); err == nil {
					u.Consul = &s
				}
			case "nomad":
				var n NomadRef
				if n, err = parseNomadService(ref); err == nil {
					u.Nomad = &n
				}
			default:
				err = fmt.Errorf("source must be consul:<service> or nomad:<service>")
			}
		case "port":
			port, err = strconv.Atoi(val)
			if err == nil && (port < 0 || port > 65535) {
				err = fmt.Errorf("bad port")
			}
		case "bind":
			var a netip.Addr
			if a, err = netip.ParseAddr(val); err == nil {
				if !a.IsLoopback() {
					err = fmt.Errorf("bind must be a loopback address")
				}
				u.Bind, u.BindAuto = netip.AddrPortFrom(a, 0), false
			}
		case "protocol":
			if val != "tcp" && val != "udp" {
				err = fmt.Errorf("protocol must be tcp or udp")
			}
			u.Protocol = val
		case "balance":
			switch Balance(val) {
			case BalanceLeastConn, BalanceRoundRobin, BalanceFirst:
				u.Balance = Balance(val)
			default:
				err = fmt.Errorf("balance must be least_conn, round_robin or first")
			}
		case "only_passing":
			u.OnlyPassing, err = strconv.ParseBool(val)
		case "udp_idle":
			u.UDPIdle, err = parseDur(val, false)
		case "max_conns":
			u.MaxConns, err = strconv.Atoi(val)
			if err == nil && u.MaxConns < 0 {
				err = fmt.Errorf("max_conns must be >= 0")
			}
		default:
			err = fmt.Errorf("unknown option %q", k)
		}
		if err != nil {
			return u, fmt.Errorf("upstream %s: %v", u.Name, err)
		}
	}
	if u.Consul == nil && u.Nomad == nil {
		return u, fmt.Errorf("upstream %s: source is required", u.Name)
	}
	if port == 0 && !testAllowPort0 {
		return u, fmt.Errorf("upstream %s: port is required", u.Name)
	}
	if u.Nomad != nil && !u.OnlyPassing {
		return u, fmt.Errorf("upstream %s: only_passing applies to consul sources only", u.Name)
	}
	u.Bind = netip.AddrPortFrom(u.Bind.Addr(), uint16(port))
	return u, nil
}

// testAllowPort0 lets tests bind ephemeral ports.
var testAllowPort0 = false

func validDNSName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || (r == '-' && i > 0 && i < len(s)-1)
		if !ok {
			return false
		}
	}
	return true
}

// assignBinds gives each auto upstream the next free IP of bind_pool (from .1, in declaration
// order, so the mapping is stable for a given config), and rejects duplicate names and
// clashing ip:port/protocol pairs.
func assignBinds(c *NetpushConfig) error {
	names := map[string]bool{}
	used := map[netip.Addr]bool{}
	for _, u := range c.Upstreams {
		if names[u.Name] {
			return fmt.Errorf("duplicate upstream %s", u.Name)
		}
		names[u.Name] = true
		if !u.BindAuto {
			used[u.Bind.Addr()] = true
		}
	}
	next := c.BindPool.Masked().Addr().Next()
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if !u.BindAuto {
			continue
		}
		for used[next] {
			next = next.Next()
		}
		if !c.BindPool.Contains(next) {
			return fmt.Errorf("bind_pool %s exhausted", c.BindPool)
		}
		u.Bind = netip.AddrPortFrom(next, u.Bind.Port())
		used[next] = true
		next = next.Next()
	}
	socks := map[string]string{}
	for _, u := range c.Upstreams {
		k := u.Protocol + "/" + u.Bind.String()
		if other, ok := socks[k]; ok && u.Bind.Port() != 0 {
			return fmt.Errorf("upstreams %s and %s both bind %s", other, u.Name, k)
		}
		socks[k] = u.Name
	}
	return nil
}
