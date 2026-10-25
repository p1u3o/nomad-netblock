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

// Mode selects whether non-allowed egress is rejected (enforce) or only counted (audit).
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

// StaticRule is one allow_cidrs entry: "proto cidr [port|lo-hi]".
type StaticRule struct {
	Proto  string // tcp | udp
	Prefix netip.Prefix
	PortLo uint16 // 0 = any port
	PortHi uint16
}

// ServiceRef is one allow_services entry: "name", "name@dc", "tag.name" or "tag.name@dc".
type ServiceRef struct {
	Name string
	Tag  string
	DC   string
}

func (s ServiceRef) String() string {
	out := s.Name
	if s.Tag != "" {
		out = s.Tag + "." + out
	}
	if s.DC != "" {
		out += "@" + s.DC
	}
	return out
}

// Config is the parsed /local/netblock.conf (rendered from nomad/jobs/<job>).
type Config struct {
	Mode               Mode
	AllowCIDRs         []StaticRule
	AllowServices      []ServiceRef
	AllowNomadServices []NomadRef
	NomadAddr          string       // "" = Task API socket, then $NOMAD_ADDR; or unix:///path, https://host:port
	NomadTokenFile     string       // used when $NOMAD_TOKEN is unset
	DNSResolvers       []netip.Addr // empty + DNSNone = no DNS
	DNSNone            bool
	IncludeCritical    bool
	RemovalGrace       time.Duration
	ConsulAddrs        []netip.AddrPort // https endpoints, tried in order with failover
	ConsulCAFile       string
	ConsulTokenFile    string
	ConsulServer       string // TLS server name override
	MetricsAddr        string
	InitRequireConsul  bool
	RunAsUID           int // >0: drop to this uid/gid with only CAP_NET_ADMIN; Consul rule matches skuid
	RunAsGID           int
	ExemptMatch        string // "auto" (cgroupv2 of the watch task, uid fallback) or "uid"
}

func defaultConfig() Config {
	return Config{
		Mode:              ModeEnforce,
		IncludeCritical:   true,
		RemovalGrace:      60 * time.Second,
		ConsulCAFile:      "/local/consul-ca.pem",
		ConsulTokenFile:   "/secrets/consul.token",
		NomadTokenFile:    "/secrets/nomad_token",
		MetricsAddr:       ":9810",
		InitRequireConsul: true,
		RunAsUID:          -1,
		RunAsGID:          -1,
		ExemptMatch:       "auto",
	}
}

func splitList(v string) []string {
	f := func(r rune) bool { return r == ';' || r == ',' || r == '\n' }
	var out []string
	for _, p := range strings.FieldsFunc(v, f) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseConfig reads key=value lines. Unknown keys are an error so typos fail closed.
// readResolv supplies resolv.conf nameservers when dns_resolver is unset.
func ParseConfig(r io.Reader, readResolv func() []netip.Addr) (Config, error) {
	c := defaultConfig()
	seen := map[string]bool{}
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
		if k == "egress_allow" { // v0.1 name
			k = "allow_cidrs"
		}
		if k == "consul_addr" { // v0.2.0 name (single address)
			k = "consul_addrs"
		}
		if seen[k] {
			return c, fmt.Errorf("line %d: duplicate key %q", ln, k)
		}
		seen[k] = true
		var err error
		switch k {
		case "mode":
			switch Mode(v) {
			case ModeEnforce, ModeAudit:
				c.Mode = Mode(v)
			default:
				err = fmt.Errorf("mode must be enforce or audit, got %q", v)
			}
		case "allow_cidrs":
			for _, e := range splitList(v) {
				var sr StaticRule
				if sr, err = parseStatic(e); err != nil {
					break
				}
				c.AllowCIDRs = append(c.AllowCIDRs, sr)
			}
		case "allow_services":
			for _, e := range splitList(v) {
				var s ServiceRef
				if s, err = parseService(e); err != nil {
					break
				}
				c.AllowServices = append(c.AllowServices, s)
			}
		case "allow_nomad_services":
			for _, e := range splitList(v) {
				var s NomadRef
				if s, err = parseNomadService(e); err != nil {
					break
				}
				c.AllowNomadServices = append(c.AllowNomadServices, s)
			}
		case "nomad_addr":
			c.NomadAddr = v
		case "nomad_token_file":
			c.NomadTokenFile = v
		case "dns_resolver":
			if v == "none" {
				c.DNSNone = true
				break
			}
			for _, e := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
				a, perr := netip.ParseAddr(e)
				if perr != nil {
					err = fmt.Errorf("dns_resolver %q: %v", e, perr)
					break
				}
				c.DNSResolvers = append(c.DNSResolvers, a)
			}
		case "include_critical":
			c.IncludeCritical, err = strconv.ParseBool(v)
		case "removal_grace":
			c.RemovalGrace, err = time.ParseDuration(v)
			if err == nil && c.RemovalGrace < 0 {
				err = fmt.Errorf("removal_grace must be >= 0")
			}
		case "consul_addrs":
			for _, e := range splitList(v) {
				ap, perr := netip.ParseAddrPort(e)
				if perr != nil {
					err = fmt.Errorf("consul_addrs entry %q must be ip:port: %v", e, perr)
					break
				}
				c.ConsulAddrs = append(c.ConsulAddrs, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			}
		case "run_as":
			u, g, hasG := strings.Cut(v, ":")
			c.RunAsUID, err = strconv.Atoi(u)
			c.RunAsGID = c.RunAsUID
			if err == nil && hasG {
				c.RunAsGID, err = strconv.Atoi(g)
			}
			if err == nil && (c.RunAsUID <= 0 || c.RunAsGID <= 0) {
				err = fmt.Errorf("run_as must be uid[:gid] > 0, got %q", v)
			}
		case "exempt_match":
			if v != "auto" && v != "uid" {
				err = fmt.Errorf("exempt_match must be auto or uid, got %q", v)
			}
			c.ExemptMatch = v
		case "consul_ca_file":
			c.ConsulCAFile = v
		case "consul_token_file":
			c.ConsulTokenFile = v
		case "consul_tls_server_name":
			c.ConsulServer = v
		case "init_require_consul":
			c.InitRequireConsul, err = strconv.ParseBool(v)
		case "metrics_addr":
			c.MetricsAddr = v
		default:
			err = fmt.Errorf("unknown key %q", k)
		}
		if err != nil {
			return c, fmt.Errorf("line %d: %v", ln, err)
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	if !seen["allow_cidrs"] && !seen["allow_services"] && !seen["allow_nomad_services"] {
		return c, fmt.Errorf("config has none of allow_cidrs, allow_services, allow_nomad_services")
	}
	if len(c.AllowServices) > 0 && len(c.ConsulAddrs) == 0 {
		return c, fmt.Errorf("allow_services set but consul_addrs missing")
	}
	if !c.DNSNone && len(c.DNSResolvers) == 0 && readResolv != nil {
		c.DNSResolvers = readResolv()
	}
	return c, nil
}

func parseStatic(e string) (StaticRule, error) {
	f := strings.Fields(e)
	if len(f) < 2 || len(f) > 3 {
		return StaticRule{}, fmt.Errorf("allow_cidrs entry %q: want 'proto cidr [port|lo-hi]'", e)
	}
	r := StaticRule{Proto: f[0]}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return r, fmt.Errorf("allow_cidrs entry %q: proto must be tcp or udp", e)
	}
	p, err := netip.ParsePrefix(f[1])
	if err != nil {
		a, aerr := netip.ParseAddr(f[1])
		if aerr != nil {
			return r, fmt.Errorf("allow_cidrs entry %q: bad cidr", e)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Bits() == 0 {
		return r, fmt.Errorf("allow_cidrs entry %q: /0 is not allowed", e)
	}
	r.Prefix = p.Masked()
	if len(f) == 3 {
		lo, hi, ok := strings.Cut(f[2], "-")
		l, err := strconv.ParseUint(lo, 10, 16)
		if err != nil || l == 0 {
			return r, fmt.Errorf("allow_cidrs entry %q: bad port", e)
		}
		h := l
		if ok {
			if h, err = strconv.ParseUint(hi, 10, 16); err != nil || h < l {
				return r, fmt.Errorf("allow_cidrs entry %q: bad port range", e)
			}
		}
		r.PortLo, r.PortHi = uint16(l), uint16(h)
	}
	return r, nil
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func parseService(e string) (ServiceRef, error) {
	var s ServiceRef
	rest, dc, hasDC := strings.Cut(e, "@")
	if hasDC {
		s.DC = dc
	}
	if tag, name, ok := strings.Cut(rest, "."); ok {
		s.Tag, s.Name = tag, name
	} else {
		s.Name = rest
	}
	if !validName(s.Name) || (s.Tag != "" && !validName(s.Tag)) || (hasDC && !validName(s.DC)) {
		return s, fmt.Errorf("allow_services entry %q: want name, tag.name, name@dc or tag.name@dc", e)
	}
	return s, nil
}

// ParseResolvConf returns nameserver addresses from resolv.conf content.
func ParseResolvConf(r io.Reader) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}
