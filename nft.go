package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const (
	tableName  = "netblock"
	logPrefix  = "netblock-drop "
	dropSetTTL = "24h"
)

// Target is one ip . port element of a service set.
type Target struct {
	Addr netip.Addr
	Port uint16
}

func (t Target) String() string { return netip.AddrPortFrom(t.Addr, t.Port).String() }

// Runner applies an nft script atomically (nft -f is one transaction) and lists objects.
type Runner interface {
	Apply(script string) error
	ListJSON(args ...string) ([]byte, error)
}

type execRunner struct{ bin string }

func (e execRunner) Apply(script string) error {
	cmd := exec.Command(e.bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if f := currentPeerFile(); f != nil {
		cmd.ExtraFiles = []*os.File{f} // fd 3, see peerCgroupNftPath
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (e execRunner) ListJSON(args ...string) ([]byte, error) {
	out, err := exec.Command(e.bin, append([]string{"-j", "list"}, args...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("nft -j list %s: %v", strings.Join(args, " "), err)
	}
	return out, nil
}

func addrList(as []netip.Addr, v6 bool) string {
	var s []string
	for _, a := range as {
		if u := a.Unmap(); u.Is4() != v6 {
			s = append(s, u.String())
		}
	}
	return strings.Join(s, ", ")
}

func dnsRules(b *strings.Builder, res []netip.Addr, owner string) {
	if v4 := addrList(res, false); v4 != "" {
		fmt.Fprintf(b, "    %sip daddr { %s } meta l4proto { tcp, udp } th dport 53 counter accept\n", owner, v4)
	}
	if v6 := addrList(res, true); v6 != "" {
		fmt.Fprintf(b, "    %sip6 daddr { %s } meta l4proto { tcp, udp } th dport 53 counter accept\n", owner, v6)
	}
}

// lockdownMatch is the rule prefix that limits egress to netpush (egress_lockdown = netpush).
// ok=false means the lockdown rules are left out entirely (fail closed).
//
// With a registered netpush peer in cgroup mode the match is the netpush task cgroup (the
// fd it handed over, same as the Consul exemption) plus its uid, so another process with
// the same uid in a different task (the app can setuid as root) does not get through.
// The uid alone is used only as the fallback (peer registered by uid, netpush_match = uid,
// or no netpush_socket); watch logs that loudly. Before netpush has registered in auto mode
// nothing matches.
func lockdownMatch(c Config, ex Exempt) (m string, ok bool) {
	if !c.EgressLockdown || c.NetpushUID <= 0 {
		return "", true
	}
	if p := ex.Peer; p != nil {
		if p.ByUID {
			return fmt.Sprintf("meta skuid %d ", p.UID), true
		}
		q := *p
		q.UID = c.NetpushUID
		e := ex
		e.Peer = &q
		return e.peerMatch(), true
	}
	if c.NetpushMatch == "uid" || c.NetpushSocket == "" {
		return fmt.Sprintf("meta skuid %d ", c.NetpushUID), true
	}
	return "", false
}

// lockdownUIDOnly reports whether the lockdown currently relies on the uid alone.
func lockdownUIDOnly(c Config, ex Exempt) bool {
	m, ok := lockdownMatch(c, ex)
	return c.EgressLockdown && ok && m != "" && !strings.Contains(m, "cgroupv2")
}

// natRules renders the on-demand redirect and the port-53 redirect (nil when both are off).
//
// TCP to the on-demand pool: REDIRECT in the nat output hook. It works for locally generated
// traffic, netpush needs no capability, and SO_ORIGINAL_DST gives it the original address.
// UDP to the pool: TPROXY in prerouting (loopback traffic passes prerouting on lo). REDIRECT
// would rewrite the destination and an unprivileged process cannot get it back for UDP
// (no SO_ORIGINAL_DST; IP_ORIGDSTADDR returns the rewritten address). TPROXY leaves the
// packet unchanged and only assigns it to the listener, so IP_ORIGDSTADDR is the original.
// The listener must have IP_TRANSPARENT (CAP_NET_ADMIN), so watch creates it and hands it to
// netpush over the peer socket (peer.go); netpush keeps no capability.
func natRules(b *strings.Builder, c Config) {
	if c.OnDemandPool.IsValid() || c.DNSRedirect != 0 {
		b.WriteString("  chain nat_out {\n    type nat hook output priority -100; policy accept;\n")
		if c.OnDemandPool.IsValid() {
			fmt.Fprintf(b, "    ip daddr %s meta l4proto tcp counter name \"ondemand_tcp\" redirect to :%d\n", c.OnDemandPool, c.OnDemandPort)
		}
		if c.DNSRedirect != 0 {
			// netpush itself forwards passthrough queries to the real resolvers.
			fmt.Fprintf(b, "    meta skuid != %d ip daddr != 127.0.0.0/8 meta l4proto { tcp, udp } th dport 53 counter name \"dns_redirect\" redirect to :%d\n", c.NetpushUID, c.DNSRedirect)
		}
		b.WriteString("  }\n")
	}
	if c.OnDemandPool.IsValid() {
		b.WriteString("  chain ondemand_pre {\n    type filter hook prerouting priority mangle; policy accept;\n")
		fmt.Fprintf(b, "    iif \"lo\" ip daddr %s meta l4proto udp counter name \"ondemand_udp\" tproxy ip to 127.0.0.1:%d\n", c.OnDemandPool, c.OnDemandPort)
		b.WriteString("  }\n")
	}
}

func header(b *strings.Builder) {
	// Create-then-delete makes the replace work whether or not the table exists; one transaction.
	fmt.Fprintf(b, "add table inet %s\ndelete table inet %s\n", tableName, tableName)
}

func elemList(ts []Target) string {
	var s []string
	for _, t := range ts {
		s = append(s, fmt.Sprintf("%s . %d", t.Addr.Unmap(), t.Port))
	}
	return strings.Join(s, ", ")
}

func splitFamilies(ts []Target) (v4, v6 []Target) {
	for _, t := range ts {
		if t.Addr.Unmap().Is4() {
			v4 = append(v4, Target{t.Addr.Unmap(), t.Port})
		} else {
			v6 = append(v6, t)
		}
	}
	sortTargets(v4)
	sortTargets(v6)
	return
}

func sortTargets(ts []Target) {
	sort.Slice(ts, func(i, j int) bool {
		if c := ts[i].Addr.Compare(ts[j].Addr); c != 0 {
			return c < 0
		}
		return ts[i].Port < ts[j].Port
	})
}

// RenderRuleset builds the full table. Policy is drop for both families in every mode;
// audit mode only changes the final verdict for packets that would have been dropped.
func RenderRuleset(c Config, targets []Target, ex Exempt) string {
	var b strings.Builder
	header(&b)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)
	b.WriteString("  set svc4 { type ipv4_addr . inet_service; }\n")
	b.WriteString("  set svc6 { type ipv6_addr . inet_service; }\n")
	fmt.Fprintf(&b, "  set drop4 { type inet_proto . ipv4_addr . inet_service; size 4096; flags dynamic,timeout; timeout %s; }\n", dropSetTTL)
	fmt.Fprintf(&b, "  set drop6 { type inet_proto . ipv6_addr . inet_service; size 4096; flags dynamic,timeout; timeout %s; }\n", dropSetTTL)
	b.WriteString("  counter would_drop {}\n  counter allowed_svc {}\n  counter ipv6_rs {}\n  counter consul_exempt {}\n  counter netpush_exempt {}\n")
	if c.OnDemandPool.IsValid() {
		b.WriteString("  counter ondemand_tcp {}\n  counter ondemand_udp {}\n")
	}
	if c.DNSRedirect != 0 {
		b.WriteString("  counter dns_redirect {}\n")
	}
	natRules(&b, c)
	lock, lockOK := lockdownMatch(c, ex)
	b.WriteString("  chain output {\n    type filter hook output priority filter; policy drop;\n")
	b.WriteString("    oif \"lo\" accept\n")
	if c.DNSRedirect != 0 {
		// A query redirected away from a remote resolver keeps the original output interface
		// (oif is not lo) in this hook, so the loopback accept above does not see it.
		fmt.Fprintf(&b, "    ct status dnat ip daddr 127.0.0.1 meta l4proto { tcp, udp } th dport %d accept\n", c.DNSRedirect)
	}
	b.WriteString("    ct state established,related accept\n    ct state invalid drop\n")
	if !c.DNSNone && lockOK {
		dnsRules(&b, c.DNSResolvers, lock)
	}
	// Consul API: only the netblock watch task (its own cgroup, plus skuid with run_as); see cgroup.go.
	if ex.Kind != ExemptNone {
		owner := ex.match()
		for _, ap := range c.ConsulAddrs {
			fam := "ip"
			if !ap.Addr().Is4() {
				fam = "ip6"
			}
			fmt.Fprintf(&b, "    %s%s daddr %s tcp dport %d counter name \"consul_exempt\" accept comment \"consul\"\n", owner, fam, ap.Addr(), ap.Port())
		}
	}
	// Consul API for the netpush task of the same alloc (peer.go). Only rendered with a
	// registered peer; with a cgroup match nft needs the peer fd (execRunner passes it).
	if pm := ex.peerMatch(); pm != "" && (ex.Kind == ExemptCgroup || ex.Peer.ByUID) {
		for _, ap := range c.ConsulAddrs {
			fam := "ip"
			if !ap.Addr().Is4() {
				fam = "ip6"
			}
			fmt.Fprintf(&b, "    %s%s daddr %s tcp dport %d counter name \"netpush_exempt\" accept comment \"netpush consul\"\n", pm, fam, ap.Addr(), ap.Port())
		}
	}
	if !lockOK {
		b.WriteString("    # egress lockdown: waiting for the netpush task to register its cgroup\n")
	}
	if lockOK {
		fmt.Fprintf(&b, "    %smeta l4proto { tcp, udp } ip daddr . th dport @svc4 counter name \"allowed_svc\" accept\n", lock)
		fmt.Fprintf(&b, "    %smeta l4proto { tcp, udp } ip6 daddr . th dport @svc6 counter name \"allowed_svc\" accept\n", lock)
	}
	for _, r := range c.AllowCIDRs {
		if !lockOK {
			break
		}
		fam := "ip"
		if r.Prefix.Addr().Is6() {
			fam = "ip6"
		}
		switch {
		case r.PortLo == 0:
			fmt.Fprintf(&b, "    %s%s daddr %s meta l4proto %s counter accept\n", lock, fam, r.Prefix, r.Proto)
		case r.PortLo == r.PortHi:
			fmt.Fprintf(&b, "    %s%s daddr %s %s dport %d counter accept\n", lock, fam, r.Prefix, r.Proto, r.PortLo)
		default:
			fmt.Fprintf(&b, "    %s%s daddr %s %s dport %d-%d counter accept\n", lock, fam, r.Prefix, r.Proto, r.PortLo, r.PortHi)
		}
	}
	// IPv6 router solicitations: the kernel retries forever with backoff (router_solicitations=-1), which showed up
	// as unexplained drops. Always drop them silently with their own counter (no log, not in would_drop).
	b.WriteString("    icmpv6 type nd-router-solicit counter name \"ipv6_rs\" drop comment \"ipv6 RS noise\"\n")
	// Everything below is a (would-be) drop: record dest per element, count, rate-limited log.
	b.WriteString("    meta nfproto ipv4 meta l4proto { tcp, udp } add @drop4 { meta l4proto . ip daddr . th dport counter }\n")
	b.WriteString("    meta nfproto ipv6 meta l4proto { tcp, udp } add @drop6 { meta l4proto . ip6 daddr . th dport counter }\n")
	fmt.Fprintf(&b, "    counter name \"would_drop\" limit rate 6/minute log prefix %q level warn\n", logPrefix)
	if c.Mode == ModeAudit {
		b.WriteString("    accept comment \"audit mode\"\n")
	} else {
		b.WriteString("    meta l4proto tcp reject with tcp reset\n    reject with icmpx admin-prohibited\n")
	}
	b.WriteString("  }\n}\n")
	v4, v6 := splitFamilies(targets)
	b.WriteString(renderElems(v4, v6, false))
	return b.String()
}

// RenderSetUpdate replaces both service sets in one transaction.
func RenderSetUpdate(targets []Target) string {
	v4, v6 := splitFamilies(targets)
	return renderElems(v4, v6, true)
}

func renderElems(v4, v6 []Target, flush bool) string {
	var b strings.Builder
	if flush {
		fmt.Fprintf(&b, "flush set inet %s svc4\nflush set inet %s svc6\n", tableName, tableName)
	}
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element inet %s svc4 { %s }\n", tableName, elemList(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element inet %s svc6 { %s }\n", tableName, elemList(v6))
	}
	return b.String()
}

// RenderFailClosed is applied when the config is unusable: deny everything except DNS.
func RenderFailClosed(res []netip.Addr) string {
	var b strings.Builder
	header(&b)
	fmt.Fprintf(&b, "table inet %s {\n  chain output {\n    type filter hook output priority filter; policy drop;\n", tableName)
	b.WriteString("    oif \"lo\" accept\n    ct state established,related accept\n")
	dnsRules(&b, res, "")
	fmt.Fprintf(&b, "    limit rate 6/minute log prefix %q level warn\n", logPrefix+"failclosed ")
	b.WriteString("    meta l4proto tcp reject with tcp reset\n    reject with icmpx admin-prohibited\n  }\n}\n")
	return b.String()
}

// DropEntry is one recorded (would-be) drop destination with its counters.
type DropEntry struct {
	Proto   string
	Dest    netip.AddrPort
	Packets uint64
	Bytes   uint64
}

// ParseDropSet parses `nft -j list set inet netblock dropN`.
func ParseDropSet(data []byte) ([]DropEntry, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []DropEntry
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, err
		}
		for _, e := range set.Elem {
			var w struct {
				Elem struct {
					Val struct {
						Concat []json.RawMessage `json:"concat"`
					} `json:"val"`
					Counter struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(e, &w); err != nil || len(w.Elem.Val.Concat) != 3 {
				continue
			}
			var proto, ip string
			var port uint16
			if json.Unmarshal(w.Elem.Val.Concat[0], &proto) != nil ||
				json.Unmarshal(w.Elem.Val.Concat[1], &ip) != nil ||
				json.Unmarshal(w.Elem.Val.Concat[2], &port) != nil {
				continue
			}
			a, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			out = append(out, DropEntry{proto, netip.AddrPortFrom(a, port), w.Elem.Counter.Packets, w.Elem.Counter.Bytes})
		}
	}
	return out, nil
}

// ParseNamedCounter parses `nft -j list counter inet netblock <name>`.
func ParseNamedCounter(data []byte) (packets, bytes uint64, err error) {
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		return
	}
	for _, o := range doc.Nftables {
		if o.Counter != nil {
			return o.Counter.Packets, o.Counter.Bytes, nil
		}
	}
	return 0, 0, fmt.Errorf("no counter in output")
}

// ParseServiceSet parses `nft -j list set inet netblock svc4|svc6` (ip . port elements).
func ParseServiceSet(data []byte) ([]Target, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Target
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, err
		}
		for _, e := range set.Elem {
			var c struct {
				Concat []json.RawMessage `json:"concat"`
			}
			if json.Unmarshal(e, &c) != nil || len(c.Concat) != 2 {
				continue
			}
			var ip string
			var port uint16
			if json.Unmarshal(c.Concat[0], &ip) != nil || json.Unmarshal(c.Concat[1], &port) != nil {
				continue
			}
			if a, err := netip.ParseAddr(ip); err == nil {
				out = append(out, Target{a, port})
			}
		}
	}
	return out, nil
}
