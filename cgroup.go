package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"
)

// Consul exemption: which local sockets may reach the Consul API addresses.
//
// v0.3 matched only `meta skuid <run_as>`. Any root process in the same network namespace
// (the app task) could setuid to that uid and get through. From v0.3.2 the watch task adds
// `socket cgroupv2 level N "<its own cgroup>"` (plus the skuid match when run_as is set), so
// only processes inside the watch task's cgroup are exempt.
//
// The cgroup is resolved at runtime from /proc/self/cgroup by the watch process itself and
// the rule is applied from inside that process's cgroup namespace. Docker tasks on Nomad get a
// private cgroup namespace, so the path is "/" (level 0); kernels with the nft_socket cgroupns
// fix (upstream 6.12, RHEL 9 5.14.0-5xx+) resolve the level relative to that namespace. Tasks
// with a host cgroup namespace see the full path (e.g. nomad.slice/<alloc>.<task>.scope).
// netblock-init runs in a different container (cgroup) and cannot name the watch cgroup, so
// init installs no exemption when run_as is set; watch adds it in its first full re-apply.
type ExemptKind int

const (
	ExemptNone   ExemptKind = iota // no Consul accept rule at all (init with run_as)
	ExemptOpen                     // any local socket (v0.2 behaviour, no run_as and no cgroup)
	ExemptUID                      // meta skuid only (fallback)
	ExemptCgroup                   // socket cgroupv2 (+ meta skuid when UID > 0)
)

type Exempt struct {
	Kind        ExemptKind
	UID         int
	CgroupPath  string // as passed to nft: relative to /sys/fs/cgroup, "/" for the namespace root
	CgroupLevel int
}

func (e Exempt) String() string {
	switch e.Kind {
	case ExemptNone:
		return "none"
	case ExemptOpen:
		return "open (any local socket)"
	case ExemptUID:
		return fmt.Sprintf("uid %d", e.UID)
	}
	s := fmt.Sprintf("cgroupv2 level %d %q", e.CgroupLevel, e.CgroupPath)
	if e.UID > 0 {
		s += fmt.Sprintf(" + uid %d", e.UID)
	}
	return s
}

// match returns the nft match prefix for the Consul rules ("" for open).
func (e Exempt) match() string {
	switch e.Kind {
	case ExemptUID:
		return fmt.Sprintf("meta skuid %d ", e.UID)
	case ExemptCgroup:
		s := fmt.Sprintf("socket cgroupv2 level %d %q ", e.CgroupLevel, e.CgroupPath)
		if e.UID > 0 {
			s += fmt.Sprintf("meta skuid %d ", e.UID)
		}
		return s
	}
	return ""
}

// initExempt is what netblock init installs: nothing when run_as is set (watch adds its own
// cgroup match), the open v0.2 rule otherwise.
func initExempt(c Config) Exempt {
	if c.RunAsUID > 0 {
		return Exempt{Kind: ExemptNone}
	}
	return Exempt{Kind: ExemptOpen}
}

// uidFallback is used when the cgroup cannot be resolved or does not match.
func uidFallback(c Config) Exempt {
	if c.RunAsUID > 0 {
		return Exempt{Kind: ExemptUID, UID: c.RunAsUID}
	}
	return Exempt{Kind: ExemptOpen}
}

// ParseSelfCgroup returns the cgroup v2 path from /proc/self/cgroup content ("0::<path>").
func ParseSelfCgroup(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			if p == "" || !strings.HasPrefix(p, "/") {
				return "", fmt.Errorf("unexpected cgroup v2 path %q", p)
			}
			return p, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no cgroup v2 entry (0::) in /proc/self/cgroup (cgroup v1 host?)")
}

// CgroupForNft turns a /proc/self/cgroup path into the nft path and level, and checks that
// the directory exists under root (normally /sys/fs/cgroup) on a cgroup2 mount.
func CgroupForNft(p, root string) (string, int, error) {
	if strings.HasSuffix(p, " (deleted)") {
		return "", 0, fmt.Errorf("cgroup %q was deleted", p)
	}
	if strings.ContainsAny(p, "\"\\\n") {
		return "", 0, fmt.Errorf("cgroup path %q has characters nft cannot take", p)
	}
	clean := strings.Trim(path.Clean(p), "/")
	nftPath, level := "/", 0
	if clean != "" {
		nftPath, level = clean, strings.Count(clean, "/")+1
	}
	if _, err := os.Stat(path.Join(root, "cgroup.controllers")); err != nil {
		return "", 0, fmt.Errorf("%s is not a cgroup v2 mount: %v", root, err)
	}
	if _, err := os.Stat(path.Join(root, clean)); err != nil {
		return "", 0, fmt.Errorf("cgroup %s does not exist (yet) under %s: %v", p, root, err)
	}
	return nftPath, level, nil
}

// resolveExempt decides the watch exemption. exempt_match=uid skips cgroup matching.
func resolveExempt(c Config, procCgroup, root string) (Exempt, error) {
	if c.ExemptMatch == "uid" {
		return uidFallback(c), errors.New("exempt_match = uid")
	}
	f, err := os.Open(procCgroup)
	if err != nil {
		return uidFallback(c), err
	}
	defer f.Close()
	p, err := ParseSelfCgroup(f)
	if err != nil {
		return uidFallback(c), err
	}
	np, lvl, err := CgroupForNft(p, root)
	if err != nil {
		return uidFallback(c), err
	}
	uid := 0
	if c.RunAsUID > 0 {
		uid = c.RunAsUID
	}
	return Exempt{Kind: ExemptCgroup, UID: uid, CgroupPath: np, CgroupLevel: lvl}, nil
}

// probeExempt opens a TCP connection attempt to each Consul address (stopping at the first
// success) so the consul_exempt counter can show whether the rule matches our own sockets.
// A SYN that hits the rule counts even if Consul itself is down.
func probeExempt(ctx context.Context, addrs []netip.AddrPort, timeout time.Duration) {
	for _, a := range addrs {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", a.String())
		if err == nil {
			conn.Close()
			return
		}
	}
}
