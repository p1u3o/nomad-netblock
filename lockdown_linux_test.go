//go:build linux

package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLockdownCgroupNft checks egress_lockdown against the real kernel: only sockets of the
// registered netpush cgroup with the netpush uid get out; the same uid in another cgroup and
// root in the netpush cgroup are rejected. Run as root in a throwaway netns:
//
//	go test -c -o /tmp/np.test && sudo NETBLOCK_NFT_TEST=1 unshare -n /tmp/np.test -test.run LockdownCgroupNft -test.v
func TestLockdownCgroupNft(t *testing.T) {
	if os.Getenv("NETBLOCK_NFT_TEST") != "1" || os.Getuid() != 0 {
		t.Skip("needs root in a throwaway netns and NETBLOCK_NFT_TEST=1 (see comment)")
	}
	// A veth whose peer end has no address: packets to 10.9.0.2 leave on v0 (not lo) and are
	// never answered. Allowed connects time out, rejected ones fail at once with a reset.
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "nbv0", "type", "veth", "peer", "name", "nbv1"},
		{"addr", "add", "10.9.0.1/24", "dev", "nbv0"},
		{"link", "set", "nbv0", "up"},
		{"link", "set", "nbv1", "up"},
		{"neigh", "replace", "10.9.0.2", "lladdr", "02:00:00:00:00:02", "dev", "nbv0"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	base, err := os.MkdirTemp("/sys/fs/cgroup", "nblock-test-")
	if err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	np, other := filepath.Join(base, "np"), filepath.Join(base, "other")
	for _, d := range []string{np, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.Remove(np); os.Remove(other); os.Remove(base) })
	rel := strings.TrimPrefix(np, "/sys/fs/cgroup/")
	level := strings.Count(rel, "/") + 1

	f, err := os.Open(np)
	if err != nil {
		t.Fatal(err)
	}
	id, err := cgroupID(np)
	if err != nil {
		t.Fatal(err)
	}
	old := setPeerFile(f)
	t.Cleanup(func() { setPeerFile(old); f.Close() })

	c := defaultConfig()
	c.Mode = ModeEnforce
	c.DNSNone = true
	c.NetpushSocket = "/nonexistent"
	c.NetpushUID = 65533
	c.EgressLockdown = true
	c.AllowCIDRs = []StaticRule{{Prefix: netip.MustParsePrefix("10.9.0.2/32"), Proto: "tcp", PortLo: 443, PortHi: 443}}
	nft := execRunner{"nft"}
	exe, _ := os.Executable()
	dial := func(cg string, uid int) error {
		cmd := exec.Command("sh", "-c", `echo $$ > "$0/cgroup.procs" && exec setpriv --reuid=$1 --regid=$1 --clear-groups "$2" -test.run '^TestLockdownDialHelper$'`, cg, strconv.Itoa(uid), exe)
		cmd.Env = append(os.Environ(), "NB_LOCKDOWN_DIAL=10.9.0.2:443")
		out, err := cmd.CombinedOutput()
		switch s := string(out); {
		case strings.Contains(s, "DIAL timeout"):
			return nil
		case strings.Contains(s, "DIAL refused"):
			return syscall.ECONNREFUSED
		default:
			return errors.New("helper: " + s + " " + errString(err))
		}
	}
	check := func(name, cg string, uid int, allowed bool) {
		t.Helper()
		err := dial(cg, uid)
		if allowed && err != nil || !allowed && !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("%s (uid %d): allowed=%v, got %v", name, uid, allowed, err)
		}
	}

	// 1. netpush not registered yet: closed for everyone.
	if err := nft.Apply(RenderRuleset(c, nil, Exempt{Kind: ExemptCgroup, CgroupPath: "/", CgroupLevel: level})); err != nil {
		t.Fatal(err)
	}
	check("closed, netpush cgroup", np, 65533, false)

	// 2. registered by cgroup.
	ex := Exempt{Kind: ExemptCgroup, CgroupPath: "/", CgroupLevel: level, Peer: &PeerExempt{ID: id, UID: 65533}}
	if err := nft.Apply(RenderRuleset(c, nil, ex)); err != nil {
		t.Fatal(err)
	}
	check("netpush cgroup", np, 65533, true)
	check("other cgroup, same uid", other, 65533, false)
	check("netpush cgroup, root", np, 0, false)
	check("other cgroup, root", other, 0, false)
	check("other cgroup, 65534", other, 65534, false)

	// 3. uid fallback: the same uid in another cgroup gets out (this is what the cgroup match closes).
	ex.Peer = &PeerExempt{ByUID: true, UID: 65533}
	if err := nft.Apply(RenderRuleset(c, nil, ex)); err != nil {
		t.Fatal(err)
	}
	check("uid fallback, other cgroup", other, 65533, true)
	check("uid fallback, root", other, 0, false)
}

// TestLockdownDialHelper is run by TestLockdownCgroupNft inside a cgroup and as a given uid.
func TestLockdownDialHelper(t *testing.T) {
	addr := os.Getenv("NB_LOCKDOWN_DIAL")
	if addr == "" {
		t.Skip("helper")
	}
	c, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
	switch {
	case err == nil:
		c.Close()
		println("DIAL connected")
	case errors.Is(err, syscall.ECONNREFUSED):
		println("DIAL refused")
	case os.IsTimeout(err):
		println("DIAL timeout")
	default:
		println("DIAL error", err.Error())
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
