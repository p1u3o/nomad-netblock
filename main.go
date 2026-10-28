// nomad-netblock: egress firewall for Nomad bridge-mode allocations.
//
//	netblock init   prestart (sidecar=false): apply the ruleset once, then exit.
//	netblock watch  poststart sidecar: keep the Consul service sets current.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var version = "0.4.0-rc5"

const (
	defaultConfPath = "/local/netblock.conf"
	resolvPath      = "/etc/resolv.conf"
)

// logName is the log prefix; the netpush mode sets it to "netpush".
var logName = "netblock"

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s: %s\n", time.Now().UTC().Format(time.RFC3339), logName, fmt.Sprintf(format, a...))
}

func readResolv() []netip.Addr {
	f, err := os.Open(resolvPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	return ParseResolvConf(f)
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return ParseConfig(f, readResolv)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: netblock init|watch|netpush|version [config]")
		os.Exit(64)
	}
	path := defaultConfPath
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	nft := execRunner{bin: envOr("NETBLOCK_NFT", "nft")}
	switch os.Args[1] {
	case "init":
		os.Exit(runInit(path, nft))
	case "watch":
		if os.Getenv(childEnv) == "" && os.Getuid() == 0 {
			if c, err := loadConfig(path); err == nil && c.RunAsUID > 0 {
				os.Exit(runAsChild(c))
			}
		}
		if os.Getenv(childEnv) != "" {
			logf("watch: running as uid=%d gid=%d %s", os.Getuid(), os.Getgid(), capsDesc())
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		os.Exit(runWatch(ctx, path, nft))
	case "netpush":
		if len(os.Args) <= 2 {
			path = defaultNetpushConfPath
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		os.Exit(runNetpush(ctx, path))
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(64)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// failClosed applies deny-all-but-DNS. Exit codes: 1 = applied, 3 = even that failed.
func failClosed(nft Runner, why error) int {
	logf("FAIL CLOSED: %v", why)
	if err := nft.Apply(RenderFailClosed(readResolv())); err != nil {
		logf("FAIL CLOSED ruleset could not be applied: %v", err)
		return 3
	}
	return 1
}

func fetchAll(ctx context.Context, srcs []source) (map[string][]Target, error) {
	out := map[string][]Target{}
	var errs []error
	for _, s := range srcs {
		ts, _, err := s.fetch(ctx, 0, 0)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[s.key] = ts
	}
	return out, errors.Join(errs...)
}

func runInit(path string, nft Runner) int {
	c, err := loadConfig(path)
	if err != nil {
		return failClosed(nft, fmt.Errorf("config %s: %v", path, err))
	}
	var targets []Target
	var consulErr error
	srcs, _, err := buildSources(c)
	if err != nil {
		return failClosed(nft, err)
	}
	if len(srcs) > 0 {
		// The ruleset is not applied yet, so Consul/Nomad are reachable. Retry briefly.
		deadline := time.Now().Add(30 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			var got map[string][]Target
			got, consulErr = fetchAll(ctx, srcs)
			cancel()
			if consulErr == nil || time.Now().After(deadline) {
				for n, ts := range got {
					logf("init: %s -> %d targets", n, len(ts))
					targets = append(targets, ts...)
				}
				break
			}
			logf("init: consul: %v (retrying)", consulErr)
			time.Sleep(3 * time.Second)
		}
	}
	ex := initExempt(c)
	if err := nft.Apply(RenderRuleset(c, dedupe(targets), ex)); err != nil {
		return failClosed(nft, err)
	}
	logf("init: applied mode=%s static=%d service_targets=%d dns=%v consul_exempt=%s", c.Mode, len(c.AllowCIDRs), len(dedupe(targets)), dnsDesc(c), ex)
	if consulErr != nil {
		logf("init: consul incomplete: %v", consulErr)
		if c.InitRequireConsul {
			return 2 // ruleset (default deny) is in place; main task does not start
		}
	}
	return 0
}

func dnsDesc(c Config) any {
	if c.DNSNone {
		return "none"
	}
	return c.DNSResolvers
}

func dedupe(ts []Target) []Target {
	seen := map[Target]bool{}
	var out []Target
	for _, t := range ts {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sortTargets(out)
	return out
}

type update struct {
	service string
	targets []Target
}

// watchService runs blocking queries for one service. On error it backs off and the
// tracker keeps the last known-good targets; the policy is never opened.
func watchService(ctx context.Context, s source, m *Metrics, out chan<- update) {
	var index uint64
	backoff := time.Second
	for ctx.Err() == nil {
		qctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		ts, got, err := s.fetch(qctx, index, 5*time.Minute)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.with(func() { m.consulErrors[s.key]++ })
			logf("watch: %v (keeping last known-good, retry in %s)", err, backoff)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		m.with(func() { m.lastSync[s.key] = float64(time.Now().Unix()); m.consulErrors[s.key] += 0 })
		select {
		case out <- update{s.key, ts}:
		case <-ctx.Done():
			return
		}
		index = nextIndex(index, got)
		if index == 0 {
			sleepCtx(ctx, time.Second)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func runWatch(ctx context.Context, path string, nft Runner) int {
	c, err := loadConfig(path)
	if err != nil {
		// Do not touch the rules init applied; just report. Exit non-zero so Nomad restarts us.
		logf("watch: config %s: %v (rules left as applied by init)", path, err)
		return 1
	}
	// Re-apply the full ruleset so config changes (mode, allow_cidrs, ...) take effect when
	// Nomad restarts this task on a template change. Current service elements are carried
	// over, and the replace is one transaction, so nothing is ever open in between.
	var carried []Target
	for _, set := range []string{"svc4", "svc6"} {
		if raw, err := nft.ListJSON("set", "inet", tableName, set); err == nil {
			if ts, err := ParseServiceSet(raw); err == nil {
				carried = append(carried, ts...)
			}
		}
	}
	carried = dedupe(carried)
	ex, err := resolveExempt(c, selfCgroupFile, cgroupRoot)
	if err != nil {
		logf("watch: CGROUP EXEMPT FALLBACK: cannot use cgroupv2 match (%v); Consul exemption falls back to %s", err, ex)
	}
	if err := nft.Apply(RenderRuleset(c, carried, ex)); err != nil {
		logf("watch: re-apply ruleset failed, rules left as they were: %v", err)
		return 1
	}
	logf("watch: ruleset applied mode=%s static=%d carried_targets=%d consul_exempt=%s", c.Mode, len(c.AllowCIDRs), len(carried), ex)
	logLockdown(c, ex)
	if ex.Kind == ExemptCgroup && len(c.ConsulAddrs) > 0 {
		ex = verifyExempt(ctx, c, nft, carried, ex)
	}
	m := NewMetrics(c.Mode)
	tr := NewTracker(c.RemovalGrace)
	if c.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			m.Write(w)
		})
		srv := &http.Server{Addr: c.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("metrics: %v", err)
			}
		}()
		defer srv.Close()
	}
	// netpush peer exemption (peer.go).
	var peerCh chan peerReg
	var odReqs chan odRequest
	if c.OnDemandPool.IsValid() {
		odReqs = make(chan odRequest)
	}
	if c.NetpushSocket != "" && (len(c.ConsulAddrs) > 0 || odReqs != nil) {
		switch {
		case c.NetpushMatch == "uid" || ex.Kind != ExemptCgroup:
			if c.NetpushUID > 0 {
				ex.Peer = &PeerExempt{ByUID: true, UID: c.NetpushUID}
				logf("watch: NETPUSH EXEMPT UID FALLBACK: netpush_match=%s watch exemption=%s; netpush Consul traffic exempted by uid %d only (any process with that uid in the alloc gets Consul)", c.NetpushMatch, ex, c.NetpushUID)
				if err := nft.Apply(RenderRuleset(c, carried, ex)); err != nil {
					logf("watch: netpush uid exemption apply failed: %v", err)
					ex.Peer = nil
				}
				logLockdown(c, ex)
			} else {
				logf("watch: NETPUSH EXEMPT DISABLED: no cgroup match and no netpush_uid; netpush gets no Consul access")
			}
			if odReqs != nil {
				// On-demand requests still use the peer socket; the cgroup is not used.
				ignored := make(chan peerReg)
				go func() {
					for r := range ignored {
						r.f.Close()
					}
				}()
				go servePeer(ctx, c, 0, ignored, odReqs)
			}
		default:
			ownID, err := cgroupID(cgroupRoot)
			if err != nil {
				logf("watch: NETPUSH EXEMPT DISABLED: own cgroup id: %v", err)
				break
			}
			peerCh = make(chan peerReg)
			go servePeer(ctx, c, ownID, peerCh, odReqs)
		}
		m.with(func() { m.netpushPeer = "waiting" })
		if ex.Peer != nil {
			m.with(func() { m.netpushPeer = ex.Peer.String() })
		}
	}
	updates := make(chan update, 16)
	var wg sync.WaitGroup
	srcs, cc, err := buildSources(c)
	if err != nil {
		logf("watch: %v", err)
		return 1
	}
	if cc != nil {
		m.consul = func() (string, uint64) { return cc.Current(), cc.Failovers() }
	}
	for _, s := range srcs {
		wg.Add(1)
		go func(s source) { defer wg.Done(); watchService(ctx, s, m, updates) }(s)
	}
	logf("watch: started mode=%s services=%d grace=%s include_critical=%v", c.Mode, len(srcs), c.RemovalGrace, c.IncludeCritical)
	w := &watcher{c: c, nft: nft, tr: tr, m: m, seenDrops: map[string]uint64{}}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	dropTick := time.NewTicker(15 * time.Second)
	defer dropTick.Stop()
	ready := map[string]bool{}
	od := &onDemandSources{c: c, cc: cc, have: map[string]bool{}, pending: map[string][]chan error{}}
	for _, s := range srcs {
		od.have[s.key] = true
	}
	nsrc := len(srcs)
	syncAll := func() {
		if len(ready) != nsrc {
			return
		}
		err := w.sync(time.Now())
		od.answer(ready, err)
	}
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			logf("watch: stopping; rules stay in place")
			return 0
		case u := <-updates:
			tr.Update(u.service, u.targets, time.Now())
			ready[u.service] = true
			// Until every service has reported once, do not flush targets init installed.
			syncAll()
		case <-tick.C:
			syncAll()
		case r := <-odReqs:
			s, isNew, err := od.add(r)
			if err != nil {
				logf("watch: on-demand allow %s %s refused: %v", r.kind, r.name, err)
				r.reply <- err
				continue
			}
			if isNew {
				nsrc++
				logf("watch: on-demand allow: watching %s service %s", r.kind, s.key)
				wg.Add(1)
				go func(s source) { defer wg.Done(); watchService(ctx, s, m, updates) }(s)
				m.with(func() { m.onDemandSources = len(od.have) - len(srcs) })
			}
			syncAll()
		case r := <-peerCh:
			old := setPeerFile(r.f)
			prev := ex.Peer
			ex.Peer = &PeerExempt{ID: r.id, UID: c.NetpushUID}
			targets := carried
			if w.have {
				targets = w.applied
			}
			if err := nft.Apply(RenderRuleset(c, targets, ex)); err != nil {
				logf("watch: netpush exemption apply failed (previous rules stay): %v", err)
				setPeerFile(old)
				ex.Peer = prev
				r.f.Close()
				continue
			}
			if old != nil {
				old.Close()
			}
			logf("watch: netpush exemption applied: %s", ex.Peer)
			logLockdown(c, ex)
			m.with(func() { m.netpushPeer = ex.Peer.String() })
		case <-dropTick.C:
			w.scanDrops()
			if c.NetpushSocket != "" {
				if raw, err := nft.ListJSON("counter", "inet", tableName, "netpush_exempt"); err == nil {
					if p, _, err := ParseNamedCounter(raw); err == nil {
						m.with(func() { m.netpushPkts = p })
					}
				}
			}
		}
	}
}

var (
	selfCgroupFile = "/proc/self/cgroup"
	cgroupRoot     = "/sys/fs/cgroup"
	probe          = func(ctx context.Context, addrs []netip.AddrPort) { probeExempt(ctx, addrs, 2*time.Second) }
)

// verifyExempt checks that the cgroupv2 rule matches this process's own sockets (consul_exempt
// counter moves after a connect attempt). On a kernel that resolves the level against the
// root cgroup namespace it would never match; then fall back to the uid match and say so.
func verifyExempt(ctx context.Context, c Config, nft Runner, carried []Target, ex Exempt) Exempt {
	probe(ctx, c.ConsulAddrs)
	raw, err := nft.ListJSON("counter", "inet", tableName, "consul_exempt")
	var p uint64
	if err == nil {
		p, _, err = ParseNamedCounter(raw)
	}
	if err == nil && p > 0 {
		logf("watch: cgroupv2 exemption verified (consul_exempt packets=%d)", p)
		return ex
	}
	fb := uidFallback(c)
	logf("watch: CGROUP EXEMPT FALLBACK: cgroupv2 rule did not match our own Consul connect (packets=%d err=%v); falling back to %s", p, err, fb)
	if aerr := nft.Apply(RenderRuleset(c, carried, fb)); aerr != nil {
		logf("watch: fallback re-apply failed, cgroupv2 rule stays: %v", aerr)
		return ex
	}
	return fb
}

type watcher struct {
	c         Config
	nft       Runner
	tr        *Tracker
	m         *Metrics
	applied   []Target
	have      bool
	seenDrops map[string]uint64
}

// sync pushes the effective targets into the sets; the error is the failed apply, if any.
func (w *watcher) sync(now time.Time) error {
	eff, graced := w.tr.Effective(now)
	sizes := w.tr.SetSizes()
	v4, v6 := splitFamilies(eff)
	w.m.with(func() {
		w.m.setSize = sizes
		w.m.effective = map[string]int{"svc4": len(v4), "svc6": len(v6)}
		w.m.graced = graced
	})
	if w.have && sameTargets(eff, w.applied) {
		return nil
	}
	if err := w.nft.Apply(RenderSetUpdate(eff)); err != nil {
		w.m.with(func() { w.m.nftErrors++ })
		logf("watch: set update failed (previous sets stay): %v", err)
		return err
	}
	logf("watch: sets updated: %d elements (%d in grace): %s", len(eff), graced, targetsDesc(eff))
	w.applied, w.have = eff, true
	w.m.with(func() { w.m.applies++ })
	return nil
}

func targetsDesc(ts []Target) string {
	var b bytes.Buffer
	for i, t := range ts {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(t.String())
	}
	return b.String()
}

func (w *watcher) scanDrops() {
	verb := "drop"
	if w.c.Mode == ModeAudit {
		verb = "would-drop"
	}
	for _, set := range []string{"drop4", "drop6"} {
		raw, err := w.nft.ListJSON("set", "inet", tableName, set)
		if err != nil {
			w.m.with(func() { w.m.nftErrors++ })
			continue
		}
		entries, err := ParseDropSet(raw)
		if err != nil {
			continue
		}
		for _, d := range entries {
			key := d.Proto + "/" + d.Dest.String()
			svc := w.tr.ServiceFor(Target{d.Dest.Addr(), d.Dest.Port()})
			if d.Packets > w.seenDrops[key] {
				name := svc
				if name == "" {
					name = "unknown"
				}
				logf("%s%s %s %s service=%s packets=%d", logPrefix, verb, d.Proto, d.Dest, name, d.Packets)
				w.seenDrops[key] = d.Packets
			}
			w.m.with(func() { w.m.drops[key] = d; w.m.dropService[key] = svc })
		}
	}
	if raw, err := w.nft.ListJSON("counter", "inet", tableName, "would_drop"); err == nil {
		if p, _, err := ParseNamedCounter(raw); err == nil {
			w.m.with(func() { w.m.wouldDrop = p })
		}
	}
	if raw, err := w.nft.ListJSON("counter", "inet", tableName, "ipv6_rs"); err == nil {
		if p, _, err := ParseNamedCounter(raw); err == nil {
			w.m.with(func() { w.m.ipv6RS = p })
		}
	}
}

// logLockdown reports which match the egress lockdown uses right now.
func logLockdown(c Config, ex Exempt) {
	if !c.EgressLockdown {
		return
	}
	m, ok := lockdownMatch(c, ex)
	switch {
	case !ok:
		logf("watch: egress lockdown closed until netpush registers its cgroup (only loopback and the Consul exemptions are open)")
	case lockdownUIDOnly(c, ex):
		logf("watch: EGRESS LOCKDOWN UID FALLBACK: egress limited by uid %d only (any process with that uid in the alloc gets out)", c.NetpushUID)
	default:
		logf("watch: egress lockdown by netpush cgroup: %s", m)
	}
}
