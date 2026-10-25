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

var version = "0.3.1-dev"

const (
	defaultConfPath = "/local/netblock.conf"
	resolvPath      = "/etc/resolv.conf"
)

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s netblock: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
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
		fmt.Fprintln(os.Stderr, "usage: netblock init|watch|version [config]")
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
	if err := nft.Apply(RenderRuleset(c, dedupe(targets))); err != nil {
		return failClosed(nft, err)
	}
	logf("init: applied mode=%s static=%d service_targets=%d dns=%v", c.Mode, len(c.AllowCIDRs), len(dedupe(targets)), dnsDesc(c))
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
	if err := nft.Apply(RenderRuleset(c, dedupe(carried))); err != nil {
		logf("watch: re-apply ruleset failed, rules left as they were: %v", err)
		return 1
	}
	logf("watch: ruleset applied mode=%s static=%d carried_targets=%d", c.Mode, len(c.AllowCIDRs), len(carried))
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
			if len(ready) == len(srcs) {
				w.sync(time.Now())
			}
		case <-tick.C:
			if len(ready) == len(srcs) {
				w.sync(time.Now())
			}
		case <-dropTick.C:
			w.scanDrops()
		}
	}
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

func (w *watcher) sync(now time.Time) {
	eff, graced := w.tr.Effective(now)
	sizes := w.tr.SetSizes()
	v4, v6 := splitFamilies(eff)
	w.m.with(func() {
		w.m.setSize = sizes
		w.m.effective = map[string]int{"svc4": len(v4), "svc6": len(v6)}
		w.m.graced = graced
	})
	if w.have && sameTargets(eff, w.applied) {
		return
	}
	if err := w.nft.Apply(RenderSetUpdate(eff)); err != nil {
		w.m.with(func() { w.m.nftErrors++ })
		logf("watch: set update failed (previous sets stay): %v", err)
		return
	}
	logf("watch: sets updated: %d elements (%d in grace): %s", len(eff), graced, targetsDesc(eff))
	w.applied, w.have = eff, true
	w.m.with(func() { w.m.applies++ })
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
