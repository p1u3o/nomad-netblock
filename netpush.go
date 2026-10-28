package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultNetpushConfPath = "/local/netpush.conf"

// discoverFunc is one blocking query: targets and the next index.
type discoverFunc func(ctx context.Context, index uint64, wait time.Duration) ([]Target, uint64, error)

type netpushDeps struct {
	consul *ConsulClient
	nomad  *NomadClient
}

type netpushRuntime struct {
	cfg     NetpushConfig
	metrics *NetpushMetrics
	pools   map[string]*pool
	// Addrs actually bound (useful with port 0 in tests).
	listenAddrs map[string]net.Addr
	dnsUDP      net.Addr
	dnsTCP      net.Addr
	metricsLn   net.Addr
	od          *onDemand
	odTCP       net.Addr
	wg          sync.WaitGroup
}

func discoverer(u Upstream, d netpushDeps) (discoverFunc, error) {
	switch {
	case u.Consul != nil:
		if d.consul == nil {
			return nil, fmt.Errorf("upstream %s: no Consul client", u.Name)
		}
		s := *u.Consul
		if u.OnlyPassing {
			return func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
				return d.consul.HealthPassing(ctx, s, i, w)
			}, nil
		}
		return func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
			return d.consul.Health(ctx, s, i, w, false)
		}, nil
	case u.Nomad != nil:
		if d.nomad == nil {
			return nil, fmt.Errorf("upstream %s: no Nomad client", u.Name)
		}
		s := *u.Nomad
		return func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
			return d.nomad.Services(ctx, s, i, w)
		}, nil
	}
	return nil, fmt.Errorf("upstream %s: no source", u.Name)
}

var discoveryWait = 5 * time.Minute

// watchUpstream runs blocking queries forever, keeping the last good target list on errors.
func watchUpstream(ctx context.Context, u Upstream, fn discoverFunc, p *pool, m *upstreamMetrics) {
	var idx uint64
	backoff := time.Second
	first := true
	for ctx.Err() == nil {
		ts, got, err := fn(ctx, idx, discoveryWait)
		if errors.Is(err, errInterrupted) {
			continue // token reload: same index, new request with the new token
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.discoveryErrors.Add(1)
			logf("upstream %s: discovery %s: %v (keeping %d targets, retry in %s)", u.Name, u.SourceString(), err, len(p.snapshot()), backoff)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			idx = 0
			continue
		}
		backoff = time.Second
		next := nextIndex(idx, got)
		if first || next != idx || got < idx {
			ts = dedupe(ts)
			old := p.snapshot()
			p.update(ts)
			if first || targetsDesc(old) != targetsDesc(ts) {
				logf("upstream %s: %s -> %s", u.Name, u.SourceString(), targetsDesc(ts))
			}
			first = false
		}
		idx = next
	}
}

// startNetpush binds every listener, then starts discovery and serving. Binding
// first means a bad config fails fast before the app starts.
func startNetpush(ctx context.Context, c NetpushConfig, d netpushDeps) (*netpushRuntime, error) {
	rt := &netpushRuntime{cfg: c, metrics: NewNetpushMetrics(), pools: map[string]*pool{}, listenAddrs: map[string]net.Addr{}}
	var closers []func()
	fail := func(err error) (*netpushRuntime, error) {
		for _, f := range closers {
			f()
		}
		return nil, err
	}
	type starter func()
	var starts []starter
	for _, u := range c.Upstreams {
		fn, err := discoverer(u, d)
		if err != nil {
			return fail(err)
		}
		m := rt.metrics.Upstream(u.Name, u.Protocol)
		p := newPool(u.Name, c.DrainTimeout, m)
		rt.pools[u.Name] = p
		f := &forwarder{up: u, pool: p, m: m, timeout: c.ConnectTimeout, ka: c.KeepAlive, retries: c.ConnectRetries}
		u := u
		if u.Protocol == "udp" {
			pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(u.Bind))
			if err != nil {
				return fail(fmt.Errorf("upstream %s: %v", u.Name, err))
			}
			closers = append(closers, func() { pc.Close() })
			rt.listenAddrs[u.Name] = pc.LocalAddr()
			starts = append(starts, func() { f.serveUDP(ctx, pc) })
		} else {
			ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(u.Bind))
			if err != nil {
				return fail(fmt.Errorf("upstream %s: %v", u.Name, err))
			}
			closers = append(closers, func() { ln.Close() })
			rt.listenAddrs[u.Name] = ln.Addr()
			starts = append(starts, func() { f.serveTCP(ctx, ln) })
		}
		starts = append(starts, func() { watchUpstream(ctx, u, fn, p, m) })
	}
	if c.OnDemand {
		rt.od = newOnDemand(ctx, c, rt.metrics, d, func(f func()) {
			rt.wg.Add(1)
			go func() { defer rt.wg.Done(); f() }()
		})
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(c.OnDemandPort)})
		if err != nil {
			return fail(fmt.Errorf("ondemand listener: %v", err))
		}
		closers = append(closers, func() { ln.Close() })
		rt.odTCP = ln.Addr()
		starts = append(starts, func() { rt.od.serveTCP(ctx, ln) })
	}
	if c.DNSListen != "" {
		ds := newDNSServer(c, rt.metrics)
		ds.od = rt.od
		if dnsTestPort != 0 {
			ds.port = dnsTestPort
		}
		pc, tl, err := listenDNS(c.DNSListen)
		if err != nil {
			return fail(err)
		}
		closers = append(closers, func() { pc.Close(); tl.Close() })
		rt.dnsUDP, rt.dnsTCP = pc.LocalAddr(), tl.Addr()
		starts = append(starts, func() { ds.serveUDP(ctx, pc) }, func() { ds.serveTCP(ctx, tl) })
	}
	if c.MetricsAddr != "" {
		ml, err := net.Listen("tcp", c.MetricsAddr)
		if err != nil {
			return fail(fmt.Errorf("metrics_addr: %v", err))
		}
		rt.metricsLn = ml.Addr()
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			rt.metrics.Write(w)
		})
		mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
			for n, p := range rt.pools {
				if !p.ready() {
					http.Error(w, "waiting for discovery: "+n, http.StatusServiceUnavailable)
					return
				}
			}
			fmt.Fprintln(w, "ok")
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		starts = append(starts, func() {
			go func() { <-ctx.Done(); srv.Close() }()
			srv.Serve(ml)
		})
	}
	for _, s := range starts {
		rt.wg.Add(1)
		go func() { defer rt.wg.Done(); s() }()
	}
	return rt, nil
}

var dnsTestPort uint16

// linkOnDemand registers with netblock watch and uses the connection for on-demand
// requests: allow-set additions and the UDP listener socket.
func (rt *netpushRuntime) linkOnDemand(ctx context.Context, sock string) {
	link := newNetblockLink()
	rt.od.allow = func(ctx context.Context, u Upstream) error {
		_, f, err := link.request(ctx, allowLine(u))
		if f != nil {
			f.Close()
		}
		return err
	}
	link.onRegister = rt.od.replay
	go registerWithNetblockLink(ctx, sock, link)
	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		if pc := rt.od.getUDPListener(ctx, link); pc != nil {
			logf("ondemand: UDP listener from netblock watch on %s", pc.LocalAddr())
			rt.od.serveUDP(ctx, pc)
		}
	}()
}

// listenDNS binds UDP and TCP on the same port. With port 0 the UDP port the kernel picks
// can be taken for TCP; then try another one.
func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dns_listen: %v", err)
	}
	tries := 1
	if ap.Port() == 0 {
		tries = 20
	}
	for i := 0; ; i++ {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("dns_listen: %v", err)
		}
		tl, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, tl, nil
		}
		pc.Close()
		if i+1 >= tries {
			return nil, nil, fmt.Errorf("dns_listen tcp: %v", err)
		}
	}
}

func (rt *netpushRuntime) Wait() { rt.wg.Wait() }

func loadNetpushConfig(path string) (NetpushConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return NetpushConfig{}, err
	}
	defer f.Close()
	return ParseNetpushConfig(f, readResolv)
}

func runNetpush(ctx context.Context, path string) int {
	logName = "netpush"
	c, err := loadNetpushConfig(path)
	if err != nil {
		logf("config: %v", err)
		return 1
	}
	var d netpushDeps
	ups := c.Upstreams
	if c.OnDemand { // the on-demand source needs its client too
		u := Upstream{Consul: &ServiceRef{}}
		if c.OnDemandSource == "nomad" {
			u = Upstream{Nomad: &NomadRef{}}
		}
		ups = append(ups[:len(ups):len(ups)], u)
	}
	for _, u := range ups {
		if u.Consul != nil && d.consul == nil {
			if d.consul, err = NewConsulClient(Config{ConsulAddrs: c.ConsulAddrs, ConsulCAFile: c.ConsulCAFile, ConsulTokenFile: c.ConsulTokenFile, ConsulServer: c.ConsulServer}); err != nil {
				logf("%v", err)
				return 1
			}
		}
		if u.Nomad != nil && d.nomad == nil {
			if d.nomad, err = NewNomadClient(Config{NomadAddr: c.NomadAddr, NomadTokenFile: c.NomadTokenFile}); err != nil {
				logf("%v", err)
				return 1
			}
		}
	}
	rt, err := startNetpush(ctx, c, d)
	if err != nil {
		logf("%v", err)
		return 1
	}
	switch {
	case c.NetblockSocket != "" && rt.od != nil:
		rt.linkOnDemand(ctx, c.NetblockSocket)
	case c.NetblockSocket != "":
		go registerWithNetblock(ctx, c.NetblockSocket)
	}
	// SIGHUP: the Consul/Nomad token files were re-rendered. Tokens are read from the files on
	// every request; cut the running blocking queries so they restart with the new token.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				logf("SIGHUP: reloading tokens (restarting Consul blocking queries)")
				if d.consul != nil {
					d.consul.Interrupt()
				}
			}
		}
	}()
	var desc []string
	for _, u := range c.Upstreams {
		desc = append(desc, fmt.Sprintf("%s=%s/%s<-%s", u.Name, rt.listenAddrs[u.Name], u.Protocol, u.SourceString()))
	}
	if rt.od != nil {
		desc = append(desc, "ondemand("+rt.od.String()+")")
	}
	logf("%s up: %s; dns=%q drain=%s uid=%d", version, strings.Join(desc, " "), c.DNSListen, drainDesc(c.DrainTimeout), os.Getuid())
	rt.Wait()
	logf("stopped")
	return 0
}
