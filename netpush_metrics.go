package main

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// upstreamMetrics are the per-upstream counters and gauges.
type upstreamMetrics struct {
	active, total, draining, forcedCloses atomic.Int64
	connectFails, retries, noTarget       atomic.Int64
	bytesUp, bytesDown                    atomic.Int64 // up = client to target
	targets, discoveryErrors, discoveryOK atomic.Int64
	udpSessions                           atomic.Int64
	limitRejects                          atomic.Int64
	lastTarget                            atomic.Value // string
}

func (m *upstreamMetrics) setTargets(n int) { m.targets.Store(int64(n)) }

// NetpushMetrics is the netpush Prometheus registry (text format, stdlib only).
type NetpushMetrics struct {
	mu        sync.Mutex
	order     []string
	upstreams map[string]*upstreamMetrics
	proto     map[string]string
	dns       map[string]*atomic.Int64 // answer kind -> count

	odMax     int
	odUsed    func() int
	odRefused map[string]*atomic.Int64 // reason -> count
}

func (m *NetpushMetrics) setOnDemand(max int, used func() int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.odMax, m.odUsed = max, used
}

// OnDemandRefused counts an on-demand lookup that got no address.
func (m *NetpushMetrics) OnDemandRefused(reason string) { m.odRefused[reason].Add(1) }

func NewNetpushMetrics() *NetpushMetrics {
	m := &NetpushMetrics{upstreams: map[string]*upstreamMetrics{}, proto: map[string]string{}, dns: map[string]*atomic.Int64{}, odRefused: map[string]*atomic.Int64{}}
	for _, k := range []string{"upstream", "upstream_nodata", "passthrough", "nxdomain", "servfail", "refused", "ondemand", "ondemand_nodata"} {
		m.dns[k] = &atomic.Int64{}
	}
	for _, k := range []string{"pattern", "unknown", "pool_full", "error", "unassigned"} {
		m.odRefused[k] = &atomic.Int64{}
	}
	return m
}

func (m *NetpushMetrics) Upstream(name, proto string) *upstreamMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.upstreams[name]; ok {
		return u
	}
	u := &upstreamMetrics{}
	u.lastTarget.Store("")
	m.upstreams[name], m.proto[name] = u, proto
	m.order = append(m.order, name)
	return u
}

func (m *NetpushMetrics) DNS(kind string) { m.dns[kind].Add(1) }

func (m *NetpushMetrics) Write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type g struct {
		name, help, typ string
		v               func(*upstreamMetrics) int64
	}
	for _, x := range []g{
		{"netpush_connections_active", "Open forwarded connections (TCP) or sessions (UDP).", "gauge", func(u *upstreamMetrics) int64 { return u.active.Load() }},
		{"netpush_connections_total", "Forwarded connections or UDP sessions.", "counter", func(u *upstreamMetrics) int64 { return u.total.Load() }},
		{"netpush_connections_draining", "Connections whose target was removed.", "gauge", func(u *upstreamMetrics) int64 { return u.draining.Load() }},
		{"netpush_drain_forced_closes_total", "Connections closed by drain_timeout.", "counter", func(u *upstreamMetrics) int64 { return u.forcedCloses.Load() }},
		{"netpush_connect_failures_total", "Failed connects to a target.", "counter", func(u *upstreamMetrics) int64 { return u.connectFails.Load() }},
		{"netpush_connect_retries_total", "Connects retried on another target.", "counter", func(u *upstreamMetrics) int64 { return u.retries.Load() }},
		{"netpush_conn_limit_rejects_total", "Client connections or UDP sessions refused by max_conns.", "counter", func(u *upstreamMetrics) int64 { return u.limitRejects.Load() }},
		{"netpush_no_target_total", "Client connections refused because no target was available.", "counter", func(u *upstreamMetrics) int64 { return u.noTarget.Load() }},
		{"netpush_bytes_up_total", "Bytes from client to target.", "counter", func(u *upstreamMetrics) int64 { return u.bytesUp.Load() }},
		{"netpush_bytes_down_total", "Bytes from target to client.", "counter", func(u *upstreamMetrics) int64 { return u.bytesDown.Load() }},
		{"netpush_targets", "Healthy targets from discovery.", "gauge", func(u *upstreamMetrics) int64 { return u.targets.Load() }},
		{"netpush_discovery_errors_total", "Failed discovery queries (last good targets kept).", "counter", func(u *upstreamMetrics) int64 { return u.discoveryErrors.Load() }},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", x.name, x.help, x.name, x.typ)
		for _, n := range m.order {
			fmt.Fprintf(w, "%s{upstream=\"%s\",protocol=\"%s\"} %d\n", x.name, esc(n), m.proto[n], x.v(m.upstreams[n]))
		}
	}
	fmt.Fprintf(w, "# HELP netpush_last_target Target chosen for the latest connection.\n# TYPE netpush_last_target gauge\n")
	for _, n := range m.order {
		if t := m.upstreams[n].lastTarget.Load().(string); t != "" {
			fmt.Fprintf(w, "netpush_last_target{upstream=\"%s\",target=\"%s\"} 1\n", esc(n), esc(t))
		}
	}
	fmt.Fprintf(w, "# HELP netpush_dns_answers_total DNS answers by kind.\n# TYPE netpush_dns_answers_total counter\n")
	for _, k := range sortedKeys(m.dns) {
		fmt.Fprintf(w, "netpush_dns_answers_total{kind=\"%s\"} %d\n", k, m.dns[k].Load())
	}
	if m.odUsed != nil {
		fmt.Fprintf(w, "# HELP netpush_ondemand_pool_size Addresses on-demand lookups may assign (ondemand_max, capped by ondemand_pool).\n# TYPE netpush_ondemand_pool_size gauge\nnetpush_ondemand_pool_size %d\n", m.odMax)
		fmt.Fprintf(w, "# HELP netpush_ondemand_pool_used Addresses assigned to on-demand services (kept for the life of the alloc).\n# TYPE netpush_ondemand_pool_used gauge\nnetpush_ondemand_pool_used %d\n", m.odUsed())
		fmt.Fprintf(w, "# HELP netpush_ondemand_refused_total On-demand lookups or connections refused, by reason.\n# TYPE netpush_ondemand_refused_total counter\n")
		for _, k := range sortedKeys(m.odRefused) {
			fmt.Fprintf(w, "netpush_ondemand_refused_total{reason=\"%s\"} %d\n", k, m.odRefused[k].Load())
		}
	}
}
