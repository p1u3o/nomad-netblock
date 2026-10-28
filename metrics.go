package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Metrics is a tiny Prometheus text-format registry (stdlib only, no client library).
type Metrics struct {
	mu              sync.Mutex
	mode            Mode
	setSize         map[string]int // service -> live instances
	effective       map[string]int // svc4/svc6 -> elements in nft
	graced          int
	consulErrors    map[string]uint64
	nftErrors       uint64
	applies         uint64
	lastSync        map[string]float64
	drops           map[string]DropEntry // key proto/dest
	dropService     map[string]string
	wouldDrop       uint64
	ipv6RS          uint64
	consul          func() (current string, failovers uint64)
	netpushPeer     string // "" = no netpush exemption configured
	netpushPkts     uint64
	onDemandSources int
}

func NewMetrics(mode Mode) *Metrics {
	return &Metrics{mode: mode, setSize: map[string]int{}, effective: map[string]int{}, consulErrors: map[string]uint64{},
		lastSync: map[string]float64{}, drops: map[string]DropEntry{}, dropService: map[string]string{}}
}

func (m *Metrics) with(f func()) { m.mu.Lock(); defer m.mu.Unlock(); f() }

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func (m *Metrics) Write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	audit := 0
	if m.mode == ModeAudit {
		audit = 1
	}
	if m.netpushPeer != "" {
		fmt.Fprintf(w, "# HELP netblock_netpush_exempt_info Current netpush Consul exemption.\n# TYPE netblock_netpush_exempt_info gauge\nnetblock_netpush_exempt_info{match=\"%s\"} 1\n", esc(m.netpushPeer))
		fmt.Fprintf(w, "# HELP netblock_ondemand_services Services added to the allow sets by netpush on-demand lookups.\n# TYPE netblock_ondemand_services gauge\nnetblock_ondemand_services %d\n", m.onDemandSources)
		fmt.Fprintf(w, "# HELP netblock_netpush_exempt_packets Packets accepted by the netpush Consul exemption.\n# TYPE netblock_netpush_exempt_packets counter\nnetblock_netpush_exempt_packets %d\n", m.netpushPkts)
	}
	fmt.Fprintf(w, "# HELP netblock_audit_mode 1 when would-be drops are accepted.\n# TYPE netblock_audit_mode gauge\nnetblock_audit_mode %d\n", audit)
	fmt.Fprintln(w, "# HELP netblock_service_instances Live instances per allowed Consul service.\n# TYPE netblock_service_instances gauge")
	for _, k := range sortedKeys(m.setSize) {
		fmt.Fprintf(w, "netblock_service_instances{service=\"%s\"} %d\n", esc(k), m.setSize[k])
	}
	fmt.Fprintln(w, "# HELP netblock_set_elements Elements in the nftables service sets (including graced).\n# TYPE netblock_set_elements gauge")
	for _, k := range sortedKeys(m.effective) {
		fmt.Fprintf(w, "netblock_set_elements{set=\"%s\"} %d\n", k, m.effective[k])
	}
	fmt.Fprintf(w, "# HELP netblock_graced_elements Removed targets still allowed during removal_grace.\n# TYPE netblock_graced_elements gauge\nnetblock_graced_elements %d\n", m.graced)
	fmt.Fprintln(w, "# HELP netblock_consul_errors_total Failed Consul reads per service.\n# TYPE netblock_consul_errors_total counter")
	for _, k := range sortedKeys(m.consulErrors) {
		fmt.Fprintf(w, "netblock_consul_errors_total{service=\"%s\"} %d\n", esc(k), m.consulErrors[k])
	}
	fmt.Fprintln(w, "# HELP netblock_consul_last_success_timestamp_seconds Last good Consul read per service.\n# TYPE netblock_consul_last_success_timestamp_seconds gauge")
	for _, k := range sortedKeys(m.lastSync) {
		fmt.Fprintf(w, "netblock_consul_last_success_timestamp_seconds{service=\"%s\"} %.0f\n", esc(k), m.lastSync[k])
	}
	fmt.Fprintf(w, "# HELP netblock_nft_apply_total Successful set updates.\n# TYPE netblock_nft_apply_total counter\nnetblock_nft_apply_total %d\n", m.applies)
	fmt.Fprintf(w, "# HELP netblock_nft_errors_total Failed nft operations.\n# TYPE netblock_nft_errors_total counter\nnetblock_nft_errors_total %d\n", m.nftErrors)
	fmt.Fprintf(w, "# HELP netblock_ipv6_rs_dropped_packets_total IPv6 router solicitations dropped silently.\n# TYPE netblock_ipv6_rs_dropped_packets_total counter\nnetblock_ipv6_rs_dropped_packets_total %d\n", m.ipv6RS)
	if m.consul != nil {
		cur, fo := m.consul()
		fmt.Fprintf(w, "# HELP netblock_consul_endpoint_active Consul endpoint currently in use.\n# TYPE netblock_consul_endpoint_active gauge\nnetblock_consul_endpoint_active{endpoint=\"%s\"} 1\n", esc(cur))
		fmt.Fprintf(w, "# HELP netblock_consul_endpoint_failures_total Endpoint failures that triggered failover.\n# TYPE netblock_consul_endpoint_failures_total counter\nnetblock_consul_endpoint_failures_total %d\n", fo)
	}
	fmt.Fprintf(w, "# HELP netblock_would_drop_packets_total Packets that hit the final reject (enforce) or audit accept.\n# TYPE netblock_would_drop_packets_total counter\nnetblock_would_drop_packets_total %d\n", m.wouldDrop)
	fmt.Fprintln(w, "# HELP netblock_drops_packets_total First packets of new flows to non-allowed destinations (24h window per dest).\n# TYPE netblock_drops_packets_total counter")
	for _, k := range sortedKeys(m.drops) {
		d := m.drops[k]
		fmt.Fprintf(w, "netblock_drops_packets_total{proto=\"%s\",dest=\"%s\",service=\"%s\"} %d\n", d.Proto, d.Dest, esc(m.dropService[k]), d.Packets)
	}
}
