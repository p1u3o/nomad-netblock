package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConsulClient does read-only health queries against one or more Consul HTTPS endpoints.
// Endpoints are tried in order starting at the last one that worked; an endpoint that fails
// (connect/TLS error, timeout, 5xx, 429) is put in a backoff (5 s doubling, max 60 s) and the
// next one is tried in the same call. 4xx answers (ACL, bad request) are returned as-is: they
// would be the same on every server.
type ConsulClient struct {
	bases     []string
	tokenFile string
	http      *http.Client

	mu        sync.Mutex
	cur       int
	fails     []int
	failUntil []time.Time
	now       func() time.Time
	failovers uint64
	intr      chan struct{} // closed by Interrupt (token reload)
}

// errInterrupted is returned by requests cut short by Interrupt; callers re-query at once.
var errInterrupted = errors.New("consul request interrupted for token reload")

func (cc *ConsulClient) interruptCh() chan struct{} {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.intr == nil {
		cc.intr = make(chan struct{})
	}
	return cc.intr
}

// Interrupt cancels in-flight blocking queries and drops idle connections, so the next
// requests read the token file again (it is read on every request).
func (cc *ConsulClient) Interrupt() {
	cc.mu.Lock()
	if cc.intr != nil {
		close(cc.intr)
	}
	cc.intr = make(chan struct{})
	cc.mu.Unlock()
	cc.http.CloseIdleConnections()
}

func NewConsulClient(c Config) (*ConsulClient, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ConsulServer}
	if c.ConsulCAFile != "" {
		pem, err := os.ReadFile(c.ConsulCAFile)
		if err != nil {
			return nil, fmt.Errorf("consul CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("consul CA %s: no certificates", c.ConsulCAFile)
		}
		tc.RootCAs = pool
	}
	var bases []string
	for _, ap := range c.ConsulAddrs {
		bases = append(bases, "https://"+ap.String())
	}
	rt := &http.Transport{
		TLSClientConfig:     tc,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 8,
	}
	return newConsulClient(bases, c.ConsulTokenFile, rt), nil
}

func newConsulClient(bases []string, tokenFile string, rt http.RoundTripper) *ConsulClient {
	return &ConsulClient{bases: bases, tokenFile: tokenFile, http: &http.Client{Transport: rt},
		fails: make([]int, len(bases)), failUntil: make([]time.Time, len(bases)), now: time.Now}
}

// order returns endpoint indexes to try: healthy ones from cur onwards, then ones in backoff.
func (cc *ConsulClient) order() []int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	now := cc.now()
	var ok, backoff []int
	for k := range cc.bases {
		i := (cc.cur + k) % len(cc.bases)
		if now.Before(cc.failUntil[i]) {
			backoff = append(backoff, i)
		} else {
			ok = append(ok, i)
		}
	}
	return append(ok, backoff...)
}

func (cc *ConsulClient) markOK(i int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.cur != i {
		logf("consul: now using %s", cc.bases[i])
	}
	cc.cur, cc.fails[i], cc.failUntil[i] = i, 0, time.Time{}
}

func (cc *ConsulClient) markFail(i int, err error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.now().Before(cc.failUntil[i]) {
		return // already in backoff (another watcher hit it concurrently)
	}
	cc.fails[i]++
	d := 5 * time.Second << min(cc.fails[i]-1, 4)
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	cc.failUntil[i] = cc.now().Add(d)
	cc.failovers++
	logf("consul: endpoint %s failed (%v), backoff %s", cc.bases[i], err, d)
}

// Failovers returns how many endpoint failures caused a switch attempt.
func (cc *ConsulClient) Failovers() uint64 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.failovers
}

// Current returns the base URL of the endpoint in use.
func (cc *ConsulClient) Current() string {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.bases[cc.cur]
}

type retryable struct{ error }

type healthEntry struct {
	Node struct {
		Node    string
		Address string
	}
	Service struct {
		Service string
		Address string
		Port    int
	}
	Checks []struct {
		Status string
	}
}

// Health returns the targets of every registered instance (no ?passing filter), the
// X-Consul-Index for the next blocking call, and an error. Critical instances are
// skipped unless includeCritical.
func (cc *ConsulClient) Health(ctx context.Context, s ServiceRef, index uint64, wait time.Duration, includeCritical bool) ([]Target, uint64, error) {
	f := filterNoCritical
	if includeCritical {
		f = filterAll
	}
	return cc.health(ctx, s, index, wait, f)
}

// HealthPassing returns only instances whose checks are all passing (netpush upstreams).
func (cc *ConsulClient) HealthPassing(ctx context.Context, s ServiceRef, index uint64, wait time.Duration) ([]Target, uint64, error) {
	return cc.health(ctx, s, index, wait, filterPassing)
}

type healthFilter int

const (
	filterAll healthFilter = iota
	filterNoCritical
	filterPassing
)

func (cc *ConsulClient) health(ctx context.Context, s ServiceRef, index uint64, wait time.Duration, f healthFilter) ([]Target, uint64, error) {
	q := url.Values{}
	if s.DC != "" {
		q.Set("dc", s.DC)
	}
	if s.Tag != "" {
		q.Set("tag", s.Tag)
	}
	if index > 0 {
		q.Set("index", strconv.FormatUint(index, 10))
		q.Set("wait", fmt.Sprintf("%ds", int(wait.Seconds())))
	}
	path := "/v1/health/service/" + url.PathEscape(s.Name)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var lastErr error
	for _, i := range cc.order() {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		ts, idx, err := cc.healthOnce(ctx, cc.bases[i]+path, s, wait, f)
		if err == nil {
			cc.markOK(i)
			return ts, idx, nil
		}
		var r retryable
		if !errors.As(err, &r) || ctx.Err() != nil {
			return nil, 0, err
		}
		cc.markFail(i, err)
		lastErr = err
	}
	return nil, 0, fmt.Errorf("consul %s: all %d endpoints failed, last: %v", s, len(cc.bases), lastErr)
}

func (cc *ConsulClient) healthOnce(ctx context.Context, u string, s ServiceRef, wait time.Duration, f healthFilter) ([]Target, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
	defer cancel()
	intr := cc.interruptCh()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-intr:
			cancel()
		case <-stop:
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if cc.tokenFile != "" {
		if tok, err := os.ReadFile(cc.tokenFile); err == nil {
			if t := strings.TrimSpace(string(tok)); t != "" {
				req.Header.Set("X-Consul-Token", t)
			}
		} else if !os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("token file: %v", err)
		}
	}
	resp, err := cc.http.Do(req)
	if err != nil {
		select {
		case <-intr:
			return nil, 0, errInterrupted
		default:
		}
		return nil, 0, retryable{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("consul %s: HTTP %d: %s", s, resp.StatusCode, strings.TrimSpace(string(b)))
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return nil, 0, retryable{err}
		}
		return nil, 0, err
	}
	newIndex, _ := strconv.ParseUint(resp.Header.Get("X-Consul-Index"), 10, 64)
	var entries []healthEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&entries); err != nil {
		select {
		case <-intr:
			return nil, 0, errInterrupted
		default:
		}
		return nil, 0, retryable{fmt.Errorf("consul %s: decode: %v", s, err)}
	}
	return filterEntries(entries, f), newIndex, nil
}

func entriesToTargets(entries []healthEntry, includeCritical bool) []Target {
	if includeCritical {
		return filterEntries(entries, filterAll)
	}
	return filterEntries(entries, filterNoCritical)
}

func filterEntries(entries []healthEntry, f healthFilter) []Target {
	var out []Target
	for _, e := range entries {
		skip := false
		for _, c := range e.Checks {
			if (f == filterNoCritical && c.Status == "critical") || (f == filterPassing && c.Status != "passing") {
				skip = true
			}
		}
		if skip {
			continue
		}
		addr := e.Service.Address
		if addr == "" {
			addr = e.Node.Address
		}
		a, err := netip.ParseAddr(addr)
		if err != nil || e.Service.Port <= 0 || e.Service.Port > 65535 {
			logf("consul: skipping %s instance on %s: non-IP address %q or bad port %d", e.Service.Service, e.Node.Node, addr, e.Service.Port)
			continue
		}
		out = append(out, Target{a.Unmap(), uint16(e.Service.Port)})
	}
	return out
}

// nextIndex applies Consul's blocking-query index rules: reset on going backwards, never 0.
func nextIndex(prev, got uint64) uint64 {
	if got < prev || got == 0 {
		return 0
	}
	return got
}
