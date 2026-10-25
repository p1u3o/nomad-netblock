package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NomadRef is a Nomad native (provider = "nomad") service: name[@namespace].
type NomadRef struct {
	Name      string
	Namespace string // empty = the task's namespace
}

func (n NomadRef) String() string {
	out := "nomad:" + n.Name
	if n.Namespace != "" {
		out += "@" + n.Namespace
	}
	return out
}

func parseNomadService(e string) (NomadRef, error) {
	name, ns, hasNS := strings.Cut(strings.TrimSpace(e), "@")
	if !validName(name) || (hasNS && !validName(ns)) {
		return NomadRef{}, fmt.Errorf("bad nomad service %q (want name[@namespace])", e)
	}
	return NomadRef{Name: name, Namespace: ns}, nil
}

// NomadClient reads /v1/service/<name> with blocking queries. By default it talks to the
// Task API socket ($NOMAD_SECRETS_DIR/api.sock), which needs no network egress, and
// authenticates with the workload identity token ($NOMAD_TOKEN, from identity { env = true },
// or nomad_token_file).
type NomadClient struct {
	base      string
	token     func() (string, error)
	defaultNS string
	http      *http.Client
}

func NewNomadClient(c Config) (*NomadClient, error) {
	addr := c.NomadAddr
	if addr == "" {
		if d := os.Getenv("NOMAD_SECRETS_DIR"); d != "" {
			if _, err := os.Stat(filepath.Join(d, "api.sock")); err == nil {
				addr = "unix://" + filepath.Join(d, "api.sock")
			}
		}
	}
	if addr == "" {
		addr = os.Getenv("NOMAD_ADDR")
	}
	if addr == "" {
		return nil, fmt.Errorf("allow_nomad_services: no Task API socket, nomad_addr or NOMAD_ADDR")
	}
	rt := &http.Transport{DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second}
	base := strings.TrimRight(addr, "/")
	if p, ok := strings.CutPrefix(addr, "unix://"); ok {
		rt.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", p)
		}
		base = "http://localhost"
	}
	tokFile := c.NomadTokenFile
	tok := func() (string, error) {
		if t := os.Getenv("NOMAD_TOKEN"); t != "" {
			return t, nil
		}
		b, err := os.ReadFile(tokFile)
		if err != nil {
			return "", fmt.Errorf("nomad token: no NOMAD_TOKEN and %v", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return &NomadClient{base: base, token: tok, defaultNS: os.Getenv("NOMAD_NAMESPACE"), http: &http.Client{Transport: rt}}, nil
}

type nomadReg struct {
	Address string
	Port    int
	NodeID  string
}

func (nc *NomadClient) Services(ctx context.Context, s NomadRef, index uint64, wait time.Duration) ([]Target, uint64, error) {
	q := url.Values{}
	ns := s.Namespace
	if ns == "" {
		ns = nc.defaultNS
	}
	if ns != "" {
		q.Set("namespace", ns)
	}
	if index > 0 {
		q.Set("index", strconv.FormatUint(index, 10))
		q.Set("wait", fmt.Sprintf("%ds", int(wait.Seconds())))
	}
	u := nc.base + "/v1/service/" + url.PathEscape(s.Name)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	tok, err := nc.token()
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Nomad-Token", tok)
	resp, err := nc.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nomad %s: %v", s, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, 0, fmt.Errorf("nomad %s: HTTP %d: %s", s, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	idx, _ := strconv.ParseUint(resp.Header.Get("X-Nomad-Index"), 10, 64)
	var regs []nomadReg
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&regs); err != nil {
		return nil, 0, fmt.Errorf("nomad %s: decode: %v", s, err)
	}
	return regsToTargets(s, regs), idx, nil
}

func regsToTargets(s NomadRef, regs []nomadReg) []Target {
	var out []Target
	for _, r := range regs {
		a, err := netip.ParseAddr(r.Address)
		if err != nil || r.Port <= 0 || r.Port > 65535 {
			logf("nomad: skipping %s instance on %s: non-IP address %q or bad port %d", s, r.NodeID, r.Address, r.Port)
			continue
		}
		out = append(out, Target{a.Unmap(), uint16(r.Port)})
	}
	return out
}

// source is one watched service from either backend.
type source struct {
	key   string
	fetch func(ctx context.Context, index uint64, wait time.Duration) ([]Target, uint64, error)
}

// buildSources returns all service sources; cc is nil when no Consul services are configured.
func buildSources(c Config) ([]source, *ConsulClient, error) {
	var out []source
	var cc *ConsulClient
	if len(c.AllowServices) > 0 {
		var err error
		if cc, err = NewConsulClient(c); err != nil {
			return nil, nil, err
		}
		for _, s := range c.AllowServices {
			out = append(out, source{s.String(), func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
				return cc.Health(ctx, s, i, w, c.IncludeCritical)
			}})
		}
	}
	if len(c.AllowNomadServices) > 0 {
		nc, err := NewNomadClient(c)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range c.AllowNomadServices {
			out = append(out, source{s.String(), func(ctx context.Context, i uint64, w time.Duration) ([]Target, uint64, error) {
				return nc.Services(ctx, s, i, w)
			}})
		}
	}
	return out, cc, nil
}
