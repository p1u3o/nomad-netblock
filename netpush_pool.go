package main

import (
	"slices"
	"sync"
	"time"
)

// pool holds one upstream's current targets and the live connections (TCP) or sessions
// (UDP) using them. When a target disappears its connections are marked draining: new
// connections go elsewhere, existing ones stay until the client closes or drain_timeout
// expires (0 = never force-close). A target that comes back before the timeout cancels
// the drain.
type pool struct {
	name  string
	drain time.Duration
	m     *upstreamMetrics

	mu      sync.Mutex
	targets []Target
	known   bool // at least one successful discovery
	active  map[Target]int
	rr      int
	conns   map[*fconn]struct{}
}

// fconn is one forwarded connection or UDP session.
type fconn struct {
	target Target
	close  func()
	timer  *time.Timer // non-nil while draining with a timeout
	drain  bool
}

func newPool(name string, drain time.Duration, m *upstreamMetrics) *pool {
	return &pool{name: name, drain: drain, m: m, active: map[Target]int{}, conns: map[*fconn]struct{}{}}
}

// update replaces the target list and starts or cancels draining.
func (p *pool) update(ts []Target) {
	ts = slices.Clone(ts)
	slices.SortFunc(ts, func(a, b Target) int {
		if c := a.Addr.Compare(b.Addr); c != 0 {
			return c
		}
		return int(a.Port) - int(b.Port)
	})
	ts = slices.Compact(ts)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets, p.known = ts, true
	p.m.setTargets(len(ts))
	for c := range p.conns {
		live := slices.Contains(ts, c.target)
		switch {
		case !live && !c.drain:
			c.drain = true
			p.m.draining.Add(1)
			logf("upstream %s: target %s gone, draining connection (timeout %s)", p.name, c.target, drainDesc(p.drain))
			if p.drain > 0 {
				cc := c
				c.timer = time.AfterFunc(p.drain, func() {
					p.m.forcedCloses.Add(1)
					logf("upstream %s: drain timeout, closing connection to %s", p.name, cc.target)
					cc.close()
				})
			}
		case live && c.drain:
			c.drain = false
			p.m.draining.Add(-1)
			if c.timer != nil {
				c.timer.Stop()
				c.timer = nil
			}
		}
	}
}

func drainDesc(d time.Duration) string {
	if d == 0 {
		return "never"
	}
	return d.String()
}

// pick chooses a target not in tried. ok=false if none is left.
func (p *pool) pick(bal Balance, tried []Target) (Target, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cand []Target
	for _, t := range p.targets {
		if !slices.Contains(tried, t) {
			cand = append(cand, t)
		}
	}
	if len(cand) == 0 {
		return Target{}, false
	}
	switch bal {
	case BalanceFirst:
		return cand[0], true
	case BalanceRoundRobin:
		p.rr++
		return cand[p.rr%len(cand)], true
	default: // least_conn, ties broken round robin
		p.rr++
		best, bestN := -1, 0
		for i := range cand {
			j := (i + p.rr) % len(cand)
			if n := p.active[cand[j]]; best < 0 || n < bestN {
				best, bestN = j, n
			}
		}
		return cand[best], true
	}
}

// acquire registers a connection to t. If t was removed while connecting, the
// connection starts out draining.
func (p *pool) acquire(t Target, closeFn func()) *fconn {
	c := &fconn{target: t, close: closeFn}
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.active[t]++
	stillLive := slices.Contains(p.targets, t)
	p.mu.Unlock()
	p.m.active.Add(1)
	p.m.total.Add(1)
	if !stillLive {
		p.update(p.snapshot())
	}
	return c
}

func (p *pool) release(c *fconn) {
	p.mu.Lock()
	if _, ok := p.conns[c]; !ok {
		p.mu.Unlock()
		return
	}
	delete(p.conns, c)
	if p.active[c.target]--; p.active[c.target] <= 0 {
		delete(p.active, c.target)
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.drain {
		p.m.draining.Add(-1)
	}
	p.mu.Unlock()
	p.m.active.Add(-1)
}

func (p *pool) snapshot() []Target {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.targets)
}

func (p *pool) ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.known
}
