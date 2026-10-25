package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Tracker holds per-service targets and applies the removal grace period.
type Tracker struct {
	mu       sync.Mutex
	grace    time.Duration
	current  map[string]map[Target]bool // service -> live targets (last known good)
	lastSeen map[Target]time.Time       // last time a target was in any service's set
	owners   map[Target]map[string]bool // target -> services that ever listed it
}

func NewTracker(grace time.Duration) *Tracker {
	return &Tracker{grace: grace, current: map[string]map[Target]bool{}, lastSeen: map[Target]time.Time{}, owners: map[Target]map[string]bool{}}
}

// Update replaces one service's targets (called only on a successful Consul read).
func (t *Tracker) Update(service string, ts []Target, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Removed targets keep their lastSeen = now so the grace starts at removal time.
	for old := range t.current[service] {
		t.lastSeen[old] = now
	}
	m := map[Target]bool{}
	for _, x := range ts {
		m[x] = true
		t.lastSeen[x] = now
		if t.owners[x] == nil {
			t.owners[x] = map[string]bool{}
		}
		t.owners[x][service] = true
	}
	t.current[service] = m
}

// Effective returns live targets plus removed ones still inside the grace period, sorted.
func (t *Tracker) Effective(now time.Time) (all []Target, graced int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	live := map[Target]bool{}
	for _, m := range t.current {
		for x := range m {
			live[x] = true
		}
	}
	for x, seen := range t.lastSeen {
		switch {
		case live[x]:
			all = append(all, x)
		case now.Sub(seen) < t.grace:
			all = append(all, x)
			graced++
		default:
			delete(t.lastSeen, x)
		}
	}
	sortTargets(all)
	return all, graced
}

// ServiceFor names the Consul service(s) that list(ed) this destination, or "".
func (t *Tracker) ServiceFor(x Target) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var s []string
	for n := range t.owners[x] {
		s = append(s, n)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// SetSizes returns live target counts per service.
func (t *Tracker) SetSizes() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]int{}
	for n, m := range t.current {
		out[n] = len(m)
	}
	return out
}

func sameTargets(a, b []Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
