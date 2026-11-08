package main

import "sync"

// flightGroup coalesces concurrent calls with the same key onto one execution:
// a caller that arrives while fn is running waits for that result instead of
// starting its own. The table render is the case that needs it — two open
// tabs, or the SSE-triggered refresh landing while a periodic one is still
// enriching, used to run two complete analyses, each a /proc pass per PID plus
// the hash, reputation and LAN passes.
//
// Generic rather than hard-wired to the render so a test can drive it with a
// counter; enrichIP keeps its own equivalent (inflight) for the same reason.
type flightGroup[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]*flightCall[V]
}

type flightCall[V any] struct {
	done chan struct{}
	val  V
}

// Do runs fn for key, or joins the run already in progress for it.
func (g *flightGroup[K, V]) Do(key K, fn func() V) V {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[K]*flightCall[V]{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.val
	}
	c := &flightCall[V]{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()
	// Deferred so a panic in fn still releases the key and wakes the waiters
	// (with the zero value) instead of parking them forever.
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		close(c.done)
	}()
	c.val = fn()
	return c.val
}
