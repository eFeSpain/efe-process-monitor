package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// A lookupQueue is the "off the request path" primitive shared by the
// reputation and LAN passes: enqueue each key once while it is pending, run
// the lookups on a few workers, and call drained once when the burst is over.
func TestLookupQueueRunsEachKeyOnceAndReportsDrain(t *testing.T) {
	q := newLookupQueue(16)
	var runs, drains atomic.Int32
	q.start(2, func(k string) { runs.Add(1); time.Sleep(10 * time.Millisecond) },
		func() { drains.Add(1) })
	for i := 0; i < 3; i++ {
		q.enqueue("a")
		q.enqueue("b")
	}
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the workers see the empty queue
	if n := runs.Load(); n != 2 {
		t.Errorf("fn ran %d times, want 2 (once per distinct pending key)", n)
	}
	if n := drains.Load(); n < 1 || n > 2 {
		t.Errorf("drained called %d times, want once per burst (1, at most one per worker)", n)
	}
	if q.isPending("a") || q.isPending("b") {
		t.Error("keys still pending after their lookups ran")
	}
	q.enqueue("a") // no longer pending: runs again
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if runs.Load() != 3 {
		t.Error("a key whose lookup finished must be queueable again")
	}
}
