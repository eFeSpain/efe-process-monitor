package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent callers with the same key share one execution; a different key
// runs on its own; once the call is over the next caller starts a fresh one.
func TestFlightGroupCoalesces(t *testing.T) {
	var g flightGroup[bool, int]
	var calls atomic.Int32
	slow := func() int {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return 42
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v := g.Do(true, slow); v != 42 {
				t.Errorf("Do = %d, want 42", v)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.Do(false, slow) // another key: its own execution
	}()
	wg.Wait()
	if n := calls.Load(); n != 2 {
		t.Errorf("fn ran %d times, want 2 (one per key)", n)
	}
	g.Do(true, slow) // nothing in flight: runs again
	if n := calls.Load(); n != 3 {
		t.Errorf("fn ran %d times after the flight ended, want 3", n)
	}
}

// A panic inside fn must not leave the key stuck in flight forever.
func TestFlightGroupReleasesOnPanic(t *testing.T) {
	var g flightGroup[string, int]
	func() {
		defer func() { recover() }()
		g.Do("k", func() int { panic("boom") })
	}()
	done := make(chan int, 1)
	go func() { done <- g.Do("k", func() int { return 1 }) }()
	select {
	case v := <-done:
		if v != 1 {
			t.Errorf("Do after panic = %d, want 1", v)
		}
	case <-time.After(time.Second):
		t.Fatal("key stayed in flight after a panic")
	}
}

// The analysis is language-neutral; the breakdown text is a view of it. Two
// browsers in different languages used to race on a process-wide "current
// language" and could each see the other's words.
func TestLocalizedConnectionsPerRequest(t *testing.T) {
	shared := []Conn{{BreakdownCode: "path_staging/25"}, {BreakdownCode: "clean"}}
	es := localizedConnections(shared, "es")
	en := localizedConnections(shared, "en")
	if es[0].Breakdown == en[0].Breakdown || es[0].Breakdown == "" || en[0].Breakdown == "" {
		t.Errorf("es=%q en=%q: should differ and be non-empty", es[0].Breakdown, en[0].Breakdown)
	}
	if es[0].Breakdown != localizeBreakdown("es", "path_staging/25") || en[1].Breakdown != localizeBreakdown("en", "clean") {
		t.Errorf("not localized through localizeBreakdown: %q / %q", es[0].Breakdown, en[1].Breakdown)
	}
	if shared[0].Breakdown != "" {
		t.Error("the shared slice must not be mutated by a request's localization")
	}
}
