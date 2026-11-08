package main

import (
	"testing"
	"time"
)

// The LAN pass used to run inline in the render: nmblookup and arp per LAN
// host, 5 s timeouts, a 10-minute cache — so every ten minutes a render stalled
// for seconds on hosts that do not answer NetBIOS. The render now reads the
// cache: a miss is nil and queued, a stale entry is served while a refresh is
// queued, so the LAN block never blinks out.
func TestLANLookupCachedNeverBlocks(t *testing.T) {
	lanMu.Lock()
	lanCache = map[string]*LANInfo{}
	lanAt = map[string]time.Time{}
	lanMu.Unlock()
	lanQueue.reset()

	const ip = "192.168.1.77"
	if got := lanLookupCached(ip); got != nil {
		t.Fatalf("uncached host returned %+v, want nil", got)
	}
	if !lanQueue.isPending(ip) || lanQueue.len() != 1 {
		t.Error("uncached host was not queued exactly once")
	}
	lanLookupCached(ip)
	if lanQueue.len() != 1 {
		t.Error("a pending host must not be queued twice")
	}
	lanQueue.reset()

	fresh := &LANInfo{NetBIOS: "NAS"}
	lanMu.Lock()
	lanCache[ip], lanAt[ip] = fresh, time.Now()
	lanMu.Unlock()
	if got := lanLookupCached(ip); got != fresh || lanQueue.len() != 0 {
		t.Errorf("fresh entry: got %+v queued=%d, want the entry and nothing queued", got, lanQueue.len())
	}

	lanMu.Lock()
	lanAt[ip] = time.Now().Add(-2 * lanTTL)
	lanMu.Unlock()
	if got := lanLookupCached(ip); got != fresh || lanQueue.len() != 1 {
		t.Errorf("stale entry: got %+v queued=%d, want the stale entry served and a refresh queued", got, lanQueue.len())
	}
	lanQueue.reset()
}
