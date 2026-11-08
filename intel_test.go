package main

import (
	"net"
	"testing"
	"time"
)

const tfFixture = `################################################################
# ThreatFox IOCs (CSV)                                          #
################################################################
"2026-06-07 10:00:22", "1", "165.154.227.66:8080", "ip:port", "botnet_cc", "win.cobalt_strike", "alias", "Cobalt Strike", "", "100", "True", "None", "tag", "1", "rep"
"2026-06-07 09:52:46", "2", "221.130.29.85:2375", "ip:port", "payload_delivery", "elf.kinsing", "h2miner", "Kinsing", "", "85", "False", "ref", "tag", "0", "rep"
"2026-06-07 09:00:00", "3", "bad.example.com", "domain", "botnet_cc", "win.x", "a", "FamilyDomain", "", "50", "True", "None", "t", "1", "r"
"2026-06-07 08:00:00", "4", "10.0.0.9:4444", "ip:port", "botnet_cc", "win.y", "a", "None", "", "75", "True", "None", "t", "1", "r"
`

func TestParseThreatFox(t *testing.T) {
	m := parseThreatFox(tfFixture)
	if len(m) != 3 { // 3 ip:port rows; the domain row is skipped
		t.Fatalf("got %d entries, want 3: %v", len(m), m)
	}
	if m["165.154.227.66"] != "Cobalt Strike" {
		t.Errorf("cobalt strike label=%q", m["165.154.227.66"])
	}
	if m["221.130.29.85"] != "Kinsing" {
		t.Errorf("kinsing label=%q", m["221.130.29.85"])
	}
	// malware_printable "None" falls back to threat_type.
	if m["10.0.0.9"] != "botnet_cc" {
		t.Errorf("fallback label=%q, want botnet_cc", m["10.0.0.9"])
	}
	// domain IOC must not appear.
	if _, ok := m["bad.example.com"]; ok {
		t.Error("domain IOC leaked into ip map")
	}
}

func TestParseThreatFoxEmpty(t *testing.T) {
	if m := parseThreatFox("# only a comment\n"); len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

const spamhausFixture = `; comment line should be ignored
{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripencc"}

{"type":"metadata","timestamp":1780827242,"records":2,"copyright":"x"}
`

func TestParseSpamhaus(t *testing.T) {
	nets := parseSpamhaus(spamhausFixture)
	if len(nets) != 2 { // metadata + comment + blank lines skipped
		t.Fatalf("got %d nets, want 2", len(nets))
	}
	hit := func(ip string) bool {
		a := net.ParseIP(ip)
		for _, n := range nets {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}
	if !hit("1.10.16.1") {
		t.Error("1.10.16.1 should be inside 1.10.16.0/20")
	}
	if !hit("2.56.193.5") {
		t.Error("2.56.193.5 should be inside 2.56.192.0/22")
	}
	if hit("8.8.8.8") {
		t.Error("8.8.8.8 must not match any DROP netblock")
	}
}

func TestParseSpamhausGarbage(t *testing.T) {
	if nets := parseSpamhaus(`{"cidr":"not-a-cidr"}` + "\n" + `garbage`); len(nets) != 0 {
		t.Errorf("expected 0 nets from garbage, got %d", len(nets))
	}
}

// The render must never wait on the network. An address without a cached
// verdict comes back nil — the row shows as partial — and is queued for the
// background workers; a cached one is returned straight away.
func TestEnrichIPCachedNeverBlocks(t *testing.T) {
	ipCacheMu.Lock()
	ipCache = map[string]ipCacheEntry{}
	ipCacheMu.Unlock()
	enrichQueue.reset()

	const ip = "203.0.113.9"
	if d := enrichIPCached(ip); d != nil {
		t.Fatalf("uncached address returned %+v, want nil", d)
	}
	if !enrichQueue.isPending(ip) {
		t.Error("uncached address was not queued for the background lookup")
	}
	if enrichQueue.len() != 1 || <-enrichQueue.ch != ip {
		t.Error("queue does not hold exactly the requested address")
	}
	enrichIPCached(ip) // asked again while pending: no second queue entry
	if enrichQueue.len() != 0 {
		t.Error("an address already pending must not be queued twice")
	}
	enrichQueue.reset()

	want := &Enrichment{Country: "Nowhere"}
	storeIP(ip, want, false)
	if d := enrichIPCached(ip); d != want {
		t.Errorf("cached address returned %+v, want the cached entry", d)
	}
	if enrichQueue.len() != 0 {
		t.Error("a cached address must not be queued")
	}
}

// When a queued lookup lands the SSE clients get a "refresh" nudge, so the
// pending row fills in without the operator doing anything. Hermetic: the
// address is pre-cached, so enrichIP returns without touching the network.
func TestEnrichWorkerNudgesClients(t *testing.T) {
	ch := subscribe()
	defer unsubscribe(ch)
	const ip = "203.0.113.77"
	storeIP(ip, &Enrichment{Country: "Nowhere"}, false)
	q := newLookupQueue(8) // own queue: the shared one may have workers in other tests
	q.start(1, enrichResolve, lookupDrained)
	q.enqueue(ip)
	select {
	case ev := <-ch:
		if ev.Kind != "refresh" {
			t.Errorf("event kind = %q, want refresh", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh event after the queued lookup completed")
	}
	if q.isPending(ip) {
		t.Error("address still marked pending after resolution")
	}
}
