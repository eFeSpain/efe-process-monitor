package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

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

// ThreatFox moved behind an Auth-Key in 2025 and the CSV exports answer 410;
// get_iocs is what remains: the last seven days of IOCs as JSON. Only ip:port
// entries feed the IP map; the label is the malware family, falling back to
// the threat type.
const tfAPIFixture = `{"query_status":"ok","data":[
 {"id":"1","ioc":"203.0.113.10:14642","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"win.remcos","malware_printable":"Remcos","confidence_level":75},
 {"id":"2","ioc":"bad.example.com","threat_type":"botnet_cc","ioc_type":"domain","malware_printable":"Dridex","confidence_level":50},
 {"id":"3","ioc":"198.51.100.7:443","threat_type":"payload_delivery","ioc_type":"ip:port","malware_printable":"","confidence_level":100},
 {"id":"4","ioc":"not-an-ip-port","threat_type":"botnet_cc","ioc_type":"ip:port","malware_printable":"X","confidence_level":50},
 {"id":"5","ioc":"abcd","threat_type":"botnet_cc","ioc_type":"sha256_hash","malware_printable":"Y","confidence_level":50}
]}`

func TestParseThreatFoxAPI(t *testing.T) {
	m, err := parseThreatFoxAPI(strings.NewReader(tfAPIFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("got %d entries, want 2 (ip:port only): %v", len(m), m)
	}
	if m["203.0.113.10"] != "Remcos" {
		t.Errorf("label=%q, want Remcos", m["203.0.113.10"])
	}
	if m["198.51.100.7"] != "payload_delivery" {
		t.Errorf("empty malware_printable should fall back to the threat type, got %q", m["198.51.100.7"])
	}
	if _, ok := m["bad.example.com"]; ok {
		t.Error("domain IOC leaked into the ip map")
	}
	if _, err := parseThreatFoxAPI(strings.NewReader(`{"query_status":"unknown_auth_key"}`)); err == nil {
		t.Error("a non-ok query_status must be an error, not an empty feed")
	}
	if _, err := parseThreatFoxAPI(strings.NewReader(`{"query_status":"ok","data":[]}`)); err != nil {
		t.Errorf("an empty but ok answer is not an error: %v", err)
	}
}

// Every feed used to retry a dead endpoint every ten minutes forever, and a
// failed download looked exactly like "nothing listed". feedMeta is the shared
// bookkeeping: when to try again, and what to tell the operator.
func TestFeedMetaRetryAndGone(t *testing.T) {
	var m feedMeta
	now := time.Now()
	if !m.due(now) {
		t.Error("a feed never fetched is due")
	}
	m.done(nil, 1200, now)
	if m.due(now.Add(feedTTL/2)) || !m.due(now.Add(feedTTL+time.Second)) {
		t.Error("a good fetch is reused until feedTTL and due after it")
	}
	t1 := now.Add(feedTTL + time.Second)
	m.done(httpStatusError(503), 0, t1)
	if m.due(t1.Add(feedFailTTL/2)) || !m.due(t1.Add(feedFailTTL+time.Second)) || m.gone {
		t.Error("a transient failure backs off for feedFailTTL and is not final")
	}
	if m.count != 1200 {
		t.Errorf("a failed refresh must keep the last good count, got %d", m.count)
	}
	m.done(httpStatusError(410), 0, t1)
	if !m.gone || m.due(t1.Add(48*time.Hour)) {
		t.Error("410 Gone means the endpoint no longer exists: never retry")
	}
	var n feedMeta
	n.done(errNoKey, 0, now)
	if !n.due(now.Add(time.Minute)) {
		t.Error("a feed waiting for a key is re-checked (the key can arrive from Settings at any time)")
	}
}

// The feed status is what the privacy modal and the banner show; a feed with
// no key, a dead endpoint and a failing download are three different things
// and must not read as "no signals".
func TestFeedStatusesDistinguishCauses(t *testing.T) {
	keysMu.Lock()
	oldKey := abusechKey
	abusechKey = ""
	keysMu.Unlock()
	t.Cleanup(func() { keysMu.Lock(); abusechKey = oldKey; keysMu.Unlock() })
	now := time.Now()
	torSet.mu.Lock()
	torSet.feedMeta = feedMeta{}
	torSet.feedMeta.done(nil, 1200, now.Add(-time.Hour))
	torSet.mu.Unlock()
	threatFox.mu.Lock()
	threatFox.feedMeta = feedMeta{}
	threatFox.feedMeta.done(errNoKey, 0, now)
	threatFox.mu.Unlock()
	spamhaus.mu.Lock()
	spamhaus.feedMeta = feedMeta{}
	spamhaus.feedMeta.done(httpStatusError(410), 0, now)
	spamhaus.mu.Unlock()

	st := map[string]FeedStatus{}
	for _, s := range feedStatuses("en") {
		st[s.ID] = s
	}
	if !st["tor"].OK || !strings.Contains(st["tor"].Status, "1200") {
		t.Errorf("tor: %+v", st["tor"])
	}
	if st["threatfox"].OK || !strings.Contains(st["threatfox"].Status, strings_("en")["feed_nokey"]) {
		t.Errorf("threatfox without key: %+v", st["threatfox"])
	}
	if st["spamhaus"].OK || !strings.Contains(st["spamhaus"].Status, "410") {
		t.Errorf("spamhaus gone: %+v", st["spamhaus"])
	}
}
