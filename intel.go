package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Enrichment is the threat-intel context gathered for a remote IP.
type Enrichment struct {
	Country, City, ISP, Org, ASN, DNS string
	VTMalicious                       *int
	AbuseScore                        *int
	Tor                               bool
	C2                                bool
	ThreatFox                         string // malware family if listed in ThreatFox, else ""
	URLhaus                           string // family/threat if the host serves a live malware URL (URLhaus), else ""
	Spamhaus                          bool   // in a Spamhaus DROP criminal/hijacked netblock
	Ports                             []int
	Vulns                             []string
	Tags                              []string
	Provider                          string // matched well-known provider, if any
}

// knownProviders are major reputable orgs whose shared cloud IPs often collect
// noisy AbuseIPDB reports without being malicious.
var knownProviders = map[string]string{
	"anthropic": "Anthropic", "openai": "OpenAI", "google": "Google",
	"microsoft": "Microsoft", "azure": "Microsoft", "amazon": "Amazon",
	"aws": "Amazon", "cloudfront": "Amazon", "cloudflare": "Cloudflare",
	"akamai": "Akamai", "fastly": "Fastly", "apple": "Apple",
	"meta": "Meta", "facebook": "Meta", "github": "GitHub", "mozilla": "Mozilla",
}

func detectProvider(e *Enrichment) string {
	hay := strings.ToLower(e.ISP + " " + e.Org + " " + e.ASN + " " + e.DNS)
	for k, name := range knownProviders {
		if strings.Contains(hay, k) {
			return name
		}
	}
	return ""
}

var httpClient = &http.Client{Timeout: 8 * time.Second}

// ── API keys (mutable at runtime via settings) ──────────────────────────────

var (
	keysMu     sync.RWMutex
	vtKey      = os.Getenv("VT_API_KEY")
	abuseKey   = os.Getenv("ABUSEIPDB_API_KEY")
	abusechKey = os.Getenv("ABUSECH_API_KEY") // abuse.ch Auth-Key: ThreatFox moved behind one in 2025
)

func getVTKey() string      { keysMu.RLock(); defer keysMu.RUnlock(); return vtKey }
func getAbuseKey() string   { keysMu.RLock(); defer keysMu.RUnlock(); return abuseKey }
func getAbuseChKey() string { keysMu.RLock(); defer keysMu.RUnlock(); return abusechKey }

// ── IP enrichment cache (TTL) ───────────────────────────────────────────────

type ipCacheEntry struct {
	at      time.Time
	data    *Enrichment
	partial bool // geo lookup failed → shorter TTL, but still cached
}

var (
	ipCacheMu sync.Mutex
	ipCache   = map[string]ipCacheEntry{}
	ipTTL     = time.Hour
	// partialIPTTL is the (short) lifetime of an entry whose geo lookup failed.
	// The result is still cached: not caching it meant that once the geo provider
	// rate-limited us, *nothing* was cached, so every refresh re-queried
	// VirusTotal, AbuseIPDB, Shodan and reverse DNS for every address on screen —
	// burning exactly the quotas we were trying to protect.
	partialIPTTL = 5 * time.Minute

	// inflight coalesces concurrent lookups of the same IP. Without it the table
	// render and the live monitor both enrich the same address at the same time.
	inflightMu sync.Mutex
	inflight   = map[string]*inflightIP{}
)

type inflightIP struct {
	done chan struct{}
	data *Enrichment
}

// maxIPCache bounds the cache; enrichment entries were previously never evicted,
// only ignored once stale, so the map grew for the life of the process.
const maxIPCache = 4096

func cachedIP(ip string) (*Enrichment, bool) {
	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()
	e, ok := ipCache[ip]
	if !ok {
		return nil, false
	}
	ttl := ipTTL
	if e.partial {
		ttl = partialIPTTL
	}
	if time.Since(e.at) >= ttl {
		delete(ipCache, ip)
		return nil, false
	}
	return e.data, true
}

func storeIP(ip string, d *Enrichment, partial bool) {
	ipCacheMu.Lock()
	defer ipCacheMu.Unlock()
	if len(ipCache) >= maxIPCache {
		// Cheap bound: drop everything already expired, and if that wasn't
		// enough, start fresh rather than grow without limit.
		for k, e := range ipCache {
			ttl := ipTTL
			if e.partial {
				ttl = partialIPTTL
			}
			if time.Since(e.at) >= ttl {
				delete(ipCache, k)
			}
		}
		if len(ipCache) >= maxIPCache {
			ipCache = map[string]ipCacheEntry{}
		}
	}
	ipCache[ip] = ipCacheEntry{at: time.Now(), data: d, partial: partial}
}

func enrichIP(ip string) *Enrichment {
	if d, ok := cachedIP(ip); ok {
		return d
	}

	// One lookup per IP at a time; everyone else waits for that result.
	inflightMu.Lock()
	if f, ok := inflight[ip]; ok {
		inflightMu.Unlock()
		<-f.done
		return f.data
	}
	f := &inflightIP{done: make(chan struct{})}
	inflight[ip] = f
	inflightMu.Unlock()

	defer func() {
		inflightMu.Lock()
		delete(inflight, ip)
		inflightMu.Unlock()
		close(f.done)
	}()

	d := &Enrichment{Country: "N/A", City: "N/A", ISP: "N/A", Org: "N/A", ASN: "N/A", DNS: "N/A"}
	geoOK := geoLookup(ip, d)

	// Reverse DNS with its own deadline: the system resolver's can be far
	// longer than the HTTP client's 8 s, and this runs once per new address.
	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if names, err := net.DefaultResolver.LookupAddr(rctx, ip); err == nil && len(names) > 0 {
		d.DNS = strings.TrimSuffix(names[0], ".")
	}
	cancel()
	d.VTMalicious = vtIP(ip)
	d.AbuseScore = abuseIPDB(ip)
	d.Tor = torExits()[ip]
	d.C2 = feodoC2()[ip]
	d.ThreatFox = threatFoxLookup(ip)
	d.URLhaus = urlhausLookup(ip)
	d.Spamhaus = spamhausHit(ip)
	shodan(ip, d)
	d.Provider = detectProvider(d)

	f.data = d
	storeIP(ip, d, !geoOK)
	return d
}

// ── Background enrichment ────────────────────────────────────────────────────
//
// The table render used to call enrichIP inline and wait: up to five network
// calls per address, sequential, eight seconds each, eight addresses at a
// time. A first load or a burst of new destinations held the page for seconds.
// VirusTotal and the signatures had already moved off the request path; this
// is the same pattern for reputation. The render reads the cache; a miss is
// reported as nil — the row renders as partial — and queued here. When a
// lookup lands the SSE clients are nudged to refresh, so the row fills in on
// its own without the operator doing anything.

const enrichWorkers = 4

var enrichQueue = newLookupQueue(4096)

// enrichIPCached is the render-path lookup: cached data or nil, never a wait.
func enrichIPCached(ip string) *Enrichment {
	if d, ok := cachedIP(ip); ok {
		return d
	}
	enrichQueue.enqueue(ip)
	return nil
}

// enrichResolve and lookupDrained are what main hands the queues: resolve
// through the existing enrichIP (its inflight coalescing and caches are
// unchanged), and nudge the SSE clients to redraw once a burst has landed.
func enrichResolve(ip string) { enrichIP(ip) }
func lookupDrained()          { broadcast(Event{Kind: "refresh"}) }

// geoLookup fills country/city/ISP/org/ASN from ipwho.is.
//
// This must be HTTPS. It used to call ip-api.com over plain HTTP, which not only
// leaked the addresses being investigated but let anyone on the path *rewrite*
// the answer — and the answer feeds the score: an injected "org":"Cloudflare"
// makes detectProvider report a known provider, which drops the AbuseIPDB weight
// from 0.4 to 0.1 and quietly attenuates a malicious IP. ip-api only serves TLS
// to paying keys, so the provider changed rather than the scheme.
func geoLookup(ip string, d *Enrichment) bool {
	var g struct {
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		City       string `json:"city"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := getJSON("https://ipwho.is/"+url.PathEscape(ip), nil, &g); err != nil {
		return false
	}
	if g.Country != "" {
		d.Country = g.Country
	}
	if g.City != "" {
		d.City = g.City
	}
	if g.Connection.ISP != "" {
		d.ISP = g.Connection.ISP
	}
	if g.Connection.Org != "" {
		d.Org = g.Connection.Org
	}
	if g.Connection.ASN != 0 {
		// Keep ip-api's "AS15169 Google LLC" shape: detectProvider matches on it.
		d.ASN = fmt.Sprintf("AS%d %s", g.Connection.ASN, g.Connection.Org)
	}
	return g.Success
}

func vtIP(ip string) *int {
	key := getVTKey()
	if key == "" {
		return nil
	}
	if !vtBucket.allow() { // share the 4/min VT quota; skip if exhausted
		return nil
	}
	var resp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious int `json:"malicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err := getJSON("https://www.virustotal.com/api/v3/ip_addresses/"+url.PathEscape(ip),
		map[string]string{"x-apikey": key}, &resp)
	if err != nil {
		return nil
	}
	m := resp.Data.Attributes.LastAnalysisStats.Malicious
	return &m
}

func abuseIPDB(ip string) *int {
	key := getAbuseKey()
	if key == "" {
		return nil
	}
	var resp struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	err := getJSON(
		"https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip),
		map[string]string{"Key": key, "Accept": "application/json"}, &resp)
	if err != nil {
		return nil
	}
	return &resp.Data.AbuseConfidenceScore
}

func shodan(ip string, d *Enrichment) {
	var resp struct {
		Ports []int    `json:"ports"`
		Vulns []string `json:"vulns"`
		Tags  []string `json:"tags"`
	}
	if err := getJSON("https://internetdb.shodan.io/"+url.PathEscape(ip), nil, &resp); err != nil {
		return
	}
	d.Ports, d.Vulns, d.Tags = resp.Ports, resp.Vulns, resp.Tags
}

// ── Intel feeds: Tor, Feodo, ThreatFox, Spamhaus ────────────────────────────

// Feed refresh cadence. failTTL is the key detail: on failure the "last
// attempted" timestamp must still advance, otherwise every single enrichIP call
// retries the download — serialized behind the feed's mutex, with an 8s timeout
// each — and one unreachable feed turns a page render into minutes of waiting.
const (
	feedTTL     = 24 * time.Hour
	feedFailTTL = 10 * time.Minute
)

// httpStatusError is a non-200 answer, kept as a type so a feed can tell a
// 410 Gone — the endpoint no longer exists, which is what happened to every
// abuse.ch export in 2025 — from a 503 worth retrying.
type httpStatusError int

func (e httpStatusError) Error() string { return fmt.Sprintf("status %d", int(e)) }

// errNoKey marks a feed that needs a key the operator has not configured.
var errNoKey = errors.New("no key configured")

// feedMeta is the bookkeeping every feed shares: when it last worked, when it
// was last tried, whether it is gone for good, and what to show the operator.
// A failed download used to look exactly like "nothing listed" — the ThreatFox
// export died and the score lost a 55-point signal without a word anywhere.
// This is what makes the difference visible (feedStatuses) and stops the
// ten-minute retry loop on a dead endpoint.
type feedMeta struct {
	at      time.Time     // last successful refresh
	triedAt time.Time     // last attempt, successful or not
	count   int           // entries loaded by the last successful refresh
	gone    bool          // 410: the endpoint no longer exists; never retry
	lastErr error         // nil after a success
	ttl     time.Duration // refresh cadence; 0 = feedTTL
}

// due reports whether a refresh should be attempted now. A feed waiting for a
// key is always due: the check is free and the key can arrive from Settings.
func (m *feedMeta) due(now time.Time) bool {
	if m.gone {
		return false
	}
	if m.triedAt.IsZero() || errors.Is(m.lastErr, errNoKey) {
		return true
	}
	ttl := m.ttl
	if ttl == 0 {
		ttl = feedTTL
	}
	return now.Sub(m.at) >= ttl && now.Sub(m.triedAt) >= feedFailTTL
}

// done records the outcome of an attempt. A failure keeps the last good data
// and its count; a 410 marks the feed gone.
func (m *feedMeta) done(err error, count int, now time.Time) {
	m.triedAt, m.lastErr = now, err
	if err == nil {
		m.at, m.count = now, count
		return
	}
	var st httpStatusError
	if errors.As(err, &st) && int(st) == http.StatusGone {
		m.gone = true
	}
}

type ipSet struct {
	mu sync.Mutex
	feedMeta
	set map[string]bool
}

func (s *ipSet) get(url string, skipComments bool) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if !s.due(now) {
		return s.set
	}
	body, err := getText(url)
	if err != nil {
		s.done(err, 0, now)
		return s.set
	}
	set := map[string]bool{}
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || (skipComments && strings.HasPrefix(ln, "#")) {
			continue
		}
		set[ln] = true
	}
	if len(set) > 0 {
		s.set = set
	}
	s.done(nil, len(set), now)
	return s.set
}

var torSet, feodoSet ipSet

func torExits() map[string]bool {
	return torSet.get("https://check.torproject.org/torbulkexitlist", false)
}
func feodoC2() map[string]bool {
	return feodoSet.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", true)
}

// ── ThreatFox (abuse.ch API, Auth-Key required) ─────────────────────────────
//
// The zipped CSV export this used to download answers 410 Gone since abuse.ch
// moved every download behind a free Auth-Key (2025). What remains is the
// get_iocs query: the IOCs of the last seven days, as JSON, about 12 MB. The
// map is rebuilt from it once a day — ThreatFox itself expires IOCs after six
// months, so a seven-day window of fresh C2 is the live part of the feed.

const threatFoxAPI = "https://threatfox-api.abuse.ch/api/v1/"

type tfFeed struct {
	mu sync.Mutex
	feedMeta
	m       map[string]string // ip -> malware family/label
	domains map[string]string // C2 domain -> malware family/label
}

var threatFox tfFeed

func (f *tfFeed) refresh() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if !f.due(now) {
		return f.m
	}
	key := getAbuseChKey()
	if key == "" {
		f.done(errNoKey, 0, now)
		return f.m
	}
	resp, err := postRaw(threatFoxAPI, map[string]string{"Auth-Key": key}, `{"query":"get_iocs","days":7}`)
	if err != nil {
		f.done(err, 0, now)
		return f.m
	}
	defer resp.Body.Close()
	m, domains, err := parseThreatFoxAPI(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		f.done(err, 0, now)
		return f.m
	}
	f.m, f.domains = m, domains
	f.done(nil, len(m)+len(domains), now)
	return f.m
}

// parseThreatFoxAPI turns a get_iocs answer into an ip→family map and a
// domain→family map. ip:port IOCs feed the first. Domains feed the second only
// when they are C2 (botnet_cc): a payload-delivery domain is often somebody's
// compromised or shared hosting, and matching what processes ask for against
// those would flag ordinary traffic. URLs and hashes are other things. The
// label is the printable family, or the threat type when the family is unknown.
func parseThreatFoxAPI(r io.Reader) (ips, domains map[string]string, err error) {
	var resp struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC              string `json:"ioc"`
			ThreatType       string `json:"threat_type"`
			IOCType          string `json:"ioc_type"`
			MalwarePrintable string `json:"malware_printable"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("threatfox: %w", err)
	}
	if resp.QueryStatus != "ok" {
		return nil, nil, fmt.Errorf("threatfox: %s", resp.QueryStatus)
	}
	ips, domains = map[string]string{}, map[string]string{}
	for _, d := range resp.Data {
		label := d.MalwarePrintable
		if label == "" || label == "None" {
			label = d.ThreatType
		}
		switch d.IOCType {
		case "ip:port":
			if host, _, err := net.SplitHostPort(d.IOC); err == nil && net.ParseIP(host) != nil {
				ips[host] = label
			}
		case "domain":
			if name := cleanHostname(d.IOC); name != "" && d.ThreatType == "botnet_cc" {
				domains[name] = label
			}
		}
	}
	return ips, domains, nil
}

// matchIOCDomain looks the names a process asked for up in a domain IOC map:
// an exact match, or a subdomain of a listed domain. Never the parent of a
// listed one — "x.duckdns.org" being a C2 says nothing about duckdns.org.
func matchIOCDomain(names []Hostname, domains map[string]string) (name, label string) {
	if len(domains) == 0 {
		return "", ""
	}
	for _, h := range names {
		n := h.Name
		for {
			if l, ok := domains[n]; ok {
				return h.Name, l
			}
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
		}
	}
	return "", ""
}

// iocNameHit is matchIOCDomain against the loaded ThreatFox C2 domains.
func iocNameHit(names []Hostname) (name, label string) {
	if len(names) == 0 {
		return "", ""
	}
	threatFox.refresh()
	threatFox.mu.Lock()
	doms := threatFox.domains
	threatFox.mu.Unlock()
	return matchIOCDomain(names, doms)
}

func threatFoxLookup(ip string) string { return threatFox.refresh()[ip] }

// ── URLhaus (abuse.ch API, Auth-Key required) ────────────────────────────────
//
// URLhaus lists URLs that distribute malware. A connection can only be
// matched by address, so only URLs whose host is an IP literal count, and
// only while the URL is online — a host that served a dropper last week says
// little about today. It is not a C2 feed: distribution sites are often
// compromised legitimate servers, hence the smaller weight. The API answers
// with the last 1000 URLs (about 20 hours), so this feed refreshes every six
// hours rather than daily.

const (
	urlhausAPI = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000"
	urlhausTTL = 6 * time.Hour
)

type uhFeed struct {
	mu sync.Mutex
	feedMeta
	m map[string]string // ip -> family or threat
}

var urlhaus = uhFeed{feedMeta: feedMeta{ttl: urlhausTTL}}

func (f *uhFeed) refresh() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if !f.due(now) {
		return f.m
	}
	key := getAbuseChKey()
	if key == "" {
		f.done(errNoKey, 0, now)
		return f.m
	}
	req, err := http.NewRequest("GET", urlhausAPI, nil)
	if err != nil {
		f.done(err, 0, now)
		return f.m
	}
	req.Header.Set("Auth-Key", key)
	resp, err := httpClient.Do(req)
	if err != nil {
		f.done(err, 0, now)
		return f.m
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		f.done(httpStatusError(resp.StatusCode), 0, now)
		return f.m
	}
	m, err := parseURLhausAPI(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		f.done(err, 0, now)
		return f.m
	}
	f.m = m
	f.done(nil, len(m), now)
	return f.m
}

// parseURLhausAPI turns a urls/recent answer into an ip→label map: online
// URLs on IP-literal hosts only. The label is the first tag that names a
// family — URLhaus capitalizes those (Mozi, SmartLoader) and keeps format and
// architecture tags lowercase (elf, mipsel, zip) — else the threat type.
func parseURLhausAPI(r io.Reader) (map[string]string, error) {
	var resp struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			Host   string   `json:"host"`
			Status string   `json:"url_status"`
			Threat string   `json:"threat"`
			Tags   []string `json:"tags"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("urlhaus: %w", err)
	}
	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("urlhaus: %s", resp.QueryStatus)
	}
	m := map[string]string{}
	for _, u := range resp.URLs {
		if u.Status != "online" || net.ParseIP(u.Host) == nil {
			continue
		}
		if _, seen := m[u.Host]; seen {
			continue // first (most recent) entry wins
		}
		label := u.Threat
		for _, t := range u.Tags {
			if t != "" && t[0] >= 'A' && t[0] <= 'Z' {
				label = t
				break
			}
		}
		m[u.Host] = label
	}
	return m, nil
}

func urlhausLookup(ip string) string { return urlhaus.refresh()[ip] }

// ── Spamhaus DROP (criminal/hijacked netblocks, CIDR, no key) ────────────────

type cidrFeed struct {
	mu sync.Mutex
	feedMeta
	nets []*net.IPNet
}

var spamhaus cidrFeed

// spamhausURLs are the DROP lists, one per address family. Only the IPv4 one
// used to be loaded, so an IPv6 connection into a hijacked netblock never
// scored.
var spamhausURLs = []string{
	"https://www.spamhaus.org/drop/drop_v4.json",
	"https://www.spamhaus.org/drop/drop_v6.json",
}

func (f *cidrFeed) refresh() []*net.IPNet {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if !f.due(now) {
		return f.nets
	}
	// Both families or nothing: half a list would read as "updated" while
	// every IPv6 (or IPv4) connection silently went unchecked.
	var nets []*net.IPNet
	for _, u := range spamhausURLs {
		body, err := getText(u)
		if err != nil {
			f.done(err, 0, now)
			return f.nets
		}
		nets = append(nets, parseSpamhaus(body)...)
	}
	if len(nets) > 0 {
		f.nets = nets
	}
	f.done(nil, len(f.nets), now)
	return f.nets
}

// parseSpamhaus turns a Spamhaus DROP list (drop_v4.json / drop_v6.json: one JSON object per line)
// into a list of networks, skipping blanks and the trailing metadata line.
func parseSpamhaus(body string) []*net.IPNet {
	var nets []*net.IPNet
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.Contains(ln, `"cidr"`) { // skips blanks and the metadata line
			continue
		}
		var row struct {
			Cidr string `json:"cidr"`
		}
		if json.Unmarshal([]byte(ln), &row) != nil || row.Cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(row.Cidr); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func spamhausHit(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, n := range spamhaus.refresh() {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// primeIntel warms every feed at start-up and logs where each one stands, so a
// dead or keyless feed is in the log from minute one instead of being inferred
// from a score that never fires.
func primeIntel() {
	torExits()
	feodoC2()
	threatFox.refresh()
	urlhaus.refresh()
	spamhaus.refresh()
	for _, s := range feedStatuses("en") {
		mark := "[+]"
		if !s.OK {
			mark = "[-]"
		}
		log.Printf("%s Feed %-11s %s", mark, s.Name, s.Status)
	}
}

// FeedStatus is one feed as shown in the privacy modal and the banner.
type FeedStatus struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // localized
	OK     bool   `json:"ok"`
}

// feedStatuses reports every feed in lang. "No key", "gone", "failing" and
// "loading" are four different things, none of which is "no signals".
func feedStatuses(lang string) []FeedStatus {
	T := strings_(lang)
	now := time.Now()
	one := func(id, name string, mu *sync.Mutex, m *feedMeta) FeedStatus {
		mu.Lock()
		meta := *m
		mu.Unlock()
		st := FeedStatus{ID: id, Name: name}
		switch {
		case meta.gone:
			st.Status = T["feed_gone"]
		case errors.Is(meta.lastErr, errNoKey):
			st.Status = T["feed_nokey"]
		case meta.triedAt.IsZero():
			st.Status = T["feed_pending"]
		case meta.lastErr != nil && meta.count > 0:
			st.Status = fmt.Sprintf(T["feed_stale"], meta.count, humanAge(now.Sub(meta.at), T), meta.lastErr)
		case meta.lastErr != nil:
			st.Status = fmt.Sprintf(T["feed_error"], meta.lastErr)
		default:
			st.OK = true
			st.Status = fmt.Sprintf(T["feed_updated"], meta.count, humanAge(now.Sub(meta.at), T))
		}
		return st
	}
	return []FeedStatus{
		one("tor", "Tor exits", &torSet.mu, &torSet.feedMeta),
		one("feodo", "Feodo C2", &feodoSet.mu, &feodoSet.feedMeta),
		one("threatfox", "ThreatFox", &threatFox.mu, &threatFox.feedMeta),
		one("urlhaus", "URLhaus", &urlhaus.mu, &urlhaus.feedMeta),
		one("spamhaus", "Spamhaus", &spamhaus.mu, &spamhaus.feedMeta),
	}
}

// ipReport builds a short human summary of an IP from its (cached) enrichment.
func ipReport(ip string) string {
	e := enrichIP(ip)
	T := strings_(currentLang())
	var p []string
	if e.Country != "" && e.Country != "N/A" {
		p = append(p, e.City+", "+e.Country)
	}
	if e.ISP != "" && e.ISP != "N/A" {
		p = append(p, e.ISP)
	}
	if e.Provider != "" {
		p = append(p, T["rp_provider"]+": "+e.Provider)
	}
	if e.AbuseScore != nil && *e.AbuseScore > 0 {
		p = append(p, fmt.Sprintf("AbuseIPDB %d%%", *e.AbuseScore))
	}
	if e.VTMalicious != nil && *e.VTMalicious > 0 {
		p = append(p, fmt.Sprintf("VT-IP %d", *e.VTMalicious))
	}
	if e.C2 {
		p = append(p, "C2 Feodo")
	}
	if e.ThreatFox != "" {
		p = append(p, "ThreatFox: "+e.ThreatFox)
	}
	if e.URLhaus != "" {
		p = append(p, "URLhaus: "+e.URLhaus)
	}
	if e.Spamhaus {
		p = append(p, "Spamhaus DROP")
	}
	if e.Tor {
		p = append(p, "Tor exit")
	}
	if len(p) == 0 {
		return T["rp_none"]
	}
	return strings.Join(p, " · ")
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

func getJSON(url string, headers map[string]string, out any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return httpStatusError(resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// postRaw sends a small JSON body and returns the response for the caller to
// read and close; a non-200 status is an httpStatusError.
func postRaw(url string, headers map[string]string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, httpStatusError(resp.StatusCode)
	}
	return resp, nil
}

// Feed downloads are bounded: these bodies come from third parties over the
// network, and an unbounded read on a hostile or broken upstream is an OOM of
// the monitor. ThreatFox's seven-day answer is ~12 MiB today.
const maxFeedBytes = 64 << 20

func getText(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Status must be checked: an upstream 503 HTML page would otherwise be parsed
	// as feed content and cached as "the Tor exit list" for 24h.
	if resp.StatusCode != 200 {
		return "", httpStatusError(resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	return string(b), err
}
