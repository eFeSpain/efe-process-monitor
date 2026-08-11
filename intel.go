package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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
	keysMu   sync.RWMutex
	vtKey    = os.Getenv("VT_API_KEY")
	abuseKey = os.Getenv("ABUSEIPDB_API_KEY")
)

func getVTKey() string    { keysMu.RLock(); defer keysMu.RUnlock(); return vtKey }
func getAbuseKey() string { keysMu.RLock(); defer keysMu.RUnlock(); return abuseKey }

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

	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		d.DNS = strings.TrimSuffix(names[0], ".")
	}
	d.VTMalicious = vtIP(ip)
	d.AbuseScore = abuseIPDB(ip)
	d.Tor = torExits()[ip]
	d.C2 = feodoC2()[ip]
	d.ThreatFox = threatFoxLookup(ip)
	d.Spamhaus = spamhausHit(ip)
	shodan(ip, d)
	d.Provider = detectProvider(d)

	f.data = d
	storeIP(ip, d, !geoOK)
	return d
}

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

// ── Daily-cached blocklists (Tor exits, Feodo C2) ───────────────────────────

// Feed refresh cadence. failTTL is the key detail: on failure the "last
// attempted" timestamp must still advance, otherwise every single enrichIP call
// retries the download — serialized behind the feed's mutex, with an 8s timeout
// each — and one unreachable feed turns a page render into minutes of waiting.
const (
	feedTTL     = 24 * time.Hour
	feedFailTTL = 10 * time.Minute
)

type ipSet struct {
	mu      sync.Mutex
	at      time.Time // last successful refresh
	triedAt time.Time // last attempt, successful or not
	set     map[string]bool
}

func (s *ipSet) get(url string, skipComments bool) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set != nil && (time.Since(s.at) < feedTTL || time.Since(s.triedAt) < feedFailTTL) {
		return s.set // fresh enough, or we tried recently and failed
	}
	s.triedAt = time.Now()
	body, err := getText(url)
	if err != nil {
		if s.set == nil {
			s.set = map[string]bool{}
		}
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
		s.set, s.at = set, time.Now()
	}
	return s.set
}

var torSet, feodoSet ipSet

func torExits() map[string]bool {
	return torSet.get("https://check.torproject.org/torbulkexitlist", false)
}
func feodoC2() map[string]bool {
	return feodoSet.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", true)
}

// ── ThreatFox C2/malware IOC feed (abuse.ch CSV, no key) ─────────────────────

type tfFeed struct {
	mu      sync.Mutex
	at      time.Time         // last successful refresh
	triedAt time.Time         // last attempt
	m       map[string]string // ip -> malware family/label
}

var threatFox tfFeed

func (f *tfFeed) refresh(force bool) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && f.m != nil && (time.Since(f.at) < feedTTL || time.Since(f.triedAt) < feedFailTTL) {
		return f.m
	}
	f.triedAt = time.Now()
	body, err := getZipCSV("https://threatfox.abuse.ch/export/csv/ip-port/full/")
	if err != nil {
		if f.m == nil {
			f.m = map[string]string{}
		}
		return f.m
	}
	if m := parseThreatFox(body); len(m) > 0 {
		f.m, f.at = m, time.Now()
	} else if f.m == nil {
		f.m = map[string]string{}
	}
	return f.m
}

// parseThreatFox turns the abuse.ch ThreatFox CSV into an ip→malware-family map.
func parseThreatFox(body string) map[string]string {
	r := csv.NewReader(strings.NewReader(body))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	rows, _ := r.ReadAll()
	m := map[string]string{}
	for _, rec := range rows {
		if len(rec) < 8 || rec[3] != "ip:port" {
			continue
		}
		host, _, err := net.SplitHostPort(rec[2])
		if err != nil || host == "" {
			continue
		}
		label := rec[7] // malware_printable
		if label == "" || label == "None" {
			label = rec[4] // threat_type fallback
		}
		m[host] = label
	}
	return m
}

func threatFoxLookup(ip string) string { return threatFox.refresh(false)[ip] }

// ── Spamhaus DROP (criminal/hijacked netblocks, CIDR, no key) ────────────────

type cidrFeed struct {
	mu      sync.Mutex
	at      time.Time // last successful refresh
	triedAt time.Time // last attempt
	nets    []*net.IPNet
}

var spamhaus cidrFeed

func (f *cidrFeed) refresh(force bool) []*net.IPNet {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && f.nets != nil && (time.Since(f.at) < feedTTL || time.Since(f.triedAt) < feedFailTTL) {
		return f.nets
	}
	f.triedAt = time.Now()
	body, err := getText("https://www.spamhaus.org/drop/drop_v4.json")
	if err != nil {
		if f.nets == nil {
			f.nets = []*net.IPNet{}
		}
		return f.nets
	}
	if nets := parseSpamhaus(body); len(nets) > 0 {
		f.nets, f.at = nets, time.Now()
	} else if f.nets == nil {
		f.nets = []*net.IPNet{}
	}
	return f.nets
}

// parseSpamhaus turns the Spamhaus DROP drop_v4.json (one JSON object per line)
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
	for _, n := range spamhaus.refresh(false) {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func primeIntel() {
	torExits()
	feodoC2()
	threatFox.refresh(false)
	spamhaus.refresh(false)
}

// ipReport builds a short human summary of an IP from its (cached) enrichment.
func ipReport(ip string) string {
	e := enrichIP(ip)
	var p []string
	if e.Country != "" && e.Country != "N/A" {
		p = append(p, e.City+", "+e.Country)
	}
	if e.ISP != "" && e.ISP != "N/A" {
		p = append(p, e.ISP)
	}
	if e.Provider != "" {
		p = append(p, "proveedor: "+e.Provider)
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
	if e.Spamhaus {
		p = append(p, "Spamhaus DROP")
	}
	if e.Tor {
		p = append(p, "Tor exit")
	}
	if len(p) == 0 {
		return "sin datos de inteligencia"
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
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Feed downloads are bounded: these bodies come from third parties over the
// network, and an unbounded io.ReadAll on a hostile or broken upstream is an OOM
// of the monitor. The uncompressed cap also defends against a zip bomb.
const (
	maxFeedBytes      = 64 << 20  // 64 MiB of compressed/raw download
	maxFeedUncompress = 256 << 20 // 256 MiB total after decompression
)

func getText(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Status must be checked: an upstream 503 HTML page would otherwise be parsed
	// as feed content and cached as "the Tor exit list" for 24h.
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	return string(b), err
}

// getZipCSV downloads a ZIP archive (abuse.ch "full" exports are zipped) and
// returns the concatenated text of every file inside it.
func getZipCSV(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	remaining := int64(maxFeedUncompress)
	for _, zf := range zr.File {
		if remaining <= 0 {
			return "", fmt.Errorf("zip demasiado grande al descomprimir (>%d bytes)", maxFeedUncompress)
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, remaining))
		rc.Close()
		remaining -= int64(len(b))
		sb.Write(b)
	}
	return sb.String(), nil
}
