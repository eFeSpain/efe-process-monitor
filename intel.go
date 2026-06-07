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
	at   time.Time
	data *Enrichment
}

var (
	ipCacheMu sync.Mutex
	ipCache   = map[string]ipCacheEntry{}
	ipTTL     = time.Hour
)

func enrichIP(ip string) *Enrichment {
	ipCacheMu.Lock()
	if e, ok := ipCache[ip]; ok && time.Since(e.at) < ipTTL {
		ipCacheMu.Unlock()
		return e.data
	}
	ipCacheMu.Unlock()

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

	if geoOK {
		ipCacheMu.Lock()
		ipCache[ip] = ipCacheEntry{time.Now(), d}
		ipCacheMu.Unlock()
	}
	return d
}

func geoLookup(ip string, d *Enrichment) bool {
	var g struct {
		Status, Country, City, ISP, Org, As string
	}
	if err := getJSON("http://ip-api.com/json/"+ip, nil, &g); err != nil {
		return false
	}
	if g.Country != "" {
		d.Country = g.Country
	}
	if g.City != "" {
		d.City = g.City
	}
	if g.ISP != "" {
		d.ISP = g.ISP
	}
	if g.Org != "" {
		d.Org = g.Org
	}
	if g.As != "" {
		d.ASN = g.As
	}
	return g.Status == "success"
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
	err := getJSON("https://www.virustotal.com/api/v3/ip_addresses/"+ip,
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
		fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip),
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
	if err := getJSON("https://internetdb.shodan.io/"+ip, nil, &resp); err != nil {
		return
	}
	d.Ports, d.Vulns, d.Tags = resp.Ports, resp.Vulns, resp.Tags
}

// ── Daily-cached blocklists (Tor exits, Feodo C2) ───────────────────────────

type ipSet struct {
	mu  sync.Mutex
	at  time.Time
	set map[string]bool
}

func (s *ipSet) get(url string, skipComments bool) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.at) < 24*time.Hour && s.set != nil {
		return s.set
	}
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
	mu sync.Mutex
	at time.Time
	m  map[string]string // ip -> malware family/label
}

var threatFox tfFeed

func (f *tfFeed) refresh(force bool) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && f.m != nil && time.Since(f.at) < 24*time.Hour {
		return f.m
	}
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
	mu   sync.Mutex
	at   time.Time
	nets []*net.IPNet
}

var spamhaus cidrFeed

func (f *cidrFeed) refresh(force bool) []*net.IPNet {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !force && f.nets != nil && time.Since(f.at) < 24*time.Hour {
		return f.nets
	}
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

func getText(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
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
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		sb.Write(b)
	}
	return sb.String(), nil
}
