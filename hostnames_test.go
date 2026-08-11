package main

import (
	"testing"
)

// withTestDB points the app at a throwaway SQLite file for one test, so the
// persistence paths are exercised for real instead of being stubbed out.
func withTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldDir := db, appDir
	appDir = t.TempDir()
	initDB()
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		db, appDir = oldDB, oldDir
	})
}

// cleanHostname processes attacker-influenced data: anyone can put anything in a
// TLS SNI field, and the result is stored and later rendered. It must reject
// anything that isn't plausibly a hostname rather than pass it through.
func TestCleanHostname(t *testing.T) {
	valid := map[string]string{
		"example.com":         "example.com",
		"EXAMPLE.COM":         "example.com",
		"  cdn.example.com  ": "cdn.example.com",
		"example.com.":        "example.com", // trailing root dot dropped
		"a-b_c.example.co.uk": "a-b_c.example.co.uk",
		"xn--80ak6aa92e.com":  "xn--80ak6aa92e.com", // punycode is already ASCII
	}
	for in, want := range valid {
		if got := cleanHostname(in); got != want {
			t.Errorf("cleanHostname(%q) = %q, want %q", in, got, want)
		}
	}

	rejected := []string{
		"", " ", "localhost", "nodot",
		"<script>alert(1)</script>",
		"exa mple.com",
		"example.com/path",
		"example.com:443",
		"exam\"ple.com",
		"exam'ple.com",
		"exam\nple.com",
		"héllo.com", // non-ASCII: real punycode arrives already encoded
		string(make([]byte, 300)),
	}
	for _, in := range rejected {
		if got := cleanHostname(in); got != "" {
			t.Errorf("cleanHostname(%q) = %q, want rejected", in, got)
		}
	}

	// Over the DNS length limit.
	long := ""
	for len(long) < 260 {
		long += "aaaaaaaaa."
	}
	if got := cleanHostname(long + "com"); got != "" {
		t.Errorf("over-long name should be rejected, got %q", got)
	}
}

func TestValidIPForHostnameBinding(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8":         true,
		"2606:4700::1111": true,
		"192.168.1.5":     true, // private is fine: a LAN name binding is still useful
		"127.0.0.1":       false,
		"::1":             false,
		"0.0.0.0":         false,
		"":                false,
		"not-an-ip":       false,
	} {
		if got := validIP(ip); got != want {
			t.Errorf("validIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

// observeHostnames is called for every captured packet, so the extraction has to
// pick the right address for each source: SNI binds to the packet destination,
// while a DNS answer binds to the addresses inside the record.
func TestObserveHostnamesExtraction(t *testing.T) {
	withTestDB(t)
	reset := func() {
		hostMu.Lock()
		hostSeen = map[string]map[string]bool{}
		hostMu.Unlock()
	}
	seen := func(ip, name string) bool {
		hostMu.Lock()
		defer hostMu.Unlock()
		return hostSeen[ip][name]
	}

	t.Run("sni binds to the destination", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{
			"ip_src": "192.168.1.10", "ip_dst": "93.184.216.34",
			"tls_sni": "example.com",
		})
		if !seen("93.184.216.34", "example.com") {
			t.Error("SNI should bind to ip_dst")
		}
		if seen("192.168.1.10", "example.com") {
			t.Error("SNI must not bind to the source address")
		}
	})

	t.Run("dns answers bind to every returned address", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{
			"ip_src": "8.8.8.8", "ip_dst": "192.168.1.10",
			"dns": "evil-cdn.tk", "dns_a": "1.2.3.4,5.6.7.8",
		})
		for _, ip := range []string{"1.2.3.4", "5.6.7.8"} {
			if !seen(ip, "evil-cdn.tk") {
				t.Errorf("DNS answer address %s should be bound to the queried name", ip)
			}
		}
		// The responding resolver is not the thing the name resolves to.
		if seen("8.8.8.8", "evil-cdn.tk") {
			t.Error("must not bind the name to the DNS server's own address")
		}
	})

	t.Run("ipv6 answers", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{
			"dns": "example.com", "dns_aaaa": "2606:4700::1111",
		})
		if !seen("2606:4700::1111", "example.com") {
			t.Error("AAAA answers should be recorded")
		}
	})

	t.Run("junk is dropped", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{
			"ip_dst": "1.1.1.1", "tls_sni": "<script>x</script>",
		})
		if seen("1.1.1.1", "<script>x</script>") {
			t.Error("a non-hostname SNI must not be recorded")
		}
	})

	t.Run("loopback is skipped", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{"ip_dst": "127.0.0.1", "tls_sni": "example.com"})
		if seen("127.0.0.1", "example.com") {
			t.Error("loopback bindings are noise")
		}
	})

	t.Run("empty packet does nothing", func(t *testing.T) {
		reset()
		observeHostnames(map[string]string{})
		hostMu.Lock()
		n := len(hostSeen)
		hostMu.Unlock()
		if n != 0 {
			t.Errorf("expected no bindings, got %d", n)
		}
	})

	reset()
}

// End to end: a packet goes in, the binding comes back out of SQLite, and SNI is
// ranked above DNS because the client declared it rather than a resolver claiming it.
func TestHostnamesPersistAndRankSNIFirst(t *testing.T) {
	withTestDB(t)
	hostMu.Lock()
	hostSeen = map[string]map[string]bool{}
	hostMu.Unlock()

	const ip = "93.184.216.34"
	// A DNS answer arrives first, then the SNI for the same address.
	observeHostnames(map[string]string{"dns": "dns-name.example", "dns_a": ip})
	observeHostnames(map[string]string{"ip_dst": ip, "tls_sni": "sni-name.example"})

	got := dbHostnames(ip)
	if len(got) != 2 {
		t.Fatalf("expected 2 bindings, got %d (%+v)", len(got), got)
	}
	if got[0].Source != "sni" {
		t.Errorf("SNI must rank first (it is client-declared), got %+v", got)
	}
	if got[0].Name != "sni-name.example" {
		t.Errorf("first binding = %q, want the SNI name", got[0].Name)
	}

	// The whole-table load used by the connection list must agree.
	all := dbAllHostnames()
	if len(all[ip]) != 2 || all[ip][0].Source != "sni" {
		t.Errorf("dbAllHostnames disagrees with dbHostnames: %+v", all[ip])
	}
}

// The risk timeline is a change log: repeated identical verdicts must not pile up,
// or a page refresh every few seconds would bury the real transitions.
func TestScoreHistoryRecordsOnlyChanges(t *testing.T) {
	withTestDB(t)
	c := Conn{
		Exe: `C:\app\app.exe`, RemoteIP: "8.8.8.8", VT: "0",
		Enrich: &Enrichment{}, Sig: Signature{Status: "Valid", Trusted: true},
	}
	c.Threat = threatScore(&c)

	recordScoreChange(&c)
	recordScoreChange(&c) // identical: must be ignored
	if n := len(dbScoreHistory(100)); n != 1 {
		t.Fatalf("expected 1 entry after an unchanged re-render, got %d", n)
	}

	// A real change is recorded.
	worse := c
	worse.Enrich = &Enrichment{C2: true}
	worse.Threat = threatScore(&worse)
	recordScoreChange(&worse)
	hist := dbScoreHistory(100)
	if len(hist) != 2 {
		t.Fatalf("expected 2 entries after the score changed, got %d", len(hist))
	}
	if hist[0].Threat <= hist[1].Threat {
		t.Errorf("newest entry should be the worse score: %+v", hist)
	}

	// Local traffic and rows built on incomplete data are not worth trending.
	local := Conn{Exe: `C:\app\app.exe`, RemoteIP: "192.168.1.5", VT: "0"}
	local.Threat = threatScore(&local)
	recordScoreChange(&local)
	partial := Conn{Exe: `C:\app\b.exe`, RemoteIP: "9.9.9.9", VT: "N/A"}
	partial.Threat = threatScore(&partial)
	if !partial.Partial {
		t.Fatal("expected the incomplete row to be marked Partial")
	}
	recordScoreChange(&partial)
	if n := len(dbScoreHistory(100)); n != 2 {
		t.Errorf("local and partial rows must not be recorded, got %d entries", n)
	}
}

// The capture field list and the key list are positional: they are zipped by
// index in parsePacket, so a mismatch silently shifts every field.
func TestCaptureFieldsAlignWithKeys(t *testing.T) {
	if len(captureFields) != len(packetKeys) {
		t.Fatalf("captureFields has %d entries, packetKeys has %d — parsePacket zips them by index",
			len(captureFields), len(packetKeys))
	}
	// Spot-check the two ends and the fields the hostname correlation depends on.
	idx := map[string]int{}
	for i, k := range packetKeys {
		idx[k] = i
	}
	for key, field := range map[string]string{
		"tls_sni":  "tls.handshake.extensions_server_name",
		"dns":      "dns.qry.name",
		"dns_a":    "dns.a",
		"dns_aaaa": "dns.aaaa",
		"ip_dst":   "ip.dst",
	} {
		i, ok := idx[key]
		if !ok {
			t.Errorf("packetKeys is missing %q", key)
			continue
		}
		if captureFields[i] != field {
			t.Errorf("key %q maps to tshark field %q, want %q", key, captureFields[i], field)
		}
	}
}
