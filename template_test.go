package main

import (
	"html/template"
	"strings"
	"testing"
)

// The templates are parsed with template.Must at startup and executed per
// request, so a typo or a renamed field is a runtime failure — a panic on boot,
// or a 500 with the real page never rendering. These tests turn both into a
// build-time failure instead.

func testTemplates(t *testing.T) *template.Template {
	t.Helper()
	tm, err := template.New("").Funcs(funcMap).ParseFS(tmplFS, "web/templates/*.html")
	if err != nil {
		t.Fatalf("templates do not parse: %v", err)
	}
	return tm
}

func TestReportTemplateExecutes(t *testing.T) {
	tm := testTemplates(t)
	for _, lang := range []string{"es", "en"} {
		data := map[string]any{
			"T": strings_(lang), "Lang": lang, "Admin": true,
			"RefreshSecs": int64(30), "NoTray": true,
		}
		var sb strings.Builder
		if err := tm.ExecuteTemplate(&sb, "report.html", data); err != nil {
			t.Fatalf("report.html [%s]: %v", lang, err)
		}
		if !strings.Contains(sb.String(), "eFe Process Monitor") {
			t.Errorf("report.html [%s] rendered without its title", lang)
		}
	}
}

func TestRowsTemplateExecutes(t *testing.T) {
	tm := testTemplates(t)

	malicious := 7
	abuse := 90
	full := Conn{
		Threat: 85, Port: 49812, LocalIP: "192.168.1.10",
		RPort: 443, RemoteIP: "93.184.216.34", PID: 1234,
		Process: "suspicious.exe", Status: "ESTABLISHED",
		Exe:        `C:\Users\José\AppData\Local\Temp\suspicious.exe`,
		Known:      "HTTPS",
		VT:         "3",
		Undetected: "60",
		Cached:     true, Suspicious: true, SuspPort: false,
		Blockable: true, Capturable: true,
		Sig:       Signature{Status: "NotSigned"},
		Partial:   true,
		Breakdown: "ruta sospechosa (+25)",
		RemoteIPs: []string{"93.184.216.34", "8.8.8.8"},
		Enrich: &Enrichment{
			Country: "United States", City: "Norwell", ISP: "Edgecast",
			Org: "Edgecast", ASN: "AS15133 Edgecast", DNS: "example.com",
			VTMalicious: &malicious, AbuseScore: &abuse,
			Tor: true, C2: true, ThreatFox: "Cobalt Strike", Spamhaus: true,
			Ports: []int{80, 443}, Vulns: []string{"CVE-2021-1234"},
			Provider: "",
		},
		LAN: &LANInfo{DNS: "host.lan", NetBIOS: "HOST", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "Acme"},
		Details: &ProcDetails{
			PPID: 4, ParentName: "services.exe", Cmdline: "suspicious.exe --run",
			CreateTime: "2026-08-11 10:00:00", IORead: 4096, IOWrite: 8192, IOok: true,
			Conns:      []ProcConn{{"192.168.1.10", 49812, "93.184.216.34", 443}},
			TotalConns: 1,
		},
	}
	// A UDP row and a bare LISTEN row: both must render, and the UDP one is the
	// case that used to be dropped from the table entirely.
	udp := Conn{
		Port: 443, LocalIP: "192.168.1.10", RPort: 443, RemoteIP: "8.8.8.8",
		PID: 900, Process: "chrome.exe", Status: "UDP", Known: "HTTPS",
		VT: "PENDING", Sig: Signature{Status: sigPendingStatus},
		Capturable: true, Enrich: &Enrichment{Country: "N/A", City: "N/A"},
	}
	bare := Conn{
		Port: 135, Status: "LISTEN", Process: "N/A", Exe: "N/A", Known: "MSRPC",
		VT: "N/A", Sig: Signature{Status: sigPendingStatus},
	}
	bound := Conn{
		Port: 5353, Status: "UDP-BOUND", Process: "mDNSResponder", Exe: "/usr/sbin/mdns",
		Known: "mDNS", VT: "NOT_IN_VT", Sig: Signature{Status: "Packaged", Signer: "avahi", Trusted: true},
	}

	for _, lang := range []string{"es", "en"} {
		var sb strings.Builder
		data := map[string]any{
			"T":     strings_(lang),
			"Conns": []Conn{full, udp, bare, bound},
		}
		if err := tm.ExecuteTemplate(&sb, "rows.html", data); err != nil {
			t.Fatalf("rows.html [%s]: %v", lang, err)
		}
		out := sb.String()
		for _, want := range []string{
			"suspicious.exe", "UDP", "UDP-BOUND", "Cobalt Strike",
			`class="udp"`, // the bound-UDP row must get its own state class
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rows.html [%s] missing %q", lang, want)
			}
		}
	}

	// The empty case has its own branch.
	var sb strings.Builder
	if err := tm.ExecuteTemplate(&sb, "rows.html",
		map[string]any{"T": strings_("es"), "Conns": []Conn{}}); err != nil {
		t.Fatalf("rows.html (empty): %v", err)
	}
}

// trunc slices by rune: a byte-wise cut can split a multi-byte character and the
// browser then shows a replacement diamond. Accented paths are the common case.
func TestTruncIsRuneSafe(t *testing.T) {
	trunc := funcMap["trunc"].(func(int, string) string)
	for _, tc := range []struct {
		n        int
		in, want string
	}{
		{3, "abcdef", "abc…"},
		{6, "abcdef", "abcdef"},
		{9, "abcdef", "abcdef"},
		{0, "abc", "…"},
		{4, "Josémanuel", "José…"},
		{1, "ñandú", "ñ…"},
		{5, "ñandú", "ñandú"},
	} {
		if got := trunc(tc.n, tc.in); got != tc.want {
			t.Errorf("trunc(%d, %q) = %q, want %q", tc.n, tc.in, got, tc.want)
		}
	}
	if !isValidUTF8(trunc(4, "Josémanuel")) {
		t.Error("trunc produced invalid UTF-8")
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

// join reads as `join sep items` in templates, which is the reverse of
// strings.Join's own argument order — easy to break, so pin it.
func TestJoinArgOrder(t *testing.T) {
	join := funcMap["join"].(func(string, []string) string)
	if got := join(", ", []string{"a", "b"}); got != "a, b" {
		t.Errorf(`join(", ", [a b]) = %q, want "a, b"`, got)
	}
	joinInts := funcMap["joinInts"].(func(string, []int) string)
	if got := joinInts(",", []int{80, 443}); got != "80,443" {
		t.Errorf(`joinInts(",", [80 443]) = %q, want "80,443"`, got)
	}
}
