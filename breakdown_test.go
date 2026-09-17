package main

import (
	"strings"
	"testing"
)

// The breakdown is stored language-neutral and rendered on read. Every reason
// threatScore can emit must survive the round trip in every language, and the
// arguments — a malware family, a spawn chain — must come back byte-for-byte
// even when they contain the encoding's own separators.
func TestBreakdownRoundTrip(t *testing.T) {
	abuse, vtip := 90, 7
	family := "Cobalt Strike; a/b|c 100%"
	chain := "winword.exe → powershell.exe"
	c := Conn{VT: "3", Suspicious: true, SuspPort: true, Known: "Metasploit",
		HighEgress: true, RateOut: 2 << 20, Sig: Signature{Status: "HashMismatch"},
		RemoteIP: "8.8.8.8", Details: &ProcDetails{BadSpawn: chain},
		Enrich: &Enrichment{ThreatFox: family, AbuseScore: &abuse, Provider: "Google",
			VTMalicious: &vtip, C2: true, Spamhaus: true, Tor: true, Vulns: []string{"CVE-1", "CVE-2"}}}
	threatScore(&c)

	if !breakdownCodeRe.MatchString(c.BreakdownCode) {
		t.Fatalf("code does not match its own grammar: %q", c.BreakdownCode)
	}
	if strings.Contains(c.BreakdownCode, family) {
		t.Errorf("arguments must be escaped in the code: %q", c.BreakdownCode)
	}
	for _, lang := range testLangs {
		got := localizeBreakdown(lang, c.BreakdownCode)
		if got == c.BreakdownCode {
			t.Errorf("[%s] breakdown not localized: %q", lang, got)
		}
		for _, want := range []string{family, chain, "Metasploit", "Google", "(+40)", "(+55)", "2 MB/s"} {
			if !strings.Contains(got, want) {
				t.Errorf("[%s] breakdown %q missing %q", lang, got, want)
			}
		}
		if strings.Contains(got, "%!") {
			t.Errorf("[%s] format verb mismatch: %q", lang, got)
		}
	}
	// The Spanish rendering is what the tooltip showed before the encoding.
	es := localizeBreakdown("es", c.BreakdownCode)
	for _, want := range []string{"VT 3 detecciones (+18)", "ruta de staging (temp/público) (+25)",
		"AbuseIPDB 90% atenuado: Google (+9)", "cadena anómala (" + chain + ") (+40)"} {
		if !strings.Contains(es, want) {
			t.Errorf("es breakdown %q missing %q", es, want)
		}
	}
	if c.Breakdown != es { // currentLang() defaults to es in tests
		t.Errorf("Conn.Breakdown %q != localized es %q", c.Breakdown, es)
	}
}

func TestBreakdownZeroCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Conn
		code string
		es   string
	}{
		{"whitelist", Conn{Whitelist: true}, "wl_exe", "binario en whitelist → 0"},
		{"ip whitelist", Conn{IPWhitelist: true}, "wl_ip", "IP en whitelist → 0"},
		{"clean", Conn{VT: "0", Sig: Signature{Status: "Valid"}}, "clean", "limpio"},
		{"partial", Conn{VT: "PENDING"}, "partial", "sin señales (datos incompletos)"},
	} {
		threatScore(&tc.c)
		if tc.c.BreakdownCode != tc.code || tc.c.Breakdown != tc.es {
			t.Errorf("%s: code=%q text=%q, want %q / %q", tc.name, tc.c.BreakdownCode, tc.c.Breakdown, tc.code, tc.es)
		}
	}
}

// Rows written before the encoding existed are free text; so is a code from a
// newer build with a key this one does not know. Both must pass through intact
// rather than render as garbage or vanish.
func TestBreakdownLegacyTextPassesThrough(t *testing.T) {
	for _, s := range []string{"ruta sospechosa (+25) · limpio", "limpio", "", "future_key/12/x"} {
		if got := localizeBreakdown("en", s); got != s {
			t.Errorf("localizeBreakdown(%q) = %q, want unchanged", s, got)
		}
	}
}
