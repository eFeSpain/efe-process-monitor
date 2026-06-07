package main

import (
	"strings"
	"testing"
)

func iptr(i int) *int { return &i }

func TestThreatScore(t *testing.T) {
	cases := []struct {
		name       string
		conn       Conn
		want       int
		breakdowni string // substring expected in Breakdown (optional)
	}{
		{"clean", Conn{VT: "0", Sig: Signature{Status: "Valid"}}, 0, "limpio"},
		{"whitelist exe", Conn{Whitelist: true, Enrich: &Enrichment{C2: true}}, 0, "whitelist"},
		{"whitelist ip", Conn{IPWhitelist: true, Enrich: &Enrichment{C2: true}}, 0, "whitelist"},
		{"c2 feodo", Conn{VT: "N/A", Enrich: &Enrichment{C2: true}}, 60, "C2 Feodo"},
		{"threatfox", Conn{VT: "N/A", Enrich: &Enrichment{ThreatFox: "Cobalt Strike"}}, 55, "ThreatFox: Cobalt Strike"},
		{"spamhaus", Conn{VT: "N/A", Enrich: &Enrichment{Spamhaus: true}}, 30, "Spamhaus DROP"},
		{"suspicious path", Conn{VT: "N/A", Suspicious: true}, 25, "sospechosa"},
		{"malware port", Conn{VT: "N/A", SuspPort: true, Known: "Metasploit"}, 30, "Metasploit"},
		{"not signed", Conn{VT: "N/A", Sig: Signature{Status: "NotSigned"}}, 15, "sin firma"},
		{"linux packaged neutral", Conn{VT: "0", Sig: Signature{Status: "Packaged", Trusted: true}}, 0, "limpio"},
		{"linux unmanaged neutral", Conn{VT: "0", Sig: Signature{Status: "Unmanaged"}}, 0, "limpio"},
		{"vt detections", Conn{VT: "5"}, 30, "VT 5"},
		{"vt capped", Conn{VT: "50"}, 60, "VT 50"},
		{"vtip", Conn{VT: "N/A", Enrich: &Enrichment{VTMalicious: iptr(3)}}, 12, "VT-IP 3"},
		{"abuse full", Conn{VT: "N/A", Enrich: &Enrichment{AbuseScore: iptr(80)}}, 32, "AbuseIPDB 80"},
		{"abuse attenuated", Conn{VT: "N/A", Enrich: &Enrichment{AbuseScore: iptr(80), Provider: "Amazon"}}, 8, "atenuado"},
		{"capped at 100", Conn{VT: "N/A", Enrich: &Enrichment{C2: true, ThreatFox: "X", Spamhaus: true}}, 100, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.conn
			got := threatScore(&conn)
			if got != c.want {
				t.Errorf("score=%d, want %d (breakdown: %q)", got, c.want, conn.Breakdown)
			}
			if c.breakdowni != "" && !strings.Contains(conn.Breakdown, c.breakdowni) {
				t.Errorf("breakdown %q missing %q", conn.Breakdown, c.breakdowni)
			}
		})
	}
}

// TestCoveragePartial verifies the "low score ≠ clean" honesty: a zero score is
// only "limpio" when the key signals were actually resolved; otherwise it's
// flagged Partial with a "datos incompletos" breakdown.
func TestCoveragePartial(t *testing.T) {
	cases := []struct {
		name        string
		conn        Conn
		wantPartial bool
	}{
		{"vt clean, no remote", Conn{VT: "0"}, false},
		{"vt not-in-vt", Conn{VT: "NOT_IN_VT"}, false},
		{"vt na", Conn{VT: "N/A"}, true},
		{"vt pending", Conn{VT: "PENDING"}, true},
		{"public ip enriched", Conn{VT: "0", RemoteIP: "8.8.8.8", Enrich: &Enrichment{}}, false},
		{"public ip not enriched", Conn{VT: "0", RemoteIP: "8.8.8.8"}, true},
		{"private ip no enrich needed", Conn{VT: "0", RemoteIP: "192.168.1.5"}, false},
		{"signal present is never partial", Conn{VT: "N/A", Enrich: &Enrichment{C2: true}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.conn
			threatScore(&conn)
			if conn.Partial != c.wantPartial {
				t.Errorf("Partial=%v, want %v (breakdown: %q)", conn.Partial, c.wantPartial, conn.Breakdown)
			}
			if c.wantPartial && !strings.Contains(conn.Breakdown, "incompletos") {
				t.Errorf("partial row breakdown should mention incomplete data, got %q", conn.Breakdown)
			}
		})
	}
}
