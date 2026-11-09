package main

import (
	"os"
	"strings"
	"testing"
)

// The monitor hides its own PID, but the subprocesses the tool itself starts
// (nmblookup, arp, tshark, netsh…) open sockets too and were reported as new
// processes — and, the first time, as new binaries with a desktop notification.
// A child of ours is ours.
func TestOwnChildFilter(t *testing.T) {
	if ownChild(ownPID) {
		t.Error("the monitor itself is not its own child")
	}
	if ownChild(int32(os.Getppid())) {
		t.Error("our parent is not our child")
	}
	if ownChild(0) || ownChild(-1) {
		t.Error("invalid PIDs are never ours")
	}
}

// The live-feed reputation alert is graded, not binary: one VirusTotal engine
// flagging a big provider's address is noise (Chrome talking to claude.ai
// raised a red alert over a single detection), two is worth a glance, three
// or more — or any curated-feed hit — is red and gets the desktop notification.
func TestIntelAlertLevels(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		name   string
		e      Enrichment
		level  string
		reason string
	}{
		{"nothing", Enrichment{}, "", ""},
		{"one VT engine", Enrichment{VTMalicious: n(1), Provider: "Anthropic"}, "low", "VirusTotal ×1"},
		{"two VT engines", Enrichment{VTMalicious: n(2)}, "med", "VirusTotal ×2"},
		{"three VT engines", Enrichment{VTMalicious: n(3)}, "high", "VirusTotal ×3"},
		{"Feodo C2", Enrichment{C2: true}, "high", "C2 Feodo"},
		{"ThreatFox", Enrichment{ThreatFox: "Mirai"}, "high", "ThreatFox: Mirai"},
		{"URLhaus", Enrichment{URLhaus: "Mozi"}, "high", "URLhaus: Mozi"},
		{"Spamhaus", Enrichment{Spamhaus: true}, "high", "Spamhaus DROP"},
		{"Tor", Enrichment{Tor: true}, "high", "Tor exit"},
		{"AbuseIPDB on an unknown host", Enrichment{AbuseScore: n(60)}, "high", "AbuseIPDB 60%"},
		{"AbuseIPDB on a known provider is noise", Enrichment{AbuseScore: n(60), Provider: "Google"}, "", ""},
		{"one VT engine plus C2: the worst wins", Enrichment{VTMalicious: n(1), C2: true}, "high", "C2 Feodo"},
	} {
		reasons, level := intelAlert(&tc.e)
		if level != tc.level {
			t.Errorf("%s: level %q, want %q (reasons %v)", tc.name, level, tc.level, reasons)
		}
		if tc.reason == "" && len(reasons) != 0 {
			t.Errorf("%s: expected no reasons, got %v", tc.name, reasons)
		}
		if tc.reason != "" && (len(reasons) == 0 || !strings.Contains(strings.Join(reasons, ", "), tc.reason)) {
			t.Errorf("%s: reasons %v lack %q", tc.name, reasons, tc.reason)
		}
	}
}
