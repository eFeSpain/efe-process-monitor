package main

import (
	"os"
	"strings"
	"testing"
	"time"
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

// The three high-precision local signals — a spawn chain that should never
// happen, a foreign process holding a credential store, executable memory from
// a memfd — were only computed when somebody rendered the table. With the
// monitor running as a service and nobody watching, a macro launching a
// payload raised nothing. localSignals is the decision, shared with the live
// monitor.
func TestLocalSignals(t *testing.T) {
	keys := func(rs []reason) string {
		var k []string
		for _, r := range rs {
			k = append(k, r.key+":"+strings.Join(r.args, ","))
		}
		return strings.Join(k, " ")
	}
	macro := []Ancestor{{PID: 10, Name: "WINWORD.EXE"}, {PID: 4, Name: "explorer.exe"}}
	if got := keys(localSignals("powershell.exe", macro, nil)); got != "spawn:winword.exe → powershell.exe" {
		t.Errorf("macro chain: %q", got)
	}
	scan := &procScan{files: []string{"browser: /home/x/.config/google-chrome/Default/Login Data", "ssh: /home/x/.ssh/id_ed25519"}, scored: 2,
		execMap: []string{"memfd: /memfd:payload (deleted) (r-xp)"}, media: []string{"media: /dev/video0"}}
	if got := keys(localSignals("updater", nil, scan)); got != "creds:2 execmap:1" {
		t.Errorf("creds + execmap: %q", got)
	}
	// Camera/microphone are context, never a signal; a clean process has none.
	if got := localSignals("zoom", []Ancestor{{PID: 1, Name: "systemd"}}, &procScan{media: []string{"media: /dev/video0"}}); len(got) != 0 {
		t.Errorf("media alone must not alert: %v", got)
	}
	if got := localSignals("bash", []Ancestor{{PID: 9, Name: "konsole"}}, nil); len(got) != 0 {
		t.Errorf("a user shell under a terminal is normal: %v", got)
	}
}

// One alert per process and signal, not one per monitor tick; a PID that is
// reused after the entry expired alerts again.
func TestLocalAlertDedupe(t *testing.T) {
	var d localAlertDedupe
	t0 := time.Now()
	if !d.fresh(42, "spawn", t0) {
		t.Fatal("first sighting must alert")
	}
	if d.fresh(42, "spawn", t0.Add(3*time.Second)) || d.fresh(42, "spawn", t0.Add(30*time.Minute)) {
		t.Error("the same signal on the same process must not repeat")
	}
	if !d.fresh(42, "creds", t0.Add(4*time.Second)) || !d.fresh(43, "spawn", t0.Add(4*time.Second)) {
		t.Error("another signal, or another process, is a new alert")
	}
	if !d.fresh(42, "spawn", t0.Add(knownPIDTTL+31*time.Minute)) {
		t.Error("after the entry expires (PID reuse) it alerts again")
	}
}
