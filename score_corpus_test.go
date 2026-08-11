package main

import (
	"fmt"
	"testing"
)

// Score calibration corpus.
//
// threat_test.go checks individual weights in isolation. That is not enough: the
// question that actually matters is "does a realistic row land in the right
// band?", and that is what breaks silently when someone nudges a weight.
//
// Each case below is a plausible whole row, labelled with the verdict a human
// analyst would give it, and asserted against a band rather than an exact number
// — so re-tuning stays possible, while a change that moves ordinary traffic into
// "suspicious", or a real intrusion out of it, fails the build.
//
// The bands deliberately overlap nothing:
//
//	benign      0–14   nothing to look at (threat-min / threat-low in the UI)
//	notable    15–39   worth a glance, not an incident (threat-low / threat-med)
//	suspicious 40–69   investigate this (threat-med / threat-high)
//	malicious  70–100  treat as compromised until proven otherwise (threat-high)
type band struct {
	name   string
	lo, hi int
}

var (
	benign     = band{"benign", 0, 14}
	notable    = band{"notable", 15, 39}
	suspicious = band{"suspicious", 40, 69}
	malicious  = band{"malicious", 70, 100}
)

func (b band) contains(n int) bool { return n >= b.lo && n <= b.hi }

// The scenarios. Keep the comments: they are the labels, and without them nobody
// can tell whether a future score change is a fix or a regression.
var scoreCorpus = []struct {
	name string
	want band
	conn Conn
}{
	// ── Benign: this is what most of a healthy machine looks like ──────────────
	{
		name: "signed OS binary to a big provider",
		want: benign,
		conn: Conn{
			VT: "0", Exe: `C:\Windows\System32\svchost.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Microsoft Windows", Trusted: true},
			RemoteIP: "20.42.65.90",
			Enrich:   &Enrichment{ISP: "Microsoft", Org: "Microsoft", Provider: "Microsoft"},
		},
	},
	{
		name: "distro-packaged binary on Linux",
		want: benign,
		conn: Conn{
			VT: "0", Exe: "/usr/bin/curl",
			Sig:      Signature{Status: "Packaged", Signer: "curl", Trusted: true},
			RemoteIP: "151.101.1.140",
			Enrich:   &Enrichment{ISP: "Fastly", Provider: "Fastly"},
		},
	},
	{
		// The case that used to be amber on every machine: a perfectly normal
		// installer or portable tool run out of the downloads folder.
		name: "signed installer run from Downloads",
		want: benign,
		conn: Conn{
			VT: "0", Exe: `C:\Users\efe\Downloads\SetupApp.exe`,
			Untrusted: true,
			Sig:       Signature{Status: "Valid", Signer: "Acme Ltd", Trusted: true},
			RemoteIP:  "104.18.2.10",
			Enrich:    &Enrichment{ISP: "Cloudflare", Provider: "Cloudflare"},
		},
	},
	{
		// Noisy AbuseIPDB reports on shared cloud infrastructure must stay quiet.
		name: "cloud IP with noisy abuse reports",
		want: benign,
		conn: Conn{
			VT: "0", Exe: `C:\Program Files\App\app.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Acme Ltd", Trusted: true},
			RemoteIP: "3.120.0.1",
			Enrich:   &Enrichment{AbuseScore: iptr(65), ISP: "Amazon", Provider: "Amazon"},
		},
	},
	{
		// A dev server on a port that was a RAT default 20 years ago.
		name: "development server on a legacy RAT port",
		want: benign,
		conn: Conn{
			VT: "0", Port: 12345, Exe: `C:\Program Files\nodejs\node.exe`,
			Known: "NetBus (RAT, histórico)", SuspPort: false, // labelled, not scored
			Sig: Signature{Status: "Valid", Signer: "OpenJS", Trusted: true},
		},
	},

	// ── Notable: worth a glance ────────────────────────────────────────────────
	{
		name: "unsigned self-built tool, clean reputation",
		want: notable,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: `D:\build\mytool.exe`,
			Sig:      Signature{Status: "NotSigned"},
			RemoteIP: "8.8.8.8", Enrich: &Enrichment{ISP: "Google", Provider: "Google"},
		},
	},
	{
		name: "unmanaged binary in a staging directory, otherwise clean",
		want: notable,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: "/tmp/build-artifact",
			Suspicious: true,
			Sig:        Signature{Status: "Unmanaged"},
		},
	},
	{
		name: "connection to a Tor exit node",
		want: notable,
		conn: Conn{
			VT: "0", Exe: `C:\Program Files\Tor\tor.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Tor Project", Trusted: true},
			RemoteIP: "185.220.101.1", Enrich: &Enrichment{Tor: true},
		},
	},

	// ── Suspicious: investigate ───────────────────────────────────────────────
	{
		// The ancestry signal on its own. No VT hit, no feed hit, nothing external
		// — this must still be loud, because it is high precision.
		name: "Word spawned PowerShell (macro payload)",
		want: suspicious,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Microsoft Windows", Trusted: true},
			RemoteIP: "45.13.something-invalid",
			Details:  &ProcDetails{BadSpawn: "winword.exe → powershell.exe"},
		},
	},
	{
		name: "web server spawned a shell (webshell)",
		want: suspicious,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: "/bin/bash",
			Sig:     Signature{Status: "Packaged", Signer: "bash", Trusted: true},
			Details: &ProcDetails{BadSpawn: "nginx → bash"},
		},
	},
	{
		name: "unsigned binary in temp with a few VT detections",
		want: suspicious,
		conn: Conn{
			VT: "4", Exe: `C:\Users\efe\AppData\Local\Temp\update.exe`,
			Suspicious: true,
			Sig:        Signature{Status: "NotSigned"},
		},
	},
	{
		name: "IP in a Spamhaus DROP netblock with high abuse score",
		want: suspicious,
		conn: Conn{
			VT: "0", Exe: `C:\Program Files\App\app.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Acme Ltd", Trusted: true},
			RemoteIP: "193.0.0.1",
			Enrich:   &Enrichment{Spamhaus: true, AbuseScore: iptr(70)},
		},
	},

	// ── Malicious: treat as compromised ───────────────────────────────────────
	{
		name: "known Feodo C2",
		want: malicious,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: `C:\Users\efe\AppData\Roaming\svc.exe`,
			Sig:      Signature{Status: "NotSigned"},
			RemoteIP: "91.109.190.1", Enrich: &Enrichment{C2: true},
		},
	},
	{
		name: "ThreatFox-listed Cobalt Strike beacon from a staging dir",
		want: malicious,
		conn: Conn{
			VT: "8", Exe: `C:\Windows\Temp\beacon.exe`,
			Suspicious: true,
			Sig:        Signature{Status: "NotSigned"},
			RemoteIP:   "5.188.206.1",
			Enrich:     &Enrichment{ThreatFox: "Cobalt Strike", AbuseScore: iptr(90)},
		},
	},
	{
		name: "macro chain to a C2 address",
		want: malicious,
		conn: Conn{
			VT: "NOT_IN_VT", Exe: `C:\Windows\System32\mshta.exe`,
			Sig:      Signature{Status: "Valid", Signer: "Microsoft Windows", Trusted: true},
			RemoteIP: "45.9.148.1",
			Enrich:   &Enrichment{C2: true, AbuseScore: iptr(80)},
			Details:  &ProcDetails{BadSpawn: "excel.exe → mshta.exe"},
		},
	},
	{
		name: "everything at once",
		want: malicious,
		conn: Conn{
			VT: "30", Exe: "/dev/shm/.x",
			Suspicious: true, SuspPort: true, Known: "Metasploit/Meterpreter",
			Sig:      Signature{Status: "NotSigned"},
			RemoteIP: "185.234.1.1",
			Enrich: &Enrichment{
				C2: true, ThreatFox: "Mirai", Spamhaus: true, Tor: true,
				AbuseScore: iptr(100), VTMalicious: iptr(12),
				Vulns: []string{"CVE-2021-1", "CVE-2021-2"},
			},
		},
	},
}

func TestScoreCorpus(t *testing.T) {
	for _, tc := range scoreCorpus {
		t.Run(tc.name, func(t *testing.T) {
			conn := tc.conn
			got := threatScore(&conn)
			if !tc.want.contains(got) {
				t.Errorf("score %d is outside band %s (%d-%d)\n  breakdown: %s",
					got, tc.want.name, tc.want.lo, tc.want.hi, conn.Breakdown)
			}
		})
	}
}

// Ordering is a weaker but more durable property than any absolute number: even
// after a re-tune, a real intrusion must outrank ordinary traffic.
func TestScoreOrdering(t *testing.T) {
	scoreOf := func(name string) int {
		for _, tc := range scoreCorpus {
			if tc.name == name {
				conn := tc.conn
				return threatScore(&conn)
			}
		}
		t.Fatalf("corpus case %q not found", name)
		return 0
	}
	// (higher, lower) pairs that must hold regardless of tuning.
	for _, p := range [][2]string{
		{"Word spawned PowerShell (macro payload)", "signed installer run from Downloads"},
		{"Word spawned PowerShell (macro payload)", "unsigned self-built tool, clean reputation"},
		{"known Feodo C2", "connection to a Tor exit node"},
		{"web server spawned a shell (webshell)", "unmanaged binary in a staging directory, otherwise clean"},
		{"unsigned binary in temp with a few VT detections", "development server on a legacy RAT port"},
		{"IP in a Spamhaus DROP netblock with high abuse score", "cloud IP with noisy abuse reports"},
	} {
		hi, lo := scoreOf(p[0]), scoreOf(p[1])
		if hi <= lo {
			t.Errorf("%q (%d) must outrank %q (%d)", p[0], hi, p[1], lo)
		}
	}
}

// A whitelist entry is an operator override and must win over every signal,
// including the new ancestry one.
func TestWhitelistBeatsEverySignal(t *testing.T) {
	worst := Conn{
		VT: "30", Suspicious: true, SuspPort: true,
		Sig:     Signature{Status: "NotSigned"},
		Details: &ProcDetails{BadSpawn: "winword.exe → powershell.exe"},
		Enrich:  &Enrichment{C2: true, ThreatFox: "Mirai", Spamhaus: true},
	}
	for _, tc := range []struct {
		name string
		mod  func(*Conn)
	}{
		{"exe whitelisted", func(c *Conn) { c.Whitelist = true }},
		{"ip whitelisted", func(c *Conn) { c.IPWhitelist = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := worst
			tc.mod(&conn)
			if got := threatScore(&conn); got != 0 {
				t.Errorf("score=%d, want 0 (%s)", got, conn.Breakdown)
			}
		})
	}
}

// Documents the current corpus scores, so a reviewer can see the effect of a
// weight change at a glance instead of decoding band assertions.
func TestScoreCorpusReport(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("run with -v to print the score table")
	}
	for _, tc := range scoreCorpus {
		conn := tc.conn
		fmt.Printf("%3d  %-10s  %s\n", threatScore(&conn), tc.want.name, tc.name)
	}
}
