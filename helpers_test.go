package main

import (
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1": true, "192.168.1.1": true, "172.16.5.5": true,
		"127.0.0.1": true, "::1": true, "169.254.1.1": true,
		"8.8.8.8": false, "1.1.1.1": false, "": true, "garbage": true,
	}
	for ip, want := range cases {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q)=%v, want %v", ip, got, want)
		}
	}
}

func TestIsBlockable(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8": true, "192.168.1.1": true, // real LAN/public addresses
		"0.0.0.0": false, "127.0.0.1": false, "255.255.255.255": false,
		"224.0.0.1": false, "": false,
	}
	for ip, want := range cases {
		if got := isBlockable(ip); got != want {
			t.Errorf("isBlockable(%q)=%v, want %v", ip, got, want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "127.5.5.5": true,
		"0.0.0.0": false, "8.8.8.8": false, "192.168.1.1": false, "": false,
	} {
		if got := isLoopback(ip); got != want {
			t.Errorf("isLoopback(%q)=%v, want %v", ip, got, want)
		}
	}
}

// Path signals are two-tiered on purpose: a staging directory (temp, public,
// /dev/shm) is genuinely odd, whereas the downloads folder is where every
// installer and portable tool legitimately lives. Treating them alike was the
// score's biggest false-positive source, so the split is pinned here.
func TestIsSuspiciousPath(t *testing.T) {
	staging := []string{
		`C:\Users\x\AppData\Local\Temp\evil.exe`,
		`C:\Users\Public\bad.exe`,
		`C:\Windows\Temp\x.exe`,
		`/tmp/payload`,
		`/dev/shm/x`,
	}
	for _, p := range staging {
		if !isSuspiciousPath(p) {
			t.Errorf("isSuspiciousPath(%q)=false, want true", p)
		}
		if isUntrustedPath(p) {
			t.Errorf("isUntrustedPath(%q)=true; staging paths belong to the other tier", p)
		}
	}

	downloads := []string{
		`C:\Users\x\Downloads\installer.exe`,
		`/home/x/downloads/tool`,
	}
	for _, p := range downloads {
		if isSuspiciousPath(p) {
			t.Errorf("isSuspiciousPath(%q)=true; downloads is the low-weight tier now", p)
		}
		if !isUntrustedPath(p) {
			t.Errorf("isUntrustedPath(%q)=false, want true", p)
		}
	}

	clean := []string{
		`C:\Windows\System32\svchost.exe`,
		`C:\Program Files\App\app.exe`,
		"", "N/A", "ACCESS_DENIED",
	}
	for _, p := range clean {
		if isSuspiciousPath(p) || isUntrustedPath(p) {
			t.Errorf("%q should match neither path tier", p)
		}
	}
}

func TestPortLabel(t *testing.T) {
	// suspicious port wins and flags
	if name, susp, legacy := portLabel(4444, 0); !susp || legacy || name != "Metasploit/Meterpreter" {
		t.Errorf("portLabel(4444,0)=(%q,%v,%v)", name, susp, legacy)
	}
	// a legacy RAT port is labelled and marked, but never scores
	if name, susp, legacy := portLabel(31337, 0); susp || !legacy || name != "Back Orifice (RAT)" {
		t.Errorf("portLabel(31337,0)=(%q,%v,%v)", name, susp, legacy)
	}
	// known service, not suspicious
	if name, susp, legacy := portLabel(443, 0); susp || legacy || name != "HTTPS" {
		t.Errorf("portLabel(443,0)=(%q,%v,%v)", name, susp, legacy)
	}
	// remote known port used when local unknown
	if name, susp, _ := portLabel(50000, 53); susp || name != "DNS" {
		t.Errorf("portLabel(50000,53)=(%q,%v)", name, susp)
	}
	// nothing known
	if name, susp, _ := portLabel(50000, 50001); susp || name != "—" {
		t.Errorf("portLabel(unknown)=(%q,%v)", name, susp)
	}
}

// Port labels are data shown in every language, so they must carry no prose of
// their own — the legacy note is rendered from i18n via LegacyPort.
func TestPortLabelsAreLanguageNeutral(t *testing.T) {
	for port, name := range legacyMalwarePorts {
		if strings.Contains(name, "histórico") || strings.Contains(name, "legacy") {
			t.Errorf("port %d label %q carries a language-specific note", port, name)
		}
	}
}

// The Linux firewall helpers are split by address family; picking the v4 tool
// for a v6 address is a silent "Block IP" failure.
func TestFirewallFamily(t *testing.T) {
	for ip, v6 := range map[string]bool{
		"8.8.8.8": false, "192.168.1.1": false, "::ffff:1.2.3.4": false,
		"2001:4860:4860::8888": true, "fe80::1": true, "::1": true,
	} {
		if got := isIPv6(ip); got != v6 {
			t.Errorf("isIPv6(%q) = %v, want %v", ip, got, v6)
		}
		wantTool, wantSet := "iptables", "blocked"
		if v6 {
			wantTool, wantSet = "ip6tables", "blocked6"
		}
		if got := iptablesFor(ip); got != wantTool {
			t.Errorf("iptablesFor(%q) = %q, want %q", ip, got, wantTool)
		}
		if got := nftSetFor(ip); got != wantSet {
			t.Errorf("nftSetFor(%q) = %q, want %q", ip, got, wantSet)
		}
	}
}

func TestDetectProvider(t *testing.T) {
	if p := detectProvider(&Enrichment{ISP: "Amazon.com, Inc."}); p != "Amazon" {
		t.Errorf("detectProvider Amazon=%q", p)
	}
	if p := detectProvider(&Enrichment{ASN: "AS13335 Cloudflare"}); p != "Cloudflare" {
		t.Errorf("detectProvider Cloudflare=%q", p)
	}
	if p := detectProvider(&Enrichment{ISP: "Random Local ISP"}); p != "" {
		t.Errorf("detectProvider unknown=%q, want empty", p)
	}
}

func TestCnFromSubject(t *testing.T) {
	if cn := cnFromSubject("CN=Microsoft Windows, O=Microsoft, C=US"); cn != "Microsoft Windows" {
		t.Errorf("cnFromSubject=%q", cn)
	}
	// No CN → falls back to the full subject (used as-is for display).
	if cn := cnFromSubject("O=NoCommonName, C=US"); cn != "O=NoCommonName, C=US" {
		t.Errorf("cnFromSubject no-CN=%q, want full subject", cn)
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{
		"":       "",
		"abc":    "****",
		"abcdef": "…cdef",
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestThreatClass(t *testing.T) {
	fn, ok := funcMap["threatClass"].(func(int) string)
	if !ok {
		t.Fatal("threatClass not in funcMap")
	}
	for score, want := range map[int]string{80: "high", 50: "med", 20: "low", 5: "min"} {
		if got := fn(score); got != want {
			t.Errorf("threatClass(%d)=%q, want %q", score, got, want)
		}
	}
}
