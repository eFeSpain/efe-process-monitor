package main

import (
	"net"
	"testing"
)

const tfFixture = `################################################################
# ThreatFox IOCs (CSV)                                          #
################################################################
"2026-06-07 10:00:22", "1", "165.154.227.66:8080", "ip:port", "botnet_cc", "win.cobalt_strike", "alias", "Cobalt Strike", "", "100", "True", "None", "tag", "1", "rep"
"2026-06-07 09:52:46", "2", "221.130.29.85:2375", "ip:port", "payload_delivery", "elf.kinsing", "h2miner", "Kinsing", "", "85", "False", "ref", "tag", "0", "rep"
"2026-06-07 09:00:00", "3", "bad.example.com", "domain", "botnet_cc", "win.x", "a", "FamilyDomain", "", "50", "True", "None", "t", "1", "r"
"2026-06-07 08:00:00", "4", "10.0.0.9:4444", "ip:port", "botnet_cc", "win.y", "a", "None", "", "75", "True", "None", "t", "1", "r"
`

func TestParseThreatFox(t *testing.T) {
	m := parseThreatFox(tfFixture)
	if len(m) != 3 { // 3 ip:port rows; the domain row is skipped
		t.Fatalf("got %d entries, want 3: %v", len(m), m)
	}
	if m["165.154.227.66"] != "Cobalt Strike" {
		t.Errorf("cobalt strike label=%q", m["165.154.227.66"])
	}
	if m["221.130.29.85"] != "Kinsing" {
		t.Errorf("kinsing label=%q", m["221.130.29.85"])
	}
	// malware_printable "None" falls back to threat_type.
	if m["10.0.0.9"] != "botnet_cc" {
		t.Errorf("fallback label=%q, want botnet_cc", m["10.0.0.9"])
	}
	// domain IOC must not appear.
	if _, ok := m["bad.example.com"]; ok {
		t.Error("domain IOC leaked into ip map")
	}
}

func TestParseThreatFoxEmpty(t *testing.T) {
	if m := parseThreatFox("# only a comment\n"); len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

const spamhausFixture = `; comment line should be ignored
{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripencc"}

{"type":"metadata","timestamp":1780827242,"records":2,"copyright":"x"}
`

func TestParseSpamhaus(t *testing.T) {
	nets := parseSpamhaus(spamhausFixture)
	if len(nets) != 2 { // metadata + comment + blank lines skipped
		t.Fatalf("got %d nets, want 2", len(nets))
	}
	hit := func(ip string) bool {
		a := net.ParseIP(ip)
		for _, n := range nets {
			if n.Contains(a) {
				return true
			}
		}
		return false
	}
	if !hit("1.10.16.1") {
		t.Error("1.10.16.1 should be inside 1.10.16.0/20")
	}
	if !hit("2.56.193.5") {
		t.Error("2.56.193.5 should be inside 2.56.192.0/22")
	}
	if hit("8.8.8.8") {
		t.Error("8.8.8.8 must not match any DROP netblock")
	}
}

func TestParseSpamhausGarbage(t *testing.T) {
	if nets := parseSpamhaus(`{"cidr":"not-a-cidr"}` + "\n" + `garbage`); len(nets) != 0 {
		t.Errorf("expected 0 nets from garbage, got %d", len(nets))
	}
}
