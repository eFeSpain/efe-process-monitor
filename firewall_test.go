package main

import (
	"errors"
	"strings"
	"testing"
)

// fakeFirewall records every firewall command instead of running it. present
// holds the rules that "exist": an iptables -C or -D for one of them succeeds.
type fakeFirewall struct {
	ran     []string
	present map[string]bool
	nftOut  string
}

func withFakeFirewall(t *testing.T, tools ...string) *fakeFirewall {
	t.Helper()
	f := &fakeFirewall{present: map[string]bool{}}
	oldRun, oldOut, oldHas := fwRun, fwOutput, hasCmd
	have := map[string]bool{}
	for _, tool := range tools {
		have[tool] = true
	}
	hasCmd = func(name string) bool { return have[name] }
	fwRun = func(name string, args ...string) error {
		line := name + " " + strings.Join(args, " ")
		f.ran = append(f.ran, line)
		if strings.HasSuffix(name, "tables") && len(args) > 0 {
			rule := name + " " + strings.Join(args[1:], " ")
			switch args[0] {
			case "-C":
				if !f.present[rule] {
					return errors.New("no such rule")
				}
			case "-D":
				if !f.present[rule] {
					return errors.New("no such rule")
				}
				delete(f.present, rule)
			case "-I":
				// "-I CHAIN 1 spec…" → the rule is "CHAIN spec…"
				f.present[name+" "+args[1]+" "+strings.Join(args[3:], " ")] = true
			}
		}
		return nil
	}
	fwOutput = func(name string, args ...string) ([]byte, error) {
		f.ran = append(f.ran, name+" "+strings.Join(args, " "))
		return []byte(f.nftOut), nil
	}
	t.Cleanup(func() { fwRun, fwOutput, hasCmd = oldRun, oldOut, oldHas })
	return f
}

func (f *fakeFirewall) has(line string) bool {
	for _, l := range f.ran {
		if l == line {
			return true
		}
	}
	return false
}

// A block is both directions: what the machine sends to the address and what
// the address sends to the machine. It used to be outbound only, so a blocked
// host could still open connections to anything listening here.
//
// The rules go to the head of the chain (-I … 1). Appended (-A), they sat
// after the chains ufw and friends hook into INPUT/OUTPUT, which accept new
// and established connections before the DROP is ever reached.
func TestBlockIPLinuxIptables(t *testing.T) {
	f := withFakeFirewall(t, "iptables", "ip6tables")
	if err := blockIPOn("linux", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -I OUTPUT 1 -d 203.0.113.9 -j DROP",
		"iptables -I INPUT 1 -s 203.0.113.9 -j DROP",
	} {
		if !f.has(want) {
			t.Errorf("missing %q in %v", want, f.ran)
		}
	}
	// Blocking again adds nothing: a duplicated rule survives one unblock.
	n := len(f.ran)
	if err := blockIPOn("linux", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.ran[n:] {
		if strings.Contains(l, " -I ") {
			t.Errorf("second block inserted a rule again: %q", l)
		}
	}

	// IPv6 goes through ip6tables.
	if err := blockIPOn("linux", "2001:db8::9"); err != nil {
		t.Fatal(err)
	}
	if !f.has("ip6tables -I INPUT 1 -s 2001:db8::9 -j DROP") || !f.has("ip6tables -I OUTPUT 1 -d 2001:db8::9 -j DROP") {
		t.Errorf("IPv6 block: %v", f.ran)
	}

	if err := unblockIPOn("linux", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for rule := range f.present {
		if strings.Contains(rule, "203.0.113.9") {
			t.Errorf("rule left behind after unblock: %q", rule)
		}
	}
}

// A block made by an earlier version has only the outbound rule: unblocking
// it must succeed, and re-applying it at start-up adds the inbound one.
func TestBlockUpgradesOutboundOnlyRule(t *testing.T) {
	f := withFakeFirewall(t, "iptables")
	f.present["iptables OUTPUT -d 198.51.100.7 -j DROP"] = true
	if err := blockIPOn("linux", "198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if !f.has("iptables -I INPUT 1 -s 198.51.100.7 -j DROP") || f.has("iptables -I OUTPUT 1 -d 198.51.100.7 -j DROP") {
		t.Errorf("want only the missing inbound rule added: %v", f.ran)
	}

	f = withFakeFirewall(t, "iptables")
	f.present["iptables OUTPUT -d 198.51.100.7 -j DROP"] = true
	if err := unblockIPOn("linux", "198.51.100.7"); err != nil {
		t.Errorf("unblocking an outbound-only block failed: %v", err)
	}
	if err := unblockIPOn("linux", "198.51.100.7"); err == nil {
		t.Error("unblocking something that is not blocked must say so")
	}
}

func TestBlockIPLinuxNft(t *testing.T) {
	f := withFakeFirewall(t, "nft")
	if err := blockIPOn("linux", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"nft add chain inet efepm out { type filter hook output priority 0 ; }",
		"nft add chain inet efepm in { type filter hook input priority 0 ; }",
		"nft add rule inet efepm out ip daddr @blocked drop",
		"nft add rule inet efepm out ip6 daddr @blocked6 drop",
		"nft add rule inet efepm in ip saddr @blocked drop",
		"nft add rule inet efepm in ip6 saddr @blocked6 drop",
		"nft add element inet efepm blocked { 203.0.113.9 }",
	} {
		if !f.has(want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(f.ran, "\n"))
		}
	}

	// Rules already in place are not added twice.
	f = withFakeFirewall(t, "nft")
	f.nftOut = "ip daddr @blocked drop\nip6 daddr @blocked6 drop\nip saddr @blocked drop\nip6 saddr @blocked6 drop\n"
	if err := blockIPOn("linux", "2001:db8::9"); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.ran {
		if strings.HasPrefix(l, "nft add rule") {
			t.Errorf("rule added although present: %q", l)
		}
	}
	if !f.has("nft add element inet efepm blocked6 { 2001:db8::9 }") {
		t.Errorf("IPv6 element: %v", f.ran)
	}
}

func TestBlockIPWindows(t *testing.T) {
	f := withFakeFirewall(t)
	if err := blockIPOn("windows", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"netsh advfirewall firewall add rule name=eFePM block 203.0.113.9 dir=out action=block remoteip=203.0.113.9",
		"netsh advfirewall firewall add rule name=eFePM block 203.0.113.9 dir=in action=block remoteip=203.0.113.9",
	} {
		if !f.has(want) {
			t.Errorf("missing %q in %v", want, f.ran)
		}
	}
	// One delete by name removes both directions.
	if err := unblockIPOn("windows", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if !f.has("netsh advfirewall firewall delete rule name=eFePM block 203.0.113.9") {
		t.Errorf("unblock: %v", f.ran)
	}
}

func TestBlockIPNoTool(t *testing.T) {
	withFakeFirewall(t)
	if err := blockIPOn("linux", "203.0.113.9"); err == nil {
		t.Error("no iptables and no nft: the block must fail, not pretend")
	}
}
