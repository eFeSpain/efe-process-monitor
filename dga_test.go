package main

import (
	"fmt"
	"testing"
	"time"
)

// A burst of distinct names that do not exist is what malware iterating a
// domain-generation algorithm looks like while it hunts for its C2. The
// detector counts distinct NXDOMAIN names in a sliding window, fires once per
// cooldown with a sample, and ignores what legitimately fails all day: reverse
// lookups (our own enrichment produces those), mDNS/LLMNR-style local names,
// and anything that is not a hostname.
func TestDGADetectorFiresOnDistinctBurst(t *testing.T) {
	var d dgaDetector
	t0 := time.Now()
	for i := 0; i < dgaThreshold-1; i++ {
		if _, fire := d.observe(fmt.Sprintf("x%02d.example", i), t0.Add(time.Duration(i)*time.Second)); fire {
			t.Fatalf("fired at %d distinct names, threshold is %d", i+1, dgaThreshold)
		}
	}
	// The same name again is not a new one.
	if _, fire := d.observe("x00.example", t0.Add(30*time.Second)); fire {
		t.Fatal("a repeated name must not count twice")
	}
	names, fire := d.observe("yyy.example", t0.Add(31*time.Second))
	if !fire {
		t.Fatal("threshold reached: should fire")
	}
	if len(names) == 0 || len(names) > dgaSample {
		t.Errorf("sample = %v, want 1..%d names", names, dgaSample)
	}
	// Within the cooldown a second burst stays quiet…
	for i := 0; i < dgaThreshold+5; i++ {
		if _, fire := d.observe(fmt.Sprintf("z%02d.example", i), t0.Add(40*time.Second)); fire {
			t.Fatal("fired again inside the cooldown")
		}
	}
	// …and after it a fresh burst fires again.
	later := t0.Add(dgaCooldown + time.Minute)
	fired := false
	for i := 0; i < dgaThreshold; i++ {
		if _, f := d.observe(fmt.Sprintf("w%02d.example", i), later); f {
			fired = true
		}
	}
	if !fired {
		t.Error("after the cooldown a new burst must fire")
	}
}

func TestDGADetectorWindowAndExclusions(t *testing.T) {
	var d dgaDetector
	t0 := time.Now()
	// Names spread beyond the window never accumulate to the threshold.
	for i := 0; i < 3*dgaThreshold; i++ {
		if _, fire := d.observe(fmt.Sprintf("slow%03d.example", i), t0.Add(time.Duration(i)*dgaWindow/2)); fire {
			t.Fatalf("fired on %d names spread over %s each", i+1, dgaWindow/2)
		}
	}
	d = dgaDetector{}
	suffixed := []string{
		"4.3.2.1.in-addr.arpa", "1.0.0.0.ip6.arpa", // our own reverse lookups
		"printer.local", "nas.lan", "box.home.arpa", "pc.localdomain", "svc.internal", "UPPER.LOCAL",
	}
	plain := []string{"wpad.corp.example", "nodots", "", "   ", "trailing.local."}
	for i := 0; i < 10; i++ { // enough distinct variants that a bug counting them would reach the threshold
		for _, n := range suffixed {
			if _, fire := d.observe(fmt.Sprintf("%d.%s", i, n), t0); fire {
				t.Fatalf("fired on excluded names (%q)", n)
			}
		}
		for _, n := range plain {
			if _, fire := d.observe(n, t0); fire {
				t.Fatalf("fired on excluded names (%q)", n)
			}
		}
	}
	if n := d.pending(); n != 0 {
		t.Errorf("excluded names were counted: %d pending", n)
	}
}
