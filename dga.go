package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// DGA detection from NXDOMAIN answers.
//
// Malware that generates its C2 domain names from an algorithm tries them in a
// row until one resolves; the hundreds that do not exist come back as NXDOMAIN.
// The passive DNS listener already sees every answer on the machine, and until
// now it threw the failures away. A burst of *distinct* non-existent names in a
// short window is the shape; nothing legitimate produces it at this rate.
//
// Stated plainly: this is a machine-wide signal. The AF_PACKET socket sees the
// answer, not the process that asked, so the alert names the domains and the
// operator finds the process. Linux only — the Windows resolver cache does not
// expose failures — and blind to DoH/DoT like the rest of the passive DNS.
//
// What is deliberately not counted: reverse lookups (our own enrichment asks
// for PTR records of every new address, and most have none), local-network
// suffixes that fail all day (mDNS, LLMNR, home routers), WPAD probes, and
// anything that is not a hostname.

const (
	dgaWindow    = 60 * time.Second // distinct names are counted within this window
	dgaThreshold = 25               // distinct NXDOMAIN names in the window that fire the alert
	dgaCooldown  = 10 * time.Minute // one alert per burst, not one per name
	dgaSample    = 6                // names quoted in the alert
)

// dgaIgnoredSuffixes never count. The leading dot keeps "notlocal.example"
// from matching ".local".
var dgaIgnoredSuffixes = []string{
	".in-addr.arpa", ".ip6.arpa", ".arpa",
	".local", ".localdomain", ".home.arpa", ".lan", ".internal", ".home", ".corp", ".localhost",
}

type dgaDetector struct {
	mu        sync.Mutex
	seen      map[string]time.Time // name -> last NXDOMAIN
	lastAlert time.Time
}

// dgaIgnored reports whether a failed name is noise rather than a candidate.
func dgaIgnored(name string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return true
	}
	if strings.HasPrefix(name, "wpad.") {
		return true
	}
	for _, s := range dgaIgnoredSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// observe records one NXDOMAIN name. It returns a sample of the names and true
// when the window holds dgaThreshold distinct names and no alert fired within
// dgaCooldown; the window is then cleared so the next alert needs a new burst.
func (d *dgaDetector) observe(name string, now time.Time) (sample []string, fire bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if dgaIgnored(name) {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]time.Time{}
	}
	for n, at := range d.seen {
		if now.Sub(at) > dgaWindow {
			delete(d.seen, n)
		}
	}
	d.seen[name] = now
	if len(d.seen) < dgaThreshold || now.Sub(d.lastAlert) < dgaCooldown {
		return nil, false
	}
	d.lastAlert = now
	for n := range d.seen {
		sample = append(sample, n)
	}
	sort.Strings(sample)
	if len(sample) > dgaSample {
		sample = sample[:dgaSample]
	}
	d.seen = map[string]time.Time{}
	return sample, true
}

// pending is the number of distinct names currently in the window (tests).
func (d *dgaDetector) pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

var dga dgaDetector

// dgaObserve feeds one NXDOMAIN name from the listener and raises the alert —
// live feed, history and desktop notification — when the burst is there.
func dgaObserve(name string) {
	sample, fire := dga.observe(name, time.Now())
	if !fire {
		return
	}
	T := strings_(currentLang())
	detail := fmt.Sprintf(T["ev_dga"], dgaThreshold, dgaWindow, strings.Join(sample, ", "))
	log.Printf("[!] DGA? %s", detail)
	publish(Event{Kind: "alert", Process: "DNS", Detail: detail})
	notify(T["notif_dga"], detail, "dga")
}
