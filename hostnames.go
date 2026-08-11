package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Hostname correlation: which name did this address come from?
//
// Everything else the tool knows about a remote IP is *about the address* —
// geolocation, ASN, reputation. None of it answers the question an analyst
// actually asks first: what did the process ask for? "93.184.216.34 in Norwell,
// Edgecast" tells you little; "93.184.216.34, asked for as cdn-updates.tk" tells
// you almost everything.
//
// Two sources, both already flowing through the packet-capture parser and neither
// previously stored:
//
//   - TLS SNI. The strongest binding available: the client literally wrote the
//     hostname it wanted into a handshake sent to that address. No inference.
//   - DNS answer records. A response naming the address. Weaker than SNI — CDNs
//     return shared addresses, so several names legitimately map to one IP — but
//     it covers plaintext and non-TLS traffic that has no SNI.
//
// Reverse DNS (already in Enrichment.DNS) is a different and much weaker thing:
// it is what the *address owner* claims, not what the process asked for. A
// malicious host controls its own PTR record; it does not control what your
// browser typed into an SNI.
//
// Scope, stated plainly: this only sees traffic while a capture is running. It is
// not passive DNS logging — that would mean keeping tshark on permanently, which
// is a much bigger change than what the data already available justifies.

// hostnameSource ranks how much a binding can be trusted.
type hostnameSource string

const (
	srcSNI hostnameSource = "sni" // client-declared, strongest
	srcDNS hostnameSource = "dns" // observed in an answer record
)

// maxHostnamesPerIP bounds what one address can accumulate: a CDN address really
// does serve many names, and without a cap a long capture would grow forever.
const maxHostnamesPerIP = 8

var (
	hostMu    sync.Mutex
	hostSeen  = map[string]map[string]bool{} // ip -> set of names, in-memory dedupe
	maxHostIP = 4096                         // bound the dedupe map itself
)

// observeHostnames extracts any IP↔name bindings from one parsed packet and
// records them. Called for every captured packet, so it must stay cheap: the
// in-memory set filters repeats before any database work happens.
func observeHostnames(pkt map[string]string) {
	// SNI binds the name to the packet's destination (the client is talking *to*
	// the server it named).
	if sni := cleanHostname(pkt["tls_sni"]); sni != "" {
		if ip := pkt["ip_dst"]; validIP(ip) {
			recordHostname(ip, sni, srcSNI)
		}
	}
	// DNS answers bind the name in the query to each address returned. tshark
	// emits multiple values comma-separated.
	if name := cleanHostname(pkt["dns"]); name != "" {
		for _, field := range []string{pkt["dns_a"], pkt["dns_aaaa"]} {
			for _, ip := range strings.Split(field, ",") {
				if ip = strings.TrimSpace(ip); validIP(ip) {
					recordHostname(ip, name, srcDNS)
				}
			}
		}
	}
}

// cleanHostname normalizes and sanity-checks a hostname from packet data. This is
// attacker-influenced input (anyone can put anything in an SNI), so it is bounded
// and stripped of anything that isn't plausibly a hostname character.
func cleanHostname(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return "" // not a hostname; drop rather than store junk
		}
	}
	return s
}

func validIP(s string) bool {
	if s == "" {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback()
}

// recordHostname persists a binding, skipping anything already seen this session.
func recordHostname(ip, name string, src hostnameSource) {
	hostMu.Lock()
	if len(hostSeen) >= maxHostIP {
		hostSeen = map[string]map[string]bool{} // crude bound; the DB is the record
	}
	set := hostSeen[ip]
	if set == nil {
		set = map[string]bool{}
		hostSeen[ip] = set
	}
	if set[name] {
		hostMu.Unlock()
		return
	}
	if len(set) >= maxHostnamesPerIP {
		hostMu.Unlock()
		return
	}
	set[name] = true
	hostMu.Unlock()

	dbSaveHostname(ip, name, string(src), time.Now().Format("2006-01-02 15:04:05"))
}
