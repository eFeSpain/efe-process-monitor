//go:build windows

package main

import (
	"strings"
	"time"
)

// dnsCachePoll is how often the resolver cache is read. PowerShell start-up is
// the whole cost (~0.3 s of CPU), which is why this is not per monitor cycle.
const dnsCachePoll = 30 * time.Second

// startPassiveDNS polls the Windows DNS client cache. Every process resolves
// through it, and it keeps each answer for its TTL, so reading it periodically
// sees nearly every lookup made on the box without any privilege.
func startPassiveDNS() {
	passiveDNSStatus = "activo — caché DNS del sistema (Get-DnsClientCache) cada 30 s"
	go func() {
		for {
			pollDNSCache()
			time.Sleep(dnsCachePoll)
		}
	}()
}

// pollDNSCache reads A/AAAA entries as "queried name<TAB>address" lines. Entry
// is the name that was asked for; for a CNAME chain that is what the process
// wanted, which is exactly the binding hostnames.go is after.
func pollDNSCache() {
	out := runCmd(20*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | "+
			"ForEach-Object { \"$($_.Entry)`t$($_.Data)\" }")
	for _, ln := range strings.Split(out, "\n") {
		name, ip, ok := strings.Cut(strings.TrimSpace(ln), "\t")
		if !ok {
			continue
		}
		observeDNSAnswer(name, []string{strings.TrimSpace(ip)})
	}
}
