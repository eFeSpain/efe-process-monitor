package main

import (
	"net"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LANInfo is best-effort detail about a host on the local network.
type LANInfo struct {
	DNS     string `json:"dns"`
	NetBIOS string `json:"netbios"`
	MAC     string `json:"mac"`
	Vendor  string `json:"vendor"`
}

var (
	lanMu    sync.Mutex
	lanCache = map[string]*LANInfo{}
	lanAt    = map[string]time.Time{}
	lanTTL   = 10 * time.Minute
)

// isLAN reports whether ip is a private/link-local host on our network.
func isLAN(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && !a.IsLoopback() && !a.IsUnspecified() &&
		(a.IsPrivate() || a.IsLinkLocalUnicast())
}

func lanLookup(ip string) *LANInfo {
	lanMu.Lock()
	if e, ok := lanCache[ip]; ok && time.Since(lanAt[ip]) < lanTTL {
		lanMu.Unlock()
		return e
	}
	lanMu.Unlock()

	info := &LANInfo{}
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		info.DNS = strings.TrimSuffix(names[0], ".")
	}
	info.MAC = arpMAC(ip)
	info.Vendor = ouiVendor(info.MAC)
	info.NetBIOS = netbiosName(ip)

	lanMu.Lock()
	lanCache[ip] = info
	lanAt[ip] = time.Now()
	lanMu.Unlock()
	return info
}

var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)

// arpMAC returns the MAC address for ip from the system ARP table.
func arpMAC(ip string) string {
	for _, args := range [][]string{{"-a", ip}, {"-a"}} {
		out := runCmd(5*time.Second, "arp", args...)
		for _, ln := range strings.Split(out, "\n") {
			if !strings.Contains(ln, ip) {
				continue
			}
			if m := macRe.FindString(ln); m != "" {
				return strings.ToLower(strings.ReplaceAll(m, "-", ":"))
			}
		}
	}
	return ""
}

// netbiosName resolves the host's NetBIOS computer name.
func netbiosName(ip string) string {
	switch runtime.GOOS {
	case "windows":
		out := runCmd(5*time.Second, "nbtstat", "-A", ip)
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "<00>") && strings.Contains(strings.ToUpper(ln), "UNIQUE") {
				if f := strings.Fields(strings.TrimSpace(ln)); len(f) > 0 {
					return f[0]
				}
			}
		}
	case "linux":
		if hasCmd("nmblookup") {
			out := runCmd(5*time.Second, "nmblookup", "-A", ip)
			for _, ln := range strings.Split(out, "\n") {
				if strings.Contains(ln, "<00>") && !strings.Contains(strings.ToUpper(ln), "GROUP") {
					if f := strings.Fields(strings.TrimSpace(ln)); len(f) > 0 {
						return f[0]
					}
				}
			}
		}
	}
	return ""
}
