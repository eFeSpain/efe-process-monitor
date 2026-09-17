package main

import (
	"encoding/binary"
	"net"
	"strings"
)

// Passive DNS without a capture.
//
// hostnames.go answers "what name did the process ask for?" — but only while a
// tshark capture is running, so in practice the answer was usually missing at
// the moment it mattered: a new remote connection in the live feed. The DNS
// answers are flowing through the machine all the time; this reads them:
//
//   - Linux, as root: an AF_PACKET socket with a BPF filter for UDP source port
//     53, so the kernel hands over only DNS responses (dns_linux.go). No libpcap,
//     no tshark, a few hundred bytes per lookup.
//   - Windows: the OS keeps a resolver cache for every process; it is polled
//     every 30 s with Get-DnsClientCache (dns_windows.go). No privilege needed.
//
// What it cannot see, stated plainly: DNS over HTTPS/TLS (Firefox and Chrome
// with DoH on, systemd-resolved with DNSOverTLS) is encrypted and never passes
// as a port-53 answer. Those names still show up if a capture is running (SNI).
//
// Bindings go through the same recordHostname as the capture path, with the
// same source label: what matters to the analyst is "observed DNS answer",
// not which mechanism observed it.

// passiveDNSStatus is what the startup banner prints for this feature.
var passiveDNSStatus string

// parseDNSAnswers extracts the queried name and the A/AAAA addresses from a DNS
// response. Only clean, successful responses count: a NXDOMAIN or a SERVFAIL
// binds nothing. Written by hand rather than pulling in a DNS library: the
// message format is a page long and this needs four fields of it.
func parseDNSAnswers(b []byte) (qname string, ips []string) {
	if len(b) < 12 {
		return "", nil
	}
	flags := binary.BigEndian.Uint16(b[2:])
	if flags&0x8000 == 0 || flags&0x000f != 0 { // not a response, or an error rcode
		return "", nil
	}
	qd, an := int(binary.BigEndian.Uint16(b[4:])), int(binary.BigEndian.Uint16(b[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, next, ok := readDNSName(b, off)
		if !ok || next+4 > len(b) {
			return "", nil
		}
		if i == 0 {
			qname = name
		}
		off = next + 4 // qtype, qclass
	}
	for i := 0; i < an; i++ {
		_, next, ok := readDNSName(b, off)
		if !ok || next+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[next:])
		rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
		off = next + 10
		if off+rdlen > len(b) {
			break
		}
		switch {
		case typ == 1 && rdlen == 4: // A
			ips = append(ips, net.IP(b[off:off+4]).String())
		case typ == 28 && rdlen == 16: // AAAA
			ips = append(ips, net.IP(b[off:off+16]).String())
		}
		off += rdlen
	}
	return qname, ips
}

// readDNSName decodes a (possibly compressed) name at off. It returns the
// name, the offset just past it in the *original* position — a pointer ends
// the name where the pointer was, not where it pointed — and false on any
// malformed input. Jumps are bounded so a pointer loop cannot spin.
func readDNSName(b []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	for jumps := 0; ; {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			off++
			if end < 0 {
				end = off
			}
			return strings.Join(labels, "."), end, true
		case l&0xC0 == 0xC0: // compression pointer
			if off+1 >= len(b) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3FFF)
			if end < 0 {
				end = off + 2
			}
			jumps++
			if jumps > 16 || ptr >= len(b) {
				return "", 0, false
			}
			off = ptr
		case l > 63:
			return "", 0, false
		default:
			off++
			if off+l > len(b) || len(labels) > 127 {
				return "", 0, false
			}
			labels = append(labels, string(b[off:off+l]))
			off += l
		}
	}
}

// observeDNSAnswer records the bindings of one parsed response.
func observeDNSAnswer(qname string, ips []string) {
	name := cleanHostname(qname)
	if name == "" {
		return
	}
	for _, ip := range ips {
		if validIP(ip) {
			recordHostname(ip, name, srcDNS)
		}
	}
}

// udpPayloadOfFrame returns the UDP payload of a cooked (link header removed)
// IPv4/IPv6 frame when it is a datagram from source port 53, else nil. The BPF
// filter already selects these; this is the userspace side of the same check,
// and where the header lengths are actually parsed.
func udpPayloadOfFrame(f []byte) []byte {
	if len(f) < 1 {
		return nil
	}
	var udp int
	switch f[0] >> 4 {
	case 4:
		if len(f) < 20 || f[9] != 17 {
			return nil
		}
		if binary.BigEndian.Uint16(f[6:])&0x1FFF != 0 { // fragment
			return nil
		}
		udp = int(f[0]&0x0F) * 4
	case 6:
		if len(f) < 40 || f[6] != 17 {
			return nil
		}
		udp = 40
	default:
		return nil
	}
	if udp+8 > len(f) || binary.BigEndian.Uint16(f[udp:]) != 53 {
		return nil
	}
	return f[udp+8:]
}
