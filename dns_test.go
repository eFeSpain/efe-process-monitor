package main

import (
	"encoding/binary"
	"testing"
)

// Builds a DNS message by hand: the parser is hand-written for the same reason,
// and a fixture that shares no code with it is the only honest test.
func dnsName(labels ...string) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func dnsHeader(flags uint16, qd, an int) []byte {
	h := []byte{0x12, 0x34}
	h = append(h, be16(flags)...)
	h = append(h, be16(uint16(qd))...)
	h = append(h, be16(uint16(an))...)
	return append(h, 0, 0, 0, 0)
}

func rr(name []byte, typ uint16, rdata []byte) []byte {
	r := append([]byte{}, name...)
	r = append(r, be16(typ)...)
	r = append(r, 0, 1, 0, 0, 0, 60) // IN, TTL 60
	r = append(r, be16(uint16(len(rdata)))...)
	return append(r, rdata...)
}

func TestParseDNSAnswers(t *testing.T) {
	// www.example.com → CNAME edge.example.net → A 93.184.216.34, AAAA 2606:2800::1
	// with the answers naming the question by compression pointer (0xC00C).
	q := dnsName("www", "example", "com")
	msg := dnsHeader(0x8180, 1, 3)
	msg = append(msg, q...)
	msg = append(msg, 0, 1, 0, 1) // A, IN
	ptr := []byte{0xC0, 0x0C}
	cname := dnsName("edge", "example", "net")
	msg = append(msg, rr(ptr, 5, cname)...)
	msg = append(msg, rr(cname, 1, []byte{93, 184, 216, 34})...)
	v6 := make([]byte, 16)
	v6[0], v6[1], v6[2], v6[3], v6[15] = 0x26, 0x06, 0x28, 0x00, 1
	msg = append(msg, rr(cname, 28, v6)...)

	qname, ips := parseDNSAnswers(msg)
	if qname != "www.example.com" {
		t.Errorf("qname = %q", qname)
	}
	if len(ips) != 2 || ips[0] != "93.184.216.34" || ips[1] != "2606:2800::1" {
		t.Errorf("ips = %v", ips)
	}

	// The whole point is binding the *queried* name to every address in the
	// answer, CNAME chain or not: that is what the process asked for.
	// Truncated at every possible length, the parser must return cleanly.
	for i := 0; i < len(msg); i++ {
		parseDNSAnswers(msg[:i])
	}
}

func TestParseDNSAnswersIgnoresNonAnswers(t *testing.T) {
	q := append(dnsName("a", "b"), 0, 1, 0, 1)
	for name, flags := range map[string]uint16{"query": 0x0100, "nxdomain": 0x8183, "servfail": 0x8182} {
		if qn, ips := parseDNSAnswers(append(dnsHeader(flags, 1, 0), q...)); qn != "" || ips != nil {
			t.Errorf("%s: got %q %v, want nothing", name, qn, ips)
		}
	}
}

// A pointer loop must not spin, and a label past the end must not panic.
func TestReadDNSNameMalformed(t *testing.T) {
	loop := []byte{0xC0, 0x00}
	if _, _, ok := readDNSName(loop, 0); ok {
		t.Error("pointer loop accepted")
	}
	if _, _, ok := readDNSName([]byte{5, 'a', 'b'}, 0); ok {
		t.Error("label past the end accepted")
	}
	if _, _, ok := readDNSName([]byte{0x80, 0}, 0); ok {
		t.Error("reserved label type accepted")
	}
}

// The cooked-frame parser is the userspace twin of the BPF filter: both must
// agree on what a DNS response looks like at the IP layer.
func TestUDPPayloadOfFrame(t *testing.T) {
	v4 := make([]byte, 20+8+2)
	v4[0] = 0x45 // IPv4, IHL 5
	v4[9] = 17   // UDP
	binary.BigEndian.PutUint16(v4[20:], 53)
	v4[28], v4[29] = 0xAB, 0xCD
	if p := udpPayloadOfFrame(v4); len(p) != 2 || p[0] != 0xAB {
		t.Errorf("v4 payload = %v", p)
	}
	binary.BigEndian.PutUint16(v4[20:], 443)
	if udpPayloadOfFrame(v4) != nil {
		t.Error("non-53 source accepted")
	}
	binary.BigEndian.PutUint16(v4[20:], 53)
	v4[6] = 0x00
	v4[7] = 0x10 // fragment offset 16
	if udpPayloadOfFrame(v4) != nil {
		t.Error("fragment accepted")
	}

	v6 := make([]byte, 40+8+1)
	v6[0] = 0x60
	v6[6] = 17
	binary.BigEndian.PutUint16(v6[40:], 53)
	v6[48] = 0xEE
	if p := udpPayloadOfFrame(v6); len(p) != 1 || p[0] != 0xEE {
		t.Errorf("v6 payload = %v", p)
	}
	if udpPayloadOfFrame([]byte{0x45}) != nil || udpPayloadOfFrame(nil) != nil {
		t.Error("short frame accepted")
	}
}
