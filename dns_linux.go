//go:build linux

package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

// startPassiveDNS opens an AF_PACKET socket for DNS responses. Root only:
// CAP_NET_RAW is what the socket needs, and the tool is run as root for kill
// and firewall anyway. See dns.go for what this is and is not.
func startPassiveDNS() {
	if os.Geteuid() != 0 {
		passiveDNSStatus = "inactivo — requiere root (o CAP_NET_RAW)"
		return
	}
	// SOCK_DGRAM on AF_PACKET delivers frames with the link-layer header
	// stripped, so the packet starts at the IP header on every interface type
	// (Ethernet, Wi-Fi, tunnels) and the filter below needs no per-link offsets.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		passiveDNSStatus = fmt.Sprintf("inactivo — socket: %v", err)
		return
	}
	// #nosec G115 -- dnsFilter is a fixed 17-instruction table; the cast cannot overflow.
	prog := unix.SockFprog{Len: uint16(len(dnsFilter)), Filter: &dnsFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		passiveDNSStatus = fmt.Sprintf("inactivo — filtro BPF: %v", err)
		return
	}
	passiveDNSStatus = "activo — respuestas DNS de todas las interfaces (AF_PACKET + BPF)"
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				log.Printf("[dns] lectura del socket falló: %v", err)
				unix.Close(fd)
				return
			}
			if payload := udpPayloadOfFrame(buf[:n]); payload != nil {
				observeDNSAnswer(parseDNSAnswers(payload))
			}
		}
	}()
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// dnsFilter is a classic BPF program over a cooked frame: accept UDP datagrams
// from source port 53, IPv4 (non-fragment) or IPv6 (UDP as the next header),
// reject everything else in the kernel so userspace never sees it. Written
// out instruction by instruction; the jump offsets are relative to the next
// instruction, as in tcpdump -dd output.
var dnsFilter = []unix.SockFilter{
	{Code: 0x30, K: 0},                    //  0: ldb [0]              ; version << 4 | ihl
	{Code: 0x74, K: 4},                    //  1: rsh #4               ; A = version
	{Code: 0x15, Jt: 0, Jf: 7, K: 4},      //  2: jeq #4 → 3 else → 10
	{Code: 0x30, K: 9},                    //  3: ldb [9]              ; IPv4 protocol
	{Code: 0x15, Jt: 0, Jf: 11, K: 17},    //  4: jeq #17 (UDP) → 5 else drop
	{Code: 0x28, K: 6},                    //  5: ldh [6]              ; flags + fragment offset
	{Code: 0x45, Jt: 9, Jf: 0, K: 0x1fff}, // 6: jset #0x1fff → drop (fragment) else → 7
	{Code: 0xb1, K: 0},                    //  7: ldx 4*([0]&0xf)      ; X = IHL in bytes
	{Code: 0x48, K: 0},                    //  8: ldh [x+0]            ; UDP source port
	{Code: 0x15, Jt: 5, Jf: 6, K: 53},     //  9: jeq #53 → accept else drop
	{Code: 0x15, Jt: 0, Jf: 5, K: 6},      // 10: jeq #6 (IPv6) → 11 else drop
	{Code: 0x30, K: 6},                    // 11: ldb [6]              ; next header
	{Code: 0x15, Jt: 0, Jf: 3, K: 17},     // 12: jeq #17 → 13 else drop
	{Code: 0x28, K: 40},                   // 13: ldh [40]             ; UDP source port after the fixed header
	{Code: 0x15, Jt: 0, Jf: 1, K: 53},     // 14: jeq #53 → accept else drop
	{Code: 0x06, K: 0x40000},              // 15: ret #262144          ; accept
	{Code: 0x06, K: 0},                    // 16: ret #0               ; drop
}
