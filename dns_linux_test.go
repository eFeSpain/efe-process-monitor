//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The filter is hand-assembled. The kernel validates a classic BPF program on
// attach — bad jump targets, unknown opcodes — and SO_ATTACH_FILTER works on
// any socket without privilege, so the verifier can be asked directly.
func TestDNSFilterIsValidBPF(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no socket: %v", err)
	}
	defer unix.Close(fd)
	prog := unix.SockFprog{Len: uint16(len(dnsFilter)), Filter: &dnsFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		t.Fatalf("kernel rejected the DNS filter: %v", err)
	}
	// Every jump must land inside the program and end in a ret.
	for i, ins := range dnsFilter {
		if ins.Code&0x07 == 0x05 { // BPF_JMP
			for _, off := range []uint8{ins.Jt, ins.Jf} {
				if i+1+int(off) >= len(dnsFilter) {
					t.Errorf("instruction %d jumps past the end", i)
				}
			}
		}
	}
	if last := dnsFilter[len(dnsFilter)-1]; last.Code != 0x06 {
		t.Error("program must end in ret")
	}
}
