//go:build !linux

package main

// Brief connections need the Linux kernel's tracepoints and eBPF. Elsewhere
// the monitor has the poll alone, as it always did.
func startShortConns() (records <-chan kernelRecord, volume bool) {
	setShortConnStatus("os", "")
	return nil, false
}
