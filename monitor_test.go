package main

import (
	"os"
	"testing"
)

// The monitor hides its own PID, but the subprocesses the tool itself starts
// (nmblookup, arp, tshark, netsh…) open sockets too and were reported as new
// processes — and, the first time, as new binaries with a desktop notification.
// A child of ours is ours.
func TestOwnChildFilter(t *testing.T) {
	if ownChild(ownPID) {
		t.Error("the monitor itself is not its own child")
	}
	if ownChild(int32(os.Getppid())) {
		t.Error("our parent is not our child")
	}
	if ownChild(0) || ownChild(-1) {
		t.Error("invalid PIDs are never ours")
	}
}
