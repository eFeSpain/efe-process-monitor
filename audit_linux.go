//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// hiddenSweepBudget bounds the kill(pid,0) sweep. pid_max is 4 194 304 on a
// systemd box and the sweep used to stop at 500 000, so a hidden process with
// a high PID — routine on a long-running machine — was simply never probed.
// Now the whole range is walked and, if the budget runs out first, the check
// says so instead of pretending it finished.
const hiddenSweepBudget = 8 * time.Second

// hiddenProcs (Linux): cross-view between /proc and a kill(pid,0) probe. A PID
// that answers a signal but has no /proc entry is being hidden (classic LKM
// rootkit). Returns the findings, whether the probe ran, and whether it was
// cut short.
func hiddenProcs() (hidden []string, ran, partial bool) {
	max := 32768
	if b, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if m, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			max = m
		}
	}
	if max > 4194304 {
		max = 4194304
	}
	listed := map[int]bool{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if n, err := strconv.Atoi(e.Name()); err == nil {
				listed[n] = true
			}
		}
	}
	deadline := time.Now().Add(hiddenSweepBudget)
	for pid := 2; pid < max; pid++ {
		if pid&0x3fff == 0 && time.Now().After(deadline) {
			return hidden, true, true
		}
		if listed[pid] {
			continue
		}
		err := syscall.Kill(pid, 0)
		if err != nil && err != syscall.EPERM { // ESRCH: nothing there
			continue
		}
		if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); !os.IsNotExist(e) {
			continue // a process that appeared after the /proc listing
		}
		// Exists but absent from /proc — unless it exited between the two
		// calls. Ask once more: a real hidden process still answers.
		if e := syscall.Kill(pid, 0); e == nil || e == syscall.EPERM {
			hidden = append(hidden, "pid "+strconv.Itoa(pid))
		}
	}
	return hidden, true, false
}

// promiscIfaces (Linux): interfaces with the IFF_PROMISC flag set (0x100).
func promiscIfaces() ([]string, bool) {
	var res []string
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, false // couldn't read sysfs: indeterminate, not "none"
	}
	for _, e := range ents {
		b, err := os.ReadFile("/sys/class/net/" + e.Name() + "/flags")
		if err != nil {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 64)
		if err == nil && v&0x100 != 0 {
			res = append(res, e.Name())
		}
	}
	return res, true
}
