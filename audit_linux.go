//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// hiddenProcs (Linux): cross-view between /proc and a kill(pid,0) probe. A PID
// that answers a signal but has no /proc entry is being hidden (classic LKM rootkit).
func hiddenProcs(lang string) []string {
	max := 32768
	if b, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if m, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			max = m
		}
	}
	if max > 500000 {
		max = 500000
	}
	listed := map[int]bool{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if n, err := strconv.Atoi(e.Name()); err == nil {
				listed[n] = true
			}
		}
	}
	var hidden []string
	for pid := 2; pid < max; pid++ {
		if listed[pid] {
			continue
		}
		err := syscall.Kill(pid, 0)
		if err == nil || err == syscall.EPERM { // exists (EPERM = exists, no perm)
			if _, e := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(e) {
				hidden = append(hidden, fmt.Sprintf(atr(lang, "rk_proc_proc"), pid))
			}
		}
	}
	return hidden
}

// promiscIfaces (Linux): interfaces with the IFF_PROMISC flag set (0x100).
func promiscIfaces() []string {
	var res []string
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
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
	return res
}
