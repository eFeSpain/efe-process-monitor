//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// hiddenProcs (Windows): cross-view between the process API (gopsutil) and
// tasklist. Each discrepancy is re-verified to avoid timing false positives.
func hiddenProcs(lang string) []string {
	gset := map[int]bool{}
	pids, _ := process.Pids()
	for _, p := range pids {
		gset[int(p)] = true
	}
	tset := tasklistPids()
	if len(tset) == 0 {
		return nil // tasklist failed — don't raise a false alarm
	}
	cand := map[int]bool{}
	for p := range tset {
		if !gset[p] {
			cand[p] = true
		}
	}
	for p := range gset {
		if !tset[p] {
			cand[p] = true
		}
	}
	var hidden []string
	for p := range cand {
		// Re-check this specific PID in both sources; a transient process is now
		// gone from both, so the discrepancy disappears (no false positive).
		inApi := func() bool { _, err := process.NewProcess(int32(p)); return err == nil }()
		o := runCmd(6*time.Second, "tasklist", "/fi", fmt.Sprintf("PID eq %d", p), "/fo", "csv", "/nh")
		inTask := strings.Contains(o, fmt.Sprintf(`"%d"`, p))
		if inApi != inTask {
			src := "tasklist"
			if inApi {
				src = atr(lang, "src_api")
			}
			hidden = append(hidden, fmt.Sprintf(atr(lang, "rk_proc_only"), p, src))
		}
	}
	return hidden
}

func tasklistPids() map[int]bool {
	out := runCmd(15*time.Second, "tasklist", "/fo", "csv", "/nh")
	set := map[int]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(ln), `","`)
		if len(f) >= 2 {
			if pid, err := strconv.Atoi(strings.Trim(f[1], `"`)); err == nil {
				set[pid] = true
			}
		}
	}
	return set
}

func promiscIfaces() []string { return nil } // not implemented on Windows
