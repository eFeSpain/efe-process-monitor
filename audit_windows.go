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
// PIDs are kept as int32 end to end — the width the process API uses — so no
// narrowing conversion is needed anywhere in this comparison.
func hiddenProcs(lang string) ([]string, bool) {
	gset := map[int32]bool{}
	pids, _ := process.Pids()
	for _, p := range pids {
		gset[p] = true
	}
	tset := tasklistPids()
	if len(tset) == 0 {
		// tasklist failed: report "couldn't check", not "nothing found".
		return nil, false
	}
	cand := map[int32]bool{}
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
		inApi := func() bool { _, err := process.NewProcess(p); return err == nil }()
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
	return hidden, true
}

func tasklistPids() map[int32]bool {
	out := runCmd(15*time.Second, "tasklist", "/fo", "csv", "/nh")
	set := map[int32]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(ln), `","`)
		if len(f) >= 2 {
			// ParseInt with an explicit bit size: this is parsed from external
			// command output, so it must not silently wrap into the int32 the
			// process API takes.
			if pid, err := strconv.ParseInt(strings.Trim(f[1], `"`), 10, 32); err == nil && pid > 0 {
				set[int32(pid)] = true
			}
		}
	}
	return set
}

// promiscIfaces is not implemented on Windows; false means "not checked", which
// the audit reports as indeterminate rather than as a clean pass.
func promiscIfaces() ([]string, bool) { return nil, false }
