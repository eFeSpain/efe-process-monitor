package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// Provenance: how old is the binary, since when has this machine seen it, and
// what has the process spawned. Three numbers an analyst otherwise computes by
// hand from a timestamp, a database and a process tree.

// youngBinary is the age under which a binary is highlighted: something
// written to disk minutes ago that already holds sockets is what a dropper
// looks like. A day covers "installed this morning" without shouting.
const youngBinary = 24 * time.Hour

// exeProvenance reads the executable's modification time and the first time
// this machine saw this exact binary (path + content). Zero values mean
// unknown, and the template skips them.
func exeProvenance(exe string) (modified, firstSeen time.Time) {
	if !pathKnown(exe) {
		return
	}
	if fi, err := os.Stat(exe); err == nil {
		modified = fi.ModTime()
	}
	if db != nil {
		firstSeen = dbBaselineFirstSeen(exe, fileHash(exe))
	}
	return
}

// childrenMap builds parent → child names for the whole process table in one
// pass, so the details block can show what each process spawned without a
// /proc scan per PID (which is what gopsutil's Children does).
func childrenMap() map[int32][]string {
	m := map[int32][]string{}
	procs, err := process.Processes()
	if err != nil {
		return m
	}
	for _, p := range procs {
		ppid, err := p.Ppid()
		if err != nil || ppid <= 0 {
			continue
		}
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		m[ppid] = append(m[ppid], name)
	}
	return m
}

// summarizeChildren renders a child list as "bash ×2 · curl", most frequent
// first, capped so a shell with sixty jobs stays one line.
func summarizeChildren(names []string) string {
	if len(names) == 0 {
		return ""
	}
	count := map[string]int{}
	for _, n := range names {
		count[n]++
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var parts []string
	for i, k := range keys {
		if i == 8 {
			parts = append(parts, fmt.Sprintf("+%d", len(keys)-8))
			break
		}
		if count[k] > 1 {
			parts = append(parts, fmt.Sprintf("%s ×%d", k, count[k]))
		} else {
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, " · ")
}

// humanAge renders a duration as "hace 20 min" / "3 h ago" / "5 天前" using
// the language's own words, from the strings map the template already holds.
func humanAge(d time.Duration, T map[string]string) string {
	if d < 0 {
		d = 0
	}
	var n int64
	var unit string
	switch {
	case d < time.Hour:
		n, unit = int64(d/time.Minute), T["unit_min"]
	case d < 48*time.Hour:
		n, unit = int64(d/time.Hour), T["unit_h"]
	case d < 60*24*time.Hour:
		n, unit = int64(d/(24*time.Hour)), T["unit_d"]
	default:
		n, unit = int64(d/(30*24*time.Hour)), T["unit_mo"]
	}
	return fmt.Sprintf(T["age_ago"], fmt.Sprintf("%d %s", n, unit))
}
