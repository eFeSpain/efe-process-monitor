package main

import (
	"strconv"
	"strings"
)

// parseServiceLines reads "pid<TAB>name<TAB>display" lines into pid → items
// ("name — display"). Pure, for the fixture test.
func parseServiceLines(out string) map[int32][]string {
	m := map[int32][]string{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(ln), "\t")
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.ParseInt(f[0], 10, 32)
		if err != nil || pid <= 0 {
			continue
		}
		item := f[1]
		if len(f) >= 3 && f[2] != "" && f[2] != f[1] {
			item += " — " + f[2]
		}
		m[int32(pid)] = append(m[int32(pid)], item)
	}
	return m
}
