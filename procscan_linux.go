//go:build linux

package main

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// procScan is the cached result of the fd and maps read for one PID. A
// browser holds a thousand descriptors and maps thousands of regions, and the
// table is re-rendered every few seconds, so the raw reads are amortized.
type procScan struct {
	at      time.Time
	files   []string // sensitive files held by a foreign process
	scored  int
	media   []string
	execMap []string
}

const procScanTTL = 60 * time.Second

var (
	procScanMu    sync.Mutex
	procScanCache = map[int32]*procScan{}
)

// scanProcess reads what the process has open and mapped. Other users'
// processes need root; unreadable ones simply report nothing.
func scanProcess(pid int32, name string) *procScan {
	procScanMu.Lock()
	if s := procScanCache[pid]; s != nil && time.Since(s.at) < procScanTTL {
		procScanMu.Unlock()
		return s
	}
	procScanMu.Unlock()

	s := &procScan{at: time.Now()}
	base := "/proc/" + strconv.Itoa(int(pid))
	if ents, err := os.ReadDir(base + "/fd"); err == nil {
		var files []string
		for _, e := range ents {
			if t, err := os.Readlink(base + "/fd/" + e.Name()); err == nil && len(t) > 0 && t[0] == '/' {
				files = append(files, t)
			}
		}
		s.files, s.scored, s.media = sensitiveOpenFiles(name, files)
	}
	if b, err := os.ReadFile(base + "/maps"); err == nil { // #nosec G304 -- /proc path from a pid
		s.execMap = anomalousExecMaps(string(b))
	}

	procScanMu.Lock()
	if len(procScanCache) > 4096 {
		clear(procScanCache)
	}
	procScanCache[pid] = s
	procScanMu.Unlock()
	return s
}
