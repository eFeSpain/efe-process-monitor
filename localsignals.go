package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Local signals in the live monitor.
//
// Three findings are computed without any external service and are precise
// enough to score on their own: a spawn chain that should never happen
// (ancestry.go), a foreign process holding a credential store or an input
// device, and executable memory from a memfd, a staging directory or a deleted
// file (procscan.go). They used to exist only in the rendered table — so with
// the monitor running as a service and nobody looking at the panel, a document
// launching a script host raised no alert and no notification. The monitor
// loop now checks every process that holds a socket: when it first appears,
// and once a minute after that (a credential store can be opened later).

// localSignals decides which local signals a process shows. Pure: the caller
// gathers the ancestry and the /proc scan. Camera and microphone are context
// and never a signal.
func localSignals(name string, chain []Ancestor, s *procScan) []reason {
	var rs []reason
	if why := suspiciousAncestry(name, chain); why != "" {
		rs = append(rs, reason{key: "spawn", args: []string{why}})
	}
	if s != nil && s.scored > 0 {
		rs = append(rs, reason{key: "creds", args: []string{strconv.Itoa(s.scored)}})
	}
	if s != nil && len(s.execMap) > 0 {
		rs = append(rs, reason{key: "execmap", args: []string{strconv.Itoa(len(s.execMap))}})
	}
	return rs
}

// localAlertDedupe makes each (process, signal) alert once. An entry lives as
// long as it keeps being seen, plus knownPIDTTL: a reused PID alerts again.
type localAlertDedupe struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (d *localAlertDedupe) fresh(pid int32, key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]time.Time{}
	}
	for k, at := range d.seen {
		if now.Sub(at) > knownPIDTTL {
			delete(d.seen, k)
		}
	}
	k := strconv.Itoa(int(pid)) + "|" + key
	_, known := d.seen[k]
	d.seen[k] = now
	return !known
}

const localCheckEvery = time.Minute

var (
	localAlerts    localAlertDedupe
	localNextCheck = map[int32]time.Time{} // monitor goroutine only
)

// checkLocalSignals runs the local checks for every process in the snapshot
// that is due, and raises a red alert — feed, history, desktop notification —
// for each signal not yet reported for that process. A whitelisted binary is
// still reported in the feed but does not notify, like every other alert.
func checkLocalSignals(snap map[connKey]gnet.ConnectionStat, wl map[string]bool, now time.Time) {
	for pid, at := range localNextCheck {
		if now.Sub(at) > knownPIDTTL {
			delete(localNextCheck, pid)
		}
	}
	seen := map[int32]bool{}
	for _, c := range snap {
		pid := c.Pid
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		if next, ok := localNextCheck[pid]; ok && now.Before(next) {
			continue
		}
		localNextCheck[pid] = now.Add(localCheckEvery)
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		name, _ := p.Name()
		rs := localSignals(name, ancestryOf(pid), scanProcess(pid, name))
		if len(rs) == 0 {
			continue
		}
		exe, _ := p.Exe()
		T := strings_(currentLang())
		var texts []string
		for _, r := range rs {
			if !localAlerts.fresh(pid, r.key, now) {
				continue
			}
			args := make([]any, len(r.args))
			for i, a := range r.args {
				args[i] = a
			}
			texts = append(texts, fmt.Sprintf(T["bd_"+r.key], args...))
		}
		if len(texts) == 0 {
			continue
		}
		detail := strings.Join(texts, " · ")
		publish(Event{Kind: "alert", Level: "high", PID: pid, Process: name, Exe: exe, Detail: detail})
		if !wl[exe] {
			notify(T["notif_local"], fmt.Sprintf("%s (%d) — %s", name, pid, detail), "local:"+strconv.Itoa(int(pid)))
		}
	}
}
