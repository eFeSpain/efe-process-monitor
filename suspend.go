package main

import (
	"log"
	"math"
	"net/http"
	"sync"

	"github.com/shirou/gopsutil/v4/process"
)

// Suspend / resume.
//
// Killing a suspicious process stops it and destroys the evidence with it:
// its memory, its open files, its sockets. Suspending freezes it — it stops
// running and stops talking — and leaves everything in place to be looked
// at, dumped or resumed if it turns out to be innocent. SIGSTOP / SIGCONT on
// Unix, NtSuspendProcess / NtResumeProcess on Windows (both through gopsutil).

// validTargetPID is the refusal shared by the process actions. The upper
// bound matters: PID is an int from JSON and int32() would wrap a huge value
// round into a different, valid PID — acting on a process the caller never
// named. Never ourselves and never init: neither is a response action, both
// are an outage.
func validTargetPID(w http.ResponseWriter, n int) (pid int32, ok bool) {
	if n <= 0 || n > math.MaxInt32 {
		http.Error(w, `{"ok":false,"error":"invalid pid"}`, http.StatusBadRequest)
		return 0, false
	}
	pid = int32(n)
	if pid == ownPID || pid == 1 {
		http.Error(w, `{"ok":false,"error":"refusing to act on the monitor or init"}`, http.StatusBadRequest)
		return 0, false
	}
	return pid, true
}

// frozen remembers what the operator suspended from here: pid → the process's
// creation time, so a PID reused by another process is not shown as frozen.
// Linux can read the state back from the kernel; Windows has no cheap way to,
// so there this record is the only source.
var (
	frozenMu sync.Mutex
	frozen   = map[int32]int64{}
)

func markFrozen(pid int32, created int64, on bool) {
	frozenMu.Lock()
	defer frozenMu.Unlock()
	if on {
		frozen[pid] = created
	} else {
		delete(frozen, pid)
	}
}

// procStopped reports whether a process is frozen: stopped by a signal
// (whoever sent it), or suspended from this monitor.
func procStopped(pid int32) bool {
	p, err := process.NewProcess(pid)
	if err != nil {
		markFrozen(pid, 0, false)
		return false
	}
	if st, err := p.Status(); err == nil {
		for _, s := range st {
			if s == process.Stop {
				return true
			}
		}
		if len(st) > 0 {
			return false // the kernel says it is in some other state
		}
	}
	frozenMu.Lock()
	created, ok := frozen[pid]
	frozenMu.Unlock()
	if !ok {
		return false
	}
	if now, err := p.CreateTime(); err != nil || now != created {
		markFrozen(pid, 0, false) // the PID belongs to another process now
		return false
	}
	return true
}

// pidStopped is procStopped with a per-render cache: a process with twenty
// sockets is asked once.
func pidStopped(cache map[int32]bool, pid int32) bool {
	if pid <= 0 {
		return false
	}
	v, ok := cache[pid]
	if !ok {
		v = procStopped(pid)
		cache[pid] = v
	}
	return v
}

// handleSuspend freezes a process, or lets it go on with {"Resume":true}.
func handleSuspend(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		PID    int
		Resume bool
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	pid, ok := validTargetPID(w, body.PID)
	if !ok {
		return
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "process not found"})
		return
	}
	// The log line is the forensic record of the action.
	name, _ := p.Name()
	exe, _ := p.Exe()
	created, _ := p.CreateTime()
	verb := "SUSPEND"
	if body.Resume {
		verb = "RESUME"
		err = p.Resume()
	} else {
		err = p.Suspend()
	}
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	markFrozen(pid, created, !body.Resume)
	log.Printf("%s pid=%d name=%q exe=%q by operator", verb, body.PID, name, exe)
	writeJSON(w, map[string]any{"ok": true, "pid": body.PID, "suspended": !body.Resume})
}
