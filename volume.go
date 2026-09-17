package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Data-volume signal: how much is this process actually moving?
//
// The process I/O counters were already being read and displayed, but never used
// for anything. A sustained outbound flow from a process that has no business
// producing one is the classic exfiltration shape, and it is the one part of that
// picture the tool was collecting and throwing away.
//
// What the numbers actually are — this matters, because it bounds what may be
// claimed from them:
//
//   - Linux: ReadBytes/WriteBytes are rchar/wchar, i.e. every byte through a
//     read()/write() syscall, sockets included. DiskReadBytes/DiskWriteBytes are
//     the block-device totals. Subtracting the second from the first isolates
//     non-disk traffic, which is a reasonable proxy for network egress (pipes and
//     ttys also land there, so it is a proxy, not a measurement).
//   - Windows: GetProcessIoCounters lumps file, network and device I/O into one
//     pair of totals with no way to separate them. The signal is genuinely weaker
//     here and the UI says so.
//
// Neither platform attributes bytes to a particular connection, so this is
// per-process and cannot prove *where* the data went.
//
// Consequence for scoring: volume on its own scores nothing. A browser download,
// a game update, a backup and a video call all move a lot of data, and weighting
// that would repeat the mistake the path and port signals used to make. It scores
// only when it coincides with an independent reason to distrust the binary — a
// staging-directory path, an anomalous spawn chain, or a malware port — because
// "this odd binary is also streaming data out" is a different claim from "this
// binary is busy".

const (
	// highEgressBytesPerSec is what counts as a notable outbound rate. Low on
	// purpose: real exfiltration is often slow and steady to stay unremarkable,
	// and since this never scores alone a generous threshold costs nothing.
	highEgressBytesPerSec = 256 << 10 // 256 KiB/s

	// egressHotSamples is how many consecutive samples must exceed the threshold.
	// One spike is a page load; sustained is a transfer.
	egressHotSamples = 2

	// ioSampleTTL drops tracking state for processes that stopped showing up.
	ioSampleTTL = 10 * time.Minute

	// cpuHotPercent / cpuHotSamples define "sustained CPU": at least this share
	// of the whole machine for this many consecutive samples (15 s at the
	// monitor's 3 s cadence). Like egress, it is informational on its own —
	// a compiler, a game and a video encoder all look like this — and scores
	// only from a binary that is already suspect, which is the miner shape.
	cpuHotPercent = 50.0
	cpuHotSamples = 5
)

// ioRate is the current traffic and resource picture for one process.
type ioRate struct {
	In, Out    float64 // bytes/sec, averaged over the last sample interval
	HighEgress bool    // Out has been over the threshold for egressHotSamples in a row

	// Resource usage, read in the same pass (see procResources). Informational
	// only: none of it scores, for the same reason volume does not — a compiler,
	// a game and a video call all burn CPU and memory.
	CPU     float64 // percent of the whole machine (100 = every core busy), last interval
	HighCPU bool    // CPU has been over cpuHotPercent for cpuHotSamples in a row
	RSS     uint64  // resident set in bytes (Windows: working set, shared pages included)
	Threads int32
	User    string // owning account, resolved once per PID
	ResOK   bool   // CPU/RSS were readable for this process
}

type ioSample struct {
	at        time.Time
	in, out   uint64  // cumulative counters at `at`
	cpu       float64 // cumulative CPU seconds (user+system) at `at`
	rate      ioRate
	hot       int // consecutive samples over the egress threshold
	cpuHot    int // consecutive samples over the CPU threshold
	lastSeen  time.Time
	haveFirst bool
	userDone  bool // Username was attempted; it can legitimately fail for other users' processes
}

// numCPU normalizes the CPU figure so 100 % means the whole machine, the way the
// Windows Task Manager shows it (top/htop count per core and can exceed 100). A
// variable rather than a call so the arithmetic is testable with a fixed count.
var numCPU = runtime.NumCPU()

var (
	ioMu      sync.Mutex
	ioSamples = map[int32]*ioSample{}
)

// advance folds a fresh pair of cumulative counters into the sample and updates
// the derived rate. Pure arithmetic on the struct, so the interesting cases —
// first sample, counter reset, the sustained-vs-spike distinction — are testable
// without a live process.
func (s *ioSample) advance(now time.Time, in, out uint64, cpu float64) {
	defer func() { s.at, s.in, s.out, s.cpu, s.haveFirst, s.lastSeen = now, in, out, cpu, true, now }()

	if !s.haveFirst {
		return // one reading is not a rate
	}
	secs := now.Sub(s.at).Seconds()
	if secs <= 0 {
		return
	}
	// The counters are monotonic per process, so a decrease means this PID is a
	// different process now (PID reuse). Start over instead of reporting a
	// nonsensical rate from the difference of two unrelated processes. CPU time
	// is monotonic too, and it also identifies the owner as stale.
	if in < s.in || out < s.out || cpu < s.cpu {
		s.rate, s.hot, s.cpuHot, s.userDone = ioRate{}, 0, 0, false
		return
	}
	s.rate.In = float64(in-s.in) / secs
	s.rate.Out = float64(out-s.out) / secs
	if s.rate.Out >= highEgressBytesPerSec {
		s.hot++
	} else {
		s.hot = 0
	}
	s.rate.HighEgress = s.hot >= egressHotSamples

	// CPU seconds consumed per wall-clock second, spread over the cores. Clamped:
	// the two clocks are read at slightly different instants, so a process that
	// is genuinely pegging every core can compute to a hair over 100.
	s.rate.CPU = (cpu - s.cpu) / secs * 100 / float64(max(numCPU, 1))
	if s.rate.CPU > 100 {
		s.rate.CPU = 100
	}
	if s.rate.CPU >= cpuHotPercent {
		s.cpuHot++
	} else {
		s.cpuHot = 0
	}
	s.rate.HighCPU = s.cpuHot >= cpuHotSamples
}

// procEgressBytes returns the cumulative (inbound, outbound) byte counters used
// for the rate calculation, and whether they mean anything on this platform.
func procEgressBytes(p *process.Process) (in, out uint64, ok bool) {
	c, err := p.IOCounters()
	if err != nil || c == nil {
		return 0, 0, false
	}
	if runtime.GOOS == "linux" {
		// Subtract block-device I/O to leave (mostly) socket traffic. Guard the
		// subtraction: the two figures come from different lines of /proc and a
		// counter reset would otherwise underflow into a huge number.
		in, out = c.ReadBytes, c.WriteBytes
		if c.DiskReadBytes <= in {
			in -= c.DiskReadBytes
		}
		if c.DiskWriteBytes <= out {
			out -= c.DiskWriteBytes
		}
		return in, out, true
	}
	// Windows and the rest: total I/O, network not separable.
	return c.ReadBytes, c.WriteBytes, true
}

// procResources reads the cumulative CPU time and the current memory picture.
// Times() is /proc/<pid>/stat on Linux and GetProcessTimes on Windows; MemoryInfo
// is statm / the working set. Cheap, cgo-free calls on both platforms.
func procResources(p *process.Process) (cpuSecs float64, rss uint64, threads int32, ok bool) {
	t, err := p.Times()
	if err != nil || t == nil {
		return 0, 0, 0, false
	}
	cpuSecs = t.User + t.System
	if m, err := p.MemoryInfo(); err == nil && m != nil {
		rss = m.RSS
	}
	if n, err := p.NumThreads(); err == nil {
		threads = n
	}
	return cpuSecs, rss, threads, true
}

// sampleProcessIO refreshes the rate and resource figures for every process in
// the current snapshot. Called once per monitor cycle, so only processes that
// hold a socket are polled.
func sampleProcessIO(snap map[connKey]gnet.ConnectionStat) {
	now := time.Now()
	pids := map[int32]bool{}
	for _, c := range snap {
		if c.Pid > 0 {
			pids[c.Pid] = true
		}
	}

	for pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		in, out, ioOK := procEgressBytes(p)
		cpu, rss, threads, resOK := procResources(p)
		if !ioOK && !resOK {
			continue
		}

		ioMu.Lock()
		s := ioSamples[pid]
		if s == nil {
			s = &ioSample{}
			ioSamples[pid] = s
		}
		needUser := resOK && !s.userDone
		ioMu.Unlock()

		// The account lookup can touch the user database (Linux) or open the
		// process token (Windows); it is done once per PID and outside the lock.
		user := ""
		if needUser {
			user, _ = p.Username()
		}

		ioMu.Lock()
		s.advance(now, in, out, cpu)
		s.rate.RSS, s.rate.Threads, s.rate.ResOK = rss, threads, resOK
		if needUser && !s.userDone { // advance may have reset on PID reuse; then retry next cycle
			s.rate.User, s.userDone = user, true
		}
		ioMu.Unlock()
	}

	ioMu.Lock()
	for pid, s := range ioSamples {
		if now.Sub(s.lastSeen) > ioSampleTTL {
			delete(ioSamples, pid)
		}
	}
	ioMu.Unlock()
}

// rateFor returns the last computed rate for a process.
func rateFor(pid int32) ioRate {
	ioMu.Lock()
	defer ioMu.Unlock()
	if s := ioSamples[pid]; s != nil {
		return s.rate
	}
	return ioRate{}
}

// humanRate formats a bytes-per-second figure for display and for the score
// breakdown.
func humanRate(bps float64) string {
	f := bps
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 {
			return fmt.Sprintf("%.0f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f TB", f)
}
