package main

import (
	"fmt"
	"log"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

const monitorInterval = 3 * time.Second

// Event is a single change detected by the live monitor.
type Event struct {
	TS         string  `json:"ts"`
	Kind       string  `json:"kind"`
	PID        int32   `json:"pid"`
	Process    string  `json:"process"`
	Exe        string  `json:"exe,omitempty"`
	Local      string  `json:"local,omitempty"`
	Remote     string  `json:"remote,omitempty"`
	NewProcess bool    `json:"new_process,omitempty"`
	Anomaly    bool    `json:"anomaly,omitempty"`
	Beacon     float64 `json:"beacon,omitempty"`
	Changed    bool    `json:"changed,omitempty"` // known path, different content: replaced on disk
	Level      string  `json:"level,omitempty"`   // alert severity: "low" | "med" | "high" (see intelAlert)
	Inbound    bool    `json:"inbound,omitempty"` // brief inbound connection: the feed draws the arrow the other way (not stored)
	Detail     string  `json:"detail,omitempty"`
}

// ── Pub/sub for SSE clients ──────────────────────────────────────────────────

var (
	subsMu sync.Mutex
	subs   = map[chan Event]bool{}
)

func subscribe() chan Event {
	ch := make(chan Event, 64)
	subsMu.Lock()
	subs[ch] = true
	subsMu.Unlock()
	return ch
}

func unsubscribe(ch chan Event) {
	subsMu.Lock()
	delete(subs, ch)
	close(ch)
	subsMu.Unlock()
}

// publish records an event in the forensic history and pushes it to the SSE
// clients.
func publish(ev Event) {
	ev.TS = time.Now().Format("15:04:05")
	logEvent(ev) // forensic timeline
	broadcast(ev)
}

// broadcast pushes an event to the SSE clients without recording it: for UI
// nudges such as "a background lookup landed, redraw", which are not events
// that happened on the machine and have no place in the history.
func broadcast(ev Event) {
	if ev.TS == "" {
		ev.TS = time.Now().Format("15:04:05")
	}
	subsMu.Lock()
	for ch := range subs {
		select {
		case ch <- ev:
		default: // drop if the client is slow
		}
	}
	subsMu.Unlock()
}

// ── Beaconing detection ──────────────────────────────────────────────────────

var (
	beaconMu    sync.Mutex
	beaconTrack = map[string][]float64{}
	// beaconTold is when the alert for an exe|IP pair was last raised: a
	// beacon is news once, and while it goes on, once every beaconRepeat.
	beaconTold = map[string]float64{}
	// beaconPruned is when the table was last swept.
	beaconPruned float64
)

const (
	beaconMinSamples = 4
	beaconCVThresh   = 0.15
	beaconMinGap     = 5.0 // seconds
	// beaconIdle drops tracking state for an exe+IP pair that has been quiet for
	// this long. Without it the map keeps an entry for every pair ever seen.
	beaconIdle = 2 * time.Hour
	// beaconRepeat is how long a pair already alerted stays quiet. Raised at
	// every sample it was a notification a minute for an editor phoning home.
	beaconRepeat = time.Hour
	// beaconSweep is how often the table is swept. On every sample the sweep
	// was quadratic, and brief connections feed samples in volume.
	beaconSweep = time.Minute
)

// pruneBeacons forgets idle exe|IP pairs. Caller holds beaconMu.
func pruneBeacons(now float64) {
	if beaconPruned != 0 && now >= beaconPruned && now-beaconPruned < beaconSweep.Seconds() {
		return
	}
	beaconPruned = now
	for k, ts := range beaconTrack {
		if len(ts) == 0 || now-ts[len(ts)-1] > beaconIdle.Seconds() {
			delete(beaconTrack, k)
		}
	}
	for k, at := range beaconTold {
		if now-at > beaconIdle.Seconds() {
			delete(beaconTold, k)
		}
	}
}

// beaconNews reports whether a beacon from exe to remoteIP is to be alerted
// now: the first time, and then once every beaconRepeat while it goes on.
func beaconNews(exe, remoteIP string, now float64) bool {
	key := exe + "|" + remoteIP
	beaconMu.Lock()
	defer beaconMu.Unlock()
	if at, ok := beaconTold[key]; ok && now >= at && now-at < beaconRepeat.Seconds() {
		return false
	}
	beaconTold[key] = now
	return true
}

func checkBeacon(exe, remoteIP string, now float64) float64 {
	if exe == "" || remoteIP == "" {
		return 0
	}
	key := exe + "|" + remoteIP
	beaconMu.Lock()
	defer beaconMu.Unlock()
	pruneBeacons(now)
	ts := append(beaconTrack[key], now)
	if len(ts) > 8 {
		ts = ts[len(ts)-8:]
	}
	beaconTrack[key] = ts
	if len(ts) < beaconMinSamples {
		return 0
	}
	var gaps []float64
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i]-ts[i-1])
	}
	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean < beaconMinGap {
		return 0
	}
	varc := 0.0
	for _, g := range gaps {
		varc += (g - mean) * (g - mean)
	}
	varc /= float64(len(gaps))
	if math.Sqrt(varc)/mean < beaconCVThresh {
		return mean
	}
	return 0
}

// ── Snapshot + monitor loop ──────────────────────────────────────────────────

type connKey struct {
	pid                  int32
	laddr, raddr, status string
}

func snapshot() map[connKey]gnet.ConnectionStat {
	conns, err := gnet.Connections("inet")
	if err != nil {
		return nil
	}
	return snapshotOf(conns)
}

// snapshotOf keeps the sockets the live monitor follows.
func snapshotOf(conns []gnet.ConnectionStat) map[connKey]gnet.ConnectionStat {
	out := map[connKey]gnet.ConnectionStat{}
	for _, c := range conns {
		if !trackConn(c) {
			continue
		}
		// A UDP socket with no peer is usually an ephemeral bind — every DNS
		// query opens and closes one — so tracking them here would flood the feed
		// and the history with noise. Connected UDP (QUIC, UDP C2) is tracked.
		if isUDP(c) && !hasPeer(c) {
			continue
		}
		if c.Pid == ownPID || ownChild(c.Pid) { // never monitor our own API traffic, nor our own subprocesses
			continue
		}
		if isLoopback(c.Laddr.IP) || (c.Raddr.IP != "" && isLoopback(c.Raddr.IP)) {
			continue
		}
		k := connKey{c.Pid, fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port), connStatus(c)}
		out[k] = c
	}
	return out
}

// intelAlert grades the reputation of an address for the live feed. The grade
// is not the score: it decides how loud the feed is. A single VirusTotal
// engine flagging an address is noise — it happens all day on big providers'
// ranges (Chrome talking to claude.ai raised a red alert over one engine) —
// so VT alone is graded by count: 1 → low, 2 → med, 3+ → high. A curated
// feed hit (Feodo, ThreatFox, URLhaus, Spamhaus), a Tor exit or a high
// AbuseIPDB confidence on an address that is not a known provider is high
// outright. Only "high" reaches the desktop notification.
func intelAlert(e *Enrichment) (reasons []string, level string) {
	raise := func(l string) {
		rank := map[string]int{"": 0, "low": 1, "med": 2, "high": 3}
		if rank[l] > rank[level] {
			level = l
		}
	}
	if e.C2 {
		reasons = append(reasons, "C2 Feodo")
		raise("high")
	}
	if e.ThreatFox != "" {
		reasons = append(reasons, "ThreatFox: "+e.ThreatFox)
		raise("high")
	}
	if e.URLhaus != "" {
		reasons = append(reasons, "URLhaus: "+e.URLhaus)
		raise("high")
	}
	if e.Spamhaus {
		reasons = append(reasons, "Spamhaus DROP")
		raise("high")
	}
	if e.Tor {
		reasons = append(reasons, "Tor exit")
		raise("high")
	}
	if e.VTMalicious != nil && *e.VTMalicious > 0 {
		reasons = append(reasons, fmt.Sprintf("VirusTotal ×%d", *e.VTMalicious))
		switch n := *e.VTMalicious; {
		case n >= 3:
			raise("high")
		case n == 2:
			raise("med")
		default:
			raise("low")
		}
	}
	// AbuseIPDB only counts when it's NOT a known provider (noise).
	if e.AbuseScore != nil && *e.AbuseScore >= 50 && e.Provider == "" {
		reasons = append(reasons, fmt.Sprintf("AbuseIPDB %d%%", *e.AbuseScore))
		raise("high")
	}
	return reasons, level
}

// alertOnIntel enriches a new public-remote connection and raises a graded
// alert in the feed; the desktop notification only for the high grade.
func alertOnIntel(ev Event, ip string) {
	e := enrichIP(ip) // cached
	reasons, level := intelAlert(e)
	// The name the process asked for (SNI / passive DNS) against the C2
	// domains: more specific than the address on shared hosting.
	if name, label := iocNameHit(dbHostnames(ip)); name != "" {
		reasons, level = append(reasons, "ThreatFox: "+label+" ("+name+")"), "high"
	}
	if len(reasons) == 0 {
		return
	}
	detail := strings.Join(reasons, ", ")
	publish(Event{Kind: "alert", Level: level, PID: ev.PID, Process: ev.Process, Exe: ev.Exe,
		Remote: ev.Remote, Detail: detail})
	if level == "high" {
		notify(strings_(currentLang())["notif_intel"],
			fmt.Sprintf("%s → %s (%s)", ev.Process, ip, detail), "intel:"+ev.Exe+ip)
	}
}

func describe(c gnet.ConnectionStat) Event {
	name, exe := "N/A", ""
	if c.Pid > 0 {
		if p, err := process.NewProcess(c.Pid); err == nil {
			if n, e := p.Name(); e == nil {
				name = n
			}
			if e, err := p.Exe(); err == nil {
				exe = e
			}
		}
	}
	ev := Event{PID: c.Pid, Process: name, Exe: exe}
	if c.Laddr.IP != "" {
		ev.Local = fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
	}
	if hasPeer(c) {
		ev.Remote = fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
	}
	return ev
}

// knownPIDTTL is how long a PID stays "known" after we last saw it holding a
// connection. It bounds the map (which previously kept every PID ever seen for
// the life of the process) while still avoiding a bogus "new process" tag for
// something that merely reconnects a moment later.
const knownPIDTTL = time.Hour

// connSighting is a connection the monitor has just learned about, from
// either source: the poll, or the kernel's records of the ones the poll
// missed (shortconn.go).
type connSighting struct {
	ev       Event  // Kind and Detail preset for a brief connection; empty for a polled one
	remoteIP string // "" when there is no peer
	newProc  bool   // first time this PID is seen
	muted    bool   // whitelisted binary: recorded, never notified
	quiet    bool   // a grouped repeat of a brief connection: published only if a check fires
	fresh    bool   // quiet, but the first of this window to that address: its reputation is still looked up
}

// announceConn runs the checks every new connection gets — where it runs
// from, whether the binary is new or was replaced, beaconing, reputation —
// and publishes it. Both sources come through here, so they cannot drift.
//
// A brief connection keeps its kind ("short") unless a check turns it into
// an alert; the alert's reason is then followed by the brief wording.
func announceConn(s connSighting, nowSec float64) {
	ev := s.ev
	T := strings_(currentLang())
	brief, base := ev.Kind == "short", ev.Detail
	// loud: news about the binary or its behaviour (replaced on disk,
	// beaconing), shown even for a grouped repeat. Where it runs from is
	// not: every connection of such a binary would be shown.
	loud, beaconAlert := false, false
	alert := func(reason string) {
		ev.Kind, ev.Detail = "alert", reason
		if brief {
			ev.Detail = reason + " · " + base
		}
	}
	public := s.remoteIP != "" && !isPrivateIP(s.remoteIP)

	switch {
	case isSuspiciousPath(ev.Exe):
		if brief {
			alert(T["ev_suspicious"])
		} else {
			ev.Kind = "alert" // no detail: the feed words it itself
		}
	case brief:
	case public:
		ev.Kind = "remote"
	default:
		ev.Kind = "new"
	}
	ev.NewProcess = s.newProc
	if ev.Exe != "" {
		if seen, changed := baselineSeen(ev.Exe, fileHash(ev.Exe)); !seen {
			ev.Anomaly = true
			if changed {
				// Same path, different bytes: the binary was replaced.
				// That is what an in-place trojanization looks like, so
				// it goes to the feed as an alert with the reason.
				ev.Changed = true
				loud = true
				alert(T["ev_binchanged"])
			}
		}
	}
	// Beaconing is this machine calling out at regular intervals; someone
	// connecting in every minute is a monitoring probe, not that.
	if public && !ev.Inbound {
		who := ev.Exe
		if who == "" && brief {
			who = "comm:" + ev.Process // the process was gone before its path could be read
		}
		if period := checkBeacon(who, s.remoteIP, nowSec); period > 0 {
			ev.Beacon = math.Round(period*10) / 10
			if beaconNews(who, s.remoteIP, nowSec) {
				loud, beaconAlert = true, true
				alert(fmt.Sprintf("beaconing ~%.0fs → %s", period, s.remoteIP))
			}
		}
	}
	if s.quiet && !loud {
		// Counted by the grouper; its summary will say how many. Nothing is
		// shown — but an address not seen in this window is still looked up:
		// twenty harmless connections must not hide the one to a listed C2.
		if s.fresh && public && !s.muted {
			startIntelCheck(ev, s.remoteIP)
		}
		return
	}
	publish(ev)

	// Background threat-intel check on new public connections → alert on
	// bad reputation (AbuseIPDB high, VT-IP, C2, Tor). Cached, so cheap.
	if public && !s.muted {
		startIntelCheck(ev, s.remoteIP)
	}

	if !s.muted {
		switch {
		case beaconAlert:
			notify(T["notif_c2"],
				fmt.Sprintf("%s → %s %s ~%.0fs", ev.Process, s.remoteIP, T["notif_every"], ev.Beacon),
				"beacon:"+ev.Exe+s.remoteIP)
		case ev.Changed:
			notify(T["notif_binchanged"],
				fmt.Sprintf("%s (%d) — %s", ev.Process, ev.PID, ev.Exe), "changed:"+ev.Exe)
		case ev.Kind == "alert":
			notify(T["notif_susp"],
				fmt.Sprintf("%s (%d) → %s", ev.Process, ev.PID, ev.Remote),
				"susp:"+ev.Exe)
		case ev.Anomaly:
			notify(T["notif_newbin"],
				fmt.Sprintf("%s (%d)", ev.Process, ev.PID), "anom:"+ev.Exe)
		}
	}
}

// startIntelCheck runs the reputation check of a new public connection in
// the background; it publishes an alert only on a hit. A variable so tests
// can announce an unmuted connection without touching the network.
var startIntelCheck = func(ev Event, ip string) { go alertOnIntel(ev, ip) }

// briefSighting is a brief connection as an event, checks not yet applied.
func briefSighting(c briefConn, T map[string]string) connSighting {
	return connSighting{
		ev: Event{Kind: "short", PID: c.PID, Process: c.Name, Exe: c.Exe, Inbound: c.Inbound,
			Local: hostPort(c.Local), Remote: hostPort(c.Remote), Detail: briefDetail(T, c)},
		remoteIP: c.Remote.Addr().String(),
	}
}

// hostPort writes an endpoint the way the poll's events do — "addr:port",
// no brackets around IPv6 — so both kinds read and search alike.
func hostPort(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return ""
	}
	return fmt.Sprintf("%s:%d", ap.Addr(), ap.Port())
}

// announceBrief is what the loop does with a brief connection: the grouper
// decides whether it gets a line of its own, and its PID becomes known.
func announceBrief(c briefConn, g *shortGrouper, knownPIDs map[int32]time.Time, wl map[string]bool, now time.Time) {
	s := briefSighting(c, strings_(currentLang()))
	s.newProc = c.PID > 0 && knownPIDs[c.PID].IsZero()
	s.muted = wl[c.Exe]
	publish, fresh := g.add(c, now)
	s.quiet, s.fresh = !publish, fresh
	if c.PID > 0 {
		knownPIDs[c.PID] = now
	}
	announceConn(s, float64(now.UnixNano())/1e9)
}

// publishShortSummary says how many brief connections were counted in
// silence: repeats of one group, or a process's overflow past its cap.
func publishShortSummary(s shortSummary) {
	ev := Event{Kind: "short", PID: s.Sample.PID, Process: s.Sample.Name, Exe: s.Sample.Exe, Inbound: s.Sample.Inbound,
		Detail: summaryDetail(strings_(currentLang()), s)}
	if !s.PerProc {
		ev.Remote = s.Sample.Remote.Addr().String()
	}
	publish(ev)
}

// afterRecv is what the loop does with its record channel after a receive:
// keep it, or — had it been closed — stop selecting on it. A closed channel
// is always ready; left in the select it would spin.
func afterRecv(ch <-chan kernelRecord, ok bool) <-chan kernelRecord {
	if !ok {
		return nil
	}
	return ch
}

// monitorLoop is the live monitor. Two sources feed it: the poll of the
// socket table every monitorInterval, and — when the kernel source is
// running (records non-nil) — a record for every TCP connection as it
// happens, from which it learns about the ones too brief for the poll.
// Everything here runs on this one goroutine.
func monitorLoop(records <-chan kernelRecord, volume bool) {
	prev := snapshot()
	for prev == nil {
		// A failed first enumeration must not stand in for "nothing was open":
		// the next good one would then announce every existing connection as
		// new, with the desktop notifications to match.
		time.Sleep(monitorInterval)
		prev = snapshot()
	}
	knownPIDs := map[int32]time.Time{}
	seen := time.Now()
	for _, c := range prev {
		knownPIDs[c.Pid] = seen
		if exe := describe(c).Exe; exe != "" {
			baselineSeen(exe, fileHash(exe))
		}
	}
	lastPrune := time.Now()
	// Listening ports: on the very first run whatever is already listening is
	// the baseline; from then on anything not in it is news — including what
	// started listening while the monitor was not running (newlisten.go).
	listeners := newListenWatch()
	seedListeners := listeners.empty()
	// Brief connections (shortconn.go).
	tracker := newShortTracker(procNameExe, volume)
	grouper := newShortGrouper()
	lastDropLog := time.Now()

	// poll is one pass over the socket table.
	poll := func() {
		conns, err := gnet.Connections("inet")
		if err != nil {
			return
		}
		snap := snapshotOf(conns)
		if time.Since(lastPrune) > 24*time.Hour {
			lastPrune = time.Now()
			pruneEvents()
		}
		// Refresh the per-process traffic rates. Only processes holding a socket
		// are polled, which is exactly the set in the snapshot.
		sampleProcessIO(snap)
		now := float64(time.Now().UnixNano()) / 1e9
		wl := whitelist()
		// Spawn chain, credential access, anomalous executable memory: alerted
		// here, not only scored when someone renders the table (localsignals.go).
		checkLocalSignals(snap, wl, time.Now())
		announceListeners(listeners.fresh(listenersOf(conns), procNameExe, seedListeners), wl)
		seedListeners = false

		for k, c := range snap {
			if _, ok := prev[k]; ok {
				continue
			}
			ev := describe(c)
			announceConn(connSighting{ev: ev, remoteIP: c.Raddr.IP,
				newProc: c.Pid > 0 && knownPIDs[c.Pid].IsZero(), muted: wl[ev.Exe]}, now)
		}

		for k, c := range prev {
			if _, ok := snap[k]; !ok {
				ev := describe(c)
				ev.Kind = "closed"
				publish(ev)
			}
		}

		prev = snap
		now2 := time.Now()
		for _, c := range snap {
			knownPIDs[c.Pid] = now2
		}
		for pid, at := range knownPIDs {
			if now2.Sub(at) > knownPIDTTL {
				delete(knownPIDs, pid)
			}
		}

		// What the poll can see is no longer the tracker's; what the grouper
		// counted in silence gets its one line when its window closes.
		tracker.polled(conns, now2)
		for _, s := range grouper.flush(now2) {
			publishShortSummary(s)
		}
		if now2.Sub(lastDropLog) >= time.Minute {
			lastDropLog = now2
			if n := tracker.dropped(); n > 0 {
				log.Printf("[short] %d connections outside the poll's view (another network namespace) were not shown as brief", n)
			}
		}
	}

	timer := time.NewTimer(monitorInterval)
	for {
		select {
		case r, ok := <-records:
			if records = afterRecv(records, ok); records == nil {
				continue
			}
			if c, isBrief := tracker.record(r, time.Now()); isBrief {
				announceBrief(c, grouper, knownPIDs, whitelist(), time.Now())
			}
		case <-timer.C:
			poll()
			timer.Reset(monitorInterval) // three seconds after the pass ends, as before
		}
	}
}
