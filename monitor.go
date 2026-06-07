package main

import (
	"fmt"
	"math"
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

func publish(ev Event) {
	ev.TS = time.Now().Format("15:04:05")
	logEvent(ev) // forensic timeline
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
)

const (
	beaconMinSamples = 4
	beaconCVThresh   = 0.15
	beaconMinGap     = 5.0 // seconds
)

func checkBeacon(exe, remoteIP string, now float64) float64 {
	if exe == "" || remoteIP == "" {
		return 0
	}
	key := exe + "|" + remoteIP
	beaconMu.Lock()
	defer beaconMu.Unlock()
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
	out := map[connKey]gnet.ConnectionStat{}
	for _, c := range conns {
		if c.Status != "LISTEN" && c.Status != "ESTABLISHED" {
			continue
		}
		if c.Pid == ownPID { // never monitor our own API traffic
			continue
		}
		if isLoopback(c.Laddr.IP) || (c.Raddr.IP != "" && isLoopback(c.Raddr.IP)) {
			continue
		}
		k := connKey{c.Pid, fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port), c.Status}
		out[k] = c
	}
	return out
}

// alertOnIntel enriches a new public-remote connection and raises an alert
// (feed event + desktop notification) when the IP has bad reputation.
func alertOnIntel(ev Event, ip string) {
	e := enrichIP(ip) // cached
	var reasons []string
	if e.C2 {
		reasons = append(reasons, "C2 Feodo")
	}
	if e.Tor {
		reasons = append(reasons, "Tor exit")
	}
	if e.VTMalicious != nil && *e.VTMalicious > 0 {
		reasons = append(reasons, fmt.Sprintf("VT-IP %d", *e.VTMalicious))
	}
	// AbuseIPDB only counts as an alert when it's NOT a known provider (noise).
	if e.AbuseScore != nil && *e.AbuseScore >= 50 && e.Provider == "" {
		reasons = append(reasons, fmt.Sprintf("AbuseIPDB %d%%", *e.AbuseScore))
	}
	if len(reasons) == 0 {
		return
	}
	detail := strings.Join(reasons, ", ")
	publish(Event{Kind: "alert", PID: ev.PID, Process: ev.Process, Exe: ev.Exe,
		Remote: ev.Remote, Detail: detail})
	notify(strings_(currentLang())["notif_intel"],
		fmt.Sprintf("%s → %s (%s)", ev.Process, ip, detail), "intel:"+ev.Exe+ip)
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
	if c.Raddr.IP != "" {
		ev.Remote = fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
	}
	return ev
}

func monitorLoop() {
	prev := snapshot()
	knownPIDs := map[int32]bool{}
	for _, c := range prev {
		knownPIDs[c.Pid] = true
		baselineSeen(describe(c).Exe)
	}

	for {
		time.Sleep(monitorInterval)
		snap := snapshot()
		if snap == nil {
			continue
		}
		now := float64(time.Now().UnixNano()) / 1e9
		wl := whitelist()

		for k, c := range snap {
			if _, ok := prev[k]; ok {
				continue
			}
			ev := describe(c)
			remoteIP := c.Raddr.IP
			muted := wl[ev.Exe]

			switch {
			case isSuspiciousPath(ev.Exe):
				ev.Kind = "alert"
			case remoteIP != "" && !isPrivateIP(remoteIP):
				ev.Kind = "remote"
			default:
				ev.Kind = "new"
			}
			if c.Pid > 0 && !knownPIDs[c.Pid] {
				ev.NewProcess = true
			}
			if ev.Exe != "" && !baselineSeen(ev.Exe) {
				ev.Anomaly = true
			}
			if remoteIP != "" && !isPrivateIP(remoteIP) {
				if period := checkBeacon(ev.Exe, remoteIP, now); period > 0 {
					ev.Beacon = math.Round(period*10) / 10
					ev.Kind = "alert"
					ev.Detail = fmt.Sprintf("beaconing ~%.0fs → %s", period, remoteIP)
				}
			}
			publish(ev)

			// Background threat-intel check on new public connections → alert on
			// bad reputation (AbuseIPDB high, VT-IP, C2, Tor). Cached, so cheap.
			if remoteIP != "" && !isPrivateIP(remoteIP) && !muted {
				go alertOnIntel(ev, remoteIP)
			}

			if !muted {
				T := strings_(currentLang())
				switch {
				case ev.Beacon > 0:
					notify(T["notif_c2"],
						fmt.Sprintf("%s → %s %s ~%.0fs", ev.Process, remoteIP, T["notif_every"], ev.Beacon),
						"beacon:"+ev.Exe+remoteIP)
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

		for k, c := range prev {
			if _, ok := snap[k]; !ok {
				ev := describe(c)
				ev.Kind = "closed"
				publish(ev)
			}
		}

		prev = snap
		for _, c := range snap {
			knownPIDs[c.Pid] = true
		}
	}
}
