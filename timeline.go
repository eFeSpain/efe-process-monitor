package main

import (
	"net"
	"sort"
	"strings"
)

// Unified timeline: one record per (binary, remote address) pair.
//
// The history modal, the risk timeline and the hostnames table each answer one
// question. An incident is the join of all three — "this binary talked to this
// address, which it asked for by this name, and here is how its risk moved and
// what the monitor saw" — and that join used to be the reader's job across
// three exports. This builds it once, for /export/timeline.json.

type timelineEntry struct {
	Exe         string        `json:"exe"`
	IP          string        `json:"ip"`
	Process     string        `json:"process,omitempty"`
	FirstSeen   string        `json:"first_seen,omitempty"`
	LastSeen    string        `json:"last_seen,omitempty"`
	Threat      int           `json:"threat"`              // latest recorded score
	Breakdown   string        `json:"breakdown,omitempty"` // latest, rendered in the reader's language
	Hostnames   []Hostname    `json:"hostnames,omitempty"` // names the address was asked for as
	Scores      []ScoreChange `json:"scores,omitempty"`    // every change, newest first
	Events      []Event       `json:"events,omitempty"`    // newest first
	Blocked     bool          `json:"blocked"`
	Whitelisted bool          `json:"whitelisted"` // the binary or the address
}

// buildTimeline joins the three histories. Pure: the handler feeds it the
// tables, the test feeds it fixtures. Events carry "ip:port" remotes; the pair
// key is the bare address, so every port to the same host lands in one entry.
func buildTimeline(lang string, events []Event, scores []ScoreChange, hosts map[string][]Hostname,
	blocked, wlExe, wlIP map[string]bool) []timelineEntry {
	type key struct{ exe, ip string }
	byKey := map[key]*timelineEntry{}
	get := func(exe, ip string) *timelineEntry {
		k := key{exe, ip}
		e := byKey[k]
		if e == nil {
			e = &timelineEntry{Exe: exe, IP: ip, Hostnames: hosts[ip],
				Blocked: blocked[ip], Whitelisted: wlExe[exe] || wlIP[ip]}
			byKey[k] = e
		}
		return e
	}
	for _, s := range scores {
		e := get(s.Exe, s.IP)
		s.Breakdown = localizeBreakdown(lang, s.Breakdown)
		if len(e.Scores) == 0 { // input is newest first
			e.Threat, e.Breakdown = s.Threat, s.Breakdown
		}
		e.Scores = append(e.Scores, s)
	}
	for _, ev := range events {
		ip := remoteHost(ev.Remote)
		if ev.Exe == "" || ip == "" || isPrivateIP(ip) {
			continue // local traffic has no reputation to trend, same rule as the score log
		}
		e := get(ev.Exe, ip)
		if e.Process == "" {
			e.Process = ev.Process
		}
		e.Events = append(e.Events, ev)
	}
	out := make([]timelineEntry, 0, len(byKey))
	for _, e := range byKey {
		// Events are newest first, so the ends are the bounds; a pair known
		// only from a score change takes its bounds from that.
		if n := len(e.Events); n > 0 {
			e.LastSeen, e.FirstSeen = e.Events[0].TS, e.Events[n-1].TS
		} else if n := len(e.Scores); n > 0 {
			e.LastSeen, e.FirstSeen = e.Scores[0].At, e.Scores[n-1].At
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Threat != out[j].Threat {
			return out[i].Threat > out[j].Threat
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	return out
}

// remoteHost strips the port from an event's "ip:port" remote.
func remoteHost(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return strings.Trim(h, "[]")
	}
	return remote
}
