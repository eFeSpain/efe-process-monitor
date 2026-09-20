package main

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Network activity aggregated per process: how many places it talks to,
// where they are, what it asked for, and how that compares with its history.
// Every row already knew its own remote; this answers "and the process as a
// whole?" without the reader adding it up.

// ProcActivity is the summary shown in the details block.
type ProcActivity struct {
	NowConns  int      // established connections right now
	NowIPs    int      // distinct remote addresses right now
	Countries []string // from the enrichment of those addresses (public only)
	Networks  []string // ISP / provider names, deduplicated
	Listening []uint32 // ports this process listens on
	Names     []string // names its addresses were asked for as (SNI / DNS), most recent first
	DayIPs    int      // distinct public remotes in the last 24 h (events table)
	DayEvents int      // feed events in the last 24 h
	Risk      int      // recorded risk changes for this binary
	FirstSeen string   // earliest event for this binary in the retained history
	LastSeen  string   // latest
}

func (a *ProcActivity) ListeningStr() string {
	s := make([]string, len(a.Listening))
	for i, p := range a.Listening {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ", ")
}

// aggregateActivity computes the live half from what the render already has;
// the history half is filled by procActivity. Pure, for the test.
func aggregateActivity(conns []ProcConn, listening []uint32, enrich map[string]*Enrichment,
	hosts map[string][]Hostname) *ProcActivity {
	a := &ProcActivity{NowConns: len(conns)}
	ips := map[string]bool{}
	countries, networks := map[string]bool{}, map[string]bool{}
	names := map[string]string{} // name → latest "at", for ordering
	for _, c := range conns {
		if c.RemoteIP == "" || ips[c.RemoteIP] {
			continue
		}
		ips[c.RemoteIP] = true
		if e := enrich[c.RemoteIP]; e != nil {
			if e.Country != "" && e.Country != "N/A" {
				countries[e.Country] = true
			}
			switch {
			case e.Provider != "":
				networks[e.Provider] = true
			case e.ISP != "" && e.ISP != "N/A":
				networks[e.ISP] = true
			}
		}
		for _, h := range hosts[c.RemoteIP] {
			if names[h.Name] < h.At {
				names[h.Name] = h.At
			}
		}
	}
	a.NowIPs = len(ips)
	a.Countries = sortedKeys(countries)
	a.Networks = sortedKeys(networks)
	a.Listening = append([]uint32(nil), listening...)
	sort.Slice(a.Listening, func(i, j int) bool { return a.Listening[i] < a.Listening[j] })
	for n := range names {
		a.Names = append(a.Names, n)
	}
	sort.Slice(a.Names, func(i, j int) bool { return names[a.Names[i]] > names[a.Names[j]] })
	if len(a.Names) > 8 {
		a.Names = a.Names[:8]
	}
	return a
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// procActivity builds the full summary for a binary: live aggregate plus the
// last 24 h and the risk log from the database. Two queries per process per
// render, against local SQLite — cheap next to the enrichment it summarizes.
func procActivity(exe string, conns []ProcConn, listening []uint32, enrich map[string]*Enrichment,
	hosts map[string][]Hostname) *ProcActivity {
	a := aggregateActivity(conns, listening, enrich, hosts)
	if db != nil && pathKnown(exe) {
		st := dbEventStats(exe, time.Now().Add(-24*time.Hour))
		a.DayIPs, a.DayEvents, a.FirstSeen, a.LastSeen = st.ips, st.events, st.first, st.last
		a.Risk = dbScoreChangeCount(exe)
	}
	return a
}
