package main

import (
	"strings"
	"testing"
	"time"
)

func TestAggregateActivity(t *testing.T) {
	conns := []ProcConn{
		{"192.168.1.15", 50000, "142.250.1.1", 443},
		{"192.168.1.15", 50001, "142.250.1.1", 443}, // same host, second port: one destination
		{"192.168.1.15", 50002, "51.195.216.106", 443},
		{"192.168.1.15", 50003, "192.168.1.126", 22}, // private: counted, not enriched
	}
	enrich := map[string]*Enrichment{
		"142.250.1.1":    {Country: "United States", ISP: "Google LLC", Provider: "Google"},
		"51.195.216.106": {Country: "United Kingdom", ISP: "OVH SAS"},
	}
	hosts := map[string][]Hostname{
		"142.250.1.1":    {{Name: "www.google.com", At: "2026-09-20 10:00:00"}, {Name: "ssl.gstatic.com", At: "2026-09-20 11:00:00"}},
		"51.195.216.106": {{Name: "vps.example.net", At: "2026-09-20 09:00:00"}},
	}
	a := aggregateActivity(conns, []uint32{5000, 22, 5000}, enrich, hosts)
	if a.NowConns != 4 || a.NowIPs != 3 {
		t.Errorf("conns=%d ips=%d", a.NowConns, a.NowIPs)
	}
	if strings.Join(a.Countries, ",") != "United Kingdom,United States" {
		t.Errorf("countries = %v", a.Countries)
	}
	if strings.Join(a.Networks, ",") != "Google,OVH SAS" { // provider name wins over the raw ISP
		t.Errorf("networks = %v", a.Networks)
	}
	if a.ListeningStr() != "22, 5000, 5000" {
		t.Errorf("listening = %q", a.ListeningStr())
	}
	if strings.Join(a.Names, ",") != "ssl.gstatic.com,www.google.com,vps.example.net" { // most recent first
		t.Errorf("names = %v", a.Names)
	}
}

func TestEventStats(t *testing.T) {
	setupTestDB(t)
	exe := "/opt/agent"
	old := Event{Kind: "remote", Process: "agent", Exe: exe, Remote: "1.1.1.1:443"}
	for _, r := range []string{"8.8.8.8:443", "8.8.8.8:853", "9.9.9.9:443", "192.168.1.5:22", ""} {
		e := old
		e.Remote = r
		e.TS = "12:00:00"
		logEvent(e)
	}
	// One event from long ago, outside the 24 h window but inside the history.
	db.Exec("INSERT INTO events (epoch, ts, kind, pid, process, exe, local, remote, detail) VALUES (?,?,?,?,?,?,?,?,?)",
		float64(time.Now().Add(-72*time.Hour).Unix()), "old", "remote", 1, "agent", exe, "", "1.1.1.1:443", "")
	st := dbEventStats(exe, time.Now().Add(-24*time.Hour))
	if st.events != 4 || st.ips != 2 { // the empty remote is not an event with a destination; 8.8.8.8 twice is one
		t.Errorf("stats = %+v", st)
	}
	if st.first != "old" || st.last != "12:00:00" {
		t.Errorf("bounds = %q → %q", st.first, st.last)
	}
	if dbScoreChangeCount(exe) != 0 {
		t.Error("no risk changes recorded yet")
	}
	dbSaveScoreChange(exe, "8.8.8.8", 40, "path_staging/25")
	if dbScoreChangeCount(exe) != 1 {
		t.Error("one risk change expected")
	}
}
