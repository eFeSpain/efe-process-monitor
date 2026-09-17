package main

import (
	"encoding/json"
	"testing"
)

func TestBuildTimeline(t *testing.T) {
	events := []Event{ // newest first, as queryEvents returns them
		{TS: "12:00:05", Kind: "closed", PID: 7, Process: "svc.exe", Exe: `C:\\Temp\\svc.exe`, Remote: "45.9.148.20:443"},
		{TS: "12:00:02", Kind: "remote", PID: 7, Process: "svc.exe", Exe: `C:\\Temp\\svc.exe`, Remote: "45.9.148.20:8443"},
		{TS: "12:00:01", Kind: "new", PID: 8, Process: "sshd", Exe: "/usr/sbin/sshd", Remote: "192.168.1.5:22"}, // private: excluded
		{TS: "11:59:00", Kind: "remote", PID: 9, Process: "curl", Exe: "/usr/bin/curl", Remote: "[2606:2800::1]:443"},
	}
	scores := []ScoreChange{ // newest first
		{At: "2026-09-17 12:00:03", Exe: `C:\\Temp\\svc.exe`, IP: "45.9.148.20", Threat: 65, Breakdown: "path_staging/25;exfil/25/2 MB;unsigned/15"},
		{At: "2026-09-17 11:00:00", Exe: `C:\\Temp\\svc.exe`, IP: "45.9.148.20", Threat: 40, Breakdown: "path_staging/25;unsigned/15"},
		{At: "2026-09-17 10:00:00", Exe: "/opt/agent", IP: "8.8.8.8", Threat: 0, Breakdown: "clean"},
	}
	hosts := map[string][]Hostname{"45.9.148.20": {{Name: "cdn-updates.tk", Source: "sni"}}}

	tl := buildTimeline("en", events, scores, hosts,
		map[string]bool{"45.9.148.20": true}, map[string]bool{"/opt/agent": true}, nil)

	if len(tl) != 3 {
		t.Fatalf("got %d entries, want 3 (svc, curl, agent): %+v", len(tl), tl)
	}
	top := tl[0]
	if top.Exe != `C:\\Temp\\svc.exe` || top.IP != "45.9.148.20" || top.Threat != 65 {
		t.Errorf("highest risk first: %+v", top)
	}
	if len(top.Events) != 2 || len(top.Scores) != 2 || top.Process != "svc.exe" {
		t.Errorf("join incomplete: events=%d scores=%d process=%q", len(top.Events), len(top.Scores), top.Process)
	}
	if top.FirstSeen != "12:00:02" || top.LastSeen != "12:00:05" {
		t.Errorf("bounds = %s … %s", top.FirstSeen, top.LastSeen)
	}
	if !top.Blocked || top.Whitelisted || len(top.Hostnames) != 1 || top.Hostnames[0].Name != "cdn-updates.tk" {
		t.Errorf("flags/hostnames wrong: %+v", top)
	}
	if top.Breakdown != "staging path (temp/public) (+25) · sustained outbound volume (2 MB/s) from a suspect binary (+25) · unsigned binary (+15)" {
		t.Errorf("breakdown not localized: %q", top.Breakdown)
	}
	for _, e := range tl {
		if e.IP == "192.168.1.5" {
			t.Error("private remote must be excluded")
		}
		if e.Exe == "/usr/bin/curl" && e.IP != "2606:2800::1" {
			t.Errorf("IPv6 remote not stripped of port/brackets: %q", e.IP)
		}
		if e.Exe == "/opt/agent" && (!e.Whitelisted || e.FirstSeen != "2026-09-17 10:00:00") {
			t.Errorf("score-only pair: %+v", e)
		}
	}
	if _, err := json.Marshal(tl); err != nil {
		t.Errorf("not serializable: %v", err)
	}
}
