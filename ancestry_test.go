package main

import (
	"strings"
	"testing"
)

func chain(names ...string) []Ancestor {
	out := make([]Ancestor, 0, len(names))
	for i, n := range names {
		out = append(out, Ancestor{PID: int32(1000 + i), Name: n})
	}
	return out
}

// The spawn rules are deliberately narrow. The negative cases matter more than
// the positive ones: a broad rule here would fire on ordinary desktop use and
// bury the score in false positives, which is exactly what the path and port
// signals used to do.
func TestSuspiciousAncestry(t *testing.T) {
	cases := []struct {
		name     string
		proc     string
		ancestry []Ancestor
		wantHit  bool
	}{
		// Should fire: a document or browser has no business launching a script host.
		{"word to powershell", "powershell.exe", chain("winword.exe", "explorer.exe"), true},
		{"excel to mshta", "mshta.exe", chain("excel.exe"), true},
		{"outlook to cmd, one level up", "cmd.exe", chain("wscript.exe", "outlook.exe"), true},
		{"acrobat to rundll32", "rundll32.exe", chain("AcroRd32.exe"), true},
		{"chrome to powershell", "powershell.exe", chain("chrome.exe"), true},
		{"nginx to bash", "bash", chain("nginx"), true},
		{"php-fpm to sh", "sh", chain("php-fpm", "nginx"), true},
		{"java to python", "python3", chain("java"), true},

		// Should NOT fire: all of these are normal.
		{"user opens a terminal", "cmd.exe", chain("explorer.exe"), false},
		{"powershell from the terminal", "powershell.exe", chain("cmd.exe", "explorer.exe"), false},
		{"installer runs msiexec", "msiexec.exe", chain("setup.exe", "explorer.exe"), false},
		{"office launched normally", "winword.exe", chain("explorer.exe"), false},
		{"browser launched normally", "chrome.exe", chain("explorer.exe"), false},
		{"shell from sshd is remote login, not a webshell", "bash", chain("sshd"), false},
		{"shell from a terminal emulator", "bash", chain("gnome-terminal-", "systemd"), false},
		{"cron running a script", "python3", chain("cron"), false},
		{"webserver running its own worker", "nginx", chain("nginx", "systemd"), false},
		{"no ancestry at all", "powershell.exe", nil, false},
		{"unknown parent name", "powershell.exe", chain("?"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := suspiciousAncestry(c.proc, c.ancestry)
			if (got != "") != c.wantHit {
				t.Errorf("suspiciousAncestry(%q, %v) = %q, wantHit=%v",
					c.proc, c.ancestry, got, c.wantHit)
			}
		})
	}
}

// Matching must not depend on how the OS reports the name: full path vs bare
// basename, and any capitalization.
func TestSuspiciousAncestryNormalizes(t *testing.T) {
	for _, a := range [][]Ancestor{
		chain(`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`),
		chain("WinWord.Exe"),
		chain("winword.exe"),
	} {
		if suspiciousAncestry("PowerShell.EXE", a) == "" {
			t.Errorf("expected a hit for ancestry %v", a)
		}
	}
	if got := suspiciousAncestry("/bin/bash", chain("/usr/sbin/nginx")); got == "" {
		t.Error("expected a hit for full Unix paths")
	}
}

func TestAncestryLabel(t *testing.T) {
	got := ancestryLabel("powershell.exe", chain("winword.exe", "explorer.exe"))
	want := "powershell.exe ← winword.exe ← explorer.exe"
	if got != want {
		t.Errorf("ancestryLabel = %q, want %q", got, want)
	}
	if got := ancestryLabel("lone.exe", nil); got != "lone.exe" {
		t.Errorf("ancestryLabel with no parents = %q, want %q", got, "lone.exe")
	}

	// Trailing unknowns are noise (the walk simply ran out of permission) and are
	// dropped; an unknown between two known names is real information and stays.
	if got, want := ancestryLabel("app.exe", chain("svc.exe", "?", "?")), "app.exe ← svc.exe"; got != want {
		t.Errorf("trailing unknowns not trimmed: %q, want %q", got, want)
	}
	if got, want := ancestryLabel("app.exe", chain("?", "explorer.exe")), "app.exe ← ? ← explorer.exe"; got != want {
		t.Errorf("interior unknown must be kept: %q, want %q", got, want)
	}
	if got, want := ancestryLabel("app.exe", chain("?", "?")), "app.exe"; got != want {
		t.Errorf("all-unknown chain should collapse: %q, want %q", got, want)
	}
}

// ancestryOf runs against the live process table: it must terminate, stay within
// the depth cap, and never report a cycle.
func TestAncestryOfSelfTerminates(t *testing.T) {
	got := ancestryOf(ownPID)
	if len(got) > maxAncestryDepth {
		t.Errorf("ancestry length %d exceeds cap %d", len(got), maxAncestryDepth)
	}
	seen := map[int32]bool{ownPID: true}
	for _, a := range got {
		if seen[a.PID] {
			t.Errorf("cycle in ancestry: PID %d repeated", a.PID)
		}
		seen[a.PID] = true
	}
	// The test binary always has at least a parent (the go tool or a shell).
	if len(got) == 0 {
		t.Log("no ancestry resolved; acceptable if the parent already exited")
	} else {
		t.Logf("ancestry of self: %s", ancestryLabel("test", got))
	}
}

// A row whose chain is flagged must say so in the breakdown, so the UI can
// explain *why* the score is what it is.
func TestBadSpawnAppearsInBreakdown(t *testing.T) {
	c := Conn{VT: "N/A", Details: &ProcDetails{BadSpawn: "winword.exe → powershell.exe"}}
	threatScore(&c)
	if !strings.Contains(c.Breakdown, "winword.exe → powershell.exe") {
		t.Errorf("breakdown should name the chain, got %q", c.Breakdown)
	}
}
