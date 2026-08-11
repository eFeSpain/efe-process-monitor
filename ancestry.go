package main

import (
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

// Process ancestry: who launched whom, all the way up.
//
// Showing only the immediate parent hides the signal. What actually distinguishes
// an intrusion from normal activity is the *chain*: cmd.exe under explorer.exe is
// a user opening a terminal, while the identical cmd.exe under winword.exe is a
// macro running a payload. Same process, same path, same signature — only the
// ancestry separates them.
//
// This is name-based and heuristic, like the rest of the scoring. It is
// deliberately narrow: every rule below is a pattern that should essentially
// never occur in normal desktop or server use, because a broad rule here would
// flood the score with false positives (see the tuning notes in ports.go).

// maxAncestryDepth bounds the walk. Chains are shallow in practice; the cap is
// there so a PID-reuse cycle or a hostile /proc can't spin us forever.
const maxAncestryDepth = 12

// Ancestor is one step in the chain, nearest parent first.
type Ancestor struct {
	PID  int32
	Name string
}

// ancestryOf walks up the parent chain from pid, nearest parent first.
//
// It stops at the root, at a repeated PID (cycle), or at the depth cap. Missing
// links are expected and not an error: on Windows the parent is frequently gone
// already, and unprivileged runs can't open every process.
func ancestryOf(pid int32) []Ancestor {
	var out []Ancestor
	seen := map[int32]bool{pid: true}
	cur := pid
	for i := 0; i < maxAncestryDepth; i++ {
		p, err := process.NewProcess(cur)
		if err != nil {
			return out
		}
		ppid, err := p.Ppid()
		if err != nil || ppid <= 0 || seen[ppid] {
			return out
		}
		seen[ppid] = true
		name := "?"
		if par, err := process.NewProcess(ppid); err == nil {
			if n, err := par.Name(); err == nil && n != "" {
				name = n
			}
		}
		out = append(out, Ancestor{PID: ppid, Name: name})
		cur = ppid
	}
	return out
}

// ── Spawn-pattern rules ──────────────────────────────────────────────────────

// scriptHosts are the interpreters and signed-binary proxies ("LOLBins") that
// malware reaches for once it has code execution. Legitimate software runs these
// too — that's why the rules below require a *parent* that has no business
// launching them, rather than flagging the child on its own.
var scriptHosts = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"wscript.exe": true, "cscript.exe": true, "mshta.exe": true,
	"rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true,
	"bitsadmin.exe": true, "msiexec.exe": true, "installutil.exe": true,
	"curl.exe": true, "wget.exe": true,
}

// documentApps must never be an ancestor of a script host: that is the classic
// macro / exploited-document execution chain.
var documentApps = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true,
	"outlook.exe": true, "msaccess.exe": true, "visio.exe": true,
	"onenote.exe": true, "acrord32.exe": true, "acrobat.exe": true,
}

// browsers must never be an ancestor of a script host either. A download that
// the user then runs gets a fresh process tree from explorer, not one parented
// to the browser.
var browsers = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true,
	"brave.exe": true, "opera.exe": true, "vivaldi.exe": true,
	"iexplore.exe": true,
}

// unixShells are the Unix equivalents of the script hosts above.
var unixShells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"python": true, "python3": true, "perl": true, "ruby": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true, "curl": true, "wget": true,
}

// serverProcs must never be an ancestor of a shell: a web server or database
// spawning /bin/sh is the signature of a webshell or an RCE being exercised.
var serverProcs = map[string]bool{
	"nginx": true, "apache2": true, "httpd": true, "lighttpd": true, "caddy": true,
	"php-fpm": true, "php": true, "node": true, "java": true, "tomcat": true,
	"postgres": true, "mysqld": true, "mariadbd": true, "redis-server": true,
}

// procBase normalizes a process name for comparison: lowercase basename.
//
// It splits on both separators explicitly instead of using filepath.Base, which
// is GOOS-dependent: on Linux a backslash is an ordinary filename character, so
// filepath.Base(`C:\...\WINWORD.EXE`) returns the whole string and the rule never
// matches. The comparison has to behave the same everywhere — these names are
// data, and the tool is cross-compiled from one host to all of them.
func procBase(name string) string {
	s := strings.TrimSpace(name)
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

// suspiciousAncestry reports a reason when the chain matches a spawn pattern that
// should not happen, or "" when nothing matches.
//
// procName is the process itself; chain is its ancestry, nearest parent first.
func suspiciousAncestry(procName string, chain []Ancestor) string {
	self := procBase(procName)

	// The child sets are already platform-specific by name (.exe vs bare), so no
	// GOOS check is needed — a rule simply never fires on the other platform.
	if scriptHosts[self] {
		for _, a := range chain {
			if an := procBase(a.Name); documentApps[an] || browsers[an] {
				return an + " → " + self
			}
		}
	}
	if unixShells[self] {
		for _, a := range chain {
			if serverProcs[procBase(a.Name)] {
				return procBase(a.Name) + " → " + self
			}
		}
	}
	return ""
}

// ancestryLabel renders the chain for the UI: "proc ← parent ← grandparent".
//
// Trailing unresolved links are dropped. Without elevation the walk runs out of
// permission somewhere up the tree, and a label ending in "? ← ? ← ?" is just
// noise — it says nothing beyond "the chain continues". An unknown *between* two
// known names is kept, because there the gap is the information.
func ancestryLabel(procName string, chain []Ancestor) string {
	end := len(chain)
	for end > 0 && chain[end-1].Name == "?" {
		end--
	}
	parts := []string{procName}
	for _, a := range chain[:end] {
		parts = append(parts, a.Name)
	}
	return strings.Join(parts, " ← ")
}
