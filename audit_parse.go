package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Pure parsers for the audit. Everything here takes text and returns
// findings, with no I/O, so each one can be pinned with a fixture: the
// firewall check once reported "could not determine" on every Spanish Windows
// because its parser was inline and nobody could feed it a Spanish sample.

// userHome is one account whose dot-files the audit inspects.
type userHome struct{ name, home string }

// userHomes returns root plus every real account (uid ≥ 1000) with an
// existing home directory, from /etc/passwd.
func userHomes() []userHome {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		home, _ := os.UserHomeDir()
		return []userHome{{"?", home}}
	}
	return userHomesFrom(string(b), func(p string) bool {
		fi, err := os.Stat(p) // #nosec G703 -- home directories come from /etc/passwd, a root-owned system file
		return err == nil && fi.IsDir()
	})
}

func userHomesFrom(passwd string, exists func(string) bool) []userHome {
	var out []userHome
	seen := map[string]bool{}
	for _, ln := range strings.Split(passwd, "\n") {
		f := strings.Split(ln, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || (uid != 0 && uid < 1000) || uid == 65534 {
			continue // system accounts; nobody
		}
		home := f[5]
		if home == "" || home == "/" || seen[home] || !exists(home) {
			continue
		}
		seen[home] = true
		out = append(out, userHome{f[0], home})
	}
	return out
}

// parseRegRunLines turns `reg query` output for a Run/RunOnce key into
// "name → command" entries, and the subset that carries a known-bad marker
// (temp/downloads paths, encoded PowerShell, LOLBin invocations).
func parseRegRunLines(out string) (entries, susp []string) {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "HKEY") {
			continue
		}
		i := strings.Index(ln, "REG_")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		val := ""
		if j := strings.Index(ln[i:], "    "); j >= 0 {
			val = strings.TrimSpace(ln[i+j:])
		}
		entry := name + " → " + val
		entries = append(entries, entry)
		lv := strings.ToLower(val)
		for _, sig := range []string{`\temp\`, `\downloads\`, "-enc", "-encodedcommand",
			"mshta", "frombase64string", "downloadstring", "-w hidden",
			"-windowstyle hidden", "iex(", "javascript:", "regsvr32 /s /n /u /i"} {
			if strings.Contains(lv, sig) {
				susp = append(susp, entry)
				break
			}
		}
	}
	return entries, susp
}

// regValue extracts the data of a single-value `reg query … /v name` output.
func regValue(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.Index(ln, "REG_"); i > 0 {
			rest := ln[i:]
			if j := strings.Index(rest, "    "); j >= 0 {
				return strings.TrimSpace(rest[j:])
			}
		}
	}
	return ""
}

// parseIFEO reads `reg query "…\Image File Execution Options" /s /v Debugger`:
// each hit is the program being hijacked and the "debugger" that replaces it.
func parseIFEO(out string) []string {
	var hits []string
	current := ""
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "HKEY") {
			current = ln[strings.LastIndex(ln, `\`)+1:]
			continue
		}
		if strings.HasPrefix(ln, "Debugger") && strings.Contains(ln, "REG_") {
			if v := regValue(ln); v != "" {
				hits = append(hits, current+" → "+v)
			}
		}
	}
	return hits
}

// parseSchtasksSuspicious returns the names of scheduled tasks whose CSV row
// mentions a staging path or an encoded/LOLBin command. `schtasks /v /fo csv`
// puts HostName first and TaskName second; the check used to report the
// first column, i.e. the computer's own name, for every hit.
func parseSchtasksSuspicious(out string) []string {
	var tasks []string
	for _, ln := range strings.Split(out, "\n") {
		l := strings.ToLower(ln)
		if strings.Contains(l, `\temp\`) || strings.Contains(l, `\appdata\`) ||
			strings.Contains(l, "powershell -enc") || strings.Contains(l, "mshta") {
			if f := strings.Split(ln, `","`); len(f) > 1 {
				tasks = append(tasks, strings.Trim(f[1], `"`))
			}
		}
	}
	return tasks
}

// parseWinServices reads "name<TAB>state<TAB>path" lines: services whose
// binary lives in a user-writable directory, and services whose path is
// unquoted with a space in it (Windows tries "C:\Program.exe" first).
func parseWinServices(out string) (susp, unquoted []string) {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(ln), "\t")
		if len(f) < 3 || f[2] == "" {
			continue
		}
		name, path := f[0], f[2]
		lp := strings.ToLower(path)
		for _, sig := range []string{`\temp\`, `\appdata\`, `\users\public\`, `\downloads\`} {
			if strings.Contains(lp, sig) {
				susp = append(susp, name+" → "+path)
				break
			}
		}
		if unquotedServicePath(path) {
			unquoted = append(unquoted, name+" → "+path)
		}
	}
	return susp, unquoted
}

// unquotedServicePath reports the classic privilege-escalation shape: an
// unquoted executable path containing a space before the .exe.
func unquotedServicePath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" || strings.HasPrefix(p, `"`) {
		return false
	}
	lp := strings.ToLower(p)
	i := strings.Index(lp, ".exe")
	if i < 0 {
		return false
	}
	return strings.Contains(p[:i], " ")
}

// parseDriverQueryUnsigned reads `driverquery /si /fo csv` and returns the
// drivers whose IsSigned column is FALSE.
func parseDriverQueryUnsigned(out string) []string {
	var unsigned []string
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Split(ln, `","`); len(f) >= 3 && strings.EqualFold(strings.Trim(f[2], `"`), "FALSE") {
			unsigned = append(unsigned, strings.Trim(f[0], `"`))
		}
	}
	return unsigned
}

// parseListeningPorts extracts the local port of every line of `ss -tuln` /
// `netstat -tuln`, or of the LISTENING lines of `netstat -ano` on Windows.
func parseListeningPorts(raw string, windowsListeningOnly bool) []int {
	var ports []int
	for _, ln := range strings.Split(raw, "\n") {
		if windowsListeningOnly && !strings.Contains(strings.ToUpper(ln), "LISTENING") {
			continue
		}
		for _, tok := range strings.Fields(ln) {
			if i := strings.LastIndex(tok, ":"); i >= 0 && i < len(tok)-1 {
				if p, err := strconv.Atoi(tok[i+1:]); err == nil && p > 0 && p <= 65535 {
					ports = append(ports, p)
					break
				}
			}
		}
	}
	return ports
}

// parseSystemdExec returns the commands of the Exec* directives of a unit.
func parseSystemdExec(unit string) []string {
	var out []string
	for _, ln := range strings.Split(unit, "\n") {
		ln = strings.TrimSpace(ln)
		for _, k := range []string{"ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecReload=", "ExecStop="} {
			if v, ok := strings.CutPrefix(ln, k); ok && strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
	}
	return out
}

// suspiciousExecPath reports whether an Exec* command starts a binary from a
// staging directory or a home directory — where no system service belongs.
func suspiciousExecPath(cmd string) bool {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return false
	}
	bin := strings.TrimLeft(f[0], "-@+!:") // systemd's Exec prefixes
	return isSuspiciousPath(bin) || strings.HasPrefix(bin, "/home/") || strings.HasPrefix(bin, "/root/")
}

// parseProcNetInodes returns the inode column of a /proc/net/{tcp,udp}[6] table.
func parseProcNetInodes(content string) []string {
	var out []string
	for i, ln := range strings.Split(content, "\n") {
		f := strings.Fields(ln)
		if i == 0 || len(f) < 10 { // header, blanks
			continue
		}
		out = append(out, f[9])
	}
	return out
}

// socketInode extracts N from a "socket:[N]" fd link; "" for anything else.
func socketInode(link string) string {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return ""
	}
	return link[len("socket:[") : len(link)-1]
}

// cronEnvLine reports a crontab settings line (SHELL=, PATH=, MAILTO=…), which
// is not a job.
func cronEnvLine(ln string) bool {
	k, _, ok := strings.Cut(ln, "=")
	if !ok || k == "" {
		return false
	}
	for _, r := range k {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// desktopExec returns the Exec= command of a .desktop file ("" if none).
func desktopExec(content string) string {
	for _, ln := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Exec="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// taintFlags decodes /proc/sys/kernel/tainted into the kernel's letter flags
// (Documentation/admin-guide/tainted-kernels.rst), e.g. 12288 → "O E".
func taintFlags(n int) string {
	const letters = "PFSRMBUDAWCIOELKXT"
	var f []string
	for bit := 0; bit < len(letters); bit++ {
		if n&(1<<bit) != 0 {
			f = append(f, string(letters[bit]))
		}
	}
	return strings.Join(f, " ")
}

// knownModuleFamilies are out-of-tree drivers that taint every machine they
// are installed on and mean nothing by themselves.
var knownModuleFamilies = []string{"nvidia", "vbox", "vmw", "vmmon", "vmnet", "zfs", "spl", "wl", "r8168", "evdi", "v4l2loopback", "openrazer", "xone", "xpad", "anbox", "ashmem", "binder"}

// unknownModules returns the out-of-tree modules ("name (flags)") that are not
// from a known proprietary family.
func unknownModules(mods []string) []string {
	var out []string
	for _, m := range mods {
		name := strings.ToLower(strings.Fields(m)[0])
		known := false
		for _, fam := range knownModuleFamilies {
			if strings.HasPrefix(name, fam) {
				known = true
				break
			}
		}
		if !known {
			out = append(out, m)
		}
	}
	return out
}

// countNftRules counts the rules of an `nft list ruleset` (lines inside chains
// that are neither chain headers nor braces).
func countNftRules(out string) int {
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t == "}" || strings.HasPrefix(t, "table ") || strings.HasPrefix(t, "chain ") ||
			strings.HasPrefix(t, "type ") || strings.HasPrefix(t, "set ") || strings.HasPrefix(t, "elements") ||
			strings.HasPrefix(t, "#") {
			continue
		}
		n++
	}
	return n
}

// countIptablesRules counts the non-policy lines of `iptables -S`.
func countIptablesRules(out string) int {
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(ln); t != "" && !strings.HasPrefix(t, "-P ") && !strings.HasPrefix(t, "-N ") {
			n++
		}
	}
	return n
}

// standardHostsNames are the names every hosts file carries by default.
var standardHostsNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "localhost4": true, "localhost6": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "broadcasthost": true,
}

// customHostsLines returns the entries of a hosts file that are not the
// standard boilerplate: a name that is not one of the defaults (or the
// machine's own), whatever the address. The previous filter dropped any line
// containing the substring "localhost", so `1.2.3.4 bank.com # localhost`
// passed as boilerplate.
func customHostsLines(content, selfName string) []string {
	var custom []string
	for _, ln := range strings.Split(content, "\n") {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		f := strings.Fields(t)
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			continue
		}
		std := true
		for _, name := range f[1:] {
			n := strings.ToLower(name)
			if !standardHostsNames[n] && !strings.EqualFold(n, selfName) &&
				!strings.EqualFold(n, selfName+".localdomain") && !strings.EqualFold(n, filepath.Base(selfName)) {
				std = false
			}
		}
		if !std {
			custom = append(custom, t)
		}
	}
	return custom
}
