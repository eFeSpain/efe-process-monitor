package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Process context: where it runs from and under what.
//
// The details block said what a process is (path, signature, hash) and what it
// talks to. It did not say where it was working from, whether a person was
// behind it, which service or container it belongs to, or whether its
// environment carries an injection or a proxy. Those are the questions an
// analyst asks next, and all four are a file read away.

// sensitiveEnvKeys are environment variables that change what a process runs
// or where its traffic goes. Anything else in the environment stays private:
// it is never read into the page.
var sensitiveEnvKeys = map[string]bool{
	// library / code injection
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "DYLD_INSERT_LIBRARIES": true,
	"GLIBC_TUNABLES": true, "COR_PROFILER": true, "COR_ENABLE_PROFILING": true,
	"CORECLR_PROFILER": true, "CORECLR_ENABLE_PROFILING": true,
	// interpreter start-up hooks
	"PYTHONPATH": true, "PYTHONSTARTUP": true, "PERL5OPT": true, "PERL5LIB": true,
	"NODE_OPTIONS": true, "JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "RUBYOPT": true,
	"BASH_ENV": true, "ENV": true, "PROMPT_COMMAND": true,
	// traffic redirection
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "SOCKS_PROXY": true,
	"SOCKS5_PROXY": true, "FTP_PROXY": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"NODE_EXTRA_CA_CERTS": true, "REQUESTS_CA_BUNDLE": true, "CURL_CA_BUNDLE": true,
}

// sensitiveEnv returns the "KEY=value" entries worth showing, with proxy
// credentials masked and long values cut. Keys are matched case-insensitively:
// Windows has no case, and `http_proxy` is the common spelling on Unix.
func sensitiveEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" || !sensitiveEnvKeys[strings.ToUpper(k)] {
			continue
		}
		out = append(out, k+"="+truncateValue(maskURLCreds(v), 100))
	}
	return out
}

// maskURLCreds hides the user:password part of a proxy URL: the point is to
// show that traffic is redirected, not to print a credential on the page.
func maskURLCreds(v string) string {
	i := strings.Index(v, "://")
	if i < 0 {
		return v
	}
	rest := v[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	at := strings.LastIndex(rest[:end], "@")
	if at < 0 {
		return v
	}
	return v[:i+3] + "***" + rest[at:]
}

func truncateValue(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// cgroup parsing: the v2 line is "0::/system.slice/nginx.service" for a
// service, "…/docker-<id>.scope" for a container, and a user.slice path for
// something started from a desktop session.
var (
	cgroupContainerRe = regexp.MustCompile(`(?i)(docker|podman|libpod|containerd|cri-containerd|lxc|kubepods)[-/:]+([0-9a-f]{12,64})`)
	cgroupUnitRe      = regexp.MustCompile(`([A-Za-z0-9@._\\-]+\.(service|scope))`)
)

// parseCgroup extracts the container (runtime + short id) and the innermost
// systemd unit from the content of /proc/<pid>/cgroup.
func parseCgroup(content string) (container, unit string) {
	for _, ln := range strings.Split(content, "\n") {
		path := ln
		if i := strings.LastIndex(ln, ":"); i >= 0 {
			path = ln[i+1:]
		}
		if container == "" {
			if m := cgroupContainerRe.FindStringSubmatch(path); m != nil {
				container = strings.ToLower(m[1]) + ":" + m[2][:12]
			}
		}
		if unit == "" {
			// The last unit in the path is the innermost: a user session's
			// app.slice/foo.service, not user@1000.service around it.
			all := cgroupUnitRe.FindAllStringSubmatch(path, -1)
			if len(all) > 0 {
				u := all[len(all)-1][1]
				// Generic wrappers say nothing about the process.
				if !strings.HasPrefix(u, "user@") && !strings.HasPrefix(u, "session-") && u != "init.scope" {
					unit = unescapeUnit(u)
				}
			}
		}
	}
	// A container's own scope is not a unit the operator recognizes; the
	// container id says it better.
	if container != "" && (strings.HasPrefix(unit, "docker-") || strings.HasPrefix(unit, "libpod-") || strings.HasPrefix(unit, "cri-containerd-")) {
		unit = ""
	}
	return container, unit
}

// unescapeUnit undoes systemd's unit-name escaping ("\x2d" for "-", and so
// on), so app-google\x2dchrome@… reads as app-google-chrome@….
func unescapeUnit(u string) string {
	if !strings.Contains(u, `\x`) {
		return u
	}
	var b strings.Builder
	for i := 0; i < len(u); i++ {
		if u[i] == '\\' && i+3 < len(u) && u[i+1] == 'x' {
			if n, err := strconv.ParseUint(u[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(u[i])
	}
	return b.String()
}

// procCgroup reads and parses /proc/<pid>/cgroup (Linux; "" elsewhere or unreadable).
func procCgroup(pid int32) (container, unit string) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cgroup") // #nosec G304 -- /proc path from a pid
	if err != nil {
		return "", ""
	}
	return parseCgroup(string(b))
}
