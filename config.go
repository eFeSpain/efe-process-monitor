package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

var envPath = ".env"

// Settings that the UI can change at runtime are read by background goroutines
// (the monitor loop, the notifier) and written by HTTP handlers, so they can't be
// plain variables: unsynchronized access is a data race under Go's memory model,
// it just happened to be invisible because CI ran the tests without -race.
// Atomic types keep every access safe without a lock discipline to get wrong.

// refreshSecs is the table auto-refresh interval (seconds; 0 = off), persisted
// server-side in .env so it's the same on every browser/restart.
var refreshSecs atomic.Int64

// atomicString is a string safe for concurrent reads and writes.
type atomicString struct{ v atomic.Value }

func (a *atomicString) Load() string   { s, _ := a.v.Load().(string); return s }
func (a *atomicString) Store(s string) { a.v.Store(s) }

func mask(k string) string {
	if len(k) >= 4 {
		return "…" + k[len(k)-4:]
	}
	if k != "" {
		return "****"
	}
	return ""
}

func getSettings() map[string]any {
	return map[string]any{
		"vt_configured":     getVTKey() != "",
		"vt_hint":           mask(getVTKey()),
		"abuse_configured":  getAbuseKey() != "",
		"abuse_hint":        mask(getAbuseKey()),
		"notify_desktop":    notifyDesktop.Load(),
		"notify_sound":      notifySound.Load(),
		"persist_whitelist": persistWhitelist.Load(),
		"persist_blocks":    persistBlocks.Load(),
		"refresh_secs":      refreshSecs.Load(),
		"auth_enabled":      authEnabled(),
		"listen_addr":       listenAddr.Load(),
		"exposed":           listenExposed,
	}
}

// setListenAddr persists the bind address (takes effect on the next restart).
// Empty = default loopback. Exposing a non-loopback address still requires a
// login password (enforced at startup) and is served over HTTPS.
func setListenAddr(s string) {
	addr := strings.TrimSpace(s)
	listenAddr.Store(addr)
	writeEnv(map[string]string{"LISTEN_ADDR": addr})
}

// setPersistWhitelist toggles write-through to SQLite for the whitelist (binaries
// and IPs). Turning it on flushes the current session so existing entries persist.
func setPersistWhitelist(b bool) {
	persistWhitelist.Store(b)
	if b {
		flushWhitelist()
	}
	writeEnv(map[string]string{"PERSIST_WHITELIST": fmt.Sprintf("%t", b)})
}

// setPersistBlocks toggles write-through to SQLite for blocked IPs.
func setPersistBlocks(b bool) {
	persistBlocks.Store(b)
	if b {
		flushBlocks()
	}
	writeEnv(map[string]string{"PERSIST_BLOCKS": fmt.Sprintf("%t", b)})
}

// setRefreshSecs persists the table auto-refresh interval (seconds; 0 = off).
func setRefreshSecs(n int) {
	if n < 0 {
		n = 0
	}
	if n > 3600 {
		n = 3600
	}
	refreshSecs.Store(int64(n))
	writeEnv(map[string]string{"REFRESH_SECS": fmt.Sprintf("%d", n)})
}

func setNotifyDesktop(b bool) {
	notifyDesktop.Store(b)
	writeEnv(map[string]string{"NOTIFY_DESKTOP": fmt.Sprintf("%t", b)})
}

func setNotifySound(b bool) {
	notifySound.Store(b)
	writeEnv(map[string]string{"NOTIFY_SOUND": fmt.Sprintf("%t", b)})
}

// updateSettings updates keys at runtime; blank values are left unchanged.
func updateSettings(vt, abuse string) {
	updates := map[string]string{}
	keysMu.Lock()
	if vt != "" {
		vtKey = vt
		updates["VT_API_KEY"] = vt
	}
	if abuse != "" {
		abuseKey = abuse
		updates["ABUSEIPDB_API_KEY"] = abuse
	}
	keysMu.Unlock()
	if len(updates) > 0 {
		writeEnv(updates)
	}
}

var envKeyRe = regexp.MustCompile(`^\s*([A-Z_][A-Z0-9_]*)\s*=`)

// envMu serializes the read-modify-write of .env. Two concurrent POSTs to
// /api/settings would otherwise each read the old file and write back their own
// merge, losing the other's keys.
var envMu sync.Mutex

// writeEnv merges key=value pairs into the .env file, preserving other lines.
//
// The write is atomic (temp file + rename): os.WriteFile truncates first, and
// this process has two exit paths that fire ~400ms after responding (restart and
// shutdown). A truncated .env loses AUTH_HASH, which silently disables the login
// — a durability bug with a security consequence, so it gets the careful version.
func writeEnv(updates map[string]string) {
	envMu.Lock()
	defer envMu.Unlock()

	var lines []string
	seen := map[string]bool{}
	if f, err := os.Open(envPath); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if m := envKeyRe.FindStringSubmatch(line); m != nil {
				if v, ok := updates[m[1]]; ok {
					lines = append(lines, fmt.Sprintf("%s=%s", m[1], v))
					seen[m[1]] = true
					continue
				}
			}
			lines = append(lines, line)
		}
		f.Close()
	}
	for k, v := range updates {
		if !seen[k] {
			lines = append(lines, fmt.Sprintf("%s=%s", k, v))
		}
	}
	if err := writeFileAtomic(envPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		log.Printf("[!] no se pudo guardar %s: %v", envPath, err)
	}
}

// writeFileAtomic writes data to path via a temp file in the same directory and
// a rename, so a crash mid-write leaves the previous contents intact rather than
// a truncated file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below has succeeded

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // durability: survive a power loss, not just a crash
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	// The mode above is ignored on Windows, so a 0600 file is only genuinely
	// private once an ACL is applied. Applying it to the *temp* file means the
	// data is never visible at its real path unprotected — a stronger guarantee
	// than write-then-lock, which leaves a window.
	if perm == 0o600 {
		if err := secureFile(tmp); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}
