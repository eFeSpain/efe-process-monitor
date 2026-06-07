package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var envPath = ".env"

// refreshSecs is the table auto-refresh interval (seconds; 0 = off), persisted
// server-side in .env so it's the same on every browser/restart.
var refreshSecs = 0

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
		"notify_desktop":    notifyDesktop,
		"notify_sound":      notifySound,
		"persist_whitelist": persistWhitelist,
		"persist_blocks":    persistBlocks,
		"refresh_secs":      refreshSecs,
		"auth_enabled":      authEnabled(),
		"listen_addr":       listenAddr,
		"exposed":           listenExposed,
	}
}

// setListenAddr persists the bind address (takes effect on the next restart).
// Empty = default loopback. Exposing a non-loopback address still requires a
// login password (enforced at startup) and is served over HTTPS.
func setListenAddr(s string) {
	listenAddr = strings.TrimSpace(s)
	writeEnv(map[string]string{"LISTEN_ADDR": listenAddr})
}

// setPersistWhitelist toggles write-through to SQLite for the whitelist (binaries
// and IPs). Turning it on flushes the current session so existing entries persist.
func setPersistWhitelist(b bool) {
	persistWhitelist = b
	if b {
		flushWhitelist()
	}
	writeEnv(map[string]string{"PERSIST_WHITELIST": fmt.Sprintf("%t", b)})
}

// setPersistBlocks toggles write-through to SQLite for blocked IPs.
func setPersistBlocks(b bool) {
	persistBlocks = b
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
	refreshSecs = n
	writeEnv(map[string]string{"REFRESH_SECS": fmt.Sprintf("%d", n)})
}

func setNotifyDesktop(b bool) {
	notifyDesktop = b
	writeEnv(map[string]string{"NOTIFY_DESKTOP": fmt.Sprintf("%t", b)})
}

func setNotifySound(b bool) {
	notifySound = b
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

// writeEnv merges key=value pairs into the .env file, preserving other lines.
func writeEnv(updates map[string]string) {
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
	os.WriteFile(envPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
