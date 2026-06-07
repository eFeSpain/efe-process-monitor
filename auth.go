package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Optional single-password gate + transport hardening. There is no user
// management by design: the tool is single-machine and the real risk is "the
// localhost port gets reached from elsewhere". We defend that with (1) a Host
// allow-list (anti DNS-rebinding), (2) an Origin check on state-changing
// requests (anti CSRF), and (3) an optional session password.

const (
	sessionTTL     = 12 * time.Hour
	minPasswordLen = 8
	lockThreshold  = 5 // failed logins before lockout kicks in
)

var errPwTooShort = errors.New("password too short")

var (
	authMu   sync.RWMutex
	authHash string // bcrypt hash of the access password ("" = login disabled)
	sessions = map[string]time.Time{}

	loginFails int       // consecutive failed logins (global; single-password gate)
	lockUntil  time.Time // login locked until this time
)

// loadAuth restores the password hash from .env (base64-wrapped so the bcrypt
// "$" characters never trip godotenv's variable expansion).
func loadAuth(env string) {
	authMu.Lock()
	defer authMu.Unlock()
	if env == "" {
		authHash = ""
		return
	}
	if b, err := base64.StdEncoding.DecodeString(env); err == nil {
		authHash = string(b)
	}
}

func authEnabled() bool {
	authMu.RLock()
	defer authMu.RUnlock()
	return authHash != ""
}

// setAuthPassword sets, changes, or (with "") clears the access password. All
// existing sessions are invalidated on any change.
func setAuthPassword(pw string) error {
	authMu.Lock()
	defer authMu.Unlock()
	sessions = map[string]time.Time{} // force re-login
	if pw == "" {
		authHash = ""
		writeEnv(map[string]string{"AUTH_HASH": ""})
		return nil
	}
	if len(pw) < minPasswordLen {
		return errPwTooShort
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	authHash = string(h)
	writeEnv(map[string]string{"AUTH_HASH": base64.StdEncoding.EncodeToString(h)})
	return nil
}

func checkPassword(pw string) bool {
	authMu.RLock()
	h := authHash
	authMu.RUnlock()
	return h != "" && bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil
}

// loginLocked reports whether logins are temporarily blocked (brute-force
// backoff) and how long remains.
func loginLocked() (bool, time.Duration) {
	authMu.RLock()
	defer authMu.RUnlock()
	if time.Now().Before(lockUntil) {
		return true, time.Until(lockUntil)
	}
	return false, 0
}

func recordLoginFail() {
	authMu.Lock()
	defer authMu.Unlock()
	loginFails++
	if loginFails >= lockThreshold {
		over := loginFails - lockThreshold
		if over > 5 {
			over = 5 // cap the shift; 30s<<5 = 16m → clamped below
		}
		d := 30 * time.Second << uint(over)
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
		lockUntil = time.Now().Add(d)
	}
}

func resetLoginFails() {
	authMu.Lock()
	loginFails, lockUntil = 0, time.Time{}
	authMu.Unlock()
}

// sessionCookie builds the session cookie. Secure is set only when serving HTTPS
// (exposed mode); on plain-HTTP loopback a Secure cookie would never be stored.
func sessionCookie() *http.Cookie {
	return &http.Cookie{
		Name: "sid", Value: newSession(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: listenTLS, MaxAge: int(sessionTTL.Seconds()),
	}
}

func newSession() string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	authMu.Lock()
	sessions[tok] = time.Now().Add(sessionTTL)
	authMu.Unlock()
	return tok
}

func validSession(tok string) bool {
	authMu.RLock()
	exp, ok := sessions[tok]
	authMu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		authMu.Lock()
		delete(sessions, tok)
		authMu.Unlock()
		return false
	}
	return true
}

func isAuthed(r *http.Request) bool {
	c, err := r.Cookie("sid")
	return err == nil && validSession(c.Value)
}

// loopbackHost reports whether a Host/authority is a loopback address. This is
// the anti-DNS-rebinding control: a browser tricked into resolving evil.com to
// 127.0.0.1 still sends "Host: evil.com", which we reject.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := splitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.") // 127.0.0.0/8
}

// splitHostPort is net.SplitHostPort but tolerant of a missing port.
func splitHostPort(hp string) (string, string, error) {
	if !strings.Contains(hp, ":") || (strings.Count(hp, ":") > 1 && !strings.Contains(hp, "]")) {
		return hp, "", nil // bare IPv6 or host without port
	}
	i := strings.LastIndex(hp, ":")
	return hp[:i], hp[i+1:], nil
}

// hostAllowed is the anti-DNS-rebinding gate. Loopback Hosts are always fine.
// When the dashboard is exposed (bound to a non-loopback address), an IP-literal
// Host is also allowed — a rebinding attack relies on a DNS *name* resolving to
// the box, so accepting only IP literals (plus loopback) blocks it.
func hostAllowed(hostport string) bool {
	if loopbackHost(hostport) {
		return true
	}
	if !listenExposed {
		return false
	}
	h := hostport
	if x, _, err := splitHostPort(hostport); err == nil {
		h = x
	}
	return net.ParseIP(strings.Trim(h, "[]")) != nil
}

// sameOrigin reports whether an Origin header belongs to the same host as the
// request (the canonical CSRF check). Host was already pinned to loopback.
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

func isPublicPath(p string) bool {
	return p == "/login" || strings.HasPrefix(p, "/static/")
}

// securityMiddleware wraps every request: Host allow-list, CSRF Origin check on
// writes, then the optional auth gate.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defensive headers on every response. The UI is fully self-contained
		// (no external scripts/styles/fonts), so a tight CSP holds; 'unsafe-inline'
		// is required only because the templates use inline <script>/<style> and
		// onclick handlers — injected content is still neutralized by html/template.
		h := w.Header()
		h.Set("Cache-Control", "no-store") // dynamic dashboard; never let the browser serve a stale shell
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin") // not "no-referrer": that makes browsers send Origin:null on form POSTs, breaking the CSRF check below
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

		if !hostAllowed(r.Host) {
			http.Error(w, "forbidden: host not allowed", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// CSRF: a state-changing request must be same-origin. The canonical
			// check is Origin host == Host header (we already pinned Host to
			// loopback above). An absent Origin is allowed (some same-origin form
			// posts omit it). Cross-origin Origins are logged and rejected.
			if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
				log.Printf("[csrf] blocked: Origin=%q Host=%q %s %s", o, r.Host, r.Method, r.URL.Path)
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		}
		if authEnabled() && !isPublicPath(r.URL.Path) && !isAuthed(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") || r.Method != http.MethodGet {
				http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rootHandler is the fully-wrapped handler the server serves.
func rootHandler() http.Handler { return securityMiddleware(http.DefaultServeMux) }

func handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := langFrom(r)
	if !authEnabled() { // nothing to log into
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		if locked, remain := loginLocked(); locked {
			renderLogin(w, lang, fmt.Sprintf(strings_(lang)["login_locked"], int(remain.Seconds())+1))
			return
		}
		if checkPassword(r.FormValue("password")) {
			resetLoginFails()
			http.SetCookie(w, sessionCookie())
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		recordLoginFail()
		time.Sleep(500 * time.Millisecond) // throttle on top of the lockout
		renderLogin(w, lang, strings_(lang)["login_error"])
		return
	}
	renderLogin(w, lang, "")
}

const loginHTML = `<!doctype html><html lang="%s"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title><style>
*{box-sizing:border-box} body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:#0d1117;color:#c9d1d9;font-family:system-ui,Segoe UI,sans-serif}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:28px 32px;width:320px;text-align:center}
h1{font-size:16px;margin:0 0 4px} p{color:#8b949e;font-size:13px;margin:0 0 16px}
input{width:100%%;padding:9px 11px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px}
button{width:100%%;margin-top:12px;padding:9px;background:#238636;border:0;border-radius:6px;color:#fff;font-weight:600;cursor:pointer}
button:hover{background:#2ea043} .err{color:#f85149;font-size:12px;margin:10px 0 0}
.lock{font-size:26px;margin-bottom:8px}
</style></head><body><form class="box" method="post" action="/login">
<div class="lock">🔒</div><h1>eFe Process Monitor</h1><p>%s</p>
<div style="position:relative">
<input type="password" id="lpw" name="password" autofocus autocomplete="current-password" placeholder="••••••••" style="padding-right:34px">
<span onclick="var p=document.getElementById('lpw');p.type=p.type=='password'?'text':'password'" style="position:absolute;right:11px;top:50%%;transform:translateY(-50%%);cursor:pointer;opacity:.55;user-select:none">👁</span>
</div>
<button type="submit">%s</button>%s</form></body></html>`

func renderLogin(w http.ResponseWriter, lang, errMsg string) {
	T := strings_(lang)
	errHTML := ""
	if errMsg != "" {
		errHTML = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginHTML, lang, html.EscapeString(T["login_title"]),
		html.EscapeString(T["login_prompt"]), html.EscapeString(T["login_btn"]), errHTML)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		authMu.Lock()
		delete(sessions, c.Value)
		authMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}
