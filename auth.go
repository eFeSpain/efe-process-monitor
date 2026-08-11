package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

	// localSessionTTL is the lifetime of a session granted by the local token
	// gate. It's long because that gate answers "which local program is this?",
	// not "is this person still authorized?" — a short TTL would just mean
	// re-opening from the tray every day for no security gain.
	localSessionTTL = 30 * 24 * time.Hour
	tokenFile       = "efemon-token"
)

var errPwTooShort = errors.New("password too short")

var (
	authMu   sync.RWMutex
	authHash string // bcrypt hash of the access password ("" = login disabled)
	sessions = map[string]time.Time{}

	// Brute-force backoff is tracked per client IP, not globally: a global
	// counter lets anyone who can reach the port lock the real operator out.
	loginFails = map[string]int{}
	lockUntil  = map[string]time.Time{}
)

// maxLockEntries caps the backoff maps so a flood of distinct source IPs can't
// grow them without bound while the dashboard is exposed.
const maxLockEntries = 1024

// clientIP is the source address used to key the login backoff.
func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// pruneLocks drops entries that are no longer locked. Caller holds authMu.
func pruneLocks() {
	now := time.Now()
	for ip, until := range lockUntil {
		if now.After(until) {
			delete(lockUntil, ip)
			delete(loginFails, ip)
		}
	}
	if len(loginFails) > maxLockEntries { // pathological: start over rather than grow
		loginFails = map[string]int{}
		lockUntil = map[string]time.Time{}
	}
}

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

// ── Local access token ───────────────────────────────────────────────────────
//
// With no password set, the Host/Origin checks above constrain *browsers* only:
// any local program can open a socket to 127.0.0.1:5000 and send whatever
// headers it likes. Since the tool is meant to run elevated, that would hand an
// unprivileged process the kill / firewall / settings / shutdown endpoints —
// a local privilege escalation.
//
// The gate: a random token minted at startup, written to a 0600 file next to
// the executable, handed to the browser once through the URL we open, and then
// exchanged for a session cookie. The browser keeps working from its cookie; a
// program that cannot read the token file cannot get in.
//
// Scope of the protection, honestly: on Unix a root-owned 0600 file keeps a
// non-elevated process out. On Windows a same-user process may still be able to
// read it, so there it raises the bar rather than closing the door. What it does
// close completely, on every platform, is the remote-website vector and access
// by other users of the machine.
//
// It only applies when no password is set — a password is the stronger gate, and
// network exposure already requires one, so this never runs on a public bind.
var localToken string

// initLocalToken mints the token for this run and persists it 0600 so a second
// launch (the "already running → just open the dashboard" path) can find it.
func initLocalToken() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("no se pudo generar el token de acceso local: %v", err)
	}
	localToken = hex.EncodeToString(b)
	p := filepath.Join(appDir, tokenFile)
	// writeSecretFile, not os.WriteFile: on Windows the 0600 mode is a no-op and
	// the file would inherit the directory ACL, leaving it readable by any process
	// running as this user — the very principal this gate exists to exclude.
	if err := writeSecretFile(p, []byte(localToken)); err != nil {
		// Not fatal: this run still works (we pass the token in the URL we open),
		// only the second-instance handoff degrades.
		log.Printf("[!] no se pudo escribir %s: %v", p, err)
	}
}

// readLocalToken loads the token written by the instance that owns the port.
func readLocalToken() string {
	b, err := os.ReadFile(filepath.Join(appDir, tokenFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// tokenURL appends the local token to the dashboard URL, so opening it in the
// browser also authorizes that browser. Empty token → URL unchanged.
func tokenURL(base, tok string) string {
	if tok == "" {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "t=" + url.QueryEscape(tok)
}

// validLocalToken compares a presented token against this run's token in
// constant time. A missing token never matches.
func validLocalToken(tok string) bool {
	if tok == "" || localToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(localToken)) == 1
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

// loginLocked reports whether logins from ip are temporarily blocked
// (brute-force backoff) and how long remains.
func loginLocked(ip string) (bool, time.Duration) {
	authMu.RLock()
	defer authMu.RUnlock()
	if until, ok := lockUntil[ip]; ok && time.Now().Before(until) {
		return true, time.Until(until)
	}
	return false, 0
}

func recordLoginFail(ip string) {
	authMu.Lock()
	defer authMu.Unlock()
	pruneLocks()
	loginFails[ip]++
	if n := loginFails[ip]; n >= lockThreshold {
		over := n - lockThreshold
		if over > 5 {
			over = 5 // cap the shift; 30s<<5 = 16m → clamped below
		}
		d := 30 * time.Second << uint(over)
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
		lockUntil[ip] = time.Now().Add(d)
	}
}

func resetLoginFails(ip string) {
	authMu.Lock()
	delete(loginFails, ip)
	delete(lockUntil, ip)
	authMu.Unlock()
}

// sessionCookie builds the session cookie. Secure is set only when serving HTTPS
// (exposed mode); on plain-HTTP loopback a Secure cookie would never be stored.
func sessionCookie() *http.Cookie { return sessionCookieFor(sessionTTL) }

// sessionCookieFor builds a session cookie valid for ttl.
func sessionCookieFor(ttl time.Duration) *http.Cookie {
	// #nosec G124 -- Secure is deliberately conditional, not a literal true: on the
	// default plain-HTTP loopback bind a Secure cookie would never be stored by the
	// browser, so the dashboard could not hold a session at all. It is set exactly
	// when we serve HTTPS, which is the only case where it can help.
	return &http.Cookie{
		Name: "sid", Value: newSession(ttl), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: listenTLS, MaxAge: int(ttl.Seconds()),
	}
}

func newSession(ttl time.Duration) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Never happens on supported platforms, but an all-zero token would be
		// guessable — refuse to mint one instead.
		log.Printf("[!] crypto/rand falló al crear la sesión: %v", err)
		return ""
	}
	tok := hex.EncodeToString(b)
	authMu.Lock()
	// Expired sessions were only dropped when someone presented them again, so
	// abandoned ones accumulated for the life of the process. Sweep on mint:
	// it's the only place the map grows, and it's rare.
	now := time.Now()
	for t, exp := range sessions {
		if now.After(exp) {
			delete(sessions, t)
		}
	}
	sessions[tok] = now.Add(ttl)
	authMu.Unlock()
	return tok
}

func validSession(tok string) bool {
	if tok == "" {
		return false
	}
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
//
// The check must be on the parsed IP, never on a string prefix: a name like
// "127.0.0.1.evil.com" starts with "127." but is a DNS name an attacker can
// point at loopback, which is exactly the rebinding case we're defending.
// "localhost" is the only *name* allowed, because browsers resolve it locally.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := splitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() // 127.0.0.0/8 and ::1
	}
	return strings.EqualFold(host, "localhost")
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
	// /favicon.ico is public so the gate doesn't log a "blocked" line every time a
	// browser probes for it — that noise lands in the same audit log we rely on to
	// spot real blocked attempts. It serves nothing sensitive (the real icon is
	// referenced from /static/).
	return p == "/login" || p == "/favicon.ico" || strings.HasPrefix(p, "/static/")
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
		// Exactly one gate is always in force: the password when one is set,
		// otherwise the local token. Never both, never neither.
		if !isPublicPath(r.URL.Path) && !isAuthed(r) {
			if authEnabled() {
				if strings.HasPrefix(r.URL.Path, "/api/") || r.Method != http.MethodGet {
					http.Error(w, `{"ok":false,"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// No password → the token in the URL we opened is what authorizes
			// this browser. Exchange it for a cookie so the token never has to
			// appear in a link again.
			if !validLocalToken(r.URL.Query().Get("t")) {
				denyLocal(w, r)
				return
			}
			http.SetCookie(w, sessionCookieFor(localSessionTTL))
		}
		next.ServeHTTP(w, r)
	})
}

// denyLocal rejects a request that presented neither a session nor the local
// token. API callers get JSON; a browser gets a page explaining how to get in,
// because the honest answer ("open it from the tray") is not guessable.
func denyLocal(w http.ResponseWriter, r *http.Request) {
	log.Printf("[gate] blocked (no session, no local token): %s %s", r.Method, r.URL.Path)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Error(w, `{"ok":false,"error":"forbidden: local token required"}`, http.StatusForbidden)
		return
	}
	lang := langFrom(r)
	T := strings_(lang)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	// Every interpolated value is escaped, including lang: it can only be a key of
	// the translations map today, but that's an invariant somewhere else.
	fmt.Fprintf(w, gateHTML, html.EscapeString(lang), html.EscapeString(T["gate_title"]),
		html.EscapeString(T["gate_title"]), html.EscapeString(T["gate_body"]),
		html.EscapeString(filepath.Join(appDir, tokenFile)))
}

const gateHTML = `<!doctype html><html lang="%s"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title><style>
*{box-sizing:border-box} body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
background:#0d1117;color:#c9d1d9;font-family:system-ui,Segoe UI,sans-serif}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:28px 32px;max-width:460px}
h1{font-size:16px;margin:0 0 10px} p{color:#8b949e;font-size:13px;margin:0 0 10px;line-height:1.6}
code{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:1px 5px;font-size:12px;word-break:break-all}
.lock{font-size:26px;margin-bottom:8px;text-align:center}
</style></head><body><div class="box">
<div class="lock">🔒</div><h1>%s</h1><p>%s</p><p><code>%s</code></p>
</div></body></html>`

// rootHandler is the fully-wrapped handler the server serves.
func rootHandler() http.Handler { return securityMiddleware(http.DefaultServeMux) }

func handleLogin(w http.ResponseWriter, r *http.Request) {
	lang := langFrom(r)
	if !authEnabled() { // nothing to log into
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		ip := clientIP(r)
		if locked, remain := loginLocked(ip); locked {
			renderLogin(w, lang, fmt.Sprintf(strings_(lang)["login_locked"], int(remain.Seconds())+1))
			return
		}
		if checkPassword(r.FormValue("password")) {
			resetLoginFails(ip)
			http.SetCookie(w, sessionCookie())
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		recordLoginFail(ip)
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
	fmt.Fprintf(w, loginHTML, html.EscapeString(lang), html.EscapeString(T["login_title"]),
		html.EscapeString(T["login_prompt"]), html.EscapeString(T["login_btn"]), errHTML)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// With no password there is nothing to log out of, and dropping the session
	// would only lock this browser out behind the local-token gate.
	if !authEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if c, err := r.Cookie("sid"); err == nil {
		authMu.Lock()
		delete(sessions, c.Value)
		authMu.Unlock()
	}
	// Same attributes as the cookie being replaced, so the browser reliably
	// overwrites it rather than keeping both.
	// #nosec G124 -- Secure mirrors sessionCookieFor; see the note there.
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: listenTLS})
	http.Redirect(w, r, "/login", http.StatusFound)
}
