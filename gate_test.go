package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end tests for securityMiddleware: the Host allow-list, the CSRF Origin
// check, the password gate and the local-token gate. These run the real
// middleware over a stub handler, so they cover the wiring and not just the
// helper functions.

func gateHandler() http.Handler {
	return securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "REACHED")
	}))
}

// withLocalGate configures "no password, token gate active" and restores after.
func withLocalGate(t *testing.T, token string) {
	t.Helper()
	oldHash, oldTok := authHash, localToken
	authMu.Lock()
	authHash = ""
	authMu.Unlock()
	localToken = token
	t.Cleanup(func() {
		authMu.Lock()
		authHash = oldHash
		authMu.Unlock()
		localToken = oldTok
	})
}

func do(h http.Handler, method, target, host string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGateBlocksWithoutToken(t *testing.T) {
	withLocalGate(t, "secrettoken")
	res := do(gateHandler(), "GET", "/", "127.0.0.1:5000", nil)
	if res.Code != http.StatusForbidden {
		t.Fatalf("no token should be forbidden, got %d", res.Code)
	}
	if strings.Contains(res.Body.String(), "REACHED") {
		t.Error("handler was reached without authorization")
	}
}

func TestGateAcceptsTokenThenCookie(t *testing.T) {
	withLocalGate(t, "secrettoken")
	h := gateHandler()

	res := do(h, "GET", "/?t=secrettoken", "127.0.0.1:5000", nil)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "REACHED") {
		t.Fatalf("valid token should pass, got %d %q", res.Code, res.Body.String())
	}
	cookies := res.Result().Cookies()
	var sid string
	for _, c := range cookies {
		if c.Name == "sid" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("token exchange should set a session cookie")
	}

	// The cookie alone must work, so the token never needs to be in a link again.
	res2 := do(h, "GET", "/", "127.0.0.1:5000", map[string]string{"Cookie": "sid=" + sid})
	if res2.Code != http.StatusOK {
		t.Errorf("session cookie should pass, got %d", res2.Code)
	}
}

func TestGateRejectsWrongToken(t *testing.T) {
	withLocalGate(t, "secrettoken")
	res := do(gateHandler(), "GET", "/?t=wrongtoken", "127.0.0.1:5000", nil)
	if res.Code != http.StatusForbidden {
		t.Errorf("wrong token should be forbidden, got %d", res.Code)
	}
}

// An unprivileged local program hitting the API is the escalation this gate
// exists to stop; it must be refused even with a valid loopback Host.
func TestGateBlocksLocalAPICaller(t *testing.T) {
	withLocalGate(t, "secrettoken")
	res := do(gateHandler(), "POST", "/api/kill", "127.0.0.1:5000",
		map[string]string{"Content-Type": "application/json"})
	if res.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated API call should be forbidden, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), `"ok":false`) {
		t.Errorf("API rejection should be JSON, got %q", res.Body.String())
	}
}

// Regression test for the DNS-rebinding bypass: a hostname that merely starts
// with "127." is attacker-controlled and must be rejected at the Host check,
// before any gate or handler runs.
func TestGateRejectsRebindingHost(t *testing.T) {
	withLocalGate(t, "secrettoken")
	for _, host := range []string{
		"127.0.0.1.evil.com:5000",
		"127.evil.com:5000",
		"127.0.0.1.nip.io:5000",
		"evil.com:5000",
	} {
		// Even *with* the right token, the Host must be refused first.
		res := do(gateHandler(), "GET", "/?t=secrettoken", host, nil)
		if res.Code != http.StatusForbidden {
			t.Errorf("Host %q should be rejected, got %d", host, res.Code)
		}
		if !strings.Contains(res.Body.String(), "host not allowed") {
			t.Errorf("Host %q: expected host rejection, got %q", host, res.Body.String())
		}
	}
}

func TestGateCSRFCrossOrigin(t *testing.T) {
	withLocalGate(t, "secrettoken")
	res := do(gateHandler(), "POST", "/api/kill?t=secrettoken", "127.0.0.1:5000",
		map[string]string{"Origin": "http://evil.com"})
	if res.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST should be forbidden, got %d", res.Code)
	}
	// Same-origin is allowed through the CSRF check.
	res2 := do(gateHandler(), "POST", "/api/kill?t=secrettoken", "127.0.0.1:5000",
		map[string]string{"Origin": "http://127.0.0.1:5000"})
	if res2.Code != http.StatusOK {
		t.Errorf("same-origin POST should pass, got %d", res2.Code)
	}
}

func TestGateStaticIsPublic(t *testing.T) {
	withLocalGate(t, "secrettoken")
	if res := do(gateHandler(), "GET", "/static/icon.svg", "127.0.0.1:5000", nil); res.Code != http.StatusOK {
		t.Errorf("/static/ must stay public, got %d", res.Code)
	}
}

// With a password set, the password is the gate and the token is irrelevant.
func TestPasswordGateTakesOver(t *testing.T) {
	old := envPath
	envPath = filepath.Join(t.TempDir(), ".env")
	oldTok := localToken
	localToken = "secrettoken"
	t.Cleanup(func() { setAuthPassword(""); envPath = old; localToken = oldTok })

	if err := setAuthPassword("longenough8"); err != nil {
		t.Fatal(err)
	}
	h := gateHandler()

	// A browser GET is redirected to the login page…
	res := do(h, "GET", "/", "127.0.0.1:5000", nil)
	if res.Code != http.StatusFound || res.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got %d %q", res.Code, res.Header().Get("Location"))
	}
	// …the API gets a 401…
	if res := do(h, "GET", "/api/connections", "127.0.0.1:5000", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for API without session, got %d", res.Code)
	}
	// …and the local token must NOT be a way around the password.
	if res := do(h, "GET", "/?t=secrettoken", "127.0.0.1:5000", nil); res.Code == http.StatusOK {
		t.Error("local token must not bypass the password gate")
	}
}

func TestSecurityHeadersAlwaysSet(t *testing.T) {
	withLocalGate(t, "secrettoken")
	res := do(gateHandler(), "GET", "/?t=secrettoken", "127.0.0.1:5000", nil)
	for h, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	} {
		if got := res.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if !strings.Contains(res.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("CSP header missing")
	}
}
