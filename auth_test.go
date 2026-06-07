package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestPasswordMinLength(t *testing.T) {
	old := envPath
	envPath = filepath.Join(t.TempDir(), ".env")
	t.Cleanup(func() { setAuthPassword(""); envPath = old })

	if err := setAuthPassword("short"); !errors.Is(err, errPwTooShort) {
		t.Errorf("short password err=%v, want errPwTooShort", err)
	}
	if authEnabled() {
		t.Error("auth should not be enabled by a rejected short password")
	}
	if err := setAuthPassword("longenough8"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
}

func TestLoginLockout(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)

	for i := 0; i < lockThreshold; i++ {
		if locked, _ := loginLocked(); locked {
			t.Fatalf("locked too early at attempt %d", i)
		}
		recordLoginFail()
	}
	if locked, remain := loginLocked(); !locked || remain <= 0 {
		t.Error("should be locked after threshold failures")
	}
	resetLoginFails()
	if locked, _ := loginLocked(); locked {
		t.Error("reset should clear the lockout")
	}
}

func TestLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"127.0.0.1:5000": true, "localhost:5000": true, "[::1]:5000": true,
		"127.5.5.5:5000": true, "localhost": true, "127.0.0.1": true,
		"evil.com:5000": false, "192.168.1.5:5000": false, "10.0.0.1": false, "": false,
	} {
		if got := loopbackHost(h); got != want {
			t.Errorf("loopbackHost(%q)=%v, want %v", h, got, want)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	// Not exposed (default): loopback only.
	listenExposed = false
	for h, want := range map[string]bool{
		"127.0.0.1:5000": true, "localhost:5000": true, "[::1]:5000": true,
		"192.168.1.5:5000": false, "evil.com:5000": false,
	} {
		if got := hostAllowed(h); got != want {
			t.Errorf("[loopback-only] hostAllowed(%q)=%v, want %v", h, got, want)
		}
	}
	// Exposed: loopback OR IP literal; hostnames (rebinding) rejected.
	listenExposed = true
	defer func() { listenExposed = false }()
	for h, want := range map[string]bool{
		"127.0.0.1:5000": true, "192.168.1.5:5000": true, "10.0.0.9:5000": true,
		"[2001:db8::1]:5000": true, "evil.com:5000": false, "myhost:5000": false,
	} {
		if got := hostAllowed(h); got != want {
			t.Errorf("[exposed] hostAllowed(%q)=%v, want %v", h, got, want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	const host = "127.0.0.1:5000"
	for o, want := range map[string]bool{
		"http://127.0.0.1:5000":   true,  // same host:port
		"http://127.0.0.1:6000":   false, // different port = cross-origin
		"http://localhost:5000":   false, // different host name
		"https://evil.com":        false,
		"http://192.168.1.5:5000": false,
		"":                        false, "garbage": false,
	} {
		if got := sameOrigin(o, host); got != want {
			t.Errorf("sameOrigin(%q, %q)=%v, want %v", o, host, got, want)
		}
	}
}

func TestPasswordAndSession(t *testing.T) {
	// Redirect .env writes to a temp file so we never touch the real one.
	old := envPath
	envPath = filepath.Join(t.TempDir(), ".env")
	t.Cleanup(func() { setAuthPassword(""); envPath = old })

	if authEnabled() {
		t.Fatal("auth should start disabled")
	}
	if err := setAuthPassword("s3cretpw"); err != nil {
		t.Fatal(err)
	}
	if !authEnabled() {
		t.Error("auth should be enabled after setting a password")
	}
	if !checkPassword("s3cretpw") {
		t.Error("correct password rejected")
	}
	if checkPassword("wrongpass") {
		t.Error("wrong password accepted")
	}

	tok := newSession()
	if !validSession(tok) {
		t.Error("fresh session should be valid")
	}
	if validSession("deadbeef") {
		t.Error("unknown token should be invalid")
	}

	// Changing the password must invalidate existing sessions.
	setAuthPassword("otherpass")
	if validSession(tok) {
		t.Error("old session should be invalidated on password change")
	}

	// Disabling clears it.
	setAuthPassword("")
	if authEnabled() {
		t.Error("auth should be disabled after empty password")
	}
}
