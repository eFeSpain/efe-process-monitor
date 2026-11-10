package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// restartSessions is what a restart does to the session store: memory is
// gone, the database is still there.
func restartSessions() {
	authMu.Lock()
	sessions = map[string]time.Time{}
	authMu.Unlock()
	loadSessions()
}

// A browser that was let in stays in across a restart of the monitor. With
// the monitor running as a service, a reboot or an update used to turn every
// open dashboard into the gate page, to be reopened from the tray (or logged
// into again).
func TestSessionsSurviveRestart(t *testing.T) {
	setupTestDB(t)
	withTempEnv(t)
	tok := newSession(time.Hour)
	expired := newSession(-time.Minute)
	if !validSession(tok) {
		t.Fatal("a fresh session is valid")
	}

	restartSessions()
	if !validSession(tok) {
		t.Error("the session did not survive the restart")
	}
	if validSession(expired) {
		t.Error("an expired session came back from the database")
	}
	if validSession("not-a-session") || validSession("") {
		t.Error("unknown tokens are never valid")
	}

	// What is on disk is not the cookie: reading efemon.db must not hand out
	// a working session.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE token_hash = ?", tok).Scan(&n); err != nil || n != 0 {
		t.Errorf("the raw session token is stored in the database (n=%d, err=%v)", n, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n); err != nil || n != 1 {
		t.Errorf("want exactly the live session on disk, got %d (err=%v)", n, err)
	}
}

// Everything that ends a session ends it on disk too — otherwise a restart
// would bring it back.
func TestSessionEndingsReachTheDatabase(t *testing.T) {
	setupTestDB(t)
	withTempEnv(t)

	// Logout.
	if err := setAuthPassword("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	tok := newSession(time.Hour)
	other := newSession(time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: tok})
	handleLogout(httptest.NewRecorder(), req)
	restartSessions()
	if validSession(tok) {
		t.Error("a logged-out session came back after a restart")
	}
	if !validSession(other) {
		t.Error("logging out one browser must not end the others")
	}

	// Changing or removing the password ends every session.
	if err := setAuthPassword("another long password"); err != nil {
		t.Fatal(err)
	}
	restartSessions()
	if validSession(other) {
		t.Error("a session from before the password change came back after a restart")
	}
}
