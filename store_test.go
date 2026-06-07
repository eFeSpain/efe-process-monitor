package main

import "testing"

// setupTestDB points the global DB at a throwaway temp file and reseeds the
// in-memory session state from it. modernc.org/sqlite is pure Go, so no cgo.
func setupTestDB(t *testing.T) {
	t.Helper()
	appDir = t.TempDir()
	initDB()
	// Close the handle before TempDir's RemoveAll runs, or Windows can't delete
	// the open efemon.db. Registered after TempDir, so it runs first (LIFO).
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
	})
	loadState() // empty fresh DB → empty session maps
}

func TestWhitelistRoundTrip(t *testing.T) {
	setupTestDB(t)
	persistWhitelist = true

	addWhitelist(`C:\app\a.exe`)
	if !whitelist()[`C:\app\a.exe`] {
		t.Fatal("exe not in session whitelist after add")
	}
	if _, ok := dbAllWhitelist()[`C:\app\a.exe`]; !ok {
		t.Error("exe not persisted to DB (persist on)")
	}
	if len(listWhitelist()) != 1 {
		t.Errorf("listWhitelist len=%d, want 1", len(listWhitelist()))
	}
	removeWhitelist(`C:\app\a.exe`)
	if whitelist()[`C:\app\a.exe`] {
		t.Error("exe still present after remove")
	}
	if _, ok := dbAllWhitelist()[`C:\app\a.exe`]; ok {
		t.Error("exe still in DB after remove")
	}
}

func TestIPWhitelistRoundTrip(t *testing.T) {
	setupTestDB(t)
	persistWhitelist = true

	addIPWhitelist("8.8.8.8")
	if !ipWhitelist()["8.8.8.8"] {
		t.Fatal("ip not in session whitelist")
	}
	removeIPWhitelist("8.8.8.8")
	if ipWhitelist()["8.8.8.8"] {
		t.Error("ip still present after remove")
	}
}

func TestBlockedRoundTrip(t *testing.T) {
	setupTestDB(t)
	persistBlocks = true

	saveBlocked("1.2.3.4", "test report")
	list := listBlocked()
	if len(list) != 1 || list[0].IP != "1.2.3.4" || list[0].Report != "test report" {
		t.Fatalf("listBlocked=%+v", list)
	}
	deleteBlocked("1.2.3.4")
	if len(listBlocked()) != 0 {
		t.Error("blocked still present after delete")
	}
}

// TestPersistToggleSessionOnly is the core of the permanent-vs-session feature:
// with persistence off, an action lives in memory but is NOT written to the DB,
// so reseeding from the DB (a restart) forgets it.
func TestPersistToggleSessionOnly(t *testing.T) {
	setupTestDB(t)
	persistWhitelist = false

	addIPWhitelist("9.9.9.9")
	if !ipWhitelist()["9.9.9.9"] {
		t.Fatal("session entry missing in memory")
	}
	if _, ok := dbAllIPWhitelist()["9.9.9.9"]; ok {
		t.Error("session-only entry leaked to DB")
	}
	loadState() // simulate a restart: reseed from DB
	if ipWhitelist()["9.9.9.9"] {
		t.Error("session-only entry survived restart, should be gone")
	}
}

// TestFlushOnEnable: turning persistence on flushes the current session to DB.
func TestFlushOnEnable(t *testing.T) {
	setupTestDB(t)
	persistWhitelist = false
	addWhitelist(`C:\tmp\y.exe`)
	if _, ok := dbAllWhitelist()[`C:\tmp\y.exe`]; ok {
		t.Fatal("should not be in DB yet")
	}
	persistWhitelist = true
	flushWhitelist()
	if _, ok := dbAllWhitelist()[`C:\tmp\y.exe`]; !ok {
		t.Error("flush did not persist current session to DB")
	}
}
