package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// queryPlan returns the detail lines of EXPLAIN QUERY PLAN for q.
func queryPlan(t *testing.T, q string, args ...any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", q, err)
	}
	defer rows.Close()
	var sb strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		sb.WriteString(detail)
		sb.WriteString("\n")
	}
	return sb.String()
}

// Every render runs these per PID (events) and per row (score_history). With
// only the epoch indexes they were full table scans over 30 days of history,
// repeated for every process on screen, several times a minute.
func TestPerRenderQueriesUseIndexes(t *testing.T) {
	setupTestDB(t)
	cases := []struct{ q, index string }{
		{"SELECT remote FROM events WHERE exe=? AND epoch>=? AND remote<>''", "idx_events_exe"},
		{"SELECT ts FROM events WHERE exe=? ORDER BY epoch ASC LIMIT 1", "idx_events_exe"},
		{"SELECT ts FROM events WHERE exe=? ORDER BY epoch DESC LIMIT 1", "idx_events_exe"},
		{"SELECT count(*) FROM score_history WHERE exe=?", "idx_score_history_pair"},
		{"SELECT threat, breakdown FROM score_history WHERE exe=? AND ip=? ORDER BY epoch DESC LIMIT 1", "idx_score_history_pair"},
	}
	for _, c := range cases {
		args := make([]any, strings.Count(c.q, "?"))
		for i := range args {
			args[i] = "x"
		}
		plan := queryPlan(t, c.q, args...)
		if !strings.Contains(plan, "USING INDEX "+c.index) && !strings.Contains(plan, "USING COVERING INDEX "+c.index) {
			t.Errorf("%s\n  does not use %s:\n%s", c.q, c.index, plan)
		}
		if strings.Contains(plan, "SCAN events") || strings.Contains(plan, "SCAN score_history") {
			t.Errorf("%s\n  still scans the table:\n%s", c.q, plan)
		}
	}
}

// hostnames is fed continuously by the passive DNS listener and loaded whole on
// every render, so it has to follow the same retention as the events it explains.
func TestPruneHostnamesFollowsRetention(t *testing.T) {
	setupTestDB(t)
	hostMu.Lock()
	hostSeen = map[string]map[string]bool{}
	hostMu.Unlock()
	eventRetentionDays = 30
	old := time.Now().AddDate(0, 0, -31).Format("2006-01-02 15:04:05")
	dbSaveHostname("1.1.1.1", "old.example", "dns", old)
	recordHostname("2.2.2.2", "fresh.example", srcDNS)

	pruneEvents()

	all := dbAllHostnames()
	if len(all["1.1.1.1"]) != 0 {
		t.Errorf("binding older than retention survived: %+v", all["1.1.1.1"])
	}
	if len(all["2.2.2.2"]) != 1 {
		t.Errorf("fresh binding was pruned: %+v", all["2.2.2.2"])
	}
	// The in-memory dedupe must forget what was pruned, or a binding still in
	// use could never be written again until a restart.
	db.Exec("DELETE FROM hostnames")
	pruneEvents()
	recordHostname("2.2.2.2", "fresh.example", srcDNS)
	if len(dbHostnames("2.2.2.2")) != 1 {
		t.Error("a pruned binding seen again was not re-recorded")
	}
}

// The database only ever grew: rows were pruned but pages never returned to the
// OS. Incremental auto-vacuum has to be on for both a fresh file and one created
// by an earlier build, which needs a one-time VACUUM to convert.
func TestIncrementalVacuumEnabled(t *testing.T) {
	setupTestDB(t)
	if got := pragmaInt(t, "auto_vacuum"); got != 2 {
		t.Errorf("fresh DB auto_vacuum=%d, want 2 (incremental)", got)
	}
	db.Close()

	// A pre-existing database written without auto_vacuum.
	appDir = t.TempDir()
	path := filepath.Join(appDir, "efemon.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec("CREATE TABLE events (epoch REAL, ts TEXT, kind TEXT, pid INTEGER, process TEXT, exe TEXT, local TEXT, remote TEXT, detail TEXT); INSERT INTO events VALUES (strftime('%s','now'),'','',0,'','','','','')"); err != nil { // a current epoch, or pruneEvents removes it
		t.Fatal(err)
	}
	legacy.Close()
	initDB()
	t.Cleanup(func() { db.Close() })
	if got := pragmaInt(t, "auto_vacuum"); got != 2 {
		t.Errorf("legacy DB auto_vacuum=%d after initDB, want 2", got)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil || n != 1 {
		t.Errorf("legacy rows lost in conversion: n=%d err=%v", n, err)
	}
}

func pragmaInt(t *testing.T, name string) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}
