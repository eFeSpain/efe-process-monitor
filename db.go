package main

import (
	"database/sql"
	"log"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

const schema = `
CREATE TABLE IF NOT EXISTS events (
    epoch REAL, ts TEXT, kind TEXT, pid INTEGER, process TEXT,
    exe TEXT, local TEXT, remote TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(epoch);
CREATE TABLE IF NOT EXISTS hashes      (hash TEXT PRIMARY KEY, score TEXT, checked TEXT);
CREATE TABLE IF NOT EXISTS signatures  (exe TEXT PRIMARY KEY, mtime INTEGER, status TEXT, signer TEXT, trusted INTEGER);
CREATE TABLE IF NOT EXISTS baseline    (exe TEXT PRIMARY KEY, first_seen TEXT);
CREATE TABLE IF NOT EXISTS whitelist   (exe TEXT PRIMARY KEY, added TEXT);
CREATE TABLE IF NOT EXISTS ip_whitelist(ip TEXT PRIMARY KEY, added TEXT);
CREATE TABLE IF NOT EXISTS blocked     (ip TEXT PRIMARY KEY, at TEXT, report TEXT);
`

func initDB() {
	var err error
	db, err = sql.Open("sqlite", filepath.Join(appDir, "efemon.db"))
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	db.SetMaxOpenConns(1) // serialize access (modernc sqlite, simplest safe model)
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("db schema: %v", err)
	}
}

// ── Events / history ─────────────────────────────────────────────────────────

func logEvent(ev Event) {
	db.Exec(`INSERT INTO events (epoch, ts, kind, pid, process, exe, local, remote, detail)
	         VALUES (?,?,?,?,?,?,?,?,?)`,
		float64(time.Now().UnixNano())/1e9, ev.TS, ev.Kind, ev.PID, ev.Process,
		ev.Exe, ev.Local, ev.Remote, ev.Detail)
}

// clearEvents deletes timeline events matching optional criteria: of a given
// kind ("" = any), whose process name contains proc ("" = any), and/or older
// than olderSecs seconds (0 = any age). Returns the number of rows deleted.
func clearEvents(kind, proc string, olderSecs int) int {
	q := "DELETE FROM events WHERE 1=1"
	var args []any
	if kind != "" {
		q += " AND kind=?"
		args = append(args, kind)
	}
	if proc != "" {
		q += " AND process LIKE ?"
		args = append(args, "%"+proc+"%")
	}
	if olderSecs > 0 {
		q += " AND epoch < ?"
		args = append(args, float64(time.Now().Unix()-int64(olderSecs)))
	}
	res, err := db.Exec(q, args...)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return int(n)
}

func queryEvents(limit int, kind string) []Event {
	q := `SELECT ts, kind, pid, process, exe, local, remote, detail FROM events`
	args := []any{}
	if kind != "" {
		q += " WHERE kind=?"
		args = append(args, kind)
	}
	q += " ORDER BY epoch DESC LIMIT ?"
	args = append(args, limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		rows.Scan(&e.TS, &e.Kind, &e.PID, &e.Process, &e.Exe, &e.Local, &e.Remote, &e.Detail)
		out = append(out, e)
	}
	return out
}

// ── VT hash score cache ──────────────────────────────────────────────────────

func dbCachedHash(hash string) (string, bool) {
	var score string
	err := db.QueryRow("SELECT score FROM hashes WHERE hash=?", hash).Scan(&score)
	return score, err == nil
}

func dbSaveHash(hash, score string) {
	db.Exec("INSERT OR REPLACE INTO hashes VALUES (?,?,?)", hash, score,
		time.Now().Format("2006-01-02"))
}

// ── Signature cache ──────────────────────────────────────────────────────────

func dbCachedSignature(exe string, mtime int64) (Signature, bool) {
	var s Signature
	var m int64
	var trusted int
	err := db.QueryRow("SELECT mtime, status, signer, trusted FROM signatures WHERE exe=?", exe).
		Scan(&m, &s.Status, &s.Signer, &trusted)
	if err != nil || m != mtime {
		return Signature{}, false
	}
	s.Trusted = trusted == 1
	return s, true
}

func dbSaveSignature(exe string, mtime int64, s Signature) {
	t := 0
	if s.Trusted {
		t = 1
	}
	db.Exec("INSERT OR REPLACE INTO signatures VALUES (?,?,?,?,?)", exe, mtime, s.Status, s.Signer, t)
}

// ── Baseline ─────────────────────────────────────────────────────────────────

func baselineSeen(exe string) bool {
	if exe == "" || exe == "N/A" || exe == "ACCESS_DENIED" {
		return true
	}
	var x int
	if db.QueryRow("SELECT 1 FROM baseline WHERE exe=?", exe).Scan(&x) == nil {
		return true
	}
	db.Exec("INSERT OR IGNORE INTO baseline VALUES (?,?)", exe, time.Now().Format("2006-01-02 15:04:05"))
	return false
}

// These are the pure SQLite persistence layer. The session-aware public API
// (whitelist/addWhitelist/saveBlocked/…) lives in store.go and decides, per the
// "permanent actions" setting, whether changes are written through to here.

// ── Whitelist (binaries) ─────────────────────────────────────────────────────

type WLEntry struct {
	Exe   string `json:"exe"`
	Added string `json:"added"`
}

func dbAllWhitelist() map[string]string {
	out := map[string]string{}
	rows, err := db.Query("SELECT exe, added FROM whitelist")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var exe, added string
		rows.Scan(&exe, &added)
		out[exe] = added
	}
	return out
}

func dbAddWhitelist(exe, added string) {
	db.Exec("INSERT OR REPLACE INTO whitelist VALUES (?,?)", exe, added)
}

func dbRemoveWhitelist(exe string) { db.Exec("DELETE FROM whitelist WHERE exe=?", exe) }

// ── IP whitelist ─────────────────────────────────────────────────────────────

type WLIPEntry struct {
	IP    string `json:"ip"`
	Added string `json:"added"`
}

func dbAllIPWhitelist() map[string]string {
	out := map[string]string{}
	rows, err := db.Query("SELECT ip, added FROM ip_whitelist")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ip, added string
		rows.Scan(&ip, &added)
		out[ip] = added
	}
	return out
}

func dbAddIPWhitelist(ip, added string) {
	db.Exec("INSERT OR REPLACE INTO ip_whitelist VALUES (?,?)", ip, added)
}

func dbRemoveIPWhitelist(ip string) { db.Exec("DELETE FROM ip_whitelist WHERE ip=?", ip) }

// ── Blocked IPs ──────────────────────────────────────────────────────────────

type Blocked struct {
	IP     string `json:"ip"`
	At     string `json:"at"`
	Report string `json:"report"`
}

func dbSaveBlocked(ip, at, report string) {
	db.Exec("INSERT OR REPLACE INTO blocked VALUES (?,?,?)", ip, at, report)
}

func dbDeleteBlocked(ip string) { db.Exec("DELETE FROM blocked WHERE ip=?", ip) }

func dbAllBlocked() []Blocked {
	rows, err := db.Query("SELECT ip, at, report FROM blocked ORDER BY at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Blocked
	for rows.Next() {
		var b Blocked
		rows.Scan(&b.IP, &b.At, &b.Report)
		out = append(out, b)
	}
	return out
}
