package main

import (
	"database/sql"
	"log"
	"os"
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

-- Hostnames observed bound to an address (TLS SNI or a DNS answer). One address
-- legitimately serves several names on a CDN, hence the composite key.
CREATE TABLE IF NOT EXISTS hostnames (
    ip TEXT, name TEXT, source TEXT, at TEXT,
    PRIMARY KEY (ip, name)
);
CREATE INDEX IF NOT EXISTS idx_hostnames_ip ON hostnames(ip);

-- Score change log: one row each time the risk of an (exe, remote ip) pair
-- changes, so the history can answer "what did this look like on Tuesday".
CREATE TABLE IF NOT EXISTS score_history (
    epoch REAL, at TEXT, exe TEXT, ip TEXT, threat INTEGER, breakdown TEXT
);
CREATE INDEX IF NOT EXISTS idx_score_history_epoch ON score_history(epoch);
`

func initDB() {
	var err error
	path := filepath.Join(appDir, "efemon.db")
	// WAL lets the audit/history reads proceed while the monitor is inserting,
	// and busy_timeout replaces an instant "database is locked" with a short wait.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	db.SetMaxOpenConns(1) // serialize access (modernc sqlite, simplest safe model)
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("db schema: %v", err)
	}
	// The DB holds the forensic history; don't leave it world-readable.
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		log.Printf("[!] no se pudieron ajustar los permisos de %s: %v", path, err)
	}
	pruneEvents()
}

// eventRetentionDays bounds the forensic history. The events table grows with
// every connection change; without a cap it grows for as long as the tool runs.
// 0 disables pruning (keep everything).
var eventRetentionDays = 30

// pruneEvents drops events older than the retention window and is called at
// startup and once a day by the monitor loop.
func pruneEvents() {
	if eventRetentionDays <= 0 {
		return
	}
	cutoff := float64(time.Now().AddDate(0, 0, -eventRetentionDays).Unix())
	res, err := db.Exec("DELETE FROM events WHERE epoch < ?", cutoff)
	if err != nil {
		log.Printf("[!] no se pudo purgar el histórico: %v", err)
		return
	}
	// The score timeline is bounded by the same window; it grows on the same
	// trigger (observed activity) and would otherwise outlive the events it explains.
	if _, err := db.Exec("DELETE FROM score_history WHERE epoch < ?", cutoff); err != nil {
		log.Printf("[!] no se pudo purgar el histórico de score: %v", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[+] histórico purgado: %d eventos con más de %d días", n, eventRetentionDays)
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

// ── Observed hostnames ───────────────────────────────────────────────────────

func dbSaveHostname(ip, name, source, at string) {
	// This runs from the packet-capture path, which is the one place in the app
	// that processes data at high rate; a nil handle here would panic the capture
	// goroutine rather than merely lose a row.
	if db == nil {
		return
	}
	// INSERT OR IGNORE: the first sighting keeps its timestamp, and an SNI binding
	// is not downgraded by a later DNS one.
	if _, err := db.Exec("INSERT OR IGNORE INTO hostnames VALUES (?,?,?,?)",
		ip, name, source, at); err != nil {
		log.Printf("[!] no se pudo guardar el hostname %s→%s: %v", ip, name, err)
	}
}

// Hostname is a name observed for an address.
type Hostname struct {
	Name   string `json:"name"`
	Source string `json:"source"` // "sni" (client-declared) or "dns" (answer record)
	At     string `json:"at"`
}

// dbHostnames returns the names seen for an address, SNI first (stronger binding).
func dbHostnames(ip string) []Hostname {
	if db == nil {
		return nil
	}
	rows, err := db.Query(
		`SELECT name, source, at FROM hostnames WHERE ip=?
		 ORDER BY CASE source WHEN 'sni' THEN 0 ELSE 1 END, at DESC LIMIT ?`,
		ip, maxHostnamesPerIP)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Hostname
	for rows.Next() {
		var h Hostname
		if err := rows.Scan(&h.Name, &h.Source, &h.At); err == nil {
			out = append(out, h)
		}
	}
	return out
}

// dbAllHostnames loads every binding as ip -> names, for one pass over the table.
func dbAllHostnames() map[string][]Hostname {
	out := map[string][]Hostname{}
	if db == nil {
		return out
	}
	rows, err := db.Query(
		`SELECT ip, name, source, at FROM hostnames
		 ORDER BY ip, CASE source WHEN 'sni' THEN 0 ELSE 1 END, at DESC`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var h Hostname
		if err := rows.Scan(&ip, &h.Name, &h.Source, &h.At); err != nil {
			continue
		}
		if len(out[ip]) < maxHostnamesPerIP {
			out[ip] = append(out[ip], h)
		}
	}
	return out
}

// ── Score history ────────────────────────────────────────────────────────────

// ScoreChange is one entry in the risk timeline of an (exe, ip) pair.
type ScoreChange struct {
	At        string `json:"at"`
	Exe       string `json:"exe"`
	IP        string `json:"ip"`
	Threat    int    `json:"threat"`
	Breakdown string `json:"breakdown"`
}

func dbSaveScoreChange(exe, ip string, threat int, breakdown string) {
	if _, err := db.Exec(
		"INSERT INTO score_history (epoch, at, exe, ip, threat, breakdown) VALUES (?,?,?,?,?,?)",
		float64(time.Now().UnixNano())/1e9, now(), exe, ip, threat, breakdown); err != nil {
		log.Printf("[!] no se pudo guardar el cambio de score: %v", err)
	}
}

// dbLastScore returns the most recent recorded score for a pair, so only actual
// changes are written.
func dbLastScore(exe, ip string) (int, string, bool) {
	var threat int
	var breakdown string
	err := db.QueryRow(
		"SELECT threat, breakdown FROM score_history WHERE exe=? AND ip=? ORDER BY epoch DESC LIMIT 1",
		exe, ip).Scan(&threat, &breakdown)
	return threat, breakdown, err == nil
}

func dbScoreHistory(limit int) []ScoreChange {
	rows, err := db.Query(
		`SELECT at, exe, ip, threat, breakdown FROM score_history
		 ORDER BY epoch DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ScoreChange
	for rows.Next() {
		var s ScoreChange
		if err := rows.Scan(&s.At, &s.Exe, &s.IP, &s.Threat, &s.Breakdown); err == nil {
			out = append(out, s)
		}
	}
	return out
}

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
