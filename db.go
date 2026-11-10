package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
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
-- The details block asks about each process on every render (activity in the
-- last 24 h, first and last event): by exe, so that is a seek and not a scan
-- of the whole retained history per PID.
CREATE INDEX IF NOT EXISTS idx_events_exe ON events(exe, epoch);
CREATE TABLE IF NOT EXISTS hashes      (hash TEXT PRIMARY KEY, score TEXT, checked TEXT);
CREATE TABLE IF NOT EXISTS signatures  (exe TEXT PRIMARY KEY, mtime INTEGER, status TEXT, signer TEXT, trusted INTEGER);
CREATE TABLE IF NOT EXISTS fileinfo    (exe TEXT PRIMARY KEY, mtime INTEGER, company TEXT, product TEXT, description TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS baseline    (exe TEXT PRIMARY KEY, first_seen TEXT);
-- Baseline keyed by content as well as path: a binary swapped in place is the
-- most common persistence move, and a path-only baseline never noticed it.
-- The path-only table is kept and still written, so a downgrade keeps working
-- and pre-upgrade rows are adopted instead of re-announced as new.
CREATE TABLE IF NOT EXISTS baseline_hash (exe TEXT, hash TEXT, first_seen TEXT, PRIMARY KEY (exe, hash));
-- Who has been seen listening on what (newlisten.go): program + protocol/port.
CREATE TABLE IF NOT EXISTS listen_baseline (key TEXT PRIMARY KEY, first_seen TEXT);
-- Live browser sessions, by the SHA-256 of their token (auth.go): they survive
-- a restart, and the file never holds something usable as a cookie.
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires INTEGER);
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

-- Every audit item ever seen, with when it first appeared: the panel marks
-- what is new against this, so "14 Run keys" becomes "one that wasn't there".
CREATE TABLE IF NOT EXISTS audit_seen (key TEXT, item TEXT, first_seen REAL, PRIMARY KEY (key, item));

-- Score change log: one row each time the risk of an (exe, remote ip) pair
-- changes, so the history can answer "what did this look like on Tuesday".
CREATE TABLE IF NOT EXISTS score_history (
    epoch REAL, at TEXT, exe TEXT, ip TEXT, threat INTEGER, breakdown TEXT
);
CREATE INDEX IF NOT EXISTS idx_score_history_epoch ON score_history(epoch);
-- recordScoreChange reads the last verdict of every (exe, ip) pair on every
-- render; without this each of those reads was a full scan.
CREATE INDEX IF NOT EXISTS idx_score_history_pair ON score_history(exe, ip, epoch);
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
	ensureIncrementalVacuum()
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("db schema: %v", err)
	}
	migrateAuditSeen()
	// The DB holds the forensic history; don't leave it world-readable.
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		log.Printf("[!] no se pudieron ajustar los permisos de %s: %v", path, err)
	}
	pruneEvents()
}

// ensureIncrementalVacuum switches the file to incremental auto-vacuum. The
// retention pruning deleted rows, but SQLite never returned the pages to the
// OS, so efemon.db only ever grew. The mode lives in the file: a fresh
// database takes it directly, one written by an earlier build needs a
// one-time VACUUM to convert — seconds, once, at start-up.
func ensureIncrementalVacuum() {
	var mode int
	if err := db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil || mode == 2 {
		return
	}
	if _, err := db.Exec("PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		log.Printf("[!] auto_vacuum: %v", err)
		return
	}
	if _, err := db.Exec("VACUUM"); err != nil {
		log.Printf("[!] no se pudo compactar la base de datos: %v", err)
	}
}

// rowsDone reports an error that ended a row scan early. rows.Next returning
// false can mean "no more rows" or "the read failed"; without this the history
// could come back silently truncated.
func rowsDone(rows *sql.Rows, what string) {
	if err := rows.Err(); err != nil {
		log.Printf("[!] lectura incompleta de %s: %v", what, err)
	}
}

// eventRetentionDays bounds the forensic history. The events table grows with
// every connection change; without a cap it grows for as long as the tool runs.
// 0 disables pruning (keep everything).
// Atomic: Settings writes it while the monitor goroutine prunes.
var eventRetentionDays atomic.Int64

func init() { eventRetentionDays.Store(30) }

// setEventRetention changes the retention window (days; 0 = keep forever) and
// persists it as EVENT_RETENTION_DAYS. It takes effect at the next prune
// (start-up and daily).
func setEventRetention(n int) {
	if n < 0 {
		n = 0
	}
	if n > 3650 {
		n = 3650
	}
	eventRetentionDays.Store(int64(n))
	writeEnv(map[string]string{"EVENT_RETENTION_DAYS": strconv.Itoa(n)})
}

// pruneEvents drops events older than the retention window and is called at
// startup and once a day by the monitor loop.
func pruneEvents() {
	days := int(eventRetentionDays.Load())
	if days <= 0 {
		return
	}
	cutoffAt := time.Now().AddDate(0, 0, -days)
	cutoff := float64(cutoffAt.Unix())
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
	pruneHostnames(cutoffAt)
	// auto_vacuum=INCREMENTAL only marks freed pages; this hands them back.
	if _, err := db.Exec("PRAGMA incremental_vacuum"); err != nil {
		log.Printf("[!] incremental_vacuum: %v", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[+] histórico purgado: %d eventos con más de %d días", n, days)
	}
}

// ── Events / history ─────────────────────────────────────────────────────────

func logEvent(ev Event) {
	db.Exec(`INSERT INTO events (epoch, ts, kind, pid, process, exe, local, remote, detail)
	         VALUES (?,?,?,?,?,?,?,?,?)`,
		float64(time.Now().UnixNano())/1e9, ev.TS, ev.Kind, ev.PID, ev.Process,
		ev.Exe, ev.Local, ev.Remote, ev.Detail)
}

// eventFilter selects events of the history: the list, the exports and the
// deletion all go through it, so what is on screen is what gets exported or
// deleted.
type eventFilter struct {
	Text    string  // every word must appear in the process, path, addresses or detail (or be the PID)
	Kind    string  // exact kind ("" = any)
	Process string  // process name contains (the older, narrower filter)
	From    float64 // epoch >= From (0 = open)
	To      float64 // epoch <  To   (0 = open)
	Before  int64   // paging cursor: only rows older than this one (0 = from the newest)
	Limit   int     // page size (0 = 200)
}

// HistEvent is an event as the history shows it: with the day it happened
// (Event.TS is only the time, which is all the live feed needs) and the row
// id the paging cursor is made of.
type HistEvent struct {
	Event
	At string `json:"at"`
	ID int64  `json:"id"`
}

const (
	maxSearchWords = 8
	likeEsc        = ` ESCAPE '\'`
)

// likePattern makes s a literal "contains" pattern: % and _ typed by the
// operator are characters to look for, not wildcards.
func likePattern(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

// where builds the WHERE clause. Only fixed SQL is concatenated; every value
// the operator typed travels as a parameter.
func (f eventFilter) where() (string, []any) {
	q := " WHERE 1=1"
	var args []any
	words := strings.Fields(f.Text)
	if len(words) > maxSearchWords {
		words = words[:maxSearchWords]
	}
	for _, w := range words {
		pat := likePattern(w)
		q += " AND (process LIKE ?" + likeEsc + " OR exe LIKE ?" + likeEsc + " OR local LIKE ?" + likeEsc +
			" OR remote LIKE ?" + likeEsc + " OR detail LIKE ?" + likeEsc
		args = append(args, pat, pat, pat, pat, pat)
		if pid, err := strconv.Atoi(w); err == nil {
			q += " OR pid=?"
			args = append(args, pid)
		}
		q += ")"
	}
	if f.Kind != "" {
		q += " AND kind=?"
		args = append(args, f.Kind)
	}
	if f.Process != "" {
		q += " AND process LIKE ?" + likeEsc
		args = append(args, likePattern(f.Process))
	}
	if f.From > 0 {
		q += " AND epoch>=?"
		args = append(args, f.From)
	}
	if f.To > 0 {
		q += " AND epoch<?"
		args = append(args, f.To)
	}
	if f.Before > 0 {
		q += " AND rowid<?"
		args = append(args, f.Before)
	}
	return q, args
}

// searchEvents returns one page of the history, newest first, and the cursor
// for the next page (0 when there is none). Rows are inserted in the order
// things happen, so the row id is the paging order: no two rows share it,
// which a timestamp cannot promise.
func searchEvents(f eventFilter) (evs []HistEvent, next int64) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	where, args := f.where()
	// #nosec G202 G701 -- where() concatenates only fixed SQL; every value is a bound parameter.
	rows, err := db.Query("SELECT rowid, epoch, ts, kind, pid, process, exe, local, remote, detail FROM events"+
		where+" ORDER BY rowid DESC LIMIT ?", append(args, limit+1)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	for rows.Next() {
		var e HistEvent
		var epoch float64
		if rows.Scan(&e.ID, &epoch, &e.TS, &e.Kind, &e.PID, &e.Process, &e.Exe, &e.Local, &e.Remote, &e.Detail) != nil {
			continue
		}
		e.At = time.Unix(int64(epoch), 0).Format("2006-01-02 15:04:05")
		evs = append(evs, e)
	}
	rowsDone(rows, "history")
	if len(evs) > limit { // one more than asked for: there is another page
		evs = evs[:limit]
		next = evs[limit-1].ID
	}
	return evs, next
}

// deleteEvents deletes the events matching the filter and, when olderSecs is
// set, older than that many seconds. Returns the number of rows deleted.
func deleteEvents(f eventFilter, olderSecs int) int {
	f.Before = 0 // a paging cursor is not a deletion criterion
	where, args := f.where()
	if olderSecs > 0 {
		where += " AND epoch<?"
		args = append(args, float64(time.Now().Unix()-int64(olderSecs)))
	}
	// #nosec G202 G701 -- where() concatenates only fixed SQL; every value is a bound parameter.
	res, err := db.Exec("DELETE FROM events"+where, args...)
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
	rowsDone(rows, "events")
	return out
}

// eventStats summarizes the events of one binary.
type eventStats struct {
	ips, events int    // distinct public remotes / events since the cutoff
	first, last string // bounds over the whole retained history
}

// dbEventStats counts a binary's activity: distinct public remote hosts and
// events since `since`, and the first and last event ever retained. The
// remote column is "ip:port"; the host is what is counted, so every port of
// one address is one remote.
func dbEventStats(exe string, since time.Time) eventStats {
	var st eventStats
	rows, err := db.Query("SELECT remote FROM events WHERE exe=? AND epoch>=? AND remote<>''",
		exe, float64(since.UnixNano())/1e9)
	if err != nil {
		return st
	}
	hosts := map[string]bool{}
	for rows.Next() {
		var r string
		if rows.Scan(&r) != nil {
			continue
		}
		st.events++
		if h := remoteHost(r); h != "" && !isPrivateIP(h) {
			hosts[h] = true
		}
	}
	rowsDone(rows, "event stats")
	rows.Close()
	st.ips = len(hosts)
	db.QueryRow("SELECT ts FROM events WHERE exe=? ORDER BY epoch ASC LIMIT 1", exe).Scan(&st.first)
	db.QueryRow("SELECT ts FROM events WHERE exe=? ORDER BY epoch DESC LIMIT 1", exe).Scan(&st.last)
	return st
}

// dbScoreChangeCount is how many times the recorded risk of this binary (any
// remote) has moved.
func dbScoreChangeCount(exe string) int {
	var n int
	db.QueryRow("SELECT count(*) FROM score_history WHERE exe=?", exe).Scan(&n)
	return n
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

// ── Version resource cache (Windows) ─────────────────────────────────────────

func dbCachedFileInfo(exe string, mtime int64) (FileInfo, bool) {
	var fi FileInfo
	var m int64
	err := db.QueryRow("SELECT mtime, company, product, description, version FROM fileinfo WHERE exe=?", exe).
		Scan(&m, &fi.Company, &fi.Product, &fi.Description, &fi.Version)
	if err != nil || m != mtime {
		return FileInfo{}, false
	}
	return fi, true
}

func dbSaveFileInfo(exe string, mtime int64, fi FileInfo) {
	db.Exec("INSERT OR REPLACE INTO fileinfo VALUES (?,?,?,?,?,?)", exe, mtime, fi.Company, fi.Product, fi.Description, fi.Version)
}

// ── Baseline ─────────────────────────────────────────────────────────────────

// baselineSeen reports whether this exact binary — path and content hash — has
// been seen before, recording it if not. changed is true when the path was
// already known with a different hash: the file was replaced on disk, which is
// a stronger signal than a new binary. An unreadable file (hash "") falls back
// to the path-only judgement, because "it changed" cannot be claimed.
func baselineSeen(exe, hash string) (seen, changed bool) {
	if exe == "" || exe == "N/A" || exe == "ACCESS_DENIED" {
		return true, false
	}
	if hash == "" {
		hash = "?"
	}
	var x int
	if db.QueryRow("SELECT 1 FROM baseline_hash WHERE exe=? AND hash=?", exe, hash).Scan(&x) == nil {
		return true, false
	}
	pathKnown := db.QueryRow("SELECT 1 FROM baseline_hash WHERE exe=?", exe).Scan(&x) == nil
	if pathKnown && hash == "?" {
		return true, false // known path, content unreadable now: no claim either way
	}
	// A row in the path-only table with nothing in baseline_hash is from before
	// the upgrade: adopt the current content silently rather than announcing
	// every binary on the machine as new once.
	legacy := !pathKnown && db.QueryRow("SELECT 1 FROM baseline WHERE exe=?", exe).Scan(&x) == nil
	now := time.Now().Format("2006-01-02 15:04:05")
	db.Exec("INSERT OR IGNORE INTO baseline_hash VALUES (?,?,?)", exe, hash, now)
	db.Exec("INSERT OR IGNORE INTO baseline VALUES (?,?)", exe, now)
	switch {
	case pathKnown:
		return false, true
	case legacy:
		return true, false
	default:
		return false, false
	}
}

// ── Sessions (see auth.go) ───────────────────────────────────────────────────
//
// db is nil until initDB: a session minted before that (or in a test that
// never opens a database) simply is not persisted.

func dbSaveSession(key string, exp time.Time) {
	if db != nil {
		db.Exec("INSERT OR REPLACE INTO sessions VALUES (?,?)", key, exp.Unix())
	}
}

func dbDeleteSession(key string) {
	if db != nil {
		db.Exec("DELETE FROM sessions WHERE token_hash=?", key)
	}
}

func dbClearSessions() {
	if db != nil {
		db.Exec("DELETE FROM sessions")
	}
}

func dbPruneSessions(now time.Time) {
	if db != nil {
		db.Exec("DELETE FROM sessions WHERE expires <= ?", now.Unix())
	}
}

func dbLoadSessions() map[string]time.Time {
	out := map[string]time.Time{}
	if db == nil {
		return out
	}
	rows, err := db.Query("SELECT token_hash, expires FROM sessions")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var exp int64
		if rows.Scan(&k, &exp) == nil {
			out[k] = time.Unix(exp, 0)
		}
	}
	rowsDone(rows, "sessions")
	return out
}

// dbListenBaseline loads every program+port ever seen listening.
func dbListenBaseline() map[string]bool {
	out := map[string]bool{}
	rows, err := db.Query("SELECT key FROM listen_baseline")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out[k] = true
		}
	}
	rowsDone(rows, "listen_baseline")
	return out
}

func dbListenAdd(key string) {
	db.Exec("INSERT OR IGNORE INTO listen_baseline VALUES (?,?)", key, time.Now().Format("2006-01-02 15:04:05"))
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
	rowsDone(rows, "whitelist")
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
	rowsDone(rows, "ip whitelist")
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
	rowsDone(rows, "hostnames")
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
	rowsDone(rows, "hostnames")
	return out
}

// ── Audit history ────────────────────────────────────────────────────────────

// dbAuditSeen loads every (check key, item) with its first-seen time. hadHistory
// is false on a machine that has never been scanned, so the first scan can
// avoid marking everything as new.
func dbAuditSeen() (seen map[string]map[string]time.Time, hadHistory bool) {
	seen = map[string]map[string]time.Time{}
	rows, err := db.Query("SELECT key, item, first_seen FROM audit_seen")
	if err != nil {
		return seen, false
	}
	defer rows.Close()
	for rows.Next() {
		var k, it string
		var first float64
		if rows.Scan(&k, &it, &first) != nil {
			continue
		}
		if seen[k] == nil {
			seen[k] = map[string]time.Time{}
		}
		seen[k][it] = time.Unix(0, int64(first*1e9))
		hadHistory = true
	}
	rowsDone(rows, "audit_seen")
	return seen, hadHistory
}

// dbBaselineFirstSeen returns when this exact binary (path + hash) was first
// recorded, falling back to the path-only table for pre-upgrade rows. Zero
// when never seen.
func dbBaselineFirstSeen(exe, hash string) time.Time {
	if hash == "" {
		hash = "?"
	}
	var s string
	err := db.QueryRow("SELECT first_seen FROM baseline_hash WHERE exe=? AND hash=?", exe, hash).Scan(&s)
	if err != nil {
		// The path-only table only answers for a path that has no content
		// rows at all (written before the upgrade). A known path with a new
		// hash is a different binary: its first sighting is not yet recorded.
		var n int
		if db.QueryRow("SELECT count(*) FROM baseline_hash WHERE exe=?", exe).Scan(&n) == nil && n > 0 {
			return time.Time{}
		}
		err = db.QueryRow("SELECT first_seen FROM baseline WHERE exe=?", exe).Scan(&s)
	}
	if err != nil {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}

func dbAuditMarkSeen(key, item string, at time.Time) {
	db.Exec("INSERT OR IGNORE INTO audit_seen VALUES (?,?,?)", key, item, float64(at.UnixNano())/1e9)
}

// migrateAuditSeen folds rows written by earlier builds, which carried the
// PID in the item, into the PID-less key auditItemKey produces now. The
// earliest sighting wins, so an upgrade does not re-announce every running
// process as new. Idempotent: once no row contains "(pid N)" it does nothing.
func migrateAuditSeen() {
	rows, err := db.Query("SELECT key, item, first_seen FROM audit_seen WHERE item LIKE '%(pid %'")
	if err != nil {
		return
	}
	type legacy struct {
		key, item string
		first     float64
	}
	var old []legacy
	for rows.Next() {
		var l legacy
		if rows.Scan(&l.key, &l.item, &l.first) == nil {
			old = append(old, l)
		}
	}
	rowsDone(rows, "audit_seen migration")
	rows.Close()
	for _, l := range old {
		k := auditItemKey(l.item)
		if k == l.item {
			continue // already normalized (contains "(pid)")
		}
		db.Exec("INSERT OR IGNORE INTO audit_seen VALUES (?,?,?)", l.key, k, l.first)
		db.Exec("UPDATE audit_seen SET first_seen = ? WHERE key=? AND item=? AND first_seen > ?", l.first, l.key, k, l.first)
		db.Exec("DELETE FROM audit_seen WHERE key=? AND item=?", l.key, l.item)
	}
	if len(old) > 0 {
		log.Printf("[+] audit_seen: %d filas antiguas con PID normalizadas", len(old))
	}
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
	rowsDone(rows, "score history")
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
	rowsDone(rows, "blocked")
	return out
}
