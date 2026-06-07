package main

import (
	"sort"
	"sync"
	"time"
)

// Session state for operator actions (whitelist, IP whitelist, blocked IPs).
//
// These in-memory maps are the source of truth for the running instance. When
// the matching "permanent" setting is on, every change is also written through
// to SQLite so it survives restarts; when off, changes live only for this
// instance and are forgotten on exit.
//
// Whatever is already persisted in the DB is always loaded at startup, so a
// permanent entry made earlier stays active even in session-only mode. Removals
// always delete from the DB too, so an "unblock"/"un-whitelist" is honored.
var (
	stateMu      sync.RWMutex
	mWhitelist   = map[string]string{}  // exe -> added
	mIPWhitelist = map[string]string{}  // ip  -> added
	mBlocked     = map[string]Blocked{} // ip  -> record

	// Write-through toggles, independent per action type. Default on (the
	// historical behavior); set from Settings, persisted in .env.
	persistWhitelist = true // PERSIST_WHITELIST — binaries + IPs whitelist
	persistBlocks    = true // PERSIST_BLOCKS    — blocked IPs
)

// loadState seeds the session maps from whatever is persisted in the DB.
func loadState() {
	stateMu.Lock()
	defer stateMu.Unlock()
	mWhitelist = dbAllWhitelist()
	mIPWhitelist = dbAllIPWhitelist()
	mBlocked = map[string]Blocked{}
	for _, b := range dbAllBlocked() {
		mBlocked[b.IP] = b
	}
}

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

// flushWhitelist / flushBlocks persist the current session to the DB. Called when
// the user switches the matching "permanent" toggle on, so entries added while
// session-only also become permanent.
func flushWhitelist() {
	stateMu.RLock()
	defer stateMu.RUnlock()
	for exe, added := range mWhitelist {
		dbAddWhitelist(exe, added)
	}
	for ip, added := range mIPWhitelist {
		dbAddIPWhitelist(ip, added)
	}
}

func flushBlocks() {
	stateMu.RLock()
	defer stateMu.RUnlock()
	for _, b := range mBlocked {
		dbSaveBlocked(b.IP, b.At, b.Report)
	}
}

// ── Whitelist (binaries) ─────────────────────────────────────────────────────

func whitelist() map[string]bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	out := make(map[string]bool, len(mWhitelist))
	for exe := range mWhitelist {
		out[exe] = true
	}
	return out
}

func addWhitelist(exe string) {
	added := now()
	stateMu.Lock()
	mWhitelist[exe] = added
	stateMu.Unlock()
	if persistWhitelist {
		dbAddWhitelist(exe, added)
	}
}

func removeWhitelist(exe string) {
	stateMu.Lock()
	delete(mWhitelist, exe)
	stateMu.Unlock()
	dbRemoveWhitelist(exe)
}

func listWhitelist() []WLEntry {
	stateMu.RLock()
	out := make([]WLEntry, 0, len(mWhitelist))
	for exe, added := range mWhitelist {
		out = append(out, WLEntry{Exe: exe, Added: added})
	}
	stateMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Added > out[j].Added })
	return out
}

// ── IP whitelist ─────────────────────────────────────────────────────────────

func ipWhitelist() map[string]bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	out := make(map[string]bool, len(mIPWhitelist))
	for ip := range mIPWhitelist {
		out[ip] = true
	}
	return out
}

func addIPWhitelist(ip string) {
	added := now()
	stateMu.Lock()
	mIPWhitelist[ip] = added
	stateMu.Unlock()
	if persistWhitelist {
		dbAddIPWhitelist(ip, added)
	}
}

func removeIPWhitelist(ip string) {
	stateMu.Lock()
	delete(mIPWhitelist, ip)
	stateMu.Unlock()
	dbRemoveIPWhitelist(ip)
}

func listIPWhitelist() []WLIPEntry {
	stateMu.RLock()
	out := make([]WLIPEntry, 0, len(mIPWhitelist))
	for ip, added := range mIPWhitelist {
		out = append(out, WLIPEntry{IP: ip, Added: added})
	}
	stateMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Added > out[j].Added })
	return out
}

// ── Blocked IPs ──────────────────────────────────────────────────────────────

func saveBlocked(ip, report string) {
	b := Blocked{IP: ip, At: now(), Report: report}
	stateMu.Lock()
	mBlocked[ip] = b
	stateMu.Unlock()
	if persistBlocks {
		dbSaveBlocked(b.IP, b.At, b.Report)
	}
}

func deleteBlocked(ip string) {
	stateMu.Lock()
	delete(mBlocked, ip)
	stateMu.Unlock()
	dbDeleteBlocked(ip)
}

func listBlocked() []Blocked {
	stateMu.RLock()
	out := make([]Blocked, 0, len(mBlocked))
	for _, b := range mBlocked {
		out = append(out, b)
	}
	stateMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}
