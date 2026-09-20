package main

import (
	"encoding/json"
	"strings"
	"sync"
)

// FileInfo is the version resource of a Windows executable: what the file
// says about itself. Cheap context and, next to the signature, a lie
// detector — "Microsoft Corporation" in the resource with no Microsoft
// signature, or an svchost.exe whose description is blank. ELF binaries carry
// nothing comparable, so on Linux this is always absent.
type FileInfo struct {
	Company     string
	Product     string
	Description string
	Version     string
}

func (f FileInfo) empty() bool {
	return f.Company == "" && f.Product == "" && f.Description == "" && f.Version == ""
}

// String renders the non-empty fields for the details line.
func (f FileInfo) String() string {
	var parts []string
	for _, s := range []string{f.Company, f.Product, f.Description} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if f.Version != "" {
		parts = append(parts, "v"+f.Version)
	}
	return strings.Join(parts, " · ")
}

// The resource is read in the same PowerShell batch that resolves Authenticode
// (see queryAuthenticode) and cached alongside it: memory first, SQLite second,
// both keyed by path + mtime.
type infoEntry struct {
	mtime int64
	info  FileInfo
}

var (
	infoMu    sync.Mutex
	infoCache = map[string]infoEntry{}
)

// fileInfoFor returns the cached resource for each path. Nothing is queued
// here: the signature queue already carries every unknown path, and the
// batch that resolves it stores the resource too.
func fileInfoFor(paths []string, mtimes map[string]int64) map[string]FileInfo {
	out := map[string]FileInfo{}
	for _, p := range paths {
		mt, ok := mtimes[p]
		if !ok {
			continue
		}
		infoMu.Lock()
		e, hit := infoCache[p]
		infoMu.Unlock()
		if hit && e.mtime == mt {
			out[p] = e.info
			continue
		}
		if fi, ok := dbCachedFileInfo(p, mt); ok {
			out[p] = fi
			infoMu.Lock()
			infoCache[p] = infoEntry{mt, fi}
			infoMu.Unlock()
		}
	}
	return out
}

func storeFileInfo(p string, mtime int64, fi FileInfo) {
	infoMu.Lock()
	capMap(infoCache, maxPathCache)
	infoCache[p] = infoEntry{mtime, fi}
	infoMu.Unlock()
	dbSaveFileInfo(p, mtime, fi)
}

// authenticodeRow is one object of the batch's JSON output.
type authenticodeRow struct {
	Path, Status, Signer            string
	Company, Product, Desc, Version string
}

// parseAuthenticodeJSON decodes the batch output — one object or an array —
// into signatures and version resources per path. Pure, for the fixture test.
func parseAuthenticodeJSON(out []byte) (sigs map[string]Signature, infos map[string]FileInfo) {
	sigs, infos = map[string]Signature{}, map[string]FileInfo{}
	trimmed := strings.TrimSpace(string(out))
	if strings.HasPrefix(trimmed, "{") {
		trimmed = "[" + trimmed + "]"
	}
	var rows []authenticodeRow
	if json.Unmarshal([]byte(trimmed), &rows) != nil {
		return sigs, infos
	}
	for _, r := range rows {
		signer := cnFromSubject(r.Signer)
		sigs[r.Path] = Signature{
			Status:  r.Status,
			Signer:  signer,
			Trusted: r.Status == "Valid" && signer != "",
		}
		fi := FileInfo{Company: strings.TrimSpace(r.Company), Product: strings.TrimSpace(r.Product),
			Description: strings.TrimSpace(r.Desc), Version: strings.TrimSpace(r.Version)}
		if !fi.empty() {
			infos[r.Path] = fi
		}
	}
	return sigs, infos
}
