package main

import "testing"

// The batch output is what PowerShell's ConvertTo-Json produces: a single
// object for one path, an array for several. Both must decode, and the
// version resource must land next to the signature.
func TestParseAuthenticodeJSON(t *testing.T) {
	one := []byte(`{"path":"C:\\Windows\\System32\\svchost.exe","status":"Valid","signer":"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond","company":"Microsoft Corporation","product":"Microsoft® Windows® Operating System","desc":"Host Process for Windows Services","version":"10.0.22621.1 (WinBuild.160101.0800)"}`)
	sigs, infos := parseAuthenticodeJSON(one)
	s := sigs[`C:\Windows\System32\svchost.exe`]
	if !s.Trusted || s.Signer != "Microsoft Windows" {
		t.Errorf("signature = %+v", s)
	}
	fi := infos[`C:\Windows\System32\svchost.exe`]
	if fi.Company != "Microsoft Corporation" || fi.Description != "Host Process for Windows Services" || fi.Version == "" {
		t.Errorf("fileinfo = %+v", fi)
	}
	if got := fi.String(); got != "Microsoft Corporation · Microsoft® Windows® Operating System · Host Process for Windows Services · v10.0.22621.1 (WinBuild.160101.0800)" {
		t.Errorf("String() = %q", got)
	}

	many := []byte(`[{"path":"C:\\a.exe","status":"NotSigned","signer":"","company":"","product":"","desc":"","version":""},` +
		`{"path":"C:\\b.exe","status":"HashMismatch","signer":"CN=Evil","company":" Acme ","product":"","desc":"","version":""}]`)
	sigs, infos = parseAuthenticodeJSON(many)
	if len(sigs) != 2 || sigs[`C:\a.exe`].Status != "NotSigned" || sigs[`C:\b.exe`].Trusted {
		t.Errorf("sigs = %+v", sigs)
	}
	if _, ok := infos[`C:\a.exe`]; ok {
		t.Error("an empty resource must not be stored")
	}
	if infos[`C:\b.exe`].Company != "Acme" {
		t.Errorf("company not trimmed: %q", infos[`C:\b.exe`].Company)
	}
	if s, i := parseAuthenticodeJSON([]byte("garbage")); len(s) != 0 || len(i) != 0 {
		t.Error("garbage must decode to nothing")
	}
}

func TestParseServiceLines(t *testing.T) {
	out := "1234\tDhcp\tDHCP Client\r\n1234\tEventLog\tWindows Event Log\r\n" +
		"5678\tEvilSvc\tEvilSvc\r\n0\tStopped\tNot running\r\nbroken\r\n"
	m := parseServiceLines(out)
	if len(m[1234]) != 2 || m[1234][0] != "Dhcp — DHCP Client" {
		t.Errorf("svchost services = %v", m[1234])
	}
	if len(m[5678]) != 1 || m[5678][0] != "EvilSvc" {
		t.Errorf("same name and display must not repeat: %v", m[5678])
	}
	if _, ok := m[0]; ok {
		t.Error("pid 0 (stopped) must be skipped")
	}
}

func TestFileInfoCache(t *testing.T) {
	setupTestDB(t)
	fi := FileInfo{Company: "Acme", Product: "Widget", Description: "Widget Service", Version: "1.2.3"}
	storeFileInfo(`C:\acme\w.exe`, 42, fi)
	got := fileInfoFor([]string{`C:\acme\w.exe`, `C:\other.exe`}, map[string]int64{`C:\acme\w.exe`: 42, `C:\other.exe`: 1})
	if got[`C:\acme\w.exe`] != fi || len(got) != 1 {
		t.Errorf("cache = %+v", got)
	}
	// A rebuilt file (new mtime) invalidates the entry.
	infoMu.Lock()
	clear(infoCache)
	infoMu.Unlock()
	if got := fileInfoFor([]string{`C:\acme\w.exe`}, map[string]int64{`C:\acme\w.exe`: 43}); len(got) != 0 {
		t.Errorf("stale entry served: %+v", got)
	}
}
