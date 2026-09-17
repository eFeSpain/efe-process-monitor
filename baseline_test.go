package main

import "testing"

// The baseline is keyed by content, not just path: replacing a binary in place
// is the most common persistence move, and the old path-only baseline never
// noticed it.
func TestBaselineByHash(t *testing.T) {
	setupTestDB(t)
	const exe = `C:\Program Files\App\app.exe`

	if seen, changed := baselineSeen(exe, "aaa"); seen || changed {
		t.Errorf("first sighting: seen=%v changed=%v, want false/false", seen, changed)
	}
	if seen, changed := baselineSeen(exe, "aaa"); !seen || changed {
		t.Errorf("same binary again: seen=%v changed=%v, want true/false", seen, changed)
	}
	// Same path, different bytes.
	if seen, changed := baselineSeen(exe, "bbb"); seen || !changed {
		t.Errorf("replaced binary: seen=%v changed=%v, want false/true", seen, changed)
	}
	// Both versions are now known; going back is not "new" either.
	if seen, _ := baselineSeen(exe, "aaa"); !seen {
		t.Error("a previously seen version must stay seen")
	}
	// Unreadable now, path known: no claim.
	if seen, changed := baselineSeen(exe, ""); !seen || changed {
		t.Errorf("unreadable known path: seen=%v changed=%v, want true/false", seen, changed)
	}
	// Unreadable and unknown: path-only, like before.
	if seen, changed := baselineSeen("/opt/x/y", ""); seen || changed {
		t.Errorf("unreadable new path: seen=%v changed=%v, want false/false", seen, changed)
	}
	if seen, _ := baselineSeen("/opt/x/y", ""); !seen {
		t.Error("unreadable path seen twice must be known")
	}
}

// Rows written by earlier builds only exist in the path-only table. They are
// adopted silently: an upgrade must not announce every binary as new, and it
// cannot claim a change it never measured.
func TestBaselineAdoptsLegacyRows(t *testing.T) {
	setupTestDB(t)
	db.Exec("INSERT INTO baseline VALUES (?,?)", "/usr/bin/legacy", "2025-01-01 00:00:00")

	if seen, changed := baselineSeen("/usr/bin/legacy", "h1"); !seen || changed {
		t.Errorf("legacy row: seen=%v changed=%v, want true/false", seen, changed)
	}
	// From now on it is content-tracked like any other.
	if seen, changed := baselineSeen("/usr/bin/legacy", "h2"); seen || !changed {
		t.Errorf("legacy binary replaced: seen=%v changed=%v, want false/true", seen, changed)
	}
}
