//go:build linux

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The unit is what systemd runs at boot; every line here is a decision from
// the spec. No sandboxing directives: raw sockets, /proc, nft and setuid all
// need them off.
func TestUnitFile(t *testing.T) {
	u := unitFile("/opt/efemon/efemon", "")
	for _, want := range []string{
		"[Unit]", "Description=eFe Process Monitor", "After=network-online.target", "Wants=network-online.target",
		"[Service]", "Type=simple", "ExecStart=/opt/efemon/efemon --service", "WorkingDirectory=/opt/efemon",
		"Restart=on-failure", "RestartSec=2", "[Install]", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want+"\n") {
			t.Errorf("unit lacks line %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "Environment=") {
		t.Error("no migration line without a source directory")
	}
	// systemd.exec(5): Environment= is unquoted and specifier-expanded, so the
	// whole assignment is quoted and % is doubled — a path with a space used to
	// silently truncate to its first word and the migration moved nothing.
	if m := unitFile("/opt/efemon/efemon", "/home/efe/Proyectos Claude/50%"); !strings.Contains(m, "Environment=\"EFEMON_MIGRATE_FROM=/home/efe/Proyectos Claude/50%%\"\n") {
		t.Errorf("migration line must be quoted and %%-escaped:\n%s", m)
	}
	// systemd's default start-rate limit (5 in 10 s) would turn a transient
	// port conflict into a permanently failed unit.
	if !strings.Contains(u, "StartLimitIntervalSec=0\n") {
		t.Error("unit must disable the start-rate limit")
	}
	if strings.Contains(u, "ProtectSystem") || strings.Contains(u, "NoNewPrivileges") {
		t.Error("no systemd sandboxing: raw sockets, /proc, nft and setuid all need it off")
	}
}

// Installing moves the data store next to the installed binary — move, not
// copy, so there is one forensic history, never two drifting apart — and never
// touches what is regenerated (token, logs) or already present at the target.
func TestMigrationPlanAndMigrate(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, f := range []string{".env", "efemon.db", "efemon.db-wal", "efemon-token", "efemon.log", "icon.png", "efemon-cert.pem"} {
		os.WriteFile(filepath.Join(src, f), []byte(f), 0o600)
	}
	os.WriteFile(filepath.Join(dst, ".env"), []byte("keep"), 0o600) // already there: never overwritten
	plan := migrationPlan(src, dst)
	sort.Strings(plan)
	if want := []string{"efemon-cert.pem", "efemon.db", "efemon.db-wal"}; strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("plan = %v, want %v", plan, want)
	}
	moved, err := migrateData(src, dst)
	if err != nil || len(moved) != 3 {
		t.Fatalf("migrate: %v %v", moved, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, ".env")); string(b) != "keep" {
		t.Error("existing .env in dst was overwritten")
	}
	if _, err := os.Stat(filepath.Join(src, "efemon.db")); !os.IsNotExist(err) {
		t.Error("moved file still in src (must be a move, not a copy)")
	}
	if _, err := os.Stat(filepath.Join(src, "efemon-token")); err != nil {
		t.Error("token must never be migrated")
	}
	if migrationPlan(filepath.Join(src, "missing"), dst) != nil || migrationPlan(dst, dst) != nil {
		t.Error("missing or identical source must yield no plan")
	}
}

// Reinstalling from /opt/efemon/efemon itself must not copy the running binary
// onto itself — that truncates it.
func TestCopyExecutableSameFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "efemon")
	os.WriteFile(p, []byte("binary"), 0o755)
	if err := copyExecutable(p, p); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "binary" {
		t.Fatal("copying a file onto itself truncated it")
	}
	q := filepath.Join(dir, "copy")
	if err := copyExecutable(p, q); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(q); fi.Mode().Perm() != 0o755 {
		t.Errorf("copy mode = %v, want 0755", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(q); string(b) != "binary" {
		t.Error("copy content differs")
	}
}

// `systemctl is-active` prints one word; only "active" means running.
func TestParseIsActive(t *testing.T) {
	for out, want := range map[string]bool{"active\n": true, "inactive\n": false, "failed": false, "": false, "activating\n": false} {
		if got := parseIsActive(out); got != want {
			t.Errorf("parseIsActive(%q) = %v, want %v", out, got, want)
		}
	}
}

// The data moves with whatever mode the user's editor gave it; in a 0755
// directory (the tray helper runs as the user and must traverse it) every
// moved file must end up owner-only.
func TestMigrateDataTightensMode(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(src, ".env"), []byte("VT_API_KEY=x"), 0o644)
	os.WriteFile(filepath.Join(src, "efemon.db"), []byte("db"), 0o664)
	if _, err := migrateData(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".env", "efemon.db"} {
		fi, err := os.Stat(filepath.Join(dst, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", f, fi.Mode().Perm())
		}
	}
	if serviceDirMode != 0o755 {
		t.Errorf("serviceDir mode = %o, want 0755: the helper execs /opt/efemon/efemon as the user", serviceDirMode)
	}
}

// Uninstalling from inside the running service: `disable --now` would kill this
// very process before the unit file is removed, leaving a stopped unit that
// still reads as "installed". The step that kills us goes last.
func TestUninstallStepsStopLast(t *testing.T) {
	var steps []string
	run := func(args ...string) (string, error) {
		steps = append(steps, "systemctl "+strings.Join(args, " "))
		return "", nil
	}
	remove := func(p string) error { steps = append(steps, "rm "+p); return nil }
	if err := uninstallServiceSteps(run, remove); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl disable efemon.service", "rm " + unitPath, "rm " + serviceLink, "systemctl daemon-reload", "systemctl stop efemon.service"}
	if strings.Join(steps, "|") != strings.Join(want, "|") {
		t.Errorf("steps:\n got %q\nwant %q", steps, want)
	}
}

// `sudo efemon` after an install finds the port busy and hands off to the
// service: the token it must read is the service's, under /opt/efemon, not a
// stale one next to whichever binary was launched.
func TestHandoffDir(t *testing.T) {
	if got := handoffDir("/home/efe/Downloads", true, true); got != serviceDir {
		t.Errorf("root + installed: %q, want %q", got, serviceDir)
	}
	if got := handoffDir("/home/efe/Downloads", false, true); got != "/home/efe/Downloads" {
		t.Errorf("not root cannot read the service token: %q", got)
	}
	if got := handoffDir("/home/efe/Downloads", true, false); got != "/home/efe/Downloads" {
		t.Errorf("no service installed: %q", got)
	}
}
