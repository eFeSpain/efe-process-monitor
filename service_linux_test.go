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
	if m := unitFile("/opt/efemon/efemon", "/home/efe/Downloads"); !strings.Contains(m, "Environment=EFEMON_MIGRATE_FROM=/home/efe/Downloads\n") {
		t.Errorf("migration line missing:\n%s", m)
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
