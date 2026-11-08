//go:build linux

package main

import (
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
