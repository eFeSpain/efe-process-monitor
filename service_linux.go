//go:build linux

package main

import (
	"path/filepath"
	"strings"
)

// Running as a systemd service. The monitor is installed under /opt/efemon —
// not left where it was downloaded — because a root service that starts from
// a user-writable directory is exactly what the audit flags.

// migrateEnv names the directory whose data the service moves into its own on
// first start, when the install was done from the UI (the manual instance
// still held the DB at that moment; see installService).
const migrateEnv = "EFEMON_MIGRATE_FROM"

// unitFile is the systemd unit for exe. migrateFrom, when non-empty, adds the
// one-shot Environment line the service consumes and removes on first start.
//
// No sandboxing directives (ProtectSystem, NoNewPrivileges, …): the monitor
// needs raw sockets for passive DNS, every process's /proc, nft/iptables,
// kill, and to start the tray helper as the session user (setuid) — each
// hardening option breaks one of those.
func unitFile(exe, migrateFrom string) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=eFe Process Monitor\n")
	b.WriteString("Documentation=https://github.com/eFeSpain/efe-process-monitor\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + exe + " --service\n")
	b.WriteString("WorkingDirectory=" + filepath.Dir(exe) + "\n")
	if migrateFrom != "" {
		b.WriteString("Environment=" + migrateEnv + "=" + migrateFrom + "\n")
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=2\n")
	b.WriteString("# No systemd sandboxing: the monitor needs raw sockets (passive DNS), every\n")
	b.WriteString("# process's /proc, nft/iptables, kill, and to start processes as the session\n")
	b.WriteString("# user (setuid) — each hardening option breaks one of those.\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}
