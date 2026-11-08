//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
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

// migratedFiles is what moves with the install: the keys and settings, the
// forensic history (with the WAL it may be mid-write in) and the TLS pair.
// Never the token or the logs — those are regenerated — nor the extracted icon.
var migratedFiles = []string{".env", "efemon.db", "efemon.db-wal", "efemon.db-shm", "efemon-cert.pem", "efemon-key.pem"}

// migrationPlan lists the basenames present in src and absent from dst, from
// migratedFiles. nil when src does not exist or is dst itself.
func migrationPlan(src, dst string) []string {
	si, err := os.Stat(src)
	if err != nil {
		return nil
	}
	if di, err := os.Stat(dst); err == nil && os.SameFile(si, di) {
		return nil
	}
	var plan []string
	for _, f := range migratedFiles {
		if _, err := os.Stat(filepath.Join(src, f)); err != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dst, f)); err == nil {
			continue // already at the target: never overwritten
		}
		plan = append(plan, f)
	}
	return plan
}

// migrateData moves the planned files from src to dst and returns what moved.
// A move, not a copy: one forensic history, never two drifting apart. Across
// filesystems (rename fails with EXDEV) it copies and removes.
func migrateData(src, dst string) (moved []string, err error) {
	for _, f := range migrationPlan(src, dst) {
		from, to := filepath.Join(src, f), filepath.Join(dst, f)
		if err := os.Rename(from, to); err != nil {
			if err := copyFile(from, to, 0o600); err != nil {
				return moved, fmt.Errorf("%s: %w", f, err)
			}
			if err := os.Remove(from); err != nil {
				return moved, fmt.Errorf("%s: %w", f, err)
			}
		}
		moved = append(moved, f)
	}
	return moved, nil
}

// copyExecutable installs src at dst (0755) through a temporary file and a
// rename, so a running binary at dst is replaced atomically. When src and dst
// are the same file it does nothing: copying a file onto itself truncates it.
func copyExecutable(src, dst string) error {
	if si, err := os.Stat(src); err == nil {
		if di, err := os.Stat(dst); err == nil && os.SameFile(si, di) {
			return nil
		}
	}
	tmp := dst + ".new"
	if err := copyFile(src, tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- src is os.Executable() or a fixed basename under appDir
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- dst is under /opt/efemon
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
