//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
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
	b.WriteString("Wants=network-online.target\n")
	// A manual instance holding the port makes the service exit 1 until it is
	// gone; systemd's default rate limit (5 starts in 10 s) would turn that
	// transient conflict into a permanently failed unit.
	b.WriteString("StartLimitIntervalSec=0\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + exe + " --service\n")
	b.WriteString("WorkingDirectory=" + filepath.Dir(exe) + "\n")
	if migrateFrom != "" {
		// systemd.exec(5): the line is unquoted and specifier-expanded, so the
		// whole assignment is quoted and % is doubled, or a path with a space
		// truncates to its first word and the migration silently moves nothing.
		b.WriteString("Environment=\"" + migrateEnv + "=" + strings.ReplaceAll(migrateFrom, "%", "%%") + "\"\n")
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
		// Owner-only whatever the user's editor left: the directory is 0755 so
		// the tray helper can exec the binary as the user.
		if err := os.Chmod(to, 0o600); err != nil {
			return moved, fmt.Errorf("%s: %w", f, err)
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
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
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

// serviceSupported is a constant, so a handler can check it without the
// systemctl call serviceStatus() makes.
const serviceSupported = true

const (
	serviceDir = "/opt/efemon"
	serviceExe = serviceDir + "/efemon"
	unitName   = "efemon.service"
	unitPath   = "/etc/systemd/system/" + unitName
	// serviceLink puts `efemon` on PATH, so `sudo efemon` and the documented
	// `efemon --uninstall-service` work after an install. os.Executable()
	// resolves it, so appDir becomes /opt/efemon.
	serviceLink = "/usr/local/bin/efemon"
	// serviceDirMode must let the session user traverse the directory: the tray
	// helper is this binary exec'd as that user, and setuid happens before
	// execve. The data files inside are 0600 (migrateData, writeSecretFile,
	// initDB), so the directory being readable exposes nothing.
	serviceDirMode = 0o755
)

// systemctl runs one systemctl command; the combined output rides in the error
// so the operator reads systemd's own words in the UI or the terminal.
func systemctl(args ...string) (string, error) {
	out, err := command("systemctl", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func parseIsActive(out string) bool { return strings.TrimSpace(out) == "active" }

func requireServiceTools() error {
	if os.Geteuid() != 0 {
		return errors.New("requires root")
	}
	if !hasCmd("systemctl") {
		return errors.New("this system does not use systemd; run efemon from your session start-up instead")
	}
	return nil
}

// installService copies the binary to /opt/efemon, writes and enables the
// unit. fromUI is the two-step path: the calling instance still holds the DB
// and the port, so the data migration is deferred to the service's first start
// (unitFile's Environment line) and the unit is enabled but not started — the
// caller starts it right before exiting (handleService).
func installService(fromUI bool) error {
	if err := requireServiceTools(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(serviceDir, serviceDirMode); err != nil {
		return err
	}
	if err := os.Chmod(serviceDir, serviceDirMode); err != nil { // an earlier 0700 install
		return err
	}
	if err := copyExecutable(exe, serviceExe); err != nil {
		return fmt.Errorf("copy to %s: %w", serviceExe, err)
	}
	log.Printf("[service] binario instalado en %s", serviceExe)
	if err := ensureServiceLink(); err != nil {
		log.Printf("[service] %s: %v (sigue sin estar en PATH)", serviceLink, err)
	}
	out, _ := systemctl("is-active", unitName)
	wasActive := parseIsActive(out)
	src, migrateFrom := filepath.Dir(exe), ""
	switch {
	case src == serviceDir:
	case fromUI:
		migrateFrom = src // moved by the service on its first start
	default:
		moved, err := migrateData(src, serviceDir)
		if err != nil {
			return fmt.Errorf("migrate data: %w", err)
		}
		if len(moved) > 0 {
			log.Printf("[service] datos movidos a %s: %s", serviceDir, strings.Join(moved, ", "))
		}
	}
	if err := os.WriteFile(unitPath, []byte(unitFile(serviceExe, migrateFrom)), 0o644); err != nil { // #nosec G306 -- unit files are world-readable by convention
		return err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	args := []string{"enable", "--now", unitName}
	if fromUI {
		args = []string{"enable", unitName}
	}
	if _, err := systemctl(args...); err != nil {
		return err
	}
	log.Printf("[service] unidad %s escrita y habilitada", unitPath)
	if wasActive && !fromUI {
		// Reinstalling over a running service replaced the file under the old
		// inode; "installed and started" must mean the new binary is running.
		if _, err := systemctl("restart", unitName); err != nil {
			return err
		}
		log.Printf("[service] servicio reiniciado con el binario nuevo")
	}
	return nil
}

// ensureServiceLink points /usr/local/bin/efemon at the installed binary. A
// regular file there is somebody else's and is left alone.
func ensureServiceLink() error {
	if fi, err := os.Lstat(serviceLink); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return errors.New("exists and is not a symlink")
		}
		if target, _ := os.Readlink(serviceLink); target == serviceExe {
			return nil
		}
		if err := os.Remove(serviceLink); err != nil {
			return err
		}
	}
	return os.Symlink(serviceExe, serviceLink)
}

// removeServiceLink removes the symlink only if it is ours.
func removeServiceLink(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return nil
	}
	if target, _ := os.Readlink(p); target != serviceExe {
		return nil
	}
	return os.Remove(p)
}

// uninstallService disables and removes the unit and the PATH link, then stops
// it. /opt/efemon is kept: it holds the forensic history and the .env with the
// keys.
func uninstallService() error {
	if err := requireServiceTools(); err != nil {
		return err
	}
	remove := func(p string) error {
		if p == serviceLink {
			return removeServiceLink(p)
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	err := uninstallServiceSteps(systemctl, remove)
	log.Printf("[service] unidad %s eliminada; %s se conserva", unitPath, serviceDir)
	return err
}

// uninstallServiceSteps is the ordered uninstall with its effects injected.
// The stop comes LAST: when the request arrives through the service's own
// /api/service, `stop` kills this very process, and a `disable --now` first
// would leave the unit file (and the "installed" status) behind.
func uninstallServiceSteps(run func(args ...string) (string, error), remove func(string) error) error {
	ignorable := func(err error) bool {
		return err == nil || strings.Contains(err.Error(), "not loaded") || strings.Contains(err.Error(), "does not exist")
	}
	if _, err := run("disable", unitName); !ignorable(err) {
		return err
	}
	if err := remove(unitPath); err != nil {
		return err
	}
	if err := remove(serviceLink); err != nil {
		return err
	}
	if _, err := run("daemon-reload"); err != nil {
		return err
	}
	if _, err := run("stop", unitName); !ignorable(err) {
		return err
	}
	return nil
}

// handoffDir is where the "already running → open the dashboard" path reads
// the token from. Root with the service installed reads the service's token:
// the one next to whichever binary was launched is stale after an install.
func handoffDir(appDir string, root, installed bool) string {
	if root && installed {
		return serviceDir
	}
	return appDir
}

func tokenHandoffDir() string {
	_, err := os.Stat(unitPath)
	return handoffDir(appDir, os.Geteuid() == 0, err == nil)
}

func serviceStatus() ServiceStatus {
	st := ServiceStatus{Supported: true, Mode: "manual", Path: serviceExe, Elevated: elevated}
	if serviceMode {
		st.Mode = "service"
	}
	if _, err := os.Stat(unitPath); err == nil {
		st.Installed = true
		out, _ := systemctl("is-active", unitName)
		st.Active = parseIsActive(out)
	}
	return st
}

// runServiceMigration completes an install started from the UI: the unit
// carries EFEMON_MIGRATE_FROM, nobody holds the files any more, so they are
// moved now and the line is removed from the unit. A missing source or a
// target that already has data is skipped silently.
func runServiceMigration() {
	src := os.Getenv(migrateEnv)
	if src == "" {
		return
	}
	moved, err := migrateData(src, serviceDir)
	switch {
	case err != nil:
		log.Printf("[service] migración desde %s incompleta: %v", src, err)
	case len(moved) > 0:
		log.Printf("[service] datos movidos desde %s: %s", src, strings.Join(moved, ", "))
	default:
		// Said out loud: a missing source or a target that already had data
		// means the user's .env and history are NOT here, and nothing else
		// would tell them why.
		log.Printf("[service] migración desde %s: nada que mover (origen inexistente o %s ya tenía datos)", src, serviceDir)
	}
	if err := os.WriteFile(unitPath, []byte(unitFile(serviceExe, "")), 0o644); err != nil { // #nosec G306 -- unit file
		log.Printf("[service] no se pudo reescribir la unidad: %v", err)
		return
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		log.Printf("[service] %v", err)
	}
}

// serviceControl is stop / restart / start of the unit, for the paths that
// used to exit or relaunch the process directly (tray Quit, Restart now, Stop).
func serviceControl(action string) error {
	switch action {
	case "stop", "restart", "start":
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
	_, err := systemctl(action, unitName)
	return err
}
