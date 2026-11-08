# Linux systemd service (`--install-service`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** efemon can install itself as a systemd system service that runs from boot and attaches its tray icon, notifications and "open panel" to the user's graphical session when one appears.

**Architecture:** A small CLI layer (`cli.go`) dispatches the new flags before anything else starts. `service_linux.go` owns everything that touches systemd and `/opt/efemon` (unit file, copy, migration, status, control) behind pure, testable functions; `service_other.go` stubs it. In service mode `desktop_linux.go` replaces the resolve-once `desktopUser()` with a `sessionWatcher` that polls for a session and spawns the existing tray helper; Quit/Restart/Stop route through `systemctl`. A `/api/service` endpoint and a Settings block expose install/uninstall.

**Tech Stack:** Go 1.26 standard library only (`flag`, `os`, `os/exec` via the project's `command()`), systemd (`systemctl`), existing `fyne.io/systray` helper. No new modules.

**Spec:** `docs/superpowers/specs/2026-11-08-linux-service-design.md`

## Global Constraints

- cgo-free single binary; every subprocess goes through `command()`/`commandContext()` (proc.go), never `exec.Command`.
- Every user-facing string exists in **es, en and zh** (`translations` in i18n.go; `TestTranslationParity` and `TestTranslationVerbParity` enforce it).
- Platform code lives in build-tagged files (`_linux.go`, `_other.go`); shared files must compile on windows/darwin.
- Install location `/opt/efemon` (dir 0700 root, binary 0755); unit `/etc/systemd/system/efemon.service`; unit name `efemon.service`.
- Files migrated: `.env`, `efemon.db`, `efemon.db-wal`, `efemon.db-shm`, `efemon-cert.pem`, `efemon-key.pem`. Never `efemon-token`, `efemon.log*`, `icon.png`.
- Watcher poll interval 5 s; one helper per session, never two.
- Commits: `git -c user.name=eFeSpain commit --no-gpg-sign` with no Co-Authored-By; `bash verify.sh --quick` green before each commit.
- Hermetic tests: no network, no `systemctl`, no root; root-only paths are verified by the user with the script in Task 9.

## Review Focus

1. Reinstalling from `/opt/efemon/efemon` itself: the copy step must be a no-op when source and destination are the same file (`os.SameFile`), or it truncates the running binary. → test in Task 3.
2. Service starts while a manual instance still owns the port: today's "already running → open browser and exit 0" would leave the service dead (`Restart=on-failure` ignores exit 0). In service mode a busy port after the retry loop must `os.Exit(1)`. → code step in Task 6, manual check in Task 9.
3. `EFEMON_MIGRATE_FROM` naming a missing directory, or `/opt/efemon` already holding data: migration is skipped silently and the variable line is removed from the unit. → test in Task 3.
4. A session whose helper answers `notray` (GNOME without the extension): the watcher must not respawn every 5 s; it remembers the uid as no-tray until that session disappears. → test in Task 5.
5. Uninstall requested from the UI while the service itself is serving: `systemctl disable --now` kills the process mid-request. The handler responds first and performs the action ~400 ms later, like Restart now. → code step in Task 7 (the deferred path exits the process, so it is not unit-tested); manual check (h)/(i) in Task 9.

---

### Task 1: Command-line options

**Files:**
- Create: `cli.go`, `cli_test.go`
- Modify: `main.go:122-130` (top of `main`)

**Interfaces:**
- Produces: `type options struct { Version, NoBrowser, Service, Install, Uninstall, Status bool }`; `func parseArgs(args []string) (options, error)` — `args` excludes the program name; unknown flag → error whose text starts with `usage:`; `func usage() string`. Globals `var serviceMode, noBrowser bool` set by `main` from `options` (and `serviceMode` also true when `os.Getenv("INVOCATION_ID") != ""`).

- [ ] **Step 1: Write the failing test** in `cli_test.go`:

```go
func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want options
	}{
		{nil, options{}},
		{[]string{"--version"}, options{Version: true}},
		{[]string{"--no-browser"}, options{NoBrowser: true}},
		{[]string{"--service"}, options{Service: true, NoBrowser: true}}, // service implies no browser
		{[]string{"--install-service"}, options{Install: true}},
		{[]string{"--uninstall-service"}, options{Uninstall: true}},
		{[]string{"--service-status"}, options{Status: true}},
	} {
		got, err := parseArgs(tc.args)
		if err != nil || got != tc.want {
			t.Errorf("parseArgs(%v) = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
	if _, err := parseArgs([]string{"--bogus"}); err == nil || !strings.HasPrefix(err.Error(), "usage:") {
		t.Errorf("unknown flag: err=%v, want a usage error", err)
	}
	if _, err := parseArgs([]string{"--install-service", "--uninstall-service"}); err == nil {
		t.Error("install and uninstall together must be refused")
	}
}
```

- [ ] **Step 2: Run** `go test -run TestParseArgs .` — expected: FAIL, `undefined: parseArgs`.
- [ ] **Step 3: Implement `cli.go`**: `parseArgs` with a `flag.NewFlagSet("efemon", flag.ContinueOnError)` whose output goes to a `strings.Builder`; on error return `fmt.Errorf("usage: %s", usage())`. `--service` sets `NoBrowser` too. `--tray-helper` is not a flag here: `trayHelperMain()` runs before `parseArgs` in `main`.
- [ ] **Step 4: Wire `main`**: after `trayHelperMain()`, `opts, err := parseArgs(os.Args[1:])`; on error print to stderr, `os.Exit(2)`; `--version` → `fmt.Printf("efemon %s\n", appVersion)` and `os.Exit(0)`, before `initLogging`. Set `serviceMode = opts.Service || os.Getenv("INVOCATION_ID") != ""`, `noBrowser = opts.NoBrowser || serviceMode`. Skip the `openDashboard` goroutine when `noBrowser`. Leave `Install/Uninstall/Status` dispatch for Task 4 (a `// dispatched in Task 4` placeholder is not acceptable — call `runServiceCommand(opts)` defined in Task 4; until then stub it in `cli.go` as `func runServiceCommand(o options) (handled bool)` returning false).
- [ ] **Step 5: Run** `bash verify.sh --quick` — expected: all green.
- [ ] **Step 6: Commit** `feat(cli): --version, --no-browser, --service and the service flags (parsing only)`.

### Task 2: Unit file and service paths

**Files:**
- Create: `service_linux.go` (`//go:build linux`), `service_linux_test.go`, `service_other.go` (`//go:build !linux`)

**Interfaces:**
- Produces (linux): `const serviceDir = "/opt/efemon"`, `serviceExe = serviceDir + "/efemon"`, `unitPath = "/etc/systemd/system/efemon.service"`, `unitName = "efemon.service"`, `migrateEnv = "EFEMON_MIGRATE_FROM"`; `func unitFile(exe, migrateFrom string) string`.
- Produces (shared, declared in `cli.go` so both platform files use it): `type ServiceStatus struct { Supported bool \`json:"supported"\`; Installed bool \`json:"installed"\`; Active bool \`json:"active"\`; Mode string \`json:"mode"\`; Path string \`json:"path"\`; Elevated bool \`json:"elevated"\` }`.

- [ ] **Step 1: Write the failing test** in `service_linux_test.go`:

```go
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
```

- [ ] **Step 2: Run** `go test -run TestUnitFile .` — expected: FAIL.
- [ ] **Step 3: Implement** `unitFile` returning the spec's unit text verbatim (comment lines included), with the `Environment=` line inserted after `WorkingDirectory=` only when `migrateFrom != ""`. Add `ServiceStatus` to `cli.go`; `service_other.go` gets `func serviceStatus() ServiceStatus { return ServiceStatus{} }`, `func installService(fromUI bool) error { return errServiceUnsupported }`, `func uninstallService() error { return errServiceUnsupported }`, `func serviceControl(action string) error { return errServiceUnsupported }`, `func runServiceMigration() {}` with `var errServiceUnsupported = errors.New("running as a service is not supported on this OS")` in `cli.go`.
- [ ] **Step 4: Run** `bash verify.sh --quick` and `GOOS=windows go vet .` — expected: green on both.
- [ ] **Step 5: Commit** `feat(service): unit file generator and platform stubs`.

### Task 3: Copy and data migration

**Files:**
- Modify: `service_linux.go`, `service_linux_test.go`

**Interfaces:**
- Produces: `func migrationPlan(src, dst string) []string` — basenames present in `src`, absent in `dst`, from the fixed list in Global Constraints; `nil` when `src` does not exist or equals `dst`. `func migrateData(src, dst string) (moved []string, err error)` — `os.Rename` each planned file (fallback copy+remove across filesystems), returns what moved. `func copyExecutable(src, dst string) error` — no-op when `os.SameFile`; otherwise write to `dst+".new"` 0755 and rename over `dst`.

- [ ] **Step 1: Write the failing tests**:

```go
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
}
```

- [ ] **Step 2: Run** `go test -run 'TestMigrationPlanAndMigrate|TestCopyExecutableSameFileIsNoop' .` — expected: FAIL.
- [ ] **Step 3: Implement** the three functions in `service_linux.go`. `migrateData` uses `os.Rename` and, on `EXDEV`, copies then removes.
- [ ] **Step 4: Run** `bash verify.sh --quick` — expected: green (gosec: file paths come from fixed constants + `os.Executable()`; annotate `#nosec G304` where it fires, with the reason).
- [ ] **Step 5: Commit** `feat(service): executable copy and data migration (pure, tested)`.

### Task 4: Install, uninstall, status, control, and the CLI dispatch

**Files:**
- Modify: `service_linux.go`, `cli.go`, `main.go`
- Test: `service_linux_test.go` (status parsing only)

**Interfaces:**
- Produces: `func systemctl(args ...string) (string, error)` (via `command("systemctl", args...)`, combined output in the error); `func installService(fromUI bool) error`; `func uninstallService() error`; `func serviceStatus() ServiceStatus`; `func serviceControl(action string) error` where `action ∈ {"stop","restart"}`; `func runServiceMigration()`; `func parseIsActive(out string) bool` (pure: `strings.TrimSpace(out) == "active"`); `func runServiceCommand(o options) bool` in `cli.go` (replaces the Task 1 stub).

- [ ] **Step 1: Write the failing test**: `TestParseIsActive` — `"active\n"` → true; `"inactive\n"`, `"failed"`, `""` → false.
- [ ] **Step 2: Run** `go test -run TestParseIsActive .` — expected: FAIL.
- [ ] **Step 3: Implement** in `service_linux.go`:
  - `installService(fromUI)`: require `os.Geteuid() == 0` (else `errors.New("requires root")`) and `hasCmd("systemctl")` (else the spec's "this system does not use systemd" message). `exe, _ := os.Executable()`; `os.MkdirAll(serviceDir, 0o700)`; `copyExecutable(exe, serviceExe)`. `src := filepath.Dir(exe)`; if `!fromUI`: `migrateData(src, serviceDir)` now and `migrateFrom = ""`; if `fromUI`: `migrateFrom = src` (skip when `src == serviceDir`). Write `unitFile(serviceExe, migrateFrom)` to `unitPath` 0644; `systemctl("daemon-reload")`; then `systemctl("enable", "--now", unitName)` when `!fromUI`, or `systemctl("enable", unitName)` when `fromUI` (the caller starts it after exiting, Task 7). Log each step with `log.Printf("[service] …")`.
  - `uninstallService()`: root check; `systemctl("disable", "--now", unitName)` (ignore "not loaded" errors); `os.Remove(unitPath)`; `daemon-reload`.
  - `serviceStatus()`: `Supported: true`, `Installed` = `unitPath` exists, `Active` = `parseIsActive(systemctl("is-active", unitName))`, `Mode` = `"service"` if `serviceMode` else `"manual"`, `Path: serviceExe`, `Elevated: elevated`.
  - `serviceControl(action)`: `systemctl(action, unitName)`.
  - `runServiceMigration()`: `src := os.Getenv(migrateEnv)`; if empty return; `migrateData(src, serviceDir)` (its plan is nil when `/opt/efemon` already has data); rewrite the unit with `unitFile(serviceExe, "")`, `daemon-reload`; log what moved.
  - `runServiceCommand(o)` in `cli.go`: for `Install`/`Uninstall`/`Status` call the matching function, print result to stdout/stderr, `os.Exit(0|1)`; return `false` when none of the three is set. `Status` prints `installed=<bool> active=<bool> path=<path>` and exits 0 only when installed && active. On uninstall print the spec's keep-data notice with `rm -rf /opt/efemon`.
- [ ] **Step 4: Wire `main`**: call `runServiceCommand(opts)` right after `--version` handling (before `initLogging`); call `runServiceMigration()` right after `appDir = exeDir()` and `initLogging()`, before `envPath` is resolved and `initDB()`.
- [ ] **Step 5: Run** `bash verify.sh --quick` — expected: green.
- [ ] **Step 6: Commit** `feat(service): install/uninstall/status via systemctl; migration on first service start`.

### Task 5: Session watcher

**Files:**
- Modify: `desktop_linux.go`, `tray_linux.go`, `tray_linux_test.go`

**Interfaces:**
- Consumes: `serviceMode` (Task 1); `spawnTrayHelper` (existing), `sessionFor`, `desktopUserCandidates` (existing).
- Produces: `type sessionWatcher struct { mu sync.Mutex; current *desktopSession; notray map[uint32]bool; probe func() *desktopSession; spawn func(*desktopSession) (done <-chan struct{}, ok bool); interval time.Duration; onAttach, onDetach func(*desktopSession) }`; `func (w *sessionWatcher) tick()` — one poll step, pure w.r.t. time; `func (w *sessionWatcher) run(stop <-chan struct{})` — loop calling `tick` every `interval`; `func (w *sessionWatcher) session() *desktopSession`. `spawnTrayHelper` changes signature to `func spawnTrayHelper(url string, s *desktopSession) (done <-chan struct{}, ok bool)` — `done` closes when the helper process exits. `desktopUser()` returns `watcher.session()` when `serviceMode`, else the resolve-once value as today. Package var `var watcher *sessionWatcher`.

- [ ] **Step 1: Write the failing test** in `tray_linux_test.go`:

```go
func TestSessionWatcherAttachesDetachesOnce(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	var cur *desktopSession
	var spawns int
	done := make(chan struct{})
	w := &sessionWatcher{
		probe: func() *desktopSession { return cur },
		spawn: func(s *desktopSession) (<-chan struct{}, bool) { spawns++; return done, true },
	}
	w.tick()
	if spawns != 0 || w.session() != nil {
		t.Fatal("no session: nothing to spawn")
	}
	cur = sess
	w.tick(); w.tick(); w.tick()
	if spawns != 1 || w.session() != sess {
		t.Fatalf("one session → exactly one helper, got %d (current=%v)", spawns, w.session())
	}
	close(done) // logout: helper exits
	w.tick()
	if w.session() != nil {
		t.Fatal("helper gone → no current session")
	}
	done = make(chan struct{})
	w.tick()
	if spawns != 2 {
		t.Fatalf("session still there after a detach → respawn, got %d spawns", spawns)
	}
}

func TestSessionWatcherRemembersNoTray(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	cur := sess
	var spawns int
	w := &sessionWatcher{
		probe: func() *desktopSession { return cur },
		spawn: func(s *desktopSession) (<-chan struct{}, bool) { spawns++; return nil, false },
	}
	for i := 0; i < 5; i++ {
		w.tick()
	}
	if spawns != 1 {
		t.Fatalf("a notray session must not be retried every tick, got %d spawns", spawns)
	}
	cur = nil
	w.tick()
	cur = sess
	w.tick()
	if spawns != 2 {
		t.Fatalf("the session went away and came back → try again once, got %d", spawns)
	}
}
```

- [ ] **Step 1b: Extend `TestDesktopUserCandidates`** (same file) with two cases if absent: no `SUDO_UID`/`PKEXEC_UID` and `runUsers = ["1000"]` → `["1000"]`; no env and `runUsers = ["1000","1001"]` → empty (two sessions: nothing is guessed). Run it; it should already pass — this pins the behaviour the service-mode probe relies on.
- [ ] **Step 2: Run** `go test -run 'TestSessionWatcher' .` — expected: FAIL.
- [ ] **Step 3: Implement** in `desktop_linux.go`: `tick()` logic — if `current != nil`: if its `done` channel is closed → `current = nil`, call `onDetach`; return. Else `s := probe()`; if `s == nil` → clear `notray` map; return. If `notray[s.uid]` → return. `done, ok := spawn(s)`; if `!ok` → `notray[s.uid] = true`; return. `current = s`, store `done`, call `onAttach`. `run` = `time.NewTicker(interval)` loop until `stop`. The production probe: `desktopUserCandidates(os.Getenv, runUsers())` → `sessionFor(uid)` for the first candidate (`runUsers()` extracted from today's `desktopUser` body: the `/run/user/*/bus` listing). The production spawn: `spawnTrayHelper(tokenURL(url, localToken), s)`. `spawnTrayHelper` creates `done := make(chan struct{})` closed by the existing stdout-reading goroutine after `cmd.Wait()`; the `quit` line handling becomes: if `serviceMode` → `serviceControl("stop")` then `os.Exit(0)`, else `os.Exit(0)` as today.
- [ ] **Step 4: Wire `runApp` (tray_linux.go)**: when `serviceMode && os.Geteuid() == 0`: `watcher = &sessionWatcher{interval: 5*time.Second, probe: …, spawn: …, onAttach: log "[tray] icono mostrado en la sesión de %s (uid=%d)", onDetach: log "[tray] sesión de %s cerrada; esperando otra"}`; start the server goroutine; `go watcher.run(make(chan struct{}))`; `noTrayMode = false`; `select {}`. The existing `sudo` branch stays as is. `runTray`'s Quit label becomes `"Detener hasta el próximo arranque / Stop until next boot"` when `serviceMode` (pass the label in; the helper knows `serviceMode` from its own `INVOCATION_ID`? No — the helper is spawned by us with a clean env: pass `--tray-helper` plus a second argument `service` when `serviceMode`, read in `trayHelperMain`).
- [ ] **Step 5: `desktopUser()`**: `if serviceMode && watcher != nil { return watcher.session() }` before the `desktopOnce` path. `runAsDesktopUser` unchanged (it calls `desktopUser()`).
- [ ] **Step 6: Run** `bash verify.sh --quick` — expected: green, including `-race` (the watcher's `current` is only read under `mu`).
- [ ] **Step 7: Commit** `feat(service): session watcher attaches the tray helper when a desktop session appears`.

### Task 6: Service-mode behaviour in main: port busy, Quit/Restart/Stop, banner, gate text

**Files:**
- Modify: `main.go` (`handleRestart`, `handleShutdown`, the port-busy branch), `actions.go` (`startupBanner`), `auth.go` (`denyLocal`), `i18n.go`
- Test: `handlers_test.go`

**Interfaces:**
- Consumes: `serviceMode`, `serviceControl` (Task 4), `watcher` (Task 5).
- Produces: i18n keys `gate_body_service` (es/en/zh) — the `gate_body` text plus the sentence "In service mode: open the panel from the tray icon, or run `sudo efemon`." (es: "En modo servicio: abre el panel desde el icono de la bandeja, o ejecuta `sudo efemon`."; zh: "服务模式下：请从托盘图标打开面板，或运行 `sudo efemon`。").

- [ ] **Step 1: Write the failing test**: `TestGatePageMentionsServiceHint` — with `serviceMode = true` (restored by `t.Cleanup`) and the local gate active, `GET /` without token → 403 whose body contains `strings_("es")["gate_body_service"]`; with `serviceMode = false` it contains `gate_body` and not the service sentence.
- [ ] **Step 2: Run** `go test -run TestGatePageMentionsServiceHint .` — expected: FAIL (missing key → empty string → test fails on the service branch).
- [ ] **Step 3: Implement**: `denyLocal` picks `gate_body_service` when `serviceMode`. `handleRestart`: when `serviceMode`, the deferred goroutine runs `serviceControl("restart")` instead of `relaunchSelf(); os.Exit(0)`. `handleShutdown`: when `serviceMode`, `serviceControl("stop")` then `os.Exit(0)`. Port-busy branch in `main`: when `serviceMode`, after the retry loop fails, `log.Printf("[!] puerto %s ocupado por otra instancia; saliendo con error para que systemd reintente", addr)` and `os.Exit(1)` — no browser. `startupBanner`: add `[+] Mode            systemd service (desktop session: waiting)` / `… (user %s)` when `serviceMode`, else `[+] Mode            manual`.
- [ ] **Step 4: Run** `bash verify.sh --quick` — expected: green.
- [ ] **Step 5: Commit** `feat(service): service-mode restart/stop via systemctl, exit 1 on a busy port, gate hint, banner`.

### Task 7: `/api/service` endpoint

**Files:**
- Modify: `main.go` (route + `handleService`), `handlers_test.go`

**Interfaces:**
- Consumes: `serviceStatus`, `installService(fromUI bool)`, `uninstallService`, `serviceControl`, `decodeJSON`, `requireMethod`.
- Produces: `GET /api/service` → `ServiceStatus` JSON; `POST /api/service {"action":"install"|"uninstall"}` → `{"ok":true}` immediately; the action runs ~400 ms later in a goroutine (install: `installService(true)`, close DB, `command("systemctl","start",unitName).Start()`, `os.Exit(0)`; uninstall: `uninstallService()`, and if `serviceMode` the process is gone with it). Errors found *before* responding (not root → 403 `{"ok":false,"error":"requires root"}`; unknown action → 400; unsupported OS → 400) are returned synchronously. Install from a manual instance that is not root → 403.

- [ ] **Step 1: Write the failing tests** in `handlers_test.go`:

```go
func TestServiceEndpointGuards(t *testing.T) {
	old := elevated
	elevated = false
	t.Cleanup(func() { elevated = old })
	w := httptest.NewRecorder()
	handleService(w, httptest.NewRequest(http.MethodGet, "/api/service", nil))
	var st ServiceStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || st.Elevated {
		t.Fatalf("GET: %v %+v", err, st)
	}
	if w := jsonPost(handleService, "/api/service", `{"action":"install"}`); w.Code != http.StatusForbidden {
		t.Errorf("install without root: %d, want 403", w.Code)
	}
	elevated = true
	if w := jsonPost(handleService, "/api/service", `{"action":"explode"}`); w.Code != http.StatusBadRequest {
		t.Errorf("unknown action: %d, want 400", w.Code)
	}
	if w := jsonPost(handleService, "/api/service", `{"action":`); w.Code != http.StatusBadRequest {
		t.Errorf("bad body: %d, want 400", w.Code)
	}
}
```

  (The deferred install/uninstall path is not unit-tested: it exits the process. It is exercised in Task 9.)
- [ ] **Step 2: Run** `go test -run TestServiceEndpointGuards .` — expected: FAIL, `undefined: handleService`.
- [ ] **Step 3: Implement `handleService`** per the Interfaces block; register `http.HandleFunc("/api/service", handleService)`. On a non-Linux build `serviceStatus().Supported == false` → POST answers 400 `{"ok":false,"error":"not supported on this OS"}`. Log `SERVICE install by operator` / `SERVICE uninstall by operator` before deferring.
- [ ] **Step 4: Run** `bash verify.sh --quick` and `GOOS=windows go vet .` — expected: green.
- [ ] **Step 5: Commit** `feat(service): /api/service — status, deferred install/uninstall`.

### Task 8: Settings block "Run at boot"

**Files:**
- Modify: `web/templates/report.html` (settings modal + JS), `i18n.go`, `template_test.go`

**Interfaces:**
- Consumes: `GET/POST /api/service` (Task 7).
- Produces i18n keys (es/en/zh): `svc_title` ("Arranque con el sistema" / "Run at boot" / "随系统启动"), `svc_installed` ("instalado y activo" / "installed and active" / "已安装且运行中"), `svc_installed_inactive` ("instalado, detenido" / "installed, stopped" / "已安装，已停止"), `svc_not_installed` ("no instalado" / "not installed" / "未安装"), `svc_install` ("Instalar como servicio" / "Install as a service" / "安装为服务"), `svc_uninstall` ("Quitar servicio" / "Remove service" / "移除服务"), `svc_needs_root` ("requiere root" / "requires root" / "需要 root"), `svc_confirm_install` ("¿Instalar efemon como servicio systemd? El binario y los datos se moverán a /opt/efemon y esta instancia se cerrará; el servicio arranca en unos segundos." / en / zh), `svc_confirm_uninstall` ("¿Quitar el servicio? Los datos de /opt/efemon se conservan." / en / zh), `svc_installing` ("instalado — el servicio arranca en unos segundos…" / "installed — the service starts in a few seconds…" / "已安装 — 服务将在几秒后启动…"), `svc_hint` ("Con el servicio, el monitor vigila desde el arranque; el icono de bandeja aparece al iniciar sesión." / en / zh).

- [ ] **Step 1: Write the failing test**: extend `TestReportTemplateExecutes` to assert the rendered shell contains `id="svc-block"` and `strings_(lang)["svc_title"]` for every language.
- [ ] **Step 2: Run** `go test -run TestReportTemplateExecutes .` — expected: FAIL.
- [ ] **Step 3: Implement**: in the settings modal, after the listen-address row, a `<div id="svc-block" style="display:none">` with the title, a `<span id="svc-status" class="status-pill">`, `<span id="svc-path" class="t">`, a `<button id="svc-btn" class="btn">` and `<div id="svc-msg">`. JS: `openSettings` also `fetch('/api/service')`; show the block only when `supported`; pill text/class from `installed`/`active`; button label install/uninstall; disabled with `svc_needs_root` when `!elevated`. Click → `confirm(T.svc_confirm_*)` → `postJSON('/api/service', {action})` → on install show `svc_installing` and `setTimeout(() => location.reload(), 6500)`; on uninstall refresh the block.
- [ ] **Step 4: Run** `bash verify.sh --quick` — expected: green (parity tests cover the 11 keys × 3).
- [ ] **Step 5: Commit** `feat(ui): "Run at boot" block in Settings`.

### Task 9: Documentation and the manual verification script

**Files:**
- Modify: `README.md`, `README.es.md` (Usage → "Run at boot (Linux)" / "Arranque con el sistema (Linux)"), `ARCHITECTURE.md` (cli.go, service_linux.go, session watcher, two-step UI install, flags list), `CHANGELOG.md` (`## [Unreleased]` → `### Added`)
- Create: `docs/superpowers/plans/2026-11-08-linux-service-manual-checks.md`

- [ ] **Step 1: Write the docs.** README section covers: `sudo efemon --install-service`, what moves to `/opt/efemon`, tray appears at login, `--uninstall-service` keeps the data, `--version`/`--no-browser`, systemd required. CHANGELOG entry under `### Added`: run at boot on Linux; `--version`, `--no-browser`; Settings block. ARCHITECTURE: new files and the service-mode runtime model.
- [ ] **Step 2: Write the manual checks** (for the user; root + systemd + desktop): (a) `sudo ./efemon --install-service` from a scratch directory holding a `.env` → `/opt/efemon` has the `.env`, `systemctl is-active efemon` = active, tray icon present, `efemon.log` shows `[service]` lines and `[tray] icono mostrado`; (b) reboot → `systemctl is-active` before login, tray after login; (c) log out / in → `[tray] sesión … cerrada` then `icono mostrado` again, one helper (`pgrep -af tray-helper` = 1); (d) tray Quit → service inactive, unit still enabled; `systemctl start efemon` brings it back; (e) Settings → Restart now with a new `LISTEN_ADDR` → service restarts, page reloads on the new address; (f) run `efemon` as a normal user → gate page with the service hint; `sudo efemon` → opens the panel; (g) start a manual `sudo ./efemon` while the service runs → the manual one hands off; stop the service, start the manual one, `systemctl start efemon` → service exits 1 and retries until the manual one is stopped; (h) `sudo efemon --uninstall-service` → unit gone, `/opt/efemon` kept; (i) fresh checkout, Settings → Install → page reloads against the service, data migrated once, unit has no `Environment=` line afterwards.
- [ ] **Step 3: Run** `bash verify.sh --quick` — expected: green.
- [ ] **Step 4: Commit** `docs: run at boot (Linux) — README, ARCHITECTURE, CHANGELOG, manual checks`.
