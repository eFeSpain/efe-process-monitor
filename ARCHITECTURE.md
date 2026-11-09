# eFe Process Monitor — Architecture & Dev Notes

Context doc to resume work in a fresh session. The product is a **defensive/forensic
process & network monitor** with a local web dashboard. Single self-contained Go binary,
cross-platform (Windows primary, Linux supported, cgo-free).

Public repo: https://github.com/eFeSpain/efe-process-monitor (the Go app = repo root contents).
A Python reference version lives in the parent folder (`../`) — **frozen**, do not edit; Go is the product.

## Build / run

```bash
go build -o efemon.exe .          # Windows
GOOS=linux  go build -o efemon .  # Linux  (cgo-free, single command)
GOOS=darwin go build -o efemon .  # macOS
./efemon.exe                      # serves http://127.0.0.1:5000, opens browser, tray icon on Windows
```
- Release builds use `-ldflags="-H windowsgui"` (no console) via `.github/workflows/release.yml` (on tag `v*`).
- Go 1.26. Deps: `gopsutil/v4`, `modernc.org/sqlite` (pure Go), `fyne.io/systray`, `joho/godotenv`.

## Tests / CI
- `go test ./...` — **hermetic** suite (no network, no OS shell-out): `threatScore` table, intel-feed parsers
  (`parseThreatFox`/`parseSpamhaus` fixtures), `ouiVendor`, IP/port helpers, **ES↔EN translation parity**
  (`*_test.go` fail if a key is in one language only), and DB/session round-trips on a temp SQLite
  (`setupTestDB`, incl. the permanent-vs-session toggle). Network/OS code (VT, AbuseIPDB, Authenticode,
  `dpkg/rpm`) is intentionally not unit-tested.
- `.github/workflows/ci.yml` (push/PR): gofmt-clean check, `go vet`, `go test -race`, staticcheck, gosec,
  **govulncheck** (the toolchain is pinned by `go.mod`; 0.4.0 shipped with 22 fixed stdlib CVEs because
  nothing checked), and a cross-build matrix (windows/linux/darwin, amd64+arm64) that keeps the binary
  cgo-free. Dependabot (`.github/dependabot.yml`) bumps modules and actions weekly.

## Where data lives (IMPORTANT)
- **`efemon.db`** (SQLite) → next to the executable (`appDir` = dir of `os.Executable()`), set in `main.go`.
- **`.env`** → next to the executable. The cwd → `../.env` fallback only exists with `EFEMON_DEV=1`
  (dev: real keys are in `../.env`). `writeEnv` saves to the one found.
- Keys/flags in `.env`: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSECH_API_KEY` (abuse.ch Auth-Key: ThreatFox
  moved behind one in 2025; without it the feed is off), `NOTIFY_DESKTOP`, `NOTIFY_SOUND`,
  `PERSIST_WHITELIST`, `PERSIST_BLOCKS`, `REFRESH_SECS`, `AUTH_HASH` (base64 of a bcrypt hash; "" = login off),
  `LISTEN_ADDR` ("" = `127.0.0.1:5000`), optional `LISTEN_CERT`/`LISTEN_KEY`,
  `EVENT_RETENTION_DAYS` (history pruning; default 30, 0 = keep forever).
- Env-only (not written back to `.env`): `EFEMON_DEV=1` lets the `.env` lookup fall back to the
  working directory and its parent (off by default, so running the binary inside another project
  can't read or rewrite that project's `.env`); `RESTART_WAIT=1` is set on the relaunched process
  by "Restart now".
- `efemon-token` (0600, next to the binary) holds this run's local access token — the gate that
  applies when no password is set. See `auth.go`.
- `efemon.log` (+ `.1`…`.3`, next to the binary) is the application log. **Release builds link with
  `-H=windowsgui` and therefore have no usable stderr**, so `logging.go` tees the standard logger to
  a rotating file; without it the whole operator audit trail is discarded on the shipped binary.
  Served to the UI by `/logs.txt`.
- **activity.go** — `aggregateActivity` (live: conns, distinct remotes, countries/networks from the
  render's enrichment, listening ports, names asked for) + `procActivity` (adds `dbEventStats` and
  `dbScoreChangeCount` from SQLite) → `ProcDetails.Activity`, rendered as its own detail block.
- **fileinfo.go / services*.go** — Windows only: `parseAuthenticodeJSON` decodes the signature batch
  that now also carries the version resource (`FileInfo`, cached in memory + `fileinfo` table by
  path+mtime, read by `fileInfoFor`); `startServiceMap` refreshes pid → hosted services every 60 s
  in the background (`parseServiceLines`), read by `servicesOf`. Stubs elsewhere return nothing.
- **provenance.go** — `exeProvenance` (exe mtime + first-seen from `baseline_hash`), `childrenMap`
  (one `/proc` pass per render) + `summarizeChildren`, `humanAge` (localized via the template's `T`).
- **procscan.go / procscan_linux.go** — what a process touches: `sensitiveOpenFiles` (categories
  with expected-reader allow-lists; camera/mic listed, not scored) and `anomalousExecMaps`
  (memfd / staging / deleted-outside-system-libs executable regions; anonymous JIT ignored), read
  from `/proc/<pid>/fd` and `maps` with a 60 s per-PID cache. Feed `wCredAccess` / `wExecAnomaly`.
- **proccontext.go** — per-process context for the details block: `sensitiveEnv` (allow-list of
  injection/proxy variables, credentials masked), `parseCgroup` (container id + innermost systemd
  unit), read in `getProcDetails` together with `Cwd` and `Terminal`. Pure parsers, tested.
- **ancestry.go** — `ancestryOf` walks the parent chain (depth-capped, cycle-safe);
  `suspiciousAncestry` matches spawn patterns that should never occur (document/browser → script
  host, web server → shell) and feeds `wBadSpawn` into the score. Deliberately narrow: a broad rule
  here would swamp the score with false positives.
- **verify.sh** — runs every CI gate locally in the same order (`gofmt`, `vet`, `test -race`,
  `staticcheck`, `gosec` with the identical arguments), then the two things CI cannot do from one
  runner: cross-compile all six release targets, and execute the test binary on Linux via WSL from a
  Windows checkout. `--quick` skips the last two. Keep the gosec arguments in sync with
  `.github/workflows/ci.yml` or the step stops meaning anything.
- **volume.go** — per-process I/O rate **and resource usage** (CPU %, RSS, threads, owner) sampled
  once per monitor cycle by `sampleProcessIO`; `rateFor(pid)` hands the last figures to
  `analyzeConnections`. CPU is per core as in top (capped at `numCPU`×100) and, like the I/O
  counters, resets on PID reuse (cumulative clock went backwards). Resources never score.
  On Linux the block-device
  totals are subtracted from `rchar`/`wchar` to isolate non-disk traffic; on Windows
  `GetProcessIoCounters` cannot separate file from network I/O, so the figure is weaker and the UI
  says so. Not attributable to a connection. `wExfilCombo` only applies when an independent distrust
  signal is already present — volume alone must never score.
- **secure_windows.go / secure_other.go** — `writeSecretFile` for the local token and the TLS
  private key. On Windows a 0600 mode is ignored by the OS, so an explicit ACL is applied; the
  principal set depends on `elevated`, because elevating does not change the user's SID and only the
  Administrators group distinguishes the two tokens. See the comment in `secure_windows.go`.
- **dns.go / dns_linux.go / dns_windows.go** — passive DNS outside captures: a hand-written
  response parser (`parseDNSAnswers`, `readDNSName`) feeding `recordHostname`; Linux as root reads
  responses from an AF_PACKET socket with a classic BPF filter for UDP sport 53 (cooked frames, v4+v6);
  Windows polls `Get-DnsClientCache` every 30 s. `passiveDNSStatus` is printed by the banner. `parseDNSResponse`
  also returns the rcode: NXDOMAIN names go to **dga.go** (`dgaDetector`: ≥ 25 distinct failed names in 60 s →
  one `alert` event + notification per 10 min, reverse/local/WPAD names excluded; machine-wide, Linux only).
- **timeline.go** — `buildTimeline` joins events + score_history + hostnames + block/whitelist state
  into one record per (exe, remote IP) for `/export/timeline.json`; pure, tested with fixtures.
- **hostnames.go** — `observeHostnames` harvests IP↔name bindings from each captured packet (TLS SNI
  and DNS answer records) into the `hostnames` table. SNI outranks DNS because the client declared
  it; both outrank reverse DNS, which the address owner controls. Only sees traffic while a capture
  runs — this is not passive DNS logging.
- `score_history` is a change log, written by `recordScoreChange` only when the verdict for an
  (exe, remote IP) pair actually moves. Skips local traffic and rows flagged `Partial`.
- Platform-specific audit probes return `(result, ran bool)`. `findingOrSkipped` turns `ran == false`
  into an informational "not available on this OS" — a stub returning an empty slice must never
  render as a clean pass. macOS is where this bites: no process cross-view, no `/proc`.
- Score weights are named constants at the top of the threat-score section in `connections.go`, and
  `score_corpus_test.go` pins labelled scenarios to score *bands* — change a weight there and the
  corpus tells you whether ordinary traffic moved into "suspicious" or an intrusion moved out.
  **Every setting is server-persisted in `.env`**
  (loaded at startup) — nothing UI-facing lives only in the browser.

## Runtime model
- `GET /` returns only the **shell** (instant). The table is loaded async from `GET /api/connections`
  (renders `rows.html`), so the UI shows "procesando" then fills in.
- **The render path never waits on the network or a subprocess.** VT hashes, signatures, IP reputation
  (`enrichIPCached`) and LAN host info (`lanLookupCached`) are cache-only during a render; a miss is
  reported as `nil`/`PENDING` (the row shows `~` partial, the IP block says "reputation pending") and
  queued on a `lookupQueue` (queue.go) whose workers resolve it and `broadcast` a `refresh` SSE event —
  not logged, it is a UI nudge — so the page redraws by itself. Concurrent `/api/connections` requests
  coalesce onto one analysis (`sharedConnections`, flight.go); the analysis is language-neutral and
  `localizedConnections` renders the breakdown per request.
- A **live monitor** goroutine (`monitorLoop`, every 3s) diffs connection snapshots and pushes SSE
  events to `/events`; the browser shows a feed and reactively refreshes the table (debounced 1.5s,
  paused while a detail row/capture is open). Optional periodic refresh interval (Settings, localStorage).
- **VT hash lookups** are rate-limited (4/min token bucket) and resolved by a **background worker**
  (`vtWorker`); the table shows `PENDING` then caches the verdict in SQLite. `NOT_IN_VT` is cached too.
- **Single instance**: if port 5000 is taken, it opens the browser and exits.

## File map
- **main.go** — HTTP server, all routes/handlers, `go:embed` of templates+static, startup (env, DB,
  elevation, monitor, vtWorker, primeIntel, browser, banner), `appDir`/`exeDir`, template `funcMap`
  (trunc, threatClass, join, joinInts, json, deref, humanBytes). Every JSON handler reads its body
  through `decodeJSON` (64 KiB bound, 400 on a decode error — never act on the zero value); the CSV
  export goes through `csvCell` (formula neutralization). `/api/kill` refuses `ownPID` and PID 1.
- **cli.go** — `parseArgs` (`--version`, `--no-browser`, `--service`, `--install-service`, `--uninstall-service`,
  `--service-status`), `serviceMode`/`noBrowser`, `ServiceStatus`, `runServiceCommand` (the three service
  commands run before log/DB/listener exist). `--tray-helper` stays ahead of all of it.
- **service_linux.go / service_other.go** — systemd integration behind pure functions: `unitFile`,
  `migrationPlan`/`migrateData` (moves `.env`, DB(+wal/shm), TLS pair — never token/logs — into `/opt/efemon`),
  `copyExecutable` (no-op on the same file: reinstalling must not truncate the running binary), the
  `/usr/local/bin/efemon` link, restart-on-reinstall, `uninstallServiceSteps` (stop **last**: from the
  service's own API the stop kills the process answering),
  `installService(fromUI)` (CLI: migrate now + `enable --now`; UI: unit carries `EFEMON_MIGRATE_FROM`, enabled
  only, the caller starts it and exits), `uninstallService` (keeps `/opt/efemon`), `serviceStatus`,
  `serviceControl(stop|restart|start)`, `runServiceMigration` (first service start). gosec G304/G703 are
  excluded for this file in CI: fixed basenames under appDir and `/opt/efemon`.
- **flight.go** — `flightGroup[K, V]`: single-flight for the table render. **queue.go** — `lookupQueue`:
  enqueue-once-while-pending + workers + `drained` callback, shared by the reputation and LAN passes.
- **connections.go** — `analyzeConnections()` (the core): enumerate via gopsutil, dedupe per exe/PID/IP,
  concurrent VT-hash + IP-enrich + LAN-lookup, build `Conn` rows. Has `Conn` struct, `fileHash`,
  `analyzeExe` (VT hash via cache→queue), `checkSignatures` (L1 mem + L2 DB) → `queryAuthenticode` on Windows
  (Authenticode) / `queryProvenance` on Unix (package ownership via dpkg/rpm/pacman → `Packaged`+pkg name =
  trusted, `Unmanaged` = neutral), `threatScore` (+ `Breakdown`), `portLabel`, `isPrivateIP`/`isBlockable`,
  `getProcDetails`, `RemoteIPs`. `threatScore` also sets `Conn.Partial` via `coverageIncomplete` — a zero
  score with unresolved key signals (VT `PENDING`/`N/A`, public IP not yet enriched) is shown as `~`
  (muted, "datos incompletos") instead of a confident "limpio", so a low score never reads as "safe".
- **intel.go** — `Enrichment`, `enrichIP` (geo ipwho.is, reverse DNS with a 3 s deadline, `vtIP`, `abuseIPDB`,
  `torExits`, `feodoC2`, `threatFoxLookup`, `spamhausHit`, `shodan`), `enrichIPCached` + `enrichQueue` (the
  render-path side, see Runtime model), provider attenuation (`detectProvider`), `ipReport`, `feedStatuses`
  (what `/api/feeds`, the privacy modal and the banner show: every feed carries a `feedMeta` — last success,
  last attempt, count, `gone` on a 410, last error — so a dead or keyless feed never reads as "no signals"),
  HTTP helpers (`getJSON`/`getText`/`postRaw`, non-200 → `httpStatusError`), `vtKey`/`abuseKey`/`abusechKey`.
  **Downloaded feeds**: ThreatFox (abuse.ch **API** `get_iocs`, Auth-Key required, last 7 days → `ip→malware
  family` map), URLhaus (same key, `urls/recent/limit/1000` ≈ 20 h, online IP-literal hosts only → `ip→family`,
  own 6 h `ttl` on its `feedMeta`, weight 35: distribution ≠ C2), Spamhaus DROP (`drop_v4.json` → CIDR set, matched with `net.IPNet.Contains`), Tor exits and
  Feodo (keyless); all cached 24h and auto-refreshed (`primeIntel` warms all four at startup and logs their state).
- **vt.go** — VT token bucket (`vtBucket`, 4/min shared hash+IP), background hash queue + `vtWorker`, `resolveHash`.
- **lan.go** — `LANInfo` (DNS/NetBIOS/MAC/**Vendor**), `lanLookup` (reverse DNS + `arpMAC` from ARP table +
  `ouiVendor` from MAC + `netbiosName` via nbtstat/nmblookup), `isLAN`. `lanLookupCached` serves the cache
  (stale included, with a refresh queued on `lanQueue`) so the render never runs nmblookup inline.
- **oui.go** — `ouiVendor(mac)`: IEEE OUI → vendor lookup, fully offline. Lazy-decompresses the embedded
  `ouidata.gz` (`go:embed`) into a map on first use; skips locally administered MACs; **longest-prefix
  match** (MA-S /36 → MA-M /28 → MA-L /24).
- **ouidata.gz** — embedded merged IEEE OUI table (MA-L+MA-M+MA-S; PREFIX\tVendor, variable-length
  prefixes, gzip, ~52k vendors), regenerate with `go run ./tools/genoui`.
- **monitor.go** — SSE pub/sub (`subscribe`/`publish` = log + push, `broadcast` = push only), `Event`,
  `snapshot`/diff (skips `ownPID` and `ownChild` — our own nmblookup/arp/tshark), beaconing (`checkBeacon`),
  `alertOnIntel` (background reputation alert on new public conns), desktop-notify triggers. (`baselineSeen` is in db.go.)
- **notify.go** — `notify()` (throttled), `sendNotification`: Windows modern toast with a registered
  **AppUserModelID** (`eFe.ProcessMonitor`, so it shows the app name, not PowerShell), `IconUri` set to the
  **real app icon** (`notifyIcon()` extracts the embedded `icon.png` next to the exe once) + `<audio silent>`
  when sound off; Linux `notify-send` (with the same extracted app icon via `-i`). Flags `notifyDesktop`,
  `notifySound`. Titles localized via `currentLang()`.
- **audit.go** — machine audit engine. `Audit(lang)` runs processes / persistence / hardening / rootkit
  **concurrently**, each sorted by severity. `AuditCheck{Category,Key,Name,Status,Detail,Items,New}`:
  `Key` is the i18n key (stable identity), `Items` the raw findings, `New` those first seen within
  `auditNewWindow` (24 h) per the `audit_seen` table (`applyAuditDiff`; the first scan marks nothing).
  Items are keyed by `auditItemKey` (the "(pid N)" blanked: a PID is not identity, and keying on it made
  every reboot mark the same processes NEW); `migrateAuditSeen` folds pre-existing rows in at start-up.
  Per-user files are checked for every real account (`userHomes`), not `$HOME` — under sudo that is /root.
  `auditStrings` = audit i18n (es/en/zh) via `atr(lang,key)`. `auditCached(lang,refresh)` per-language cache.
- **audit_parse.go** — the audit's pure parsers (reg query, IFEO, schtasks, services, driverquery,
  ss/netstat, unit files, nft/iptables counts, hosts), each with a fixture test in `audit_test.go`.
- **audit_windows.go / audit_linux.go / audit_other.go** — build-tagged `hiddenProcs(lang)` (cross-view:
  Linux kill-vs-/proc, Windows API-vs-tasklist) and `promiscIfaces()`.
- **actions.go** — `blockIP`/`unblockIP` (Windows netsh, Linux iptables/nft fallback), `openBrowser`,
  `relaunchSelf` (spawns a fresh copy with `RESTART_WAIT=1` for the "Restart now" action), `isElevated`,
  `startupBanner`, `hasCmd`, `ensureNft`. (Relaunch handoff: the new process retries `net.Listen` ~10s
  while the old one frees the port.)
- **db.go** — SQLite (modernc, `SetMaxOpenConns(1)`). Tables: hashes, events, signatures, baseline,
  baseline_hash, whitelist, ip_whitelist, blocked, hostnames, score_history. Indexes `events(exe, epoch)`
  and `score_history(exe, ip, epoch)` back the per-render queries. `pruneEvents` (start-up + daily) applies
  `EVENT_RETENTION_DAYS` to events, score_history **and hostnames**, then `incremental_vacuum`
  (`ensureIncrementalVacuum` converts an older file once). Every `rows.Next` loop ends in `rowsDone`. **Pure persistence
  layer** (`db*` helpers: `dbAddWhitelist`, `dbAllBlocked`, …) + `baselineSeen(exe, hash)` → `(seen,
  changed)`: keyed by content, adopts pre-upgrade path-only rows silently. The session-aware public
  API is in store.go.
- **store.go** — **session state layer** for operator actions (whitelist / IP whitelist / blocked).
  In-memory maps are the source of truth for the running instance; `whitelist()`/`addWhitelist`/
  `saveBlocked`/`listBlocked`/… read/write them. `loadState()` (startup) seeds from the DB. When
  the matching toggle (`persistWhitelist` for binaries+IPs, `persistBlocks` for blocked IPs) is on,
  changes write through to SQLite (survive restarts); when off they're session-only. Adds write-through
  if persisting; removes always delete from DB. `flushWhitelist()`/`flushBlocks()` (on toggling a
  permanent setting on) persist the current session.
- **listen.go** — bind/TLS resolution. `resolveListen()` honors `LISTEN_ADDR`; **a non-loopback bind is
  gated on login** (no password → forced back to `127.0.0.1` + warning) and **served over HTTPS**
  (`tlsListener`: user `LISTEN_CERT`/`LISTEN_KEY`, else a cached self-signed cert next to the exe with
  SANs for loopback + every local IP). Sets `listenExposed`/`listenTLS`.
- **auth.go** — transport hardening + optional single-password gate (no user management by design).
  After the local token is exchanged for a cookie, GET/HEAD are redirected to the URL without `?t=`
  (`tokenlessTarget`: local path only — "//evil.com" is an open redirect).
  `securityMiddleware` (wraps everything via `rootHandler`): **Host allow-list** (`hostAllowed` — loopback,
  plus IP-literal Hosts when exposed → anti DNS-rebinding), **same-origin Origin check** on writes (anti
  CSRF; `Referrer-Policy: same-origin` so form POSTs keep their Origin), then the auth gate. `sessionCookie`
  sets `Secure` when serving HTTPS. Password is bcrypt-hashed,
  stored base64 in `.env` (`setAuthPassword`, min 8 chars); in-memory sessions (`sid` cookie,
  HttpOnly+SameSite=Strict, 12h). Brute-force **lockout** (exponential backoff after 5 fails: 30s→15m) +
  per-request **security headers** (CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`).
  `handleLogin`/`handleLogout` + an inline bilingual login page. Toggled from Settings.
- **config.go** — `getSettings`/`updateSettings`/`setNotifyDesktop`/`setNotifySound`/`setPersistWhitelist`/
  `setPersistBlocks`/`setRefreshSecs`/`writeEnv`/`mask`. `refreshSecs` (table auto-refresh) lives here.
- **ports.go** — `knownPorts` (services) + `suspiciousPorts` (malware/C2 defaults, feed threat score).
- **i18n.go** — `translations` (es/en/zh) for the UI, `langFrom(r)` (?lang or cookie), `strings_(lang)`.
  Score breakdowns are **not prose in the code**: `threatScore` emits `reason{key, pts, args}`,
  `encodeReasons` packs them as `key/pts/arg|arg;…` (what `score_history` stores) and
  `localizeBreakdown(lang, code)` renders them through the `bd_*` keys at display time.
  `langFrom` also records `uiLang` (guarded global) so background goroutines can localize via
  `currentLang()` — the live monitor uses it to emit **desktop notifications in the selected language**.
- **tray_windows.go / tray_linux.go / tray_other.go** — `runApp`: Windows = systray icon + menu (Open/Quit);
  Linux = same over SNI/D-Bus when a `StatusNotifierWatcher` exists; else headless.
- **desktop_linux.go** — root cannot join the user's session bus, so as root every desktop
  interaction runs *as the logged-in user*. In **service mode** (`--service`, or `INVOCATION_ID` set *and*
  ppid == 1 — the variable alone is inherited by every terminal under a systemd desktop session) nobody
  launched us from a session: `sessionWatcher` polls `/run/user/*/bus` every 5 s; the first session found is
  current at once (notifications and "open panel" go there, tray or not), then the tray helper is spawned —
  one per session; `notray` or a dead helper is retried with a 15 s/30 s/1 min/5 min backoff. The helper does
  not exit at logout (systray keeps waiting on the vanished bus), so the watcher kills it when
  `/run/user/<uid>/bus` is gone and starts over. Quit from the helper, *Restart now* and *Stop* go through
  `serviceControl`; a busy port at start-up is retried ~30 s then `exit 1` so systemd retries
  (`StartLimitIntervalSec=0`); the browser never opens by itself; the handoff reads the token from `/opt/efemon`. `runAsDesktopUser(cmd)` sets credentials + session env
  (from `/proc/<pid>/environ`) for `xdg-open`/`notify-send`, and `spawnTrayHelper` runs a copy of
  the binary with `--tray-helper` (URL over stdin, "ready|notray|quit" over stdout) to show the icon.
- **tools/genicon/** — generates `web/static/icon.{ico,png}` from the hexagon design. `versioninfo.json`
  + `resource_windows.syso` embed the icon into the .exe (goversioninfo).
- **tools/genoui/** — builds `ouidata.gz` by merging the IEEE MA-L/MA-M/MA-S CSVs (downloads all three,
  or `-in a.csv,b.csv,c.csv`); skips the "IEEE Registration Authority" placeholder so subdivided blocks
  resolve to the real owner.
- **web/templates/report.html** — the shell: header, all modals (settings, history, blocked, whitelist,
  audit, block-IP, **privacy/egress**) and all CSS. **No inline JavaScript**: the script is
  **web/static/app.js** (translations arrive on `<body data-t data-refresh>`), and every control carries
  `data-action` / `data-change` / `data-input` routed by one delegated dispatcher to the `actions` table at
  the end of app.js — parameters go in `data-*` attributes, which the template escapes. **web/static/login.js**
  does the same for the login page. **web/templates/rows.html** — the connection table rows partial.

## HTTP endpoints
`/`, `/api/connections`, `/events` (SSE), `/api/interfaces`, `/capture` (SSE), `/capture.pcap`,
`/login` (GET/POST), `/logout`, `/api/events` (DELETE needs `confirm=1`), `/export.csv|json`,
`/export/timeline.json`, `/api/settings` (GET/POST),
`/api/restart` (POST — relaunches the process to apply a new `LISTEN_ADDR`), `/api/whitelist` (GET/POST/DELETE),
`/api/ip_whitelist` (GET/POST/DELETE), `/api/kill`, `/api/block_ip`, `/api/blocked`, `/api/unblock`,
`/api/audit`, `/audit.json|txt`, `/static/`.

## Conventions (follow these)
- **Every language (ES/EN/ZH) — everything user-facing must have all of them.** UI strings: add the key
  to EVERY language map in `i18n.go` (`testLangs` in `i18n_test.go` lists them and the parity tests
  fail on a missing key or a changed `%` verb count); use `{{ .T.key }}` (report.html) / `{{ $T.key }}` (rows.html) / `T.key`
  (JS, injected as `const T = {{ json .T }}`). Audit strings: add to `auditStrings` (es+en) in audit.go,
  use `atr(lang, key)`. Language comes from the ES|EN toggle (cookie).
- **No AI co-authorship in commits.** Do NOT add `Co-Authored-By: Claude…`. Author = the user (eFeSpain).
- **User speaks Spanish (Spain)** — tutear, no voseo, `es-ES` locale.
- OS-specific code: guard with `runtime.GOOS` and shell out (no Windows-only imports in shared files);
  put truly platform-specific funcs in build-tagged files. Keep it **cgo-free**.
- **Always shell out via `command()`/`commandContext()`** (proc.go), never `exec.Command` directly: in a
  `-H windowsgui` (no-console) build, every console subprocess pops a command window unless spawned with
  `CREATE_NO_WINDOW` (set by `hideWindow` in proc_windows.go; no-op elsewhere).
- **Nothing on the render path waits on the network or a subprocess.** New lookups follow the pattern:
  cache hit or `nil`, miss queued on a `lookupQueue`, worker resolves, `broadcast` a `refresh`.
- **JSON handlers decode through `decodeJSON`** and reject what does not parse; state-changing endpoints
  declare their methods with `requireMethod`.
- **No inline JavaScript, ever** (CSP `script-src 'self'`). A new control gets `data-action="name"` in the
  template and a `name: fn` entry in the `actions` table of app.js; `TestNoInlineScriptOrHandlers` and
  `TestDataActionsAreWired` enforce both halves.
- Test gotcha: due to single-instance, a stale `efemon.exe` keeps serving the OLD build — always
  `taskkill /F /IM efemon.exe` before re-running, or you'll test the old binary.
- Many features (kill, block IP, full process names, Authenticode) need **admin/root**.

## Feature status (done)
Connection inventory + process details; VT hash + Authenticode signature; IP intel (geo, VT, AbuseIPDB,
Tor, Feodo C2, ThreatFox malware C2, Spamhaus DROP, Shodan) with provider attenuation; unified threat score
(sortable, breakdown tooltip);
suspicious malware ports; live monitor (SSE feed, beaconing, baseline anomalies, desktop notifications
w/ sound toggle); forensic history (SQLite) + CSV/JSON export; tshark live capture (stats, domains/IOCs,
QUIC via `_ws.col.protocol`, colors, filter, pcap export, error handling) + interface auto-detect;
response actions (kill, block IP multi-select modal, unblock panel); whitelist (per-exe **and per-IP**)
management panel; independent permanent-vs-session toggles for whitelist and IP blocks (Settings);
server-persisted auto-refresh interval; all settings persisted in `.env` and loaded at startup;
machine audit (processes/persistence/hardening/rootkit cross-view) + export; LAN host info (NetBIOS/DNS/MAC +
offline OUI vendor name);
system tray + embedded exe icon; single instance; configurable refresh interval; settings UI for API keys
and notification toggles; optional login (single password) + Host/CSRF hardening + brute-force lockout;
opt-in network exposure (`LISTEN_ADDR`) gated on login and served over self-signed HTTPS; privacy/egress
disclosure modal; full ES/EN/ZH i18n.

## Ideas / pending (not done)
- (GreyNoise was evaluated and rejected: it classifies inbound scanners, not useful for an egress monitor.)
- Optional extra keyless feeds (CINS Army, Emerging Threats compromised-ips, blocklist.de, URLhaus).

## Rejected (don't re-propose)
- Audit "network exposure" check (listening services on public interfaces): built and removed —
  redundant with the threat score / live alerts and too noisy (lists every ephemeral RPC port).
- Remote access: loopback by default; opt-in network exposure via `LISTEN_ADDR`, **gated on login + HTTPS**
  (listen.go). SSH tunnel still works for the loopback default. Multi-user management was rejected as
  over-engineering for a single-machine tool.
