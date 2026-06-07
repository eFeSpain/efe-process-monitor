# eFe Process Monitor — Architecture & Dev Notes

Context doc to resume work in a fresh session. The product is a **defensive/forensic
process & network monitor** with a local web dashboard. Single self-contained Go binary,
cross-platform (Windows primary, Linux supported, cgo-free).

Public repo: https://github.com/eFeSpain/efe-process-monitor (the Go app = repo root contents).
A Python reference version lives in the parent folder (`../`) — **frozen**, do not edit; Go is the product.

## Build / run

```bash
cd go
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
- `.github/workflows/ci.yml` (push/PR): gofmt-clean check, `go vet`, `go test`, and a cross-build matrix
  (windows/linux/darwin, amd64+arm64) that keeps the binary cgo-free.

## Where data lives (IMPORTANT)
- **`efemon.db`** (SQLite) → next to the executable (`appDir` = dir of `os.Executable()`), set in `main.go`.
- **`.env`** → searched: exe dir → cwd → `../.env` (dev: real keys are in `../.env`). `writeEnv` saves to the one found.
- Keys/flags in `.env`: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `NOTIFY_DESKTOP`, `NOTIFY_SOUND`,
  `PERSIST_WHITELIST`, `PERSIST_BLOCKS`, `REFRESH_SECS`, `AUTH_HASH` (base64 of a bcrypt hash; "" = login off),
  `LISTEN_ADDR` ("" = `127.0.0.1:5000`), optional `LISTEN_CERT`/`LISTEN_KEY`.
  **Every setting is server-persisted in `.env`**
  (loaded at startup) — nothing UI-facing lives only in the browser.

## Runtime model
- `GET /` returns only the **shell** (instant). The table is loaded async from `GET /api/connections`
  (renders `rows.html`), so the UI shows "procesando" then fills in.
- A **live monitor** goroutine (`monitorLoop`, every 3s) diffs connection snapshots and pushes SSE
  events to `/events`; the browser shows a feed and reactively refreshes the table (debounced 1.5s,
  paused while a detail row/capture is open). Optional periodic refresh interval (Settings, localStorage).
- **VT hash lookups** are rate-limited (4/min token bucket) and resolved by a **background worker**
  (`vtWorker`); the table shows `PENDING` then caches the verdict in SQLite. `NOT_IN_VT` is cached too.
- **Single instance**: if port 5000 is taken, it opens the browser and exits.

## File map (go/)
- **main.go** — HTTP server, all routes/handlers, `go:embed` of templates+static, startup (env, DB,
  elevation, monitor, vtWorker, primeIntel, browser, banner), `appDir`/`exeDir`, template `funcMap`
  (trunc, threatClass, join, joinInts, json, deref, humanBytes).
- **connections.go** — `analyzeConnections()` (the core): enumerate via gopsutil, dedupe per exe/PID/IP,
  concurrent VT-hash + IP-enrich + LAN-lookup, build `Conn` rows. Has `Conn` struct, `fileHash`,
  `analyzeExe` (VT hash via cache→queue), `checkSignatures` (L1 mem + L2 DB) → `queryAuthenticode` on Windows
  (Authenticode) / `queryProvenance` on Unix (package ownership via dpkg/rpm/pacman → `Packaged`+pkg name =
  trusted, `Unmanaged` = neutral), `threatScore` (+ `Breakdown`), `portLabel`, `isPrivateIP`/`isBlockable`,
  `getProcDetails`, `RemoteIPs`. `threatScore` also sets `Conn.Partial` via `coverageIncomplete` — a zero
  score with unresolved key signals (VT `PENDING`/`N/A`, public IP not yet enriched) is shown as `~`
  (muted, "datos incompletos") instead of a confident "limpio", so a low score never reads as "safe".
- **intel.go** — `Enrichment`, `enrichIP` (geo ip-api, reverse DNS, `vtIP`, `abuseIPDB`, `torExits`,
  `feodoC2`, `threatFoxLookup`, `spamhausHit`, `shodan`), provider attenuation (`detectProvider`), `ipReport`,
  HTTP helpers (`getJSON`/`getText`/`getZipCSV`), `vtKey`/`abuseKey`. **Keyless downloaded feeds**: ThreatFox
  (abuse.ch zipped CSV → `ip→malware family` map) and Spamhaus DROP (`drop_v4.json` → CIDR set, matched with
  `net.IPNet.Contains`); both cached 24h and auto-refreshed (no manual refresh — `primeIntel` warms all four at startup).
- **vt.go** — VT token bucket (`vtBucket`, 4/min shared hash+IP), background hash queue + `vtWorker`, `resolveHash`.
- **lan.go** — `LANInfo` (DNS/NetBIOS/MAC/**Vendor**), `lanLookup` (reverse DNS + `arpMAC` from ARP table +
  `ouiVendor` from MAC + `netbiosName` via nbtstat/nmblookup), `isLAN`.
- **oui.go** — `ouiVendor(mac)`: IEEE OUI → vendor lookup, fully offline. Lazy-decompresses the embedded
  `ouidata.gz` (`go:embed`) into a map on first use; skips locally administered MACs; **longest-prefix
  match** (MA-S /36 → MA-M /28 → MA-L /24).
- **ouidata.gz** — embedded merged IEEE OUI table (MA-L+MA-M+MA-S; PREFIX\tVendor, variable-length
  prefixes, gzip, ~52k vendors), regenerate with `go run ./tools/genoui`.
- **monitor.go** — SSE pub/sub (`subscribe`/`publish`), `Event`, `snapshot`/diff, beaconing (`checkBeacon`),
  `alertOnIntel` (background reputation alert on new public conns), desktop-notify triggers. (`baselineSeen` is in db.go.)
- **notify.go** — `notify()` (throttled), `sendNotification`: Windows modern toast with a registered
  **AppUserModelID** (`eFe.ProcessMonitor`, so it shows the app name, not PowerShell), `IconUri` set to the
  **real app icon** (`notifyIcon()` extracts the embedded `icon.png` next to the exe once) + `<audio silent>`
  when sound off; Linux `notify-send` (with the same extracted app icon via `-i`). Flags `notifyDesktop`,
  `notifySound`. Titles localized via `currentLang()`.
- **audit.go** — machine audit engine. `Audit(lang)` → processes / persistence / hardening / rootkit checks.
  `AuditCheck{Category,Name,Status(ok|warn|risk|info),Detail}`. `auditStrings` = audit i18n (es/en) via `atr(lang,key)`.
  `auditCached(lang,refresh)` per-language cache.
- **audit_windows.go / audit_linux.go / audit_other.go** — build-tagged `hiddenProcs(lang)` (cross-view:
  Linux kill-vs-/proc, Windows API-vs-tasklist) and `promiscIfaces()`.
- **actions.go** — `blockIP`/`unblockIP` (Windows netsh, Linux iptables/nft fallback), `openBrowser`,
  `relaunchSelf` (spawns a fresh copy with `RESTART_WAIT=1` for the "Restart now" action), `isElevated`,
  `startupBanner`, `hasCmd`, `ensureNft`. (Relaunch handoff: the new process retries `net.Listen` ~10s
  while the old one frees the port.)
- **db.go** — SQLite (modernc, `SetMaxOpenConns(1)`). Tables: hashes, events, signatures, baseline,
  whitelist, ip_whitelist, blocked. **Pure persistence layer** (`db*` helpers: `dbAddWhitelist`,
  `dbAllBlocked`, …) + `baselineSeen`. The session-aware public API is in store.go.
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
- **i18n.go** — `translations` (es/en) for the UI, `langFrom(r)` (?lang or cookie), `strings_(lang)`.
  `langFrom` also records `uiLang` (guarded global) so background goroutines can localize via
  `currentLang()` — the live monitor uses it to emit **desktop notifications in the selected language**.
- **tray_windows.go / tray_other.go** — `runApp`: Windows = systray icon + menu (Open/Quit); else headless.
- **tools/genicon/** — generates `web/static/icon.{ico,png}` from the hexagon design. `versioninfo.json`
  + `resource_windows.syso` embed the icon into the .exe (goversioninfo).
- **tools/genoui/** — builds `ouidata.gz` by merging the IEEE MA-L/MA-M/MA-S CSVs (downloads all three,
  or `-in a.csv,b.csv,c.csv`); skips the "IEEE Registration Authority" placeholder so subdivided blocks
  resolve to the real owner.
- **web/templates/report.html** — the shell: header, all modals (settings, history, blocked, whitelist,
  audit, block-IP, **privacy/egress**), all CSS and all JS. **web/templates/rows.html** — the connection table rows partial.

## HTTP endpoints
`/`, `/api/connections`, `/events` (SSE), `/api/interfaces`, `/capture` (SSE), `/capture.pcap`,
`/login` (GET/POST), `/logout`, `/api/events`, `/export.csv|json`, `/api/settings` (GET/POST),
`/api/restart` (POST — relaunches the process to apply a new `LISTEN_ADDR`), `/api/whitelist` (GET/POST/DELETE),
`/api/ip_whitelist` (GET/POST/DELETE), `/api/kill`, `/api/block_ip`, `/api/blocked`, `/api/unblock`,
`/api/audit`, `/audit.json|txt`, `/static/`.

## Conventions (follow these)
- **Bilingual (ES/EN) — everything user-facing must have both.** UI strings: add the key to BOTH
  `es` and `en` maps in `i18n.go`; use `{{ .T.key }}` (report.html) / `{{ $T.key }}` (rows.html) / `T.key`
  (JS, injected as `const T = {{ json .T }}`). Audit strings: add to `auditStrings` (es+en) in audit.go,
  use `atr(lang, key)`. Language comes from the ES|EN toggle (cookie).
- **No AI co-authorship in commits.** Do NOT add `Co-Authored-By: Claude…`. Author = the user (eFeSpain).
- **User speaks Spanish (Spain)** — tutear, no voseo, `es-ES` locale.
- OS-specific code: guard with `runtime.GOOS` and shell out (no Windows-only imports in shared files);
  put truly platform-specific funcs in build-tagged files. Keep it **cgo-free**.
- **Always shell out via `command()`/`commandContext()`** (proc.go), never `exec.Command` directly: in a
  `-H windowsgui` (no-console) build, every console subprocess pops a command window unless spawned with
  `CREATE_NO_WINDOW` (set by `hideWindow` in proc_windows.go; no-op elsewhere).
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
disclosure modal; full ES/EN i18n.

## Ideas / pending (not done)
- (GreyNoise was evaluated and rejected: it classifies inbound scanners, not useful for an egress monitor.)
- Optional extra keyless feeds (CINS Army, Emerging Threats compromised-ips, blocklist.de, URLhaus).

## Rejected (don't re-propose)
- Audit "network exposure" check (listening services on public interfaces): built and removed —
  redundant with the threat score / live alerts and too noisy (lists every ephemeral RPC port).
- Remote access: loopback by default; opt-in network exposure via `LISTEN_ADDR`, **gated on login + HTTPS**
  (listen.go). SSH tunnel still works for the loopback default. Multi-user management was rejected as
  over-engineering for a single-machine tool.
