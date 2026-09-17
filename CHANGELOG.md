# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased] — audit: every user's home, more persistence, new-since badge

### Added
- **Reverse-shell detection (Linux)**: a shell or interpreter whose stdin or
  stdout *is* a socket. Nothing legitimate wires a shell's standard streams to
  a socket; every reverse-shell one-liner does.
- **Traced processes (Linux)**: `TracerPid` set — a debugger, or an injection.
- **System-level systemd units**: locally defined units/timers are listed, and
  any whose `Exec*` starts something from temp, shm or a home directory is a
  finding. This is the most common Linux persistence and was not covered.
- **Windows persistence**: Winlogon `Shell`/`Userinit`, IFEO `Debugger`
  hijacks, `AppInit_DLLs`, services whose binary sits in a user-writable
  directory, and unquoted service paths with spaces.
- **`/etc/passwd` / `shadow` / `sudoers` permissions** and, without ufw, the
  actual nft/iptables rule count instead of "check manually".
- **"NEW" badge**: every item a scan reports is remembered with its first
  sighting; anything first seen in the last 24 h is marked, in the panel and
  in `audit.txt`. The first scan on a machine marks nothing. The panel also
  shows when the (cached) result was produced.

### Fixed
- **Run as root, the audit inspected the wrong home.** `~/.bashrc`, autostart
  entries, user systemd units and `authorized_keys` were read from `/root`
  under sudo. Every real account's home is now checked and each finding says
  whose it is.
- The hidden-process sweep stopped at PID 500 000 while `pid_max` is
  4 194 304 on systemd machines; it now walks the whole range under a time
  budget and reports when it was cut short. A process that exits between the
  probe and the `/proc` check is re-verified instead of reported as hidden.
- `authorized_keys` unreadable for permissions was reported as "no keys";
  it is now "could not check".
- The hosts-file filter dropped any line containing "localhost", so
  `1.2.3.4 bank.com # localhost` passed as boilerplate.

### Changed
- The four audit categories run concurrently; the scan takes as long as the
  slowest one. Checks are ordered by severity within each category.
- Every parser the audit relies on (reg query, schtasks, driverquery, ss /
  netstat, unit files, hosts) is a pure function with a fixture test.
- `/api/audit` returns `{at, checks}`; each check carries a stable `key`, its
  raw `items` and the `new` ones. `/audit.json` is unchanged.

## [Unreleased] — passive DNS, content baseline, miner signal, timeline export

### Added
- **Passive DNS outside captures.** "What name did the process ask for?" was
  only answered while a tshark capture ran. Now DNS answers are read all the
  time: on Linux as root through an AF_PACKET socket with a BPF filter for
  UDP source port 53 (no libpcap, no tshark; `dns_linux.go`), on Windows by
  polling the resolver cache every 30 s (`Get-DnsClientCache`, no
  privilege). Bindings land in the same hostnames table with the same
  "observed DNS answer" label. DNS over HTTPS/TLS is not visible; the
  tooltip says so.
- **Baseline by content.** The new-binary baseline is keyed by (path,
  sha256), so a binary replaced in place — the most common persistence move
  — raises an alert with the reason and its own desktop notification. Rows
  from earlier builds are adopted silently on first sighting.
- **Cryptominer signal.** CPU over 50 % of the machine for 15 s is flagged
  and scores (+25) only from a binary that is already suspect, the same rule
  as the egress signal. Pinned in the corpus both ways.
- **`/export/timeline.json`**: one entry per (binary, remote address) with
  its events, risk changes (localized), names asked for and block/whitelist
  state — the incident report as a single document, from the history modal.

### Fixed
- Persisted IP blocks are re-created in the firewall at startup on Linux
  (iptables/nft rules do not survive a reboot; netsh ones do).
- `DELETE /api/events` requires `confirm=1`; the UI already asked.
- `tools/genoui` cut vendor names by byte and could split a multi-byte
  character; now by rune, with the first test under `tools/`.

## [Unreleased] — Simplified Chinese, language-neutral score history

### Added
- **Simplified Chinese (zh-CN) UI**, requested in #1: every UI, login, gate,
  notification and audit string, selectable from the flag toggle. Translated
  from the English set with the industry's usual loanwords kept as they are
  (VT, SNI, rDNS, PID, C2); a native review is welcome — the parity tests
  guarantee no key is missing, not that every phrase is idiomatic.
- The translation tests now cover every language in the map, not just es/en,
  and also pin the `%` verb count per key, so a translation that drops a `%s`
  cannot print `%!(EXTRA …)` into a tooltip.

### Fixed
- **Run as root on Linux: no tray icon, no desktop notifications, and the
  browser never opened.** All three had one cause: `sudo` strips the
  graphical session from the environment, and the session D-Bus only admits
  the uid that owns it (dbus-daemon(1)), so root cannot borrow it either.
  The tray check failed and the panel showed the "install the GNOME
  extension" hint on a KDE desktop with a perfectly good tray.

  Desktop work is now done *as the logged-in user*: `xdg-open` and
  `notify-send` are spawned with that user's credentials and session
  environment (read from a process of theirs: `WAYLAND_DISPLAY`, `DISPLAY`,
  `XAUTHORITY`, the bus address), and the tray icon is shown by a helper copy
  of the binary run the same way (`--tray-helper`), which receives the
  dashboard URL over stdin and relays "Quit" over stdout. The user is
  `SUDO_UID`/`PKEXEC_UID`, or the only user with a session bus. When no
  session can be identified, the panel says that instead of blaming the
  desktop.
- **Blocking an IPv6 peer on Linux failed.** `iptables -d <v6>` errors out and
  the nft set was `ipv4_addr`, so "Block IP" on any IPv6 remote returned an
  error (Windows `netsh` was fine). Linux now picks `ip6tables` and a second
  `ipv6_addr` set by address family.

### Changed
- Legacy malware-port labels (`SubSeven (RAT, histórico)`…) carried a Spanish
  note inside the data. The label is now the name only, and the "legacy, never
  scores" note is rendered from i18n next to it with its own tooltip.
- **The score breakdown is no longer Spanish-only.** `threatScore` emits
  reason keys with arguments; the tooltip renders them in the active language
  and `score_history` stores the neutral encoding, so the risk timeline reads
  correctly whichever language is on when it is opened. Rows written by earlier
  builds (free text) are shown unchanged. Switching the language no longer
  registers as the risk of every pair having changed. The IP report attached to
  a block, the "IP cannot be blocked" and "no firewall tool" messages follow the
  UI language too.

## [Unreleased] — resource usage per process

### Added
- **CPU, memory, threads and owner per process**, sampled in the same monitor
  pass that already reads the I/O counters (`volume.go`), so it costs two extra
  cgo-free calls per socket-holding process every 3 s and nothing per render.
  Shown as a sortable **CPU / Mem** column next to the process name and as a
  *Resources* line in the details block.

  CPU is a percentage of the whole machine (100 % = every core busy), averaged
  over the last interval, so the first value takes two samples; PID reuse is
  detected the same way as for the I/O counters (the cumulative clock going
  backwards) and resets the figure and the owner. Memory is the resident set —
  on Windows the working set, shared pages included, and the tooltip says so.

  **None of it scores.** Same principle as volume: a compiler, a game and a video
  call all burn CPU and memory, and weighting that would only add noise.
- **Disk I/O line (Linux)** in the details block: the block-device bytes, next
  to the syscall totals the I/O line already showed. The difference between the
  two is what the throughput figure is built on, and now both are visible.
  Windows does not separate disk from network, so the line is Linux-only.

### Fixed
- **`.env` line injection from Settings.** `writeEnv` wrote values verbatim, so
  a settings request carrying `"x\nAUTH_HASH="` in an API-key field produced a
  second line — and godotenv keeps the last assignment, so on the next start the
  login could be off. That request only had to be authenticated; changing or
  removing the password is supposed to require the *current* password. Values
  are now trimmed and stripped of line breaks before they are written.
- The monitor no longer treats a failed first enumeration as "nothing was open":
  the next good snapshot used to announce every existing connection as new.
- `ancestryOf` opened each process in the chain twice; on Windows that is two
  `OpenProcess` calls per link, per PID, per render.

## [Unreleased] — data-volume signal, real ACLs on the secrets

### Added
- **`verify.sh`**: runs every CI gate locally in the same order, then cross-compiles
  all six release targets and executes the test binary on Linux through WSL. It
  exists because three separate CI failures had the same cause — a local run that
  covered a subset of the gates. Each tool in it has caught something the others
  missed: `-race` found the settings data races, `gosec` an unbounded PID
  conversion, `staticcheck` dead code, and the Linux run a `filepath.Base` call
  whose GOOS dependence had made a detection rule permanently inert.
- **Data-volume signal.** The process I/O counters were already being read and
  displayed and then used for nothing. `volume.go` now tracks the per-process
  rate between monitor samples and flags a sustained outbound flow.

  What the numbers are, because it bounds the claim: on Linux `rchar`/`wchar`
  minus the block-device totals isolates non-disk traffic, which is a reasonable
  proxy for network egress; on Windows `GetProcessIoCounters` lumps file, network
  and device I/O together with no way to separate them. Neither platform
  attributes bytes to a connection, so this is per-process and cannot prove where
  the data went. The UI says all of this in the tooltip.

  **Volume scores nothing on its own** — a download, a backup and a video call all
  move data, and weighting that would repeat the mistake the path and port signals
  used to make. It adds to the score only when the binary is already suspect for
  an independent reason (staging path, anomalous spawn chain, malware port), which
  is the actual exfiltration shape. Pinned in the corpus both ways: a signed app
  at 8 MB/s scores 0, an unsigned binary in Temp at 2 MB/s scores 65.

### Security
- **The token file and the TLS private key now get a real ACL on Windows.**
  `os.WriteFile(..., 0600)` is a no-op there — Go maps the mode to the read-only
  attribute and nothing else — so both files simply inherited the directory ACL
  and were readable by any process running as this user. For the local access
  token that is precisely the principal the gate exists to exclude.

  `writeSecretFile` now applies an explicit ACL. The set depends on elevation,
  because elevating on Windows does **not** change your SID: an elevated and a
  non-elevated process of the same account share it, so granting "the current
  user" would leave the hole open. What differs is that the Administrators group
  is deny-only in a non-elevated token.

  - elevated → Administrators + SYSTEM. A non-elevated same-user process is
    refused, which closes the escalation path. Verified by applying the ACL and
    confirming a non-elevated read fails with `Permission denied`.
  - not elevated → the current user only. Cannot do better without locking
    ourselves out, but other users of the machine are shut out — the equivalent of
    0600 on Unix.

  The startup banner now prints who can read the token, and warns explicitly when
  running unelevated on Windows means a same-user process could still read it.
  Documented in the code: there is a one-syscall window between creating the file
  and applying the ACL, because attaching a security descriptor at creation needs
  `CreateFileW` with `SECURITY_ATTRIBUTES`, which Go's `os` package does not expose.

---

## [Unreleased] — hostname correlation, risk timeline, release provenance, macOS

### Added
- **Hostname correlation: what the process actually asked for.** Everything else
  the tool knew about a remote address was *about the address* — geo, ASN,
  reputation — and none of it answered the first question an analyst asks.
  `hostnames.go` records the bindings already flowing through the capture parser
  and previously discarded: the TLS **SNI** (the client wrote that name into a
  handshake sent to that address — no inference) and **DNS answer records**. Shown
  on the connection card as "asked for", with SNI marked as the stronger source.
  Reverse DNS stays, relabelled `rDNS`, because it is a weaker claim made by the
  address owner — who controls their own PTR record.
- **Risk timeline** (`score_history`): one row each time the verdict for an
  (exe, remote IP) pair changes, with the breakdown that produced it, exposed at
  `/api/score_history` and in the history modal. The score used to exist only on
  the rendered page, so the history could not answer "what did this look like on
  Tuesday". Written as a change log, not per render, so refreshes don't bury the
  real transitions; bounded by the same retention window as the events.
- **Signed build provenance on releases** (`actions/attest-build-provenance`).
  `checksums.txt` only proves the files agree with themselves; it says nothing
  about where they came from. Downloads can now be verified with
  `gh attestation verify <file> --repo eFeSpain/efe-process-monitor`.

### Fixed
- **The audit no longer claims to have run checks it cannot.** On macOS the
  process cross-view was a stub returning an empty list, and the deleted-binary
  check read `/proc`, which does not exist there — so both rendered as confident
  passes ("no discrepancies between process sources"). A probe that did not run
  now reports "not available on this OS", the same honesty the command-failure path
  already had. The same applies to a failed `tasklist` on Windows and an
  unreadable sysfs on Linux.
- Guarded the database helpers reachable from the capture path against a nil
  handle: a missing database should cost a row, not panic the capture goroutine.

### Removed
- **macOS binaries are no longer published.** The badge claimed a platform that
  had never been tested, and the reason not to ship it is concrete rather than
  cautious: parts of the audit have no macOS implementation, so a user would be
  running a security tool with holes in it. The code still cross-compiles for
  darwin and CI keeps proving it, so building from source remains possible — the
  README now explains what is missing instead of implying support.

---

## [Unreleased] — logging, process ancestry, score calibration

### Added
- **The application log now survives the shipped binary.** Release builds link
  with `-H=windowsgui`, so the process has no usable stderr and every log line —
  the whole operator audit trail (`KILL`, `BLOCK`, `UNBLOCK`, settings changed,
  history cleared) plus the security events (`[gate] blocked`, `[csrf] blocked`) —
  was written to a handle that goes nowhere. `logging.go` tees the standard logger
  to `efemon.log` next to the executable, rotating at 5 MiB and keeping 3
  archives, and `/logs.txt` shows it in the dashboard. Verified against a real
  `-H=windowsgui` build, not just a console one.
- **Full process ancestry** with spawn-chain detection. Showing only the immediate
  parent hid the signal: `cmd.exe` under `explorer.exe` is a user at a terminal,
  the identical `cmd.exe` under `winword.exe` is a macro payload — same process,
  same path, same signature. `ancestryOf` walks the chain (depth-capped and
  cycle-safe) and `suspiciousAncestry` flags patterns that should never occur:
  document or browser → script host / LOLBin, web server → shell (webshell). It is
  one of the few high-precision signals available with no external service, and
  scores accordingly.
- **A score calibration corpus** (`score_corpus_test.go`): labelled, realistic
  rows pinned to score *bands* (benign / notable / suspicious / malicious), plus
  ordering invariants that must hold through any re-tune. The headline feature had
  no way to tell a tuning fix from a regression.

### Changed
- **Re-tuned the two locally-computed score signals, which were the main
  false-positive source.** Both were as loud as a curated C2 feed hit:
  - Path signals are now two tiers. Staging directories (temp, `\Users\Public`,
    `/dev/shm`) keep the full weight; the downloads folder drops to a nudge —
    running an installer from there is what installers do, and it used to make a
    healthy machine show a wall of amber rows.
  - Malware ports are split into ones still used by live tooling (Metasploit
    4444/4445, reduced weight) and extinct 1990s RATs, which now **label without
    scoring**. 1337 and 12345 are ordinary development ports today.
- Score weights are named constants instead of numbers inline, so a tuning change
  is reviewable in a diff.
- `/favicon.ico` is a public path: every browser probes for it, and each probe was
  logging a `[gate] blocked` line into the same audit log used to spot real
  blocked attempts.
- Ancestry labels drop trailing unresolved links — without elevation the walk runs
  out of permission and a label ending in `? ← ? ← ?` says nothing. An unknown
  *between* two known names is kept, because there the gap is the information.

---

## [Unreleased] — security & correctness review

### Security
- **Fixed a DNS-rebinding bypass.** The loopback check tested
  `strings.HasPrefix(host, "127.")`, so an attacker-owned name like
  `127.0.0.1.evil.com` passed both the Host allow-list and the same-origin CSRF
  check, giving a malicious page full access to the API. The check now parses the
  Host as an IP and requires `IsLoopback()`; `localhost` is the only name allowed.
- **Closed the unauthenticated local API.** The Host/Origin checks only constrain
  browsers; any local program could POST to the port and, because the tool runs
  elevated, obtain kill / firewall / settings / shutdown. There is now always one
  gate: a password if set, otherwise a per-run local access token written to
  `efemon-token` (0600) and handed to the browser through the URL the app opens.
- **Geolocation moved to HTTPS** (`ipwho.is`). The old `http://ip-api.com` call
  leaked the addresses under investigation and, worse, was rewritable in transit:
  injecting `"org":"Cloudflare"` made `detectProvider` attenuate the AbuseIPDB
  weight from 0.4 to 0.1, lowering the score of a malicious IP.
- **`.env` writes are atomic** (temp file + rename) and serialized. A crash during
  the previous truncate-then-write could drop `AUTH_HASH`, silently disabling the
  login. Two concurrent settings POSTs could also lose keys.
- **Threat-feed downloads are size-capped** (`io.LimitReader`, plus a cap on
  decompressed ZIP output), and their HTTP status is checked — a 503 HTML page was
  previously parsed as feed content and cached as the Tor exit list for 24h.
- Changing or disabling an existing password now requires the current one.
- Login backoff is **per client IP**; it was global, so anyone reaching the port
  could lock the real operator out.
- HTTP server now sets `ReadHeaderTimeout` and `IdleTimeout` (slowloris).
- `esc()` in the UI escapes single quotes, and the one single-quoted handler was
  moved to the `data-*` + `dataset` pattern used elsewhere.
- The `.env` lookup no longer walks the working directory and its parent unless
  `EFEMON_DEV=1`; launching the binary inside another project would otherwise read
  *and rewrite* that project's `.env`.
- `efemon.db` is created mode 0600 (it holds the forensic history).

### Fixed
- **UDP is visible again.** gopsutil never reports `LISTEN`/`ESTABLISHED` for
  datagram sockets (`NONE` on Linux, empty on Windows), so filtering on those two
  labels dropped *every* UDP socket from the table, the live monitor and the
  history — QUIC/HTTP3 on 443, DNS and UDP-based C2 included.
- **No more phantom rootkit findings.** The same root cause made the audit's
  cross-view compare an API set with no UDP against `ss -tuln`, which lists UDP,
  so every open UDP port was reported as a hidden listening port.
- **Fixed a crash in packet capture.** `streamCapture` returned on stop without
  waiting for its scanner goroutine, which could then hit a send on the
  already-closed packet channel — a panic in a goroutine that takes the process
  down. It also read the stderr buffer before `Wait()` (a data race).
- Capture no longer leaks tshark: cancellation is watched while waiting for the
  next packet (with `∞` on an idle flow, closing the tab used to leave it
  running), and the pcap download runs under the request context.
- **Enrichment is cached even when geolocation fails.** It previously cached only
  on success, so once the geo provider rate-limited us nothing was cached and
  every refresh re-queried VirusTotal, AbuseIPDB, Shodan and reverse DNS for every
  address on screen.
- Feeds back off after a failure. `at` was only advanced on success, so an
  unreachable feed was re-downloaded on *every* enrichment call, serialized behind
  its mutex — turning a page render into minutes.
- Audit checks report "could not check" instead of "ok" when the underlying
  command fails or times out. `find … -perm /6000` over a large `/home` routinely
  timed out and was reported as "no SUID binaries found".
- Windows audit checks no longer depend on the system language: the firewall state
  and the Administrators group are read via `Get-NetFirewallProfile` and the
  well-known SID `S-1-5-32-544`, and NetBIOS name parsing no longer requires the
  English word "UNIQUE". On a Spanish Windows several of these silently misreported.
- `/api/audit` only re-scans when asked; it passed `refresh=true` unconditionally,
  making the cache dead code and every panel open a full machine scan. The scan no
  longer holds a lock that blocked `/audit.json` and `/audit.txt`.
- Data races on the runtime settings (`notifyDesktop`, `notifySound`,
  `persistWhitelist`, `persistBlocks`, `refreshSecs`, `listenAddr`), read by
  background goroutines and written by HTTP handlers. CI now runs `go test -race`.
- Linux firewall rules are idempotent: `iptables -A` appended a duplicate on every
  repeat block and a single `-D` removed only one, leaving the IP still blocked
  after "unblock".
- `trunc` in the templates cuts by rune, not byte — accented paths no longer
  render a replacement diamond.
- The language cookie has a `MaxAge`, so the choice survives a browser restart.

### Changed
- Code-signature lookups moved off the request path into a background worker
  (like the VirusTotal hashes already were): PowerShell start-up on Windows, or
  one sequential `dpkg -S` per binary at 5s each on Linux, used to run inside the
  HTTP handler. Unresolved entries show `PENDING` and count as incomplete data for
  the score, never as a bad signature.
- Per-request enrichment is bounded (8 workers per pass) and deduplicated: process
  identity is looked up once per PID instead of once per socket, and concurrent
  lookups of the same IP share one result.
- SQLite runs in WAL with a `busy_timeout`, and the `events` table has a retention
  window (`EVENT_RETENTION_DAYS`, default 30) pruned at startup and daily.
- Long-lived caches are bounded (sessions, notification throttle, beacon tracking,
  known PIDs, file hashes, signatures, IP and LAN lookups); several previously grew
  for the lifetime of the process.
- Added tests: the templates are parsed *and executed* (they were runtime-only), and
  the security middleware is covered end to end — token gate, rebinding hosts,
  CSRF, password takeover, headers.

---

## [0.2.0] — 2026-06-08

### Added — Linux support
- **System tray icon on Linux** via the D-Bus StatusNotifierItem protocol
  (`fyne.io/systray`). Works natively on KDE Plasma, XFCE, MATE, Cinnamon and
  any desktop that implements the SNI spec. On GNOME, the
  *AppIndicator and KStatusNotifierItem Support* extension is required.
- **Automatic tray detection**: at startup the app queries the session D-Bus for
  a StatusNotifierWatcher. If none is found it runs headless and shows a
  warning banner in the web UI with setup instructions.
- **"Stop service" button** in the web dashboard, visible only when no tray
  icon is available, with confirmation dialog. Backed by a new
  `POST /api/shutdown` endpoint.

### Added — Audit checks (Linux)
- **SSH authorized_keys**: lists every entry in `~/.ssh/authorized_keys` so
  unexpected backdoor keys are immediately visible.
- **Sudoers NOPASSWD**: scans `/etc/sudoers` and all files under
  `/etc/sudoers.d/` for `NOPASSWD` entries.
- **SUID/SGID binaries in dangerous paths**: finds executables with the SUID
  or SGID bit set under `/tmp`, `/var/tmp`, `/dev/shm`, `/home` and `/var/www`.
- **AppArmor / SELinux status**: reports whether a mandatory access control
  system is active, which one, and its mode (enforcing / permissive).
- **World-writable directories in PATH**: flags any `$PATH` entry writable by
  all users, which allows command hijacking without privileges.
- **LD_PRELOAD in `/etc/environment`**: detects system-wide library injection,
  a technique used by user-mode rootkits.
- **Out-of-tree kernel modules**: reads `/sys/module/*/taint` and lists modules
  with the `O` (out-of-tree) or `E` (unsigned) flag. Proprietary drivers such
  as Nvidia legitimately appear here; the check provides context, not a verdict.

### Fixed — Documentation
- **README described Linux tray as unsupported**: both README.md and README.es.md
  now document the SNI tray behaviour, the GNOME extension requirement, and the
  web-UI fallback stop button.

### Fixed — Linux compatibility
- **Suspicious path detection was broken on Linux**: `suspiciousPaths` only
  contained Windows backslash paths; none of them ever matched a Linux path.
  Added `/tmp/`, `/var/tmp/`, `/dev/shm/` and `/downloads`.
- **`notify-send` ignored the "sound" setting**: the urgency was hardcoded to
  `critical` regardless of the *Alert sound* toggle. Now maps the toggle to
  `normal` (sound on) / `low` (sound off).
- **ARP lookup used the deprecated `arp` command**: on modern Linux systems
  `arp` is not installed by default. The lookup now tries `ip neighbor show`
  first and falls back to `arp` for older kernels and other platforms.
- **Shell startup audit only checked bash files**: expanded the scanned file
  list to include `.zshrc`, `.zprofile`, `~/.config/fish/config.fish`,
  `/etc/bash.bashrc` and every file under `/etc/profile.d/`.
- **Shell startup audit missed library-injection patterns**: added
  `LD_PRELOAD` and `LD_LIBRARY_PATH` assignments to the list of suspicious
  lines detected in shell startup files.

---

## [0.1.0-beta] — 2026-06-07

Initial public release.

### Features
- **Single self-contained binary** — no installer, no runtime dependencies,
  cgo-free. Runs on Windows and Linux (amd64 + arm64). macOS binaries are provided but have never been tested.
- **Web dashboard** served at `127.0.0.1:5000`, listing every active TCP/UDP
  connection with its owning process: PID, parent, command line, start time
  and all open sockets.
- **Binary reputation**: SHA-256 lookup via VirusTotal; Authenticode signature
  verification on Windows, package-manager ownership (`dpkg` / `rpm` /
  `pacman`) on Linux.
- **IP reputation**: geolocation / ISP / ASN, reverse DNS, VirusTotal,
  AbuseIPDB, Tor exit-node list, abuse.ch Feodo + ThreatFox, Spamhaus DROP
  and Shodan open-ports / CVE data.
- **Threat score (0–100)** combining all signals, sortable, with per-signal
  breakdown on hover. Incomplete data is marked; noisy shared-infrastructure
  reports are attenuated.
- **Live SSE feed** of new/closed connections and processes, beaconing/C2
  heuristics, new-binary anomalies and optional desktop notifications
  (Windows toast / Linux `notify-send`).
- **Packet capture** via tshark per connection, with real-time hex stream,
  protocol highlighting and `.pcap` download.
- **Machine audit**: processes from suspicious paths, deleted-binary processes,
  persistence mechanisms (Run keys, scheduled tasks, cron, autostart, systemd
  units), hardening checks (firewall, SSH config, Defender, RDP, UID-0
  accounts), rootkit heuristics (hidden processes, hidden ports,
  `/etc/ld.so.preload`, kernel taint, promiscuous interfaces).
- **IP blocking** via `netsh` (Windows) or `iptables` / `nft` (Linux).
- **Whitelist** for trusted binaries and IPs (optional persistence to SQLite).
- **Authentication**: optional single-password gate with bcrypt, brute-force
  lockout and CSRF / DNS-rebinding protection.
- **HTTPS**: auto-generated self-signed certificate when the listen address is
  exposed beyond localhost.
- **System tray icon** on Windows with *Open dashboard* and *Stop* actions.
- Bilingual UI: Spanish and English.
