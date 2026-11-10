# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- **Local signals alert live.** A spawn chain that should never happen (a
  document or a browser launching a script host, a web server launching a
  shell), a foreign process holding a credential store or an input device,
  and executable memory from a memfd, a staging directory or a deleted file
  were only computed when the table was rendered. The monitor loop now checks
  every process that holds a socket — when it appears and once a minute — and
  raises a red alert with a desktop notification, once per process and signal.
  With the monitor running as a service, nobody has to be looking.
- **C2 domains against what processes ask for.** ThreatFox's C2 domains
  (thousands a week) were discarded — only its addresses were used. They are
  now matched against the names observed for each connection (TLS SNI and
  passive DNS): an exact match or a subdomain of a listed domain scores like a
  listed address (+55, never twice) and raises a red alert. More specific than
  the address on shared hosting. Payload-delivery domains and URLhaus hosts
  are deliberately not matched: they include the likes of `github.com`.
- **Scheduled audit.** The machine audit ran only when its panel was opened.
  It now also runs on its own — two minutes after start-up, then every six
  hours (⚙ Settings, `AUDIT_EVERY_HOURS`; 0 = off) — and reports what is
  **new** against the baseline: a Run key, a cron job, a systemd unit, an
  authorized SSH key, a UID-0 account. Each new item once, in the live feed,
  the history and a desktop notification.
- The executable's **SHA-256** in the process details, linked to its
  VirusTotal report (the link is followed by your browser, on click).
- **History retention in ⚙ Settings** (`EVENT_RETENTION_DAYS` was only
  reachable by editing `.env`).
- **Alert webhook.** Alerts only reached the desktop of whoever was logged in.
  One URL in ⚙ Settings now receives every alert the desktop notification
  gets — even with desktop notifications off — as JSON (fields for Slack,
  Discord and generic receivers) or as plain text with a `Title` header
  (ntfy). Off unless configured; the URL is treated as a secret and never
  shown back in full; a *Test* button sends a test alert; the privacy panel
  lists it as an outbound connection.
- **New-version notice, optional and off by default.** Turned on in ⚙ Settings
  (`UPDATE_CHECK`), the monitor asks GitHub's public releases API once a day
  which is the latest release and, if it is newer than the one running, shows
  a small link in the header. The request carries no key and nothing about
  the machine or the version it runs; nothing is downloaded or installed; the
  privacy panel lists it. Off, the monitor never contacts GitHub.
- **Brief connections (Linux).** The live monitor looks at the socket table
  every 3 s, so a connection that opened and closed in between left nothing —
  and a C2 check-in or a quick upload is shorter than that. An eBPF program
  on the kernel tracepoint `sock:inet_sock_set_state` now reports every TCP
  connection as it happens. The ones the poll never saw appear in the feed
  and the history as a new kind, `short` (⚡): the process that made the
  connection (taken inside its `connect()`), how long it lasted, bytes sent
  and received, inbound ones attributed to whoever listens on the port, and
  failed attempts marked as such. They go through the same checks as any
  connection — reputation, C2 domains, new or replaced binary — and they
  feed the beaconing detector, which until now only saw what the poll caught.
  Repeats are grouped: the first is shown, the rest counted and summarised
  after 60 s; at most 20 individual lines per process and minute.
  Needs root and Linux ≥ 5.8; without them the monitor works as before and
  says why at start-up and in ⚙ Settings, where there is a switch
  (`SHORT_CONNS`, applied at the next start). The program is written in Go —
  no compiled object in the repository — and is verified by the kernel at
  load. New dependency: `github.com/cilium/ebpf` (pure Go, MIT).
  Limits: TCP only; a process that exits within milliseconds is named but
  has no path; byte counts need kernel BTF.
- **New listening port.** A port that starts accepting connections from the
  network — a bind shell, a rogue proxy, a forgotten debug server — reached
  the feed as one more "new connection". The monitor now keeps a baseline of
  who listens on what (program + protocol/port, on disk) and raises a
  specific alert, with a notification, for anything outside it: TCP in
  LISTEN and bound UDP on a non-ephemeral port, on any non-loopback address.
  Seeded silently the first time; after that a listener that appeared while
  the monitor was stopped is announced when it starts. All the random high
  ports of one program count as a single entry.
- **Suspend / resume a process.** Killing a suspicious process destroys the
  evidence with it. *Suspend* (in the process details, next to *Kill*)
  freezes it — it stops running and talking — and leaves its memory, files
  and sockets in place to be analysed, or resumed if it turns out to be
  innocent. SIGSTOP/SIGCONT on Unix, NtSuspendProcess on Windows. A frozen
  process is marked ⏸ in its row, also when something else stopped it.
- **History search.** The history window loaded the last 500 events and
  filtered them in the browser by process name; anything older could not be
  found. The search now runs in the database over everything retained: any
  text of the event (process, path, addresses, detail, PID — several words
  must all match), the type and a date range, a page at a time with *Load
  more*. Each row shows the date, not only the time of day. `GET
  /api/history?q=&kind=&from=&to=&limit=&before=`.
- **Spamhaus DROP for IPv6** (`drop_v6.json`): only the IPv4 list was loaded,
  so an IPv6 connection into a hijacked netblock never scored.

### Changed
- **The beaconing alert is raised once, then at most once an hour** while the
  beacon goes on. It was raised again at every new sample: with brief
  connections feeding the detector, an editor that talks to the same host
  every minute produced an alert — and a notification — a minute. The event
  still carries the period.
- **The CSV/JSON exports and *Delete* follow the history filter**: what is on
  screen is what is exported or deleted. The exports' `ts` is now the full
  date and time (it was the time of day alone, over weeks of history); the
  JSON adds `at` and `id`. A filter that cannot be parsed is refused instead
  of being ignored.
- **Browser sessions survive a restart.** With the monitor running as a
  service, a reboot or an update turned every open dashboard into the gate
  page (or the login). Live sessions are now kept in `efemon.db` — by the
  SHA-256 of their token, never the token, so the file holds nothing usable
  as a cookie. Logging out, changing or removing the password and expiry end
  them on disk too.
- **Blocking an IP blocks both directions.** It was outbound only, so a
  blocked host could still connect to anything listening on the machine.
  Blocks saved by an earlier version get their inbound rule when the monitor
  next starts (Linux) or the next time the address is blocked (Windows).

### Fixed
- **An application's own `Cookies` file counted as credential access.** Every
  Electron application (VS Code, Slack, Discord, Signal…) keeps files named
  `Cookies` and `Local State` and holds them open; the check went by file
  name alone, so they were scored — and, with local signals now alerting
  live, would have raised a red alert at every start. The signal is now what
  it says: a *browser's* store (or a mail client's) held by something that is
  not a browser, on Linux, snap, flatpak, Windows and macOS layouts.
- **Linux (iptables): a block could be skipped when ufw or another front-end
  was active.** The DROP rule was appended to the chain, after the chains
  those tools hook in — which accept new and established connections first.
  It is inserted at the head now.
- **Linux: every unconnected UDP socket was logged as a connection to
  `0.0.0.0:0`.** The filter that keeps ephemeral UDP binds (one per DNS
  query) out of the feed and the history looked for an empty remote address,
  which is how Windows reports them; Linux reports `0.0.0.0:0`. They are
  filtered on both now, and such a socket is labelled `UDP-BOUND` in the
  table instead of `UDP`.
- Ticking *require login* without typing a password did nothing and said
  nothing; it now says a password is needed and that nothing changed.
- The Settings window had outgrown the screen — neither its title nor *Save*
  were reachable. Its fields scroll and *Save* stays in a fixed footer.

## [0.5.0] — 2026-11-09

### Security
- **Content-Security-Policy without `unsafe-inline` for scripts.** The
  dashboard's JavaScript moved to `/static/app.js` and every control is wired
  through `data-action` attributes and one delegated dispatcher, so the page
  has no inline script or handler left and `script-src` is `'self'` alone
  (plus `object-src 'none'`, `form-action 'self'`). An XSS that slipped past
  `html/template` could no longer execute. A test fails the build on any
  inline handler, and another on a `data-action` the script does not define.

### Added
- **Run at boot on Linux.** `sudo efemon --install-service` copies the binary
  to `/opt/efemon`, moves the existing `.env`, database and TLS pair there and
  enables a systemd unit; `--uninstall-service` removes it (the data stays);
  `--service-status` reports it. The same from **⚙ Settings → Run at boot**
  when elevated. As a service the monitor is watching before anyone logs in
  and the tray icon, notifications and *Open panel* attach to the desktop
  session when it appears — and again after a logout/login. *Quit* from the
  tray and *Stop* in the panel stop the unit until the next boot; *Restart
  now* restarts it. The persistence the audit looks for runs at boot; now the
  monitor does too.
- `--version` and `--no-browser`.
- **URLhaus** (abuse.ch, same Auth-Key as ThreatFox): a remote address that is
  serving a malware-distribution URL *right now* scores +35 — less than a C2
  listing, because distribution sites are often compromised legitimate
  servers — with the family or threat as the reason, in the details, the
  live-feed alert and the privacy panel. Only online URLs on IP-literal hosts
  count; the feed refreshes every six hours (the API returns the last ~20 h).

### Changed
- The live-activity block is resizable: drag the handle at its bottom-right
  corner; the height is remembered per browser.
- **Graded reputation alerts in the live feed.** One VirusTotal engine
  flagging an address is a yellow note, two an amber warning, three or more —
  or any Feodo/ThreatFox/URLhaus/Spamhaus/Tor hit, or a high AbuseIPDB score
  off a known provider — stays red; only red reaches the desktop
  notification. A single engine on a big provider's range (Chrome talking to
  claude.ai) used to raise a red alert and a notification. The reason reads
  `VirusTotal ×N`.

### Fixed
- Service mode polish from the review: the session watcher never holds its
  lock across the `/proc` scan or the helper handshake, rescans `/proc` only
  when the set of logged-in users changes (or every 30 s), and is read
  atomically; the gate page puts the service hint before the token path;
  `--no-browser` is honoured on the "already running" handoff; installing from
  the service itself or from the CLI while another efemon runs is refused with
  the reason.
- Service mode no longer mistakes the display manager's login screen (sddm,
  gdm — a system account with a display of its own) for the user's desktop
  session at boot: only regular users (uid ≥ `UID_MIN`) are candidates, so the
  tray attaches to your session even while the greeter is still alive.
- The privacy panel's table no longer runs texts over the next column (cells
  inherited the connection table's no-wrap), and its footnote now says that
  ThreatFox and URLhaus are fetched with the abuse.ch Auth-Key.

## [0.4.1] — 2026-11-08

### Added
- **DGA alert from the passive DNS listener** (Linux). A burst of distinct
  names that do not exist — 25 NXDOMAIN answers in a minute — is malware
  iterating generated domains in search of its C2; the listener used to throw
  those answers away. One alert per burst in the live feed, the history and
  a desktop notification, quoting a sample of the names. Machine-wide (the
  socket sees the answer, not the asker); reverse lookups, local-network
  suffixes and WPAD probes never count.

### Security
- **ThreatFox was silently dead — now back, through the abuse.ch API.** abuse.ch
  withdrew every keyless export in 2025 (`410 Gone`), so the ThreatFox feed —
  a 55-point signal, announced in the README and the privacy panel — had been
  returning nothing while the rows read "clean", and the download was retried
  every ten minutes. ThreatFox now uses the API with a free **abuse.ch
  Auth-Key** (`ABUSECH_API_KEY`, or ⚙ Settings): the IOCs of the last seven
  days, refreshed daily. Without a key the feed is off and says so.
- **Every feed shows its state.** The privacy panel has a *Status* column and
  the start-up log a line per feed: entries and age, *no key*, *withdrawn by
  the provider (HTTP 410)*, or the last error — four things that used to look
  like "no signals". A `410` stops the retries for good. The live-feed
  reputation alert now also fires on ThreatFox and Spamhaus hits, not only
  Feodo, Tor, VirusTotal and AbuseIPDB.
- **CSV export neutralizes formulas.** Process names, paths and detail lines
  are attacker-influenced text, and the export is opened in Excel or
  LibreOffice; a cell starting with `= + - @` or a tab is a formula there. Such
  cells now carry a leading apostrophe, the standard defence.
- **The local token leaves the address bar.** After exchanging `?t=` for the
  session cookie the browser is redirected to the same URL without it, so a
  token valid for the whole run no longer sits in the history.
- `/api/kill` refuses the monitor's own PID and PID 1 (it could be made to
  kill itself from its own API), and the `KILL` log line now records the
  process name and path — a bare PID is meaningless in a later reading.
- JSON API bodies are bounded (64 KiB) and a body that does not decode is a
  `400`; the handlers used to act on the zero value, so a malformed body to
  `/api/whitelist` whitelisted the empty string.
- **Toolchain: Go 1.26.3 → 1.26.10.** `go.mod` pins the toolchain the binary is
  built with, and 0.4.0 shipped with 22 fixed standard-library vulnerabilities
  reachable from this code — in `net/http`, `crypto/tls`, `html/template`,
  `crypto/x509`, `net/textproto`, `net/url` and `encoding/asn1`: the server, the
  HTTPS mode and the templates. `govulncheck` now runs in CI and in `verify.sh`,
  so a pinned toolchain going stale is a failing gate instead of something
  nobody notices.
- Dependencies updated (gopsutil 4.26.10, x/crypto 0.58, x/sys 0.49, systray
  1.12.2, dbus 5.2.4, modernc sqlite 1.62). Dependabot opens weekly PRs for
  modules and actions, and the gosec action is pinned to a release instead of
  tracking `master`.

### Performance
- **IP reputation off the request path.** The table render waited for every
  new public address to be looked up — up to five network calls each,
  sequential, eight seconds apiece, eight at a time — so a first load or a
  burst of new destinations held the page for seconds. Lookups now run in
  background workers; the row shows *reputation pending* with its details and
  Sniff button in place, and the page redraws itself when the results land
  (one redraw per burst, not per address). Reverse DNS has its own 3 s
  deadline. Same pattern VirusTotal and the signatures already used.
- **LAN host lookups off the request path too.** `nmblookup` and `arp` ran
  inline per LAN host with 5 s timeouts behind a 10-minute cache, so every ten
  minutes a render stalled for seconds on hosts that do not answer NetBIOS. A
  stale entry is served while its refresh is queued, so the LAN block never
  blinks out. Measured cold render: 68 ms, down from 3–4 s.
- **Indexes for the per-render queries.** The details block asks SQLite about
  each process on every render (activity in the last 24 h, first and last
  event) and the risk log looks up the last verdict of every (binary, remote
  IP) pair; both only had an index on the timestamp, so each was a full scan
  of the retained history, repeated per process several times a minute.
  `events(exe, epoch)` and `score_history(exe, ip, epoch)` turn them into seeks.
- **The database stops growing forever.** `hostnames`, fed all day by the
  passive DNS listener and loaded whole on every render, now follows the same
  retention as the events. `audit_seen` keyed its items by text including the
  PID, so every reboot marked the same processes **NEW** and added a row per
  PID; items are now keyed without the PID and old rows are folded in on
  start-up. Freed pages are returned to the OS (`auto_vacuum=INCREMENTAL`,
  converting an existing file once at start-up).
- **One analysis per concurrent render.** Two open tabs, or the live-feed
  refresh arriving while a periodic one was still enriching, each ran a
  complete analysis — a `/proc` pass per PID plus the hash, reputation and LAN
  passes. Concurrent requests now share one (`sharedConnections`).

### Fixed
- The live feed no longer reports the monitor's own subprocesses (`nmblookup`,
  `arp`, `tshark`, `netsh`…) as new processes — nor, the first time, as new
  binaries with a desktop notification. A direct child of the monitor is the
  monitor's, in the feed and in the table's *hide self* filter.
- Database reads report an error that cut a scan short instead of returning a
  silently truncated history; the SSE keepalive uses one ticker instead of a
  timer per event.

### Documentation
- `ARCHITECTURE.md` catches up: the render-path rule (cache or queue, never a
  wait), the single-flight render, `broadcast` vs `publish`, the new indexes and
  retention, the audit diff keying, and the stale "cd go" / `.env` lookup
  lines from before the repo root became the Go module.
- The score breakdown is rendered in the language of the request that reads
  it. It used to be rendered from a process-wide "current language", so two
  browsers in different languages could each see the other's words.

## [0.4.0] — 2026-09-24

The details block now answers the questions an analyst asks next about a
process — where it works from, under what, what it touches, how old it is,
what it has spawned, and how much it talks — and two of those answers score.
CPU is shown per core, as `top` does.

### Added
- **Process network activity** block in the details: current connections and
  distinct destinations with their countries and networks, listening ports,
  the names the process asked for (across all its addresses), and its
  history — destinations and events in the last 24 h, recorded risk changes,
  first and last event — with a link that opens the history modal filtered
  to that process. The history modal's process and kind filters now narrow
  the list as you type, not only what gets deleted.
- **Windows: version resource and hosted services.** What the executable
  says about itself (company, product, description, version) is read in the
  same PowerShell batch that resolves Authenticode, cached by path + mtime,
  and shown as a *File* line and as the tooltip of the process name — so a
  "Microsoft Corporation" without a Microsoft signature is visible. A
  background map refreshed every minute lists the services each process
  hosts, which turns `svchost.exe` into "Dhcp — DHCP Client · EventLog — …"
  and shows a service registered on any other binary the same way.
- **Provenance** in the details block: when the executable was last modified
  and how long ago (highlighted under 24 h — a binary written minutes ago
  that already holds sockets is the dropper shape), the first time this
  machine recorded exactly this binary, and the processes it has spawned,
  grouped ("bash ×2 · curl"). Children come from one process-table pass per
  render, not a scan per PID.
- **What a process touches** (Linux; root for other users' processes), in
  the details block and in the score. *Access*: sensitive files held open by
  a process that is not their expected reader — browser password and cookie
  stores, SSH keys, shadow/sudoers, keyrings and `.kdbx`, wallets, input
  devices — with the legitimate readers (the browser with its own profile,
  ssh, the compositor, backup tools) excluded up front; camera and
  microphone are listed for context only. *Memory*: executable regions from
  a memfd, a staging directory or a deleted file outside the system library
  tree (a library replaced by an upgrade is not flagged; anonymous JIT
  regions never count). Both score on their own (+25 / +30): they are
  high-precision and computed locally. Reads are cached 60 s per PID.
- **Process context** in the details block: working directory (red when it
  is a staging path), controlling terminal or "no terminal", the systemd
  unit and the container the process belongs to (from its cgroup; Linux),
  and any environment variable that redirects code or traffic —
  `LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS`, `HTTP_PROXY`, custom CA
  bundles… Only that short list is read; the rest of the environment is
  never shown, and proxy credentials are masked. Informational, no score.

### Changed
- **CPU is now per core, as `top`/`htop` show it** (a 4-thread process can
  read 400 %), instead of a share of the whole machine: on a 20-core box the
  old figure flattened every process to "0.x %" and hid the busy one. The
  cryptominer threshold follows: 80 % of one core sustained for 15 s, which
  a miner throttled to two threads reaches and a whole-machine threshold
  never would.

### Fixed
- The chosen column sort survives table refreshes, is shown with an arrow on
  the header and remembered per browser.

## [0.3.1] — 2026-09-18

### Fixed
- **Details block layout**: the "asked for" hostname chips ran past their
  column into the connections block. The value side of a detail line can now
  shrink and wrap.

### Documentation
- Screenshots of the 0.3.x dashboard (main table with the CPU / Mem column,
  details, history with the timeline export, and the new audit modal), with
  addresses and machine-specific findings pixelated.
- README: passive DNS, running as root on Linux (tray, notifications and
  browser handed to the desktop user), timeline export, privacy note, and a
  "what's new" summary linking to this changelog.

## [0.3.0] — 2026-09-17

Eight rounds of work since 0.2.0, each kept below with its own notes. The short
version:

- **Simplified Chinese UI** (#1) alongside Spanish and English; every string,
  including the audit and the score breakdown, which is now stored
  language-neutral and rendered in the reader's language.
- **Per-process resources**: CPU, memory, threads and owner in a sortable
  column; sustained CPU from a suspect binary scores as the miner shape.
- **Passive DNS** without a capture (Linux as root, Windows always): a remote
  address shows the name the process asked for.
- **Baseline by content**: a binary replaced in place is alerted as such.
- **Audit**: every user's home (not `/root` under sudo), reverse shells, traced
  processes, system-level systemd units, Winlogon/IFEO/AppInit/services on
  Windows, file permissions, real firewall rule counts; a **NEW** badge for
  findings first seen in the last 24 h; four categories in parallel; every
  parser tested. Known proprietary drivers and the monitor's own capture no
  longer show as rootkit warnings.
- **Root on Linux works as a desktop app**: tray icon, notifications and the
  browser run as the logged-in user; IPv6 peers can be blocked; persisted
  blocks are re-applied at boot.
- **`/export/timeline.json`**: the incident report as one document.
- Security: `.env` values can no longer inject a line that disables the login.

### Audit: every user's home, more persistence, new-since badge

#### Added
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

#### Fixed
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

#### Changed
- The four audit categories run concurrently; the scan takes as long as the
  slowest one. Checks are ordered by severity within each category.
- Every parser the audit relies on (reg query, schtasks, driverquery, ss /
  netstat, unit files, hosts) is a pure function with a fixture test.
- `/api/audit` returns `{at, checks}`; each check carries a stable `key`, its
  raw `items` and the `new` ones. `/audit.json` is unchanged.

### Passive DNS, content baseline, miner signal, timeline export

#### Added
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

#### Fixed
- Persisted IP blocks are re-created in the firewall at startup on Linux
  (iptables/nft rules do not survive a reboot; netsh ones do).
- `DELETE /api/events` requires `confirm=1`; the UI already asked.
- `tools/genoui` cut vendor names by byte and could split a multi-byte
  character; now by rune, with the first test under `tools/`.

### Simplified Chinese, language-neutral score history

#### Added
- **Simplified Chinese (zh-CN) UI**, requested in #1: every UI, login, gate,
  notification and audit string, selectable from the flag toggle. Translated
  from the English set with the industry's usual loanwords kept as they are
  (VT, SNI, rDNS, PID, C2); a native review is welcome — the parity tests
  guarantee no key is missing, not that every phrase is idiomatic.
- The translation tests now cover every language in the map, not just es/en,
  and also pin the `%` verb count per key, so a translation that drops a `%s`
  cannot print `%!(EXTRA …)` into a tooltip.

#### Fixed
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

#### Changed
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

### Resource usage per process

#### Added
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

#### Fixed
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

### Data-volume signal, real ACLs on the secrets

#### Added
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

#### Security
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

### Hostname correlation, risk timeline, release provenance, macOS

#### Added
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

#### Fixed
- **The audit no longer claims to have run checks it cannot.** On macOS the
  process cross-view was a stub returning an empty list, and the deleted-binary
  check read `/proc`, which does not exist there — so both rendered as confident
  passes ("no discrepancies between process sources"). A probe that did not run
  now reports "not available on this OS", the same honesty the command-failure path
  already had. The same applies to a failed `tasklist` on Windows and an
  unreadable sysfs on Linux.
- Guarded the database helpers reachable from the capture path against a nil
  handle: a missing database should cost a row, not panic the capture goroutine.

#### Removed
- **macOS binaries are no longer published.** The badge claimed a platform that
  had never been tested, and the reason not to ship it is concrete rather than
  cautious: parts of the audit have no macOS implementation, so a user would be
  running a security tool with holes in it. The code still cross-compiles for
  darwin and CI keeps proving it, so building from source remains possible — the
  README now explains what is missing instead of implying support.

---

### Logging, process ancestry, score calibration

#### Added
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

#### Changed
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

### Security & correctness review

#### Security
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

#### Fixed
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

#### Changed
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
