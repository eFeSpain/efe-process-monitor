# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
Versions follow [Semantic Versioning](https://semver.org/).

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
  cgo-free. Runs on Windows, Linux and macOS (amd64 + arm64).
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
