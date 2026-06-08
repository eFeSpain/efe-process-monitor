<div align="center">

<img src="docs/logo.png" width="80" alt="eFe Process Monitor">

# eFe Process Monitor

Process and network monitor with a local web dashboard. It shows which process
each connection belongs to, where it connects, and what reputation/threat-intel
sources say about the binary and the remote IP.

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)

**English** · [Español](README.es.md)

</div>

> **Status: beta.** It works and is used day to day, but it's early — expect rough
> edges, and the UI, stored data or options may still change between versions.

<div align="center">
<img src="docs/screenshot-main.png" alt="Main dashboard" width="880">
</div>

## What it is

A single, self-contained binary (no install, no dependencies, cgo-free) that
serves a web dashboard on `127.0.0.1:5000`. It lists every active TCP/UDP
connection together with the process behind it, and enriches each one with
binary and IP reputation data. Roughly: `netstat`/TCPView, plus reputation
lookups, a packet capture and a machine audit, in one local page.

It's a **defensive / forensic** tool — for inspecting your own machine, not for
attacking others.

## Features

**Connections & processes**
- Every TCP/UDP connection with its owning process: parent, command line, start
  time, I/O counters and the process's other open sockets.

**Reputation & threat intel**
- Binary: SHA-256 lookup on **VirusTotal**, and code signature — **Authenticode**
  on Windows, **package ownership** (`dpkg`/`rpm`/`pacman`) on Linux.
- Remote IP: geolocation / ISP / ASN, reverse DNS, **VirusTotal**, **AbuseIPDB**,
  **Tor** exit nodes, **abuse.ch** (Feodo + ThreatFox), **Spamhaus DROP** and
  **Shodan** (open ports / CVEs).
- **Threat score (0–100)** combining all signals, sortable, with a per-signal
  breakdown on hover. It's a heuristic: a low score means "no signals found",
  not "safe" — rows with incomplete data (e.g. a pending VirusTotal lookup) are
  marked, and noisy reports on big providers are attenuated to cut false alarms.

**Live monitoring**
- SSE feed of new/closed connections and new processes, **beaconing/C2**
  heuristics (regular connections to the same host), new-binary anomalies, and
  optional **desktop notifications**.
- **Pin** a connection to keep a frozen copy of its card even after it closes.

**Capture & audit**
- Per-connection **packet capture** via `tshark` (TLS SNI, HTTP host, DNS, flags;
  pcap export), with automatic interface detection.
- **Machine audit**: heuristic checks for suspicious processes, persistence,
  hardening and rootkit indicators (runs entirely locally — see *Privacy*).

**Actions & history**
- Kill a process, block/unblock an IP at the firewall, whitelist binaries or IPs.
- **LAN host info**: NetBIOS / DNS / MAC, with offline **OUI vendor** lookup.
- Forensic **history** in SQLite, exportable to CSV/JSON, with filtered deletion
  (by process, type or age).

**Other**
- Optional **password login**, and optional network exposure over **HTTPS** (off
  by default — see *Access*).
- Bilingual UI (English / Spanish), system-tray icon on Windows and Linux (SNI desktops), single binary.

## Screenshots

| Connection details & IP intel | Packet capture |
|---|---|
| ![Details](docs/screenshot-details.png) | ![Capture](docs/screenshot-capture.png) |

| Forensic history |
|---|
| ![History](docs/screenshot-history.png) |

## Install

Download the binary for your OS from the [Releases](../../releases) page and run it.

Or build from source (Go 1.26+, no cgo):

```bash
git clone https://github.com/eFeSpain/efe-process-monitor.git
cd efe-process-monitor
go build -o efemon .                       # Windows: efemon.exe
GOOS=linux  CGO_ENABLED=0 go build -o efemon .   # cross-compile for Linux
GOOS=darwin CGO_ENABLED=0 go build -o efemon .   # cross-compile for macOS
```

## Usage

```bash
./efemon          # serves http://127.0.0.1:5000 and opens it in your browser
```

- Run as **administrator / root** to see every process (name, exe, signature) and
  to use *kill* / *block IP*. Without elevation it still runs, but some processes
  show `N/A` (it warns you).
- **Packet capture** is optional and needs [tshark/Wireshark](https://www.wireshark.org/) on `PATH`.
- Only **one instance** runs at a time; launching a second just opens the dashboard.
- On **Windows** it lives in the **system tray** — right-click to open or quit;
  closing the browser tab does not stop it.
- On **Linux** it also uses the system tray on SNI-compatible desktops (KDE,
  XFCE, MATE, Cinnamon…). On GNOME you need the
  [AppIndicator and KStatusNotifierItem Support](https://extensions.gnome.org/extension/615/appindicator-support/)
  extension; without it (or on any other unsupported desktop), no tray icon
  appears — a **Stop** button is shown in the web dashboard instead.
- On **macOS** it runs in the foreground (`Ctrl+C` to stop).

### API keys (optional)

VirusTotal and AbuseIPDB lookups need free API keys — add them in **⚙ Settings**
(saved to `.env`) or create a `.env` next to the binary:

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

Geolocation, Tor, Feodo/ThreatFox, Spamhaus and Shodan work with **no key**.
Without VirusTotal/AbuseIPDB keys, those two are simply skipped.

## Access

By default the dashboard binds to **`127.0.0.1` only** and has **no password** —
it exposes sensitive data and destructive actions, so it's meant as a local tool.

- If you do want to bind it to the network, **enable a password first** in
  Settings. Network exposure is only allowed with a password set, and is then
  served over **HTTPS** (a self-signed certificate is generated automatically).

## Privacy

No telemetry; everything is stored locally (`efemon.db`). To enrich data the tool
queries external services for the IPs/hashes **you inspect**: ip-api, VirusTotal,
AbuseIPDB and Shodan receive those values; the abuse.ch / Spamhaus / Tor lists are
plain public downloads that reveal nothing about you. Results are cached so each
binary/IP is queried at most once (hourly for IPs). The machine audit runs fully
locally. The in-app **🛰 Privacy** panel spells out exactly what goes where.

## Tech stack

Go · [gopsutil](https://github.com/shirou/gopsutil) · `net/http` + `html/template`
+ `go:embed` · [modernc.org/sqlite](https://modernc.org/sqlite) (cgo-free) ·
[fyne.io/systray](https://github.com/fyne-io/systray) · `tshark` for capture.

## License

[MIT](LICENSE) © eFe

## Support

If you find it useful, you can support its development with the **💖 Sponsor**
button at the top of the repository. Thanks!
