# Handoff: what is pending on Windows

Written 2026-11-10 on the Linux development machine, for whoever continues
this project **from a Windows machine** — a person or a coding agent with no
access to the conversation that produced it. Everything here was true at
commit time; check it against the code before relying on it.

The owner writes in Spanish (Spain) and is addressed informally. Reply in
Spanish.

## Read first

1. `ARCHITECTURE.md` — how the program is built and the conventions. They
   are binding; the ones that bite most often:
   - Commits: `git -c user.name=eFeSpain commit --no-gpg-sign`, **no
     Co-Authored-By or any AI attribution**, feature branch then
     `git merge --ff-only` into `main`. **Never push or tag unless asked.**
   - Every user-facing string in **es, en and zh** (`i18n.go`; parity tests).
   - No inline JS (CSP `script-src 'self'`): `data-action` / `data-change` and
     the `actions` table in `web/static/app.js`.
   - Platform code in build-tagged files; subprocesses through `command()`.
   - Test first. `bash verify.sh --quick` green before every commit
     (`bash verify.sh` in full before merging: six cross-compiles).
   - The render path never waits on the network or a subprocess.
2. `CHANGELOG.md` → `[0.6.0]`: everything added since 0.5.0.
3. `REVISION-0.6.md` is the owner's checklist; it is **untracked** and exists
   only on the Linux machine. Its Windows-relevant content is repeated here.

## State of the repository

- 0.6.0 was released on 2026-11-10. Its notes say plainly that it was not
  run on Windows. Releasing anything (bump `version.go`, date the changelog,
  push, tag) is the owner's decision — do not do it on your own.
- Nothing of the 0.6 round has ever **run** on Windows. It cross-compiles for
  windows/amd64 and windows/arm64 and its unit tests pass on Linux. Section 1
  is the list of what to try.

## 1. Check by hand on Windows what 0.6 added

These touch the operating system; run the monitor as Administrator.

| Feature | How to check | What to look for |
|---|---|---|
| **Suspend / resume** (`suspend.go`, `/api/suspend`) | In a process's details: *Suspend*, then *Resume*. Try it on Notepad. | The process freezes and thaws (gopsutil → `NtSuspendProcess`). The row shows ⏸ and the button flips. On Windows the badge only reflects what the monitor itself suspended (an in-memory record keyed by PID + creation time): a process suspended by another tool shows no badge. |
| **Block IP, both directions** (`actions.go` `blockIPOn`) | Block an address from the panel, then `netsh advfirewall firewall show rule name="eFePM block <ip>"`. | **Two** rules with the same name, `dir=out` and `dir=in`. Traffic stops both ways. *Unblock* removes both (one delete by name). A block saved by ≤ 0.5.0 has only the outbound rule; blocking it again adds the inbound one (the start-up re-apply is Linux-only). |
| **New listening port** (`newlisten.go`) | Start something listening on all interfaces, e.g. PowerShell `[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,4444).Start()`. | One amber alert `new listening port: tcp/4444` with a notification; the same program on the same port again: nothing. First run after upgrading seeds the baseline silently. |
| **Sessions survive a restart** (`auth.go`) | Open the panel, restart the monitor, reload the page. | Still in, without going through the tray again. |
| **History search** (`history.go`) | 🕑 History: text, kind, date range, *Load more*, CSV/JSON export. | Results match; exports follow the filter. |
| **Webhook, update notice, scheduled audit** | ⚙ Settings. | Smoke test only: the code is platform-neutral. The scheduled audit uses the Windows audit (`audit_windows.go`). |

Known gaps to decide with the owner, not bugs to fix silently:

- **Ephemeral port threshold.** `ephemeralFrom = 32768` in `newlisten.go` is
  Linux's range. Windows' dynamic range starts at 49152, so a *fixed* port
  between the two is treated as ephemeral (one baseline entry per program
  instead of one per port). Making it per-OS is a small change.
- **Local signals** (`localsignals.go`): only the spawn-chain signal works on
  Windows. Credential access and anomalous executable memory need
  `scanProcess`, which is a stub outside Linux (`procscan_other.go`).
- **The Settings switch "Detect brief connections"** shows *not available on
  this system (Linux only)* on Windows. Its strings (`short_conns_label`,
  `short_conns_hint`, `short_st_*`) say "eBPF, Linux only" and "needs root";
  they must change when section 2 is done.

## 2. Brief connections on Windows (ETW)

**What it is.** The live monitor polls the socket table every 3 s; a TCP
connection that opens and closes in between left no trace. On Linux an eBPF
program reports every TCP connection as it happens and the ones the poll
missed appear as `short` events (⚡). Design, plan and what the review found:

- `docs/superpowers/specs/2026-11-10-brief-connections-ebpf-design.md`
  (read its two *Amendments* sections — they are the lessons)
- `docs/superpowers/plans/2026-11-10-brief-connections-ebpf.md`

**What is already portable and must be reused as it is** (`shortconn.go`):
the record type, `shortTracker` (which connections were brief),
`shortGrouper` (what gets its own line), the wording, the switch
(`SHORT_CONNS`) and the status. `monitor.go` already selects over the record
channel and runs brief connections through `announceConn`. **Only the source
of records is missing on Windows.**

**What to write:** `shortconn_windows.go` providing

```go
func startShortConns() (records <-chan kernelRecord, volume bool)
```

and narrow `shortconn_other.go`'s build tag to `!linux && !windows`.
`shortconn_linux.go` is the model for its shape (status, forwarding, never
fatal).

**The contract the tracker relies on** — get this right and the Windows
source inherits every fix made on Linux:

| Record | When | Must carry |
|---|---|---|
| `recStart` | a process begins an outbound connect | `PID` of that process, `Comm` (image name; used if the path can no longer be read), `Remote`. `Local` may lack the port. |
| `recEstablished` | handshake completed | full `Local` and `Remote`; `Old = tcpSynSent` for outbound, **`Old = tcpSynRecv` for inbound** (an inbound connection has no start record). |
| `recClosed` | the connection is gone | `Old = tcpSynSent` **only** if the connect never completed (that is what makes it an "attempt not established"); `Sent` / `Recv` if available. |

- On `recStart`, fill `Name` and `Exe` (who the PID is) in the reader, as
  the record arrives — the monitor goroutine may be busy and the process
  gone a moment later. Drop loopback records in the reader (`loopbackRecord`).
- `Sock`: any 64-bit value that identifies the connection while it lives.
- `TS`: a monotonic clock in nanoseconds; durations are differences of it.
- Addresses unmapped (`netip.Addr.Unmap()`), ports in host order.
- Send on the channel with a **blocking** send and **never close it**.
- Report state with `setShortConnStatus` (`active`, `refused` + detail,
  `off`, `stopped`; "needs Administrator" needs a new code or reworded
  `short_st_root`).
- **Byte counts:** the tracker subtracts 2 from `Sent` and 1 from `Recv`
  because Linux counts in TCP sequence space (SYN and FIN). If Windows gives
  payload bytes, either add them back in the Windows source or move that
  correction into `shortconn_linux.go`. Decide and test it.

**The Windows mechanism: ETW.** What follows is **from memory and has not
been verified on a machine** — confirm with `logman query providers` and the
provider manifests before building on it:

- Provider *Microsoft-Windows-Kernel-Network*,
  `{7DD42A49-5329-4832-8DFD-43D979153A88}`. I recall TCP events for
  connection attempted, connection accepted, disconnect, data sent/received
  and connection attempt failed, each with the PID, both addresses and
  ports and a connection id. The event ids and field names need checking.
- Consuming ETW without cgo: either the Win32 calls through
  `golang.org/x/sys/windows` (`StartTrace`, `EnableTraceEx2`, `OpenTrace`,
  `ProcessTrace`, callbacks via `windows.NewCallback`), or a pure-Go
  library. A new dependency is the owner's decision; the Linux side added
  exactly one (`github.com/cilium/ebpf`) after discussing it.
- Needs Administrator. A real-time session has a name: stop a stale one left
  by a crashed run before starting.

**Testing.** Unit tests for the translation of ETW events into
`kernelRecord` (hermetic, run anywhere). The real thing can only be tested on
Windows as Administrator: a short `curl`, a refused connect, an inbound
connection to a listener, bytes of a known download. On Linux this was done
in a VM and then on the real machine; the equivalent here is yours to design
with the owner. What the real run found on Linux and is worth repeating:
ordinary desktop noise was about 2 brief lines a minute, and periodic
clients (an editor's telemetry every 60 s) trigger the beaconing detector —
which is why its alert is now raised once per pair and hour.

## 3. Passive DNS on Windows via ETW

Today `dns_windows.go` runs PowerShell every 30 s to read the resolver
cache: slow, and it misses names that expire in between. The same ETW
consumer as section 2 can do it properly.

- Feed `observeDNSAnswer(qname, ips)` and, for a name that does not exist,
  `dgaObserve(qname)` — the two entry points `dns_linux.go` uses.
- **Unverified, from memory:** provider *Microsoft-Windows-DNS-Client*,
  `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`, with a "query completed" event
  carrying the name, the status and the results as text. Check ids and
  fields on the machine.
- Sections 2 and 3 share the session and the consumer: design them together.

## 4. Run at boot on Windows

Dropped from 0.5.0 and **not designed**. The Linux version is a systemd
service plus a watcher that attaches the tray icon and notifications to the
user's session (`service_linux.go`, `desktop_linux.go`; spec
`docs/superpowers/specs/2026-11-08-linux-service-design.md`). Windows needs
its own design — a service in session 0 cannot show a tray icon, so it needs
a helper in the user's session. Start with a design conversation with the
owner; do not start coding it.

## Order suggested to the owner

1. Section 1 (an hour, no code): it decides whether 0.6.0 can list Windows
   as tested.
2. Sections 2 and 3 as one delivery, with a short design first.
3. Section 4, separately.
