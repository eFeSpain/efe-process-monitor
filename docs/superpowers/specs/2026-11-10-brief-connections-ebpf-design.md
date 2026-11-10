# Brief connections on Linux via eBPF — design

Date: 2026-11-10 · Status: approved and implemented; amended during implementation (see *Amendments*) · Target: 0.6.0 · Checklist: `REVISION-0.6.md` item 5

## Goal

The live monitor polls the socket table every 3 s. A connection that opens and
closes between two polls leaves no trace: no line in the feed, no row in the
history, no reputation lookup, no beaconing sample. A C2 check-in or a `curl`
that uploads a file lasts less than that.

After this change, on Linux, every TCP connection the poll misses is recorded
— with the process that made it, how long it lasted and how much it moved —
and goes through the same checks as any other connection.

Success looks like: a 200 ms `curl` to a public address appears in the feed as
a brief connection attributed to `curl`; if the address is on a feed, the
alert fires; a process checking in every 60 s for 200 ms is flagged as
beaconing.

Scope of this delivery: **Linux**. Windows (the same idea over ETW, together
with passive DNS over ETW) is a separate delivery; what is pending there goes
into a handoff document written after this work.

## Decisions taken with the user

| Question | Decision |
|---|---|
| Mechanism | **eBPF**, so the process is known at the moment of the connection. Packet capture of SYNs and conntrack events were rejected: neither gives the PID. |
| Directions | **Outbound and inbound**, repeated ones grouped. |
| How the program ships | **Written in Go** with the library's assembler. No C, no clang, no compiled object in the repository. |
| Failed attempts | Recorded, marked as attempts. |
| Bytes moved | Included as the **last, separable task**; the delivery does not depend on it. |
| Relation to the poll | The poll is unchanged and stays the source of the table. This adds only what it misses. |

## What exists and is reused

- `monitor.go` `monitorLoop`: the poll (`gnet.Connections` every
  `monitorInterval`), the per-connection checks (kind, new process, binary
  baseline, beaconing, reputation, notifications), `publish`, `checkBeacon`,
  `alertOnIntel`.
- `dns_linux.go` / `dns.go`: the pattern for an optional root-only kernel
  source — a status string printed by `startupBanner`, a `_linux.go` file with
  the real thing and a stub for other systems.
- `newlisten.go` `listenersOf`, `procNameExe`: who listens on what, and who a
  PID is.
- `connections.go` `hasPeer`, `isLoopback`, `isPrivateIP`, `ownPID`, `ownChild`.
- `history.go` / `db.go`: events are stored and searched by kind; a new kind
  needs no schema change.
- Settings plumbing (`config.go` `getSettings`, `handleSettings`, `writeEnv`).

## Architecture

```
kernel ── tracepoint sock:inet_sock_set_state ──▶ eBPF program (filters)
                                                      │ ring buffer
                                                      ▼
        reader (shortconn_linux.go) ──▶ channel ──▶ monitorLoop
                                                      │       ▲
                                    shortTracker ◀────┘       └── poll every 3 s
                                         │
                       brief = closed without any poll having seen it
                                         ▼
                 grouping ──▶ publish · reputation · baseline · beaconing
```

Three units, each with one job:

1. **Kernel program** (`shortconn_prog_linux.go`). Decides which socket state
   changes are worth a record and writes it.
2. **Reader** (`shortconn_linux.go`; `shortconn_other.go` is a stub). Loads
   and attaches the program, reads the ring buffer, decodes records, sends
   them on a channel. Owns every kernel resource and the status string.
3. **Tracker and grouping** (`shortconn.go`, portable, no kernel involved).
   Turns records plus poll snapshots into "this connection was brief", and
   decides what is published individually and what is summarised.

`monitorLoop` becomes a `select` over the poll timer and the record channel.
The tracker is touched by that goroutine only: no locks.

## Kernel program

Attached to the tracepoint `sock:inet_sock_set_state`, a stable interface
since Linux 4.16 whose record layout was confirmed on the target kernel
(6.12): `skaddr`@8, `oldstate`@16, `newstate`@20, `sport`@24, `dport`@26,
`family`@28, `protocol`@30, `saddr`@32, `daddr`@36, `saddr_v6`@40,
`daddr_v6`@56. Ports are in host byte order; `sport` is the socket's local
port in both directions.

It returns at once unless `protocol == IPPROTO_TCP` and the new state is one
of three:

| New state | Record kind | Meaning |
|---|---|---|
| `TCP_SYN_SENT` | `start` | A process called `connect()`. The program runs in that process's context, so `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid` and `bpf_get_current_comm` are exact. |
| `TCP_ESTABLISHED` | `established` | The handshake completed. `oldstate == TCP_SYN_RECV` means it is an inbound connection, which has no `start` record. |
| `TCP_CLOSE` | `closed` | The socket is gone. |

Record written to a `BPF_MAP_TYPE_RINGBUF` (256 KiB), fixed size, native byte
order: kernel monotonic timestamp, socket address (the identity of the
connection while it lives), kind, old state, family, local and remote port,
local and remote address (16 bytes each; IPv4 in the first four), and — on
`start` only — PID (tgid), UID and `comm`. With the volume task, `closed`
also carries bytes sent and received.

Process identity is taken only on `start`. `established` for an inbound
connection and `closed` run in interrupt context or in whatever process
happened to be on the CPU; their "current process" means nothing and is not
read.

The program is built with `github.com/cilium/ebpf/asm` (pure Go, MIT). It is
a few dozen instructions, commented line by line, in its own file. The kernel
verifier checks it at load: bounded memory access, no unbounded loops. A
program it does not accept is refused; it cannot destabilise the machine.

Requirements: root (or `CAP_BPF` + `CAP_PERFMON`), Linux ≥ 5.8 (ring buffer),
tracefs available. `RLIMIT_MEMLOCK` is lifted for kernels before 5.11.

## Tracker

A map from socket address to an open flow:

- `start` → new outbound flow with PID, UID, `comm`, endpoints, kernel time.
  The executable path is resolved immediately from the PID
  (`procNameExe`). If the process is already gone, the flow keeps `comm` (up
  to 15 characters) and has no path or hash.
- `established` → marks the flow established. With `oldstate == SYN_RECV` and
  no flow, creates an inbound one.
- After each poll, every flow whose endpoints appear in the snapshot is
  **dropped**: the poll has it, and its `closed` record will find nothing.
  Addresses are compared unmapped, so `::ffff:1.2.3.4` equals `1.2.3.4`.
- `closed` → if a flow exists it was never seen by a poll. Two outcomes:
  - never established → a **failed attempt** (refused, or timed out after the
    kernel's SYN retries — up to a couple of minutes), reported whatever it
    lasted. The poll only lists established and listening sockets, so it
    never sees these.
  - established → **brief** when it lasted less than two poll intervals
    (6 s), reported with its duration (difference of kernel timestamps) and
    the byte counts when present.
- An established flow still unseen after 6 s is dropped without being
  reported, and counted. It is a connection the poll cannot see at all — a
  socket in another network namespace (a container) — not a brief one;
  showing it as "brief" hours later would be wrong. Brief connections from
  those namespaces *are* reported, attributed by the host PID.
- Any flow older than 5 minutes is dropped: its `closed` record was lost.
- A `closed` whose flow is unknown (a listening socket, a flow already
  dropped) is ignored.
- If the kernel reports lost records, the count goes to the log. Nothing is
  inferred from a gap: a lost connection is simply absent.

Discarded before tracking: loopback endpoints, the monitor's own PID and its
subprocesses.

**Inbound attribution.** The poll's `LISTEN` sockets give a map from local
port to the listening process, rebuilt on every poll; a listener outlives a
poll interval by definition. An inbound brief connection is attributed to it,
preferring a listener bound to the same local address. No listener known →
no process.

## What happens to a brief connection

A new event kind, `short`, published through the existing `publish`:

```
[08:41:07] ⚡ brief connection — curl (48213) → 203.0.113.9:443 · 0.2 s · ↑38 MB ↓1 kB
[08:41:09] ⚡ failed attempt — python3 (48302) → 198.51.100.4:8443
[08:41:15] ⚡ brief inbound — sshd (912) ← 192.168.1.50 :22 · 0.4 s
```

- `Event` gains `Inbound bool` (JSON `inbound`, not stored) for the arrow in
  the live feed; the stored `detail` carries the wording, like every other
  event. Strings in es/en/zh.
- The feed gets an `ev-short` style; the history's kind selector gets a
  `short` option; search, CSV/JSON export and the timeline export include
  these rows with no further change.
- The table is not affected: these connections are over.

It goes through the checks a polled connection gets. The per-connection block
of `monitorLoop` (kind by path, new process, binary baseline, beaconing,
reputation, notifications) is extracted into one function used by both
sources, so the two cannot drift:

- reputation of the remote address and C2 domains (`alertOnIntel`), for public
  remotes and non-whitelisted binaries;
- new or replaced binary, suspicious path;
- beaconing: every brief outbound connection — failed attempts too — is a
  sample for `checkBeacon`, keyed by executable, or by `comm` when there is no
  path. Today the detector only sees what the poll catches.

A brief connection never notifies by itself; only those reasons do. A
whitelisted binary is recorded and does not notify.

**Grouping.** Key: direction + process (path, else `comm`) + remote address
(for inbound: remote address + local port).

- The first one is published immediately.
- Further ones within 60 s are counted silently — they still feed beaconing —
  and one line is published when the window closes: `×14 more in 60 s`.
- Per process, at most 20 individual lines a minute; the rest go to one
  summary (`×230 more brief connections to 61 addresses`).

Both numbers are named constants. How much a browser adds in ordinary use is
not known yet; they are to be tuned after the first real run.

## Bytes moved (last task, separable)

At `closed`, read `bytes_acked` and `bytes_received` from the socket
(`struct tcp_sock`) with `bpf_probe_read_kernel`. Their offsets differ
between kernels, so they are looked up in the kernel's own type information
(BTF, `/sys/kernel/btf/vmlinux`) at start-up and written into the program as
constants.

- No BTF → the program is built without the reads; connections have no volume.
- The kernel refuses the program with the reads (lockdown in confidentiality
  mode forbids reading kernel memory) → load again without them.

If this task proves harder than expected it is dropped from 0.6.0 and nothing
else changes.

## Degradation and the switch

Loading is never fatal. The status is a line in the start-up banner and a
field in Settings:

```
[+] Brief connections  active — eBPF
[-] Brief connections  inactive — needs root
[-] Brief connections  inactive — kernel without ring buffer (before 5.8)
[-] Brief connections  inactive — the kernel refused the program: <reason>
[-] Brief connections  disabled in Settings
```

A reader error after start (the ring buffer closed) logs once and leaves the
feature inactive; the monitor carries on with the poll alone.

Settings gets a checkbox, on by default, persisted as `SHORT_CONNS`
(`false` = off). It is a kernel hook: the operator must be able to turn it off
without changing version. It takes effect at the next restart, and Settings
says so next to the current status. No privacy-panel entry: nothing leaves the
machine.

## Files

| File | Content |
|---|---|
| `shortconn.go` | record and flow types, tracker, grouping, wording. Portable. |
| `shortconn_prog_linux.go` | the eBPF program as Go assembly; BTF offset lookup (volume task). |
| `shortconn_linux.go` | load, attach, read, decode, status. |
| `shortconn_other.go` | stub: status "Linux only", nil channel. |
| `monitor.go` | `select` loop; per-connection checks extracted; listener map. |
| `config.go`, `main.go`, `actions.go` | `SHORT_CONNS`, settings fields, banner line. |
| `web/templates/report.html`, `web/static/app.js`, `i18n.go` | checkbox + status, feed line, `short` kind. |
| `scripts/vm-kernel-test.sh` | boots the host kernel in QEMU with the kernel tests as init. |
| `.github/workflows/ci.yml`, `verify.sh` | kernel tests under `sudo` in CI; gosec exclusions kept in sync. |
| `go.mod` | `github.com/cilium/ebpf`. |

## Testing

1. **Unit, hermetic** (any OS, no root): tracker — brief, seen by the poll,
   failed attempt, inbound with and without a known listener, mapped
   addresses, the 6 s bound for established flows, a slow failed attempt, the
   5-minute prune, unknown `closed`; grouping — first, counted,
   window summary, per-process cap; record decoding from bytes; wording and
   translation parity; the Settings markup; the `short` option in the history.
2. **Kernel** (`//go:build linux`, skipped unless root): load and attach; open
   real TCP connections and assert `start`/`established`/`closed` with the
   right PID, `comm` and ports; an inbound connection; a refused connect
   (`start` then `closed`, never `established`); byte counts (volume task).
   These read raw records, so loopback is fine.
3. **VM**: `scripts/vm-kernel-test.sh` builds the test binary and boots
   `/boot/vmlinuz-$(uname -r)` under QEMU/KVM with it as PID 1 (the test's
   `TestMain` mounts proc/sysfs/tracefs, brings `lo` up, runs, powers off).
   Root inside the VM, nothing touched on the host. Verified feasible on this
   machine: the kernel boots that way and exposes the tracepoint and BTF.
4. **CI**: the kernel tests run under `sudo` on the GitHub runner — a second,
   different kernel on every push. Not verifiable before a push.
5. **By the user, as root, on the real machine**: start the monitor, check the
   banner line, run a short `curl`, see the ⚡ line; browse for a few minutes
   and judge the noise.

## Documentation

README (both languages): the feature, its requirements (root, kernel ≥ 5.8),
its limits (TCP only; a process that exits within milliseconds is named but
has no path). ARCHITECTURE.md: the second event source and the rule that the
tracker belongs to the monitor goroutine. CHANGELOG `[Unreleased]`.
`REVISION-0.6.md` item 5 ticked when done.

## Out of scope

- UDP (no connection start to hook; short UDP is mostly DNS, which passive DNS
  covers).
- A port-scan alert. The summary line shows the numbers; deciding when they
  are suspicious needs real use first.
- Windows and macOS.
- Turning the feature on or off without a restart.
- Kernels before 5.8 (a perf-buffer fallback).
- Connections in other network namespaces that outlive the poll interval.
- Making the kernel the primary source of connection events.

## Amendments (2026-11-10, during implementation)

- **A start record has no local port.** The kernel binds the local port of an
  outbound connection after the CLOSE→SYN_SENT state change, so the record
  written there carries the local address with port 0 (seen on 6.12). The
  tracker takes the endpoints from the `established` record, and from the
  `closed` record for an attempt that never established. Pinned by
  `TestKernelOutbound` / `TestKernelRefused` and `TestTrackerLocalPortArrivesLater`.
- **Lost records are counted by the program**, in a one-slot array map it
  increments when `bpf_ringbuf_output` fails; a ring buffer does not report
  losses by itself.
- **The loop's receive** is handled by `afterRecv` (the decision after the
  receive) rather than a helper that does the receive, which could not share
  a `select` with the poll timer.
- **Privileges** are checked as effective UID 0, like passive DNS. A process
  with `CAP_BPF` + `CAP_PERFMON` but not root is told it needs root.
- **Not exercised by any test:** the reload without byte counters after the
  kernel refuses the program with them (the refusal cannot be induced in the
  VM), and kernels other than 6.12 until CI runs.

## Amendments (2026-11-10, after the independent review and the first real run)

Found by a reviewer with a fresh context and by running the monitor as root
on the real machine; each fix has a test that failed first.

- **"The poll has it" means listed as ESTABLISHED.** The poll only follows
  established sockets; one it lists while closing (CLOSE_WAIT, FIN_WAIT…) it
  never announces, so the tracker keeps that flow and reports it at its
  close. Being listed at all proves the socket is in this network namespace,
  which exempts it from the 6 s rule.
- **The 6 s run from `established`**, not from `connect()`: SYN
  retransmissions, which the far end controls, are not held against a short
  exchange.
- **An inbound `established` always replaces the flow** under its socket
  address, and **an attempt is "failed" only if its close comes from
  SYN_SENT**: after a lost record the tracker reported the wrong process and
  direction, or a working connection as failed.
- **Inbound attribution**: a listener on the same address, or a wildcard
  listener when the address is this machine's; otherwise no process (a
  container's port 80 is not the host's nginx). Connections to the monitor's
  own dashboard are not reported.
- **Past the grouping limits the reputation check still runs** for an
  address not seen in the window, though nothing is shown.
- **Only news about the binary or its behaviour overrides grouping**
  (replaced on disk, beaconing). A staging path alone does not: every
  connection of a `go run` binary or an AppImage was a history row.
- **Beaconing alert once per pair and hour**; the beacon table is swept once
  a minute instead of on every sample (it was quadratic).
- **Byte counts are corrected for sequence space** (our SYN and FIN, the
  peer's FIN): a connection that carried nothing showed "↑1 B".
- **The VM harness and the CI step require tests that ran and passed**: a
  pattern matching nothing, or skipped tests, no longer count as a pass.

The review's minor findings were addressed afterwards, at the owner's
request:

- The tracker remembers what the last poll listed as ESTABLISHED, so a
  connection established just before a poll is not announced twice.
- The reader goroutine resolves the process as a start record arrives and
  drops loopback records; the tracker uses what the reader found.
- Summaries add up bytes; an attempt that never established is a group of
  its own; a process over its cap gets one summary line, not one per address.
- The tracepoint's layout is checked at start-up, before loading.
- "Failed attempt" is worded "attempt not established" (it also covers a
  connect the application abandoned); inbound summaries say "from"; alerts
  from inbound connections draw ←; brief events write IPv6 like polled ones.
- The monitor's state is a type (`liveMonitor`) with `poll` and `record`, and
  a test drives it with both sources. Kernel tests now cover another
  process's connection, a full ring buffer, the reader's back-pressure and a
  non-loopback path (an alias address on `lo`). The VM init requires a
  marker file, not only PID 1.

Left as it is: full-connect scans of an exposed port trigger reputation
lookups and notifications for each scanner — whether that is noise depends
on a machine that is exposed, which the development machine is not.
