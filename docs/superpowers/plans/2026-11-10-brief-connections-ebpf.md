# Brief connections on Linux via eBPF — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Linux, every TCP connection the 3-second poll misses is recorded with its process, duration and volume, and goes through the same checks as a polled connection.

**Architecture:** An eBPF program on the tracepoint `sock:inet_sock_set_state` writes one fixed-size record per relevant TCP state change to a ring buffer. A Linux-only reader decodes records onto a channel. `monitorLoop` selects over that channel and the poll timer; a portable tracker decides which connections were brief, a grouper decides what is published individually.

**Tech Stack:** Go 1.26, `github.com/cilium/ebpf` v0.22.0 (`asm`, `ringbuf`, `link`, `rlimit`, `features`, `btf`) — pure Go, no cgo, no clang. QEMU/KVM for the kernel tests.

**Spec:** `docs/superpowers/specs/2026-11-10-brief-connections-ebpf-design.md`

## Global Constraints

- cgo-free single binary; `CGO_ENABLED=0 go build` stays the only build step. No C source, no compiled BPF object in the repository.
- Kernel code only in `_linux.go` files; shared files must compile for windows and darwin (`verify.sh` cross-compiles six targets).
- Runtime requirements: root, Linux ≥ 5.8 (ring buffer). Loading is never fatal; without it the monitor behaves exactly as today.
- Fixed values: ring buffer 256 KiB (`1 << 18`); record 104 bytes; brief bound 6 s (two poll intervals); flow prune 5 min; grouping window 60 s; 20 individual lines per process per minute.
- Every user-facing string in **es, en and zh** (`i18n.go`; the parity tests enforce it). New keys go in their own blank-line-separated group so gofmt does not realign the map.
- No inline JS: controls use `data-action` / `data-change` and the `actions` table in `web/static/app.js`.
- The tracker and the grouper are touched by the monitor goroutine only. No locks, no other callers.
- Hermetic unit tests: no network, no root. Kernel tests are named `TestKernel…`, live in `_linux_test.go` files and skip unless `os.Geteuid() == 0`.
- Commits: `git -c user.name=eFeSpain commit --no-gpg-sign`, no Co-Authored-By, on branch `feat/short-conns`. `bash verify.sh --quick > out; rc=$?` and commit only when `rc == 0`. Never push or tag.
- gosec exclusions are per file and must be identical in `verify.sh` and `.github/workflows/ci.yml`.

## Review Focus

1. **A record of the wrong size** (a short read, a future layout): `decodeKernelRecord` returns `false`; nothing panics and nothing is tracked. → Task 1.
2. **The kernel reuses a socket address** right after a close whose record was lost: a `start` for an address that still has a flow replaces it; the old flow is not reported with the new one's endpoints. → Task 1.
3. **`closed` earlier than `start`** (records from two CPUs arriving out of order): the duration is clamped to 0 and the connection is still reported. Wall-clock changes never matter: durations come from kernel timestamps only. → Task 1.
4. **A burst** — one process, 10,000 brief connections to 5,000 addresses in a minute: at most 20 individual lines and one per-process summary, and the grouper holds nothing after the window is flushed. → Task 2.
5. **The feature inactive** (no root, old kernel, switched off, another OS): `startShortConns` returns a nil channel; the loop's `select` never fires on it and a closed channel is replaced by nil instead of spinning. → Task 5.

---

### Task 1: Records and the tracker

**Files:**
- Create: `shortconn.go`
- Test: `shortconn_test.go`

**Interfaces:**
- Consumes: `ownPID`, `ownChild(pid int32) bool`, `isLoopback(ip string) bool` (connections.go); `gnet.ConnectionStat` as produced by `gnet.Connections("inet")`.
- Produces:

```go
const (
	recStart, recEstablished, recClosed = 1, 2, 3 // kernelRecord.Kind
	tcpEstablished, tcpSynSent, tcpSynRecv, tcpClose = 1, 2, 3, 7
	kernelRecordSize = 104
	briefBound       = 2 * monitorInterval // 6 s
	flowMaxAge       = 5 * time.Minute
)

// Wire layout, native byte order:
//  0 ts u64 · 8 sock u64 · 16 pid u32 · 20 uid u32 · 24 kind u8 · 25 old u8 ·
// 26 family u16 · 28 lport u16 · 30 rport u16 · 32 laddr4 [4] · 36 raddr4 [4] ·
// 40 laddr6 [16] · 56 raddr6 [16] · 72 comm [16] · 88 sent u64 · 96 recv u64
type kernelRecord struct {
	TS, Sock      uint64 // kernel monotonic ns; socket address
	PID, UID      uint32 // start only
	Kind, Old     uint8
	Local, Remote netip.AddrPort // unmapped
	Comm          string         // start only, NUL-trimmed
	Sent, Recv    uint64         // closed only
}
func decodeKernelRecord(b []byte) (kernelRecord, bool) // false unless len(b) == kernelRecordSize and family is 2 or 10

type briefConn struct {
	Inbound, Failed bool
	PID             int32
	Name, Exe       string // Name falls back to the kernel's comm
	Local, Remote   netip.AddrPort
	Duration        time.Duration
	Sent, Recv      uint64
	HasBytes        bool
}
func newShortTracker(who func(pid int32) (name, exe string), volume bool) *shortTracker
func (t *shortTracker) record(r kernelRecord, now time.Time) (briefConn, bool)
func (t *shortTracker) polled(conns []gnet.ConnectionStat, now time.Time)
func (t *shortTracker) dropped() int // established flows the poll never saw, discarded since the last call
```

- [ ] **Step 1: Write the failing tests** in `shortconn_test.go`. Helpers: `rec(kind, old uint8, sock, tsMillis uint64, pid uint32, local, remote string) kernelRecord` and `encode(kernelRecord) []byte` (the inverse of the decoder, test-only). `who` in tests maps pid 100 → `("curl", "/usr/bin/curl")`, pid 200 → `("sshd", "/usr/sbin/sshd")`, anything else → `("N/A", "")`.

  `TestDecodeKernelRecord`: round-trips an IPv4 start (`pid 100`, `comm "curl"`, `192.168.1.24:50000 → 203.0.113.9:443`) and an IPv6 closed with `Sent 38_000_000, Recv 1024`; an AF_INET6 record carrying `::ffff:203.0.113.9` decodes to `203.0.113.9`; **Review Focus 1:** `decodeKernelRecord(b[:103])`, `append(b, 0)` and a record with family 99 all return `false`.

  `TestTrackerBrief`: start(ts 0) → established → closed(ts 200 ms) emits `{Inbound:false, Failed:false, PID:100, Name:"curl", Exe:"/usr/bin/curl", Duration:200ms}`; nothing is emitted at start or established.

  `TestTrackerSeenByPoll`: start → established → `polled` with a snapshot containing the same local and remote endpoint → closed emits nothing. Same with the snapshot giving the remote as `::ffff:203.0.113.9`.

  `TestTrackerFailedAttempt`: start → closed(ts 300 ms) emits `Failed:true`; start → closed(ts 130 s) **also** emits `Failed:true` (a timed-out connect is never established and never in the poll).

  `TestTrackerBound`: start → established → closed at ts 5.9 s emits; at ts 6.1 s emits nothing. start → established, then `polled(nil, now+7s)` → `dropped() == 1` and a later closed emits nothing.

  `TestTrackerInbound`: `polled` with a LISTEN socket pid 200 on `0.0.0.0:22`, then established(old `tcpSynRecv`, local `192.168.1.24:22`, remote `192.168.1.50:51000`) → closed(+400 ms) emits `{Inbound:true, PID:200, Name:"sshd", Duration:400ms}`. With no listener known: `PID:0, Name:"N/A"`. With listeners on `10.0.0.1:22` (pid 300) and `192.168.1.24:22` (pid 200): the one bound to the local address wins.

  `TestTrackerDiscards`: a start from `ownPID`; a start to `127.0.0.1:5000`; a start from `::1`; an established without a flow whose old state is not `tcpSynRecv`; a closed for an unknown socket — none emits, none leaves a flow (`len(t.flows) == 0`).

  `TestTrackerProcessGone`: start with pid 999 and comm `"x"` → closed emits `Name:"x", Exe:""`.

  **Review Focus 2** `TestTrackerSocketReuse`: start(sock 7, → `203.0.113.9:443`), then start(sock 7, → `198.51.100.4:80`) with no closed between → established → closed emits exactly one conn, remote `198.51.100.4:80`.

  **Review Focus 3** `TestTrackerOutOfOrder`: start(ts 500 ms) → established → closed(ts 400 ms) emits `Duration: 0`.

  `TestTrackerPrune`: start at wall time `t0`; `polled(nil, t0+5min+1s)` → `len(t.flows) == 0`.

- [ ] **Step 2: Run** `go test -run 'DecodeKernelRecord|Tracker' .` — expected: build failure, `undefined: kernelRecord`.

- [ ] **Step 3: Implement `shortconn.go`.** Flows live in the field `flows map[uint64]*flow`, keyed by `Sock`; a flow keeps the kernel `TS` of its first record (for durations) and the wall time it was created (for pruning and the 6 s drop in `polled`). `polled` builds the set of `(local, remote)` endpoint pairs of sockets with a peer (`hasPeer`), unmapped, deletes matching flows, rebuilds the listener table (`port → []{ip, pid}`) from `Status == "LISTEN"`, drops established flows older than `briefBound` (counting them) and any flow older than `flowMaxAge`. `HasBytes` is the tracker's `volume` flag, set only on non-failed conns.

- [ ] **Step 4: Run** `go test -run 'DecodeKernelRecord|Tracker' .` — expected: PASS.

- [ ] **Step 5: Commit** — `feat(shortconn): kernel record and the tracker that decides what was brief`.

---

### Task 2: Grouping and wording

**Files:**
- Modify: `shortconn.go`, `i18n.go`
- Test: `shortconn_test.go`

**Interfaces:**
- Consumes: `briefConn` (Task 1); the byte formatter behind the `mem` template function (`humanRate`, main.go funcMap).
- Produces:

```go
const (
	shortGroupWindow   = 60 * time.Second
	shortPerProcPerMin = 20
)
type shortSummary struct {
	Sample  briefConn // the first connection of the group
	Count   int       // connections not published individually
	Addrs   int       // distinct remote addresses (per-process summaries only)
	PerProc bool
}
func newShortGrouper() *shortGrouper
func (g *shortGrouper) add(c briefConn, now time.Time) bool      // true = publish this one
func (g *shortGrouper) flush(now time.Time) []shortSummary       // groups whose window has closed
func briefDetail(T map[string]string, c briefConn) string
func summaryDetail(T map[string]string, s shortSummary) string
```

i18n keys (es / en / zh), own group:

| Key | es | en |
|---|---|---|
| `ev_short` | `conexión breve` | `brief connection` |
| `ev_short_failed` | `intento fallido` | `failed attempt` |
| `ev_short_in` | `entrante breve` | `brief inbound` |
| `ev_short_more` | `×%d más en 60 s` | `×%d more in 60 s` |
| `ev_short_more_proc` | `×%d conexiones breves más a %d direcciones` | `×%d more brief connections to %d addresses` |

- [ ] **Step 1: Write the failing tests.**

  `TestGrouperFirstThenCounted`: three conns with the same process and remote address at t, t+1s, t+2s → `add` returns `true, false, false`; `flush(t+59s)` is empty; `flush(t+61s)` returns one summary with `Count 2`, `PerProc false`. A group with only its first connection produces no summary. A different remote address, a different process, or `Inbound` differing each start their own group (`add` returns `true`).

  `TestGrouperInboundKey`: inbound conns from the same remote to local ports 22 and 80 are two groups; same remote and port from different remote *ports* is one.

  **Review Focus 4** `TestGrouperBurst`: 10,000 conns from one process to 5,000 distinct addresses (two each) within one second → `add` returns `true` exactly 20 times; `flush(t+61s)` contains exactly one `PerProc` summary with `Count 9960` and `Addrs 4980`, plus 20 per-address summaries with `Count 1` (the second connection to each published address); after it, `len(g.groups) == 0 && len(g.procs) == 0`.

  `TestBriefDetail` (es): `{Duration: 200ms, HasBytes: true, Sent: 38_000_000, Recv: 1024}` → starts with `"conexión breve · 0.2 s · ↑"` and contains `"↓"`; `{Duration: 2400ms}` → `"conexión breve · 2.4 s"` (no arrows without `HasBytes`); `{Failed: true}` → exactly `"intento fallido"`; `{Inbound: true, Duration: 400ms}` → `"entrante breve · 0.4 s"`. `TestSummaryDetail`: `{Count: 14}` → `"×14 más en 60 s"`; `{PerProc: true, Count: 230, Addrs: 61}` → `"×230 conexiones breves más a 61 direcciones"`.

- [ ] **Step 2: Run** `go test -run 'Grouper|BriefDetail|SummaryDetail|Translation' .` — expected: FAIL (undefined).

- [ ] **Step 3: Implement.** Fields `groups` (by group key) and `procs` (by process). Group key: `inbound|proc|remoteIP` outbound, `inbound|proc|remoteIP|localPort` inbound, where `proc` is `Exe`, else `Name`. A new group whose process has already published `shortPerProcPerMin` lines in its current 60 s window is not created: the conn is counted in that process's overflow (count + a set of remote addresses) and `add` returns false. `flush` emits and deletes every group and every process window older than `shortGroupWindow`. Durations print with one decimal and a dot.

- [ ] **Step 4: Run** the same command — expected: PASS.

- [ ] **Step 5: Commit** — `feat(shortconn): group repeated brief connections; wording in three languages`.

---

### Task 3: Kernel test harness (VM)

**Files:**
- Create: `scripts/vm-kernel-test.sh`, `vmmain_linux_test.go`, `shortconn_kernel_linux_test.go`

**Interfaces:**
- Produces: `bash scripts/vm-kernel-test.sh` exits 0 when every `TestKernel…` test passes inside the VM, non-zero otherwise, and prints the test output. `requireKernelTest(t *testing.T)` skips unless root.

- [ ] **Step 1: Write the first kernel test** in `shortconn_kernel_linux_test.go`: `TestKernelTracepointExists` — `requireKernelTest(t)`; reads `/sys/kernel/tracing/events/sock/inet_sock_set_state/format` (falling back to `/sys/kernel/debug/tracing/…`) and asserts it contains each of `skaddr;\toffset:8`, `oldstate;\toffset:16`, `newstate;\toffset:20`, `sport;\toffset:24`, `dport;\toffset:26`, `family;\toffset:28`, `protocol;\toffset:30`, `saddr[4];\toffset:32`, `daddr[4];\toffset:36`, `saddr_v6[16];\toffset:40`, `daddr_v6[16];\toffset:56`. This pins the layout the program hard-codes, on every kernel the tests run on.

- [ ] **Step 2: Write `vmmain_linux_test.go`:** `func TestMain(m *testing.M)`. When `os.Getpid() != 1` it is `os.Exit(m.Run())`. As PID 1: mount `proc` on `/proc`, `sysfs` on `/sys`, `tracefs` on `/sys/kernel/tracing`, `tmpfs` on `/tmp`; set `TMPDIR=/tmp`; bring `lo` up (`SIOCSIFFLAGS` with `IFF_UP` through `golang.org/x/sys/unix`); run; print `VMTEST: exit <code>`; `unix.Sync()`; `unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)`.

- [ ] **Step 3: Write `scripts/vm-kernel-test.sh`:** `set -euo pipefail`; needs `qemu-system-x86_64`, `cpio`, a readable `/boot/vmlinuz-$(uname -r)` and a writable `/dev/kvm`, else prints why and exits 2. Builds `CGO_ENABLED=0 go test -c -o "$tmp/root/init" .`, packs `$tmp/root` with `cpio -o -H newc`, runs `timeout 180 qemu-system-x86_64 -enable-kvm -m 1024 -nographic -no-reboot -kernel … -initrd … -append "console=ttyS0 quiet panic=-1 -- -test.run=^TestKernel -test.v"`, tees the output and exits 0 only if it contains `VMTEST: exit 0`. The temp dir is removed on exit.

- [ ] **Step 4: Run** `bash scripts/vm-kernel-test.sh` — expected: `--- PASS: TestKernelTracepointExists`, `VMTEST: exit 0`, exit status 0. Run `go test -run TestKernel .` as the normal user — expected: `ok` with the test skipped.

- [ ] **Step 5: Commit** — `test: run kernel tests as root inside a VM booted with the host kernel`.

---

### Task 4: The eBPF program and its reader

**Files:**
- Modify: `go.mod`, `go.sum` (`go get github.com/cilium/ebpf@v0.22.0`)
- Create: `shortconn_prog_linux.go`, `shortconn_linux.go`
- Test: `shortconn_kernel_linux_test.go`

**Interfaces:**
- Consumes: `kernelRecord`, `decodeKernelRecord`, the record layout and constants (Task 1); the harness (Task 3).
- Produces:

```go
// shortconn_prog_linux.go
type volumeOffsets struct{ sent, recv int32 } // byte offsets in struct tcp_sock; nil = no volume (Task 7 fills it)
func shortConnProgram(eventsFD, dropsFD int, vol *volumeOffsets) asm.Instructions

// shortconn_linux.go
type shortConnSource struct{ /* reader, link, program, maps */ }
var errNoRingBuf = errors.New("kernel without BPF ring buffer")
func openShortConnSource() (*shortConnSource, error) // errNoRingBuf, or the load/attach error
func (s *shortConnSource) next() (kernelRecord, error) // blocks; malformed records are skipped
func (s *shortConnSource) setDeadline(t time.Time)
func (s *shortConnSource) lost() uint64                 // records the kernel could not queue, cumulative
func (s *shortConnSource) volume() bool
func (s *shortConnSource) Close() error
```

Program behaviour (the tests below are the contract; the assembly is the implementer's):
- `r1` is the tracepoint record. Return 0 unless `protocol` (u16 @30) is 6 and `newstate` (@20) is `tcpSynSent`, `tcpEstablished` or `tcpClose`.
- Build the 104-byte record on the stack, every byte initialised. `ts` = `bpf_ktime_get_ns`; `sock` = `skaddr`; `old` = `oldstate`; `family`, `lport` = `sport`, `rport` = `dport` copied as they are; bytes 32–71 of the tracepoint record copied to bytes 32–71 of ours (the two layouts coincide on purpose).
- `kind` = `recStart` / `recEstablished` / `recClosed`. On `recStart` only: `pid` = upper 32 bits of `bpf_get_current_pid_tgid`, `uid` = lower 32 bits of `bpf_get_current_uid_gid`, `comm` = `bpf_get_current_comm`.
- `bpf_ringbuf_output(events, &rec, 104, 0)`; when it fails, atomically add 1 to slot 0 of the `drops` array map. Return 0.
- License `"GPL"`, type `ebpf.TracePoint`.

`openShortConnSource`: `rlimit.RemoveMemlock()`; `features.HaveMapType(ebpf.RingBuf)` failing → `errNoRingBuf`; maps `events` (`ebpf.RingBuf`, `MaxEntries 1 << 18`) and `drops` (`ebpf.Array`, key 4, value 8, 1 entry); `ebpf.NewProgram`; `link.Tracepoint("sock", "inet_sock_set_state", prog, nil)`; `ringbuf.NewReader(events)`. Everything opened so far is closed on any error.

- [ ] **Step 1: Write the failing kernel tests.** Shared helper `collect(t, src, want func([]kernelRecord) bool) []kernelRecord`: reads with a 3 s deadline until `want` is satisfied, keeping only records whose local or remote port is one the test owns.

  `TestKernelOutbound`: listen on `127.0.0.1:0`, accept in a goroutine, dial it, close both. Among the records for the client's local port: a `recStart` with `PID == uint32(os.Getpid())`, `Comm` equal to the contents of `/proc/self/comm` (trimmed), `UID == 0`, `Remote` the listener's address; then a `recEstablished` with `Old == tcpSynSent`; then a `recClosed`; all three share one `Sock` and have non-decreasing `TS`.

  `TestKernelInbound`: same exchange; among the records whose **local** port is the listener's: a `recEstablished` with `Old == tcpSynRecv` and `Remote` equal to the client's address, then a `recClosed` with the same `Sock`; and **no** `recStart` for that socket.

  `TestKernelRefused`: dial a port nothing listens on (bind `127.0.0.1:0`, note the port, close, dial) → a `recStart` and a `recClosed` for the client socket and no `recEstablished` between them.

  `TestKernelIPv6`: the outbound test over `[::1]`; `Local.Addr()` and `Remote.Addr()` are `::1`.

  `TestKernelIgnoresUDP`: send a UDP datagram to `127.0.0.1` on a free port; no record carries that port.

  `TestKernelLostRecords`: `src.lost()` is 0 after the tests above (the counter exists and reads).

- [ ] **Step 2: Run** `bash scripts/vm-kernel-test.sh` — expected: build failure (`undefined: openShortConnSource`), exit non-zero.

- [ ] **Step 3: Implement** `shortconn_prog_linux.go` (one comment per instruction or small group, register roles stated at the top) and `shortconn_linux.go`. When the verifier refuses the program, wrap the `*ebpf.VerifierError` so its first lines reach the log.

- [ ] **Step 4: Run** `bash scripts/vm-kernel-test.sh` — expected: all six `TestKernel…` plus `TestKernelTracepointExists` pass, `VMTEST: exit 0`. Then `bash verify.sh` (full, not `--quick`: the new files must cross-compile for all six targets) — expected: `all green`.

- [ ] **Step 5: Commit** — `feat(shortconn): eBPF program on sock:inet_sock_set_state and its ring-buffer reader`. The message states the kernel version the tests ran on.

---

### Task 5: Start-up, status and the switch

**Files:**
- Modify: `shortconn.go`, `shortconn_linux.go`, `config.go`, `main.go`, `i18n.go`, `web/templates/report.html`, `web/static/app.js`
- Create: `shortconn_other.go`
- Test: `shortconn_test.go`, `template_test.go`

**Interfaces:**
- Consumes: `openShortConnSource`, `errNoRingBuf` (Task 4).
- Produces:

```go
// shortconn.go (portable)
var shortConnsEnabled atomic.Bool        // SHORT_CONNS != "false"; default on
func loadShortConns()
func setShortConns(on bool)              // persists SHORT_CONNS; takes effect at the next start
func shortConnStatus() (code, detail string) // "active" | "root" | "ringbuf" | "refused" | "off" | "os" | "stopped"
func shortConnStatusText(T map[string]string) (text string, active bool)

// shortconn_linux.go / shortconn_other.go
func startShortConns() (records <-chan kernelRecord, volume bool) // nil channel when inactive
```

`startShortConns` order: switched off → `"off"`; not root → `"root"`; `errNoRingBuf` → `"ringbuf"`; any other error → `"refused"` with the error text as detail; else `"active"`, a goroutine that forwards `next()` to a channel of capacity 1024 with a **blocking** send (back-pressure stays in the kernel buffer, where overflow is counted) and, once a minute, logs the increase of `lost()`. A read error other than a deadline logs once, sets `"stopped"` and ends the goroutine **without closing the channel**. The non-Linux stub sets `"os"` and returns `nil, false`.

Settings: `getSettings` adds `short_conns` (bool) and `short_conns_status` (localised by the request's language — `handleSettings` already knows it; pass `T` or add the two fields there). Body field `ShortConns *bool`.

i18n keys, own group: `short_conns_label` (es `Detectar conexiones breves (eBPF, solo Linux)`), `short_conns_hint` (es `Registra las conexiones TCP que duran menos que el sondeo de 3 s, con su proceso. Es un enganche en el kernel: necesita root y Linux 5.8 o posterior. El cambio se aplica al reiniciar el monitor.`), `short_st_active` (`activo — eBPF`), `short_st_root` (`inactivo — requiere root`), `short_st_ringbuf` (`inactivo — kernel sin ring buffer (anterior a 5.8)`), `short_st_refused` (`inactivo — el kernel rechazó el programa: %s`), `short_st_off` (`desactivado en Ajustes`), `short_st_os` (`no disponible en este sistema (solo Linux)`), `short_st_stopped` (`detenido — el lector falló; mira el log`). English and Chinese equivalents with the same verbs.

UI: checkbox `id="short-conns"` and `<span id="short-conns-status">` in the Settings body, after the update-check block; `openSettings` fills both; `settingsPayload` sends `ShortConns`. Before anything has called `startShortConns`, the status code is `"off"` when the switch is off and `"stopped"` otherwise; Task 6 makes `main` call it.

- [ ] **Step 1: Write the failing tests.**

  `TestShortConnsSwitch`: `withTempEnv`; default `shortConnsEnabled` is true after `loadShortConns()` with the variable unset; `SHORT_CONNS=false` turns it off; `jsonPost(handleSettings, …, {"ShortConns":false})` returns `short_conns == false` and the temp `.env` contains `SHORT_CONNS=false`; posting `{}` leaves it unchanged.

  **Review Focus 5** `TestStartShortConnsInactive`: skipped when root. With the switch on, `startShortConns()` returns a nil channel and `false`, and `shortConnStatus()` is `"root"` on Linux, `"os"` elsewhere. With the switch off the code is `"off"` (checked before privileges). `shortConnStatusText(strings_("es"))` returns the matching sentence and `active == false`.

  `TestShortConnStatusTexts`: for every code, `shortConnStatusText` in es, en and zh is non-empty and, for `"refused"` with detail `"boom"`, contains `"boom"`.

  `TestSettingsHasShortConns` (template_test.go): the rendered `report.html` contains `id="short-conns"` and `id="short-conns-status"`, both before `class="modal-foot"`.

- [ ] **Step 2: Run** `go test -run 'ShortConn|SettingsHasShortConns|Translation' .` — expected: FAIL (undefined).

- [ ] **Step 3: Implement.** `main.go`: `loadShortConns()` next to `loadUpdateCheck()`. Nothing calls `startShortConns()` outside the tests yet.

- [ ] **Step 4: Run** the same command — expected: PASS. Add to `shortconn_kernel_linux_test.go` `TestKernelStartShortConns`: as root, `startShortConns()` returns a non-nil channel, the status is `"active"`, and a loopback connection produces records on the channel. Run `bash scripts/vm-kernel-test.sh` — expected: PASS.

- [ ] **Step 5: Commit** — `feat(shortconn): start-up status, Settings switch (SHORT_CONNS)`.

---

### Task 6: The monitor uses it

**Files:**
- Modify: `monitor.go`, `main.go`, `actions.go`, `web/static/app.js`, `web/templates/report.html`
- Test: `monitor_test.go`, `template_test.go`, `shortconn_kernel_linux_test.go`

**Interfaces:**
- Consumes: `startShortConns`, `newShortTracker`, `(*shortTracker).record/polled/dropped`, `newShortGrouper`, `add`, `flush`, `briefDetail`, `summaryDetail`, `procNameExe`.
- Produces:

```go
// Event gains:
Inbound bool `json:"inbound,omitempty"` // brief inbound connection: the feed draws the arrow the other way

type connSighting struct {
	ev       Event  // Kind and Detail preset for a brief connection; empty for a polled one
	remoteIP string
	newProc  bool // first time this PID is seen
	muted    bool // whitelisted binary: recorded, never notified
	quiet    bool // grouped repeat: published only if a check fires
}
func announceConn(s connSighting, nowSec float64)
func monitorLoop(records <-chan kernelRecord, volume bool) // was monitorLoop()
func briefSighting(c briefConn, T map[string]string) connSighting // the Event for a brief connection, checks not yet applied
```

`announceConn` is today's per-connection block of `monitorLoop`, moved unchanged in behaviour for polled connections: kind by path and remote, binary baseline (`Anomaly`, `Changed`), beaconing, `publish`, `alertOnIntel`, the notification switch. For a preset `ev.Kind == "short"`:
- the kind stays `short` unless an alert reason fires (suspicious path, replaced binary, beaconing); then `Kind = "alert"` and `Detail = <reason> · <brief detail>`;
- beaconing is skipped when `ev.Inbound`; when there is no `Exe`, the key is `"comm:" + Process`;
- `quiet`: nothing is published and `alertOnIntel` is not started unless an alert reason fired.

`main.go`: `records, volume := startShortConns()` synchronously, then `go monitorLoop(records, volume)` — so the status is settled before `startupBanner` runs. `startupBanner` gains `[+] Conex. breves   <text>` when active and `[-] Conex. breves   <text>` otherwise, from `shortConnStatusText(strings_(currentLang()))`.

`monitorLoop`: one `shortTracker` (built with `procNameExe` and `volume`) and one `shortGrouper`; the `time.Sleep` becomes a `time.Timer` reset after each poll, in a `select` with `records`. On a record: `tracker.record` → if brief, `grouper.add` decides `quiet`, then `announceConn`. `r, ok := <-records` with `!ok` sets `records = nil`. After each poll: `tracker.polled(conns, now)`; each `grouper.flush(now)` summary is published as `Event{Kind: "short", Detail: summaryDetail(…)}` with the sample's process and remote; once a minute, a non-zero `tracker.dropped()` is logged as connections outside the poll's view.

Feed (`app.js` `eventLabel`): `case 'short': return '⚡ ' + (ev.detail || T.ev_short) + ' — ' + proc + ' (' + pid + ') ' + (ev.inbound ? '← ' : '→ ') + (ev.remote || '')`. CSS `.ev-short{color:#a371f7;}`. History kind selector: `<option value="short">short</option>`.

- [ ] **Step 1: Write the failing tests.** Helper `captureEvents(t)`: `setupTestDB`, `subscribe()`, returns a func that drains what was published.

  `TestAnnouncePolledUnchanged`: a sighting with an empty event kind, a public remote and a known binary publishes exactly one event of kind `remote`; a private remote → `new`; an exe under `/tmp/` → `alert`. (This pins the refactor.)

  `TestAnnounceBrief`: `briefSighting` of `{Name:"curl", Exe:"/usr/bin/curl", PID:100, Remote: 203.0.113.9:443, Duration:200ms}` announced → one event with `Kind "short"`, `Process "curl"`, `Remote "203.0.113.9:443"`, `Detail` starting with `conexión breve`. With `quiet: true` → no event. With `Inbound` → `Inbound == true` on the event and `Local` set to the listening endpoint.

  `TestAnnounceBriefBeacon`: five brief sightings of the same exe and remote, announced with `nowSec` 0, 60, 120, 180, 240, the last four `quiet` → the fifth publishes an event of kind `alert` whose detail contains both `beaconing` and `conexión breve`. The same sequence with `Inbound` publishes no alert.

  `TestAnnounceBriefNoPath`: `{Name:"x", Exe:""}` four times at 60 s spacing → the beacon key is `comm:x` (an alert appears on the fourth sample or later, as for a path).

  **Review Focus 5** `TestClosedRecordChannelIsDisabled`: the loop's receive step, factored as `func recvRecord(ch <-chan kernelRecord) (kernelRecord, bool, <-chan kernelRecord)`, returns the same channel on a value and `nil` on a closed channel.

  `TestHistoryKindShort` (template_test.go): the history modal contains `<option value="short">`; `report.html` contains `.ev-short`.

- [ ] **Step 2: Run** `go test -run 'Announce|ClosedRecordChannel|HistoryKindShort' .` — expected: FAIL (undefined).

- [ ] **Step 3: Implement.** Move the block first and run the whole suite (`go test .`) before adding the brief path: the existing monitor tests must pass untouched.

- [ ] **Step 4: Run** `go test .` — expected: PASS. Then add `TestKernelEndToEnd` and run `bash scripts/vm-kernel-test.sh` — expected: PASS. The VM has only `lo`, and the tracker discards loopback, so the test joins the real pieces by hand: `startShortConns()` → the records of one loopback exchange made by the test → their endpoints rewritten to `192.0.2.1:<port>` and `203.0.113.9:<port>` → a tracker whose `who` knows the test's PID → `briefSighting` → `announceConn`. Assert: `searchEvents(eventFilter{Kind: "short"})` holds exactly one row, with the test process's name and remote `203.0.113.9:<port>`.

- [ ] **Step 5: Commit** — `feat(monitor): brief connections reach the feed, the history and the checks`.

---

### Task 7: Bytes moved (separable — skip if it does not converge)

**Files:**
- Modify: `shortconn_prog_linux.go`, `shortconn_linux.go`
- Test: `shortconn_kernel_linux_test.go`, `shortconn_test.go`

**Interfaces:**
- Consumes: `volumeOffsets`, `shortConnProgram(…, vol)` (Task 4).
- Produces: `func tcpSockOffsets() (*volumeOffsets, error)` — `btf.LoadKernelSpec()`, the struct `tcp_sock`, members `bytes_acked` and `bytes_received` found recursively through anonymous struct/union members, offsets in bytes. `(*shortConnSource).volume()` reports whether the loaded program reads them.

Program: on `recClosed` and `vol != nil`, two `bpf_probe_read_kernel(dst, 8, skaddr + offset)` into `sent` (@88) and `recv` (@96). `openShortConnSource`: offsets unavailable → load without; load with offsets refused → load again without (`volume() == false`), and the log says which.

- [ ] **Step 1: Write the failing tests.** `TestKernelVolume`: skip if `tcpSockOffsets()` errors; the client writes 100,000 bytes and reads 20,000 written by the server, both close → the client socket's `recClosed` has `Sent` in `[100000, 100016]` and `Recv` in `[20000, 20016]` (the kernel counts the SYN/FIN sequence numbers in some versions). `TestKernelVolumeOffsets`: both offsets are positive, different, and multiples of 8. Unit (`shortconn_test.go`): a tracker built with `volume: false` never sets `HasBytes`; with `true`, a failed attempt still has `HasBytes == false`.

- [ ] **Step 2: Run** `bash scripts/vm-kernel-test.sh` — expected: FAIL (`undefined: tcpSockOffsets`).

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run** `bash scripts/vm-kernel-test.sh` — expected: PASS, including every earlier kernel test.

- [ ] **Step 5: Commit** — `feat(shortconn): bytes sent and received of a brief connection, from kernel BTF offsets`. If after a bounded effort the verifier or the offsets do not converge, revert this task's changes, leave `vol` always nil, and record in the changelog that brief connections carry no volume.

---

### Task 8: CI, verify, documentation

**Files:**
- Modify: `.github/workflows/ci.yml`, `verify.sh`, `README.md`, `README.es.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `REVISION-0.6.md` (untracked)

- [ ] **Step 1: CI.** After the `go test (race)` step: a step `kernel tests (eBPF, as root)` running `CGO_ENABLED=0 go test -c -o "$RUNNER_TEMP/efemon.test" .` then `sudo "$RUNNER_TEMP/efemon.test" -test.run '^TestKernel' -test.v`. Any gosec exclusion the new files needed is added, with its one-line reason, to both the workflow and `verify.sh`.

- [ ] **Step 2: `verify.sh`.** In full mode, after the cross-compile, a step `kernel tests (VM)` that runs `scripts/vm-kernel-test.sh`; exit status 2 from the script (no QEMU/KVM) prints `skipped` and is not a failure.

- [ ] **Step 3: Documentation.** README (both languages): the feature under live monitoring; requirements (root, Linux ≥ 5.8); limits — TCP only, a process that exits within milliseconds is named but has no path, connections inside other network namespaces that outlive the poll are not shown. ARCHITECTURE.md: the second event source, the files, the rule that tracker and grouper belong to the monitor goroutine, how to run the kernel tests. CHANGELOG `[Unreleased]` → Added. `REVISION-0.6.md`: item 5 ticked.

- [ ] **Step 4: Run** `bash verify.sh` (full) — expected: `all green`, with the VM step passing.

- [ ] **Step 5: Commit** — `ci,docs: kernel tests in CI and in verify.sh; brief connections documented`. Then `git checkout main && git merge --ff-only feat/short-conns`, rebuild the desktop shortcut binary, and hand the user the manual check: start as root, read the `Conex. breves` banner line, run a short `curl`, look for the ⚡ line, browse for a few minutes and report the noise.
