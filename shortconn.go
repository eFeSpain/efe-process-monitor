package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
)

// Brief connections.
//
// The live monitor polls the socket table every monitorInterval. A connection
// that opens and closes between two polls leaves no trace — and a C2 check-in
// or a quick upload lasts less than that. On Linux the kernel tells us about
// every TCP connection as it happens (shortconn_linux.go); this file is the
// part that needs no kernel: what a record is, and which connections were
// brief.
//
// Everything here belongs to the monitor goroutine. There are no locks.

// Kinds of kernel record, and the TCP states the kernel reports in them.
const (
	recStart       = 1 // a process called connect()
	recEstablished = 2 // the handshake completed (either direction)
	recClosed      = 3 // the socket is gone

	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3

	afInet  = 2
	afInet6 = 10
)

const (
	// kernelRecordSize is the fixed size of a record on the wire. Layout,
	// native byte order:
	//
	//	 0 ts u64      8 sock u64    16 pid u32    20 uid u32
	//	24 kind u8    25 old u8     26 family u16 28 lport u16  30 rport u16
	//	32 laddr4 [4] 36 raddr4 [4] 40 laddr6 [16] 56 raddr6 [16]
	//	72 comm [16]  88 sent u64   96 recv u64
	//
	// Bytes 32–71 are bytes 32–71 of the kernel's own tracepoint record: the
	// program copies them across without looking at them.
	kernelRecordSize = 104

	// briefBound is how long an established connection can have lasted and
	// still be "one the poll missed": two poll intervals. Past that, a
	// connection the poll never saw is one it cannot see at all (a socket in
	// another network namespace), not a brief one.
	briefBound = 2 * monitorInterval

	// flowMaxAge forgets a flow whose close never arrived (a lost record).
	flowMaxAge = 5 * time.Minute
)

// kernelRecord is one TCP state change, as the kernel program reported it.
type kernelRecord struct {
	TS, Sock      uint64 // kernel monotonic clock (ns); the socket's address, its identity while it lives
	PID, UID      uint32 // recStart only: the process inside whose connect() the kernel was
	Kind, Old     uint8  // rec…; the TCP state the socket was leaving
	Local, Remote netip.AddrPort
	Comm          string // recStart only: the kernel's name for that process, up to 15 bytes
	Sent, Recv    uint64 // recClosed only, and only when the program reads them

	// Not from the kernel: who the PID is, looked up by the reader the moment
	// a recStart arrives ("" = not looked up; "N/A" = already gone).
	Name, Exe string
}

// loopbackRecord reports whether a record is about a loopback connection,
// which the monitor does not follow. The reader drops these before they take
// room in the channel: a machine busy talking to itself must not crowd out
// the records that matter.
func loopbackRecord(r kernelRecord) bool {
	return (r.Local.IsValid() && r.Local.Addr().IsLoopback()) || (r.Remote.IsValid() && r.Remote.Addr().IsLoopback())
}

// decodeKernelRecord parses one record. Anything of another size or with an
// unknown address family is not a record of ours.
func decodeKernelRecord(b []byte) (kernelRecord, bool) {
	if len(b) != kernelRecordSize {
		return kernelRecord{}, false
	}
	ne := binary.NativeEndian
	r := kernelRecord{
		TS: ne.Uint64(b[0:]), Sock: ne.Uint64(b[8:]),
		PID: ne.Uint32(b[16:]), UID: ne.Uint32(b[20:]),
		Kind: b[24], Old: b[25],
		Sent: ne.Uint64(b[88:]), Recv: ne.Uint64(b[96:]),
	}
	lport, rport := ne.Uint16(b[28:]), ne.Uint16(b[30:])
	var la, ra netip.Addr
	switch ne.Uint16(b[26:]) {
	case afInet:
		la, ra = netip.AddrFrom4([4]byte(b[32:36])), netip.AddrFrom4([4]byte(b[36:40]))
	case afInet6:
		// Unmapped: an AF_INET6 socket talking to an IPv4 peer must compare
		// equal to the plain IPv4 address the poll reports.
		la, ra = netip.AddrFrom16([16]byte(b[40:56])).Unmap(), netip.AddrFrom16([16]byte(b[56:72])).Unmap()
	default:
		return kernelRecord{}, false
	}
	r.Local, r.Remote = netip.AddrPortFrom(la, lport), netip.AddrPortFrom(ra, rport)
	comm := b[72:88]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	r.Comm = string(comm)
	return r, true
}

// briefConn is a connection the poll never saw: over before it could.
type briefConn struct {
	Inbound       bool // someone connected to a port this machine listens on
	Failed        bool // a connect() that never completed: refused or timed out
	PID           int32
	Name, Exe     string // Name falls back to the kernel's comm when the process is gone
	Local, Remote netip.AddrPort
	Duration      time.Duration
	Sent, Recv    uint64
	HasBytes      bool // Sent/Recv are meaningful
}

// flow is a connection seen starting and not yet seen ending.
type flow struct {
	ts          uint64    // kernel time of its first record: durations are differences of these
	born        time.Time // wall time, for pruning only
	estTS       uint64    // kernel time it was established (0: not yet, or that record was lost)
	estBorn     time.Time // wall time it was established
	inbound     bool
	established bool
	visible     bool // the poll has listed this socket, though never as ESTABLISHED: it is in this network namespace
	pid         int32
	name, exe   string
	local       netip.AddrPort
	remote      netip.AddrPort
}

type listener struct {
	addr netip.Addr
	pid  int32
}

// shortTracker turns kernel records and poll snapshots into brief connections.
// endpoints identify a connection the way both sources can name it.
type endpoints struct{ local, remote netip.AddrPort }

type shortTracker struct {
	who       func(pid int32) (name, exe string)
	hostAddrs func() []netip.Addr // this machine's own addresses (a variable for the tests)
	volume    bool                // the kernel program reads byte counters
	flows     map[uint64]*flow
	listeners map[uint16][]listener // local port → who listens there, from the last poll
	own       map[netip.Addr]bool   // hostAddrs at the last poll
	announced map[endpoints]bool    // listed as ESTABLISHED by the last poll: the poll announced these
	lost      int                   // established flows dropped as invisible to the poll
}

func newShortTracker(who func(pid int32) (name, exe string), volume bool) *shortTracker {
	return &shortTracker{who: who, hostAddrs: interfaceAddrs, volume: volume,
		flows: map[uint64]*flow{}, listeners: map[uint16][]listener{}, own: map[netip.Addr]bool{},
		announced: map[endpoints]bool{}}
}

// interfaceAddrs are the addresses configured on this machine's interfaces.
func interfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// record takes one kernel record and returns a brief connection when the
// record closes one.
func (t *shortTracker) record(r kernelRecord, now time.Time) (briefConn, bool) {
	switch r.Kind {
	case recStart:
		// Replaces any flow left under this socket address: the kernel reuses
		// addresses, and the previous connection's close may have been lost.
		delete(t.flows, r.Sock)
		if r.PID > math.MaxInt32 || !trackable(r) {
			return briefConn{}, false
		}
		pid := int32(r.PID)
		if pid == ownPID || ownChild(pid) {
			return briefConn{}, false
		}
		// Who it is was looked up by the reader as the record arrived; if
		// not (tests, another source), now. In a moment the process may be
		// gone, and then the kernel's own name for it is all there is.
		name, exe := r.Name, r.Exe
		if name == "" {
			name, exe = t.who(pid)
		}
		if name == "" || name == "N/A" {
			name = r.Comm
		}
		t.flows[r.Sock] = &flow{ts: r.TS, born: now, pid: pid, name: name, exe: exe, local: r.Local, remote: r.Remote}

	case recEstablished:
		if r.Old == tcpSynRecv {
			// An inbound connection has no start record: this is its first.
			// It replaces whatever was under this socket address — a flow
			// still there lost its close, and its process and direction
			// belong to another connection.
			delete(t.flows, r.Sock)
			if trackable(r) {
				t.flows[r.Sock] = &flow{ts: r.TS, born: now, estTS: r.TS, estBorn: now,
					inbound: true, established: true, local: r.Local, remote: r.Remote}
			}
		} else if f := t.flows[r.Sock]; f != nil {
			f.established, f.estTS, f.estBorn = true, r.TS, now
			// The start record was written before the kernel chose the
			// local port; from here on the endpoints are complete.
			if trackable(r) {
				f.local, f.remote = r.Local, r.Remote
			}
			// Established just before the last poll read the socket table,
			// its records processed after: the poll has announced it.
			if t.announced[endpoints{f.local, f.remote}] {
				delete(t.flows, r.Sock)
			}
		}

	case recClosed:
		f := t.flows[r.Sock]
		if f == nil {
			return briefConn{}, false // a listening socket, or a flow the poll took over
		}
		delete(t.flows, r.Sock)
		var d time.Duration
		if r.TS > f.ts { // records from two CPUs can arrive out of order
			d = time.Duration(r.TS - f.ts) // #nosec G115 -- a difference of monotonic nanoseconds since boot
		}
		// A socket only closes from SYN_SENT when the connect never
		// completed. Closing from any other state it was established, even
		// if that record was lost.
		failed := !f.established && r.Old == tcpSynSent
		if (failed || f.local.Port() == 0) && r.Local.IsValid() && r.Local.Port() != 0 {
			f.local = r.Local // no "established" was seen: the close has the port
		}
		c := briefConn{Inbound: f.inbound, Failed: failed, PID: f.pid, Name: f.name, Exe: f.exe,
			Local: f.local, Remote: f.remote, Duration: d}
		if !failed {
			// Brief means brief once connected: the handshake's own delay —
			// SYN retransmissions, which the far end controls — is not held
			// against it. A socket the poll has listed is in this namespace
			// whatever it lasted.
			since := f.ts
			if f.estTS != 0 {
				since = f.estTS
			}
			if !f.visible && r.TS > since && time.Duration(r.TS-since) >= briefBound { // #nosec G115 -- as above
				t.lost++
				return briefConn{}, false
			}
			c.HasBytes = t.volume
			// The kernel counts in sequence space: our SYN and FIN take one
			// number each on the way out, the peer's FIN one on the way in.
			// Off by a byte or two for a connection reset instead of closed.
			c.Sent, c.Recv = r.Sent-min(r.Sent, 2), r.Recv-min(r.Recv, 1)
		}
		if c.Inbound {
			var mine bool
			if c.PID, c.Name, c.Exe, mine = t.listenerOf(c.Local); mine {
				return briefConn{}, false // someone opening the monitor's own dashboard
			}
		}
		return c, true
	}
	return briefConn{}, false
}

// trackable: loopback is not the monitor's business, here as in the poll.
func trackable(r kernelRecord) bool {
	return r.Local.IsValid() && r.Remote.IsValid() && !r.Local.Addr().IsLoopback() && !r.Remote.Addr().IsLoopback()
}

// listenerOf is the process an inbound connection to local belongs to: a
// listener bound to that very address, or a wildcard one when the address is
// this machine's. A wildcard listener here does not own a connection to an
// address in another network namespace (a container's port 80 is not the
// host's nginx). mine reports that the listener is the monitor itself.
func (t *shortTracker) listenerOf(local netip.AddrPort) (pid int32, name, exe string, mine bool) {
	var pick *listener
	for i, l := range t.listeners[local.Port()] {
		if l.addr == local.Addr() {
			pick = &t.listeners[local.Port()][i]
			break
		}
		if l.addr.IsUnspecified() && t.own[local.Addr()] && pick == nil {
			pick = &t.listeners[local.Port()][i]
		}
	}
	if pick == nil {
		return 0, "N/A", "", false
	}
	if pick.pid == ownPID || ownChild(pick.pid) {
		return 0, "", "", true
	}
	name, exe = t.who(pick.pid)
	return pick.pid, name, exe, false
}

// polled is called with every poll's sockets. A flow the poll can see is no
// longer ours — it follows the ordinary path — and the listeners are whoever
// inbound connections will be attributed to.
func (t *shortTracker) polled(conns []gnet.ConnectionStat, now time.Time) {
	seen := t.announced            // listed as ESTABLISHED: the poll announces these itself
	listed := map[endpoints]bool{} // listed in a closing state: the poll never announces these
	clear(seen)
	clear(t.listeners)
	clear(t.own)
	for _, a := range t.hostAddrs() {
		t.own[a] = true
	}
	for _, c := range conns {
		la, ok := addrPortOf(c.Laddr)
		if !ok || isUDP(c) {
			continue
		}
		if c.Status == "LISTEN" {
			if c.Pid > 0 {
				t.listeners[la.Port()] = append(t.listeners[la.Port()], listener{la.Addr(), c.Pid})
			}
			continue
		}
		ra, ok := addrPortOf(c.Raddr)
		if !ok || !hasPeer(c) {
			continue
		}
		// The poll only follows ESTABLISHED sockets (trackConn). One it
		// lists while closing — CLOSE_WAIT, FIN_WAIT… — it will never
		// announce, so that connection is still the tracker's to report.
		if c.Status == "ESTABLISHED" {
			seen[endpoints{la, ra}] = true
		} else {
			listed[endpoints{la, ra}] = true
		}
	}
	for sock, f := range t.flows {
		p := endpoints{f.local, f.remote}
		if listed[p] {
			f.visible = true
		}
		switch {
		case seen[p]:
			delete(t.flows, sock)
		case f.established && !f.visible && now.Sub(f.estBorn) >= briefBound:
			// Established for longer than two polls and never listed: not
			// brief, invisible (another network namespace).
			t.lost++
			delete(t.flows, sock)
		case now.Sub(f.born) >= flowMaxAge:
			delete(t.flows, sock)
		}
	}
}

// dropped returns how many established connections were discarded as
// invisible to the poll since the last call.
func (t *shortTracker) dropped() int {
	n := t.lost
	t.lost = 0
	return n
}

// addrPortOf converts a polled socket address, unmapped like the kernel's.
func addrPortOf(a gnet.Addr) (netip.AddrPort, bool) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || a.Port > math.MaxUint16 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), true
}

// ── Grouping ─────────────────────────────────────────────────────────────────
//
// One line per brief connection would bury the feed and the history under a
// process that makes hundreds of them — a scanner, a torrent client, a build
// fetching dependencies. The first of a kind is shown at once; repeats are
// counted and summarised when the window closes.

const (
	// shortGroupWindow is how long repeats of the same connection are counted
	// before their summary is published.
	shortGroupWindow = 60 * time.Second
	// shortPerProcPerMin caps the individual lines one process gets in a
	// window; past it, everything goes to a single per-process summary.
	shortPerProcPerMin = 20
)

// shortSummary is what was not published individually.
type shortSummary struct {
	Sample     briefConn // the first connection of the group
	Count      int       // connections counted in silence
	Addrs      int       // distinct remote addresses (per-process summaries only)
	PerProc    bool      // the per-process overflow rather than one group's repeats
	Sent, Recv uint64    // what the counted connections moved, together
	HasBytes   bool
}

// tally is what a group or a process's overflow has counted in silence.
type tally struct {
	count      int
	sent, recv uint64
	hasBytes   bool
}

func (t *tally) add(c briefConn) {
	t.count++
	t.sent += c.Sent
	t.recv += c.Recv
	t.hasBytes = t.hasBytes || c.HasBytes
}

func (t *tally) merge(o tally) {
	t.count += o.count
	t.sent += o.sent
	t.recv += o.recv
	t.hasBytes = t.hasBytes || o.hasBytes
}

type shortGroup struct {
	start  time.Time
	proc   string
	sample briefConn
	tally
}

type shortProc struct {
	start     time.Time
	published int
	sample    briefConn // first connection over the cap
	addrs     map[netip.Addr]bool
	tally     // the overflow: connections past the cap
}

// shortGrouper decides which brief connections get a line of their own.
type shortGrouper struct {
	groups map[string]*shortGroup // direction + outcome + process + remote address (+ local port, inbound)
	procs  map[string]*shortProc  // process
}

func newShortGrouper() *shortGrouper {
	return &shortGrouper{groups: map[string]*shortGroup{}, procs: map[string]*shortProc{}}
}

// briefProc identifies the process of a brief connection: its path, or the
// name when the path could not be read.
func briefProc(c briefConn) string {
	if c.Exe != "" {
		return c.Exe
	}
	return "comm:" + c.Name
}

// add reports whether c should be published on its own, and whether it is
// the first connection of this window from that process to that address. A
// repeat of a group already open is counted; a new group is published unless
// its process has used up its lines — but a new address is still new, and
// still has to be checked, when nothing is shown for it.
//
// An attempt that never established is not a repeat of a connection that
// worked, nor the other way round: they are separate groups.
func (g *shortGrouper) add(c briefConn, now time.Time) (publish, fresh bool) {
	proc := briefProc(c)
	key := "out|"
	if c.Inbound {
		key = "in|" + strconv.Itoa(int(c.Local.Port())) + "|"
	}
	if c.Failed {
		key += "failed|"
	}
	key += proc + "|" + c.Remote.Addr().String()
	if grp := g.groups[key]; grp != nil {
		grp.add(c)
		return false, false
	}
	p := g.procs[proc]
	if p == nil {
		p = &shortProc{start: now, addrs: map[netip.Addr]bool{}}
		g.procs[proc] = p
	}
	if p.published >= shortPerProcPerMin {
		if p.count == 0 {
			p.sample = c
		}
		p.add(c)
		fresh = !p.addrs[c.Remote.Addr()]
		p.addrs[c.Remote.Addr()] = true
		return false, fresh
	}
	p.published++
	g.groups[key] = &shortGroup{start: now, proc: proc, sample: c}
	return true, true
}

// flush returns the summaries of every window that has closed, and forgets
// those windows. A process that went over its cap gets one line for
// everything it was not shown — the overflow and the repeats of the
// addresses that did get a line — instead of one per address.
func (g *shortGrouper) flush(now time.Time) []shortSummary {
	var out []shortSummary
	for k, p := range g.procs {
		if now.Sub(p.start) < shortGroupWindow {
			continue
		}
		if p.count > 0 {
			for gk, grp := range g.groups {
				if grp.proc != k {
					continue
				}
				if grp.count > 0 {
					p.merge(grp.tally)
					p.addrs[grp.sample.Remote.Addr()] = true
				}
				delete(g.groups, gk)
			}
			out = append(out, shortSummary{Sample: p.sample, Count: p.count, Addrs: len(p.addrs), PerProc: true,
				Sent: p.sent, Recv: p.recv, HasBytes: p.hasBytes})
		}
		delete(g.procs, k)
	}
	for k, grp := range g.groups {
		if now.Sub(grp.start) < shortGroupWindow {
			continue
		}
		if grp.count > 0 {
			out = append(out, shortSummary{Sample: grp.sample, Count: grp.count,
				Sent: grp.sent, Recv: grp.recv, HasBytes: grp.hasBytes})
		}
		delete(g.groups, k)
	}
	return out
}

// briefDetail is the wording of a brief connection in the feed and the
// history: what it was, how long it lasted, how much it moved.
func briefDetail(T map[string]string, c briefConn) string {
	if c.Failed {
		return T["ev_short_failed"]
	}
	s := T["ev_short"]
	if c.Inbound {
		s = T["ev_short_in"]
	}
	s += fmt.Sprintf(" · %.1f s", c.Duration.Seconds())
	if c.HasBytes {
		s += " · ↑" + humanRate(float64(c.Sent)) + " ↓" + humanRate(float64(c.Recv))
	}
	return s
}

func summaryDetail(T map[string]string, s shortSummary) string {
	var text string
	switch {
	case s.PerProc && s.Sample.Inbound:
		text = fmt.Sprintf(T["ev_short_more_proc_in"], s.Count, s.Addrs)
	case s.PerProc:
		text = fmt.Sprintf(T["ev_short_more_proc"], s.Count, s.Addrs)
	case s.Sample.Failed:
		text = T["ev_short_failed"] + " · " + fmt.Sprintf(T["ev_short_more"], s.Count)
	default:
		text = fmt.Sprintf(T["ev_short_more"], s.Count)
	}
	if s.HasBytes {
		text += " · ↑" + humanRate(float64(s.Sent)) + " ↓" + humanRate(float64(s.Recv))
	}
	return text
}

// ── Switch and status ────────────────────────────────────────────────────────

// shortConnsEnabled is the operator's switch (SHORT_CONNS; default on). It is
// a kernel hook: it must be possible to turn it off without changing version.
// Read once at start-up — a change takes effect at the next start.
var shortConnsEnabled atomic.Bool

func init() { shortConnsEnabled.Store(true) }

func loadShortConns() { shortConnsEnabled.Store(os.Getenv("SHORT_CONNS") != "false") }

func setShortConns(on bool) {
	shortConnsEnabled.Store(on)
	writeEnv(map[string]string{"SHORT_CONNS": fmt.Sprintf("%t", on)})
}

// shortState is what the feature is doing right now: written at start-up and
// by the reader if it fails, read by the banner and by Settings.
var shortState struct {
	sync.Mutex
	code, detail string
}

func setShortConnStatus(code, detail string) {
	shortState.Lock()
	shortState.code, shortState.detail = code, detail
	shortState.Unlock()
}

// shortConnStatus returns the state as a code — "active", "root" (needs it),
// "ringbuf" (kernel too old), "refused" (detail says why), "off", "os" (not
// Linux), "stopped" (the reader failed, or nothing has started it) — and the
// detail that goes with it.
func shortConnStatus() (code, detail string) {
	shortState.Lock()
	defer shortState.Unlock()
	if shortState.code == "" {
		return "stopped", ""
	}
	return shortState.code, shortState.detail
}

// shortConnStatusText is the state in words, and whether it is working.
func shortConnStatusText(T map[string]string) (text string, active bool) {
	code, detail := shortConnStatus()
	text = T["short_st_"+code]
	if code == "refused" {
		text = fmt.Sprintf(text, detail)
	}
	return text, code == "active"
}

// tracepointLayout checks the kernel's description of the tracepoint
// sock:inet_sock_set_state (its `format` file) against the offsets the eBPF
// program reads. They belong to a stable interface, but a kernel that lays
// the record out differently must be refused, not read wrongly.
func tracepointLayout(format string) error {
	for _, field := range []string{
		"skaddr;\toffset:8;\tsize:8;", "oldstate;\toffset:16;\tsize:4;", "newstate;\toffset:20;\tsize:4;",
		"sport;\toffset:24;\tsize:2;", "dport;\toffset:26;\tsize:2;", "family;\toffset:28;\tsize:2;",
		"protocol;\toffset:30;\tsize:2;", "saddr[4];\toffset:32;\tsize:4;", "daddr[4];\toffset:36;\tsize:4;",
		"saddr_v6[16];\toffset:40;\tsize:16;", "daddr_v6[16];\toffset:56;\tsize:16;",
	} {
		if !strings.Contains(format, " "+field) {
			name, _, _ := strings.Cut(field, ";")
			return fmt.Errorf("tracepoint sock:inet_sock_set_state: field %s is not where the program expects it", name)
		}
	}
	return nil
}
