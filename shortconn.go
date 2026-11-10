package main

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
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
	inbound     bool
	established bool
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
type shortTracker struct {
	who       func(pid int32) (name, exe string)
	volume    bool // the kernel program reads byte counters
	flows     map[uint64]*flow
	listeners map[uint16][]listener // local port → who listens there, from the last poll
	lost      int                   // established flows dropped as invisible to the poll
}

func newShortTracker(who func(pid int32) (name, exe string), volume bool) *shortTracker {
	return &shortTracker{who: who, volume: volume, flows: map[uint64]*flow{}, listeners: map[uint16][]listener{}}
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
		// Resolved now: in a moment the process may be gone, and then the
		// kernel's own name for it is all there is.
		name, exe := t.who(pid)
		if name == "" || name == "N/A" {
			name = r.Comm
		}
		t.flows[r.Sock] = &flow{ts: r.TS, born: now, pid: pid, name: name, exe: exe, local: r.Local, remote: r.Remote}

	case recEstablished:
		if f := t.flows[r.Sock]; f != nil {
			f.established = true
		} else if r.Old == tcpSynRecv && trackable(r) {
			// An inbound connection has no start record: this is its first.
			t.flows[r.Sock] = &flow{ts: r.TS, born: now, inbound: true, established: true, local: r.Local, remote: r.Remote}
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
		c := briefConn{Inbound: f.inbound, Failed: !f.established, PID: f.pid, Name: f.name, Exe: f.exe,
			Local: f.local, Remote: f.remote, Duration: d}
		switch {
		case c.Failed:
			// Reported whatever it lasted: a connect that times out is never
			// established, so the poll never lists it.
		case d >= briefBound:
			t.lost++
			return briefConn{}, false
		default:
			c.Sent, c.Recv, c.HasBytes = r.Sent, r.Recv, t.volume
		}
		if c.Inbound {
			c.PID, c.Name, c.Exe = t.listenerOf(c.Local)
		}
		return c, true
	}
	return briefConn{}, false
}

// trackable: loopback is not the monitor's business, here as in the poll.
func trackable(r kernelRecord) bool {
	return r.Local.IsValid() && r.Remote.IsValid() && !r.Local.Addr().IsLoopback() && !r.Remote.Addr().IsLoopback()
}

// listenerOf is the process an inbound connection to local belongs to: the
// one listening on that port, preferring a listener bound to that very
// address, then a wildcard one.
func (t *shortTracker) listenerOf(local netip.AddrPort) (pid int32, name, exe string) {
	ls := t.listeners[local.Port()]
	if len(ls) == 0 {
		return 0, "N/A", ""
	}
	pick := ls[0]
	for _, l := range ls {
		if l.addr == local.Addr() {
			pick = l
			break
		}
		if l.addr.IsUnspecified() && !pick.addr.IsUnspecified() {
			pick = l
		}
	}
	name, exe = t.who(pick.pid)
	return pick.pid, name, exe
}

// polled is called with every poll's sockets. A flow the poll can see is no
// longer ours — it follows the ordinary path — and the listeners are whoever
// inbound connections will be attributed to.
func (t *shortTracker) polled(conns []gnet.ConnectionStat, now time.Time) {
	type pair struct{ local, remote netip.AddrPort }
	seen := map[pair]bool{}
	clear(t.listeners)
	for _, c := range conns {
		la, ok := addrPortOf(c.Laddr)
		if !ok {
			continue
		}
		if !isUDP(c) && c.Status == "LISTEN" && c.Pid > 0 {
			t.listeners[la.Port()] = append(t.listeners[la.Port()], listener{la.Addr(), c.Pid})
			continue
		}
		if ra, ok := addrPortOf(c.Raddr); ok && hasPeer(c) {
			seen[pair{la, ra}] = true
		}
	}
	for sock, f := range t.flows {
		age := now.Sub(f.born)
		switch {
		case seen[pair{f.local, f.remote}]:
			delete(t.flows, sock)
		case f.established && age >= briefBound:
			// Established, older than two polls and never listed: not brief,
			// invisible (another network namespace).
			t.lost++
			delete(t.flows, sock)
		case age >= flowMaxAge:
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
