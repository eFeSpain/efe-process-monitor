package main

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
)

// rec builds a kernel record with its timestamp in milliseconds.
func rec(kind, old uint8, sock, tsMillis uint64, pid uint32, local, remote string) kernelRecord {
	return kernelRecord{TS: tsMillis * 1_000_000, Sock: sock, PID: pid, Kind: kind, Old: old,
		Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote)}
}

// encode is the inverse of decodeKernelRecord: what the kernel program
// writes. family 2 uses the 4-byte address slots, 10 the 16-byte ones.
func encode(r kernelRecord, family uint16) []byte {
	b := make([]byte, kernelRecordSize)
	ne := binary.NativeEndian
	ne.PutUint64(b[0:], r.TS)
	ne.PutUint64(b[8:], r.Sock)
	ne.PutUint32(b[16:], r.PID)
	ne.PutUint32(b[20:], r.UID)
	b[24], b[25] = r.Kind, r.Old
	ne.PutUint16(b[26:], family)
	ne.PutUint16(b[28:], r.Local.Port())
	ne.PutUint16(b[30:], r.Remote.Port())
	if family == 2 {
		l, rm := r.Local.Addr().As4(), r.Remote.Addr().As4()
		copy(b[32:36], l[:])
		copy(b[36:40], rm[:])
	} else {
		l, rm := r.Local.Addr().As16(), r.Remote.Addr().As16()
		copy(b[40:56], l[:])
		copy(b[56:72], rm[:])
	}
	copy(b[72:88], r.Comm)
	ne.PutUint64(b[88:], r.Sent)
	ne.PutUint64(b[96:], r.Recv)
	return b
}

// hostHas stands in for the machine's interface addresses.
func hostHas(ips ...string) func() []netip.Addr {
	return func() []netip.Addr {
		var out []netip.Addr
		for _, ip := range ips {
			out = append(out, netip.MustParseAddr(ip))
		}
		return out
	}
}

func testWho(pid int32) (string, string) {
	switch pid {
	case 100:
		return "curl", "/usr/bin/curl"
	case 200:
		return "sshd", "/usr/sbin/sshd"
	case 300:
		return "nginx", "/usr/sbin/nginx"
	}
	return "N/A", ""
}

func tcpEst(pid int32, lip string, lport uint32, rip string, rport uint32) gnet.ConnectionStat {
	return gnet.ConnectionStat{Pid: pid, Type: uint32(syscall.SOCK_STREAM), Status: "ESTABLISHED",
		Laddr: gnet.Addr{IP: lip, Port: lport}, Raddr: gnet.Addr{IP: rip, Port: rport}}
}

const (
	cliAddr = "192.168.1.24:50000"
	srvAddr = "203.0.113.9:443"
)

// feed runs records through a tracker and returns what it reported.
func feed(t *shortTracker, now time.Time, recs ...kernelRecord) []briefConn {
	var out []briefConn
	for _, r := range recs {
		if c, ok := t.record(r, now); ok {
			out = append(out, c)
		}
	}
	return out
}

func TestDecodeKernelRecord(t *testing.T) {
	v4 := rec(recStart, 7, 0xffff888012345678, 1500, 100, cliAddr, srvAddr)
	v4.UID, v4.Comm = 1000, "curl"
	got, ok := decodeKernelRecord(encode(v4, 2))
	if !ok || got != v4 {
		t.Errorf("IPv4 start: ok=%v\n got %+v\nwant %+v", ok, got, v4)
	}

	v6 := rec(recClosed, 1, 9, 2000, 0, "[2001:db8::24]:50001", "[2001:db8::9]:443")
	v6.Sent, v6.Recv = 38_000_000, 1024
	got, ok = decodeKernelRecord(encode(v6, 10))
	if !ok || got != v6 {
		t.Errorf("IPv6 closed: ok=%v\n got %+v\nwant %+v", ok, got, v6)
	}

	// An AF_INET6 socket talking to an IPv4 peer carries a mapped address;
	// it must compare equal to what the poll reports.
	mapped := rec(recEstablished, tcpSynSent, 9, 0, 0, "[::ffff:192.168.1.24]:50000", "[::ffff:203.0.113.9]:443")
	got, ok = decodeKernelRecord(encode(mapped, 10))
	if !ok || got.Remote != netip.MustParseAddrPort(srvAddr) || got.Local != netip.MustParseAddrPort(cliAddr) {
		t.Errorf("mapped addresses must be unmapped: %+v", got)
	}

	// A record of the wrong size or of an unknown family is not a record:
	// nothing panics, nothing is tracked.
	b := encode(v4, 2)
	if _, ok := decodeKernelRecord(b[:kernelRecordSize-1]); ok {
		t.Error("a short record was accepted")
	}
	if _, ok := decodeKernelRecord(append(append([]byte{}, b...), 0)); ok {
		t.Error("a long record was accepted")
	}
	if _, ok := decodeKernelRecord(nil); ok {
		t.Error("an empty record was accepted")
	}
	if _, ok := decodeKernelRecord(encode(v4, 99)); ok {
		t.Error("an unknown address family was accepted")
	}
}

// A connection that opens and closes without any poll having seen it is
// brief: reported once, at its close, with who made it and how long it lasted.
func TestTrackerBrief(t *testing.T) {
	tr := newShortTracker(testWho, false)
	now := time.Now()
	if got := feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 20, 0, cliAddr, srvAddr)); len(got) != 0 {
		t.Fatalf("reported before the close: %+v", got)
	}
	got := feed(tr, now, rec(recClosed, tcpEstablished, 1, 200, 0, cliAddr, srvAddr))
	if len(got) != 1 {
		t.Fatalf("want one brief connection, got %+v", got)
	}
	c := got[0]
	if c.Inbound || c.Failed || c.PID != 100 || c.Name != "curl" || c.Exe != "/usr/bin/curl" ||
		c.Duration != 200*time.Millisecond || c.Remote.String() != srvAddr || c.Local.String() != cliAddr || c.HasBytes {
		t.Errorf("brief connection: %+v", c)
	}
	if len(tr.flows) != 0 {
		t.Errorf("the flow must be forgotten once reported: %d left", len(tr.flows))
	}
}

// The poll has it: it follows the ordinary path and is not reported twice.
func TestTrackerSeenByPoll(t *testing.T) {
	for name, remoteIP := range map[string]string{"plain": "203.0.113.9", "mapped": "::ffff:203.0.113.9"} {
		tr := newShortTracker(testWho, false)
		now := time.Now()
		feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 20, 0, cliAddr, srvAddr))
		tr.polled([]gnet.ConnectionStat{tcpEst(100, "192.168.1.24", 50000, remoteIP, 443)}, now.Add(time.Second))
		if got := feed(tr, now, rec(recClosed, tcpEstablished, 1, 1500, 0, cliAddr, srvAddr)); len(got) != 0 {
			t.Errorf("%s: a polled connection was reported as brief: %+v", name, got)
		}
	}
}

// A connect that never completes — refused at once, or timed out after the
// kernel's retries — is an attempt, reported whatever it lasted: the poll
// only lists established sockets and never sees it.
func TestTrackerFailedAttempt(t *testing.T) {
	for _, ms := range []uint64{300, 130_000} {
		tr := newShortTracker(testWho, true)
		now := time.Now()
		got := feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recClosed, tcpSynSent, 1, ms, 0, cliAddr, srvAddr))
		if len(got) != 1 || !got[0].Failed || got[0].Name != "curl" || got[0].HasBytes {
			t.Errorf("attempt of %d ms: %+v", ms, got)
		}
	}
}

// An established connection the poll never saw and that lasted longer than
// two poll intervals is not brief: it is one the poll cannot see at all (a
// socket in another network namespace). It is dropped, and counted.
func TestTrackerBound(t *testing.T) {
	run := func(closeMs uint64) []briefConn {
		tr := newShortTracker(testWho, false)
		return feed(tr, time.Now(), rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr),
			rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr), rec(recClosed, tcpEstablished, 1, closeMs, 0, cliAddr, srvAddr))
	}
	if got := run(5900); len(got) != 1 {
		t.Errorf("5.9 s is brief: %+v", got)
	}
	if got := run(6100); len(got) != 0 {
		t.Errorf("6.1 s is not brief: %+v", got)
	}

	tr := newShortTracker(testWho, false)
	now := time.Now()
	feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr))
	tr.polled(nil, now.Add(7*time.Second))
	if n := tr.dropped(); n != 1 {
		t.Errorf("dropped() = %d, want 1", n)
	}
	if n := tr.dropped(); n != 0 {
		t.Errorf("dropped() must reset: %d", n)
	}
	if got := feed(tr, now, rec(recClosed, tcpEstablished, 1, 3_600_000, 0, cliAddr, srvAddr)); len(got) != 0 {
		t.Errorf("an hour-long invisible connection reported as brief: %+v", got)
	}
	// An attempt still in progress is not dropped at 6 s.
	feed(tr, now, rec(recStart, 7, 2, 0, 100, cliAddr, srvAddr))
	tr.polled(nil, now.Add(7*time.Second))
	if len(tr.flows) != 1 {
		t.Error("a connect still in progress must be kept until it closes")
	}
}

// Inbound connections have no process of their own in the kernel record:
// they belong to whoever listens on the local port.
func TestTrackerInbound(t *testing.T) {
	const local, peer = "192.168.1.24:22", "192.168.1.50:51000"
	inbound := func(tr *shortTracker) []briefConn {
		return feed(tr, time.Now(), rec(recEstablished, tcpSynRecv, 5, 1000, 0, local, peer), rec(recClosed, tcpEstablished, 5, 1400, 0, local, peer))
	}

	tr := newShortTracker(testWho, false)
	tr.hostAddrs = hostHas("192.168.1.24")
	tr.polled([]gnet.ConnectionStat{tcpListen(200, "0.0.0.0", 22)}, time.Now())
	got := inbound(tr)
	if len(got) != 1 || !got[0].Inbound || got[0].PID != 200 || got[0].Name != "sshd" || got[0].Exe != "/usr/sbin/sshd" ||
		got[0].Duration != 400*time.Millisecond || got[0].Local.String() != local || got[0].Remote.String() != peer {
		t.Errorf("inbound: %+v", got)
	}

	tr = newShortTracker(testWho, false)
	got = inbound(tr)
	if len(got) != 1 || got[0].PID != 0 || got[0].Name != "N/A" {
		t.Errorf("no known listener: %+v", got)
	}

	tr = newShortTracker(testWho, false)
	tr.polled([]gnet.ConnectionStat{tcpListen(300, "10.0.0.1", 22), tcpListen(200, "192.168.1.24", 22)}, time.Now())
	if got = inbound(tr); len(got) != 1 || got[0].PID != 200 {
		t.Errorf("the listener bound to the local address must win: %+v", got)
	}
}

func TestTrackerDiscards(t *testing.T) {
	tr := newShortTracker(testWho, false)
	got := feed(tr, time.Now(),
		rec(recStart, 7, 1, 0, uint32(ownPID), cliAddr, srvAddr),                    // the monitor's own traffic
		rec(recStart, 7, 2, 0, 100, "127.0.0.1:40000", "127.0.0.1:5000"),            // loopback
		rec(recStart, 7, 3, 0, 100, "[::1]:40000", "[::1]:5000"),                    // loopback, v6
		rec(recEstablished, tcpSynSent, 4, 0, 0, cliAddr, srvAddr),                  // its start was never seen
		rec(recEstablished, tcpSynRecv, 6, 0, 0, "127.0.0.1:22", "127.0.0.1:51000"), // inbound over loopback
		rec(recClosed, tcpEstablished, 99, 0, 0, cliAddr, srvAddr),                  // unknown socket
		rec(recClosed, 10, 1, 5, 0, cliAddr, srvAddr), rec(recClosed, 10, 2, 5, 0, cliAddr, srvAddr),
	)
	if len(got) != 0 || len(tr.flows) != 0 {
		t.Errorf("reported %+v, %d flows left", got, len(tr.flows))
	}
}

// The process was gone before its path could be read: the name the kernel
// took at connect() is what is left.
func TestTrackerProcessGone(t *testing.T) {
	tr := newShortTracker(testWho, false)
	start := rec(recStart, 7, 1, 0, 999, cliAddr, srvAddr)
	start.Comm = "x"
	got := feed(tr, time.Now(), start, rec(recClosed, tcpSynSent, 1, 3, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Name != "x" || got[0].Exe != "" || got[0].PID != 999 {
		t.Errorf("%+v", got)
	}
}

// The kernel reuses a socket's address as soon as it is freed. If the close
// of the previous connection was lost, the new start replaces the old flow.
func TestTrackerSocketReuse(t *testing.T) {
	tr := newShortTracker(testWho, false)
	got := feed(tr, time.Now(),
		rec(recStart, 7, 7, 0, 100, cliAddr, srvAddr),
		rec(recStart, 7, 7, 1000, 100, "192.168.1.24:50001", "198.51.100.4:80"),
		rec(recEstablished, tcpSynSent, 7, 1010, 0, "192.168.1.24:50001", "198.51.100.4:80"),
		rec(recClosed, tcpEstablished, 7, 1100, 0, "192.168.1.24:50001", "198.51.100.4:80"))
	if len(got) != 1 || got[0].Remote.String() != "198.51.100.4:80" || got[0].Duration != 100*time.Millisecond {
		t.Errorf("%+v", got)
	}
}

// Records from two CPUs can arrive out of order. A close stamped before its
// start is a connection of no measurable length, not a negative one.
func TestTrackerOutOfOrder(t *testing.T) {
	tr := newShortTracker(testWho, false)
	got := feed(tr, time.Now(), rec(recStart, 7, 1, 500, 100, cliAddr, srvAddr),
		rec(recEstablished, tcpSynSent, 1, 510, 0, cliAddr, srvAddr), rec(recClosed, tcpEstablished, 1, 400, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Duration != 0 {
		t.Errorf("%+v", got)
	}
}

// A flow whose close never arrives (the record was lost) is forgotten.
func TestTrackerPrune(t *testing.T) {
	tr := newShortTracker(testWho, false)
	t0 := time.Now()
	feed(tr, t0, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr))
	tr.polled(nil, t0.Add(flowMaxAge-time.Second))
	if len(tr.flows) != 1 {
		t.Fatal("pruned too early")
	}
	tr.polled(nil, t0.Add(flowMaxAge+time.Second))
	if len(tr.flows) != 0 {
		t.Error("a flow older than flowMaxAge must be forgotten")
	}
}

// Volume is reported only when the kernel program reads it, and never for an
// attempt that moved nothing.
func TestTrackerVolume(t *testing.T) {
	tr := newShortTracker(testWho, true)
	closed := rec(recClosed, tcpEstablished, 1, 200, 0, cliAddr, srvAddr)
	// The kernel counts in sequence space, where our SYN and FIN take one
	// number each on the way out and the peer's FIN one on the way in.
	closed.Sent, closed.Recv = 38_000_002, 1025
	got := feed(tr, time.Now(), rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr), closed)
	if len(got) != 1 || !got[0].HasBytes || got[0].Sent != 38_000_000 || got[0].Recv != 1024 {
		t.Errorf("%+v", got)
	}
	// A connection that carried nothing says nothing, not "1 B" (seen on the
	// real machine: a handshake and a close, shown as ↑1 B).
	for _, raw := range [][2]uint64{{1, 0}, {2, 1}, {0, 0}} {
		closed.Sock, closed.Sent, closed.Recv = 2, raw[0], raw[1]
		got = feed(tr, time.Now(), rec(recStart, 7, 2, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 2, 10, 0, cliAddr, srvAddr), closed)
		if len(got) != 1 || got[0].Sent != 0 || got[0].Recv != 0 {
			t.Errorf("raw counters %v: %+v", raw, got)
		}
	}
}

// groupAdd is add() for the tests that only care whether a line is published.
func groupAdd(g *shortGrouper, c briefConn, now time.Time) bool {
	publish, _ := g.add(c, now)
	return publish
}

func brief(name, exe, remote string) briefConn {
	return briefConn{PID: 100, Name: name, Exe: exe, Local: netip.MustParseAddrPort(cliAddr),
		Remote: netip.MustParseAddrPort(remote), Duration: 200 * time.Millisecond}
}

// The first connection of a kind is shown at once; repeats within the window
// are counted and summarised in one line when it closes.
func TestGrouperFirstThenCounted(t *testing.T) {
	g := newShortGrouper()
	t0 := time.Now()
	c := brief("curl", "/usr/bin/curl", srvAddr)
	for i, want := range []bool{true, false, false} {
		if got := groupAdd(g, c, t0.Add(time.Duration(i)*time.Second)); got != want {
			t.Errorf("add #%d = %v, want %v", i+1, got, want)
		}
	}
	// Each of these is a group of its own.
	other := brief("curl", "/usr/bin/curl", "198.51.100.4:443")
	otherProc := brief("wget", "/usr/bin/wget", srvAddr)
	in := c
	in.Inbound = true
	for name, x := range map[string]briefConn{"another address": other, "another process": otherProc, "the other direction": in} {
		if !groupAdd(g, x, t0.Add(3*time.Second)) {
			t.Errorf("%s must start its own group", name)
		}
	}
	// Another port of the same address is the same group.
	if groupAdd(g, brief("curl", "/usr/bin/curl", "203.0.113.9:8443"), t0.Add(4*time.Second)) {
		t.Error("another port of the same remote address is the same group")
	}

	if got := g.flush(t0.Add(59 * time.Second)); len(got) != 0 {
		t.Errorf("flushed before the window closed: %+v", got)
	}
	got := g.flush(t0.Add(shortGroupWindow + 4*time.Second))
	if len(got) != 1 || got[0].Count != 3 || got[0].PerProc || got[0].Sample.Remote.String() != srvAddr {
		t.Errorf("want one summary of 3 repeats (groups with only their first say nothing): %+v", got)
	}
	if len(g.groups) != 0 || len(g.procs) != 0 {
		t.Errorf("state left after the flush: %d groups, %d procs", len(g.groups), len(g.procs))
	}
	// After the window, the same connection is news again.
	if !groupAdd(g, c, t0.Add(2*shortGroupWindow)) {
		t.Error("a new window must publish its first connection")
	}
}

func TestGrouperInboundKey(t *testing.T) {
	g := newShortGrouper()
	t0 := time.Now()
	in := func(local, remote string) briefConn {
		return briefConn{Inbound: true, PID: 200, Name: "sshd", Exe: "/usr/sbin/sshd",
			Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote)}
	}
	if !groupAdd(g, in("192.168.1.24:22", "192.168.1.50:51000"), t0) {
		t.Fatal("first inbound")
	}
	if groupAdd(g, in("192.168.1.24:22", "192.168.1.50:51001"), t0) {
		t.Error("the same peer to the same local port, from another source port, is the same group")
	}
	if !groupAdd(g, in("192.168.1.24:80", "192.168.1.50:51002"), t0) {
		t.Error("the same peer to another local port is another group")
	}
}

// One process, ten thousand brief connections to five thousand addresses in
// a second (a scanner, a torrent client): the feed gets twenty lines and a
// summary, and the grouper keeps nothing afterwards.
func TestGrouperBurst(t *testing.T) {
	g := newShortGrouper()
	t0 := time.Now()
	published := 0
	for i := 0; i < 5000; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		c := briefConn{PID: 100, Name: "nmap", Exe: "/usr/bin/nmap", Remote: netip.AddrPortFrom(ip, 443)}
		for j := 0; j < 2; j++ {
			if groupAdd(g, c, t0.Add(time.Duration(i)*100*time.Microsecond)) {
				published++
			}
		}
	}
	if published != shortPerProcPerMin {
		t.Errorf("published %d individually, want %d", published, shortPerProcPerMin)
	}
	// One line says it all: the repeats of the twenty published addresses are
	// folded into the process's summary instead of twenty "×1 more" lines.
	sums := g.flush(t0.Add(shortGroupWindow + time.Second))
	if len(sums) != 1 || !sums[0].PerProc || sums[0].Count != 9980 || sums[0].Addrs != 5000 || sums[0].Sample.Name != "nmap" {
		t.Errorf("want one per-process summary of 9980 connections to 5000 addresses: %+v", sums)
	}
	if len(g.groups) != 0 || len(g.procs) != 0 {
		t.Errorf("state left after the flush: %d groups, %d procs", len(g.groups), len(g.procs))
	}
}

func TestBriefDetail(t *testing.T) {
	T := strings_("es")
	for _, c := range []struct {
		conn briefConn
		want string
	}{
		{briefConn{Duration: 200 * time.Millisecond, HasBytes: true, Sent: 38 << 20, Recv: 1024}, "conexión breve · 0.2 s · ↑38 MB ↓1 KB"},
		{briefConn{Duration: 2400 * time.Millisecond}, "conexión breve · 2.4 s"},
		{briefConn{Duration: 0}, "conexión breve · 0.0 s"},
		{briefConn{Failed: true, Duration: 130 * time.Second}, "intento no establecido"},
		{briefConn{Inbound: true, Duration: 400 * time.Millisecond}, "entrante breve · 0.4 s"},
		{briefConn{Inbound: true, Duration: time.Second, HasBytes: true}, "entrante breve · 1.0 s · ↑0 B ↓0 B"},
	} {
		if got := briefDetail(T, c.conn); got != c.want {
			t.Errorf("briefDetail(%+v) = %q, want %q", c.conn, got, c.want)
		}
	}
	if got := briefDetail(strings_("en"), briefConn{Failed: true}); got != "attempt not established" {
		t.Errorf("en: %q", got)
	}
}

func TestSummaryDetail(t *testing.T) {
	T := strings_("es")
	if got := summaryDetail(T, shortSummary{Count: 14}); got != "×14 más en 60 s" {
		t.Errorf("%q", got)
	}
	if got := summaryDetail(T, shortSummary{PerProc: true, Count: 230, Addrs: 61}); got != "×230 conexiones breves más a 61 direcciones" {
		t.Errorf("%q", got)
	}
}

// Found against the real kernel: when a start record is written the local
// port has not been chosen yet (the kernel binds it after the state change).
// The flow's local endpoint is whatever a later record says.
func TestTrackerLocalPortArrivesLater(t *testing.T) {
	const unbound = "192.168.1.24:0"
	now := time.Now()

	tr := newShortTracker(testWho, false)
	got := feed(tr, now, rec(recStart, 7, 1, 0, 100, unbound, srvAddr),
		rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr), rec(recClosed, tcpEstablished, 1, 200, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Local.String() != cliAddr {
		t.Errorf("brief: local %v, want %s", got, cliAddr)
	}

	// The poll must still recognise it as its own.
	tr = newShortTracker(testWho, false)
	feed(tr, now, rec(recStart, 7, 1, 0, 100, unbound, srvAddr), rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr))
	tr.polled([]gnet.ConnectionStat{tcpEst(100, "192.168.1.24", 50000, "203.0.113.9", 443)}, now.Add(time.Second))
	if len(tr.flows) != 0 {
		t.Error("a polled connection whose start had no local port yet was not recognised")
	}

	// A failed attempt is never established: its close carries the port.
	tr = newShortTracker(testWho, false)
	got = feed(tr, now, rec(recStart, 7, 1, 0, 100, unbound, srvAddr), rec(recClosed, tcpSynSent, 1, 5, 0, cliAddr, srvAddr))
	if len(got) != 1 || !got[0].Failed || got[0].Local.String() != cliAddr {
		t.Errorf("failed attempt: %+v", got)
	}
}

func withShortConnsState(t *testing.T) {
	t.Helper()
	oldOn := shortConnsEnabled.Load()
	oldCode, oldDetail := shortConnStatus()
	t.Cleanup(func() { shortConnsEnabled.Store(oldOn); setShortConnStatus(oldCode, oldDetail) })
}

// On by default; SHORT_CONNS=false turns it off; Settings persists the choice.
func TestShortConnsSwitch(t *testing.T) {
	withTempEnv(t)
	withShortConnsState(t)
	t.Setenv("SHORT_CONNS", "")
	loadShortConns()
	if !shortConnsEnabled.Load() {
		t.Error("brief-connection detection is on unless switched off")
	}
	t.Setenv("SHORT_CONNS", "false")
	loadShortConns()
	if shortConnsEnabled.Load() {
		t.Error("SHORT_CONNS=false must switch it off")
	}

	var out map[string]any
	json.Unmarshal(jsonPost(handleSettings, "/api/settings", `{"ShortConns":true}`).Body.Bytes(), &out)
	if out["short_conns"] != true || out["short_conns_status"] == nil || out["short_conns_status"] == "" {
		t.Errorf("switching on: %v / %v", out["short_conns"], out["short_conns_status"])
	}
	out = map[string]any{}
	json.Unmarshal(jsonPost(handleSettings, "/api/settings", `{}`).Body.Bytes(), &out)
	if out["short_conns"] != true {
		t.Error("a settings save that does not mention it must leave it alone")
	}
	out = map[string]any{}
	json.Unmarshal(jsonPost(handleSettings, "/api/settings", `{"ShortConns":false}`).Body.Bytes(), &out)
	env, _ := os.ReadFile(envPath)
	if out["short_conns"] != false || !strings.Contains(string(env), "SHORT_CONNS=false") {
		t.Errorf("switching off: %v, .env:\n%s", out["short_conns"], env)
	}
}

// Without what it needs the feature is simply absent: no channel, and a
// status that says why. Off is checked before privileges.
func TestStartShortConnsInactive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root on Linux it would really start")
	}
	withShortConnsState(t)
	shortConnsEnabled.Store(true)
	ch, volume := startShortConns()
	if ch != nil || volume {
		t.Errorf("startShortConns without privileges returned a channel (%v) or volume (%v)", ch != nil, volume)
	}
	want := "os"
	if runtime.GOOS == "linux" {
		want = "root"
	}
	if code, _ := shortConnStatus(); code != want {
		t.Errorf("status %q, want %q", code, want)
	}
	if text, active := shortConnStatusText(strings_("es")); active || text != strings_("es")["short_st_"+want] {
		t.Errorf("status text %q active=%v", text, active)
	}

	shortConnsEnabled.Store(false)
	if ch, _ := startShortConns(); ch != nil {
		t.Error("switched off, it must not start")
	}
	if code, _ := shortConnStatus(); runtime.GOOS == "linux" && code != "off" {
		t.Errorf("switched off: status %q, want off", code)
	}
}

func TestShortConnStatusTexts(t *testing.T) {
	withShortConnsState(t)
	for _, lang := range []string{"es", "en", "zh"} {
		T := strings_(lang)
		for _, code := range []string{"active", "root", "ringbuf", "refused", "off", "os", "stopped"} {
			setShortConnStatus(code, "boom")
			text, active := shortConnStatusText(T)
			if text == "" || active != (code == "active") {
				t.Errorf("%s/%s: text %q active %v", lang, code, text, active)
			}
			if code == "refused" && !strings.Contains(text, "boom") {
				t.Errorf("%s: the kernel's reason is missing from %q", lang, text)
			}
			if strings.Contains(text, "%!") {
				t.Errorf("%s/%s: bad format: %q", lang, code, text)
			}
		}
	}
}

func tcpState(pid int32, status, lip string, lport uint32, rip string, rport uint32) gnet.ConnectionStat {
	c := tcpEst(pid, lip, lport, rip, rport)
	c.Status = status
	return c
}

// Review I1: the poll only follows ESTABLISHED sockets. One it lists in a
// closing state was never announced by it, so the tracker must not take it
// for "the poll has it" — neither source would report the connection. And a
// socket the poll lists at all is in this network namespace: the 6 s rule
// (for sockets the poll cannot see) does not apply to it.
func TestTrackerHalfClosedIsReported(t *testing.T) {
	for _, state := range []string{"CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"} {
		tr := newShortTracker(testWho, false)
		now := time.Now()
		feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr))
		row := []gnet.ConnectionStat{tcpState(100, state, "192.168.1.24", 50000, "203.0.113.9", 443)}
		tr.polled(row, now.Add(time.Second))
		tr.polled(row, now.Add(10*time.Second))
		if len(tr.flows) != 1 || tr.dropped() != 0 {
			t.Fatalf("%s: a socket the poll lists only while closing must stay with the tracker", state)
		}
		got := feed(tr, now, rec(recClosed, 8, 1, 20_000, 0, cliAddr, srvAddr))
		if len(got) != 1 || got[0].Failed || got[0].Duration != 20*time.Second {
			t.Errorf("%s: want it reported at its close with its real duration: %+v", state, got)
		}
	}
}

// Review I1: the 6 s that separate "brief" from "invisible to the poll" run
// from the moment the connection is established. A handshake that needed
// SYN retransmissions — which the remote end controls — must not make a
// short exchange disappear.
func TestTrackerSlowHandshake(t *testing.T) {
	tr := newShortTracker(testWho, false)
	now := time.Now()
	feed(tr, now, rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr))
	tr.polled(nil, now.Add(7*time.Second)) // still connecting
	got := feed(tr, now.Add(7*time.Second), rec(recEstablished, tcpSynSent, 1, 7000, 0, cliAddr, srvAddr),
		rec(recClosed, tcpEstablished, 1, 7500, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Failed || got[0].Duration != 7500*time.Millisecond {
		t.Errorf("7 s of handshake and 0.5 s of connection is a brief connection: %+v", got)
	}
	if tr.dropped() != 0 {
		t.Error("it was counted as invisible to the poll")
	}
}

// Review I4: after a lost close, an inbound connection landing on the same
// socket address must not inherit the old flow's process and direction.
func TestTrackerInboundReplacesStaleFlow(t *testing.T) {
	const local, peer = "192.168.1.24:22", "198.51.100.7:51000"
	tr := newShortTracker(testWho, false)
	tr.hostAddrs = hostHas("192.168.1.24")
	now := time.Now()
	tr.polled([]gnet.ConnectionStat{tcpListen(200, "0.0.0.0", 22)}, now)
	got := feed(tr, now, rec(recStart, 7, 7, 0, 100, cliAddr, srvAddr), // curl's connection; its close is lost
		rec(recEstablished, tcpSynRecv, 7, 1000, 0, local, peer),
		rec(recClosed, tcpEstablished, 7, 1400, 0, local, peer))
	if len(got) != 1 || !got[0].Inbound || got[0].PID != 200 || got[0].Name != "sshd" ||
		got[0].Local.String() != local || got[0].Remote.String() != peer || got[0].Duration != 400*time.Millisecond {
		t.Errorf("want sshd ← %s, got %+v", peer, got)
	}
}

// Review I4: a lost "established" must not turn a connection that worked
// into a failed attempt. A socket only closes from SYN_SENT when the connect
// never completed.
func TestTrackerLostEstablished(t *testing.T) {
	tr := newShortTracker(testWho, true)
	closed := rec(recClosed, 4 /* FIN_WAIT1 */, 1, 300, 0, cliAddr, srvAddr)
	closed.Sent, closed.Recv = 1002, 501
	got := feed(tr, time.Now(), rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), closed)
	if len(got) != 1 || got[0].Failed || !got[0].HasBytes || got[0].Sent != 1000 || got[0].Recv != 500 || got[0].Local.String() != cliAddr {
		t.Errorf("want a brief connection with its bytes, got %+v", got)
	}
}

// Review I5: an inbound connection is attributed to a listener on the same
// address, or to a wildcard listener when the address is this machine's.
// A wildcard listener on the host does not own a connection to a container's
// address; and connections to the monitor's own dashboard are not reported.
func TestTrackerInboundAttribution(t *testing.T) {
	inbound := func(tr *shortTracker, local string) []briefConn {
		return feed(tr, time.Now(), rec(recEstablished, tcpSynRecv, 5, 1000, 0, local, "198.51.100.7:51000"),
			rec(recClosed, tcpEstablished, 5, 1400, 0, local, "198.51.100.7:51000"))
	}
	tr := newShortTracker(testWho, false)
	tr.hostAddrs = hostHas("192.168.1.24")
	tr.polled([]gnet.ConnectionStat{tcpListen(300, "0.0.0.0", 80), tcpListen(200, "10.0.0.1", 22)}, time.Now())

	if got := inbound(tr, "172.17.0.2:80"); len(got) != 1 || got[0].PID != 0 || got[0].Name != "N/A" {
		t.Errorf("a container's address: the host's wildcard listener must not be named: %+v", got)
	}
	if got := inbound(tr, "192.168.1.24:80"); len(got) != 1 || got[0].PID != 300 {
		t.Errorf("the host's own address: the wildcard listener owns it: %+v", got)
	}
	if got := inbound(tr, "192.168.1.24:22"); len(got) != 1 || got[0].PID != 0 {
		t.Errorf("a listener bound to another address must not be named: %+v", got)
	}

	tr.polled([]gnet.ConnectionStat{tcpListen(ownPID, "0.0.0.0", 5000)}, time.Now())
	if got := inbound(tr, "192.168.1.24:5000"); len(got) != 0 {
		t.Errorf("connections to the monitor's own dashboard are its own traffic: %+v", got)
	}
}

// Review I2: the grouper also says whether this is the first connection of
// the window to that address from that process — past the per-process cap
// nothing is shown, but a new address still has to be looked up.
func TestGrouperFreshAddress(t *testing.T) {
	g := newShortGrouper()
	t0 := time.Now()
	addr := func(i int) briefConn {
		return briefConn{PID: 100, Name: "x", Exe: "/usr/bin/x", Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}), 443)}
	}
	if publish, fresh := g.add(addr(0), t0); !publish || !fresh {
		t.Errorf("first: publish=%v fresh=%v", publish, fresh)
	}
	if publish, fresh := g.add(addr(0), t0); publish || fresh {
		t.Errorf("repeat: publish=%v fresh=%v", publish, fresh)
	}
	for i := 1; i < shortPerProcPerMin; i++ {
		g.add(addr(i), t0)
	}
	if publish, fresh := g.add(addr(100), t0); publish || !fresh {
		t.Errorf("past the cap, a new address: publish=%v fresh=%v, want not shown but fresh", publish, fresh)
	}
	if publish, fresh := g.add(addr(100), t0); publish || fresh {
		t.Errorf("past the cap, the same address again: publish=%v fresh=%v", publish, fresh)
	}
}

// Review minor: a connection established just before the poll reads the
// socket table is announced by the poll; its kernel records are processed
// after that poll, when the tracker no longer has a flow to drop. It must
// not be announced a second time as brief.
func TestTrackerPolledJustBefore(t *testing.T) {
	tr := newShortTracker(testWho, false)
	now := time.Now()
	tr.polled([]gnet.ConnectionStat{tcpEst(100, "192.168.1.24", 50000, "203.0.113.9", 443)}, now)
	got := feed(tr, now, rec(recStart, 7, 1, 0, 100, "192.168.1.24:0", srvAddr),
		rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr), rec(recClosed, tcpEstablished, 1, 900, 0, cliAddr, srvAddr))
	if len(got) != 0 || len(tr.flows) != 0 {
		t.Errorf("announced by the poll and again as brief: %+v (%d flows)", got, len(tr.flows))
	}
	// The next poll no longer lists it: a later connection on other ports is
	// news again.
	tr.polled(nil, now.Add(3*time.Second))
	got = feed(tr, now, rec(recStart, 7, 2, 4000, 100, "192.168.1.24:0", srvAddr),
		rec(recEstablished, tcpSynSent, 2, 4010, 0, "192.168.1.24:50001", srvAddr), rec(recClosed, tcpEstablished, 2, 4200, 0, "192.168.1.24:50001", srvAddr))
	if len(got) != 1 {
		t.Errorf("a later brief connection must be reported: %+v", got)
	}
}

// Review minor: the reader resolves who the process is the moment the record
// arrives; the tracker runs on the monitor goroutine, which may be busy with
// a poll pass while a short-lived process exits. What the reader found wins.
func TestTrackerUsesReaderResolvedProcess(t *testing.T) {
	tr := newShortTracker(func(int32) (string, string) { return "N/A", "" }, false) // gone by now
	start := rec(recStart, 7, 1, 0, 4242, cliAddr, srvAddr)
	start.Comm, start.Name, start.Exe = "dropper", "dropper", "/tmp/.x/dropper"
	got := feed(tr, time.Now(), start, rec(recClosed, tcpSynSent, 1, 3, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Name != "dropper" || got[0].Exe != "/tmp/.x/dropper" {
		t.Errorf("%+v", got)
	}
	// The reader looked and the process was already gone: the kernel's name.
	start.Sock, start.Name, start.Exe = 2, "N/A", ""
	got = feed(tr, time.Now(), start, rec(recClosed, tcpSynSent, 2, 3, 0, cliAddr, srvAddr))
	if len(got) != 1 || got[0].Name != "dropper" || got[0].Exe != "" {
		t.Errorf("%+v", got)
	}
}

// Review minor: loopback records are discarded by the reader, before they
// take room in the channel the monitor reads.
func TestLoopbackRecord(t *testing.T) {
	for r, want := range map[kernelRecord]bool{
		rec(recStart, 7, 1, 0, 100, "127.0.0.1:0", "127.0.0.1:5000"):                  true,
		rec(recEstablished, tcpSynRecv, 1, 0, 0, "[::1]:22", "[::1]:51000"):           true,
		rec(recClosed, 1, 1, 0, 0, "127.0.0.1:40000", "127.0.0.53:53"):                true,
		rec(recStart, 7, 1, 0, 100, "192.168.1.24:0", srvAddr):                        false,
		rec(recClosed, 1, 1, 0, 0, cliAddr, srvAddr):                                  false,
		rec(recEstablished, tcpSynRecv, 1, 0, 0, "192.168.1.24:22", "10.0.0.5:51000"): false,
	} {
		if got := loopbackRecord(r); got != want {
			t.Errorf("loopbackRecord(%v → %v) = %v, want %v", r.Local, r.Remote, got, want)
		}
	}
}

// Review minors: a summary says how much the connections it stands for
// moved; attempts that never established are not mixed with connections
// that worked; an inbound per-process summary says "from".
func TestGrouperSummaryTotals(t *testing.T) {
	g := newShortGrouper()
	t0 := time.Now()
	up := brief("curl", "/usr/bin/curl", srvAddr)
	up.HasBytes, up.Sent, up.Recv = true, 10<<20, 1024
	failed := brief("curl", "/usr/bin/curl", srvAddr)
	failed.Failed = true

	if !groupAdd(g, up, t0) {
		t.Fatal("first upload")
	}
	if !groupAdd(g, failed, t0) {
		t.Error("an attempt that never established is not a repeat of a connection that worked")
	}
	for i := 0; i < 3; i++ {
		groupAdd(g, up, t0)
		groupAdd(g, failed, t0)
	}
	T := strings_("es")
	var ok, ko *shortSummary
	sums := g.flush(t0.Add(shortGroupWindow + time.Second))
	for i := range sums {
		if sums[i].Sample.Failed {
			ko = &sums[i]
		} else {
			ok = &sums[i]
		}
	}
	if len(sums) != 2 || ok == nil || ko == nil {
		t.Fatalf("want two summaries, got %+v", sums)
	}
	if ok.Count != 3 || !ok.HasBytes || ok.Sent != 30<<20 || ok.Recv != 3*1024 {
		t.Errorf("uploads: %+v", ok)
	}
	if got := summaryDetail(T, *ok); got != "×3 más en 60 s · ↑30 MB ↓3 KB" {
		t.Errorf("%q", got)
	}
	if got := summaryDetail(T, *ko); got != "intento no establecido · ×3 más en 60 s" {
		t.Errorf("%q", got)
	}

	in := shortSummary{PerProc: true, Count: 230, Addrs: 61, Sample: briefConn{Inbound: true}}
	if got := summaryDetail(T, in); got != "×230 entrantes breves más desde 61 direcciones" {
		t.Errorf("%q", got)
	}
	out := shortSummary{PerProc: true, Count: 230, Addrs: 61, HasBytes: true, Sent: 2 << 20, Recv: 4 << 20}
	if got := summaryDetail(T, out); got != "×230 conexiones breves más a 61 direcciones · ↑2 MB ↓4 MB" {
		t.Errorf("%q", got)
	}
}
