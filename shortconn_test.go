package main

import (
	"encoding/binary"
	"net/netip"
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
	closed.Sent, closed.Recv = 38_000_000, 1024
	got := feed(tr, time.Now(), rec(recStart, 7, 1, 0, 100, cliAddr, srvAddr), rec(recEstablished, tcpSynSent, 1, 10, 0, cliAddr, srvAddr), closed)
	if len(got) != 1 || !got[0].HasBytes || got[0].Sent != 38_000_000 || got[0].Recv != 1024 {
		t.Errorf("%+v", got)
	}
}
