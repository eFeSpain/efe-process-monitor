//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel tests: they load the eBPF program into the running kernel and need
// root. They are skipped otherwise; scripts/vm-kernel-test.sh runs them as
// root inside a throwaway VM booted with this machine's kernel, and CI runs
// them under sudo.
func requireKernelTest(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("kernel test: needs root (run scripts/vm-kernel-test.sh)")
	}
	// These tests talk to themselves over loopback, which the reader
	// otherwise drops before the monitor sees it.
	shortConnKeepLoopback = true
}

// The program reads the tracepoint's record at fixed offsets. They are part
// of a stable kernel interface, and this pins them on every kernel the tests
// run on: if one ever moved, this fails before anything misreads a field.
func TestKernelTracepointExists(t *testing.T) {
	requireKernelTest(t)
	format, err := readTracepointFormat()
	if err != nil {
		t.Fatal(err)
	}
	if err := tracepointLayout(format); err != nil {
		t.Errorf("%v\n%s", err, format)
	}
}

func openTestSource(t *testing.T) *shortConnSource {
	t.Helper()
	requireKernelTest(t)
	src, err := openShortConnSource()
	if err != nil {
		t.Fatalf("loading the eBPF program: %v", err)
	}
	t.Cleanup(func() { src.Close() })
	return src
}

// exchange makes one TCP connection to a listener on addr ("127.0.0.1:0",
// "[::1]:0"), lets payload flow both ways when asked, and closes both ends.
func exchange(t *testing.T, addr string, clientSends, serverSends int) (client, server netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(make([]byte, serverSends))
		_, _ = io.Copy(io.Discard, c) // until the client closes its side
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client = c.LocalAddr().(*net.TCPAddr).AddrPort()
	server = c.RemoteAddr().(*net.TCPAddr).AddrPort()
	_, _ = c.Write(make([]byte, clientSends))
	_, _ = io.CopyN(io.Discard, c, int64(serverSends))
	c.Close()
	<-done
	return client, server
}

// collect reads records until done says it has what it wants or three
// seconds pass, keeping only those that involve one of the given ports.
func collect(t *testing.T, src *shortConnSource, ports []uint16, done func([]kernelRecord) bool) []kernelRecord {
	t.Helper()
	mine := func(r kernelRecord) bool {
		for _, p := range ports {
			if r.Local.Port() == p || r.Remote.Port() == p {
				return true
			}
		}
		return false
	}
	var got []kernelRecord
	src.setDeadline(time.Now().Add(3 * time.Second))
	for {
		r, err := src.next()
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("reading records: %v", err)
			}
			return got
		}
		if mine(r) {
			got = append(got, r)
			if done != nil && done(got) {
				return got
			}
		}
	}
}

// socketRecords are the records of the socket whose local port is lport,
// in arrival order.
func socketRecords(recs []kernelRecord, lport uint16) []kernelRecord {
	var out []kernelRecord
	for _, r := range recs {
		if r.Local.Port() == lport {
			out = append(out, r)
		}
	}
	return out
}

// socketOf returns every record of the socket whose close matches pick, in
// arrival order. A socket is identified by its address, not by its ports: the
// kernel assigns the local port of an outbound connection after the state
// change that produces the start record.
func socketOf(recs []kernelRecord, pick func(kernelRecord) bool) []kernelRecord {
	for _, c := range recs {
		if c.Kind != recClosed || !pick(c) {
			continue
		}
		var out []kernelRecord
		for _, r := range recs {
			if r.Sock == c.Sock {
				out = append(out, r)
			}
		}
		return out
	}
	return nil
}

func closedWith(pick func(kernelRecord) bool) func([]kernelRecord) bool {
	return func(recs []kernelRecord) bool { return socketOf(recs, pick) != nil }
}

func kinds(recs []kernelRecord) []uint8 {
	var k []uint8
	for _, r := range recs {
		k = append(k, r.Kind)
	}
	return k
}

func hasClosed(lport uint16) func([]kernelRecord) bool {
	return func(recs []kernelRecord) bool {
		for _, r := range socketRecords(recs, lport) {
			if r.Kind == recClosed {
				return true
			}
		}
		return false
	}
}

// An outbound connection: the kernel tells us who called connect(), when the
// handshake completed and when the socket went away — three records of one
// socket.
func TestKernelOutbound(t *testing.T) {
	src := openTestSource(t)
	client, server := exchange(t, "127.0.0.1:0", 0, 0)
	isClient := func(r kernelRecord) bool { return r.Local == client && r.Remote == server }
	recs := socketOf(collect(t, src, []uint16{client.Port(), server.Port()}, closedWith(isClient)), isClient)
	if len(recs) != 3 || recs[0].Kind != recStart || recs[1].Kind != recEstablished || recs[2].Kind != recClosed {
		t.Fatalf("client socket records: kinds %v, want start, established, closed\n%+v", kinds(recs), recs)
	}
	comm, _ := os.ReadFile("/proc/self/comm")
	start := recs[0]
	if start.PID != uint32(os.Getpid()) || start.UID != 0 || start.Comm != strings.TrimSpace(string(comm)) {
		t.Errorf("start: pid=%d (want %d) uid=%d comm=%q (want %q)", start.PID, os.Getpid(), start.UID, start.Comm, strings.TrimSpace(string(comm)))
	}
	// At the start the kernel knows where the connection is going but has
	// not chosen the local port yet: the tracker takes the local endpoint
	// from a later record.
	if start.Remote != server {
		t.Errorf("start: remote %v, want %v", start.Remote, server)
	}
	t.Logf("start record local endpoint: %v (the connection's is %v)", start.Local, client)
	if recs[1].Old != tcpSynSent || !isClient(recs[1]) {
		t.Errorf("established: old state %d, %v → %v; want SYN_SENT and the full endpoints", recs[1].Old, recs[1].Local, recs[1].Remote)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].Sock != start.Sock || recs[i].TS < recs[i-1].TS {
			t.Errorf("record %d: sock %#x ts %d (previous: sock %#x ts %d)", i, recs[i].Sock, recs[i].TS, recs[i-1].Sock, recs[i-1].TS)
		}
		if recs[i].PID != 0 || recs[i].Comm != "" {
			t.Errorf("record %d carries a process (%d %q): only a start is in the process's context", i, recs[i].PID, recs[i].Comm)
		}
	}
}

// An inbound connection has no start: its first record is "established"
// coming from SYN_RECV, on a socket whose local port is the listener's.
func TestKernelInbound(t *testing.T) {
	src := openTestSource(t)
	client, server := exchange(t, "127.0.0.1:0", 0, 0)
	recs := socketRecords(collect(t, src, []uint16{server.Port()}, hasClosed(server.Port())), server.Port())
	if len(recs) != 2 || recs[0].Kind != recEstablished || recs[1].Kind != recClosed {
		t.Fatalf("accepted socket records: kinds %v, want established, closed\n%+v", kinds(recs), recs)
	}
	if recs[0].Old != tcpSynRecv || recs[0].Remote != client || recs[0].Local != server || recs[1].Sock != recs[0].Sock {
		t.Errorf("inbound: %+v", recs)
	}
}

// A refused connect: a start and a close, never established.
func TestKernelRefused(t *testing.T) {
	src := openTestSource(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
	ln.Close()
	if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		c.Close()
		t.Skip("the port got taken")
	}
	// The client's socket closes straight from SYN_SENT. (The listener that
	// was just closed went from LISTEN to CLOSE: another socket.)
	isClient := func(r kernelRecord) bool { return r.Old == tcpSynSent && r.Remote.Port() == port }
	recs := socketOf(collect(t, src, []uint16{port}, closedWith(isClient)), isClient)
	if len(recs) != 2 || recs[0].Kind != recStart || recs[1].Kind != recClosed {
		t.Fatalf("refused connect: kinds %v, want start, closed\n%+v", kinds(recs), recs)
	}
	if recs[0].PID != uint32(os.Getpid()) || recs[0].Remote.Port() != port {
		t.Errorf("start: %+v", recs[0])
	}
	t.Logf("refused: start local %v, closed local %v", recs[0].Local, recs[1].Local)
}

func TestKernelIPv6(t *testing.T) {
	src := openTestSource(t)
	client, server := exchange(t, "[::1]:0", 0, 0)
	isClient := func(r kernelRecord) bool { return r.Local == client && r.Remote == server }
	recs := socketOf(collect(t, src, []uint16{client.Port(), server.Port()}, closedWith(isClient)), isClient)
	if len(recs) != 3 {
		t.Fatalf("kinds %v\n%+v", kinds(recs), recs)
	}
	loop := netip.MustParseAddr("::1")
	if recs[0].Remote != server || recs[1].Local != client || recs[1].Local.Addr() != loop || recs[1].Remote.Addr() != loop {
		t.Errorf("IPv6 endpoints: start → %v, established %v → %v; want %v → %v", recs[0].Remote, recs[1].Local, recs[1].Remote, client, server)
	}
}

// Only TCP: a UDP datagram produces nothing.
func TestKernelIgnoresUDP(t *testing.T) {
	src := openTestSource(t)
	c, err := net.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	_, _ = c.Write([]byte("x"))
	c.Close()
	src.setDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		r, err := src.next()
		if err != nil {
			break
		}
		if r.Local.Port() == port {
			t.Fatalf("a UDP socket produced a record: %+v", r)
		}
	}
}

// The count of records the kernel could not queue exists and starts at zero.
func TestKernelLostRecords(t *testing.T) {
	src := openTestSource(t)
	exchange(t, "127.0.0.1:0", 0, 0)
	if n := src.lost(); n != 0 {
		t.Errorf("lost() = %d after one connection, want 0", n)
	}
	if src.volume() {
		t.Log("the program reads byte counters")
	}
}

// The way the monitor uses it: started once, records arrive on a channel,
// and the status says it is working.
func TestKernelStartShortConns(t *testing.T) {
	requireKernelTest(t)
	oldOn := shortConnsEnabled.Load()
	shortConnsEnabled.Store(true)
	t.Cleanup(func() { shortConnsEnabled.Store(oldOn) })

	ch, _ := startShortConns()
	if ch == nil {
		code, detail := shortConnStatus()
		t.Fatalf("startShortConns as root returned no channel: %s %s", code, detail)
	}
	if code, _ := shortConnStatus(); code != "active" {
		t.Errorf("status %q, want active", code)
	}
	if text, active := shortConnStatusText(strings_("en")); !active || text != "active — eBPF" {
		t.Errorf("status text %q active=%v", text, active)
	}
	client, server := exchange(t, "127.0.0.1:0", 0, 0)
	deadline := time.After(3 * time.Second)
	for {
		select {
		case r := <-ch:
			if r.Kind == recClosed && r.Local == client && r.Remote == server {
				return
			}
		case <-deadline:
			t.Fatal("the connection's close never arrived on the channel")
		}
	}
}

// From the kernel to the history, with the real pieces: a connection made
// here, reported by the kernel, tracked, announced and stored. The VM has
// only a loopback interface and the tracker discards loopback, so the
// records' addresses are rewritten to routable ones on the way in — the one
// thing in this chain that is not what production does.
func TestKernelEndToEnd(t *testing.T) {
	requireKernelTest(t)
	setupTestDB(t)
	oldOn := shortConnsEnabled.Load()
	shortConnsEnabled.Store(true)
	t.Cleanup(func() { shortConnsEnabled.Store(oldOn) })
	ch, volume := startShortConns()
	if ch == nil {
		t.Fatal("the kernel source did not start")
	}

	exe, _ := os.Executable()
	// The connection is made by this very process, whose traffic the tracker
	// discards as the monitor's own: the start is passed on under another PID.
	const otherPID = 4242
	who := func(pid int32) (string, string) {
		if pid == otherPID {
			return "vmtest", exe
		}
		return "N/A", ""
	}
	tracker := newShortTracker(who, volume)
	grouper := newShortGrouper()
	known := map[int32]time.Time{}
	wl := map[string]bool{exe: true} // muted: no reputation lookups from a test

	_, server := exchange(t, "127.0.0.1:0", 1000, 0)
	routable := func(ap netip.AddrPort, ip string) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr(ip), ap.Port())
	}
	var clientSock uint64
	deadline := time.After(3 * time.Second)
	for done := false; !done; {
		select {
		case r := <-ch:
			if r.Kind == recStart && r.PID == uint32(os.Getpid()) && r.Remote.Port() == server.Port() {
				clientSock = r.Sock
			}
			if r.Sock != clientSock || clientSock == 0 {
				continue // the accepted socket and anything else on the machine
			}
			r.Local, r.Remote = routable(r.Local, "192.0.2.1"), routable(r.Remote, "203.0.113.9")
			if r.Kind == recStart {
				r.PID = otherPID
			}
			if c, ok := tracker.record(r, time.Now()); ok {
				announceBrief(c, grouper, known, wl, time.Now())
			}
			done = r.Kind == recClosed
		case <-deadline:
			t.Fatal("the connection's records never arrived")
		}
	}

	rows, _ := searchEvents(eventFilter{Kind: "short"})
	want := "203.0.113.9:" + strconv.Itoa(int(server.Port()))
	if len(rows) != 1 || rows[0].Remote != want || rows[0].Process != "vmtest" || rows[0].PID != otherPID || !strings.HasPrefix(rows[0].Detail, strings_(currentLang())["ev_short"]) {
		t.Fatalf("history: want one brief connection to %s, got %+v", want, rows)
	}
	t.Logf("history row: %s %s (%d) → %s — %s", rows[0].At, rows[0].Process, rows[0].PID, rows[0].Remote, rows[0].Detail)
}

// Where the byte counters live in this kernel's struct tcp_sock, from the
// kernel's own type information.
func TestKernelVolumeOffsets(t *testing.T) {
	requireKernelTest(t)
	vol, err := tcpSockOffsets()
	if err != nil {
		t.Skipf("no usable BTF on this kernel: %v", err)
	}
	if vol.sent <= 0 || vol.recv <= 0 || vol.sent == vol.recv || vol.sent%8 != 0 || vol.recv%8 != 0 {
		t.Errorf("offsets of bytes_acked / bytes_received: %+v", vol)
	}
	t.Logf("tcp_sock: bytes_acked @%d, bytes_received @%d", vol.sent, vol.recv)
}

// A brief connection says how much it moved: 100,000 bytes out, 20,000 in.
func TestKernelVolume(t *testing.T) {
	if _, err := tcpSockOffsets(); err != nil {
		requireKernelTest(t)
		t.Skipf("no usable BTF on this kernel: %v", err)
	}
	src := openTestSource(t)
	if !src.volume() {
		t.Fatal("BTF is available but the program was loaded without byte counters")
	}
	client, server := exchange(t, "127.0.0.1:0", 100_000, 20_000)
	isClient := func(r kernelRecord) bool { return r.Local == client && r.Remote == server }
	recs := socketOf(collect(t, src, []uint16{client.Port(), server.Port()}, closedWith(isClient)), isClient)
	if len(recs) != 3 {
		t.Fatalf("kinds %v", kinds(recs))
	}
	closed := recs[2]
	// The kernel counts in sequence space, where the SYN and the FIN take
	// one number each: a few bytes over the payload, never under.
	if closed.Sent < 100_000 || closed.Sent > 100_016 || closed.Recv < 20_000 || closed.Recv > 20_016 {
		t.Errorf("closed: sent %d (want ≈100000), received %d (want ≈20000)", closed.Sent, closed.Recv)
	}
	if recs[0].Sent != 0 || recs[1].Sent != 0 || recs[0].Recv != 0 || recs[1].Recv != 0 {
		t.Errorf("only the close carries byte counts: %+v", recs[:2])
	}
}

// Review: every kernel test made its connections from the test process
// itself. The point of the feature is naming *another* process — including
// one that is gone by the time anyone asks who it was.
func TestKernelOtherProcess(t *testing.T) {
	src := openTestSource(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()

	cmd := command(os.Args[0])
	cmd.Env = append(os.Environ(), dialAndExit+"="+ln.Addr().String())
	if err := cmd.Run(); err != nil {
		t.Fatalf("the helper process: %v", err)
	}
	child := uint32(cmd.Process.Pid)

	recs := collect(t, src, []uint16{port}, func(recs []kernelRecord) bool {
		for _, r := range recs {
			if r.Kind == recStart && r.PID == child {
				return true
			}
		}
		return false
	})
	comm, _ := os.ReadFile("/proc/self/comm")
	found := false
	for _, r := range recs {
		if r.Kind == recStart && r.Remote.Port() == port {
			found = true
			if r.PID != child || r.PID == uint32(os.Getpid()) || r.Comm != strings.TrimSpace(string(comm)) {
				t.Errorf("start: pid %d comm %q, want the helper's pid %d and comm %q", r.PID, r.Comm, child, strings.TrimSpace(string(comm)))
			}
		}
	}
	if !found {
		t.Fatalf("no start record for the helper's connection: %+v", recs)
	}
	// The helper has exited: asking the system who it was gets nothing, and
	// the name the kernel recorded is all there is.
	if name, exe := procNameExe(int32(child)); name != "N/A" || exe != "" {
		t.Errorf("the helper is gone, yet procNameExe says %q %q", name, exe)
	}
}

// Review: nothing made the kernel buffer overflow. When it does, records
// are lost, the loss is counted, and reading carries on.
func TestKernelLostRecordsAreCounted(t *testing.T) {
	requireKernelTest(t)
	src, err := openShortConnSourceSized(4096) // room for some thirty records
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for i := 0; i < 40; i++ { // five records each, none read
		exchange(t, "127.0.0.1:0", 0, 0)
	}
	lost := src.lost()
	if lost == 0 {
		t.Fatal("two hundred records into a buffer for thirty, and none counted as lost")
	}
	// What did fit is still readable, and new records keep coming.
	src.setDeadline(time.Now().Add(time.Second))
	n := 0
	for {
		if _, err := src.next(); err != nil {
			break
		}
		n++
	}
	if n == 0 {
		t.Error("nothing readable after the overflow")
	}
	client, server := exchange(t, "127.0.0.1:0", 0, 0)
	isClient := func(r kernelRecord) bool { return r.Local == client && r.Remote == server }
	if recs := socketOf(collect(t, src, []uint16{client.Port(), server.Port()}, closedWith(isClient)), isClient); len(recs) != 3 {
		t.Errorf("after an overflow a new connection must still be reported in full: %v", kinds(recs))
	}
	t.Logf("%d records lost, %d read", lost, n)
}

// Review: with the monitor not reading, the reader goroutine must leave the
// records in the kernel (where an overflow is counted) rather than queue
// them without bound; when the monitor reads again, records flow.
func TestKernelReaderBackPressure(t *testing.T) {
	requireKernelTest(t)
	src, err := openShortConnSourceSized(4096)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan kernelRecord, 1) // a monitor that reads nothing
	go forwardShortConns(src, ch)
	for i := 0; i < 40; i++ {
		exchange(t, "127.0.0.1:0", 0, 0)
	}
	time.Sleep(200 * time.Millisecond)
	if src.lost() == 0 {
		t.Error("with nobody reading, the overflow must happen in the kernel buffer and be counted")
	}
	if len(ch) != 1 {
		t.Errorf("the channel holds %d records, want it full at 1 and the reader blocked", len(ch))
	}
	// The monitor comes back.
	deadline := time.After(3 * time.Second)
	for got := 0; got < 10; {
		select {
		case <-ch:
			got++
		case <-deadline:
			t.Fatalf("only %d records after the monitor resumed reading", got)
		}
	}
	if code, _ := shortConnStatus(); code == "stopped" {
		t.Error("the reader gave up")
	}
}

// loopbackAlias gives lo a second, routable-looking address (TEST-NET-1) for
// the length of a test: the VM has no other interface, and the monitor does
// not follow loopback addresses.
func loopbackAlias(t *testing.T) string {
	t.Helper()
	const alias = "192.0.2.1"
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no loopback interface: %v", err)
	}
	if err := netlinkAddr(unix.RTM_NEWADDR, lo.Index, netip.MustParseAddr(alias)); err != nil && !errors.Is(err, unix.EEXIST) {
		t.Skipf("cannot add %s to lo: %v", alias, err)
	}
	t.Cleanup(func() { _ = netlinkAddr(unix.RTM_DELADDR, lo.Index, netip.MustParseAddr(alias)) })
	return alias
}

// netlinkAddr adds or removes an IPv4 /32 on an interface (rtnetlink).
func netlinkAddr(msgType uint16, ifindex int, addr netip.Addr) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ip := addr.As4()
	ne := binary.NativeEndian
	msg := make([]byte, 16+8+8+8)
	ne.PutUint32(msg[0:], uint32(len(msg)))
	ne.PutUint16(msg[4:], msgType)
	ne.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	ne.PutUint32(msg[8:], 1)                // sequence
	msg[16], msg[17] = unix.AF_INET, 32     // ifaddrmsg: family, prefix length
	msg[19] = unix.RT_SCOPE_UNIVERSE        // scope
	ne.PutUint32(msg[20:], uint32(ifindex)) // interface
	for i, attr := range []uint16{unix.IFA_LOCAL, unix.IFA_ADDRESS} {
		off := 24 + 8*i
		ne.PutUint16(msg[off:], 8)
		ne.PutUint16(msg[off+2:], attr)
		copy(msg[off+4:], ip[:])
	}
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	ack := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, ack, 0)
	if err != nil {
		return err
	}
	if n >= 20 && ne.Uint16(ack[4:]) == unix.NLMSG_ERROR {
		if code := int32(ne.Uint32(ack[16:])); code != 0 {
			return unix.Errno(-code)
		}
	}
	return nil
}

// Review: every kernel test ran over 127.0.0.1, which the reader drops and
// the tracker discards — so the path a real connection takes was never
// taken. With a routable-looking address on lo, a connection goes through
// the reader's filter and the tracker as it would in production, while a
// loopback one made alongside does not.
func TestKernelNonLoopbackPath(t *testing.T) {
	requireKernelTest(t)
	alias := loopbackAlias(t)
	shortConnKeepLoopback = false
	t.Cleanup(func() { shortConnKeepLoopback = true })
	src, err := openShortConnSource()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan kernelRecord, 256)
	go forwardShortConns(src, ch)

	loClient, _ := exchange(t, "127.0.0.1:0", 0, 0)
	client, server := exchange(t, alias+":0", 0, 0)

	// The tracker, with one change from production: the connection is made
	// by this process, whose traffic it discards as the monitor's own, so
	// the start is passed on under another PID.
	const otherPID = 4242
	tracker := newShortTracker(func(int32) (string, string) { return "vmtest", "/init" }, false)
	var brief []briefConn
	deadline := time.After(3 * time.Second)
	for done := false; !done; {
		select {
		case r := <-ch:
			if r.Local.Port() == loClient.Port() || r.Remote.Port() == loClient.Port() {
				t.Fatalf("a loopback record reached the monitor: %+v", r)
			}
			if r.Kind == recStart {
				r.PID, r.Name, r.Exe = otherPID, "", ""
			}
			if c, ok := tracker.record(r, time.Now()); ok {
				brief = append(brief, c)
				done = len(brief) == 2 // the client's side and the accepted side
			}
		case <-deadline:
			done = true
		}
	}
	var out *briefConn
	for i := range brief {
		if !brief[i].Inbound {
			out = &brief[i]
		}
	}
	if out == nil || out.Local != client || out.Remote != server || out.PID != otherPID || out.Failed {
		t.Fatalf("want the outbound brief connection %v → %v, got %+v", client, server, brief)
	}
	if !out.Remote.Addr().Is4() || out.Remote.Addr().IsLoopback() {
		t.Errorf("remote %v", out.Remote)
	}
}
