package main

import (
	"syscall"
	"testing"

	gnet "github.com/shirou/gopsutil/v4/net"
)

func tcpListen(pid int32, ip string, port uint32) gnet.ConnectionStat {
	return gnet.ConnectionStat{Pid: pid, Type: uint32(syscall.SOCK_STREAM), Status: "LISTEN",
		Laddr: gnet.Addr{IP: ip, Port: port}}
}

func udpBound(pid int32, ip string, port uint32) gnet.ConnectionStat {
	return gnet.ConnectionStat{Pid: pid, Type: uint32(syscall.SOCK_DGRAM),
		Laddr: gnet.Addr{IP: ip, Port: port}}
}

// What counts as "waiting for others to connect": a TCP socket in LISTEN, or
// an unconnected UDP socket on a non-ephemeral port (a UDP client's source
// port is ephemeral; every DNS query opens one). Only on an address another
// machine can reach — loopback is not the alert's business.
func TestListenersOf(t *testing.T) {
	established := tcpListen(7, "192.168.1.5", 50000)
	established.Status = "ESTABLISHED"
	established.Raddr = gnet.Addr{IP: "203.0.113.9", Port: 443}
	quic := udpBound(8, "192.168.1.5", 4433)
	quic.Raddr = gnet.Addr{IP: "203.0.113.9", Port: 443}

	got := listenersOf([]gnet.ConnectionStat{
		tcpListen(1, "0.0.0.0", 4444),
		tcpListen(1, "::", 4444), // the same listener on both families: once
		tcpListen(2, "127.0.0.1", 5432),
		tcpListen(2, "::1", 5432),
		tcpListen(3, "192.168.1.5", 8080),
		established,
		udpBound(4, "0.0.0.0", 5353),
		udpBound(5, "0.0.0.0", 45123), // an ephemeral bind: a client, not a server
		quic,
		tcpListen(ownPID, "0.0.0.0", 5000), // the dashboard itself
	})
	want := []listenSocket{
		{pid: 1, proto: "tcp", port: 4444},
		{pid: 3, proto: "tcp", port: 8080},
		{pid: 4, proto: "udp", port: 5353},
	}
	if len(got) != len(want) {
		t.Fatalf("listenersOf = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].pid != want[i].pid || got[i].proto != want[i].proto || got[i].port != want[i].port {
			t.Errorf("listener %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A program that listens on a random high port gets a different one every
// time it starts; announcing each would teach the operator to ignore the
// alert. Ephemeral ports share one baseline entry per program.
func TestListenKey(t *testing.T) {
	for _, c := range []struct {
		who, proto string
		port       uint32
		want       string
	}{
		{"/usr/bin/nc", "tcp", 4444, "/usr/bin/nc|tcp/4444"},
		{"/usr/bin/nc", "udp", 4444, "/usr/bin/nc|udp/4444"},
		{"/usr/bin/transmission", "tcp", 51413, "/usr/bin/transmission|tcp/eph"},
		{"/usr/bin/transmission", "tcp", 61999, "/usr/bin/transmission|tcp/eph"},
		{"", "tcp", 22, "?|tcp/22"},
		// A program updated while running: the kernel appends " (deleted)" to
		// its path. It is still the same program.
		{"/opt/google/chrome/chrome (deleted)", "udp", 5353, "/opt/google/chrome/chrome|udp/5353"},
	} {
		if got := listenKey(c.who, c.proto, c.port); got != c.want {
			t.Errorf("listenKey(%q, %q, %d) = %q, want %q", c.who, c.proto, c.port, got, c.want)
		}
	}
}

func TestListenWatch(t *testing.T) {
	setupTestDB(t)
	who := func(pid int32) (string, string) {
		switch pid {
		case 1:
			return "sshd", "/usr/sbin/sshd"
		case 2:
			return "nc", "/usr/bin/nc"
		case 3:
			return "transmission", "/usr/bin/transmission"
		}
		return "N/A", ""
	}
	w := newListenWatch()
	if !w.empty() {
		t.Fatal("a fresh database has no listening-port baseline")
	}

	// First run ever: what is already listening is the baseline, not news.
	base := []listenSocket{{1, "tcp", "0.0.0.0", 22}, {3, "tcp", "0.0.0.0", 51413}}
	if got := w.fresh(base, who, true); len(got) != 0 {
		t.Errorf("seeding announced %v", got)
	}
	if w.empty() {
		t.Error("seeding must record the baseline")
	}

	// A port nobody was listening on: announced once, while it stays open.
	withNC := append(append([]listenSocket{}, base...), listenSocket{2, "tcp", "0.0.0.0", 4444})
	got := w.fresh(withNC, who, false)
	if len(got) != 1 || got[0].sock.port != 4444 || got[0].name != "nc" || got[0].exe != "/usr/bin/nc" {
		t.Fatalf("new listener: %+v", got)
	}
	if again := w.fresh(withNC, who, false); len(again) != 0 {
		t.Errorf("announced again while still open: %+v", again)
	}

	// The same program on the same port after a restart of either side is not
	// news: the baseline is on disk.
	w2 := newListenWatch()
	if got := w2.fresh([]listenSocket{{9, "tcp", "0.0.0.0", 4444}}, func(int32) (string, string) { return "nc", "/usr/bin/nc" }, false); len(got) != 0 {
		t.Errorf("known program+port announced after reload: %+v", got)
	}
	// A known program on another ephemeral port: not news either.
	if got := w2.fresh([]listenSocket{{3, "tcp", "0.0.0.0", 60123}}, who, false); len(got) != 0 {
		t.Errorf("ephemeral port of a known program announced: %+v", got)
	}
	// A known program on a new well-known port, and a known port taken by
	// another program: both are news.
	got = w2.fresh([]listenSocket{{3, "tcp", "0.0.0.0", 8080}, {2, "tcp", "0.0.0.0", 22}}, who, false)
	if len(got) != 2 {
		t.Errorf("want two new listeners, got %+v", got)
	}
	// A socket whose owner cannot be read (another user's, without root) is
	// keyed by the port alone.
	got = w2.fresh([]listenSocket{{0, "tcp", "0.0.0.0", 31337}}, who, false)
	if len(got) != 1 || got[0].name != "N/A" {
		t.Errorf("unattributed listener: %+v", got)
	}
}

// An unconnected socket has no peer, but the platforms disagree on how to say
// so: Windows leaves the remote address empty, Linux reports 0.0.0.0:0 (or
// [::]:0). The monitor only looked for the empty form, so on Linux every
// ephemeral UDP bind — one per DNS query — reached the feed and the history
// as a "new connection" to 0.0.0.0:0, and was labelled UDP instead of
// UDP-BOUND in the table.
func TestUnpeeredUDPIsNotAConnection(t *testing.T) {
	linux4 := udpBound(10, "192.168.1.24", 47063)
	linux4.Raddr = gnet.Addr{IP: "0.0.0.0", Port: 0}
	linux6 := udpBound(10, "::", 47064)
	linux6.Raddr = gnet.Addr{IP: "::", Port: 0}
	windows := udpBound(10, "192.168.1.24", 47065)
	quic := udpBound(10, "192.168.1.24", 47066)
	quic.Raddr = gnet.Addr{IP: "142.251.147.6", Port: 443}

	for name, c := range map[string]gnet.ConnectionStat{"linux v4": linux4, "linux v6": linux6, "windows": windows} {
		if hasPeer(c) {
			t.Errorf("%s: an unconnected socket has no peer", name)
		}
		if got := connStatus(c); got != "UDP-BOUND" {
			t.Errorf("%s: status %q, want UDP-BOUND", name, got)
		}
		if ev := describe(c); ev.Remote != "" {
			t.Errorf("%s: event carries a remote %q", name, ev.Remote)
		}
	}
	if !hasPeer(quic) || connStatus(quic) != "UDP" {
		t.Error("a connected UDP socket (QUIC) has a peer")
	}
	snap := snapshotOf([]gnet.ConnectionStat{linux4, linux6, windows, quic})
	if len(snap) != 1 {
		t.Errorf("the live monitor follows %d of these sockets, want only the connected one", len(snap))
	}

	// The same representation applies to listenersOf: Linux's 0.0.0.0:0 peer
	// on a bound UDP port must not hide the listener.
	mdns := udpBound(4, "0.0.0.0", 5353)
	mdns.Raddr = gnet.Addr{IP: "0.0.0.0", Port: 0}
	if got := listenersOf([]gnet.ConnectionStat{mdns}); len(got) != 1 {
		t.Errorf("listenersOf missed a UDP listener reported the Linux way: %v", got)
	}
}
