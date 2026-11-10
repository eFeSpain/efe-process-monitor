package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// New listening port.
//
// A port that starts accepting connections from the network is how a bind
// shell, a rogue proxy or a forgotten debug server looks from the outside,
// and until now it reached the feed as one more "new connection". The
// monitor keeps a baseline of who listens on what — program + protocol/port,
// on disk — and raises a specific alert for anything outside it.
//
// The baseline is seeded silently the first time (whatever is listening when
// the monitor first runs is the machine's normal). After that it is not: a
// listener that appeared while the monitor was stopped is announced when it
// starts, which is the case of something installed to listen from boot.

// ephemeralFrom is where the kernel's automatic port range starts on Linux
// (32768–60999); Windows and the BSDs start higher (49152). A program that
// asks for "any port" lands here and gets a different one every run.
const ephemeralFrom = 32768

// listenSocket is one socket waiting for others to connect to it.
type listenSocket struct {
	pid   int32
	proto string // "tcp" | "udp"
	ip    string
	port  uint32
}

// listenersOf picks, from every socket on the machine, the ones another
// machine could connect to: TCP in LISTEN and unconnected UDP on a
// non-ephemeral port (an unconnected UDP socket on an ephemeral port is a
// client's — every DNS query opens one), bound to something other than
// loopback. The dashboard's own socket is not news. One entry per
// pid+protocol+port: 0.0.0.0 and :: are the same listener.
func listenersOf(conns []gnet.ConnectionStat) []listenSocket {
	type id struct {
		pid   int32
		proto string
		port  uint32
	}
	seen := map[id]bool{}
	var out []listenSocket
	for _, c := range conns {
		if c.Laddr.Port == 0 || isLoopback(c.Laddr.IP) || c.Pid == ownPID || ownChild(c.Pid) {
			continue
		}
		proto := ""
		switch {
		case isUDP(c):
			if !hasPeer(c) && c.Laddr.Port < ephemeralFrom {
				proto = "udp"
			}
		case c.Status == "LISTEN":
			proto = "tcp"
		}
		k := id{c.Pid, proto, c.Laddr.Port}
		if proto == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, listenSocket{c.Pid, proto, c.Laddr.IP, c.Laddr.Port})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.pid != b.pid {
			return a.pid < b.pid
		}
		if a.proto != b.proto {
			return a.proto < b.proto
		}
		return a.port < b.port
	})
	return out
}

// listenKey is the baseline entry for a program listening on a port. Every
// ephemeral port of a program is the same entry: announcing each random port
// of a torrent client or an RPC service would only teach the operator to
// ignore the alert. who is the executable path (the process name when the
// path cannot be read); a socket whose owner is unknown is keyed by the port.
func listenKey(who, proto string, port uint32) string {
	// Replaced on disk while running (an update): still the same program.
	who = strings.TrimSuffix(who, " (deleted)")
	if who == "" || who == "N/A" || who == "ACCESS_DENIED" {
		who = "?"
	}
	p := strconv.FormatUint(uint64(port), 10)
	if port >= ephemeralFrom {
		p = "eph"
	}
	return who + "|" + proto + "/" + p
}

// newListener is a listening socket outside the baseline, with its owner.
type newListener struct {
	sock      listenSocket
	name, exe string
}

// listenWatch is the baseline plus the sockets already looked at, so a socket
// that stays open costs nothing on the following passes. Monitor goroutine only.
type listenWatch struct {
	known   map[string]bool
	checked map[listenSocket]bool
}

func newListenWatch() *listenWatch {
	return &listenWatch{known: dbListenBaseline(), checked: map[listenSocket]bool{}}
}

func (w *listenWatch) empty() bool { return len(w.known) == 0 }

// fresh records every listener not in the baseline and returns them — unless
// seeding, which records without returning anything.
func (w *listenWatch) fresh(socks []listenSocket, who func(pid int32) (name, exe string), seeding bool) []newListener {
	open := make(map[listenSocket]bool, len(socks))
	var out []newListener
	for _, s := range socks {
		open[s] = true
		if w.checked[s] {
			continue
		}
		w.checked[s] = true
		name, exe := who(s.pid)
		owner := exe
		if owner == "" {
			owner = name
		}
		k := listenKey(owner, s.proto, s.port)
		if w.known[k] {
			continue
		}
		w.known[k] = true
		dbListenAdd(k)
		if !seeding {
			out = append(out, newListener{s, name, exe})
		}
	}
	for s := range w.checked {
		if !open[s] {
			delete(w.checked, s)
		}
	}
	return out
}

// procNameExe is who owns a PID, as far as this process is allowed to see.
func procNameExe(pid int32) (name, exe string) {
	name = "N/A"
	if pid <= 0 {
		return name, ""
	}
	if p, err := process.NewProcess(pid); err == nil {
		if n, err := p.Name(); err == nil {
			name = n
		}
		exe, _ = p.Exe()
	}
	return name, exe
}

// announceListeners raises the alert — feed, history, notification — for each
// new listener. A whitelisted binary is reported but does not notify.
func announceListeners(found []newListener, wl map[string]bool) {
	if len(found) == 0 {
		return
	}
	T := strings_(currentLang())
	for _, l := range found {
		detail := fmt.Sprintf(T["ev_newlisten"], l.sock.proto, l.sock.port)
		local := fmt.Sprintf("%s:%d", l.sock.ip, l.sock.port)
		publish(Event{Kind: "alert", Level: "med", PID: l.sock.pid, Process: l.name, Exe: l.exe,
			Local: local, Detail: detail})
		if !wl[l.exe] {
			notify(T["notif_newlisten"], fmt.Sprintf("%s (%d) — %s (%s)", l.name, l.sock.pid, detail, local),
				"listen:"+listenKey(l.exe, l.sock.proto, l.sock.port))
		}
	}
}
