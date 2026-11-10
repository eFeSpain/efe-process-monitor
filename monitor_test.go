package main

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
)

// The monitor hides its own PID, but the subprocesses the tool itself starts
// (nmblookup, arp, tshark, netsh…) open sockets too and were reported as new
// processes — and, the first time, as new binaries with a desktop notification.
// A child of ours is ours.
func TestOwnChildFilter(t *testing.T) {
	if ownChild(ownPID) {
		t.Error("the monitor itself is not its own child")
	}
	if ownChild(int32(os.Getppid())) {
		t.Error("our parent is not our child")
	}
	if ownChild(0) || ownChild(-1) {
		t.Error("invalid PIDs are never ours")
	}
}

// The live-feed reputation alert is graded, not binary: one VirusTotal engine
// flagging a big provider's address is noise (Chrome talking to claude.ai
// raised a red alert over a single detection), two is worth a glance, three
// or more — or any curated-feed hit — is red and gets the desktop notification.
func TestIntelAlertLevels(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		name   string
		e      Enrichment
		level  string
		reason string
	}{
		{"nothing", Enrichment{}, "", ""},
		{"one VT engine", Enrichment{VTMalicious: n(1), Provider: "Anthropic"}, "low", "VirusTotal ×1"},
		{"two VT engines", Enrichment{VTMalicious: n(2)}, "med", "VirusTotal ×2"},
		{"three VT engines", Enrichment{VTMalicious: n(3)}, "high", "VirusTotal ×3"},
		{"Feodo C2", Enrichment{C2: true}, "high", "C2 Feodo"},
		{"ThreatFox", Enrichment{ThreatFox: "Mirai"}, "high", "ThreatFox: Mirai"},
		{"URLhaus", Enrichment{URLhaus: "Mozi"}, "high", "URLhaus: Mozi"},
		{"Spamhaus", Enrichment{Spamhaus: true}, "high", "Spamhaus DROP"},
		{"Tor", Enrichment{Tor: true}, "high", "Tor exit"},
		{"AbuseIPDB on an unknown host", Enrichment{AbuseScore: n(60)}, "high", "AbuseIPDB 60%"},
		{"AbuseIPDB on a known provider is noise", Enrichment{AbuseScore: n(60), Provider: "Google"}, "", ""},
		{"one VT engine plus C2: the worst wins", Enrichment{VTMalicious: n(1), C2: true}, "high", "C2 Feodo"},
	} {
		reasons, level := intelAlert(&tc.e)
		if level != tc.level {
			t.Errorf("%s: level %q, want %q (reasons %v)", tc.name, level, tc.level, reasons)
		}
		if tc.reason == "" && len(reasons) != 0 {
			t.Errorf("%s: expected no reasons, got %v", tc.name, reasons)
		}
		if tc.reason != "" && (len(reasons) == 0 || !strings.Contains(strings.Join(reasons, ", "), tc.reason)) {
			t.Errorf("%s: reasons %v lack %q", tc.name, reasons, tc.reason)
		}
	}
}

// The three high-precision local signals — a spawn chain that should never
// happen, a foreign process holding a credential store, executable memory from
// a memfd — were only computed when somebody rendered the table. With the
// monitor running as a service and nobody watching, a macro launching a
// payload raised nothing. localSignals is the decision, shared with the live
// monitor.
func TestLocalSignals(t *testing.T) {
	keys := func(rs []reason) string {
		var k []string
		for _, r := range rs {
			k = append(k, r.key+":"+strings.Join(r.args, ","))
		}
		return strings.Join(k, " ")
	}
	macro := []Ancestor{{PID: 10, Name: "WINWORD.EXE"}, {PID: 4, Name: "explorer.exe"}}
	if got := keys(localSignals("powershell.exe", macro, nil)); got != "spawn:winword.exe → powershell.exe" {
		t.Errorf("macro chain: %q", got)
	}
	scan := &procScan{files: []string{"browser: /home/x/.config/google-chrome/Default/Login Data", "ssh: /home/x/.ssh/id_ed25519"}, scored: 2,
		execMap: []string{"memfd: /memfd:payload (deleted) (r-xp)"}, media: []string{"media: /dev/video0"}}
	if got := keys(localSignals("updater", nil, scan)); got != "creds:2 execmap:1" {
		t.Errorf("creds + execmap: %q", got)
	}
	// Camera/microphone are context, never a signal; a clean process has none.
	if got := localSignals("zoom", []Ancestor{{PID: 1, Name: "systemd"}}, &procScan{media: []string{"media: /dev/video0"}}); len(got) != 0 {
		t.Errorf("media alone must not alert: %v", got)
	}
	if got := localSignals("bash", []Ancestor{{PID: 9, Name: "konsole"}}, nil); len(got) != 0 {
		t.Errorf("a user shell under a terminal is normal: %v", got)
	}
}

// One alert per process and signal, not one per monitor tick; a PID that is
// reused after the entry expired alerts again.
func TestLocalAlertDedupe(t *testing.T) {
	var d localAlertDedupe
	t0 := time.Now()
	if !d.fresh(42, "spawn", t0) {
		t.Fatal("first sighting must alert")
	}
	if d.fresh(42, "spawn", t0.Add(3*time.Second)) || d.fresh(42, "spawn", t0.Add(30*time.Minute)) {
		t.Error("the same signal on the same process must not repeat")
	}
	if !d.fresh(42, "creds", t0.Add(4*time.Second)) || !d.fresh(43, "spawn", t0.Add(4*time.Second)) {
		t.Error("another signal, or another process, is a new alert")
	}
	if !d.fresh(42, "spawn", t0.Add(knownPIDTTL+31*time.Minute)) {
		t.Error("after the entry expires (PID reuse) it alerts again")
	}
}

// captureEvents gives the test a fresh history and returns a function that
// drains what has been published since the last call. Sightings in these
// tests are muted (a whitelisted binary): an unmuted one starts reputation
// lookups and desktop notifications, which are not this file's business.
func captureEvents(t *testing.T) func() []Event {
	t.Helper()
	setupTestDB(t)
	beaconMu.Lock()
	clear(beaconTrack)
	clear(beaconTold)
	beaconPruned = 0
	beaconMu.Unlock()
	ch := subscribe()
	t.Cleanup(func() { unsubscribe(ch) })
	return func() []Event {
		var out []Event
		for {
			select {
			case ev := <-ch:
				out = append(out, ev)
			default:
				return out
			}
		}
	}
}

// The checks a polled connection goes through were moved into announceConn
// so that brief connections go through the very same ones. For a polled
// connection nothing may have changed.
func TestAnnouncePolledUnchanged(t *testing.T) {
	drain := captureEvents(t)
	polled := func(exe, remote, remoteIP string, newProc bool) Event {
		announceConn(connSighting{ev: Event{PID: 10, Process: "a", Exe: exe, Local: "192.168.1.24:50000", Remote: remote},
			remoteIP: remoteIP, newProc: newProc, muted: true}, 1000)
		evs := drain()
		if len(evs) != 1 {
			t.Fatalf("%s → %s: %d events, want 1: %+v", exe, remote, len(evs), evs)
		}
		return evs[0]
	}
	if ev := polled("/usr/bin/a", "203.0.113.9:443", "203.0.113.9", true); ev.Kind != "remote" || !ev.NewProcess || !ev.Anomaly || ev.Detail != "" {
		t.Errorf("public remote, first sighting of the binary: %+v", ev)
	}
	if ev := polled("/usr/bin/a", "203.0.113.9:443", "203.0.113.9", false); ev.Kind != "remote" || ev.NewProcess || ev.Anomaly {
		t.Errorf("same binary again: %+v", ev)
	}
	if ev := polled("/usr/bin/a", "192.168.1.5:445", "192.168.1.5", false); ev.Kind != "new" {
		t.Errorf("private remote: %+v", ev)
	}
	if ev := polled("/usr/bin/a", "", "0.0.0.0", false); ev.Kind != "new" {
		t.Errorf("listening socket: %+v", ev)
	}
	if ev := polled("/tmp/x/evil", "203.0.113.9:443", "203.0.113.9", false); ev.Kind != "alert" || ev.Detail != "" {
		t.Errorf("staging path: %+v", ev)
	}
}

func testBrief(name, exe string) briefConn {
	return briefConn{PID: 100, Name: name, Exe: exe, Local: netip.MustParseAddrPort("192.168.1.24:50000"),
		Remote: netip.MustParseAddrPort("203.0.113.9:443"), Duration: 200 * time.Millisecond}
}

func TestAnnounceBrief(t *testing.T) {
	drain := captureEvents(t)
	T := strings_("es")

	s := briefSighting(testBrief("curl", "/usr/bin/curl"), T)
	s.muted = true
	announceConn(s, 1000)
	evs := drain()
	if len(evs) != 1 || evs[0].Kind != "short" || evs[0].Process != "curl" || evs[0].PID != 100 || evs[0].Exe != "/usr/bin/curl" ||
		evs[0].Remote != "203.0.113.9:443" || !strings.HasPrefix(evs[0].Detail, "conexión breve · 0.2 s") || evs[0].Inbound {
		t.Fatalf("brief connection event: %+v", evs)
	}
	// It is in the history under its own kind.
	if rows, _ := searchEvents(eventFilter{Kind: "short"}); len(rows) != 1 || rows[0].Process != "curl" {
		t.Errorf("history: %+v", rows)
	}

	// A grouped repeat is published only if a check fires.
	s.quiet = true
	announceConn(s, 1001)
	if evs := drain(); len(evs) != 0 {
		t.Errorf("a quiet repeat was published: %+v", evs)
	}

	in := testBrief("sshd", "/usr/sbin/sshd")
	in.Inbound, in.Local, in.Remote = true, netip.MustParseAddrPort("192.168.1.24:22"), netip.MustParseAddrPort("192.168.1.50:51000")
	s = briefSighting(in, T)
	s.muted = true
	announceConn(s, 1002)
	evs = drain()
	if len(evs) != 1 || !evs[0].Inbound || evs[0].Kind != "short" || evs[0].Local != "192.168.1.24:22" || evs[0].Remote != "192.168.1.50:51000" ||
		!strings.HasPrefix(evs[0].Detail, "entrante breve") {
		t.Errorf("inbound: %+v", evs)
	}

	// A brief connection from a staging directory is an alert that still
	// says it was brief.
	s = briefSighting(testBrief("nc", "/tmp/.x/nc"), T)
	s.muted = true
	announceConn(s, 1003)
	evs = drain()
	if len(evs) != 1 || evs[0].Kind != "alert" || !strings.Contains(evs[0].Detail, "conexión breve") || !strings.Contains(evs[0].Detail, T["ev_suspicious"]) {
		t.Errorf("staging path: %+v", evs)
	}
}

// A check-in of 200 ms every minute is what beaconing looks like, and the
// poll almost never catches one. Brief connections feed the detector — the
// grouped ones too, which is where a beacon's repeats end up.
func TestAnnounceBriefBeacon(t *testing.T) {
	drain := captureEvents(t)
	T := strings_("es")
	run := func(c briefConn) []Event {
		var all []Event
		for i := 0; i < 5; i++ {
			s := briefSighting(c, T)
			s.muted, s.quiet = true, i > 0
			announceConn(s, float64(1000+60*i))
			all = append(all, drain()...)
		}
		return all
	}

	evs := run(testBrief("implant", "/usr/bin/implant"))
	var alerts []Event
	for _, ev := range evs {
		if ev.Kind == "alert" {
			alerts = append(alerts, ev)
		}
	}
	if len(evs) != 2 || evs[0].Kind != "short" || len(alerts) != 1 ||
		!strings.Contains(alerts[0].Detail, "beaconing") || !strings.Contains(alerts[0].Detail, "conexión breve") || alerts[0].Beacon != 60 {
		t.Errorf("want the first as a brief connection and one beaconing alert later: %+v", evs)
	}

	// With no path the kernel's name is the identity.
	evs = run(testBrief("x", ""))
	found := false
	for _, ev := range evs {
		found = found || (ev.Kind == "alert" && strings.Contains(ev.Detail, "beaconing"))
	}
	if !found {
		t.Errorf("a process known only by name must still be tracked for beaconing: %+v", evs)
	}

	// Someone connecting to us every minute is a monitoring probe, not this
	// machine beaconing out.
	in := testBrief("sshd", "/usr/sbin/sshd")
	in.Inbound = true
	for _, ev := range run(in) {
		if ev.Kind == "alert" {
			t.Errorf("inbound connections must not feed the beacon detector: %+v", ev)
		}
	}
}

// The glue the loop runs for each brief connection: grouping decides what is
// shown, and the PID becomes known.
func TestAnnounceBriefGrouped(t *testing.T) {
	drain := captureEvents(t)
	g := newShortGrouper()
	known := map[int32]time.Time{}
	wl := map[string]bool{"/usr/bin/curl": true}
	now := time.Now()
	c := testBrief("curl", "/usr/bin/curl")
	announceBrief(c, g, known, wl, now)
	announceBrief(c, g, known, wl, now.Add(time.Second))
	evs := drain()
	if len(evs) != 1 || !evs[0].NewProcess || evs[0].Kind != "short" {
		t.Fatalf("two identical brief connections: want one event, flagged as a new process: %+v", evs)
	}
	if known[100].IsZero() {
		t.Error("the PID of a brief connection must become known")
	}

	for _, s := range g.flush(now.Add(shortGroupWindow + time.Second)) {
		publishShortSummary(s)
	}
	evs = drain()
	if len(evs) != 1 || evs[0].Kind != "short" || evs[0].Process != "curl" || evs[0].Remote != "203.0.113.9" ||
		evs[0].Detail != summaryDetail(strings_(currentLang()), shortSummary{Count: 1}) {
		t.Errorf("summary event: %+v", evs)
	}
	publishShortSummary(shortSummary{Sample: c, Count: 230, Addrs: 61, PerProc: true})
	if evs = drain(); len(evs) != 1 || evs[0].Remote != "" || evs[0].Process != "curl" {
		t.Errorf("per-process summary names no single address: %+v", evs)
	}
}

// The reader never closes the channel, but if it ever were closed the loop
// must stop selecting on it rather than spin on zero values. A nil channel
// — the feature inactive — is never ready.
func TestClosedRecordChannelIsDisabled(t *testing.T) {
	ch := make(chan kernelRecord, 1)
	ch <- kernelRecord{Kind: recStart}
	var in <-chan kernelRecord = ch
	_, ok := <-in
	if got := afterRecv(in, ok); got == nil {
		t.Error("a channel that delivered a value must stay")
	}
	close(ch)
	_, ok = <-in
	if got := afterRecv(in, ok); got != nil {
		t.Error("a closed channel must be replaced by nil")
	}
	var inactive <-chan kernelRecord
	select {
	case <-inactive:
		t.Error("a nil channel delivered something")
	default:
	}
}

// recordIntel replaces the background reputation lookup with a recorder, so
// an unmuted sighting can be announced without touching the network.
func recordIntel(t *testing.T) *[]string {
	t.Helper()
	var looked []string
	old, oldNotify := startIntelCheck, notifyDesktop.Load()
	startIntelCheck = func(ev Event, ip string) { looked = append(looked, ip) }
	notifyDesktop.Store(false)
	t.Cleanup(func() { startIntelCheck = old; notifyDesktop.Store(oldNotify) })
	return &looked
}

// Review I2: past the grouping limits nothing is shown for a connection, but
// an address not seen in this window must still get its reputation check —
// otherwise twenty harmless connections hide the one to a listed C2.
func TestQuietFreshAddressIsStillLookedUp(t *testing.T) {
	drain := captureEvents(t)
	looked := recordIntel(t)
	T := strings_("es")
	s := briefSighting(testBrief("curl", "/usr/bin/curl"), T)

	announceConn(s, 1000) // shown: looked up, as always
	if len(drain()) != 1 || len(*looked) != 1 || (*looked)[0] != "203.0.113.9" {
		t.Fatalf("a published brief connection: looked up %v", *looked)
	}
	s.quiet, s.fresh = true, true
	announceConn(s, 1001)
	if evs := drain(); len(evs) != 0 || len(*looked) != 2 {
		t.Errorf("quiet and fresh: want nothing published and one more lookup; events %+v, lookups %v", evs, *looked)
	}
	s.fresh = false
	announceConn(s, 1002)
	if len(*looked) != 2 {
		t.Errorf("a repeat to an address already looked up must not be looked up again: %v", *looked)
	}
	s.muted, s.fresh = true, true
	announceConn(s, 1003)
	if len(*looked) != 2 {
		t.Errorf("a whitelisted binary is not looked up: %v", *looked)
	}
}

// Review I3: a binary under a staging directory makes every connection an
// alert. Grouped repeats of a brief connection must still be grouped —
// `go run` and AppImages live under /tmp and would write a history row per
// connection. Only what is news about the binary or its behaviour (replaced
// on disk, beaconing) is shown despite the grouping.
func TestStagingPathBriefFollowsGrouping(t *testing.T) {
	drain := captureEvents(t)
	T := strings_("es")
	s := briefSighting(testBrief("tool", "/tmp/go-build1/exe/tool"), T)
	s.muted = true
	announceConn(s, 1000)
	if evs := drain(); len(evs) != 1 || evs[0].Kind != "alert" {
		t.Fatalf("the first is an alert: %+v", evs)
	}
	s.quiet = true
	for i := 0; i < 50; i++ {
		announceConn(s, 1001+float64(i)/10)
	}
	if evs := drain(); len(evs) != 0 {
		t.Errorf("%d grouped repeats from a staging path were published", len(evs))
	}
}

// Seen on the real machine: an editor that talks to the same host every
// minute raised the beaconing alert at every sample from the fourth on — a
// notification a minute until the binary was whitelisted. The alert is news
// once; while the beacon goes on it is repeated at most once an hour.
func TestBeaconAlertIsRaisedOncePerHour(t *testing.T) {
	drain := captureEvents(t)
	polled := func(nowSec float64) Event {
		announceConn(connSighting{ev: Event{PID: 10, Process: "agent", Exe: "/usr/bin/agent", Remote: "203.0.113.9:443"},
			remoteIP: "203.0.113.9", muted: true}, nowSec)
		evs := drain()
		if len(evs) != 1 {
			t.Fatalf("%d events", len(evs))
		}
		return evs[0]
	}
	var alerts []float64
	for i := 0; i < 70; i++ { // seventy minutes of a 60 s beacon
		now := float64(1000 + 60*i)
		if ev := polled(now); ev.Kind == "alert" {
			alerts = append(alerts, now)
		} else if i >= 3 && ev.Beacon == 0 {
			t.Fatalf("sample %d: the event must still carry the period it beacons at: %+v", i, ev)
		}
	}
	if len(alerts) != 2 || alerts[0] != 1000+60*3 || alerts[1]-alerts[0] < 3600 {
		t.Errorf("alerts at %v: want one at the fourth sample and one an hour later", alerts)
	}
}

// Review: pruning the beacon table scanned every pair on every sample, and
// brief connections now feed it in volume — tens of thousands of pairs
// stalled the monitor for seconds. Once a minute is enough.
func TestBeaconPruneIsRateLimited(t *testing.T) {
	captureEvents(t)
	stale := func(key string, at float64) {
		beaconMu.Lock()
		beaconTrack[key] = []float64{at}
		beaconMu.Unlock()
	}
	has := func(key string) bool {
		beaconMu.Lock()
		defer beaconMu.Unlock()
		_, ok := beaconTrack[key]
		return ok
	}
	now := 100_000.0
	stale("old|a", now-beaconIdle.Seconds()-1)
	checkBeacon("/usr/bin/x", "203.0.113.9", now)
	if has("old|a") {
		t.Fatal("the first call prunes")
	}
	stale("old|b", now-beaconIdle.Seconds()-1)
	checkBeacon("/usr/bin/x", "203.0.113.9", now+1)
	if !has("old|b") {
		t.Error("pruned again within the same minute")
	}
	checkBeacon("/usr/bin/x", "203.0.113.9", now+61)
	if has("old|b") {
		t.Error("a minute later the idle pair must go")
	}
}

// Review minor: a brief event writes its addresses the way a polled one
// does — "addr:port", no brackets for IPv6 — so one search finds both.
func TestBriefSightingAddressFormat(t *testing.T) {
	c := briefConn{Name: "curl", Local: netip.MustParseAddrPort("[2001:db8::24]:50000"), Remote: netip.MustParseAddrPort("[2001:db8::9]:443")}
	s := briefSighting(c, strings_("es"))
	if s.ev.Local != "2001:db8::24:50000" || s.ev.Remote != "2001:db8::9:443" || s.remoteIP != "2001:db8::9" {
		t.Errorf("local %q remote %q ip %q", s.ev.Local, s.ev.Remote, s.remoteIP)
	}
	c = testBrief("curl", "/usr/bin/curl")
	if s = briefSighting(c, strings_("es")); s.ev.Remote != "203.0.113.9:443" {
		t.Errorf("IPv4: %q", s.ev.Remote)
	}
}

// fakePID is above any PID the kernel hands out (pid_max is 4194304), so
// nothing these tests do can touch a real process.
const fakePID = 4_200_000

func kindsOf(evs []Event) map[string]int {
	out := map[string]int{}
	for _, ev := range evs {
		out[ev.Kind]++
	}
	return out
}

// Review: nothing exercised the monitor with both of its sources. One
// connection is over before any poll (brief); another is caught by a poll
// and its kernel records arrive around it (polled, and only polled).
func TestLiveMonitorBothSources(t *testing.T) {
	drain := captureEvents(t)
	looked := recordIntel(t)
	t0 := time.Now()
	m := newLiveMonitor(map[connKey]gnet.ConnectionStat{}, false)
	m.tracker.who = func(int32) (string, string) { return "N/A", "" }

	const briefLocal, briefRemote = "192.168.1.24:50000", "203.0.113.9:443"
	const polledLocal, polledRemote = "192.168.1.24:50001", "198.51.100.4:443"
	start := func(sock uint64, remote string) kernelRecord {
		r := rec(recStart, 7, sock, 0, fakePID, "192.168.1.24:0", remote)
		r.Comm = "implant"
		return r
	}

	// A: opens and closes between two polls.
	m.record(start(1, briefRemote), t0)
	m.record(rec(recEstablished, tcpSynSent, 1, 10, 0, briefLocal, briefRemote), t0)
	m.record(rec(recClosed, tcpEstablished, 1, 300, 0, briefLocal, briefRemote), t0)
	evs := drain()
	if len(evs) != 1 || evs[0].Kind != "short" || evs[0].Process != "implant" || evs[0].PID != fakePID || evs[0].Remote != briefRemote {
		t.Fatalf("the brief connection: %+v", evs)
	}

	// B: its start arrives, then a poll lists it, then the rest.
	m.record(start(2, polledRemote), t0.Add(time.Second))
	m.record(rec(recEstablished, tcpSynSent, 2, 1010, 0, polledLocal, polledRemote), t0.Add(time.Second))
	listed := []gnet.ConnectionStat{tcpEst(fakePID, "192.168.1.24", 50001, "198.51.100.4", 443)}
	m.poll(listed, t0.Add(3*time.Second))
	evs = drain()
	if k := kindsOf(evs); len(evs) != 1 || k["remote"] != 1 {
		t.Fatalf("the polled connection is announced once, by the poll: %+v", evs)
	}
	m.poll(nil, t0.Add(6*time.Second))
	m.record(rec(recClosed, tcpEstablished, 2, 5000, 0, polledLocal, polledRemote), t0.Add(6*time.Second))
	evs = drain()
	if k := kindsOf(evs); len(evs) != 1 || k["closed"] != 1 {
		t.Errorf("its end is the poll's `closed`, and nothing brief: %+v", evs)
	}

	// C: established just before a poll reads the table; its records are
	// only processed after that pass. Announced by the poll, once.
	const lateLocal, lateRemote = "192.168.1.24:50002", "198.51.100.5:443"
	m.poll([]gnet.ConnectionStat{tcpEst(fakePID, "192.168.1.24", 50002, "198.51.100.5", 443)}, t0.Add(9*time.Second))
	m.record(start(3, lateRemote), t0.Add(9*time.Second))
	m.record(rec(recEstablished, tcpSynSent, 3, 8990, 0, lateLocal, lateRemote), t0.Add(9*time.Second))
	m.record(rec(recClosed, tcpEstablished, 3, 9500, 0, lateLocal, lateRemote), t0.Add(9*time.Second))
	evs = drain()
	if k := kindsOf(evs); len(evs) != 1 || k["remote"] != 1 || k["short"] != 0 {
		t.Errorf("announced by the poll and not again as brief: %+v", evs)
	}

	// Every new public address went to the reputation check, once.
	if got := strings.Join(*looked, " "); got != "203.0.113.9 198.51.100.4 198.51.100.5" {
		t.Errorf("reputation lookups: %q", got)
	}

	// Repeats of A are counted, and summarised when the window closes.
	for i := uint64(0); i < 3; i++ {
		m.record(start(10+i, briefRemote), t0.Add(10*time.Second))
		m.record(rec(recEstablished, tcpSynSent, 10+i, 10_000, 0, briefLocal, briefRemote), t0.Add(10*time.Second))
		m.record(rec(recClosed, tcpEstablished, 10+i, 10_200, 0, briefLocal, briefRemote), t0.Add(10*time.Second))
	}
	if evs = drain(); len(evs) != 0 {
		t.Errorf("repeats within the window were published: %+v", evs)
	}
	m.poll(nil, t0.Add(shortGroupWindow+12*time.Second))
	evs = drain()
	if len(evs) != 2 { // the poll's `closed` for C, and the summary
		t.Fatalf("%+v", evs)
	}
	for _, ev := range evs {
		if ev.Kind == "short" && !strings.HasPrefix(ev.Detail, "×3") {
			t.Errorf("summary: %+v", ev)
		}
	}
}
