//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Root under sudo has no graphical session in its environment; the browser,
// the notifications and the tray are handed to the invoking user's. The
// candidate order decides which user that is, and a wrong pick is worse than
// none.
func TestDesktopUserCandidates(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		run  []string
		want string
	}{
		{"sudo", map[string]string{"SUDO_UID": "1000"}, []string{"1000", "1001"}, "1000"},
		{"pkexec", map[string]string{"PKEXEC_UID": "1001"}, []string{"1000", "1001"}, "1001"},
		{"sudo wins over pkexec", map[string]string{"SUDO_UID": "1000", "PKEXEC_UID": "1001"}, nil, "1000,1001"},
		{"sudo as root itself is not a user", map[string]string{"SUDO_UID": "0"}, []string{"1000"}, "1000"},
		{"su -: the only logged-in user", map[string]string{}, []string{"0", "1000"}, "1000"},
		{"su -: two users is a guess we do not make", map[string]string{}, []string{"1000", "1001"}, ""},
		// The display manager's greeter (sddm, gdm: system uids) has a bus and a
		// display too; at boot it is the only "session" for a while and the
		// service tried to put the tray there. System accounts are not users.
		{"greeter plus the user at login", map[string]string{}, []string{"111", "1000"}, "1000"},
		{"greeter alone before login", map[string]string{}, []string{"111"}, ""},
		{"nothing", map[string]string{}, nil, ""},
	} {
		got := strings.Join(desktopUserCandidates(env(tc.env), tc.run), ",")
		if got != tc.want {
			t.Errorf("%s: candidates = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The child gets the session's display and bus and nothing else — in
// particular none of the variables sudo set for root.
func TestSessionEnvFrom(t *testing.T) {
	environ := []byte("SHELL=/bin/bash\x00WAYLAND_DISPLAY=wayland-0\x00DISPLAY=:1\x00" +
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\x00SUDO_COMMAND=/bin/ls\x00" +
		"XAUTHORITY=/run/user/1000/xauth_abc\x00HOME=/home/efe\x00NOEQUALS\x00LS_COLORS=rs=0:di=01\x00")
	got := sessionEnvFrom(environ)
	for _, want := range []string{"WAYLAND_DISPLAY=wayland-0", "DISPLAY=:1",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XAUTHORITY=/run/user/1000/xauth_abc", "HOME=/home/efe"} {
		if !hasKey(got, strings.SplitN(want, "=", 2)[0]) || !strings.Contains(strings.Join(got, "\n"), want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for _, drop := range []string{"SHELL", "SUDO_COMMAND", "LS_COLORS"} {
		if hasKey(got, drop) {
			t.Errorf("%s should not be passed to the session child: %v", drop, got)
		}
	}
	if len(got) != 5 {
		t.Errorf("expected exactly 5 variables, got %d: %v", len(got), got)
	}
}

// In service mode nobody launched us from a session: the watcher polls for one,
// records it as the current session as soon as it exists (notifications and
// "open panel" work from then on, tray or not), spawns the tray helper exactly
// once, and when the session ends it kills the helper and starts over.
func TestSessionWatcherSessionLifecycle(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	var cur *desktopSession
	var spawns, kills int
	done := make(chan struct{})
	w := &sessionWatcher{
		probe: func() *desktopSession { return cur },
		alive: func(s *desktopSession) bool { return cur != nil && cur.uid == s.uid },
		spawn: func(s *desktopSession) (<-chan struct{}, func(), bool) {
			spawns++
			return done, func() { kills++; close(done) }, true
		},
	}
	t0 := time.Now()
	w.tick(t0)
	if spawns != 0 || w.session() != nil {
		t.Fatal("no session: nothing to record, nothing to spawn")
	}
	cur = sess
	for i := 1; i <= 3; i++ {
		w.tick(t0.Add(time.Duration(i) * 5 * time.Second))
	}
	if spawns != 1 || w.session() != sess {
		t.Fatalf("one session → exactly one helper, got %d (current=%v)", spawns, w.session())
	}
	cur = nil // logout: the session bus is gone; the helper does not exit by itself
	w.tick(t0.Add(20 * time.Second))
	if kills != 1 {
		t.Fatalf("logout must kill the lingering helper, kills=%d", kills)
	}
	w.tick(t0.Add(25 * time.Second))
	if w.session() != nil {
		t.Fatal("after logout there is no current session")
	}
	done = make(chan struct{})
	cur = sess // login again
	w.tick(t0.Add(30 * time.Second))
	if spawns != 2 || w.session() != sess {
		t.Fatalf("login after logout → new helper, got %d spawns", spawns)
	}
}

// A desktop whose tray host is not up yet (Plasma registers the
// StatusNotifierWatcher seconds after WAYLAND_DISPLAY exists) or absent (GNOME
// without the extension) answers "notray". The session is still current — the
// notifications must not die with the icon — and the helper is retried with a
// growing backoff, never every tick.
func TestSessionWatcherNoTrayKeepsSessionAndRetriesWithBackoff(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	var spawns int
	w := &sessionWatcher{
		probe: func() *desktopSession { return sess },
		alive: func(*desktopSession) bool { return true },
		spawn: func(*desktopSession) (<-chan struct{}, func(), bool) { spawns++; return nil, nil, false },
	}
	t0 := time.Now()
	for i := 0; i < 3; i++ {
		w.tick(t0.Add(time.Duration(i) * 5 * time.Second))
	}
	if spawns != 1 {
		t.Fatalf("notray must not be retried every tick, got %d spawns in 10 s", spawns)
	}
	if w.session() != sess {
		t.Fatal("a session without a tray is still the session: notifications go there")
	}
	w.tick(t0.Add(helperBackoff(0) + time.Second))
	if spawns != 2 {
		t.Fatalf("first retry after %s, got %d spawns", helperBackoff(0), spawns)
	}
	w.tick(t0.Add(helperBackoff(0) + helperBackoff(1) + 2*time.Second))
	if spawns != 3 {
		t.Fatalf("second retry after a longer wait, got %d spawns", spawns)
	}
	for n, want := range map[int]time.Duration{0: 15 * time.Second, 1: 30 * time.Second, 2: time.Minute, 3: 5 * time.Minute, 9: 5 * time.Minute} {
		if got := helperBackoff(n); got != want {
			t.Errorf("helperBackoff(%d) = %s, want %s", n, got, want)
		}
	}
}

// A helper that exits while the session is still there (crash, killed by hand)
// is respawned — after the backoff, not immediately.
func TestSessionWatcherRespawnsAfterHelperExit(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	var spawns int
	var done chan struct{}
	w := &sessionWatcher{
		probe: func() *desktopSession { return sess },
		alive: func(*desktopSession) bool { return true },
		spawn: func(*desktopSession) (<-chan struct{}, func(), bool) {
			spawns++
			done = make(chan struct{})
			return done, func() {}, true
		},
	}
	t0 := time.Now()
	w.tick(t0)
	close(done) // helper died
	w.tick(t0.Add(5 * time.Second))
	w.tick(t0.Add(10 * time.Second))
	if spawns != 1 {
		t.Fatalf("a dead helper must not be respawned on the next tick, got %d", spawns)
	}
	w.tick(t0.Add(helperBackoff(0) + 6*time.Second))
	if spawns != 2 || w.session() != sess {
		t.Fatalf("respawn after the backoff, got %d spawns", spawns)
	}
}

// desktopUser() is read from notification goroutines while tick() may be
// inside probe() (a /proc scan) or spawn() (a 5 s handshake): the lock must
// cover the state, not the slow calls.
func TestSessionWatcherDoesNotBlockReadersDuringSpawn(t *testing.T) {
	sess := &desktopSession{uid: 1000, name: "efe"}
	release := make(chan struct{})
	w := &sessionWatcher{
		probe: func() *desktopSession { return sess },
		alive: func(*desktopSession) bool { return true },
		spawn: func(*desktopSession) (<-chan struct{}, func(), bool) {
			<-release
			return make(chan struct{}), func() {}, true
		},
	}
	go w.tick(time.Now())
	got := make(chan *desktopSession, 1)
	go func() { got <- w.session() }()
	select {
	case <-got:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("session() blocked behind a spawn in progress")
	}
	close(release)
}

// The production probe scans every process's environ. With a uid that has a
// bus but no graphical session (an SSH login), scanning every 5 s forever is
// waste: rescan when the set of uids changes, otherwise at most every 30 s.
func TestSessionProbeRateLimit(t *testing.T) {
	var p sessionProbe
	t0 := time.Now()
	if !p.shouldScan([]string{"1000"}, t0) {
		t.Fatal("first sight of a uid must scan")
	}
	if p.shouldScan([]string{"1000"}, t0.Add(5*time.Second)) || p.shouldScan([]string{"1000"}, t0.Add(25*time.Second)) {
		t.Error("same uids, under 30 s: no rescan")
	}
	if !p.shouldScan([]string{"1000"}, t0.Add(31*time.Second)) {
		t.Error("same uids after 30 s: rescan")
	}
	if !p.shouldScan([]string{"1000", "1001"}, t0.Add(32*time.Second)) {
		t.Error("a new uid must scan at once")
	}
	if p.shouldScan(nil, t0.Add(33*time.Second)) {
		t.Error("no uids: nothing to scan")
	}
}

// Before the watcher exists (the banner runs first) service mode has no
// session and must not fall back to the sudo-style resolve-once scan.
func TestDesktopUserServiceModeWithoutWatcher(t *testing.T) {
	old, oldW := serviceMode, watcher.Load()
	serviceMode = true
	watcher.Store(nil)
	t.Cleanup(func() { serviceMode = old; watcher.Store(oldW) })
	if desktopUser() != nil || desktopSessionName() != "" {
		t.Error("service mode without a watcher: no session")
	}
}

// --install-service from the CLI while another efemon is running would rename
// the database out from under it; the running instances are reported so the
// operator stops them (or installs from that instance's Settings).
func TestOtherInstancesExcludesSelf(t *testing.T) {
	for _, pid := range otherInstances() {
		if pid == ownPID {
			t.Fatal("our own process is not another instance")
		}
	}
}

func TestLoginDefsUIDMin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "login.defs")
	os.WriteFile(p, []byte("# comment\nUID_MIN                  500\nUID_MAX 60000\n"), 0o644)
	if got := loginDefsUIDMin(p); got != 500 {
		t.Errorf("UID_MIN = %d, want 500", got)
	}
	if got := loginDefsUIDMin(filepath.Join(dir, "missing")); got != 1000 {
		t.Errorf("missing file → %d, want the 1000 default", got)
	}
}
