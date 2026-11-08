//go:build linux

package main

import (
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
