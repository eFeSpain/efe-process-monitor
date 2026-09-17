//go:build linux

package main

import (
	"strings"
	"testing"
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
