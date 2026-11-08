package main

import (
	"strings"
	"testing"
)

// The flags are the only interface a service manager or a script has to the
// binary; each one is pinned, and --service implies --no-browser because at
// boot there is nobody to open a browser for.
func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want options
	}{
		{nil, options{}},
		{[]string{"--version"}, options{Version: true}},
		{[]string{"--no-browser"}, options{NoBrowser: true}},
		{[]string{"--service"}, options{Service: true, NoBrowser: true}},
		{[]string{"--install-service"}, options{Install: true}},
		{[]string{"--uninstall-service"}, options{Uninstall: true}},
		{[]string{"--service-status"}, options{Status: true}},
	} {
		got, err := parseArgs(tc.args)
		if err != nil || got != tc.want {
			t.Errorf("parseArgs(%v) = %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
	if _, err := parseArgs([]string{"--bogus"}); err == nil || !strings.HasPrefix(err.Error(), "usage:") {
		t.Errorf("unknown flag: err=%v, want a usage error", err)
	}
	if _, err := parseArgs([]string{"--install-service", "--uninstall-service"}); err == nil {
		t.Error("install and uninstall together must be refused")
	}
}

// systemd sets INVOCATION_ID for everything it starts — including the user's
// own session, so a terminal or an editor under it inherits the variable. Only
// a system service is a direct child of PID 1; anything else with the variable
// is a user program and must not go quiet (no browser, Quit → systemctl stop).
func TestInferServiceMode(t *testing.T) {
	for _, tc := range []struct {
		flag bool
		inv  string
		ppid int
		want bool
	}{
		{true, "", 4242, true},      // explicit flag always wins
		{false, "", 1, false},       // child of PID 1 without the variable: not systemd (e.g. a container init)
		{false, "abc", 1, true},     // the service itself
		{false, "abc", 4242, false}, // a terminal under a systemd-managed session
	} {
		if got := inferServiceMode(tc.flag, tc.inv, tc.ppid); got != tc.want {
			t.Errorf("inferServiceMode(%v,%q,%d) = %v, want %v", tc.flag, tc.inv, tc.ppid, got, tc.want)
		}
	}
}
