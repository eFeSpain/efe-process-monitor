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
