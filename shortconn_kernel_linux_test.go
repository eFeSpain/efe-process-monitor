//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
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
}

// The program reads the tracepoint's record at fixed offsets. They are part
// of a stable kernel interface, and this pins them on every kernel the tests
// run on: if one ever moved, this fails before anything misreads a field.
func TestKernelTracepointExists(t *testing.T) {
	requireKernelTest(t)
	var format []byte
	var err error
	for _, p := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if format, err = os.ReadFile(p + "/events/sock/inet_sock_set_state/format"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("tracepoint sock:inet_sock_set_state not found: %v", err)
	}
	for _, field := range []string{
		"skaddr;\toffset:8;", "oldstate;\toffset:16;", "newstate;\toffset:20;",
		"sport;\toffset:24;", "dport;\toffset:26;", "family;\toffset:28;", "protocol;\toffset:30;",
		"saddr[4];\toffset:32;", "daddr[4];\toffset:36;", "saddr_v6[16];\toffset:40;", "daddr_v6[16];\toffset:56;",
	} {
		if !strings.Contains(string(format), field) {
			t.Errorf("tracepoint layout: %q not found in\n%s", field, format)
		}
	}
}
