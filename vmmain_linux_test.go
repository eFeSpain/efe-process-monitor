//go:build linux

package main

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMain exists for one case: scripts/vm-kernel-test.sh boots a VM whose
// only process — PID 1 — is this test binary. There is no init system to
// have prepared anything, so the binary mounts what the kernel tests need,
// brings the loopback interface up, re-executes itself, runs, reports and
// powers the VM off.
// Run any other way, it is the ordinary test main.
func TestMain(m *testing.M) {
	if os.Getpid() != 1 {
		os.Exit(m.Run())
	}
	if os.Getenv(vmReady) == "" {
		vmPrepare()
		// Start over, now that /proc exists. Libraries inspect the system
		// when the process starts — the eBPF library reads
		// /proc/self/mountinfo once and remembers the answer — and this
		// process started before there was anything to inspect.
		_ = os.Setenv(vmReady, "1")
		err := unix.Exec(os.Args[0], os.Args, os.Environ())
		fmt.Printf("VMTEST: re-exec: %v\n", err)
	}
	code := m.Run()
	fmt.Printf("VMTEST: exit %d\n", code)
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(code) // not reached if the power-off worked
}

const vmReady = "EFEMON_VMTEST_READY"

// vmPrepare does what an init system would have done before any program ran.
func vmPrepare() {
	for _, mnt := range []struct{ src, dir, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"tracefs", "/sys/kernel/tracing", "tracefs"},
		{"tmpfs", "/tmp", "tmpfs"},
	} {
		_ = os.MkdirAll(mnt.dir, 0o755)
		if err := unix.Mount(mnt.src, mnt.dir, mnt.fs, 0, ""); err != nil {
			fmt.Printf("VMTEST: mount %s: %v\n", mnt.dir, err)
		}
	}
	_ = os.Setenv("TMPDIR", "/tmp")
	if err := loopbackUp(); err != nil {
		fmt.Printf("VMTEST: lo up: %v\n", err)
	}
}

// loopbackUp sets IFF_UP on lo; the kernel then gives it 127.0.0.1 and ::1.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
