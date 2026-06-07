//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWindow makes a child process run without allocating/showing a console
// window (CREATE_NO_WINDOW), so a GUI build doesn't flash command windows.
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
