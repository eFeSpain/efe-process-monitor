//go:build !linux

package main

import "os/exec"

// The root/desktop-user split only exists on Linux (see desktop_linux.go):
// Windows elevation keeps the interactive session, and macOS has no tray here.

func runAsDesktopUser(cmd *exec.Cmd) bool { return false }
func trayHelperMain() bool                { return false }
