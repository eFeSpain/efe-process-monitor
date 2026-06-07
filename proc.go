package main

import (
	"context"
	"os/exec"
)

// command / commandContext wrap exec.Command and suppress the console window of
// child processes on Windows: the app ships as a GUI binary (no console), so
// every console subprocess (netsh, powershell, tshark, arp…) would otherwise pop
// a command window. hideWindow is a no-op on non-Windows platforms.
func command(name string, arg ...string) *exec.Cmd {
	c := exec.Command(name, arg...)
	hideWindow(c)
	return c
}

func commandContext(ctx context.Context, name string, arg ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, name, arg...)
	hideWindow(c)
	return c
}
