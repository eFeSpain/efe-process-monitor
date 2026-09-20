//go:build !windows

package main

// Windows services have no equivalent here; systemd units are shown through
// the cgroup in proccontext.go instead.
func startServiceMap()              {}
func servicesOf(pid int32) []string { return nil }
