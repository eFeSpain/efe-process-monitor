//go:build !linux && !windows

package main

// Rootkit cross-view probes are not implemented on this OS.
func hiddenProcs(lang string) []string { return nil }
func promiscIfaces() []string          { return nil }
