//go:build !linux

package main

// Open files and memory maps of another process have no reliable cgo-free
// source on Windows, and macOS is not a target. Nothing is reported rather
// than something guessed.
func scanProcess(pid int32, name string) *procScan { return nil }

type procScan struct {
	files   []string
	scored  int
	media   []string
	execMap []string
}
