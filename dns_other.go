//go:build !linux && !windows

package main

// No passive DNS source here: macOS has neither AF_PACKET nor a readable
// resolver cache without a helper, and macOS is not a supported target.
func startPassiveDNS() { passiveDNSStatus = "no disponible en este sistema" }
