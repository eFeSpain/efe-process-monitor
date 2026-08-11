//go:build !windows && !linux

package main

import (
	"log"
	"net"
)

// runApp serves HTTP in the foreground (no tray on non-Windows; runs headless).
func runApp(ln net.Listener, url string) {
	log.Fatal(newServer().Serve(ln))
}
