//go:build !windows && !linux

package main

import (
	"log"
	"net"
	"net/http"
)

// runApp serves HTTP in the foreground (no tray on non-Windows; runs headless).
func runApp(ln net.Listener, url string) {
	log.Fatal(http.Serve(ln, rootHandler()))
}
