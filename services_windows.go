//go:build windows

package main

import (
	"sync"
	"time"
)

// Services hosted per process. svchost.exe is one name for dozens of
// services; the map turns "svchost.exe (pid 1234)" into "Dhcp — DHCP Client ·
// EventLog — Windows Event Log", and shows a service registered on any other
// binary the same way. Refreshed in the background, never on the request
// path: one PowerShell start-up per minute instead of one per render.
var (
	svcMu    sync.RWMutex
	svcByPID = map[int32][]string{}
)

const servicesRefresh = 60 * time.Second

func startServiceMap() {
	go func() {
		for {
			out := runCmd(30*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command",
				"Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | "+
					"ForEach-Object { \"$($_.ProcessId)`t$($_.Name)`t$($_.DisplayName)\" }")
			if m := parseServiceLines(out); len(m) > 0 {
				svcMu.Lock()
				svcByPID = m
				svcMu.Unlock()
			}
			time.Sleep(servicesRefresh)
		}
	}()
}

func servicesOf(pid int32) []string {
	svcMu.RLock()
	defer svcMu.RUnlock()
	return svcByPID[pid]
}
