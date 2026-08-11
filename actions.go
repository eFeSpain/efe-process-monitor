package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ensureNft creates the nftables table/set/chain/rule once (idempotent).
func ensureNft() {
	command("nft", "add", "table", "inet", "efepm").Run()
	command("nft", "add", "set", "inet", "efepm", "blocked", "{ type ipv4_addr; }").Run()
	command("nft", "add", "chain", "inet", "efepm", "out",
		"{ type filter hook output priority 0 ; }").Run()
	out, _ := command("nft", "list", "chain", "inet", "efepm", "out").Output()
	if !strings.Contains(string(out), "@blocked") {
		command("nft", "add", "rule", "inet", "efepm", "out", "ip", "daddr", "@blocked", "drop").Run()
	}
}

// isElevated reports whether the process runs with admin/root privileges.
func isElevated() bool {
	if runtime.GOOS == "windows" {
		// "net session" needs admin; succeeds silently when elevated.
		return command("net", "session").Run() == nil
	}
	return os.Geteuid() == 0
}

// blockIP adds an outbound block rule using the platform firewall.
func blockIP(ip string) error {
	switch runtime.GOOS {
	case "windows":
		return command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=eFePM block "+ip, "dir=out", "action=block", "remoteip="+ip).Run()
	case "linux":
		if hasCmd("iptables") { // works on most distros (incl. iptables-nft shim)
			// -C first: -A appends unconditionally, so blocking the same IP twice
			// used to leave two identical rules and a single unblock only removed
			// one of them, leaving the IP silently still blocked.
			if command("iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP").Run() == nil {
				return nil // already blocked
			}
			return command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP").Run()
		}
		if hasCmd("nft") {
			ensureNft()
			// nft sets are inherently idempotent: adding a member twice is a no-op.
			return command("nft", "add", "element", "inet", "efepm", "blocked", "{ "+ip+" }").Run()
		}
		return fmt.Errorf("ni iptables ni nft disponibles (¿root?)")
	case "darwin":
		return fmt.Errorf("block not supported on macOS")
	}
	return fmt.Errorf("unsupported OS")
}

// unblockIP removes the outbound block rule created by blockIP.
func unblockIP(ip string) error {
	switch runtime.GOOS {
	case "windows":
		return command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=eFePM block "+ip).Run()
	case "linux":
		if hasCmd("iptables") {
			// Delete every copy: rules added before the -C guard above existed (or
			// by hand) can be duplicated, and leaving one behind means "unblocked"
			// in the UI while the traffic is still dropped.
			var err error
			for i := 0; i < 16; i++ {
				if e := command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run(); e != nil {
					if i == 0 {
						err = e // nothing was removed at all — report it
					}
					break
				}
			}
			return err
		}
		if hasCmd("nft") {
			return command("nft", "delete", "element", "inet", "efepm", "blocked", "{ "+ip+" }").Run()
		}
		return fmt.Errorf("ni iptables ni nft disponibles (¿root?)")
	}
	return fmt.Errorf("unsupported OS")
}

// relaunchSelf starts a fresh copy of this executable (same args) with
// RESTART_WAIT set so it waits for this process to release the port, then the
// caller exits. Used by the "Restart now" action to apply a new listen address.
func relaunchSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "RESTART_WAIT=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	_ = cmd.Start()
}

// openDashboard opens the dashboard in the browser, carrying the local access
// token so that browser gets authorized. Every "open the panel" path (startup,
// tray menu, second instance) must go through here, not openBrowser, or the
// browser lands on the gate page instead of the dashboard.
func openDashboard(url string) { openBrowser(tokenURL(url, localToken)) }

// openBrowser opens the default browser at url (best effort).
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = command("open", url)
	default:
		cmd = command("xdg-open", url)
	}
	_ = cmd.Start()
}

func startupBanner() {
	log.Println("[+] eFe Process Monitor")
	if getVTKey() != "" {
		log.Println("[+] VirusTotal      configured")
	} else {
		log.Println("[-] VirusTotal      not configured (VT_API_KEY)")
	}
	if getAbuseKey() != "" {
		log.Println("[+] AbuseIPDB       configured")
	}
	info := captureInfo(false)
	if info.Tshark {
		log.Printf("[+] tshark          OK (%d interfaces) → %s \"%s\" idx %d",
			len(info.Interfaces), info.LocalIP, info.Adapter, info.Recommended)
	} else {
		log.Println("[-] tshark          not found — capture disabled")
	}
	log.Printf("[+] Live monitor    active (every %s)", monitorInterval)
	if listenExposed {
		log.Printf("[!] Access          EXPOSED on %s over HTTPS — reachable from the network (login required)", listenAddr.Load())
	} else {
		log.Println("[+] Access          localhost only (loopback Host enforced, CSRF-guarded)")
	}
	if authEnabled() {
		log.Println("[+] Login           ENABLED (password required)")
	} else {
		log.Println("[+] Login           disabled — local token gate active (only the browser this app opens can act)")
		log.Printf("[+] Token           %s", filepath.Join(appDir, tokenFile))
	}
}
