package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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
			return command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP").Run()
		}
		if hasCmd("nft") {
			ensureNft()
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
			return command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run()
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
		log.Printf("[!] Access          EXPOSED on %s over HTTPS — reachable from the network (login required)", listenAddr)
	} else {
		log.Println("[+] Access          localhost only (loopback Host enforced, CSRF-guarded)")
	}
	if authEnabled() {
		log.Println("[+] Login           ENABLED (password required)")
	} else {
		log.Println("[-] Login           disabled — anyone who reaches this port can act. Enable it in Settings if you expose it.")
	}
}
