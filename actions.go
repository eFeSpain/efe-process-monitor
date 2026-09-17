package main

import (
	"fmt"
	"log"
	"net"
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

// ensureSbinPath adds the sbin directories to this process's PATH on Linux.
// nft, iptables, ss and ufw live there, and a user shell's PATH usually does
// not include them — so the audit reported "ufw not installed, check
// nft/iptables by hand" on a box where nft was one directory away, and the
// hidden-ports check fell back to netstat. Affects only this process.
func ensureSbinPath() {
	if runtime.GOOS != "linux" {
		return
	}
	path := os.Getenv("PATH")
	for _, d := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(":"+path+":", ":"+d+":") {
			path += ":" + d
		}
	}
	os.Setenv("PATH", path)
}

// isIPv6 reports whether ip is an IPv6 literal. The Linux firewall tools are
// split by family: iptables and an ipv4_addr nft set silently reject a v6
// address, which used to make "Block IP" fail for every IPv6 peer.
func isIPv6(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && a.To4() == nil
}

// iptablesFor is the iptables binary for the address family.
func iptablesFor(ip string) string {
	if isIPv6(ip) {
		return "ip6tables"
	}
	return "iptables"
}

// nftSetFor is the nft set for the address family (see ensureNft).
func nftSetFor(ip string) string {
	if isIPv6(ip) {
		return "blocked6"
	}
	return "blocked"
}

// ensureNft creates the nftables table, one set per address family, the chain
// and its two rules, once (every command is idempotent).
func ensureNft() {
	command("nft", "add", "table", "inet", "efepm").Run()
	command("nft", "add", "set", "inet", "efepm", "blocked", "{ type ipv4_addr; }").Run()
	command("nft", "add", "set", "inet", "efepm", "blocked6", "{ type ipv6_addr; }").Run()
	command("nft", "add", "chain", "inet", "efepm", "out",
		"{ type filter hook output priority 0 ; }").Run()
	out, _ := command("nft", "list", "chain", "inet", "efepm", "out").Output()
	// "@blocked6" contains "@blocked", so the v4 rule is looked up as a whole word.
	if !strings.Contains(string(out), "daddr @blocked ") {
		command("nft", "add", "rule", "inet", "efepm", "out", "ip", "daddr", "@blocked", "drop").Run()
	}
	if !strings.Contains(string(out), "@blocked6") {
		command("nft", "add", "rule", "inet", "efepm", "out", "ip6", "daddr", "@blocked6", "drop").Run()
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
		if ipt := iptablesFor(ip); hasCmd(ipt) { // works on most distros (incl. iptables-nft shim)
			// -C first: -A appends unconditionally, so blocking the same IP twice
			// used to leave two identical rules and a single unblock only removed
			// one of them, leaving the IP silently still blocked.
			if command(ipt, "-C", "OUTPUT", "-d", ip, "-j", "DROP").Run() == nil {
				return nil // already blocked
			}
			return command(ipt, "-A", "OUTPUT", "-d", ip, "-j", "DROP").Run()
		}
		if hasCmd("nft") {
			ensureNft()
			// nft sets are inherently idempotent: adding a member twice is a no-op.
			return command("nft", "add", "element", "inet", "efepm", nftSetFor(ip), "{ "+ip+" }").Run()
		}
		return fmt.Errorf("%s", strings_(currentLang())["no_fw_tool"])
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
		if ipt := iptablesFor(ip); hasCmd(ipt) {
			// Delete every copy: rules added before the -C guard above existed (or
			// by hand) can be duplicated, and leaving one behind means "unblocked"
			// in the UI while the traffic is still dropped.
			var err error
			for i := 0; i < 16; i++ {
				if e := command(ipt, "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run(); e != nil {
					if i == 0 {
						err = e // nothing was removed at all — report it
					}
					break
				}
			}
			return err
		}
		if hasCmd("nft") {
			return command("nft", "delete", "element", "inet", "efepm", nftSetFor(ip), "{ "+ip+" }").Run()
		}
		return fmt.Errorf("%s", strings_(currentLang())["no_fw_tool"])
	}
	return fmt.Errorf("unsupported OS")
}

// reapplyBlocks re-creates the firewall rules for the persisted blocks. netsh
// rules on Windows survive a reboot; iptables/nft rules do not, so on Linux a
// "permanent" block was only permanent in the panel — the IP showed as blocked
// while the traffic flowed. Called once at startup, after elevation is known.
func reapplyBlocks() {
	if runtime.GOOS != "linux" {
		return
	}
	blocked := listBlocked()
	if len(blocked) == 0 {
		return
	}
	if !elevated {
		log.Printf("[!] Bloqueos        %d IPs persistidas NO reaplicadas al firewall: requiere root", len(blocked))
		return
	}
	ok := 0
	for _, b := range blocked {
		if err := blockIP(b.IP); err != nil {
			log.Printf("[!] Bloqueos        no se pudo reaplicar %s: %v", b.IP, err)
			continue
		}
		ok++
	}
	log.Printf("[+] Bloqueos        %d/%d IPs persistidas reaplicadas al firewall", ok, len(blocked))
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
		// As root there is no display in our environment and the browser would
		// run as root anyway; hand it to the logged-in user's session.
		runAsDesktopUser(cmd)
	}
	_ = cmd.Start()
}

func startupBanner() {
	log.Printf("[+] eFe Process Monitor v%s", appVersion)
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
	if strings.HasPrefix(passiveDNSStatus, "activo") {
		log.Printf("[+] DNS pasivo      %s", passiveDNSStatus)
	} else {
		log.Printf("[-] DNS pasivo      %s", passiveDNSStatus)
	}
	if listenExposed {
		log.Printf("[!] Access          EXPOSED on %s over HTTPS — reachable from the network (login required)", listenAddr.Load())
	} else {
		log.Println("[+] Access          localhost only (loopback Host enforced, CSRF-guarded)")
	}
	if authEnabled() {
		log.Println("[+] Login           ENABLED (password required)")
	} else {
		log.Println("[+] Login           disabled — local token gate active (only the browser this app opens can act)")
		tp := filepath.Join(appDir, tokenFile)
		log.Printf("[+] Token           %s", tp)
		// Print who can read it: this is the whole strength of the local gate, and
		// on Windows it silently depends on whether we are elevated.
		log.Printf("[+] Token ACL       %s", describeFileACL(tp))
		if runtime.GOOS == "windows" && !elevated {
			log.Println("[!] Token ACL       sin elevación solo se puede restringir al propio usuario:")
			log.Println("[!]                 otro proceso del mismo usuario aún podría leer el token.")
		}
	}
	if logPath != "" {
		log.Printf("[+] Log             %s (rota a %d MiB, %d archivos)", logPath, logMaxBytes>>20, logKeep)
	} else {
		log.Println("[-] Log             solo consola — no se pudo escribir el fichero de log")
	}
}
