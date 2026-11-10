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

// hasCmd reports whether a tool is on PATH. A variable so the firewall tests
// can say which tools exist.
var hasCmd = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// fwRun / fwOutput run one firewall command. Variables so the tests can
// record what would be executed: the real thing needs root and changes the
// machine's firewall.
var (
	fwRun    = func(name string, args ...string) error { return command(name, args...).Run() }
	fwOutput = func(name string, args ...string) ([]byte, error) { return command(name, args...).Output() }
)

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

// ensureNft creates the nftables table, one set per address family, one chain
// per direction and their rules, once (every command is idempotent).
func ensureNft() {
	_ = fwRun("nft", "add", "table", "inet", "efepm")
	_ = fwRun("nft", "add", "set", "inet", "efepm", "blocked", "{ type ipv4_addr; }")
	_ = fwRun("nft", "add", "set", "inet", "efepm", "blocked6", "{ type ipv6_addr; }")
	for _, c := range []struct{ chain, hook, field string }{
		{"out", "output", "daddr"},
		{"in", "input", "saddr"},
	} {
		_ = fwRun("nft", "add", "chain", "inet", "efepm", c.chain,
			"{ type filter hook "+c.hook+" priority 0 ; }")
		out, _ := fwOutput("nft", "list", "chain", "inet", "efepm", c.chain)
		// "@blocked6" contains "@blocked", so the v4 rule is looked up as a whole word.
		if !strings.Contains(string(out)+" ", c.field+" @blocked ") {
			_ = fwRun("nft", "add", "rule", "inet", "efepm", c.chain, "ip", c.field, "@blocked", "drop")
		}
		if !strings.Contains(string(out), "@blocked6") {
			_ = fwRun("nft", "add", "rule", "inet", "efepm", c.chain, "ip6", c.field, "@blocked6", "drop")
		}
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

// iptablesBlockRules are the two rules of a block, as "CHAIN match… -j DROP":
// what this machine sends to the address, and what the address sends here.
func iptablesBlockRules(ip string) [][]string {
	return [][]string{
		{"OUTPUT", "-d", ip, "-j", "DROP"},
		{"INPUT", "-s", ip, "-j", "DROP"},
	}
}

// blockIP blocks an address at the platform firewall, in both directions.
// Outbound alone left a blocked host free to connect to anything listening
// here.
func blockIP(ip string) error { return blockIPOn(runtime.GOOS, ip) }

func blockIPOn(goos, ip string) error {
	switch goos {
	case "windows":
		// Same name for both rules: one delete by name removes the pair.
		for _, dir := range []string{"out", "in"} {
			if err := fwRun("netsh", "advfirewall", "firewall", "add", "rule",
				"name=eFePM block "+ip, "dir="+dir, "action=block", "remoteip="+ip); err != nil {
				return err
			}
		}
		return nil
	case "linux":
		if ipt := iptablesFor(ip); hasCmd(ipt) { // works on most distros (incl. iptables-nft shim)
			for _, rule := range iptablesBlockRules(ip) {
				// -C first: blocking the same IP twice used to leave two
				// identical rules and a single unblock only removed one of
				// them, leaving the IP silently still blocked.
				if fwRun(ipt, append([]string{"-C"}, rule...)...) == nil {
					continue // already there
				}
				// -I … 1, not -A: an appended rule sits after the chains that
				// ufw and friends hook into INPUT/OUTPUT, which accept new and
				// established connections before the DROP is ever reached.
				insert := append([]string{"-I", rule[0], "1"}, rule[1:]...)
				if err := fwRun(ipt, insert...); err != nil {
					return err
				}
			}
			return nil
		}
		if hasCmd("nft") {
			ensureNft()
			// nft sets are inherently idempotent: adding a member twice is a no-op.
			return fwRun("nft", "add", "element", "inet", "efepm", nftSetFor(ip), "{ "+ip+" }")
		}
		return fmt.Errorf("%s", strings_(currentLang())["no_fw_tool"])
	case "darwin":
		return fmt.Errorf("block not supported on macOS")
	}
	return fmt.Errorf("unsupported OS")
}

// unblockIP removes the rules created by blockIP.
func unblockIP(ip string) error { return unblockIPOn(runtime.GOOS, ip) }

func unblockIPOn(goos, ip string) error {
	switch goos {
	case "windows":
		return fwRun("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=eFePM block "+ip)
	case "linux":
		if ipt := iptablesFor(ip); hasCmd(ipt) {
			// Delete every copy: rules added before the -C guard existed (or by
			// hand) can be duplicated, and leaving one behind means "unblocked"
			// in the UI while the traffic is still dropped. A block made by an
			// earlier version has no inbound rule; that is not an error — only
			// removing nothing at all is.
			var first error
			removed := 0
			for _, rule := range iptablesBlockRules(ip) {
				for i := 0; i < 16; i++ {
					if err := fwRun(ipt, append([]string{"-D"}, rule...)...); err != nil {
						if first == nil {
							first = err
						}
						break
					}
					removed++
				}
			}
			if removed == 0 {
				return first
			}
			return nil
		}
		if hasCmd("nft") {
			return fwRun("nft", "delete", "element", "inet", "efepm", nftSetFor(ip), "{ "+ip+" }")
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
	if getAbuseChKey() != "" {
		log.Println("[+] abuse.ch        Auth-Key configured (ThreatFox API)")
	} else {
		log.Println("[-] abuse.ch        no Auth-Key (ABUSECH_API_KEY) — ThreatFox off; the feed status is logged after priming")
	}
	info := captureInfo(false)
	if info.Tshark {
		log.Printf("[+] tshark          OK (%d interfaces) → %s \"%s\" idx %d",
			len(info.Interfaces), info.LocalIP, info.Adapter, info.Recommended)
	} else {
		log.Println("[-] tshark          not found — capture disabled")
	}
	log.Printf("[+] Live monitor    active (every %s)", monitorInterval)
	switch {
	case serviceMode && desktopSessionName() != "":
		log.Printf("[+] Mode            systemd service (desktop session: user %s)", desktopSessionName())
	case serviceMode:
		log.Println("[+] Mode            systemd service (desktop session: waiting — the tray attaches at login)")
	default:
		log.Println("[+] Mode            manual")
	}
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
