package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"syscall"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Signature is the Authenticode result for a binary.
type Signature struct {
	Status  string
	Signer  string
	Trusted bool
}

// ProcConn is one active TCP connection of a process.
type ProcConn struct {
	LocalIP    string
	LocalPort  uint32
	RemoteIP   string
	RemotePort uint32
}

// ProcDetails is the expandable per-process info block.
type ProcDetails struct {
	PPID       int32
	ParentName string
	Cmdline    string
	CreateTime string
	IORead     uint64
	IOWrite    uint64
	IOok       bool
	Conns      []ProcConn
	TotalConns int
	Err        string
}

// Conn is one analyzed connection row shown in the UI.
type Conn struct {
	Threat      int
	Port        uint32
	LocalIP     string
	RPort       uint32
	RemoteIP    string
	PID         int32
	Process     string
	Status      string
	Exe         string
	Known       string
	VT          string
	Undetected  string
	Cached      bool
	Suspicious  bool
	SuspPort    bool
	Blockable   bool
	Capturable  bool // has a public remote peer, so tshark has something to filter on
	Sig         Signature
	Whitelist   bool
	IPWhitelist bool
	Partial     bool // key signals (VT/enrichment) couldn't be resolved → low score ≠ clean
	Enrich      *Enrichment
	LAN         *LANInfo
	Details     *ProcDetails
	Breakdown   string
	RemoteIPs   []string // unique blockable remote IPs of this connection's process
}

// getProcDetails fills per-process info. The process's active connections come
// from pidConns (built once from the global snapshot) — far cheaper than calling
// p.Connections() per PID.
func getProcDetails(pid int32, pidConns map[int32][]ProcConn) *ProcDetails {
	d := &ProcDetails{ParentName: "N/A", Cmdline: "N/A", CreateTime: "N/A"}
	p, err := process.NewProcess(pid)
	if err != nil {
		d.Err = "process not found"
		return d
	}
	if ppid, err := p.Ppid(); err == nil {
		d.PPID = ppid
		if par, err := process.NewProcess(ppid); err == nil {
			if n, err := par.Name(); err == nil {
				d.ParentName = n
			}
		}
	}
	if cl, err := p.Cmdline(); err == nil && cl != "" {
		d.Cmdline = cl
	}
	if ct, err := p.CreateTime(); err == nil {
		d.CreateTime = time.UnixMilli(ct).Format("2006-01-02 15:04:05")
	}
	if io, err := p.IOCounters(); err == nil {
		d.IORead, d.IOWrite, d.IOok = io.ReadBytes, io.WriteBytes, true
	}
	d.Conns = pidConns[pid]
	d.TotalConns = len(d.Conns)
	return d
}

// ownPID is this process, so we can hide the monitor's own API traffic.
var ownPID = int32(os.Getpid())

var suspiciousPaths = []string{
	// Windows
	`\appdata\local\temp`, `\users\public`, `\programdata`,
	`\windows\temp`, `\downloads`, `\recycle`,
	// Linux — executables in temp/shared-memory locations are a strong malware signal
	`/tmp/`, `/var/tmp/`, `/dev/shm/`, `/downloads`,
}

// portLabel resolves a protocol label for the connection. Known malware/C2 ports
// win (and flag it); otherwise a standard service name; else "—".
func portLabel(lport, rport uint32) (string, bool) {
	for _, p := range [2]uint32{lport, rport} {
		if p != 0 {
			if name, ok := suspiciousPorts[p]; ok {
				return name, true
			}
		}
	}
	if name, ok := knownPorts[lport]; ok {
		return name, false
	}
	if rport != 0 {
		if name, ok := knownPorts[rport]; ok {
			return name, false
		}
	}
	return "—", false
}

func isSuspiciousPath(p string) bool {
	if p == "" || p == "N/A" || p == "ACCESS_DENIED" {
		return false
	}
	lp := strings.ToLower(p)
	for _, s := range suspiciousPaths {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return true
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

// isBlockable reports whether an IP makes sense to block at the firewall: a real
// LAN or public address. Excludes 0.0.0.0/::, loopback, multicast and broadcast.
func isBlockable(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil || a.IsUnspecified() || a.IsLoopback() ||
		a.IsMulticast() || a.IsLinkLocalMulticast() || a.Equal(net.IPv4bcast) {
		return false
	}
	return true
}

func isLoopback(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && a.IsLoopback()
}

// ── TCP/UDP socket classification ────────────────────────────────────────────
//
// gopsutil never reports "LISTEN" or "ESTABLISHED" for datagram sockets: on
// Linux it hardcodes Status "NONE", and on Windows the UDP row conversion never
// sets Status at all. Filtering on those two labels — which is what this code
// used to do — silently dropped *every* UDP socket from the table, the live
// monitor, the history and the audit's cross-view. That hid QUIC/HTTP3 on 443,
// DNS traffic and any UDP-based C2, and it made the audit report every open UDP
// port as a "hidden listening port" because the netstat/ss side does list them.

// isUDP reports whether a socket is a datagram socket.
func isUDP(c gnet.ConnectionStat) bool { return c.Type == uint32(syscall.SOCK_DGRAM) }

// trackConn reports whether a socket belongs in the dashboard: for TCP only the
// two interesting states, for UDP always (there are no states to filter on).
func trackConn(c gnet.ConnectionStat) bool {
	if isUDP(c) {
		return true
	}
	return c.Status == "LISTEN" || c.Status == "ESTABLISHED"
}

// connStatus is the label shown in the State column. UDP is split into "peered"
// (has a remote address, e.g. QUIC) and a plain bound socket.
func connStatus(c gnet.ConnectionStat) string {
	if isUDP(c) {
		if c.Raddr.IP != "" {
			return "UDP"
		}
		return "UDP-BOUND"
	}
	return c.Status
}

// ── File hash (cached by path+mtime+size) ────────────────────────────────────

type hashEntry struct {
	mtime int64
	size  int64
	hash  string
}

var (
	hashMu    sync.Mutex
	hashCache = map[string]hashEntry{}
)

// maxPathCache bounds the path-keyed caches (file hashes, signatures). The number
// of distinct binaries on a machine is naturally limited, but paths under temp
// directories churn, so an unbounded map would drift upwards forever.
const maxPathCache = 8192

// capMap drops everything once a map outgrows its bound. Crude but adequate: both
// caches are backed by SQLite, so a reset costs a re-read, not a re-scan.
func capMap[V any](m map[string]V, max int) {
	if len(m) > max {
		clear(m)
	}
}

func fileHash(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	hashMu.Lock()
	if e, ok := hashCache[path]; ok && e.mtime == fi.ModTime().UnixNano() && e.size == fi.Size() {
		hashMu.Unlock()
		return e.hash
	}
	hashMu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	hashMu.Lock()
	capMap(hashCache, maxPathCache)
	hashCache[path] = hashEntry{fi.ModTime().UnixNano(), fi.Size(), sum}
	hashMu.Unlock()
	return sum
}

// ── VirusTotal hash verdict ──────────────────────────────────────────────────

// analyzeExe returns (cached, vtResult, undetected). Uncached hashes are queued
// for background resolution (rate-limited to 4/min) and reported as PENDING, so
// the page render never blocks on VirusTotal.
func analyzeExe(exe string) (bool, string, string) {
	if exe == "" || exe == "N/A" || exe == "ACCESS_DENIED" {
		return false, "N/A", ""
	}
	h := fileHash(exe)
	if h == "" {
		return false, "no_hash", ""
	}
	if score, ok := dbCachedHash(h); ok {
		if score == "NOT_IN_VT" {
			return true, "NOT_IN_VT", ""
		}
		parts := strings.SplitN(score, "/", 2)
		und := ""
		if len(parts) > 1 {
			und = parts[1]
		}
		return true, parts[0], und
	}
	if getVTKey() == "" {
		return false, "N/A", ""
	}
	enqueueHash(h) // resolved in the background by vtWorker
	return false, "PENDING", ""
}

// ── Authenticode signatures (Windows, PowerShell batch, cached by mtime) ─────

type sigEntry struct {
	mtime int64
	sig   Signature
}

var (
	sigMu    sync.Mutex
	sigCache = map[string]sigEntry{}
)

// checkSignatures returns the signature for each path from cache, queueing
// anything unknown for background resolution.
//
// It used to resolve inline, which meant the HTTP handler waited on a PowerShell
// start-up (Windows) or on one `dpkg -S` per path at 5s each, sequentially
// (Linux) — tens of seconds of page render for a machine with many new binaries.
// Unknown entries now report PENDING and appear on the next refresh, exactly like
// the VirusTotal hash lookups already did.
func checkSignatures(paths []string) map[string]Signature {
	out := map[string]Signature{}
	for _, p := range paths {
		if p == "" || p == "N/A" || p == "ACCESS_DENIED" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		mtime := fi.ModTime().UnixNano()
		sigMu.Lock()
		e, ok := sigCache[p]
		sigMu.Unlock()
		if ok && e.mtime == mtime {
			out[p] = e.sig
			continue
		}
		if s, ok := dbCachedSignature(p, mtime); ok { // L2: survives restarts
			out[p] = s
			sigMu.Lock()
			sigCache[p] = sigEntry{mtime, s}
			sigMu.Unlock()
			continue
		}
		out[p] = Signature{Status: sigPendingStatus}
		enqueueSig(p)
	}
	return out
}

// sigPendingStatus marks a signature that hasn't been resolved yet. It must be
// treated as "no information" by the score, never as a bad signature.
const sigPendingStatus = "PENDING"

var (
	sigQueue      = make(chan string, 4096)
	sigInProgress sync.Map // path -> struct{}, avoids duplicate queue entries
)

func enqueueSig(path string) {
	if _, loaded := sigInProgress.LoadOrStore(path, struct{}{}); loaded {
		return
	}
	select {
	case sigQueue <- path:
	default:
		sigInProgress.Delete(path) // queue full; a later render re-enqueues
	}
}

// sigWorker resolves queued signatures in batches, so one PowerShell start-up
// covers up to sigBatch binaries instead of one each.
func sigWorker() {
	const sigBatch = 32
	for path := range sigQueue {
		batch := []string{path}
	drain:
		for len(batch) < sigBatch {
			select {
			case p := <-sigQueue:
				batch = append(batch, p)
			default:
				break drain
			}
		}
		resolveSignatures(batch)
		for _, p := range batch {
			sigInProgress.Delete(p)
		}
	}
}

// resolveSignatures queries the platform for each path and persists the verdict.
func resolveSignatures(paths []string) {
	var queried map[string]Signature
	if runtime.GOOS == "windows" {
		queried = queryAuthenticode(paths) // Authenticode
	} else {
		queried = queryProvenance(paths) // package provenance (Linux/macOS)
	}
	for p, s := range queried {
		if fi, err := os.Stat(p); err == nil {
			mtime := fi.ModTime().UnixNano()
			sigMu.Lock()
			capMap(sigCache, maxPathCache)
			sigCache[p] = sigEntry{mtime, s}
			sigMu.Unlock()
			dbSaveSignature(p, mtime, s) // L2: persist across restarts
		}
	}
}

// queryProvenance is the Unix analog of Authenticode: it asks the system package
// manager whether each binary belongs to an installed package (distro-managed =
// trusted). Unmanaged binaries stay neutral — many are legitimate (snap/flatpak,
// /opt, self-built); the suspicious-path heuristic covers the dangerous locations.
func queryProvenance(paths []string) map[string]Signature {
	out := map[string]Signature{}
	var owner func(string) (string, bool)
	switch {
	case hasCmd("dpkg"): // Debian/Ubuntu → "pkg:arch: /path"
		owner = func(p string) (string, bool) {
			o := runCmd(5*time.Second, "dpkg", "-S", p)
			if i := strings.Index(o, ":"); i > 0 && strings.Contains(o, p) {
				return strings.TrimSpace(o[:i]), true
			}
			return "", false
		}
	case hasCmd("rpm"): // RHEL/Fedora → "pkg-version.arch"
		owner = func(p string) (string, bool) {
			o := strings.TrimSpace(runCmd(5*time.Second, "rpm", "-qf", p))
			if o != "" && !strings.Contains(strings.ToLower(o), "not owned") {
				return o, true
			}
			return "", false
		}
	case hasCmd("pacman"): // Arch → "/path is owned by pkg version"
		owner = func(p string) (string, bool) {
			o := runCmd(5*time.Second, "pacman", "-Qo", p)
			if i := strings.Index(o, "owned by "); i >= 0 {
				if f := strings.Fields(o[i+len("owned by "):]); len(f) > 0 {
					return f[0], true
				}
			}
			return "", false
		}
	}
	for _, p := range paths {
		switch {
		case owner == nil: // no known package manager
			out[p] = Signature{Status: "N/A"}
		default:
			if pkg, ok := owner(p); ok {
				out[p] = Signature{Status: "Packaged", Signer: pkg, Trusted: true}
			} else {
				out[p] = Signature{Status: "Unmanaged"}
			}
		}
	}
	return out
}

func queryAuthenticode(paths []string) map[string]Signature {
	out := map[string]Signature{}
	tmp, err := os.CreateTemp("", "epm-*.txt")
	if err != nil {
		return out
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(strings.Join(paths, "\n"))
	tmp.Close()

	ps := fmt.Sprintf(`Get-Content -LiteralPath '%s' -Encoding UTF8 | ForEach-Object { `+
		`$s = Get-AuthenticodeSignature -LiteralPath $_; `+
		`[PSCustomObject]@{ path="$_"; status="$($s.Status)"; `+
		`signer="$($s.SignerCertificate.Subject)" } } | ConvertTo-Json -Compress`, tmp.Name())

	cmd := command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	stdout, err := cmd.Output()
	if err != nil || len(stdout) == 0 {
		return out
	}
	var rows []struct{ Path, Status, Signer string }
	trimmed := strings.TrimSpace(string(stdout))
	if strings.HasPrefix(trimmed, "{") {
		trimmed = "[" + trimmed + "]"
	}
	if json.Unmarshal([]byte(trimmed), &rows) != nil {
		return out
	}
	for _, r := range rows {
		signer := cnFromSubject(r.Signer)
		out[r.Path] = Signature{
			Status:  r.Status,
			Signer:  signer,
			Trusted: r.Status == "Valid" && signer != "",
		}
	}
	return out
}

func cnFromSubject(s string) string {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return s
}

// ── Threat score ─────────────────────────────────────────────────────────────

func threatScore(c *Conn) int {
	if c.Whitelist {
		c.Breakdown = "binario en whitelist → 0"
		return 0
	}
	if c.IPWhitelist {
		c.Breakdown = "IP en whitelist → 0"
		return 0
	}
	score := 0.0
	var why []string
	add := func(pts float64, reason string) {
		score += pts
		why = append(why, fmt.Sprintf("%s (+%d)", reason, int(pts)))
	}

	if n, err := strconv.Atoi(c.VT); err == nil && n > 0 {
		if n > 10 {
			n = 10
		}
		add(float64(n)*6, fmt.Sprintf("VT %s detecciones", c.VT))
	}
	if c.Suspicious {
		add(25, "ruta sospechosa")
	}
	if c.SuspPort {
		add(30, "puerto de malware ("+c.Known+")")
	}
	switch c.Sig.Status {
	case "NotSigned":
		add(15, "binario sin firma")
	// PENDING means "not resolved yet", so it must score 0 — it is reflected in
	// coverageIncomplete instead, which marks the row as partial data.
	case "Valid", "N/A", "Unknown", "", "Packaged", "Unmanaged", sigPendingStatus:
	default:
		add(10, "firma "+c.Sig.Status)
	}
	if e := c.Enrich; e != nil {
		if e.VTMalicious != nil && *e.VTMalicious > 0 {
			n := *e.VTMalicious
			if n > 10 {
				n = 10
			}
			add(float64(n)*4, fmt.Sprintf("VT-IP %d", *e.VTMalicious))
		}
		if e.AbuseScore != nil && *e.AbuseScore > 0 {
			w, note := 0.4, ""
			if e.Provider != "" {
				w, note = 0.1, " atenuado: "+e.Provider
			}
			add(float64(*e.AbuseScore)*w, fmt.Sprintf("AbuseIPDB %d%%%s", *e.AbuseScore, note))
		}
		if e.C2 {
			add(60, "C2 Feodo")
		}
		if e.ThreatFox != "" {
			add(55, "ThreatFox: "+e.ThreatFox)
		}
		if e.Spamhaus {
			add(30, "Spamhaus DROP")
		}
		if e.Tor {
			add(15, "Tor exit")
		}
		if len(e.Vulns) > 0 {
			add(10, fmt.Sprintf("%d CVEs (Shodan)", len(e.Vulns)))
		}
	}
	if score > 100 {
		score = 100
	}
	if len(why) == 0 {
		// A zero score is only "clean" if we actually managed to check the key
		// signals. If VT has no real verdict, or a public IP wasn't enriched yet,
		// the low score means "no data", not "safe" — flag it as partial coverage.
		if coverageIncomplete(c) {
			c.Partial = true
			c.Breakdown = "sin señales (datos incompletos)"
		} else {
			c.Breakdown = "limpio"
		}
	} else {
		c.Breakdown = strings.Join(why, " · ")
	}
	return int(score)
}

// coverageIncomplete reports whether the key intel signals could NOT be resolved
// for this connection, so a low score should not read as a confident "clean".
func coverageIncomplete(c *Conn) bool {
	// VT hash: covered if we have a numeric verdict or a definitive "not in VT".
	vtCovered := c.VT == "NOT_IN_VT"
	if _, err := strconv.Atoi(c.VT); err == nil {
		vtCovered = true
	}
	// IP reputation: only relevant for a public remote; covered once enriched.
	ipCovered := c.RemoteIP == "" || isPrivateIP(c.RemoteIP) || c.Enrich != nil
	// Signature: a queued-but-unresolved lookup is missing data, not a clean bill.
	sigCovered := c.Sig.Status != sigPendingStatus
	return !vtCovered || !ipCovered || !sigCovered
}

// ── Main analysis ────────────────────────────────────────────────────────────

// Concurrency caps for the per-request enrichment passes. Small on purpose: the
// point is to overlap latency, not to open a hundred sockets or spawn a hundred
// subprocesses because the machine happens to be busy.
const (
	maxHashWorkers   = 8
	maxEnrichWorkers = 8
	maxLANWorkers    = 8
)

// forEachLimited runs fn for every item, with at most limit running at once.
func forEachLimited[T any](items []T, limit int, fn func(T)) {
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer func() { <-sem; wg.Done() }()
			fn(it)
		}(it)
	}
	wg.Wait()
}

func analyzeConnections(hideSelf bool) []Conn {
	conns, err := gnet.Connections("inet")
	if err != nil {
		return nil
	}

	type row struct {
		c    gnet.ConnectionStat
		name string
		exe  string
	}
	var rows []row
	exeSet := map[string]bool{}
	ipSet := map[string]bool{}
	lanSet := map[string]bool{}
	pidConns := map[int32][]ProcConn{} // built once for getProcDetails

	// Process identity is per PID, not per socket: a browser with 60 sockets used
	// to cost 60 × (NewProcess + Name + Exe), which on Windows is 60 handle opens
	// and 60 queries for the same answer.
	type procInfo struct{ name, exe string }
	procCache := map[int32]procInfo{}
	lookupProc := func(pid int32) procInfo {
		if pi, ok := procCache[pid]; ok {
			return pi
		}
		pi := procInfo{"N/A", "N/A"}
		if pid > 0 {
			if p, err := process.NewProcess(pid); err == nil {
				if n, err := p.Name(); err == nil {
					pi.name = n
				}
				if e, err := p.Exe(); err == nil && e != "" {
					pi.exe = e
				}
			} else {
				pi = procInfo{"ACCESS_DENIED", "ACCESS_DENIED"}
			}
		}
		procCache[pid] = pi
		return pi
	}

	for _, c := range conns {
		if !trackConn(c) {
			continue
		}
		if hideSelf && c.Pid == ownPID {
			continue
		}
		if c.Status == "ESTABLISHED" && c.Raddr.IP != "" && c.Pid > 0 {
			pidConns[c.Pid] = append(pidConns[c.Pid],
				ProcConn{c.Laddr.IP, c.Laddr.Port, c.Raddr.IP, c.Raddr.Port})
		}
		pi := lookupProc(c.Pid)
		name, exe := pi.name, pi.exe
		rows = append(rows, row{c, name, exe})
		if exe != "N/A" && exe != "ACCESS_DENIED" {
			exeSet[exe] = true
		}
		if c.Raddr.IP != "" && !isPrivateIP(c.Raddr.IP) {
			ipSet[c.Raddr.IP] = true
		}
		if isLAN(c.Raddr.IP) {
			lanSet[c.Raddr.IP] = true
		}
	}

	// The three enrichment passes run concurrently with each other, but each one
	// is bounded. Previously every unique exe, public IP and LAN host got its own
	// goroutine with no cap: 150 public IPs meant 150 goroutines × ~6 HTTP calls
	// each, on every single /api/connections request.
	vtMap := map[string][3]string{} // exe -> {cached("1"/""), result, undetected}
	var vtMapMu sync.Mutex
	enrichMap := map[string]*Enrichment{}
	var enrichMu sync.Mutex
	lanMap := map[string]*LANInfo{}
	var lanMapMu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { // VT hash per unique exe (disk-bound: SHA-256 over each binary)
		defer wg.Done()
		forEachLimited(keys(exeSet), maxHashWorkers, func(exe string) {
			cached, res, und := analyzeExe(exe)
			c := ""
			if cached {
				c = "1"
			}
			vtMapMu.Lock()
			vtMap[exe] = [3]string{c, res, und}
			vtMapMu.Unlock()
		})
	}()
	go func() { // reputation per unique public IP (several HTTP calls each)
		defer wg.Done()
		forEachLimited(keys(ipSet), maxEnrichWorkers, func(ip string) {
			e := enrichIP(ip)
			enrichMu.Lock()
			enrichMap[ip] = e
			enrichMu.Unlock()
		})
	}()
	go func() { // LAN host info per unique LAN IP (arp/nbtstat subprocesses)
		defer wg.Done()
		forEachLimited(keys(lanSet), maxLANWorkers, func(ip string) {
			l := lanLookup(ip)
			lanMapMu.Lock()
			lanMap[ip] = l
			lanMapMu.Unlock()
		})
	}()
	wg.Wait()

	sigMap := checkSignatures(keys(exeSet))
	wl := whitelist()
	ipwl := ipWhitelist()
	detailsMap := map[int32]*ProcDetails{} // deduped per PID

	out := make([]Conn, 0, len(rows))
	for _, r := range rows {
		known, suspPort := portLabel(r.c.Laddr.Port, r.c.Raddr.Port)
		vt := vtMap[r.exe]
		conn := Conn{
			Port:        r.c.Laddr.Port,
			LocalIP:     r.c.Laddr.IP,
			RPort:       r.c.Raddr.Port,
			RemoteIP:    r.c.Raddr.IP,
			PID:         r.c.Pid,
			Process:     r.name,
			Status:      connStatus(r.c),
			Exe:         r.exe,
			Known:       known,
			Cached:      vt[0] == "1",
			VT:          orNA(vt[1]),
			Undetected:  vt[2],
			Suspicious:  isSuspiciousPath(r.exe),
			SuspPort:    suspPort,
			Blockable:   isBlockable(r.c.Raddr.IP),
			Sig:         sigMap[r.exe],
			Whitelist:   wl[r.exe],
			IPWhitelist: ipwl[r.c.Raddr.IP],
		}
		if conn.RemoteIP != "" && !isPrivateIP(conn.RemoteIP) {
			conn.Enrich = enrichMap[conn.RemoteIP]
		}
		if isLAN(conn.RemoteIP) {
			conn.LAN = lanMap[conn.RemoteIP]
		}
		// Capture needs a public peer to filter on; it works the same for UDP
		// (QUIC) as for TCP, so the gate is "has a public remote", not the state.
		conn.Capturable = conn.Enrich != nil
		if (r.c.Status == "ESTABLISHED" || isUDP(r.c)) && r.c.Pid > 0 {
			d, ok := detailsMap[r.c.Pid]
			if !ok {
				d = getProcDetails(r.c.Pid, pidConns)
				detailsMap[r.c.Pid] = d
			}
			conn.Details = d
		}
		// Unique blockable remote IPs for this process (this row's remote + the
		// process's other active connections), so the UI can offer all of them.
		ipseen := map[string]bool{}
		addIP := func(ip string) {
			if isBlockable(ip) && !ipseen[ip] {
				ipseen[ip] = true
				conn.RemoteIPs = append(conn.RemoteIPs, ip)
			}
		}
		addIP(r.c.Raddr.IP)
		if conn.Details != nil {
			for _, pc := range conn.Details.Conns {
				addIP(pc.RemoteIP)
			}
		}
		conn.Threat = threatScore(&conn)
		out = append(out, conn)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Threat != out[j].Threat {
			return out[i].Threat > out[j].Threat
		}
		return out[i].PID < out[j].PID
	})
	return out
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
