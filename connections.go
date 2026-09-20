package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
	DiskRead   uint64 // block-device bytes, Linux only (see getProcDetails)
	DiskWrite  uint64
	DiskOK     bool
	Conns      []ProcConn
	TotalConns int
	Err        string

	Ancestry    []Ancestor // parent chain, nearest first
	AncestryStr string     // "proc ← parent ← grandparent", for display
	BadSpawn    string     // non-empty when the chain matches a known-bad pattern

	// Context (see proccontext.go): where it runs from and under what.
	Cwd       string   // working directory ("" if unreadable)
	CwdSusp   bool     // cwd is a staging directory
	EnvHits   []string // sensitive environment variables, "KEY=value", credentials masked
	TTYKnown  bool     // terminal state was determined (Linux)
	TTY       string   // controlling terminal, "" = none (a daemon or a detached process)
	Unit      string   // systemd unit the process belongs to (Linux)
	Container string   // "docker:3f2a1b…" when it runs inside a container (Linux)

	// Provenance (see provenance.go).
	ExeModified time.Time // executable's mtime; zero if unknown
	ExeYoung    bool      // modified less than youngBinary ago
	FirstSeen   time.Time // first time this machine recorded this exact binary; zero if unknown
	Children    string    // "bash ×2 · curl", "" if none

	// What it touches (see procscan.go; Linux, root for other users' processes).
	SensitiveFiles []string // sensitive files held by a process that is not their expected reader
	CredFiles      int      // how many of those score
	MediaFiles     []string // camera / microphone held open: context, never scored
	ExecAnomalies  []string // executable memory from memfd, staging dirs or deleted files
}

// Conn is one analyzed connection row shown in the UI.
type Conn struct {
	Threat        int
	Port          uint32
	LocalIP       string
	RPort         uint32
	RemoteIP      string
	PID           int32
	Process       string
	Status        string
	Exe           string
	Known         string
	VT            string
	Undetected    string
	Cached        bool
	Suspicious    bool // runs from a staging directory (temp, public, /dev/shm)
	Untrusted     bool // runs from a downloads directory: weak signal
	SuspPort      bool
	LegacyPort    bool // a RAT/worm default from decades ago: labelled, never scored
	Blockable     bool
	Capturable    bool    // has a public remote peer, so tshark has something to filter on
	RateIn        float64 // bytes/sec inbound (see volume.go on what this measures)
	RateOut       float64 // bytes/sec outbound
	HighEgress    bool    // sustained outbound flow; informational unless combined
	CPU           float64 // % of the whole machine over the last monitor interval (volume.go)
	HighCPU       bool    // sustained high CPU; informational unless combined (miner shape)
	RSS           uint64  // resident memory in bytes (Windows: working set)
	Threads       int32
	User          string // owning account, "" if not resolvable
	ResOK         bool   // CPU/RSS were readable for this PID
	Sig           Signature
	Whitelist     bool
	IPWhitelist   bool
	Partial       bool // key signals (VT/enrichment) couldn't be resolved → low score ≠ clean
	Enrich        *Enrichment
	Hostnames     []Hostname // names observed bound to RemoteIP (TLS SNI / DNS answers)
	LAN           *LANInfo
	Details       *ProcDetails
	Breakdown     string   // the reasons, rendered in the UI language (see localizeBreakdown)
	BreakdownCode string   // the same reasons, language-neutral; what score_history stores
	RemoteIPs     []string // unique blockable remote IPs of this connection's process
}

// getProcDetails fills per-process info. The process's active connections come
// from pidConns (built once from the global snapshot) — far cheaper than calling
// p.Connections() per PID.
func getProcDetails(pid int32, pidConns map[int32][]ProcConn, children map[int32][]string) *ProcDetails {
	d := &ProcDetails{ParentName: "N/A", Cmdline: "N/A", CreateTime: "N/A"}
	p, err := process.NewProcess(pid)
	if err != nil {
		d.Err = "process not found"
		return d
	}
	name := ""
	if n, err := p.Name(); err == nil {
		name = n
	}
	if exe, err := p.Exe(); err == nil {
		d.ExeModified, d.FirstSeen = exeProvenance(exe)
		d.ExeYoung = !d.ExeModified.IsZero() && time.Since(d.ExeModified) < youngBinary
	}
	d.Children = summarizeChildren(children[pid])
	// Full chain, not just the immediate parent: cmd.exe under explorer.exe is a
	// user at a terminal, the same cmd.exe under winword.exe is a macro payload.
	d.Ancestry = ancestryOf(pid)
	d.AncestryStr = ancestryLabel(name, d.Ancestry)
	d.BadSpawn = suspiciousAncestry(name, d.Ancestry)
	if len(d.Ancestry) > 0 {
		d.PPID = d.Ancestry[0].PID
		d.ParentName = d.Ancestry[0].Name
	} else if ppid, err := p.Ppid(); err == nil {
		d.PPID = ppid
	}
	if cl, err := p.Cmdline(); err == nil && cl != "" {
		d.Cmdline = cl
	}
	if ct, err := p.CreateTime(); err == nil {
		d.CreateTime = time.UnixMilli(ct).Format("2006-01-02 15:04:05")
	}
	if cwd, err := p.Cwd(); err == nil && cwd != "" {
		d.Cwd, d.CwdSusp = cwd, isSuspiciousPath(cwd+string(os.PathSeparator))
	}
	// Only the variables that redirect code or traffic are read out; see
	// sensitiveEnvKeys. Other users' environments need root, as with everything.
	if env, err := p.Environ(); err == nil {
		d.EnvHits = sensitiveEnv(env)
	}
	if runtime.GOOS == "linux" {
		if t, err := p.Terminal(); err == nil {
			d.TTYKnown, d.TTY = true, strings.TrimPrefix(t, "/dev/")
		}
		d.Container, d.Unit = procCgroup(pid)
		if s := scanProcess(pid, name); s != nil {
			d.SensitiveFiles, d.CredFiles, d.MediaFiles, d.ExecAnomalies = s.files, s.scored, s.media, s.execMap
		}
	}
	if io, err := p.IOCounters(); err == nil {
		d.IORead, d.IOWrite, d.IOok = io.ReadBytes, io.WriteBytes, true
		if runtime.GOOS == "linux" {
			// Only Linux separates block-device I/O from the syscall totals; on
			// Windows the counters lump disk, network and devices together.
			d.DiskRead, d.DiskWrite, d.DiskOK = io.DiskReadBytes, io.DiskWriteBytes, true
		}
	}
	d.Conns = pidConns[pid]
	d.TotalConns = len(d.Conns)
	return d
}

// ownPID is this process, so we can hide the monitor's own API traffic.
var ownPID = int32(os.Getpid())

// Path signals come in two tiers, because lumping them together was the single
// biggest false-positive source in the score.
//
// stagingPaths are locations a normal installed program does not run from. A
// binary executing there is genuinely odd and earns wSuspiciousPath.
var stagingPaths = []string{
	// Windows
	`\appdata\local\temp`, `\users\public`, `\programdata`,
	`\windows\temp`, `\recycle`,
	// Linux — executables in temp/shared-memory locations are a strong malware signal
	`/tmp/`, `/var/tmp/`, `/dev/shm/`,
}

// untrustedPaths are merely *unvetted*. Running something straight out of the
// downloads folder is what installers, portable tools and game launchers do all
// day, so this is worth a nudge (wUntrustedPath) and nothing more. It used to sit
// in the list above and contribute the same weight as /dev/shm, which meant a
// perfectly ordinary machine showed a wall of amber rows.
var untrustedPaths = []string{`\downloads`, `/downloads`}

// portLabel resolves the protocol label, whether it should score, and whether
// it is a legacy malware port: labelled as useful context, scored zero, and
// marked so the UI can say why.
func portLabel(lport, rport uint32) (label string, scores, legacy bool) {
	for _, p := range [2]uint32{lport, rport} {
		if p != 0 {
			if name, ok := scoringMalwarePorts[p]; ok {
				return name, true, false
			}
		}
	}
	for _, p := range [2]uint32{lport, rport} {
		if p != 0 {
			if name, ok := legacyMalwarePorts[p]; ok {
				return name, false, true
			}
		}
	}
	if name, ok := knownPorts[lport]; ok {
		return name, false, false
	}
	if rport != 0 {
		if name, ok := knownPorts[rport]; ok {
			return name, false, false
		}
	}
	return "—", false, false
}

func pathKnown(p string) bool {
	return p != "" && p != "N/A" && p != "ACCESS_DENIED"
}

// isSuspiciousPath reports a staging-directory hit (high weight).
func isSuspiciousPath(p string) bool {
	if !pathKnown(p) {
		return false
	}
	lp := strings.ToLower(p)
	for _, s := range stagingPaths {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

// isUntrustedPath reports a downloads-directory hit (low weight).
func isUntrustedPath(p string) bool {
	if !pathKnown(p) {
		return false
	}
	lp := strings.ToLower(p)
	for _, s := range untrustedPaths {
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

	// #nosec G304 -- hashing a binary by path is the whole job here; the path comes
	// from the OS process table (p.Exe()), not from a request.
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

// Score weights, named so a tuning change is reviewable in a diff instead of
// being a bare number buried in an expression. Every change here should be made
// against the corpus in score_corpus_test.go, which pins the expected band for a
// set of labelled scenarios.
//
// The guiding rule is precision over recall. A signal only earns a large weight
// if it is hard to trigger accidentally:
//
//   - High precision, external: a hit on a curated C2/IOC feed (Feodo,
//     ThreatFox) means someone observed that address serving malware.
//   - High precision, local: a spawn chain that should never occur, e.g. Word
//     launching PowerShell.
//   - Low precision: "the binary lives in a directory malware also likes", or
//     "the port was a RAT default in 2003". These have to stay small, because
//     they fire constantly on healthy machines.
const (
	wVTPerDetection  = 6.0 // × detections, capped at vtDetectionCap
	wVTIPPerHit      = 4.0 // × malicious verdicts on the remote IP
	vtDetectionCap   = 10
	wAbusePerPercent = 0.4  // × AbuseIPDB confidence
	wAbuseAttenuated = 0.1  // same, when the IP belongs to a known big provider
	wFeodoC2         = 60.0 // curated C2 tracker
	wThreatFox       = 55.0 // curated IOC feed
	wSpamhausDROP    = 30.0 // criminal / hijacked netblock
	wBadSpawn        = 40.0 // ancestry pattern that should never happen
	wUnsigned        = 15.0 // no code signature at all
	wBadSignature    = 10.0 // a signature that exists but does not validate
	wTorExit         = 15.0
	wShodanCVEs      = 10.0
	wSuspiciousPath  = 25.0 // temp / shared-memory / public dirs: malware staging
	wUntrustedPath   = 8.0  // Downloads: weakly suspicious, extremely common
	wMalwarePort     = 12.0 // a port still used by live tooling (Metasploit)
	wExfilCombo      = 25.0 // sustained egress *from a binary already distrusted*
	wMinerCombo      = 25.0 // sustained CPU *from a binary already distrusted*
	wCredAccess      = 25.0 // holds a credential store / input device it has no business with
	wExecAnomaly     = 30.0 // executes code from memfd, a staging dir or a deleted file
)

func threatScore(c *Conn) int {
	// finish renders the reasons both ways: neutral for the history, localized
	// for the tooltip. The language is the one of the request being served.
	var rs []reason
	finish := func(score float64) int {
		c.BreakdownCode = encodeReasons(rs)
		c.Breakdown = localizeBreakdown(currentLang(), c.BreakdownCode)
		return int(score)
	}
	if c.Whitelist {
		rs = []reason{{key: "wl_exe"}}
		return finish(0)
	}
	if c.IPWhitelist {
		rs = []reason{{key: "wl_ip"}}
		return finish(0)
	}
	score := 0.0
	add := func(pts float64, key string, args ...string) {
		score += pts
		rs = append(rs, reason{key: key, pts: int(pts), args: args})
	}

	if n, err := strconv.Atoi(c.VT); err == nil && n > 0 {
		if n > vtDetectionCap {
			n = vtDetectionCap
		}
		add(float64(n)*wVTPerDetection, "vt", c.VT)
	}
	switch {
	case c.Suspicious:
		add(wSuspiciousPath, "path_staging")
	case c.Untrusted:
		add(wUntrustedPath, "path_untrusted")
	}
	if c.SuspPort {
		add(wMalwarePort, "port", c.Known)
	}
	// A spawn chain that should never happen is one of the few high-precision
	// signals computable without any external service.
	if c.Details != nil && c.Details.BadSpawn != "" {
		add(wBadSpawn, "spawn", c.Details.BadSpawn)
	}
	// Volume never scores on its own: a download, a backup and a video call all
	// move data. It scores when the binary was already suspect for an independent
	// reason, because "this odd process is streaming data out" is a different
	// claim from "this process is busy". See volume.go.
	if c.HighEgress && (c.Suspicious || c.SuspPort ||
		(c.Details != nil && c.Details.BadSpawn != "")) {
		add(wExfilCombo, "exfil", humanRate(c.RateOut))
	}
	// Same logic for CPU: sustained load is a compiler or a game on a healthy
	// box, and the cryptominer shape only once the binary is suspect anyway.
	if c.HighCPU && (c.Suspicious || c.SuspPort ||
		(c.Details != nil && c.Details.BadSpawn != "")) {
		add(wMinerCombo, "cpu", fmt.Sprintf("%.0f", c.CPU))
	}
	// These two score on their own: each category's expected readers are
	// excluded up front, so what is left is a foreign process holding a
	// credential store or an input device, or code running from somewhere no
	// legitimate loader puts it. High precision, computed locally.
	if c.Details != nil && c.Details.CredFiles > 0 {
		add(wCredAccess, "creds", strconv.Itoa(c.Details.CredFiles))
	}
	if c.Details != nil && len(c.Details.ExecAnomalies) > 0 {
		add(wExecAnomaly, "execmap", strconv.Itoa(len(c.Details.ExecAnomalies)))
	}
	switch c.Sig.Status {
	case "NotSigned":
		add(wUnsigned, "unsigned")
	// PENDING means "not resolved yet", so it must score 0 — it is reflected in
	// coverageIncomplete instead, which marks the row as partial data.
	case "Valid", "N/A", "Unknown", "", "Packaged", "Unmanaged", sigPendingStatus:
	default:
		add(wBadSignature, "sig", c.Sig.Status)
	}
	if e := c.Enrich; e != nil {
		if e.VTMalicious != nil && *e.VTMalicious > 0 {
			n := *e.VTMalicious
			if n > vtDetectionCap {
				n = vtDetectionCap
			}
			add(float64(n)*wVTIPPerHit, "vtip", strconv.Itoa(*e.VTMalicious))
		}
		if e.AbuseScore != nil && *e.AbuseScore > 0 {
			if e.Provider != "" {
				add(float64(*e.AbuseScore)*wAbuseAttenuated, "abuse_att", strconv.Itoa(*e.AbuseScore), e.Provider)
			} else {
				add(float64(*e.AbuseScore)*wAbusePerPercent, "abuse", strconv.Itoa(*e.AbuseScore))
			}
		}
		if e.C2 {
			add(wFeodoC2, "c2")
		}
		if e.ThreatFox != "" {
			add(wThreatFox, "threatfox", e.ThreatFox)
		}
		if e.Spamhaus {
			add(wSpamhausDROP, "spamhaus")
		}
		if e.Tor {
			add(wTorExit, "tor")
		}
		if len(e.Vulns) > 0 {
			add(wShodanCVEs, "cves", strconv.Itoa(len(e.Vulns)))
		}
	}
	if score > 100 {
		score = 100
	}
	if len(rs) == 0 {
		// A zero score is only "clean" if we actually managed to check the key
		// signals. If VT has no real verdict, or a public IP wasn't enriched yet,
		// the low score means "no data", not "safe" — flag it as partial coverage.
		if coverageIncomplete(c) {
			c.Partial = true
			rs = []reason{{key: "partial"}}
		} else {
			rs = []reason{{key: "clean"}}
		}
	}
	return finish(score)
}

// ── Score breakdown encoding ─────────────────────────────────────────────────
//
// The reasons behind a score are kept as keys plus arguments, not as prose: the
// tooltip renders them in the operator's language, and score_history stores the
// neutral form, so the timeline reads correctly in whichever language is active
// when it is opened. Before this the breakdown was Spanish-only, in the UI and
// in the database.

// reason is one scored signal: a translation key (bd_<key>), the points it
// added, and the arguments its text takes.
type reason struct {
	key  string
	pts  int
	args []string
}

// The encoding is `key/pts/arg|arg;key/pts;key`. Arguments are escaped so a
// malware family or a spawn chain can never break the format.
var (
	reasonEscaper   = strings.NewReplacer("%", "%25", ";", "%3B", "/", "%2F", "|", "%7C")
	reasonUnescaper = strings.NewReplacer("%3B", ";", "%2F", "/", "%7C", "|", "%25", "%")
	breakdownCodeRe = regexp.MustCompile(`^[a-z0-9_]+(/-?\d+(/[^;]*)?)?(;[a-z0-9_]+(/-?\d+(/[^;]*)?)?)*$`)
)

func encodeReasons(rs []reason) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		p := r.key
		if r.pts != 0 || len(r.args) > 0 {
			p += "/" + strconv.Itoa(r.pts)
		}
		if len(r.args) > 0 {
			esc := make([]string, len(r.args))
			for i, a := range r.args {
				esc[i] = reasonEscaper.Replace(a)
			}
			p += "/" + strings.Join(esc, "|")
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ";")
}

// localizeBreakdown renders an encoded breakdown in lang. Anything that is not
// the encoding — rows written before it existed are free text — is returned as
// it is, as is a code whose key this build does not know.
func localizeBreakdown(lang, code string) string {
	if code == "" || !breakdownCodeRe.MatchString(code) {
		return code
	}
	T := strings_(lang)
	var out []string
	for _, p := range strings.Split(code, ";") {
		f := strings.SplitN(p, "/", 3)
		tmpl, ok := T["bd_"+f[0]]
		if !ok {
			return code
		}
		var args []any
		if len(f) == 3 {
			for _, a := range strings.Split(f[2], "|") {
				args = append(args, reasonUnescaper.Replace(a))
			}
		}
		s := fmt.Sprintf(tmpl, args...)
		if len(f) >= 2 {
			s += " (+" + f[1] + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, " · ")
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
	hostMap := dbAllHostnames()            // one query, not one per row
	children := childrenMap()              // one /proc pass, not one per PID
	detailsMap := map[int32]*ProcDetails{} // deduped per PID

	out := make([]Conn, 0, len(rows))
	for _, r := range rows {
		known, suspPort, legacyPort := portLabel(r.c.Laddr.Port, r.c.Raddr.Port)
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
			Untrusted:   isUntrustedPath(r.exe),
			SuspPort:    suspPort,
			LegacyPort:  legacyPort,
			Blockable:   isBlockable(r.c.Raddr.IP),
			Sig:         sigMap[r.exe],
			Whitelist:   wl[r.exe],
			IPWhitelist: ipwl[r.c.Raddr.IP],
		}
		if conn.RemoteIP != "" && !isPrivateIP(conn.RemoteIP) {
			conn.Enrich = enrichMap[conn.RemoteIP]
		}
		conn.Hostnames = hostMap[conn.RemoteIP]
		rate := rateFor(r.c.Pid)
		conn.RateIn, conn.RateOut, conn.HighEgress = rate.In, rate.Out, rate.HighEgress
		conn.CPU, conn.RSS, conn.Threads, conn.User, conn.ResOK =
			rate.CPU, rate.RSS, rate.Threads, rate.User, rate.ResOK
		conn.HighCPU = rate.HighCPU
		if isLAN(conn.RemoteIP) {
			conn.LAN = lanMap[conn.RemoteIP]
		}
		// Capture needs a public peer to filter on; it works the same for UDP
		// (QUIC) as for TCP, so the gate is "has a public remote", not the state.
		conn.Capturable = conn.Enrich != nil
		if (r.c.Status == "ESTABLISHED" || isUDP(r.c)) && r.c.Pid > 0 {
			d, ok := detailsMap[r.c.Pid]
			if !ok {
				d = getProcDetails(r.c.Pid, pidConns, children)
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
		recordScoreChange(&conn)
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

// recordScoreChange appends to the risk timeline, but only when the verdict for
// this (exe, remote IP) pair actually changed.
//
// The history used to keep a free-text detail line and nothing else, so it could
// not answer "what did this look like on Tuesday" — the score and its reasoning
// existed only in the rendered page. Writing every row on every render would be
// thousands of near-identical rows, so this is a change log: the interesting
// moment is when a pair's risk moves, which is also exactly what a trend is made of.
func recordScoreChange(c *Conn) {
	if c.Exe == "" || c.Exe == "N/A" || c.Exe == "ACCESS_DENIED" {
		return
	}
	if c.RemoteIP == "" || isPrivateIP(c.RemoteIP) {
		return // local traffic has no reputation to trend
	}
	if c.Partial {
		return // don't record a verdict we already know is based on missing data
	}
	// Compared and stored in the neutral encoding, so switching the UI language
	// does not register as the risk of every pair having changed.
	if last, lastWhy, ok := dbLastScore(c.Exe, c.RemoteIP); ok &&
		last == c.Threat && lastWhy == c.BreakdownCode {
		return
	}
	dbSaveScoreChange(c.Exe, c.RemoteIP, c.Threat, c.BreakdownCode)
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
