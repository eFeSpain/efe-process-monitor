package main

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/shirou/gopsutil/v4/process"
)

//go:embed web/templates/*.html
var tmplFS embed.FS

//go:embed web/static/*
var staticFS embed.FS

var tmpl *template.Template
var elevated bool
var noTrayMode bool

// appDir is the directory of the executable; the DB and .env live there so the
// app behaves the same regardless of the working directory it's launched from.
var appDir = "."

func exeDir() string {
	if p, err := os.Executable(); err == nil {
		return filepath.Dir(p)
	}
	return "."
}

var funcMap = template.FuncMap{
	// trunc cuts by runes, not bytes: slicing a string at a byte offset can land
	// mid-character, and accented paths ("C:\Users\José\…") then render as a
	// replacement diamond.
	"trunc": func(n int, s string) string {
		if n < 0 {
			return s
		}
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n]) + "…"
	},
	"threatClass": func(t int) string {
		switch {
		case t >= 70:
			return "high"
		case t >= 40:
			return "med"
		case t >= 15:
			return "low"
		default:
			return "min"
		}
	},
	// Note the argument order: templates read better as `join ", " $items`, which
	// is the reverse of strings.Join's own signature.
	"join": func(sep string, items []string) string { return strings.Join(items, sep) },
	"json": func(v any) template.JS {
		b, _ := json.Marshal(v)
		return template.JS(b)
	},
	"deref": func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	},
	"joinInts": func(sep string, items []int) string {
		parts := make([]string, len(items))
		for i, n := range items {
			parts[i] = strconv.Itoa(n)
		}
		return strings.Join(parts, sep)
	},
	"humanBytes": func(n uint64) string {
		f := float64(n)
		for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
			if f < 1024 {
				return fmt.Sprintf("%.1f %s", f, u)
			}
			f /= 1024
		}
		return fmt.Sprintf("%.1f PB", f)
	},
}

func main() {
	// DB and .env live next to the executable, so the app behaves the same
	// wherever it's launched from.
	//
	// The cwd/parent fallback is gated behind EFEMON_DEV=1: it's convenient when
	// the .env sits in the project root during development, but on a normal run
	// it means launching the binary from inside some other project makes us read
	// *and rewrite* that project's .env — writing AUTH_HASH and API keys into it.
	appDir = exeDir()
	envPath = filepath.Join(appDir, ".env")
	candidates := []string{envPath}
	if os.Getenv("EFEMON_DEV") == "1" {
		candidates = append(candidates, ".env", "../.env")
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			envPath = p
			break
		}
	}
	_ = godotenv.Load(envPath)
	// Re-read keys now that .env is loaded (package-level vars init before main).
	keysMu.Lock()
	vtKey = os.Getenv("VT_API_KEY")
	abuseKey = os.Getenv("ABUSEIPDB_API_KEY")
	keysMu.Unlock()
	notifyDesktop.Store(os.Getenv("NOTIFY_DESKTOP") != "false")       // default on
	notifySound.Store(os.Getenv("NOTIFY_SOUND") != "false")           // default on
	persistWhitelist.Store(os.Getenv("PERSIST_WHITELIST") != "false") // default on
	persistBlocks.Store(os.Getenv("PERSIST_BLOCKS") != "false")       // default on
	if n, err := strconv.Atoi(os.Getenv("REFRESH_SECS")); err == nil {
		refreshSecs.Store(int64(n))
	}
	if n, err := strconv.Atoi(os.Getenv("EVENT_RETENTION_DAYS")); err == nil && n >= 0 {
		eventRetentionDays = n // 0 = keep forever
	}
	loadAuth(os.Getenv("AUTH_HASH"))
	listenAddr.Store(os.Getenv("LISTEN_ADDR"))

	initDB()
	loadState() // seed session whitelist/blocked from the DB
	elevated = isElevated()
	tmpl = template.Must(template.New("").Funcs(funcMap).ParseFS(tmplFS, "web/templates/*.html"))
	go primeIntel()
	go monitorLoop()
	go vtWorker()  // resolves VT hashes in the background at 4/min
	go sigWorker() // resolves code signatures off the request path

	staticSub, _ := fs.Sub(staticFS, "web/static")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/api/connections", handleConnections)
	http.HandleFunc("/events", handleEvents)
	http.HandleFunc("/api/interfaces", handleInterfaces)
	http.HandleFunc("/capture", handleCapture)
	http.HandleFunc("/capture.pcap", handleCapturePcap)
	http.HandleFunc("/api/events", handleAPIEvents)
	http.HandleFunc("/export.csv", handleExportCSV)
	http.HandleFunc("/export.json", handleExportJSON)
	http.HandleFunc("/api/settings", handleSettings)
	http.HandleFunc("/api/restart", handleRestart)
	http.HandleFunc("/api/whitelist", handleWhitelist)
	http.HandleFunc("/api/ip_whitelist", handleIPWhitelist)
	http.HandleFunc("/api/kill", handleKill)
	http.HandleFunc("/api/block_ip", handleBlockIP)
	http.HandleFunc("/api/blocked", handleBlocked)
	http.HandleFunc("/api/unblock", handleUnblock)
	http.HandleFunc("/api/shutdown", handleShutdown)
	http.HandleFunc("/api/audit", handleAudit)
	http.HandleFunc("/audit.json", handleAuditJSON)
	http.HandleFunc("/audit.txt", handleAuditTxt)

	addr, url := resolveListen() // honors LISTEN_ADDR; exposure gated on login

	// Single instance: if the port is taken, another instance is already running.
	ln, err := net.Listen("tcp", addr)
	if err != nil && os.Getenv("RESTART_WAIT") != "" {
		// We were relaunched by "Restart now"; wait (up to ~10s) for the old
		// process to release the port instead of bailing as a second instance.
		for i := 0; i < 100 && err != nil; i++ {
			time.Sleep(100 * time.Millisecond)
			ln, err = net.Listen("tcp", addr)
		}
	}
	if err != nil {
		// Hand off to the instance that owns the port, carrying its token so the
		// browser is authorized by the local gate.
		log.Printf("[!] Ya hay una instancia en %s — abriendo y saliendo.", url)
		openBrowser(tokenURL(url, readLocalToken()))
		os.Exit(0)
	}
	if listenTLS {
		ln = tlsListener(ln) // serve HTTPS when exposed beyond loopback
	}

	// Mint the local access token only once we own the port, so a losing second
	// instance can't overwrite the running instance's token file.
	initLocalToken()

	startupBanner()
	go func() { time.Sleep(1500 * time.Millisecond); openDashboard(url) }()
	log.Printf("[+] eFe Process Monitor → %s", url)
	runApp(ln, url) // serves; on Windows also shows the tray icon + menu
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	lang := langFrom(r)
	if l := r.URL.Query().Get("lang"); l != "" {
		// MaxAge, otherwise the choice is a session cookie and the UI silently
		// reverts to Spanish next time the browser is restarted, unlike every
		// other setting.
		http.SetCookie(w, &http.Cookie{Name: "lang", Value: lang, Path: "/",
			MaxAge: int((365 * 24 * time.Hour).Seconds()), SameSite: http.SameSiteStrictMode})
	}
	render(w, "report.html", map[string]any{"T": strings_(lang), "Lang": lang, "Admin": elevated,
		"RefreshSecs": refreshSecs.Load(), "NoTray": noTrayMode})
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	lang := langFrom(r)
	hideSelf := r.URL.Query().Get("self") != "1" // default: hide own traffic
	render(w, "rows.html", map[string]any{
		"T":     strings_(lang),
		"Conns": analyzeConnections(hideSelf),
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := subscribe()
	defer unsubscribe(ch)
	fmt.Fprintf(w, "data: {\"kind\":\"hello\"}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-time.After(15 * time.Second):
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	var authErr string
	if r.Method == "POST" {
		var body struct {
			VTKey, AbuseKey  string
			NotifyDesktop    *bool
			NotifySound      *bool
			PersistWhitelist *bool
			PersistBlocks    *bool
			RefreshSecs      *int
			AuthEnabled      *bool
			AuthPassword     *string
			CurrentPassword  *string
			ListenAddr       *string
		}
		json.NewDecoder(r.Body).Decode(&body)
		updateSettings(body.VTKey, body.AbuseKey)
		if body.AuthEnabled != nil {
			T := strings_(langFrom(r))
			disabling := !*body.AuthEnabled
			replacing := body.AuthPassword != nil && *body.AuthPassword != ""
			// Changing or removing an *existing* password requires proving you
			// know it, so a hijacked session can't quietly take the gate down.
			locked := authEnabled() && (disabling || replacing) &&
				(body.CurrentPassword == nil || !checkPassword(*body.CurrentPassword))
			switch {
			case locked:
				authErr = T["auth_current_bad"]
			case disabling:
				setAuthPassword("") // disable login
				// Disabling wipes every session, which would lock this very tab
				// out behind the local-token gate. Hand it a fresh session.
				http.SetCookie(w, sessionCookieFor(localSessionTTL))
			case replacing:
				if err := setAuthPassword(*body.AuthPassword); err != nil {
					authErr = T["auth_too_short"]
				} else {
					http.SetCookie(w, sessionCookie()) // keep the operator logged in
				}
			}
		}
		if body.NotifyDesktop != nil {
			setNotifyDesktop(*body.NotifyDesktop)
		}
		if body.NotifySound != nil {
			setNotifySound(*body.NotifySound)
		}
		if body.PersistWhitelist != nil {
			setPersistWhitelist(*body.PersistWhitelist)
		}
		if body.PersistBlocks != nil {
			setPersistBlocks(*body.PersistBlocks)
		}
		if body.RefreshSecs != nil {
			setRefreshSecs(*body.RefreshSecs)
		}
		if body.ListenAddr != nil {
			setListenAddr(*body.ListenAddr)
		}
		log.Println("settings updated via UI")
	}
	resp := getSettings()
	if authErr != "" {
		resp["auth_error"] = authErr
	}
	writeJSON(w, resp)
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
	go func() {
		time.Sleep(400 * time.Millisecond) // let the response flush
		log.Println("restarting via UI…")
		relaunchSelf()
		os.Exit(0)
	}()
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
	go func() {
		time.Sleep(400 * time.Millisecond)
		log.Println("shutdown via UI…")
		os.Exit(0)
	}()
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost, http.MethodDelete) {
		return
	}
	if r.Method == "GET" {
		writeJSON(w, listWhitelist())
		return
	}
	var body struct{ Exe string }
	json.NewDecoder(r.Body).Decode(&body)
	switch r.Method {
	case "POST":
		addWhitelist(body.Exe)
	case "DELETE":
		removeWhitelist(body.Exe)
	}
	writeJSON(w, map[string]any{"ok": true, "exe": body.Exe})
}

func handleIPWhitelist(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodPost, http.MethodDelete) {
		return
	}
	if r.Method == "GET" {
		writeJSON(w, listIPWhitelist())
		return
	}
	var body struct{ IP string }
	json.NewDecoder(r.Body).Decode(&body)
	if net.ParseIP(body.IP) == nil {
		http.Error(w, `{"ok":false,"error":"invalid ip"}`, 400)
		return
	}
	switch r.Method {
	case "POST":
		addIPWhitelist(body.IP)
	case "DELETE":
		removeIPWhitelist(body.IP)
	}
	writeJSON(w, map[string]any{"ok": true, "ip": body.IP})
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct{ PID int }
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.PID <= 0 {
		http.Error(w, `{"ok":false,"error":"invalid pid"}`, 400)
		return
	}
	p, err := process.NewProcess(int32(body.PID))
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "process not found"})
		return
	}
	if err := p.Kill(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	log.Printf("KILL pid=%d by operator", body.PID)
	writeJSON(w, map[string]any{"ok": true, "pid": body.PID})
}

func handleInterfaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, captureInfo(r.URL.Query().Get("refresh") == "1"))
}

var ifaceRe = regexp.MustCompile(`^\d{1,4}$`)

func handleCapture(w http.ResponseWriter, r *http.Request) {
	localIP := r.URL.Query().Get("local_ip")
	remoteIP := r.URL.Query().Get("remote_ip")
	iface := r.URL.Query().Get("iface")
	if net.ParseIP(localIP) == nil || net.ParseIP(remoteIP) == nil {
		http.Error(w, "invalid IP", 400)
		return
	}
	if !ifaceRe.MatchString(iface) {
		http.Error(w, "invalid interface", 400)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	count := 300 // 0 = until stopped
	if n, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && n >= 0 && n <= 100000 {
		count = n
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	stop := make(chan struct{})
	defer close(stop)
	pkts := make(chan map[string]string, 256)
	var errMsg string
	go func() {
		errMsg = streamCapture(localIP, remoteIP, iface, count, func(p map[string]string) {
			select {
			case pkts <- p:
			case <-stop:
			}
		}, stop)
		close(pkts)
	}()
	// Cancellation has to be watched *while* waiting for the next packet, not
	// only after one arrives: with count=0 (∞) on an idle flow, closing the tab
	// used to leave this handler parked on the channel and tshark running
	// indefinitely, because the check was never reached.
	streaming := true
	for streaming {
		select {
		case p, ok := <-pkts:
			if !ok {
				streaming = false
				break
			}
			b, _ := json.Marshal(p)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
	if errMsg != "" {
		b, _ := json.Marshal(map[string]string{"error": errMsg})
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	fmt.Fprint(w, "data: {\"done\":true}\n\n")
	flusher.Flush()
}

func handleCapturePcap(w http.ResponseWriter, r *http.Request) {
	localIP := r.URL.Query().Get("local_ip")
	remoteIP := r.URL.Query().Get("remote_ip")
	iface := r.URL.Query().Get("iface")
	if net.ParseIP(localIP) == nil || net.ParseIP(remoteIP) == nil || !ifaceRe.MatchString(iface) {
		http.Error(w, "invalid parameters", 400)
		return
	}
	count := 1000
	if n, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && n > 0 && n <= 100000 {
		count = n
	}
	cmd := buildPcapCmd(r.Context(), localIP, remoteIP, iface, count, 60) // autostop 60s
	out, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "capture failed", 500)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=capture.pcap")
	if err := cmd.Start(); err != nil {
		http.Error(w, "tshark failed", 500)
		return
	}
	io.Copy(w, out)
	cmd.Wait()
}

func handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		older, _ := strconv.Atoi(r.URL.Query().Get("older"))
		kind := r.URL.Query().Get("kind")
		proc := r.URL.Query().Get("process")
		n := clearEvents(kind, proc, older)
		log.Printf("history cleared by operator (kind=%q process=%q older=%ds): %d events", kind, proc, older, n)
		writeJSON(w, map[string]any{"ok": true, "deleted": n})
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	writeJSON(w, queryEvents(limit, r.URL.Query().Get("kind")))
}

func handleExportJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=events.json")
	writeJSON(w, queryEvents(5000, ""))
}

func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=events.csv")
	cw := csv.NewWriter(w)
	cw.Write([]string{"ts", "kind", "pid", "process", "exe", "local", "remote", "detail"})
	for _, e := range queryEvents(5000, "") {
		cw.Write([]string{e.TS, e.Kind, strconv.Itoa(int(e.PID)), e.Process, e.Exe, e.Local, e.Remote, e.Detail})
	}
	cw.Flush()
}

func handleBlockIP(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct{ IP string }
	json.NewDecoder(r.Body).Decode(&body)
	if !isBlockable(body.IP) {
		writeJSON(w, map[string]any{"ok": false, "error": "IP no bloqueable (0.0.0.0/loopback/multicast)"})
		return
	}
	if err := blockIP(body.IP); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	saveBlocked(body.IP, ipReport(body.IP))
	log.Printf("BLOCK ip=%s by operator", body.IP)
	writeJSON(w, map[string]any{"ok": true, "ip": body.IP})
}

func handleBlocked(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, listBlocked())
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	// Only re-scan when the operator asks (the "re-scan" button); opening the
	// panel serves the cached result. Passing true unconditionally made the TTL
	// dead code and turned every open into a full machine scan.
	writeJSON(w, auditCached(langFrom(r), r.URL.Query().Get("refresh") == "1"))
}

func handleAuditJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=audit.json")
	writeJSON(w, auditCached(langFrom(r), false))
}

func handleAuditTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=audit.txt")
	fmt.Fprintf(w, "eFe Process Monitor — audit %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	mark := map[string]string{"ok": "[ OK ]", "warn": "[WARN]", "risk": "[RISK]", "info": "[INFO]"}
	for _, c := range auditCached(langFrom(r), false) {
		fmt.Fprintf(w, "%s %-12s %s\n        %s\n", mark[c.Status], c.Category, c.Name, c.Detail)
	}
}

func handleUnblock(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct{ IP string }
	json.NewDecoder(r.Body).Decode(&body)
	if net.ParseIP(body.IP) == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "invalid IP"})
		return
	}
	// Always clear our record so a stale entry can't get stuck (e.g. a 0.0.0.0
	// that was never firewall-blocked). The firewall rule only exists for
	// blockable IPs, and removing it is best-effort — a failure is reported as a
	// non-fatal warning, not as a reason to keep the entry.
	var warn string
	if isBlockable(body.IP) {
		if err := unblockIP(body.IP); err != nil {
			warn = err.Error()
		}
	}
	deleteBlocked(body.IP)
	log.Printf("UNBLOCK ip=%s by operator", body.IP)
	resp := map[string]any{"ok": true, "ip": body.IP}
	if warn != "" {
		resp["warn"] = warn
	}
	writeJSON(w, resp)
}

func render(w http.ResponseWriter, name string, data any) {
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template error (%s): %v", name, err)
		http.Error(w, "template error", 500)
	}
}

// requireMethod rejects anything but the allowed methods. State-changing
// endpoints must declare one: the CSRF Origin check only runs on non-GET
// requests, so an endpoint that quietly accepts GET is outside that guard.
func requireMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, `{"ok":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// outboundIP reports the local address the OS would use to reach the internet.
// detectCapture uses it to pick the tshark interface that matches.
func outboundIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}
