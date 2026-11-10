package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// histFixture fills the history with events at known moments, oldest first.
func histFixture(t *testing.T) {
	t.Helper()
	setupTestDB(t)
	at := func(day, hour int) float64 {
		return float64(time.Date(2026, 11, day, hour, 0, 0, 0, time.Local).Unix())
	}
	for _, e := range []struct {
		epoch float64
		ev    Event
	}{
		{at(1, 9), Event{Kind: "new", PID: 100, Process: "sshd", Exe: "/usr/sbin/sshd", Local: "0.0.0.0:22"}},
		{at(2, 10), Event{Kind: "remote", PID: 200, Process: "chrome", Exe: "/opt/google/chrome/chrome", Remote: "142.250.184.14:443"}},
		{at(3, 11), Event{Kind: "alert", PID: 300, Process: "nc", Exe: "/tmp/.x/nc", Remote: "203.0.113.9:4444", Detail: "Feodo C2"}},
		{at(4, 12), Event{Kind: "closed", PID: 300, Process: "nc", Exe: "/tmp/.x/nc", Remote: "203.0.113.9:4444"}},
		{at(5, 13), Event{Kind: "remote", PID: 400, Process: "Chrome_Helper", Exe: "/opt/google/chrome/helper", Remote: "203.0.113.9:443", Detail: "100% CPU"}},
		{at(6, 14), Event{Kind: "alert", PID: 500, Process: "python3", Exe: "/usr/bin/python3", Local: "0.0.0.0:8080", Detail: "puerto nuevo a la escucha: tcp/8080"}},
	} {
		if _, err := db.Exec(`INSERT INTO events (epoch, ts, kind, pid, process, exe, local, remote, detail) VALUES (?,?,?,?,?,?,?,?,?)`,
			e.epoch, time.Unix(int64(e.epoch), 0).Format("15:04:05"), e.ev.Kind, e.ev.PID, e.ev.Process, e.ev.Exe, e.ev.Local, e.ev.Remote, e.ev.Detail); err != nil {
			t.Fatal(err)
		}
	}
}

func pids(evs []HistEvent) []int32 {
	var out []int32
	for _, e := range evs {
		out = append(out, e.PID)
	}
	return out
}

func samePIDs(got []int32, want ...int32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The history used to be the last 500 events, filtered in the browser by
// process name. The search runs in the database, over everything retained:
// by any text of the event, by kind and by date range, a page at a time.
func TestSearchEvents(t *testing.T) {
	histFixture(t)
	for _, c := range []struct {
		name string
		f    eventFilter
		want []int32 // newest first
	}{
		{"everything", eventFilter{}, []int32{500, 400, 300, 300, 200, 100}},
		{"process name, any case", eventFilter{Text: "CHROME"}, []int32{400, 200}},
		{"remote address", eventFilter{Text: "203.0.113.9"}, []int32{400, 300, 300}},
		{"path", eventFilter{Text: "/tmp/"}, []int32{300, 300}},
		{"detail", eventFilter{Text: "feodo"}, []int32{300}},
		{"local port", eventFilter{Text: ":8080"}, []int32{500}},
		{"every word must match", eventFilter{Text: "nc 4444 feodo"}, []int32{300}},
		{"a number is also a PID", eventFilter{Text: "200"}, []int32{200}},
		{"% is a character, not a wildcard", eventFilter{Text: "100%"}, []int32{400}},
		{"_ is a character, not a wildcard", eventFilter{Text: "chrome_helper"}, []int32{400}},
		{"% typed by the operator matches nothing else", eventFilter{Text: "1%4"}, nil},
		{"_ typed by the operator matches nothing else", eventFilter{Text: "chrom_"}, nil},
		{"the older process filter", eventFilter{Process: "chrome"}, []int32{400, 200}},
		{"kind", eventFilter{Kind: "alert"}, []int32{500, 300}},
		{"kind and text", eventFilter{Kind: "closed", Text: "nc"}, []int32{300}},
		{"from", eventFilter{From: float64(time.Date(2026, 11, 5, 0, 0, 0, 0, time.Local).Unix())}, []int32{500, 400}},
		{"to", eventFilter{To: float64(time.Date(2026, 11, 2, 0, 0, 0, 0, time.Local).Unix())}, []int32{100}},
		{"range", eventFilter{
			From: float64(time.Date(2026, 11, 2, 0, 0, 0, 0, time.Local).Unix()),
			To:   float64(time.Date(2026, 11, 4, 0, 0, 0, 0, time.Local).Unix())}, []int32{300, 200}},
		{"nothing", eventFilter{Text: "no-such-thing"}, nil},
	} {
		evs, next := searchEvents(c.f)
		if !samePIDs(pids(evs), c.want...) || next != 0 {
			t.Errorf("%s: got %v (next=%d), want %v", c.name, pids(evs), next, c.want)
		}
	}

	// A row says when it happened, not only at what time of day: the history
	// spans weeks.
	evs, _ := searchEvents(eventFilter{Text: "sshd"})
	if len(evs) != 1 || evs[0].At != "2026-11-01 09:00:00" || evs[0].TS != "09:00:00" {
		t.Errorf("row date: %+v", evs)
	}
}

func TestSearchEventsPages(t *testing.T) {
	histFixture(t)
	var seen []int32
	f := eventFilter{Limit: 4}
	evs, next := searchEvents(f)
	if len(evs) != 4 || next == 0 {
		t.Fatalf("first page: %d events, next=%d; want 4 and a cursor", len(evs), next)
	}
	seen = append(seen, pids(evs)...)
	f.Before = next
	evs, next = searchEvents(f)
	if len(evs) != 2 || next != 0 {
		t.Fatalf("last page: %d events, next=%d; want 2 and no cursor", len(evs), next)
	}
	seen = append(seen, pids(evs)...)
	if !samePIDs(seen, 500, 400, 300, 300, 200, 100) {
		t.Errorf("pages overlap or skip: %v", seen)
	}
	// A page that ends exactly at the last row has no cursor either.
	if evs, next := searchEvents(eventFilter{Limit: 6}); len(evs) != 6 || next != 0 {
		t.Errorf("exact fit: %d events, next=%d", len(evs), next)
	}
}

func getHistory(t *testing.T, query string) (int, struct {
	Events []HistEvent `json:"events"`
	Next   int64       `json:"next"`
}) {
	t.Helper()
	w := httptest.NewRecorder()
	handleHistory(w, httptest.NewRequest(http.MethodGet, "/api/history?"+query, nil))
	var out struct {
		Events []HistEvent `json:"events"`
		Next   int64       `json:"next"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("history is not JSON: %v %s", err, w.Body.String())
		}
	}
	return w.Code, out
}

func TestHistoryAPI(t *testing.T) {
	histFixture(t)
	q := url.Values{"q": {"203.0.113.9"}, "kind": {"remote"}}
	if code, out := getHistory(t, q.Encode()); code != 200 || !samePIDs(pids(out.Events), 400) {
		t.Errorf("q+kind: %d %v", code, pids(out.Events))
	}
	// The dates are what a datetime-local field sends, in local time. "to" is
	// inclusive of the moment named: a day includes the whole day.
	if code, out := getHistory(t, "from=2026-11-03T00:00&to=2026-11-04T12:00"); code != 200 || !samePIDs(pids(out.Events), 300, 300) {
		t.Errorf("minute range: %d %v", code, pids(out.Events))
	}
	if code, out := getHistory(t, "from=2026-11-05&to=2026-11-05"); code != 200 || !samePIDs(pids(out.Events), 400) {
		t.Errorf("one day: %d %v", code, pids(out.Events))
	}
	code, out := getHistory(t, "limit=5")
	if code != 200 || len(out.Events) != 5 || out.Next == 0 {
		t.Fatalf("limit: %d n=%d next=%d", code, len(out.Events), out.Next)
	}
	if code, out := getHistory(t, "limit=5&before="+itoa(int(out.Next))); code != 200 || !samePIDs(pids(out.Events), 100) || out.Next != 0 {
		t.Errorf("second page: %d %v next=%d", code, pids(out.Events), out.Next)
	}
	// An empty result is an empty list, not null: the page maps over it.
	w := httptest.NewRecorder()
	handleHistory(w, httptest.NewRequest(http.MethodGet, "/api/history?q=no-such-thing", nil))
	if !strings.Contains(w.Body.String(), `"events":[]`) {
		t.Errorf("empty result: %s", w.Body.String())
	}
	// A filter that cannot be understood is refused, not silently dropped —
	// dropping it would show (or delete) far more than was asked for.
	for _, bad := range []string{"from=yesterday", "to=2026-13-40", "before=x", "limit=-1"} {
		if code, _ := getHistory(t, bad); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", bad, code)
		}
	}
}

// Deleting uses the same filter as the list: what is on screen is what goes.
func TestDeleteHistoryUsesTheSearchFilter(t *testing.T) {
	histFixture(t)
	del := func(query string) (int, string) {
		w := httptest.NewRecorder()
		handleAPIEvents(w, httptest.NewRequest(http.MethodDelete, "/api/events?"+query, nil))
		return w.Code, w.Body.String()
	}
	if code, _ := del("q=nc"); code != http.StatusBadRequest {
		t.Errorf("no confirm: %d, want 400", code)
	}
	if code, body := del("confirm=1&q=203.0.113.9&kind=closed"); code != 200 || !strings.Contains(body, `"deleted":1`) {
		t.Errorf("q+kind: %d %s", code, body)
	}
	if code, body := del("confirm=1&from=2026-11-06&to=2026-11-06"); code != 200 || !strings.Contains(body, `"deleted":1`) {
		t.Errorf("date range: %d %s", code, body)
	}
	if code, _ := del("confirm=1&from=whenever"); code != http.StatusBadRequest {
		t.Errorf("a bad date must not turn into 'delete everything': %d", code)
	}
	// The old parameter still works: process name contains.
	if code, body := del("confirm=1&process=chrome"); code != 200 || !strings.Contains(body, `"deleted":2`) {
		t.Errorf("process: %d %s", code, body)
	}
	if evs, _ := searchEvents(eventFilter{}); !samePIDs(pids(evs), 300, 100) {
		t.Errorf("left: %v", pids(evs))
	}
}

// The exports take the same filter, and their rows carry the date.
func TestExportsUseTheSearchFilter(t *testing.T) {
	histFixture(t)
	w := httptest.NewRecorder()
	handleExportCSV(w, httptest.NewRequest(http.MethodGet, "/export.csv?q=nc", nil))
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("csv: err=%v rows=%d\n%s", err, len(rows), w.Body.String())
	}
	if rows[0][0] != "ts" || rows[1][0] != "2026-11-04 12:00:00" || rows[2][0] != "2026-11-03 11:00:00" {
		t.Errorf("csv dates: %v / %v / %v", rows[0], rows[1], rows[2])
	}
	w = httptest.NewRecorder()
	handleExportJSON(w, httptest.NewRequest(http.MethodGet, "/export.json?kind=alert", nil))
	var evs []HistEvent
	if err := json.Unmarshal(w.Body.Bytes(), &evs); err != nil || !samePIDs(pids(evs), 500, 300) || evs[0].At == "" {
		t.Errorf("json: err=%v %v", err, pids(evs))
	}
	w = httptest.NewRecorder()
	handleExportCSV(w, httptest.NewRequest(http.MethodGet, "/export.csv?from=nonsense", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad filter on export: %d", w.Code)
	}
}

func TestHistoryModalMarkup(t *testing.T) {
	page := renderedPages(t)["report.html"]
	for _, want := range []string{
		`id="hist-q"`, `id="hist-kind"`, `id="hist-from"`, `id="hist-to"`, `type="datetime-local"`,
		`data-action="moreHistory"`, `id="hist-count"`,
		`<option value="alert">`, `<option value="remote">`, `<option value="new">`, `<option value="closed">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("history modal lacks %s", want)
		}
	}
}
