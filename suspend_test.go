package main

import (
	"net/http"
	"strings"
	"testing"
)

// Same refusals as kill: freezing the monitor or init is an outage, not a
// response action, and a PID that does not fit an int32 must not wrap round
// into some other process.
func TestSuspendRefusals(t *testing.T) {
	for _, body := range []string{
		`{"PID":` + itoa(int(ownPID)) + `}`,
		`{"PID":1}`,
		`{"PID":0}`,
		`{"PID":-5}`,
		`{"PID":4294967297}`,
		`{"PID":` + itoa(int(ownPID)) + `,"Resume":true}`,
		`{"PID":`,
	} {
		w := jsonPost(handleSuspend, "/api/suspend", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("suspend %s: got %d %q, want 400", body, w.Code, w.Body.String())
		}
	}
}

// The details offer "suspend" for a running process and "resume" for a frozen
// one, and a frozen process is marked in its row.
func TestSuspendControlsInRows(t *testing.T) {
	tm := testTemplates(t)
	conns := rowsTestConns()
	conns[0].Suspended = true
	var sb strings.Builder
	if err := tm.ExecuteTemplate(&sb, "rows.html", map[string]any{"T": strings_("es"), "Conns": conns}); err != nil {
		t.Fatal(err)
	}
	page := sb.String()
	for _, want := range []string{`data-action="resumeProc"`, `data-action="suspendProc"`, `class="badge-susp"`} {
		if !strings.Contains(page, want) {
			t.Errorf("rows.html lacks %s", want)
		}
	}
	if n := strings.Count(page, `data-action="resumeProc"`); n != 1 {
		t.Errorf("%d resume buttons, want one (only the frozen process)", n)
	}
}
