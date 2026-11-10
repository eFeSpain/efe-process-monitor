package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// withUpdateCheck points the check at a fake releases endpoint and restores
// every piece of state it touches.
func withUpdateCheck(t *testing.T, url string, on bool) {
	t.Helper()
	oldURL, oldOn, oldLatest, oldErr := releasesAPI, updateCheck.Load(), latestRelease.Load(), updateLastErr.Load()
	oldAt := updateCheckedAt.Load()
	releasesAPI = url
	updateCheck.Store(on)
	latestRelease.Store("")
	updateLastErr.Store("")
	updateCheckedAt.Store(0)
	t.Cleanup(func() {
		releasesAPI = oldURL
		updateCheck.Store(oldOn)
		latestRelease.Store(oldLatest)
		updateLastErr.Store(oldErr)
		updateCheckedAt.Store(oldAt)
	})
}

func releaseServer(t *testing.T, body string, status int, hits *atomic.Int64, ua *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if ua != nil {
			ua.Store(r.Header.Get("User-Agent"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Only a strictly higher X.Y.Z counts as new. Anything that is not a plain
// release version — a pre-release, a tag from some other scheme, garbage from
// a proxy — is never announced.
func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"0.6.0", "0.5.0", true},
		{"v0.6.0", "0.5.0", true},
		{"0.5.1", "0.5.0", true},
		{"1.0.0", "0.9.9", true},
		{"0.10.0", "0.9.0", true}, // numeric, not lexical
		{"0.5.0", "0.5.0", false},
		{"0.4.9", "0.5.0", false},
		{"0.6.0-rc1", "0.5.0", false},
		{"0.6", "0.5.0", false},
		{"", "0.5.0", false},
		{"<script>", "0.5.0", false},
		{"0.6.0", "dev", false},
	} {
		if got := newerVersion(c.latest, c.current); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestFetchLatestRelease(t *testing.T) {
	var ua atomic.Value
	srv := releaseServer(t, `{"tag_name":"v9.9.9","draft":false,"prerelease":false,"body":"notes"}`, 200, nil, &ua)
	withUpdateCheck(t, srv.URL, true)
	v, err := fetchLatestRelease()
	if err != nil || v != "9.9.9" {
		t.Fatalf("fetchLatestRelease = %q, %v; want 9.9.9", v, err)
	}
	// GitHub refuses requests without a User-Agent. It names the tool and
	// nothing else: no version, no host, nothing about the machine.
	if got, _ := ua.Load().(string); got != "efemon" {
		t.Errorf("User-Agent = %q, want just the tool name", got)
	}

	for name, body := range map[string]string{
		"not a version": `{"tag_name":"nightly"}`,
		"pre-release":   `{"tag_name":"v9.9.9","prerelease":true}`,
		"draft":         `{"tag_name":"v9.9.9","draft":true}`,
		"not JSON":      `<html>rate limited</html>`,
	} {
		srv := releaseServer(t, body, 200, nil, nil)
		releasesAPI = srv.URL
		if v, err := fetchLatestRelease(); err == nil {
			t.Errorf("%s: got %q with no error", name, v)
		}
	}
	srv = releaseServer(t, `{"tag_name":"v9.9.9"}`, 403, nil, nil)
	releasesAPI = srv.URL
	if _, err := fetchLatestRelease(); err == nil {
		t.Error("a 403 (rate limit) must be an error")
	}
}

// Off is off: with the check disabled the monitor never contacts GitHub.
func TestUpdateCheckOffSendsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := releaseServer(t, `{"tag_name":"v9.9.9"}`, 200, &hits, nil)
	withUpdateCheck(t, srv.URL, false)
	checkForUpdate()
	if hits.Load() != 0 || updateAvailable() != "" {
		t.Errorf("disabled check made %d requests, available=%q", hits.Load(), updateAvailable())
	}
}

func TestUpdateDefaultsOff(t *testing.T) {
	old := updateCheck.Load()
	t.Cleanup(func() { updateCheck.Store(old) })
	t.Setenv("UPDATE_CHECK", "")
	loadUpdateCheck()
	if updateCheck.Load() {
		t.Error("the update check must be off unless the operator turns it on")
	}
	t.Setenv("UPDATE_CHECK", "true")
	loadUpdateCheck()
	if !updateCheck.Load() {
		t.Error("UPDATE_CHECK=true turns it on")
	}
}

func TestCheckForUpdate(t *testing.T) {
	srv := releaseServer(t, `{"tag_name":"v9.9.9"}`, 200, nil, nil)
	withUpdateCheck(t, srv.URL, true)
	checkForUpdate()
	if updateAvailable() != "9.9.9" || updateCheckedAt.Load() == 0 || updateLastErr.Load() != "" {
		t.Errorf("available=%q at=%d err=%q", updateAvailable(), updateCheckedAt.Load(), updateLastErr.Load())
	}

	// Running the latest release: nothing to announce.
	srv = releaseServer(t, `{"tag_name":"v`+appVersion+`"}`, 200, nil, nil)
	withUpdateCheck(t, srv.URL, true)
	checkForUpdate()
	if updateAvailable() != "" || latestRelease.Load() != appVersion {
		t.Errorf("same version: available=%q latest=%q", updateAvailable(), latestRelease.Load())
	}

	// A failed check records why and keeps what was known.
	withUpdateCheck(t, srv.URL, true)
	latestRelease.Store("9.9.9")
	bad := releaseServer(t, `nope`, 500, nil, nil)
	releasesAPI = bad.URL
	checkForUpdate()
	if updateLastErr.Load() == "" || updateAvailable() != "9.9.9" {
		t.Errorf("after a failure: err=%q available=%q", updateLastErr.Load(), updateAvailable())
	}
}

// Due once a day, and not at all while disabled.
func TestUpdateDue(t *testing.T) {
	withUpdateCheck(t, "http://127.0.0.1:1/", true)
	const day = int64(24 * 3600)
	now := int64(1_800_000_000)
	if !updateDue(now) {
		t.Error("never checked: due")
	}
	updateCheckedAt.Store(now - day + 60)
	if updateDue(now) {
		t.Error("checked 23 h 59 min ago: not due")
	}
	updateCheckedAt.Store(now - day)
	if !updateDue(now) {
		t.Error("checked a day ago: due")
	}
	updateCheck.Store(false)
	if updateDue(now) {
		t.Error("disabled: never due")
	}
}

func TestUpdateSettings(t *testing.T) {
	withTempEnv(t)
	var hits atomic.Int64
	srv := releaseServer(t, `{"tag_name":"v9.9.9"}`, 200, &hits, nil)
	withUpdateCheck(t, srv.URL, false)

	var out map[string]any
	json.Unmarshal(jsonPost(handleSettings, "/api/settings", `{}`).Body.Bytes(), &out)
	if out["update_check"] != false || out["update_available"] != "" {
		t.Errorf("default: %v %v", out["update_check"], out["update_available"])
	}

	// Turning it on checks right away, so the operator sees an answer instead
	// of waiting a day for the first one.
	setUpdateCheck(true)
	if hits.Load() != 1 || updateAvailable() != "9.9.9" {
		t.Errorf("enabling: hits=%d available=%q", hits.Load(), updateAvailable())
	}
	out = map[string]any{}
	json.Unmarshal(jsonPost(handleSettings, "/api/settings", `{}`).Body.Bytes(), &out)
	if out["update_check"] != true || out["update_available"] != "9.9.9" || out["update_checked"] == "" {
		t.Errorf("enabled: %v %v %v", out["update_check"], out["update_available"], out["update_checked"])
	}

	// Turning it off forgets what it knew: no notice from a disabled feature.
	setUpdateCheck(false)
	if updateAvailable() != "" {
		t.Errorf("disabled but still announcing %q", updateAvailable())
	}
}

// The header notice and the Settings switch exist; the link goes to the
// releases page (a constant — nothing from the network ends up in an href)
// and the privacy panel lists the connection.
func TestUpdateNoticeMarkup(t *testing.T) {
	page := renderedPages(t)["report.html"]
	for _, want := range []string{
		`id="update-link"`, `href="` + releasesPage + `"`, `rel="noopener noreferrer"`,
		`id="update-check"`, `id="update-status"`, `id="priv-update"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("report.html lacks %s", want)
		}
	}
	i := strings.Index(page, `<a id="update-link"`)
	if i < 0 {
		t.Fatal("the notice is a link")
	}
	if tag := page[i : i+strings.Index(page[i:], ">")]; !strings.Contains(tag, "display:none") {
		t.Errorf("the notice starts hidden, it only appears when a newer release is known: %s", tag)
	}
}
