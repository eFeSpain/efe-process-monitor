package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Optional update check.
//
// A security tool that stays on an old release without saying so is a quiet
// liability, but a monitor whose privacy panel promises "no telemetry" does
// not get to phone anywhere on its own either. So this is off unless the
// operator turns it on, and when on it is one unauthenticated GET a day to
// GitHub's public releases API: no key, no identifier, a User-Agent that says
// "efemon" and nothing about the machine or the version it runs. The answer
// only ever becomes a discreet notice in the header — nothing is downloaded
// or installed.

// releasesPage is where the notice links. A constant: nothing that came from
// the network is ever used as a link target.
const releasesPage = "https://github.com/eFeSpain/efe-process-monitor/releases/latest"

// releasesAPI is a variable so the tests can point it at a local server.
var releasesAPI = "https://api.github.com/repos/eFeSpain/efe-process-monitor/releases/latest"

const (
	updateEvery      = 24 * time.Hour
	updateRetryAfter = time.Hour // after a failed check
)

var (
	updateCheck     atomic.Bool  // UPDATE_CHECK=true; default off
	latestRelease   atomicString // newest release seen ("" = not known)
	updateLastErr   atomicString // why the last check failed ("" = it did not)
	updateCheckedAt atomic.Int64 // unix time of the last attempt (0 = never)
)

func loadUpdateCheck() { updateCheck.Store(os.Getenv("UPDATE_CHECK") == "true") }

// setUpdateCheck turns the check on or off. Turning it on checks right away,
// so the operator gets an answer now rather than tomorrow; turning it off
// forgets what was known — a disabled feature announces nothing.
func setUpdateCheck(on bool) {
	was := updateCheck.Swap(on)
	writeEnv(map[string]string{"UPDATE_CHECK": fmt.Sprintf("%t", on)})
	switch {
	case on && !was:
		checkForUpdate()
	case !on:
		latestRelease.Store("")
		updateLastErr.Store("")
		updateCheckedAt.Store(0)
	}
}

// parseVersion reads a plain release version, "X.Y.Z" or "vX.Y.Z". Anything
// else (a pre-release suffix, another tag scheme) is not one.
func parseVersion(s string) (v [3]int, ok bool) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || len(p) > 6 || strings.TrimLeft(p, "0123456789") != "" {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// newerVersion reports whether latest is a strictly higher release than current.
func newerVersion(latest, current string) bool {
	l, ok1 := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// fetchLatestRelease asks GitHub for the latest published release and returns
// its version without the "v".
func fetchLatestRelease() (string, error) {
	req, err := http.NewRequest("GET", releasesAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "efemon") // required by GitHub; deliberately says nothing else
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("GitHub answered %d", resp.StatusCode)
	}
	var rel struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", err
	}
	if _, ok := parseVersion(rel.TagName); !ok || rel.Draft || rel.Prerelease {
		return "", fmt.Errorf("latest release is not a plain version: %q", rel.TagName)
	}
	return strings.TrimPrefix(rel.TagName, "v"), nil
}

// checkForUpdate runs one check, if the operator enabled it. A failure keeps
// whatever was known and records why.
func checkForUpdate() {
	if !updateCheck.Load() {
		return
	}
	updateCheckedAt.Store(time.Now().Unix())
	v, err := fetchLatestRelease()
	if err != nil {
		updateLastErr.Store(err.Error())
		log.Printf("[update] %v", err)
		return
	}
	updateLastErr.Store("")
	if latestRelease.Load() != v && newerVersion(v, appVersion) {
		log.Printf("[update] v%s is available (running v%s)", v, appVersion)
	}
	latestRelease.Store(v)
}

// updateAvailable is the newer release to announce, or "".
func updateAvailable() string {
	if v := latestRelease.Load(); updateCheck.Load() && newerVersion(v, appVersion) {
		return v
	}
	return ""
}

// updateDue: once a day while enabled; an hour after a failed attempt.
func updateDue(now int64) bool {
	if !updateCheck.Load() {
		return false
	}
	every := updateEvery
	if updateLastErr.Load() != "" {
		every = updateRetryAfter
	}
	last := updateCheckedAt.Load()
	return last == 0 || now-last >= int64(every/time.Second)
}

// updateLoop wakes every minute — the first check lands a minute after
// start-up, and a change in Settings needs no restart.
func updateLoop() {
	for {
		time.Sleep(time.Minute)
		if updateDue(time.Now().Unix()) {
			checkForUpdate()
		}
	}
}

// updateSettingsInfo is the part of /api/settings that describes the check.
func updateSettingsInfo() map[string]any {
	checked := ""
	if at := updateCheckedAt.Load(); at > 0 {
		checked = time.Unix(at, 0).Format(time.RFC3339)
	}
	return map[string]any{
		"update_check":     updateCheck.Load(),
		"update_latest":    latestRelease.Load(),
		"update_available": updateAvailable(),
		"update_checked":   checked,
		"update_error":     updateLastErr.Load(),
	}
}
