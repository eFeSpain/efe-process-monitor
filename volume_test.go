package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The rate arithmetic decides whether the volume signal fires at all, and it runs
// against counters that can jump, reset, or be sampled at uneven intervals.

func TestIOSampleFirstReadingHasNoRate(t *testing.T) {
	var s ioSample
	t0 := time.Now()
	s.advance(t0, 1<<30, 1<<30) // huge cumulative totals from a long-running process
	if s.rate.In != 0 || s.rate.Out != 0 || s.rate.HighEgress {
		t.Errorf("a single reading cannot be a rate, got %+v", s.rate)
	}
}

func TestIOSampleComputesRate(t *testing.T) {
	var s ioSample
	t0 := time.Now()
	s.advance(t0, 0, 0)
	s.advance(t0.Add(2*time.Second), 2048, 4096)
	if s.rate.In != 1024 {
		t.Errorf("In = %v, want 1024 B/s", s.rate.In)
	}
	if s.rate.Out != 2048 {
		t.Errorf("Out = %v, want 2048 B/s", s.rate.Out)
	}
}

// A spike is a page load; sustained is a transfer. One sample over the threshold
// must not raise the flag.
func TestIOSampleNeedsSustainedEgress(t *testing.T) {
	var s ioSample
	t0 := time.Now()
	big := uint64(highEgressBytesPerSec * 4)

	s.advance(t0, 0, 0)
	s.advance(t0.Add(time.Second), 0, big)
	if s.rate.HighEgress {
		t.Fatalf("one sample over the threshold is a spike, not a transfer (hot=%d)", s.hot)
	}
	s.advance(t0.Add(2*time.Second), 0, big*2)
	if !s.rate.HighEgress {
		t.Errorf("expected HighEgress after %d consecutive samples", egressHotSamples)
	}

	// Dropping back down clears it: the flag describes now, not history.
	s.advance(t0.Add(3*time.Second), 0, big*2+10)
	if s.rate.HighEgress {
		t.Error("HighEgress should clear once the rate falls")
	}
}

// PID reuse gives us the counters of a different process. Subtracting them would
// produce a wild rate (or with unsigned maths, an enormous one).
func TestIOSampleHandlesCounterReset(t *testing.T) {
	var s ioSample
	t0 := time.Now()
	s.advance(t0, 0, 0)
	s.advance(t0.Add(time.Second), 1<<20, 1<<20)
	s.advance(t0.Add(2*time.Second), 10, 10) // counters went backwards
	if s.rate.In != 0 || s.rate.Out != 0 {
		t.Errorf("a counter reset must clear the rate, got %+v", s.rate)
	}
	if s.rate.Out < 0 {
		t.Error("rate must never be negative")
	}
	// And it recovers on the next pair of readings.
	s.advance(t0.Add(3*time.Second), 10, 1034)
	if s.rate.Out != 1024 {
		t.Errorf("expected the rate to resume after a reset, got %v", s.rate.Out)
	}
}

func TestIOSampleZeroInterval(t *testing.T) {
	var s ioSample
	t0 := time.Now()
	s.advance(t0, 0, 0)
	s.advance(t0, 5000, 5000) // same timestamp: would divide by zero
	if s.rate.Out != 0 {
		t.Errorf("a zero interval must not produce a rate, got %v", s.rate.Out)
	}
}

func TestHumanRate(t *testing.T) {
	for in, want := range map[float64]string{
		0: "0 B", 512: "512 B", 1024: "1 KB",
		1536: "2 KB", 1 << 20: "1 MB", 1 << 30: "1 GB",
	} {
		if got := humanRate(in); got != want {
			t.Errorf("humanRate(%v) = %q, want %q", in, got, want)
		}
	}
}

// The whole point of the design: volume alone must not move the score, because a
// download, a backup and a video call all move data. It only counts when the
// binary was already suspect.
func TestVolumeOnlyScoresInCombination(t *testing.T) {
	base := Conn{VT: "NOT_IN_VT", RemoteIP: "8.8.8.8", Enrich: &Enrichment{},
		Sig: Signature{Status: "Valid", Trusted: true}}

	busy := base
	busy.HighEgress, busy.RateOut = true, 4<<20
	busyScore := threatScore(&busy)
	if busyScore != 0 {
		t.Errorf("high egress alone scored %d, want 0 (%s)", busyScore, busy.Breakdown)
	}

	// Same traffic, but from a binary in a staging directory.
	staged := busy
	staged.Suspicious = true
	stagedScore := threatScore(&staged)
	if stagedScore <= wSuspiciousPath {
		t.Errorf("egress should escalate a staging-path row: got %d, staging alone is %v (%s)",
			stagedScore, wSuspiciousPath, staged.Breakdown)
	}
	if !strings.Contains(staged.Breakdown, "volumen de salida") {
		t.Errorf("breakdown should explain the escalation, got %q", staged.Breakdown)
	}

	// And with an anomalous spawn chain.
	spawned := busy
	spawned.Details = &ProcDetails{BadSpawn: "winword.exe → powershell.exe"}
	if s := threatScore(&spawned); s <= wBadSpawn {
		t.Errorf("egress should escalate a bad-spawn row: got %d, spawn alone is %v", s, wBadSpawn)
	}

	// A staging-path row that is *not* moving data must not get the escalation.
	quiet := base
	quiet.Suspicious = true
	if s := threatScore(&quiet); s != int(wSuspiciousPath) {
		t.Errorf("quiet staging row = %d, want %v (%s)", s, wSuspiciousPath, quiet.Breakdown)
	}
}

// writeSecretFile is what protects the local access token and the TLS private
// key. On Windows the file mode is ignored by the OS, so this is the only thing
// standing between the token and any process running as this user.
func TestWriteSecretFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	const body = "s3cret-token-value"
	if err := writeSecretFile(p, []byte(body)); err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}

	// Rewriting must work: the token is minted fresh on every start.
	if err := writeSecretFile(p, []byte("second")); err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "second" {
		t.Errorf("rewrite left %q", got)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %#o, want 0600", perm)
		}
	}

	// The banner reports this, so it must say something concrete.
	if d := describeFileACL(p); d == "" || d == "desconocida" {
		t.Errorf("describeFileACL returned %q; the startup banner shows this", d)
	}
}

// On Windows the ACL must not leave the broad principals that inheritance grants.
func TestSecretFileACLDropsInheritance(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ACL behaviour is Windows-specific")
	}
	p := filepath.Join(t.TempDir(), "secret")
	if err := writeSecretFile(p, []byte("x")); err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	acl := describeFileACL(p)
	t.Logf("ACL: %s (elevated=%v)", acl, elevated)
	for _, broad := range []string{"Everyone", "Todos", "BUILTIN\\Users", "Usuarios"} {
		if strings.Contains(acl, broad) {
			t.Errorf("ACL still grants %q: %s", broad, acl)
		}
	}
}
