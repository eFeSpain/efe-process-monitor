package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The log file is the only record of operator actions on the shipped Windows
// binary (no console under -H=windowsgui), so the rotation logic is worth
// testing: silently stopping mid-session, or losing the current file during a
// rotation, would take the audit trail with it.

func TestRotatingWriterRotates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.log")
	w, err := newRotatingWriter(p)
	if err == nil {
		t.Cleanup(func() { w.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}

	// Write past the size threshold several times over.
	line := strings.Repeat("x", 4096) + "\n"
	for written := 0; written < logMaxBytes*2; written += len(line) {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	if _, err := os.Stat(p); err != nil {
		t.Errorf("the live log must exist after rotating: %v", err)
	}
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Errorf("expected a rotated file .1: %v", err)
	}
	// Never more than logKeep archives.
	if _, err := os.Stat(fmt.Sprintf("%s.%d", p, logKeep+1)); err == nil {
		t.Errorf("found %s.%d; must keep at most %d archives", p, logKeep+1, logKeep)
	}
	// The live file must be under the cap right after a rotation.
	if fi, err := os.Stat(p); err == nil && fi.Size() > logMaxBytes {
		t.Errorf("live log is %d bytes, over the %d cap", fi.Size(), logMaxBytes)
	}
}

func TestRotatingWriterAppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.log")
	if err := os.WriteFile(p, []byte("previous run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := newRotatingWriter(p)
	if err == nil {
		t.Cleanup(func() { w.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("this run\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// A restart must not truncate the previous session's audit trail.
	if !strings.Contains(string(b), "previous run") || !strings.Contains(string(b), "this run") {
		t.Errorf("expected both sessions in the log, got %q", b)
	}
}

// log.Logger writes from any goroutine; the writer is shared, so it has to be
// safe under concurrent use (run under -race to mean anything).
func TestRotatingWriterConcurrent(t *testing.T) {
	dir := t.TempDir()
	w, err := newRotatingWriter(filepath.Join(dir, "test.log"))
	if err == nil {
		t.Cleanup(func() { w.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := w.Write([]byte(fmt.Sprintf("goroutine %d line %d\n", n, j))); err != nil {
					t.Errorf("write failed: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestTailLogWithoutFile(t *testing.T) {
	old := logPath
	logPath = ""
	t.Cleanup(func() { logPath = old })
	if _, err := tailLog(1024); err == nil {
		t.Error("tailLog should report an error when file logging is inactive")
	}
}

func TestTailLogReturnsTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.log")
	// Longer than the tail we ask for, so the truncation path is exercised.
	body := ""
	for i := 0; i < 500; i++ {
		body += fmt.Sprintf("line %03d ..........\n", i)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := logPath
	logPath = p
	t.Cleanup(func() { logPath = old })

	b, err := tailLog(512)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 512 {
		t.Errorf("tail returned %d bytes, asked for at most 512", len(b))
	}
	// The tail must be the *end* of the file, which is where recent events are.
	if !strings.Contains(string(b), "line 499") {
		t.Errorf("tail should contain the last line, got %q", b)
	}
	if strings.Contains(string(b), "line 000") {
		t.Error("tail should not reach back to the first line")
	}
}
