package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Logging has to survive the shipped Windows binary.
//
// Release builds link with -H=windowsgui so no console window appears, which
// means the process has no usable stderr: every log line — including the whole
// operator audit trail (KILL, BLOCK, UNBLOCK, settings changed, history cleared)
// and the security events ([gate] blocked, [csrf] blocked) — was written to a
// handle that goes nowhere. For a forensic tool, silently losing the record of
// what the operator did is the wrong failure mode.
//
// So: always tee to a rotating file next to the executable, and keep stderr for
// the console/dev builds where it still works.

const (
	logFileName = "efemon.log"
	logMaxBytes = 5 << 20 // rotate past 5 MiB
	logKeep     = 3       // efemon.log.1 … .3
)

// rotatingWriter is a size-rotating file writer. Deliberately hand-rolled: the
// project ships a single cgo-free binary and this is ~60 lines, which is a
// better trade than another module in go.mod.
type rotatingWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func newRotatingWriter(path string) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

// open attaches to the current log file. Caller holds mu (or is the constructor).
func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f = f
	w.size = 0
	if fi, err := f.Stat(); err == nil {
		w.size = fi.Size()
	}
	return nil
}

// rotate shifts efemon.log.N → .N+1 and starts a fresh log. Caller holds mu.
//
// The file is closed before renaming and reopened after: on Windows an open file
// cannot be renamed, so the close/rename/open order is required, not stylistic.
func (w *rotatingWriter) rotate() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, logKeep))
	for i := logKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	_ = os.Rename(w.path, w.path+".1")
	_ = w.open() // if this fails, Write below degrades to dropping lines, not crashing
}

// Close releases the underlying file. The process-wide logger never needs this
// (it lives until exit), but a type that owns a file handle and can't hand it
// back is untestable on Windows, where an open file cannot be removed.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil // rotation failed earlier; drop rather than kill the app
	}
	if w.size+int64(len(p)) > logMaxBytes {
		w.rotate()
		if w.f == nil {
			return len(p), nil
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// logPath is where the log ended up, for the UI and the startup banner.
var logPath string

// initLogging tees the standard logger to a rotating file. Called as early as
// possible in main so even the startup banner is captured.
//
// A failure here is not fatal: the app is still useful without a log file, and
// refusing to start a security monitor because it can't write a log (read-only
// install directory, for instance) would be the worse outcome.
func initLogging() {
	log.SetFlags(log.LstdFlags) // keep the existing "2026/08/11 18:13:47 " prefix

	p := filepath.Join(appDir, logFileName)
	w, err := newRotatingWriter(p)
	if err != nil {
		log.Printf("[!] no se pudo abrir %s: %v — solo log en consola", p, err)
		return
	}
	logPath = p
	// Tee: the file is what survives in the GUI build, stderr is what a developer
	// running from a terminal expects to see.
	log.SetOutput(io.MultiWriter(os.Stderr, w))
}

// tailLog returns the last maxBytes of the log for the UI, oldest-first.
func tailLog(maxBytes int64) ([]byte, error) {
	if logPath == "" {
		return nil, fmt.Errorf("logging to file is not active")
	}
	f, err := os.Open(logPath) // #nosec G304 -- logPath is built by us from appDir
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if fi.Size() > maxBytes {
		start = fi.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
