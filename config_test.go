package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A value with a newline in it would be written as a second .env line. The
// interesting payload is "AUTH_HASH=": on the next start godotenv keeps the last
// assignment, so a settings request that only had to be authenticated — never
// asked for the current password — could switch the login off.
func TestWriteEnvRejectsLineInjection(t *testing.T) {
	old := envPath
	envPath = filepath.Join(t.TempDir(), ".env")
	t.Cleanup(func() { envPath = old })

	writeEnv(map[string]string{"AUTH_HASH": "real-hash"})
	writeEnv(map[string]string{"VT_API_KEY": "key\nAUTH_HASH=\r\nLISTEN_ADDR=0.0.0.0:80"})

	body, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly the two keys written, got %d lines:\n%s", len(lines), body)
	}
	if !strings.Contains(string(body), "AUTH_HASH=real-hash") {
		t.Errorf("AUTH_HASH was overwritten:\n%s", body)
	}
	// The payload is neutralized, not silently dropped: it stays inside the
	// VT_API_KEY value, on that one line, where godotenv reads it as a (bad) key.
	for _, ln := range lines {
		if strings.HasPrefix(ln, "LISTEN_ADDR=") {
			t.Errorf("injected key became its own line:\n%s", body)
		}
	}
}

func TestCleanEnvValue(t *testing.T) {
	for in, want := range map[string]string{
		"  abc  ":       "abc",
		"a\nb":          "ab",
		"a\r\nb":        "ab",
		"a\x00b":        "ab",
		"plain-value":   "plain-value",
		"with # inside": "with # inside",
	} {
		if got := cleanEnvValue(in); got != want {
			t.Errorf("cleanEnvValue(%q) = %q, want %q", in, got, want)
		}
	}
}
