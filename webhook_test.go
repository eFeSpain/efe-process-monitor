package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// capture is a webhook receiver that records what it was sent.
type capture struct {
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

func (c *capture) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, string(b))
	c.headers = append(c.headers, r.Header.Clone())
	c.mu.Unlock()
}

func (c *capture) wait(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.bodies)
		c.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("webhook received %d requests, want %d", len(c.bodies), n)
}

func withWebhook(t *testing.T, url, format string) {
	t.Helper()
	oldU, oldF := webhookURL.Load(), webhookFormat.Load()
	webhookURL.Store(url)
	webhookFormat.Store(format)
	t.Cleanup(func() { webhookURL.Store(oldU); webhookFormat.Store(oldF) })
}

// The JSON format carries the alert under the names the common receivers read:
// text (Slack), content (Discord), title/message (anything generic).
func TestWebhookJSON(t *testing.T) {
	var c capture
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	withWebhook(t, srv.URL+"/hook", "json")
	if err := sendWebhook("⚠ Reputación", "chrome → 203.0.113.9 (C2 Feodo)"); err != nil {
		t.Fatal(err)
	}
	c.wait(t, 1)
	var got map[string]any
	if err := json.Unmarshal([]byte(c.bodies[0]), &got); err != nil {
		t.Fatalf("body is not JSON: %v %q", err, c.bodies[0])
	}
	for _, k := range []string{"title", "message", "text", "content", "host", "app", "time"} {
		if got[k] == nil || got[k] == "" {
			t.Errorf("JSON lacks %q: %v", k, got)
		}
	}
	if got["title"] != "⚠ Reputación" || !strings.Contains(got["text"].(string), "C2 Feodo") || got["app"] != "efemon" {
		t.Errorf("payload: %v", got)
	}
	if ct := c.headers[0].Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
}

// The text format is what ntfy reads: the message as the body, the title in
// a header.
func TestWebhookText(t *testing.T) {
	var c capture
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	withWebhook(t, srv.URL+"/topic", "text")
	if err := sendWebhook("Posible DGA", "25 dominios inexistentes"); err != nil {
		t.Fatal(err)
	}
	c.wait(t, 1)
	if c.bodies[0] != "25 dominios inexistentes" || c.headers[0].Get("Title") != "Posible DGA" {
		t.Errorf("body=%q Title=%q", c.bodies[0], c.headers[0].Get("Title"))
	}
}

// An alert reaches the webhook even with desktop notifications off — the
// machine nobody is sitting at is the case it exists for — and is throttled
// like the desktop one.
func TestNotifyForwardsToWebhook(t *testing.T) {
	var c capture
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	withWebhook(t, srv.URL, "json")
	old := notifyDesktop.Load()
	notifyDesktop.Store(false)
	t.Cleanup(func() { notifyDesktop.Store(old) })
	notify("t", "first", "webhook-test-key")
	notify("t", "again within the throttle window", "webhook-test-key")
	c.wait(t, 1)
	time.Sleep(100 * time.Millisecond)
	if len(c.bodies) != 1 {
		t.Errorf("webhook got %d requests, want 1 (throttled per key)", len(c.bodies))
	}
}

func TestWebhookErrorsAndValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	withWebhook(t, srv.URL, "json")
	if err := sendWebhook("t", "m"); err == nil {
		t.Error("a 500 from the receiver must be an error")
	}
	withWebhook(t, "", "json")
	if err := sendWebhook("t", "m"); err != nil {
		t.Errorf("no URL configured is not an error, just nothing to do: %v", err)
	}
	for u, ok := range map[string]bool{
		"https://ntfy.sh/mytopic": true, "http://192.168.1.5:8080/hook": true, "": true,
		"javascript:alert(1)": false, "file:///etc/passwd": false, "ftp://x/y": false, "https://": false, "not a url": false,
	} {
		if got := validWebhookURL(u); got != ok {
			t.Errorf("validWebhookURL(%q) = %v, want %v", u, got, ok)
		}
	}
	// The URL is a secret (the topic or token is in its path): only scheme and
	// host are ever shown back.
	if got := maskWebhook("https://ntfy.sh/my-secret-topic?auth=abc"); got != "https://ntfy.sh/…" {
		t.Errorf("maskWebhook = %q", got)
	}
	if maskWebhook("") != "" {
		t.Error("empty stays empty")
	}
}

func TestWebhookSettings(t *testing.T) {
	withTempEnv(t)
	withWebhook(t, "", "json")
	w := jsonPost(handleSettings, "/api/settings", `{"WebhookURL":"https://ntfy.sh/topic-xyz","WebhookFormat":"text"}`)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["webhook_configured"] != true || out["webhook_hint"] != "https://ntfy.sh/…" || out["webhook_format"] != "text" {
		t.Errorf("settings: %v %v %v", out["webhook_configured"], out["webhook_hint"], out["webhook_format"])
	}
	if strings.Contains(w.Body.String(), "topic-xyz") {
		t.Error("the full webhook URL must never be echoed back")
	}
	w = jsonPost(handleSettings, "/api/settings", `{"WebhookURL":"javascript:alert(1)"}`)
	out = map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["webhook_error"] == nil || webhookURL.Load() != "https://ntfy.sh/topic-xyz" {
		t.Errorf("an invalid URL must be refused and the old one kept: %v", out["webhook_error"])
	}
	jsonPost(handleSettings, "/api/settings", `{"WebhookURL":""}`)
	if webhookURL.Load() != "" {
		t.Error("an explicit empty URL clears the webhook")
	}
}
