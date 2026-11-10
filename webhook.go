package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Alert webhook.
//
// Alerts only reached the desktop of whoever was logged in. A monitor that
// runs as a service on a machine nobody is sitting at needs somewhere else to
// say "this happened": one URL, set by the operator, that receives the same
// alerts the desktop notification gets. Off unless configured; the privacy
// panel lists it, because it is an outbound connection carrying process names
// and addresses to a destination of the operator's choosing.
//
// Two shapes, because the receivers disagree:
//   - "json": one object with the alert under the names the common receivers
//     read — text (Slack), content (Discord), title/message (generic).
//   - "text": the message as the body and the title in a Title header, which
//     is what ntfy reads.

// webhookURL / webhookFormat are persisted as ALERT_WEBHOOK / ALERT_WEBHOOK_FORMAT.
// The URL is a secret (the topic or token is part of it): never echoed back.
var webhookURL, webhookFormat atomicString

func loadWebhook() {
	webhookURL.Store(os.Getenv("ALERT_WEBHOOK"))
	f := os.Getenv("ALERT_WEBHOOK_FORMAT")
	if f != "text" {
		f = "json"
	}
	webhookFormat.Store(f)
}

// validWebhookURL accepts an http(s) URL with a host, or "" (clear).
func validWebhookURL(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// maskWebhook shows where alerts go without the part that is the credential.
func maskWebhook(s string) string {
	u, err := url.Parse(s)
	if s == "" || err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/…"
}

var errWebhookInvalid = errors.New("invalid webhook URL")

// setWebhook stores the URL (when not nil; "" clears it) and the format.
func setWebhook(u *string, format *string) error {
	updates := map[string]string{}
	if u != nil {
		v := strings.TrimSpace(*u)
		if !validWebhookURL(v) {
			return errWebhookInvalid
		}
		webhookURL.Store(v)
		updates["ALERT_WEBHOOK"] = v
	}
	if format != nil {
		f := "json"
		if *format == "text" {
			f = "text"
		}
		webhookFormat.Store(f)
		updates["ALERT_WEBHOOK_FORMAT"] = f
	}
	if len(updates) > 0 {
		writeEnv(updates)
	}
	return nil
}

// sendWebhook posts one alert. No URL configured is not an error.
func sendWebhook(title, message string) error {
	target := webhookURL.Load()
	if target == "" {
		return nil
	}
	var req *http.Request
	var err error
	if webhookFormat.Load() == "text" {
		req, err = http.NewRequest("POST", target, strings.NewReader(message))
		if err == nil {
			req.Header.Set("Content-Type", "text/plain; charset=utf-8")
			req.Header.Set("Title", title)
		}
	} else {
		host, _ := os.Hostname()
		line := title + " — " + message
		body, _ := json.Marshal(map[string]string{
			"title": title, "message": message,
			"text": line, "content": line, // Slack / Discord
			"host": host, "app": "efemon", "version": appVersion,
			"time": time.Now().Format(time.RFC3339),
		})
		req, err = http.NewRequest("POST", target, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "efemon/"+appVersion)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook answered %d", resp.StatusCode)
	}
	return nil
}

// forwardAlert is the fire-and-forget path from notify(): failures go to the
// log, masked, never to the caller.
func forwardAlert(title, message string) {
	if err := sendWebhook(title, message); err != nil {
		log.Printf("[webhook] %s: %v", maskWebhook(webhookURL.Load()), err)
	}
}
