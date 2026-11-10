package main

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"
)

// Scheduled audit.
//
// The machine audit only ran when somebody opened its panel. The audit's diff
// already knows what is new against the baseline — a Run key, a cron job, a
// systemd unit, an authorized SSH key, an account with UID 0 — and with the
// monitor running as a service that is exactly what should reach the operator
// without them asking. A pass every auditEveryHours; each new item is
// reported once, in the live feed, the history and a desktop notification.

const (
	defaultAuditEveryHours = 6
	maxAuditEveryHours     = 168 // a week
	auditFirstDelay        = 2 * time.Minute
)

// auditEveryHours is the schedule (hours; 0 = off), persisted as
// AUDIT_EVERY_HOURS. Atomic: the scheduler reads it, Settings writes it.
var auditEveryHours atomic.Int64

func init() { auditEveryHours.Store(defaultAuditEveryHours) }

func setAuditEvery(n int) {
	if n < 0 {
		n = 0
	}
	if n > maxAuditEveryHours {
		n = maxAuditEveryHours
	}
	auditEveryHours.Store(int64(n))
	writeEnv(map[string]string{"AUDIT_EVERY_HOURS": fmt.Sprintf("%d", n)})
}

// newAuditFindings returns "check name: item" for every new item not reported
// yet, and records it in notified. An item stays "new" in the panel for 24 h;
// without this the same finding would be announced at every pass of that day.
func newAuditFindings(checks []AuditCheck, notified map[string]bool) []string {
	var lines []string
	for _, c := range checks {
		for _, it := range c.New {
			k := c.Key + "|" + auditItemKey(it)
			if notified[k] {
				continue
			}
			notified[k] = true
			lines = append(lines, c.Name+": "+it)
		}
	}
	return lines
}

// auditScheduler runs the audit on schedule. The first pass is shortly after
// start-up (the boot-time persistence check), then every auditEveryHours; the
// setting is re-read every minute so a change in Settings needs no restart.
func auditScheduler() {
	notified := map[string]bool{}
	started := time.Now()
	var last time.Time
	for {
		time.Sleep(time.Minute)
		every := time.Duration(auditEveryHours.Load()) * time.Hour
		if every == 0 {
			continue
		}
		if last.IsZero() {
			if time.Since(started) < auditFirstDelay {
				continue
			}
		} else if time.Since(last) < every {
			continue
		}
		last = time.Now()
		lang := currentLang()
		lines := newAuditFindings(auditCached(lang, true), notified)
		if len(lines) == 0 {
			continue
		}
		shown := lines
		if len(shown) > 5 {
			shown = shown[:5]
		}
		T := strings_(lang)
		detail := fmt.Sprintf(T["ev_audit_new"], len(lines), strings.Join(shown, " | "))
		log.Printf("[audit] %s", detail)
		publish(Event{Kind: "alert", Level: "med", Process: "audit", Detail: detail})
		notify(T["notif_audit"], detail, "audit")
	}
}
