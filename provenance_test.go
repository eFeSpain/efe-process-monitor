package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSummarizeChildren(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []string
		want string
	}{
		"none":      {nil, ""},
		"one":       {[]string{"curl"}, "curl"},
		"grouped":   {[]string{"bash", "curl", "bash"}, "bash ×2 · curl"},
		"tie order": {[]string{"zsh", "bash"}, "bash · zsh"},
		"capped":    {[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, "a · b · c · d · e · f · g · h · +2"},
	} {
		if got := summarizeChildren(tc.in); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestHumanAge(t *testing.T) {
	for _, lang := range testLangs {
		T := strings_(lang)
		for d, unit := range map[time.Duration]string{
			20 * time.Minute:    T["unit_min"],
			3 * time.Hour:       T["unit_h"],
			40 * time.Hour:      T["unit_h"], // under two days it stays in hours
			5 * 24 * time.Hour:  T["unit_d"],
			90 * 24 * time.Hour: T["unit_mo"],
			-5 * time.Minute:    T["unit_min"], // clock skew: never negative
		} {
			got := humanAge(d, T)
			if unit == "" || !strings.Contains(got, unit) {
				t.Errorf("[%s] humanAge(%v) = %q, want unit %q", lang, d, got, unit)
			}
			if strings.Contains(got, "-") {
				t.Errorf("[%s] negative age rendered: %q", lang, got)
			}
		}
		if got := humanAge(20*time.Minute, T); got != fmt.Sprintf(T["age_ago"], "20 "+T["unit_min"]) {
			t.Errorf("[%s] humanAge = %q", lang, got)
		}
	}
}

// First-seen comes from the content baseline, falling back to the path-only
// table for rows written before the upgrade.
func TestBaselineFirstSeen(t *testing.T) {
	setupTestDB(t)
	if !dbBaselineFirstSeen("/x", "h").IsZero() {
		t.Error("unknown binary must have no first-seen")
	}
	baselineSeen("/x", "h1")
	first := dbBaselineFirstSeen("/x", "h1")
	if first.IsZero() || time.Since(first) > time.Minute {
		t.Errorf("first-seen = %v", first)
	}
	if !dbBaselineFirstSeen("/x", "h2").IsZero() {
		t.Error("a different content has its own first-seen")
	}
	db.Exec("INSERT INTO baseline VALUES (?,?)", "/legacy", "2025-01-02 03:04:05")
	if got := dbBaselineFirstSeen("/legacy", "h"); got.Year() != 2025 {
		t.Errorf("legacy row not used: %v", got)
	}
}
