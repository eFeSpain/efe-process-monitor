package main

import (
	"fmt"
	"testing"
)

// TestTranslationParity mechanically enforces the project's bilingual rule:
// every UI string must exist in BOTH es and en. A key present in one map but not
// the other fails the build — so a half-translated string can't slip through.
func TestTranslationParity(t *testing.T) {
	assertParity(t, "translations", translations["es"], translations["en"])
}

func TestAuditStringParity(t *testing.T) {
	assertParity(t, "auditStrings", auditStrings["es"], auditStrings["en"])
}

func assertParity(t *testing.T, name string, es, en map[string]string) {
	t.Helper()
	if len(es) == 0 || len(en) == 0 {
		t.Fatalf("%s: empty language map (es=%d en=%d)", name, len(es), len(en))
	}
	var missing []string
	for k := range es {
		if _, ok := en[k]; !ok {
			missing = append(missing, fmt.Sprintf("%q present in es, missing in en", k))
		}
	}
	for k := range en {
		if _, ok := es[k]; !ok {
			missing = append(missing, fmt.Sprintf("%q present in en, missing in es", k))
		}
	}
	for _, m := range missing {
		t.Errorf("%s: %s", name, m)
	}
}

func TestStringsFallback(t *testing.T) {
	if strings_("es")["title"] == "" {
		t.Error("strings_(es) missing title")
	}
	// Unknown language falls back to Spanish, never nil.
	if strings_("xx")["title"] == "" {
		t.Error("strings_(unknown) should fall back to es, got empty")
	}
}
