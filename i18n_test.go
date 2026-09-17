package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The project's translation rule, mechanically enforced: every UI string must
// exist in EVERY language. Spanish is the reference set; a key present in one
// map but not another fails the build, so a half-translated string can't slip
// through. Adding a language means adding it here once — the loops do the rest.
var testLangs = []string{"es", "en", "zh"}

func TestTranslationParity(t *testing.T) {
	for _, lang := range testLangs[1:] {
		assertParity(t, "translations", "es", lang, translations["es"], translations[lang])
	}
}

func TestAuditStringParity(t *testing.T) {
	for _, lang := range testLangs[1:] {
		assertParity(t, "auditStrings", "es", lang, auditStrings["es"], auditStrings[lang])
	}
}

// Both maps must offer exactly the same languages, or the audit panel would
// silently fall back to Spanish for a language the rest of the UI supports.
func TestLanguageSetsMatch(t *testing.T) {
	want := append([]string(nil), testLangs...)
	sort.Strings(want)
	for name, m := range map[string]map[string]map[string]string{"translations": translations, "auditStrings": auditStrings} {
		var got []string
		for k := range m {
			got = append(got, k)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s languages = %v, want %v", name, got, want)
		}
	}
}

func assertParity(t *testing.T, name, refLang, lang string, ref, other map[string]string) {
	t.Helper()
	if len(ref) == 0 || len(other) == 0 {
		t.Fatalf("%s: empty language map (%s=%d %s=%d)", name, refLang, len(ref), lang, len(other))
	}
	var missing []string
	for k := range ref {
		if _, ok := other[k]; !ok {
			missing = append(missing, fmt.Sprintf("%q present in %s, missing in %s", k, refLang, lang))
		}
	}
	for k := range other {
		if _, ok := ref[k]; !ok {
			missing = append(missing, fmt.Sprintf("%q present in %s, missing in %s", k, lang, refLang))
		}
	}
	for _, m := range missing {
		t.Errorf("%s: %s", name, m)
	}
}

// Format verbs are part of the contract: a translation that drops a %s makes
// fmt.Sprintf print "%!(EXTRA ...)" into the tooltip, and one that adds a %d
// where the code passes a string prints "%!d(string=...)". Count them per key.
func TestTranslationVerbParity(t *testing.T) {
	verbs := func(s string) string {
		s = strings.ReplaceAll(s, "%%", "")
		var out []string
		for i := 0; i < len(s)-1; i++ {
			// A verb is % followed by a letter; "100 %" in prose is not one.
			if c := s[i+1]; s[i] == '%' && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				out = append(out, s[i:i+2])
			}
		}
		return strings.Join(out, "")
	}
	for name, m := range map[string]map[string]map[string]string{"translations": translations, "auditStrings": auditStrings} {
		for k, es := range m["es"] {
			for _, lang := range testLangs[1:] {
				if got, want := verbs(m[lang][k]), verbs(es); got != want {
					t.Errorf("%s[%s][%q]: format verbs %q, es has %q", name, lang, k, got, want)
				}
			}
		}
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
