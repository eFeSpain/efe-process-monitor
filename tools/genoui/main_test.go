package main

import (
	"testing"
	"unicode/utf8"
)

func TestCleanVendor(t *testing.T) {
	for in, want := range map[string]string{
		"  Acme   Corp  ":     "Acme Corp",
		"Plain":               "Plain",
		"":                    "",
		"Tabs\tand\nnewlines": "Tabs and newlines",
	} {
		if got := cleanVendor(in); got != want {
			t.Errorf("cleanVendor(%q) = %q, want %q", in, got, want)
		}
	}
	// Long names are cut at 48 characters, never inside one.
	long := "Société Anonyme des Ateliers Électriques de Charleroi et Environs"
	got := cleanVendor(long)
	if !utf8.ValidString(got) {
		t.Errorf("cut produced invalid UTF-8: %q", got)
	}
	if n := utf8.RuneCountInString(got); n > 48 {
		t.Errorf("length %d runes, want <= 48: %q", n, got)
	}
	cjk := "株式会社日本電気東京本社株式会社日本電気東京本社株式会社日本電気東京本社株式会社日本電気東京本社株式会社日本電気"
	if got := cleanVendor(cjk); !utf8.ValidString(got) || utf8.RuneCountInString(got) != 48 {
		t.Errorf("CJK cut = %q (%d runes)", got, utf8.RuneCountInString(got))
	}
}
