package main

import "testing"

func TestOUIVendor(t *testing.T) {
	// MA-L (/24): Nokia 28:6F:B9 — stable, in the committed table.
	if v := ouiVendor("28:6F:B9:11:22:33"); v == "" {
		t.Error("MA-L lookup (Nokia 28:6F:B9) returned empty")
	}
	// MA-S (/36): proves longest-prefix reaches a 9-hex assignment.
	if v := ouiVendor("8C:1F:64:AF:A0:00"); v == "" {
		t.Error("MA-S longest-prefix lookup (8C1F64AFA) returned empty")
	}
	// Locally administered (U/L bit set in first octet) → no IEEE owner.
	if v := ouiVendor("02:00:00:00:00:00"); v != "" {
		t.Errorf("locally administered should be empty, got %q", v)
	}
	// Degenerate inputs.
	for _, mac := range []string{"", "ab", "zz:zz:zz:zz:zz:zz"} {
		if v := ouiVendor(mac); v != "" {
			t.Errorf("ouiVendor(%q)=%q, want empty", mac, v)
		}
	}
}

func TestOUISeparatorsAndCase(t *testing.T) {
	// Same OUI, different separators/case must resolve identically.
	want := ouiVendor("28:6F:B9:00:00:00")
	if want == "" {
		t.Skip("base lookup empty; table not loaded")
	}
	for _, mac := range []string{"28-6F-B9-00-00-00", "286fb9000000", "28:6f:b9:00:00:00"} {
		if got := ouiVendor(mac); got != want {
			t.Errorf("ouiVendor(%q)=%q, want %q", mac, got, want)
		}
	}
}
