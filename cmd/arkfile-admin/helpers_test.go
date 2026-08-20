package main

import "testing"

func TestParseStorageLimit(t *testing.T) {
	bytes, err := parseStorageLimit("10GB")
	if err != nil {
		t.Fatalf("parseStorageLimit: %v", err)
	}
	if bytes != 10*1024*1024*1024 {
		t.Fatalf("unexpected bytes: %d", bytes)
	}
}

func TestLooksLikeDollarsAndCents(t *testing.T) {
	if !looksLikeDollarsAndCents("19.99") {
		t.Fatal("expected valid price")
	}
	if looksLikeDollarsAndCents("-1") {
		t.Fatal("expected invalid negative price")
	}
}

func TestFormatMFAStatus(t *testing.T) {
	cases := []struct {
		enabled bool
		methods []string
		want    string
	}{
		{false, nil, "No"},
		{false, []string{}, "No"},
		{true, nil, "Yes"},
		{true, []string{"totp"}, "Yes (TOTP)"},
		{true, []string{"webauthn"}, "Yes (HW)"},
		{true, []string{"totp", "webauthn"}, "Yes (TOTP+HW)"},
		{false, []string{"totp"}, "Yes (TOTP)"},
	}
	for _, tc := range cases {
		got := formatMFAStatus(tc.enabled, tc.methods)
		if got != tc.want {
			t.Fatalf("formatMFAStatus(%v, %v) = %q, want %q", tc.enabled, tc.methods, got, tc.want)
		}
	}
}

func TestParseStringSlice(t *testing.T) {
	got := parseStringSlice([]interface{}{"totp", "webauthn", " ", 1})
	if len(got) != 2 || got[0] != "totp" || got[1] != "webauthn" {
		t.Fatalf("unexpected parseStringSlice result: %#v", got)
	}
	got = parseStringSlice([]string{" totp "})
	if len(got) != 1 || got[0] != "totp" {
		t.Fatalf("unexpected parseStringSlice string slice: %#v", got)
	}
}

func TestEmptyOrValue(t *testing.T) {
	if got := emptyOrValue("", "fallback"); got != "fallback" {
		t.Fatalf("got %q", got)
	}
	if got := emptyOrValue("value", "fallback"); got != "value" {
		t.Fatalf("got %q", got)
	}
}
