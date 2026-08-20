package main

import (
	"flag"
	"testing"
)

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

func TestOptionalBoolFlag(t *testing.T) {
	var f optionalBoolFlag
	if f.set {
		t.Fatal("expected unset by default")
	}
	if err := f.Set("true"); err != nil || !f.set || !f.value {
		t.Fatalf("Set(true): set=%v value=%v err=%v", f.set, f.value, err)
	}
	if err := f.Set("no"); err != nil || !f.set || f.value {
		t.Fatalf("Set(no): set=%v value=%v err=%v", f.set, f.value, err)
	}
	if err := f.Set("bogus"); err == nil {
		t.Fatal("expected error for bogus MFA filter")
	}
}

func TestListUsersFilterFlagParse(t *testing.T) {
	fs := flag.NewFlagSet("list-users", flag.ContinueOnError)
	var mfaFilter optionalBoolFlag
	minFiles := fs.Int("min-files", 0, "")
	fs.Var(&mfaFilter, "mfa", "")
	if err := fs.Parse([]string{"--mfa", "--min-files", "1"}); err != nil {
		t.Fatalf("parse --mfa --min-files 1: %v", err)
	}
	if !mfaFilter.set || !mfaFilter.value {
		t.Fatalf("expected MFA filter enabled, set=%v value=%v", mfaFilter.set, mfaFilter.value)
	}
	if *minFiles != 1 {
		t.Fatalf("min-files=%d", *minFiles)
	}

	fsNo := flag.NewFlagSet("list-users", flag.ContinueOnError)
	var mfaNo optionalBoolFlag
	fsNo.Var(&mfaNo, "mfa", "")
	if err := fsNo.Parse([]string{"--mfa=no"}); err != nil {
		t.Fatalf("parse --mfa=no: %v", err)
	}
	if !mfaNo.set || mfaNo.value {
		t.Fatalf("expected MFA filter disabled, set=%v value=%v", mfaNo.set, mfaNo.value)
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
