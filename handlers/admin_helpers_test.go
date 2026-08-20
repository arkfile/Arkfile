package handlers

import (
	"testing"

	"github.com/arkfile/Arkfile/auth"
)

func TestParseOptionalBoolQuery(t *testing.T) {
	cases := []struct {
		raw     string
		set     bool
		value   bool
		wantErr bool
	}{
		{"", false, false, false},
		{"true", true, true, false},
		{"YES", true, true, false},
		{"1", true, true, false},
		{"false", true, false, false},
		{"no", true, false, false},
		{"0", true, false, false},
		{"maybe", false, false, true},
	}
	for _, tc := range cases {
		set, value, err := parseOptionalBoolQuery(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseOptionalBoolQuery(%q): expected error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseOptionalBoolQuery(%q): %v", tc.raw, err)
		}
		if set != tc.set || value != tc.value {
			t.Fatalf("parseOptionalBoolQuery(%q) = (%v, %v), want (%v, %v)", tc.raw, set, value, tc.set, tc.value)
		}
	}
}

func TestParseMinFilesQuery(t *testing.T) {
	n, err := parseMinFilesQuery("")
	if err != nil || n != 0 {
		t.Fatalf("empty: n=%d err=%v", n, err)
	}
	n, err = parseMinFilesQuery("1")
	if err != nil || n != 1 {
		t.Fatalf("1: n=%d err=%v", n, err)
	}
	if _, err := parseMinFilesQuery("-1"); err == nil {
		t.Fatal("expected error for negative min_files")
	}
	if _, err := parseMinFilesQuery("abc"); err == nil {
		t.Fatal("expected error for non-integer min_files")
	}
}

func TestMFAMethodsFromFlags(t *testing.T) {
	none := mfaMethodsFromFlags(false, false)
	if len(none) != 0 {
		t.Fatalf("expected empty methods, got %v", none)
	}

	totpOnly := mfaMethodsFromFlags(true, false)
	if len(totpOnly) != 1 || totpOnly[0] != auth.MFAMethodTOTP {
		t.Fatalf("expected totp only, got %v", totpOnly)
	}

	hwOnly := mfaMethodsFromFlags(false, true)
	if len(hwOnly) != 1 || hwOnly[0] != auth.MFAMethodWebAuthn {
		t.Fatalf("expected webauthn only, got %v", hwOnly)
	}

	both := mfaMethodsFromFlags(true, true)
	if len(both) != 2 || both[0] != auth.MFAMethodTOTP || both[1] != auth.MFAMethodWebAuthn {
		t.Fatalf("expected totp then webauthn, got %v", both)
	}
}

func TestStorageUsagePercent(t *testing.T) {
	if got := storageUsagePercent(0, 0); got != 0 {
		t.Fatalf("zero limit: got %v", got)
	}
	if got := storageUsagePercent(50, 100); got != 50 {
		t.Fatalf("half used: got %v", got)
	}
	if got := storageUsagePercent(1073741824, 1073741824); got != 100 {
		t.Fatalf("full: got %v", got)
	}
}
