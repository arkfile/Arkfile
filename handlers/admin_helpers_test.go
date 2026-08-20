package handlers

import (
	"testing"

	"github.com/arkfile/Arkfile/auth"
)

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
