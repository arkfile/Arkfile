package crypto

import (
	"strings"
	"testing"
	"time"
)

// shareTicketTestKey returns a deterministic 32-byte key for unit tests so the
// HMAC verification logic is exercised without the KeyManager/DB dependency.
func shareTicketTestKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestIssueShareTicket_VerifyRoundTrip(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	issuedAt := time.Now().Truncate(time.Second)

	ticket, err := IssueShareTicket(key, shareID, entityID, issuedAt)
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}
	if ticket == "" {
		t.Fatal("ticket is empty")
	}

	gotIssued, err := VerifyShareTicket(key, ticket, shareID, entityID, time.Now())
	if err != nil {
		t.Fatalf("VerifyShareTicket failed: %v", err)
	}
	if !gotIssued.Equal(issuedAt) {
		t.Errorf("issued-at mismatch: got %v, want %v", gotIssued, issuedAt)
	}
}

func TestVerifyShareTicket_RejectsWrongEntityID(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityA := strings.Repeat("a", 64)
	entityB := strings.Repeat("b", 64)

	ticket, err := IssueShareTicket(key, shareID, entityA, time.Now())
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	if _, err := VerifyShareTicket(key, ticket, shareID, entityB, time.Now()); err == nil {
		t.Fatal("ticket bound to entity A must be rejected for entity B")
	}
}

func TestVerifyShareTicket_RejectsWrongShareID(t *testing.T) {
	key := shareTicketTestKey()
	entityID := strings.Repeat("a", 64)
	shareA := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	shareB := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	ticket, err := IssueShareTicket(key, shareA, entityID, time.Now())
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	if _, err := VerifyShareTicket(key, ticket, shareB, entityID, time.Now()); err == nil {
		t.Fatal("ticket bound to share A must be rejected for share B")
	}
}

func TestVerifyShareTicket_RejectsExpired(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	// Issued well outside the TTL.
	old := time.Now().Add(-(ShareTicketTTL + time.Minute))
	ticket, err := IssueShareTicket(key, shareID, entityID, old)
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	if _, err := VerifyShareTicket(key, ticket, shareID, entityID, time.Now()); err == nil {
		t.Fatal("expired ticket must be rejected")
	}
}

func TestVerifyShareTicket_RejectsFutureIssuedAt(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	future := time.Now().Add(5 * time.Minute)
	ticket, err := IssueShareTicket(key, shareID, entityID, future)
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	if _, err := VerifyShareTicket(key, ticket, shareID, entityID, time.Now()); err == nil {
		t.Fatal("ticket issued in the future must be rejected")
	}
}

func TestVerifyShareTicket_RejectsTamperedTicket(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	ticket, err := IssueShareTicket(key, shareID, entityID, time.Now())
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	// Flip a character in the base64 ticket body to tamper with the tag.
	tampered := ticket
	if tampered[len(tampered)-1] == 'A' {
		tampered = tampered[:len(tampered)-1] + "B"
	} else {
		tampered = tampered[:len(tampered)-1] + "A"
	}

	if _, err := VerifyShareTicket(key, tampered, shareID, entityID, time.Now()); err == nil {
		t.Fatal("tampered ticket must be rejected")
	}
}

func TestVerifyShareTicket_RejectsWrongKey(t *testing.T) {
	keyA := shareTicketTestKey()
	keyB := make([]byte, 32)
	for i := range keyB {
		keyB[i] = byte(255 - i)
	}
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	ticket, err := IssueShareTicket(keyA, shareID, entityID, time.Now())
	if err != nil {
		t.Fatalf("IssueShareTicket failed: %v", err)
	}

	if _, err := VerifyShareTicket(keyB, ticket, shareID, entityID, time.Now()); err == nil {
		t.Fatal("ticket verified under the wrong key must be rejected")
	}
}

func TestIssueShareTicket_RejectsBadInputs(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	badKey := []byte{1, 2, 3}
	if _, err := IssueShareTicket(badKey, shareID, entityID, time.Now()); err == nil {
		t.Fatal("issue with short key must error")
	}
	if _, err := IssueShareTicket(key, "", entityID, time.Now()); err == nil {
		t.Fatal("issue with empty shareID must error")
	}
	if _, err := IssueShareTicket(key, shareID, "", time.Now()); err == nil {
		t.Fatal("issue with empty entityID must error")
	}
}

func TestVerifyShareTicket_RejectsMalformed(t *testing.T) {
	key := shareTicketTestKey()
	shareID := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"
	entityID := strings.Repeat("a", 64)

	cases := []string{
		"",
		"not-base64!!!",
		"AAAA", // too short
	}
	for _, tc := range cases {
		if _, err := VerifyShareTicket(key, tc, shareID, entityID, time.Now()); err == nil {
			t.Errorf("malformed ticket %q must be rejected", tc)
		}
	}
}
