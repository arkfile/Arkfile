package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// GetShareTicketKey returns the 32-byte share ticket master key, generating it
// lazily on first call via the KeyManager. This mirrors how the EntityID master
// is obtained and keeps the key persisted (envelope-encrypted) in system_keys.
var (
	shareTicketKeyOnce sync.Once
	shareTicketKeyErr  error
)

func GetShareTicketKey() ([]byte, error) {
	shareTicketKeyOnce.Do(func() {
		km, err := GetKeyManager()
		if err != nil {
			shareTicketKeyErr = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}
		key, err := km.GetOrGenerateKey(ShareTicketMasterKeyID, ShareTicketKeyType, 32)
		if err != nil {
			shareTicketKeyErr = fmt.Errorf("failed to get/generate share ticket master key: %w", err)
			return
		}
		if len(key) != 32 {
			shareTicketKeyErr = fmt.Errorf("invalid share ticket master key length: expected 32 bytes, got %d", len(key))
			return
		}
		cachedShareTicketKey = key
	})
	if shareTicketKeyErr != nil {
		return nil, shareTicketKeyErr
	}
	return cachedShareTicketKey, nil
}

// cachedShareTicketKey holds the material loaded by GetShareTicketKey. It is
// read-only after the once Do completes.
var cachedShareTicketKey []byte

// ShareTicketTTL is how long a share download ticket remains valid after
// issuance. Short enough that a ticket captured from a compromised channel is
// useless within minutes, long enough that a normal multi-chunk download on a
// slow connection (the 3 GB RAM / Tor Browser persona) does not have to refresh
// mid-download except for very large files.
const ShareTicketTTL = 10 * time.Minute

const shareTicketLabel = "arkfile-share-ticket"

// IssueShareTicket returns a short-lived, entity-bound download ticket that a
// recipient presents (as X-Share-Ticket) to download share chunks, replacing
// the never-rotated static download token as the per-chunk credential.
//
// The ticket is stateless: it carries its own issued-at timestamp and a random
// nonce, plus an HMAC over (label, shareID, entityID, issuedAt, nonce) keyed by
// the server-only share ticket master key. The server validates it at chunk
// time by recomputing the HMAC, checking the TTL, and confirming the bound
// entity ID matches the requester. No DB row is needed.
//
// ticketKey must be the 32-byte share ticket master from the KeyManager.
// entityID is the requester's privacy-preserving entity ID (HMAC of IP/UA).
func IssueShareTicket(ticketKey []byte, shareID, entityID string, issuedAt time.Time) (string, error) {
	if len(ticketKey) != 32 {
		return "", fmt.Errorf("share ticket key must be 32 bytes, got %d", len(ticketKey))
	}
	if shareID == "" || entityID == "" {
		return "", fmt.Errorf("shareID and entityID are required")
	}

	nonce := GenerateRandomBytes(16)
	issuedUnix := uint64(issuedAt.Unix())

	payload := shareTicketPayload(shareID, entityID, issuedUnix, nonce)
	mac := hmac.New(sha256.New, ticketKey)
	mac.Write(payload)
	tag := mac.Sum(nil)

	// Wire format: issuedAt(8) || nonce(16) || tag(32), base64 (standard).
	buf := make([]byte, 0, 8+16+32)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], issuedUnix)
	buf = append(buf, ts[:]...)
	buf = append(buf, nonce...)
	buf = append(buf, tag...)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// VerifyShareTicket validates a share download ticket against the server key,
// checking the HMAC, the TTL, and that the bound entity ID matches the
// requester. Returns the issued-at time on success.
func VerifyShareTicket(ticketKey []byte, ticket, shareID, entityID string, now time.Time) (time.Time, error) {
	if len(ticketKey) != 32 {
		return time.Time{}, fmt.Errorf("share ticket key must be 32 bytes, got %d", len(ticketKey))
	}
	if ticket == "" || shareID == "" || entityID == "" {
		return time.Time{}, fmt.Errorf("ticket, shareID and entityID are required")
	}

	raw, err := base64.StdEncoding.DecodeString(ticket)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid ticket encoding: %w", err)
	}
	const minLen = 8 + 16 + 32
	if len(raw) != minLen {
		return time.Time{}, fmt.Errorf("invalid ticket length: got %d, want %d", len(raw), minLen)
	}

	issuedUnix := binary.BigEndian.Uint64(raw[:8])
	nonce := raw[8 : 8+16]
	tag := raw[8+16:]

	payload := shareTicketPayload(shareID, entityID, issuedUnix, nonce)
	mac := hmac.New(sha256.New, ticketKey)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !SecureCompare(tag, expected) {
		return time.Time{}, fmt.Errorf("invalid ticket signature")
	}

	issuedAt := time.Unix(int64(issuedUnix), 0)
	if now.Before(issuedAt) {
		// Issued in the future: reject (clock skew / tampering).
		return time.Time{}, fmt.Errorf("ticket issued in the future")
	}
	if now.Sub(issuedAt) > ShareTicketTTL {
		return time.Time{}, fmt.Errorf("ticket expired")
	}
	return issuedAt, nil
}

// shareTicketPayload builds the canonical bytes covered by the ticket HMAC.
// Ordering and label are fixed so two tickets for different (shareID, entityID)
// pairs cannot be confused, and the issued-at timestamp is bound into the tag
// so it cannot be mutated after issuance.
func shareTicketPayload(shareID, entityID string, issuedUnix uint64, nonce []byte) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], issuedUnix)
	out := make([]byte, 0, len(shareTicketLabel)+len(shareID)+len(entityID)+8+len(nonce))
	out = append(out, shareTicketLabel...)
	out = append(out, ':')
	out = append(out, shareID...)
	out = append(out, ':')
	out = append(out, entityID...)
	out = append(out, ':')
	out = append(out, ts[:]...)
	out = append(out, ':')
	out = append(out, nonce...)
	return out
}
