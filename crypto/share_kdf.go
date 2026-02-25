package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ShareKDFParams defines the Argon2id parameters for share key derivation
// These MUST match the client-side parameters in share-crypto.ts
// Loaded from crypto/argon2id-params.json
var ShareKDFParams = struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}{}

func init() {
	// Ensure parameters are loaded
	if UnifiedArgonSecure.Memory == 0 {
		// This should have been initialized by key_derivation.go's init()
		// But just in case of initialization order issues, we check here
		// Note: key_derivation.go panics if load fails, so we can assume valid if non-zero
		panic("CRITICAL: UnifiedArgonSecure not initialized")
	}

	ShareKDFParams.Memory = UnifiedArgonSecure.Memory
	ShareKDFParams.Iterations = UnifiedArgonSecure.Time
	ShareKDFParams.Parallelism = UnifiedArgonSecure.Threads
	ShareKDFParams.SaltLength = 32 // Fixed for share KDF
	ShareKDFParams.KeyLength = UnifiedArgonSecure.KeyLen
}

// GenerateShareSalt generates a random 32-byte salt for share key derivation
func GenerateShareSalt() (string, error) {
	salt := make([]byte, ShareKDFParams.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// DeriveShareKey derives a 256-bit key from a password and salt using Argon2id
// This is primarily used for testing/validation, as the actual derivation happens client-side
func DeriveShareKey(password string, saltBase64 string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	if len(salt) != int(ShareKDFParams.SaltLength) {
		return nil, fmt.Errorf("invalid salt length: expected %d, got %d", ShareKDFParams.SaltLength, len(salt))
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		ShareKDFParams.Iterations,
		ShareKDFParams.Memory,
		ShareKDFParams.Parallelism,
		ShareKDFParams.KeyLength,
	)

	return key, nil
}

// HashDownloadToken creates a SHA-256 hash of the download token
// The download token is derived from the share key: HKDF(share_key, "download_token", 32)
func HashDownloadToken(downloadTokenBase64 string) (string, error) {
	token, err := base64.StdEncoding.DecodeString(downloadTokenBase64)
	if err != nil {
		return "", fmt.Errorf("invalid download token encoding: %w", err)
	}

	hash := sha256.Sum256(token)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// VerifyDownloadToken verifies a download token against its hash
func VerifyDownloadToken(downloadTokenBase64 string, expectedHashBase64 string) (bool, error) {
	hash, err := HashDownloadToken(downloadTokenBase64)
	if err != nil {
		return false, err
	}
	return hash == expectedHashBase64, nil
}

// ShareEnvelope represents the decrypted content of a Share Envelope
// This is a JSON structure containing the FEK, Download Token, and file metadata.
// File metadata (filename, size, sha256) is included so share recipients can:
//   - Preview the file before downloading (filename, size)
//   - Verify integrity after decryption (sha256)
//
// The metadata is protected by the same AES-GCM-AAD encryption as the FEK,
// so only someone with the share password can access it.
type ShareEnvelope struct {
	FEK           string `json:"fek"`                  // base64-encoded FEK
	DownloadToken string `json:"download_token"`       // base64-encoded Download Token
	Filename      string `json:"filename,omitempty"`   // plaintext filename (optional for backward compat)
	SizeBytes     int64  `json:"size_bytes,omitempty"` // file size in bytes (optional for backward compat)
	SHA256        string `json:"sha256,omitempty"`     // plaintext SHA256 hex digest (optional for backward compat)
}

// GenerateDownloadToken generates a cryptographically secure 32-byte Download Token
func GenerateDownloadToken() ([]byte, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("failed to generate download token: %w", err)
	}
	return token, nil
}

// CreateShareEnvelope creates a Share Envelope JSON payload with file metadata.
// The metadata (filename, sizeBytes, sha256) allows share recipients to preview
// file info before downloading and verify integrity after decryption.
func CreateShareEnvelope(fek, downloadToken []byte, filename string, sizeBytes int64, sha256hex string) ([]byte, error) {
	envelope := ShareEnvelope{
		FEK:           base64.StdEncoding.EncodeToString(fek),
		DownloadToken: base64.StdEncoding.EncodeToString(downloadToken),
		Filename:      filename,
		SizeBytes:     sizeBytes,
		SHA256:        sha256hex,
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal share envelope: %w", err)
	}

	return envelopeJSON, nil
}

// ParseShareEnvelope parses a Share Envelope JSON payload
func ParseShareEnvelope(envelopeJSON []byte) (*ShareEnvelope, error) {
	var envelope ShareEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse share envelope: %w", err)
	}

	// Validate required fields
	if envelope.FEK == "" || envelope.DownloadToken == "" {
		return nil, fmt.Errorf("invalid envelope: missing required fields")
	}

	return &envelope, nil
}

// CreateAAD creates the Additional Authenticated Data for envelope encryption
// AAD = share_id + file_id (UTF-8 encoded concatenation)
// This binds the encrypted envelope to specific share_id and file_id
func CreateAAD(shareID, fileID string) []byte {
	return []byte(shareID + fileID)
}
