package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
