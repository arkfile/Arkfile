package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// UnifiedArgonProfile defines Argon2ID parameters for all file encryption contexts
type UnifiedArgonProfile struct {
	Time    uint32 // iterations
	Memory  uint32 // KB
	Threads uint8  // parallelism
	KeyLen  uint32 // output length in bytes
}

// argon2ParamsJSON matches the structure of config/argon2id-params.json
type argon2ParamsJSON struct {
	MemoryCostKiB int    `json:"memoryCostKiB"`
	TimeCost      int    `json:"timeCost"`
	Parallelism   int    `json:"parallelism"`
	KeyLength     int    `json:"keyLength"`
	Variant       string `json:"variant"`
}

var (
	// UnifiedArgonSecure is the profile for all file encryption contexts
	// SINGLE SOURCE OF TRUTH: Loaded from config/argon2id-params.json
	UnifiedArgonSecure UnifiedArgonProfile
	argonLoadOnce      sync.Once
	argonLoadErr       error
)

// loadArgon2Params loads Argon2ID parameters from config/argon2id-params.json
func loadArgon2Params() error {
	file, err := os.ReadFile("config/argon2id-params.json")
	if err != nil {
		return fmt.Errorf("failed to read argon2id params: %w", err)
	}

	var params argon2ParamsJSON
	if err := json.Unmarshal(file, &params); err != nil {
		return fmt.Errorf("failed to parse argon2id params: %w", err)
	}

	// Validate variant
	if params.Variant != "Argon2id" {
		return fmt.Errorf("unsupported Argon2 variant: %s (expected Argon2id)", params.Variant)
	}

	// Convert to UnifiedArgonProfile
	UnifiedArgonSecure = UnifiedArgonProfile{
		Time:    uint32(params.TimeCost),
		Memory:  uint32(params.MemoryCostKiB),
		Threads: uint8(params.Parallelism),
		KeyLen:  uint32(params.KeyLength),
	}

	return nil
}

// init loads Argon2ID parameters at package initialization
func init() {
	argonLoadOnce.Do(func() {
		argonLoadErr = loadArgon2Params()
	})

	// If loading fails, panic since crypto operations cannot proceed safely
	if argonLoadErr != nil {
		panic(fmt.Sprintf("FATAL: Failed to load Argon2ID parameters: %v", argonLoadErr))
	}
}

// Static salts for FEK wrapping
//
// SECURITY NOTE: These salts are intentionally static and deterministic.
// This design is SAFE because:
//
// 1. Security Model: Password → Argon2ID → KEK → wraps random FEK → encrypts file
//   - User passwords are processed through Argon2ID (256MB memory, 8 iterations)
//   - This derives a Key Encryption Key (KEK) which wraps the File Encryption Key (FEK)
//   - Each file has a randomly-generated FEK (true entropy, not password-derived)
//   - The FEK is what actually encrypts the file data
//
// 2. Why Deterministic Salts Are Safe Here:
//   - These salts are used for KEY WRAPPING, not password storage
//   - Argon2ID provides strong protection even with known salts due to its memory-hard properties
//   - An attacker would need to break Argon2ID to derive the KEK (computationally infeasible)
//   - The actual file encryption uses randomly-generated FEKs with unique nonces per file
//
// 3. Benefits of This Design:
//   - Allows password changes without re-encrypting all files
//   - Each user gets a unique KEK via username-based salt derivation (see Derive*PasswordKey functions)
//   - Maintains separation between account, custom, and share password contexts
//
// 4. Defense in Depth:
//   - Even if an attacker knows the salt, they still face Argon2ID's memory-hard function
//   - The 256MB memory requirement makes parallel attacks expensive
//   - The randomly-generated FEKs provide an additional layer of security
//
// This is a well-established pattern in cryptographic key management systems.
var (
	FEKAccountSalt = []byte("arkfile-fek-account-salt-v1")
	FEKCustomSalt  = []byte("arkfile-fek-custom-salt-v1")
	FEKShareSalt   = []byte("arkfile-fek-share-salt-v1")
)

// DeriveArgon2IDKey derives a key using Argon2ID with specified parameters
func DeriveArgon2IDKey(password, salt []byte, keyLen uint32, memory, time uint32, threads uint8) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("key length must be greater than 0")
	}

	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// Password-based key derivation functions using Argon2ID
// These replace the old OPAQUE export key based functions

// DerivePasswordMetadataKey derives a metadata encryption key from password using Argon2ID
func DerivePasswordMetadataKey(password []byte, salt []byte, username string) ([]byte, error) {
	// Use unified Argon2ID parameters
	baseKey, err := DeriveArgon2IDKey(password, salt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	if err != nil {
		return nil, fmt.Errorf("argon2id derivation failed: %w", err)
	}

	info := fmt.Sprintf("arkfile-metadata-encryption:%s", username)
	return hkdfExpand(baseKey, []byte(info), 32)
}

// DeriveAccountPasswordKey derives a key from an account password
func DeriveAccountPasswordKey(password []byte, username string) []byte {
	salt := sha256.Sum256([]byte("arkfile-account-key-salt:" + username))
	key, _ := DeriveArgon2IDKey(password, salt[:], UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	return key
}

// DeriveCustomPasswordKey derives a key from a custom file password
func DeriveCustomPasswordKey(password []byte, username string) []byte {
	salt := sha256.Sum256([]byte("arkfile-custom-key-salt:" + username))
	key, _ := DeriveArgon2IDKey(password, salt[:], UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	return key
}

// DeriveSharePasswordKey derives a key from a share password
func DeriveSharePasswordKey(password []byte, username string) []byte {
	salt := sha256.Sum256([]byte("arkfile-share-key-salt:" + username))
	key, _ := DeriveArgon2IDKey(password, salt[:], UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
	return key
}

// hkdfExpand performs HKDF-Expand operation
func hkdfExpand(prk []byte, info []byte, length int) ([]byte, error) {
	if len(prk) == 0 {
		return nil, fmt.Errorf("pseudorandom key cannot be empty")
	}

	if length <= 0 || length > 255*32 {
		return nil, fmt.Errorf("invalid output length: %d", length)
	}

	// Use HKDF-Expand with SHA-256
	reader := hkdf.Expand(sha256.New, prk, info)

	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	return result, nil
}
