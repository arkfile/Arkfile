package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
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

// argon2ParamsJSON matches the structure of crypto/argon2id-params.json
type argon2ParamsJSON struct {
	MemoryCostKiB int    `json:"memoryCostKiB"`
	TimeCost      int    `json:"timeCost"`
	Parallelism   int    `json:"parallelism"`
	KeyLength     int    `json:"keyLength"`
	Variant       string `json:"variant"`
}

//go:embed argon2id-params.json
var embeddedArgon2Params []byte

var (
	// UnifiedArgonSecure is the profile for all file encryption contexts
	// SINGLE SOURCE OF TRUTH: Embedded from crypto/argon2id-params.json at build time
	UnifiedArgonSecure UnifiedArgonProfile
	argonLoadOnce      sync.Once
	argonLoadErr       error
)

// loadArgon2Params loads Argon2ID parameters from embedded config
func loadArgon2Params() error {
	var params argon2ParamsJSON
	if err := json.Unmarshal(embeddedArgon2Params, &params); err != nil {
		return fmt.Errorf("failed to parse embedded argon2id params: %w", err)
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

// GetEmbeddedArgon2ParamsJSON returns the raw embedded JSON for API serving
func GetEmbeddedArgon2ParamsJSON() []byte {
	return embeddedArgon2Params
}

// MaxPasswordBytes is the defense-in-depth limit for password inputs to Argon2id.
// This prevents absurdly long inputs from wasting memory on string allocation.
// The primary enforcement is in the validation layer (password_validation.go);
// this is a safety net in case validation is bypassed.
const MaxPasswordBytes = 1024

const (
	AccountKDFContext = "account"
	CustomKDFContext  = "custom"
)

// DeriveArgon2IDKey derives a key using Argon2ID with specified parameters
func DeriveArgon2IDKey(password, salt []byte, keyLen uint32, memory, time uint32, threads uint8) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(password) > MaxPasswordBytes {
		return nil, fmt.Errorf("password too long: %d bytes (maximum %d)", len(password), MaxPasswordBytes)
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("key length must be greater than 0")
	}

	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

func GeneratePasswordSalt() ([]byte, error) {
	salt := make([]byte, OwnerEnvelopeSaltSize())
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	return salt, nil
}

func ValidatePasswordSalt(salt []byte) error {
	if len(salt) != OwnerEnvelopeSaltSize() {
		return fmt.Errorf("password salt must be %d bytes, got %d", OwnerEnvelopeSaltSize(), len(salt))
	}
	return nil
}

func deriveContextSalt(publicSalt []byte, context string) ([]byte, error) {
	if err := ValidatePasswordSalt(publicSalt); err != nil {
		return nil, err
	}
	if context != AccountKDFContext && context != CustomKDFContext {
		return nil, fmt.Errorf("unsupported password context: %s", context)
	}

	h := sha256.New()
	h.Write([]byte("arkfile-owner-kdf-v1"))
	h.Write([]byte{0})
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write(publicSalt)
	return h.Sum(nil), nil
}

func DerivePasswordKey(password, publicSalt []byte, context string) ([]byte, error) {
	salt, err := deriveContextSalt(publicSalt, context)
	if err != nil {
		return nil, err
	}
	return DeriveArgon2IDKey(password, salt, UnifiedArgonSecure.KeyLen, UnifiedArgonSecure.Memory, UnifiedArgonSecure.Time, UnifiedArgonSecure.Threads)
}

func DeriveAccountPasswordKey(password, publicSalt []byte) ([]byte, error) {
	return DerivePasswordKey(password, publicSalt, AccountKDFContext)
}

func DeriveCustomPasswordKey(password, publicSalt []byte) ([]byte, error) {
	return DerivePasswordKey(password, publicSalt, CustomKDFContext)
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
