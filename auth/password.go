package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/84adam/arkfile/config"
)

// HashPassword hashes a password using Argon2ID with server configuration
func HashPassword(password string) (string, error) {
	cfg := config.GetConfig()

	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash with server-side parameters
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		cfg.Security.ServerArgon2ID.Time,
		cfg.Security.ServerArgon2ID.Memory,
		cfg.Security.ServerArgon2ID.Threads,
		32, // 32-byte hash
	)

	// Encode with parameters for storage/verification
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		cfg.Security.ServerArgon2ID.Memory,
		cfg.Security.ServerArgon2ID.Time,
		cfg.Security.ServerArgon2ID.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2ID hash
func VerifyPassword(password, encodedHash string) bool {
	// Parse the encoded hash
	params, salt, hash, err := parseEncodedHash(encodedHash)
	if err != nil {
		return false
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(len(hash)),
	)

	// Compare hashes
	return subtle.ConstantTimeCompare(hash, computedHash) == 1
}

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parseEncodedHash(encodedHash string) (*argon2Params, []byte, []byte, error) {
	// Parse format: $argon2id$v=19$m=131072,t=4,p=4$saltBase64$hashBase64
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	// Parse parameters from parts[3]: "m=131072,t=4,p=4"
	var memory, time uint32
	var threads uint8

	paramParts := strings.Split(parts[3], ",")
	for _, param := range paramParts {
		if strings.HasPrefix(param, "m=") {
			fmt.Sscanf(param, "m=%d", &memory)
		} else if strings.HasPrefix(param, "t=") {
			fmt.Sscanf(param, "t=%d", &time)
		} else if strings.HasPrefix(param, "p=") {
			fmt.Sscanf(param, "p=%d", &threads)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}

	return &argon2Params{memory, time, threads}, salt, hash, nil
}
