package auth

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/84adam/Arkfile/crypto"
)

var (
	jwtPrivateKey ed25519.PrivateKey
	jwtPublicKey  ed25519.PublicKey
	keysOnce      sync.Once
	keysError     error
)

// LoadJWTKeys loads the Ed25519 private and public keys for JWT signing
// It uses the KeyManager to retrieve or generate the keys securely.
func LoadJWTKeys() error {
	keysOnce.Do(func() {
		km, err := crypto.GetKeyManager()
		if err != nil {
			keysError = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}

		// Retrieve or generate the 32-byte seed for the Ed25519 key
		// We use "jwt_signing_key_v1" as the ID and "jwt" as the type context
		seed, err := km.GetOrGenerateKey("jwt_signing_key_v1", "jwt", 32)
		if err != nil {
			keysError = fmt.Errorf("failed to get/generate JWT key seed: %w", err)
			return
		}

		if len(seed) != 32 {
			keysError = fmt.Errorf("invalid JWT key seed length: expected 32 bytes, got %d", len(seed))
			return
		}

		// Generate the key pair from the seed
		jwtPrivateKey = ed25519.NewKeyFromSeed(seed)
		jwtPublicKey = jwtPrivateKey.Public().(ed25519.PublicKey)
	})

	return keysError
}

// GetJWTPrivateKey returns the loaded Ed25519 private key
func GetJWTPrivateKey() ed25519.PrivateKey {
	if err := LoadJWTKeys(); err != nil {
		panic(fmt.Sprintf("JWT private key not available: %v", err))
	}
	return jwtPrivateKey
}

// GetJWTPublicKey returns the loaded Ed25519 public key
func GetJWTPublicKey() ed25519.PublicKey {
	if err := LoadJWTKeys(); err != nil {
		panic(fmt.Sprintf("JWT public key not available: %v", err))
	}
	return jwtPublicKey
}

// Testing helper - DO NOT USE IN PRODUCTION
// ResetKeysForTest resets the sync.Once and key variables for testing purposes
func ResetKeysForTest() {
	keysOnce = sync.Once{}
	jwtPrivateKey = nil
	jwtPublicKey = nil
	keysError = nil
}
