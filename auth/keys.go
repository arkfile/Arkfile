package auth

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/84adam/Arkfile/crypto"
)

// Two-tier JWT signing keys (A-01 fix).
//
// The temp-tier key signs short-lived tokens issued by OPAQUE finalize that
// carry aud=arkfile-totp and requires_totp=true. Those tokens are only valid
// at /api/totp/{setup,verify,auth}, validated by TOTPJWTMiddleware against
// the temp public key.
//
// The full-tier key signs full-access tokens issued after a successful TOTP
// step (or via /api/refresh on an existing full session). Those tokens carry
// aud=arkfile-api and requires_totp=false and are validated by JWTMiddleware
// against the full public key.
//
// Two separate keys make audience confusion structurally impossible:
// presenting a temp token to JWTMiddleware fails signature verification
// before any claim is inspected, and vice versa. The audience claim is
// enforced as defense in depth in ParseTokenFunc.
var (
	jwtTempPrivateKey ed25519.PrivateKey
	jwtTempPublicKey  ed25519.PublicKey
	jwtFullPrivateKey ed25519.PrivateKey
	jwtFullPublicKey  ed25519.PublicKey

	tempKeysOnce  sync.Once
	tempKeysError error

	fullKeysOnce  sync.Once
	fullKeysError error
)

// LoadJWTTempKeys retrieves or generates the Ed25519 keypair used to sign
// temporary post-OPAQUE TOTP-handoff tokens (aud=arkfile-totp).
func LoadJWTTempKeys() error {
	tempKeysOnce.Do(func() {
		km, err := crypto.GetKeyManager()
		if err != nil {
			tempKeysError = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}

		seed, err := km.GetOrGenerateKey("jwt_signing_key_temp_v1", "jwt", 32)
		if err != nil {
			tempKeysError = fmt.Errorf("failed to get/generate JWT temp key seed: %w", err)
			return
		}
		if len(seed) != 32 {
			tempKeysError = fmt.Errorf("invalid JWT temp key seed length: expected 32 bytes, got %d", len(seed))
			return
		}

		jwtTempPrivateKey = ed25519.NewKeyFromSeed(seed)
		jwtTempPublicKey = jwtTempPrivateKey.Public().(ed25519.PublicKey)
	})
	return tempKeysError
}

// LoadJWTFullKeys retrieves or generates the Ed25519 keypair used to sign
// full-access tokens (aud=arkfile-api). Also used for export-scoped tokens.
func LoadJWTFullKeys() error {
	fullKeysOnce.Do(func() {
		km, err := crypto.GetKeyManager()
		if err != nil {
			fullKeysError = fmt.Errorf("failed to get KeyManager: %w", err)
			return
		}

		seed, err := km.GetOrGenerateKey("jwt_signing_key_full_v1", "jwt", 32)
		if err != nil {
			fullKeysError = fmt.Errorf("failed to get/generate JWT full key seed: %w", err)
			return
		}
		if len(seed) != 32 {
			fullKeysError = fmt.Errorf("invalid JWT full key seed length: expected 32 bytes, got %d", len(seed))
			return
		}

		jwtFullPrivateKey = ed25519.NewKeyFromSeed(seed)
		jwtFullPublicKey = jwtFullPrivateKey.Public().(ed25519.PublicKey)
	})
	return fullKeysError
}

// GetJWTTempPrivateKey returns the loaded Ed25519 private key for temp tokens.
func GetJWTTempPrivateKey() ed25519.PrivateKey {
	if err := LoadJWTTempKeys(); err != nil {
		panic(fmt.Sprintf("JWT temp private key not available: %v", err))
	}
	return jwtTempPrivateKey
}

// GetJWTTempPublicKey returns the loaded Ed25519 public key for temp tokens.
func GetJWTTempPublicKey() ed25519.PublicKey {
	if err := LoadJWTTempKeys(); err != nil {
		panic(fmt.Sprintf("JWT temp public key not available: %v", err))
	}
	return jwtTempPublicKey
}

// GetJWTFullPrivateKey returns the loaded Ed25519 private key for full tokens.
func GetJWTFullPrivateKey() ed25519.PrivateKey {
	if err := LoadJWTFullKeys(); err != nil {
		panic(fmt.Sprintf("JWT full private key not available: %v", err))
	}
	return jwtFullPrivateKey
}

// GetJWTFullPublicKey returns the loaded Ed25519 public key for full tokens.
func GetJWTFullPublicKey() ed25519.PublicKey {
	if err := LoadJWTFullKeys(); err != nil {
		panic(fmt.Sprintf("JWT full public key not available: %v", err))
	}
	return jwtFullPublicKey
}

// LoadJWTKeys initializes both tiers. Kept for callers that just need to
// ensure JWT subsystem is ready at startup.
func LoadJWTKeys() error {
	if err := LoadJWTTempKeys(); err != nil {
		return err
	}
	return LoadJWTFullKeys()
}

// ResetKeysForTest resets the sync.Once and key variables for testing purposes.
// DO NOT USE IN PRODUCTION.
func ResetKeysForTest() {
	tempKeysOnce = sync.Once{}
	jwtTempPrivateKey = nil
	jwtTempPublicKey = nil
	tempKeysError = nil

	fullKeysOnce = sync.Once{}
	jwtFullPrivateKey = nil
	jwtFullPublicKey = nil
	fullKeysError = nil
}
