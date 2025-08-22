package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"github.com/84adam/Arkfile/config"
)

var (
	jwtPrivateKey ed25519.PrivateKey
	jwtPublicKey  ed25519.PublicKey
	keysOnce      sync.Once
	keysError     error
)

// LoadJWTKeys loads the Ed25519 private and public keys for JWT signing
func LoadJWTKeys() error {
	keysOnce.Do(func() {
		cfg := config.GetConfig()

		// Load private key
		jwtPrivateKey, keysError = loadEd25519PrivateKey(cfg.Security.JWTPrivateKeyPath)
		if keysError != nil {
			keysError = fmt.Errorf("failed to load JWT private key: %w", keysError)
			return
		}

		// Load public key
		jwtPublicKey, keysError = loadEd25519PublicKey(cfg.Security.JWTPublicKeyPath)
		if keysError != nil {
			keysError = fmt.Errorf("failed to load JWT public key: %w", keysError)
			return
		}

		// Verify key pair consistency
		if keysError = verifyKeyPair(jwtPrivateKey, jwtPublicKey); keysError != nil {
			keysError = fmt.Errorf("JWT key pair verification failed: %w", keysError)
			return
		}
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

// loadEd25519PrivateKey loads an Ed25519 private key from a PEM file
func loadEd25519PrivateKey(filepath string) (ed25519.PrivateKey, error) {
	keyBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %s: %w", filepath, err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key file %s", filepath)
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %s in private key file %s", block.Type, filepath)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key from %s: %w", filepath, err)
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key from %s is not an Ed25519 key", filepath)
	}

	return ed25519Key, nil
}

// loadEd25519PublicKey loads an Ed25519 public key from a PEM file
func loadEd25519PublicKey(filepath string) (ed25519.PublicKey, error) {
	keyBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file %s: %w", filepath, err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from public key file %s", filepath)
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %s in public key file %s", block.Type, filepath)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key from %s: %w", filepath, err)
	}

	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key from %s is not an Ed25519 key", filepath)
	}

	return ed25519Key, nil
}

// verifyKeyPair ensures the private and public keys form a valid Ed25519 keypair
func verifyKeyPair(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) error {
	// Derive public key from private key and compare
	derivedPublicKey := privateKey.Public().(ed25519.PublicKey)

	if len(derivedPublicKey) != len(publicKey) {
		return fmt.Errorf("public key length mismatch: derived %d, loaded %d", len(derivedPublicKey), len(publicKey))
	}

	for i := range derivedPublicKey {
		if derivedPublicKey[i] != publicKey[i] {
			return fmt.Errorf("public key mismatch: loaded public key does not match private key")
		}
	}

	return nil
}

// Testing helper - DO NOT USE IN PRODUCTION
// ResetKeysForTest resets the sync.Once and key variables for testing purposes
func ResetKeysForTest() {
	keysOnce = sync.Once{}
	jwtPrivateKey = nil
	jwtPublicKey = nil
	keysError = nil
}
