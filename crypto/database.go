package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize   = 32
	NonceSize = 24
)

type DatabaseCrypto struct {
	key [KeySize]byte
}

// NewDatabaseCrypto creates a new crypto instance with the provided hex-encoded key
func NewDatabaseCrypto(hexKey string) (*DatabaseCrypto, error) {
	var key [KeySize]byte
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil || len(keyBytes) != KeySize {
		return nil, fmt.Errorf("invalid key size or format: key must be %d bytes hex-encoded", KeySize)
	}
	copy(key[:], keyBytes)
	return &DatabaseCrypto{key: key}, nil
}

// Encrypt encrypts the database file at sourcePath and writes it to destPath
func (dc *DatabaseCrypto) Encrypt(sourcePath, destPath string) error {
	// Read the database file
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Generate random nonce
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return fmt.Errorf("nonce generation: %w", err)
	}

	// Encrypt the data
	encrypted := secretbox.Seal(nonce[:], data, &nonce, &dc.key)

	// Write encrypted data with restricted permissions
	return os.WriteFile(destPath, encrypted, 0600)
}

// Decrypt decrypts the database file at sourcePath and writes it to destPath
func (dc *DatabaseCrypto) Decrypt(sourcePath, destPath string) error {
	// Read encrypted file
	encrypted, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read encrypted: %w", err)
	}

	if len(encrypted) < NonceSize {
		return fmt.Errorf("invalid encrypted file: too short")
	}

	// Extract nonce
	var nonce [NonceSize]byte
	copy(nonce[:], encrypted[:NonceSize])

	// Decrypt the data
	decrypted, ok := secretbox.Open(nil, encrypted[NonceSize:], &nonce, &dc.key)
	if !ok {
		return fmt.Errorf("decryption failed: invalid key or corrupted data")
	}

	// Write decrypted database with restricted permissions
	return os.WriteFile(destPath, decrypted, 0600)
}

// GenerateKey generates a new random encryption key and returns it hex-encoded
func GenerateKey() (string, error) {
	var key [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", fmt.Errorf("key generation: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}
