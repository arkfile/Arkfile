package crypto

import (
	"fmt"
)

// KeyType represents the type of encryption key
type KeyType byte

const (
	KeyTypeAccount KeyType = 0x01 // Account password
	KeyTypeCustom  KeyType = 0x02 // Custom password
	KeyTypeShare   KeyType = 0x03 // Share password
)

// KeyInfo contains information about an encryption key
type KeyInfo struct {
	ID       string  // User-friendly identifier
	Type     KeyType // Account, custom, or share
	Password []byte  // Password for key derivation
	Salt     []byte  // Salt for Argon2ID
	Username string  // Username for HKDF context
	FileID   string  // File ID for HKDF context
	Hint     string  // Optional hint for custom passwords
}

// FileEncryptionVersion represents file encryption format versions
type FileEncryptionVersion byte

const (
	VersionPasswordBased FileEncryptionVersion = 0x01 // Password-based encryption with Argon2ID
)

// CreatePasswordKeyEnvelope creates an envelope for password-based encryption
func CreatePasswordKeyEnvelope(fek []byte, keyInfo KeyInfo) ([]byte, error) {
	// All encryption is now password-based with version 0x01
	version := VersionPasswordBased

	// Derive Key Encryption Key (KEK) from password using Argon2ID
	var kek []byte
	var err error

	switch keyInfo.Type {
	case KeyTypeAccount:
		kek, err = DerivePasswordFileKey(keyInfo.Password, keyInfo.Salt, keyInfo.FileID, keyInfo.Username)
	case KeyTypeCustom:
		kek, err = DerivePasswordFileKey(keyInfo.Password, keyInfo.Salt, keyInfo.FileID, keyInfo.Username)
	case KeyTypeShare:
		kek, err = DerivePasswordShareKey(keyInfo.Password, keyInfo.Salt, keyInfo.FileID, keyInfo.Username)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyInfo.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	// Encrypt the FEK
	encryptedFEK, err := EncryptGCM(fek, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	// Build envelope: version + keyType + salt + encryptedFEK
	result := []byte{byte(version), byte(keyInfo.Type)}
	result = append(result, keyInfo.Salt...)
	result = append(result, encryptedFEK...)

	return result, nil
}

// ExtractFEKFromPasswordEnvelope extracts the File Encryption Key using password
func ExtractFEKFromPasswordEnvelope(envelope []byte, password []byte, username, fileID string) ([]byte, error) {
	if len(envelope) < 34 { // version(1) + keyType(1) + salt(32) + minimum encrypted data
		return nil, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])
	keyType := KeyType(envelope[1])
	salt := envelope[2:34]        // 32-byte salt
	encryptedFEK := envelope[34:] // Rest is encrypted FEK

	if version != VersionPasswordBased {
		return nil, fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}

	// Derive KEK based on key type
	var kek []byte
	var err error

	switch keyType {
	case KeyTypeAccount:
		kek, err = DerivePasswordFileKey(password, salt, fileID, username)
	case KeyTypeCustom:
		kek, err = DerivePasswordFileKey(password, salt, fileID, username)
	case KeyTypeShare:
		kek, err = DerivePasswordShareKey(password, salt, fileID, username)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", keyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	// Decrypt FEK
	fek, err := DecryptGCM(encryptedFEK, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt FEK: %w", err)
	}

	return fek, nil
}

// GetPasswordEnvelopeInfo returns information about a password-based envelope without decrypting it
func GetPasswordEnvelopeInfo(envelope []byte) (FileEncryptionVersion, KeyType, []byte, error) {
	if len(envelope) < 34 {
		return 0, 0, nil, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])
	keyType := KeyType(envelope[1])
	salt := envelope[2:34]

	if version != VersionPasswordBased {
		return 0, 0, nil, fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}

	switch keyType {
	case KeyTypeAccount, KeyTypeCustom, KeyTypeShare:
		return version, keyType, salt, nil
	default:
		return 0, 0, nil, fmt.Errorf("unsupported key type: %d", keyType)
	}
}
