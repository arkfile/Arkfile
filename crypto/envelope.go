package crypto

import (
	"fmt"
)

// KeyType represents the type of encryption key
type KeyType byte

const (
	KeyTypeAccount KeyType = 0x01 // OPAQUE account password
	KeyTypeCustom  KeyType = 0x02 // OPAQUE custom password
)

// KeyInfo contains information about an encryption key
type KeyInfo struct {
	ID        string  // User-friendly identifier
	Type      KeyType // Account or custom
	ExportKey []byte  // OPAQUE export key (for both account and custom)
	Username  string  // Username for HKDF context
	FileID    string  // File ID for HKDF context
	Hint      string  // Optional hint for custom passwords
}

// FileEncryptionVersion represents file encryption format versions
type FileEncryptionVersion byte

const (
	VersionOPAQUEAccount FileEncryptionVersion = 0x01 // OPAQUE account password
	VersionOPAQUECustom  FileEncryptionVersion = 0x02 // OPAQUE custom password
)

// CreateSingleKeyEnvelope creates a simple envelope for single-key encryption using OPAQUE
func CreateSingleKeyEnvelope(fek []byte, keyInfo KeyInfo) ([]byte, error) {
	version := VersionOPAQUECustom
	if keyInfo.Type == KeyTypeAccount {
		version = VersionOPAQUEAccount
	}

	// Derive Key Encryption Key (KEK) from OPAQUE export key using HKDF
	var kek []byte
	var err error
	if keyInfo.Type == KeyTypeAccount {
		// Use account file key derivation
		kek, err = DeriveAccountFileKey(keyInfo.ExportKey, keyInfo.Username, keyInfo.FileID)
	} else {
		// Use custom file key derivation (different HKDF context)
		kek, err = DeriveOPAQUEFileKey(keyInfo.ExportKey, keyInfo.FileID, keyInfo.Username)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to derive KEK: %w", err)
	}

	// Encrypt the FEK
	encryptedFEK, err := EncryptGCM(fek, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	// Build envelope: version + keyType + encryptedFEK (no salt needed - OPAQUE provides entropy)
	result := []byte{byte(version), byte(keyInfo.Type)}
	result = append(result, encryptedFEK...)

	return result, nil
}

// ExtractFEKFromEnvelope attempts to extract the File Encryption Key using OPAQUE export key
func ExtractFEKFromEnvelope(envelope []byte, exportKey []byte, username, fileID string) ([]byte, error) {
	if len(envelope) < 2 {
		return nil, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])
	keyType := KeyType(envelope[1])
	encryptedFEK := envelope[2:]

	// Derive KEK based on key type
	var kek []byte
	var err error

	switch version {
	case VersionOPAQUEAccount:
		if keyType != KeyTypeAccount {
			return nil, fmt.Errorf("key type mismatch for account version")
		}
		kek, err = DeriveAccountFileKey(exportKey, username, fileID)
	case VersionOPAQUECustom:
		if keyType != KeyTypeCustom {
			return nil, fmt.Errorf("key type mismatch for custom version")
		}
		kek, err = DeriveOPAQUEFileKey(exportKey, fileID, username)
	default:
		return nil, fmt.Errorf("unsupported envelope version: 0x%02x", version)
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

// GetEnvelopeInfo returns information about an envelope without decrypting it
func GetEnvelopeInfo(envelope []byte) (FileEncryptionVersion, KeyType, error) {
	if len(envelope) < 2 {
		return 0, 0, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])
	keyType := KeyType(envelope[1])

	switch version {
	case VersionOPAQUEAccount, VersionOPAQUECustom:
		return version, keyType, nil
	default:
		return 0, 0, fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}
}
