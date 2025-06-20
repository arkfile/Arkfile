package crypto

import (
	"bytes"
	"fmt"
)

// KeyType represents the type of encryption key
type KeyType byte

const (
	KeyTypeAccount KeyType = 0x01 // OPAQUE session key
	KeyTypeCustom  KeyType = 0x00 // Custom password
)

// KeyInfo contains information about an encryption key
type KeyInfo struct {
	ID       string  // User-friendly identifier
	Type     KeyType // Account or custom
	Password []byte  // Raw password or session key
	Hint     string  // Optional hint for custom passwords
}

// FileEncryptionVersion represents file encryption format versions
type FileEncryptionVersion byte

const (
	VersionAccountSingle FileEncryptionVersion = 0x01 // OPAQUE session key, single key
	VersionAccountMulti  FileEncryptionVersion = 0x02 // OPAQUE session key, multi-key
	VersionCustomSingle  FileEncryptionVersion = 0x03 // Custom password, single key
	VersionCustomMulti   FileEncryptionVersion = 0x04 // Custom password, multi-key
)

// EncryptedKeyEntry represents a single key entry in a multi-key envelope
type EncryptedKeyEntry struct {
	KeyType      KeyType
	KeyID        string
	Salt         []byte // For key derivation
	EncryptedFEK []byte // Encrypted File Encryption Key
}

// CreateSingleKeyEnvelope creates a simple envelope for single-key encryption
func CreateSingleKeyEnvelope(fek []byte, keyInfo KeyInfo) ([]byte, error) {
	version := VersionCustomSingle
	if keyInfo.Type == KeyTypeAccount {
		version = VersionAccountSingle
	}

	// Generate salt for key derivation
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive Key Encryption Key (KEK)
	var kek []byte
	if keyInfo.Type == KeyTypeAccount {
		// Session key is already derived, use directly
		kek = keyInfo.Password
	} else {
		// Custom password, derive using Argon2ID
		kek = DeriveKeyArgon2ID(keyInfo.Password, salt, ArgonInteractive)
	}

	// Encrypt the FEK
	encryptedFEK, err := EncryptGCM(fek, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	// Build envelope: version + keyType + salt + encryptedFEK
	result := []byte{byte(version), byte(keyInfo.Type)}
	result = append(result, salt...)
	result = append(result, encryptedFEK...)

	return result, nil
}

// CreateMultiKeyEnvelope creates an envelope that can be decrypted by multiple keys
func CreateMultiKeyEnvelope(fek []byte, keys []KeyInfo) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one key is required")
	}
	if len(keys) > 255 {
		return nil, fmt.Errorf("maximum 255 keys supported")
	}

	// Determine version based on primary key type
	version := VersionCustomMulti
	if keys[0].Type == KeyTypeAccount {
		version = VersionAccountMulti
	}

	// Start with version and key count
	result := []byte{byte(version), byte(len(keys))}

	// Create encrypted key entries
	for _, keyInfo := range keys {
		entry, err := createKeyEntry(fek, keyInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to create key entry for %s: %w", keyInfo.ID, err)
		}
		result = append(result, entry...)
	}

	return result, nil
}

// createKeyEntry creates an encrypted key entry for a single key
func createKeyEntry(fek []byte, keyInfo KeyInfo) ([]byte, error) {
	// Generate salt for this key
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive Key Encryption Key (KEK)
	var kek []byte
	if keyInfo.Type == KeyTypeAccount {
		// Session key is already derived, use directly
		kek = keyInfo.Password
	} else {
		// Custom password, derive using Argon2ID
		kek = DeriveKeyArgon2ID(keyInfo.Password, salt, ArgonInteractive)
	}

	// Encrypt the FEK
	encryptedFEK, err := EncryptGCM(fek, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	// Build entry: keyType + keyID + null terminator + salt + encryptedFEK
	entry := []byte{byte(keyInfo.Type)}
	entry = append(entry, []byte(keyInfo.ID)...)
	entry = append(entry, 0x00) // null terminator
	entry = append(entry, salt...)
	entry = append(entry, encryptedFEK...)

	return entry, nil
}

// ExtractFEKFromEnvelope attempts to extract the File Encryption Key using the provided password
func ExtractFEKFromEnvelope(envelope []byte, password []byte) ([]byte, error) {
	if len(envelope) < 2 {
		return nil, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])
	envelope = envelope[1:]

	switch version {
	case VersionAccountSingle, VersionCustomSingle:
		return extractFEKSingleKey(envelope, password, version)
	case VersionAccountMulti, VersionCustomMulti:
		return extractFEKMultiKey(envelope, password, version)
	default:
		return nil, fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}
}

// extractFEKSingleKey extracts FEK from a single-key envelope
func extractFEKSingleKey(envelope []byte, password []byte, version FileEncryptionVersion) ([]byte, error) {
	if len(envelope) < 1+32+12+32+16 { // keyType + salt + nonce + key + tag
		return nil, fmt.Errorf("single-key envelope too short")
	}

	keyType := KeyType(envelope[0])
	salt := envelope[1:33]
	encryptedFEK := envelope[33:]

	// Derive KEK based on key type
	var kek []byte
	if keyType == KeyTypeAccount {
		// Password should be the session key
		kek = password
	} else {
		// Custom password, derive using Argon2ID
		kek = DeriveKeyArgon2ID(password, salt, ArgonInteractive)
	}

	// Decrypt FEK
	fek, err := DecryptGCM(encryptedFEK, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt FEK: %w", err)
	}

	return fek, nil
}

// extractFEKMultiKey extracts FEK from a multi-key envelope
func extractFEKMultiKey(envelope []byte, password []byte, version FileEncryptionVersion) ([]byte, error) {
	if len(envelope) < 1 {
		return nil, fmt.Errorf("multi-key envelope too short")
	}

	numKeys := int(envelope[0])
	envelope = envelope[1:]

	// Try each key entry
	for i := 0; i < numKeys; i++ {
		if len(envelope) < 1 {
			return nil, fmt.Errorf("envelope truncated at key %d", i)
		}

		keyType := KeyType(envelope[0])
		envelope = envelope[1:]

		// Find key ID (null-terminated string)
		nullPos := bytes.IndexByte(envelope, 0x00)
		if nullPos == -1 {
			return nil, fmt.Errorf("key ID not null-terminated at key %d", i)
		}

		keyID := string(envelope[:nullPos])
		envelope = envelope[nullPos+1:]

		// Extract salt and encrypted FEK
		if len(envelope) < 32 {
			return nil, fmt.Errorf("no salt for key %d (%s)", i, keyID)
		}
		salt := envelope[:32]
		envelope = envelope[32:]

		// Minimum encrypted FEK size (nonce + key + tag)
		minFEKSize := 12 + 32 + 16
		if len(envelope) < minFEKSize {
			return nil, fmt.Errorf("encrypted FEK too short for key %d (%s)", i, keyID)
		}

		// Extract encrypted FEK (we need to know the size)
		// For GCM: nonce(12) + ciphertext(32) + tag(16) = 60 bytes
		encryptedFEKSize := 60
		if len(envelope) < encryptedFEKSize {
			return nil, fmt.Errorf("not enough data for encrypted FEK at key %d (%s)", i, keyID)
		}

		encryptedFEK := envelope[:encryptedFEKSize]
		envelope = envelope[encryptedFEKSize:]

		// Try to decrypt with this key
		var kek []byte
		if keyType == KeyTypeAccount {
			kek = password
		} else {
			kek = DeriveKeyArgon2ID(password, salt, ArgonInteractive)
		}

		fek, err := DecryptGCM(encryptedFEK, kek)
		if err == nil {
			// Successfully decrypted!
			return fek, nil
		}
		// If decryption failed, continue to next key
	}

	return nil, fmt.Errorf("password does not match any of the %d keys", numKeys)
}

// GetEnvelopeInfo returns information about an envelope without decrypting it
func GetEnvelopeInfo(envelope []byte) (FileEncryptionVersion, int, error) {
	if len(envelope) < 2 {
		return 0, 0, fmt.Errorf("envelope too short")
	}

	version := FileEncryptionVersion(envelope[0])

	switch version {
	case VersionAccountSingle, VersionCustomSingle:
		return version, 1, nil
	case VersionAccountMulti, VersionCustomMulti:
		numKeys := int(envelope[1])
		return version, numKeys, nil
	default:
		return 0, 0, fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}
}
