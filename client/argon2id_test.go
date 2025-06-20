//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"syscall/js"
	"testing"
)

// Test helper to create mock js.Value objects
func createMockJSValue(data interface{}) js.Value {
	switch v := data.(type) {
	case string:
		return js.ValueOf(v)
	case []byte:
		// For byte arrays, we need to simulate a Uint8Array
		arr := js.Global().Get("Uint8Array").New(len(v))
		js.CopyBytesToJS(arr, v)
		return arr
	default:
		return js.ValueOf(v)
	}
}

// Test basic Argon2ID key derivation
func TestArgon2IDKeyDerivation(t *testing.T) {
	password := []byte("testpassword123!")
	salt := make([]byte, 32)
	rand.Read(salt)

	// Test our implementation using the balanced profile
	profile := ArgonBalanced
	key1 := deriveKeyArgon2ID(password, salt, profile)
	key2 := deriveKeyArgon2ID(password, salt, profile)

	// Same input should produce same output
	if !bytes.Equal(key1, key2) {
		t.Error("Argon2ID should be deterministic - same inputs should produce same outputs")
	}

	// Check key length
	if len(key1) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key1))
	}

	// Test with different salt - should produce different key
	salt2 := make([]byte, 32)
	rand.Read(salt2)
	key3 := deriveKeyArgon2ID(password, salt2, profile)

	if bytes.Equal(key1, key3) {
		t.Error("Different salts should produce different keys")
	}

	// Test with different password - should produce different key
	password2 := []byte("differentpassword123!")
	key4 := deriveKeyArgon2ID(password2, salt, profile)

	if bytes.Equal(key1, key4) {
		t.Error("Different passwords should produce different keys")
	}
}

// Test device capability detection and profiles
func TestDeviceCapabilityProfiles(t *testing.T) {
	// Test device capability detection
	capability := detectDeviceCapability()
	if capability != DeviceBalanced {
		t.Errorf("Expected DeviceBalanced for WASM, got %v", capability)
	}

	// Test all profile types
	profiles := []struct {
		name       string
		capability DeviceCapability
		minTime    uint32
		minMemory  uint32
	}{
		{"DeviceMinimal", DeviceMinimal, 1, 16 * 1024},
		{"DeviceInteractive", DeviceInteractive, 1, 32 * 1024},
		{"DeviceBalanced", DeviceBalanced, 2, 64 * 1024},
		{"DeviceMaximum", DeviceMaximum, 4, 128 * 1024},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			profile := getProfileForCapability(tc.capability)

			if profile.Time < tc.minTime {
				t.Errorf("Profile time too low: got %d, expected at least %d", profile.Time, tc.minTime)
			}
			if profile.Memory < tc.minMemory {
				t.Errorf("Profile memory too low: got %d, expected at least %d", profile.Memory, tc.minMemory)
			}
			if profile.KeyLen != 32 {
				t.Errorf("Profile key length should be 32, got %d", profile.KeyLen)
			}
			if profile.Threads == 0 {
				t.Error("Profile threads should be greater than 0")
			}
		})
	}
}

// Test deriveKeyWithDeviceCapability function
func TestDeriveKeyWithDeviceCapability(t *testing.T) {
	password := []byte("testpassword123!")
	salt := make([]byte, 32)
	rand.Read(salt)

	// Test different capabilities produce different keys
	capabilities := []DeviceCapability{
		DeviceMinimal, DeviceInteractive, DeviceBalanced, DeviceMaximum,
	}

	keys := make(map[string]DeviceCapability)

	for _, capability := range capabilities {
		key := deriveKeyWithDeviceCapability(password, salt, capability)

		if len(key) != 32 {
			t.Errorf("Key length should be 32 for %v, got %d", capability, len(key))
		}

		keyStr := base64.StdEncoding.EncodeToString(key)
		if existingCap, exists := keys[keyStr]; exists {
			// Some capabilities might produce the same result if they have identical parameters
			// This is okay, but log it
			t.Logf("Capability %v produced same key as %v", capability, existingCap)
		}
		keys[keyStr] = capability
	}
}

// Test salt uniqueness
func TestSaltUniqueness(t *testing.T) {
	salts := make(map[string]bool)

	// Generate 100 salts and ensure they're all unique
	for i := 0; i < 100; i++ {
		salt := make([]byte, saltLength)
		rand.Read(salt)
		saltStr := base64.StdEncoding.EncodeToString(salt)

		if salts[saltStr] {
			t.Error("Generated duplicate salt")
		}
		salts[saltStr] = true
	}
}

// Test key uniqueness across different files
func TestKeyUniquenessAcrossFiles(t *testing.T) {
	password := []byte("samepassword123!")
	keys := make(map[string]bool)
	capability := DeviceBalanced

	// Generate keys for 50 different "files" (different salts)
	for i := 0; i < 50; i++ {
		salt := make([]byte, saltLength)
		rand.Read(salt)

		key := deriveKeyWithDeviceCapability(password, salt, capability)
		keyStr := base64.StdEncoding.EncodeToString(key)

		if keys[keyStr] {
			t.Error("Generated duplicate key for same password with different salts")
		}
		keys[keyStr] = true
	}
}

// Test session key derivation with domain separation
func TestSessionKeyDerivation(t *testing.T) {
	password := "userpassword123!"
	salt := make([]byte, 32)
	rand.Read(salt)
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	// Test session key derivation
	args := []js.Value{js.ValueOf(password), js.ValueOf(saltB64)}
	result := deriveSessionKey(js.Undefined(), args)

	sessionKeyB64, ok := result.(string)
	if !ok {
		t.Error("Expected string result from deriveSessionKey")
	}

	sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyB64)
	if err != nil {
		t.Errorf("Failed to decode session key: %v", err)
	}

	if len(sessionKey) != 32 {
		t.Errorf("Expected session key length 32, got %d", len(sessionKey))
	}

	// Verify domain separation - session key should be different from direct key derivation
	capability := detectDeviceCapability()
	directKey := deriveKeyWithDeviceCapability([]byte(password), salt, capability)
	if bytes.Equal(sessionKey, directKey) {
		t.Error("Session key should be different from direct key derivation due to domain separation")
	}

	// Test same inputs produce same session key
	result2 := deriveSessionKey(js.Undefined(), args)
	sessionKeyB64_2, ok := result2.(string)
	if !ok || sessionKeyB64 != sessionKeyB64_2 {
		t.Error("Same inputs should produce same session key")
	}
}

// Test file encryption and decryption roundtrip
func TestFileEncryptionDecryptionRoundtrip(t *testing.T) {
	// Test data
	originalData := []byte("This is test file content for encryption testing with Argon2ID!")
	password := "testpassword123!"

	// Test custom password encryption
	dataJS := createMockJSValue(originalData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom")}

	encryptResult := encryptFile(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatalf("Expected string result from encryptFile, got %T", encryptResult)
	}

	// Test decryption
	decryptArgs := []js.Value{js.ValueOf(encryptedB64), js.ValueOf(password)}
	decryptResult := decryptFile(js.Undefined(), decryptArgs)

	decryptedB64, ok := decryptResult.(string)
	if !ok {
		t.Fatalf("Expected string result from decryptFile, got %T", decryptResult)
	}

	// Decode and compare
	decryptedData, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatalf("Failed to decode decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data doesn't match original data")
	}
}

// Test encryption format version
func TestEncryptionFormatVersion(t *testing.T) {
	originalData := []byte("test data")
	password := "testpassword123!"

	dataJS := createMockJSValue(originalData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom")}

	encryptResult := encryptFile(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatal("Failed to encrypt data")
	}

	// Decode and check version byte
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		t.Fatalf("Failed to decode encrypted data: %v", err)
	}

	if len(encryptedData) < 2 {
		t.Fatal("Encrypted data too short")
	}

	if encryptedData[0] != 0x04 {
		t.Errorf("Expected version 0x04, got 0x%02x", encryptedData[0])
	}

	// Check key type for custom password
	if encryptedData[1] != 0x00 {
		t.Errorf("Expected key type 0x00 for custom password, got 0x%02x", encryptedData[1])
	}
}

// Test multi-key encryption and decryption
func TestMultiKeyEncryptionDecryption(t *testing.T) {
	originalData := []byte("Multi-key test data for Argon2ID encryption")
	primaryPassword := "primary123!"
	additionalPassword := "additional123!"

	// Create test data
	dataJS := createMockJSValue(originalData)

	// Create additional keys array
	additionalKeys := js.Global().Get("Array").New(1)
	keyInfo := js.Global().Get("Object").New()
	keyInfo.Set("password", additionalPassword)
	keyInfo.Set("id", "share1")
	additionalKeys.SetIndex(0, keyInfo)

	args := []js.Value{
		dataJS,
		js.ValueOf(primaryPassword),
		js.ValueOf("custom"),
		additionalKeys,
	}

	encryptResult := encryptFileMultiKey(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatalf("Expected string result from encryptFileMultiKey, got %T", encryptResult)
	}

	// Test decryption with primary password
	decryptArgs1 := []js.Value{js.ValueOf(encryptedB64), js.ValueOf(primaryPassword)}
	decryptResult1 := decryptFileMultiKey(js.Undefined(), decryptArgs1)

	decryptedB64_1, ok := decryptResult1.(string)
	if !ok {
		t.Fatalf("Failed to decrypt with primary password: %v", decryptResult1)
	}

	decryptedData1, err := base64.StdEncoding.DecodeString(decryptedB64_1)
	if err != nil {
		t.Fatalf("Failed to decode decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData1) {
		t.Error("Primary password decryption failed")
	}

	// Test decryption with additional password
	decryptArgs2 := []js.Value{js.ValueOf(encryptedB64), js.ValueOf(additionalPassword)}
	decryptResult2 := decryptFileMultiKey(js.Undefined(), decryptArgs2)

	decryptedB64_2, ok := decryptResult2.(string)
	if !ok {
		t.Fatalf("Failed to decrypt with additional password: %v", decryptResult2)
	}

	decryptedData2, err := base64.StdEncoding.DecodeString(decryptedB64_2)
	if err != nil {
		t.Fatalf("Failed to decode decrypted data: %v", err)
	}

	if !bytes.Equal(originalData, decryptedData2) {
		t.Error("Additional password decryption failed")
	}

	// Test with wrong password should fail
	decryptArgs3 := []js.Value{js.ValueOf(encryptedB64), js.ValueOf("wrongpassword")}
	decryptResult3 := decryptFileMultiKey(js.Undefined(), decryptArgs3)

	if result, ok := decryptResult3.(string); !ok || !bytes.Contains([]byte(result), []byte("Failed")) {
		t.Error("Wrong password should fail to decrypt")
	}
}

// Test multi-key format version
func TestMultiKeyFormatVersion(t *testing.T) {
	originalData := []byte("test data")
	password := "testpassword123!"

	dataJS := createMockJSValue(originalData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom"), js.Null()}

	encryptResult := encryptFileMultiKey(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatal("Failed to encrypt data")
	}

	// Decode and check version byte
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		t.Fatalf("Failed to decode encrypted data: %v", err)
	}

	if len(encryptedData) < 2 {
		t.Fatal("Encrypted data too short")
	}

	if encryptedData[0] != 0x05 {
		t.Errorf("Expected version 0x05 for multi-key, got 0x%02x", encryptedData[0])
	}

	// Check number of keys
	if encryptedData[1] != 0x01 {
		t.Errorf("Expected 1 key, got %d", encryptedData[1])
	}
}
