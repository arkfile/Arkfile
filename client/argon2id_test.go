//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"syscall/js"
	"testing"
	"time"
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

	// Test our implementation
	key1 := deriveKeyArgon2ID(password, salt)
	key2 := deriveKeyArgon2ID(password, salt)

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
	key3 := deriveKeyArgon2ID(password, salt2)

	if bytes.Equal(key1, key3) {
		t.Error("Different salts should produce different keys")
	}

	// Test with different password - should produce different key
	password2 := []byte("differentpassword123!")
	key4 := deriveKeyArgon2ID(password2, salt)

	if bytes.Equal(key1, key4) {
		t.Error("Different passwords should produce different keys")
	}
}

// Test Argon2ID parameters are correctly set
func TestArgon2IDParameters(t *testing.T) {
	// Verify our constants match expected values
	if argon2Time != 4 {
		t.Errorf("Expected argon2Time=4, got %d", argon2Time)
	}
	if argon2Memory != 131072 { // 128MB in KB
		t.Errorf("Expected argon2Memory=131072, got %d", argon2Memory)
	}
	if argon2Threads != 4 {
		t.Errorf("Expected argon2Threads=4, got %d", argon2Threads)
	}
	if argon2KeyLen != 32 {
		t.Errorf("Expected argon2KeyLen=32, got %d", argon2KeyLen)
	}
	if saltLength != 32 {
		t.Errorf("Expected saltLength=32, got %d", saltLength)
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

	// Generate keys for 50 different "files" (different salts)
	for i := 0; i < 50; i++ {
		salt := make([]byte, saltLength)
		rand.Read(salt)

		key := deriveKeyArgon2ID(password, salt)
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
	directKey := deriveKeyArgon2ID([]byte(password), salt)
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

// Test invalid password handling
func TestInvalidPasswordHandling(t *testing.T) {
	originalData := []byte("test data")
	password := "testpassword123!"

	// Encrypt data
	dataJS := createMockJSValue(originalData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom")}

	encryptResult := encryptFile(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatal("Failed to encrypt data")
	}

	// Try to decrypt with wrong password
	decryptArgs := []js.Value{js.ValueOf(encryptedB64), js.ValueOf("wrongpassword")}
	decryptResult := decryptFile(js.Undefined(), decryptArgs)

	if result, ok := decryptResult.(string); !ok || !bytes.Contains([]byte(result), []byte("Failed")) {
		t.Error("Wrong password should fail to decrypt")
	}
}

// Performance benchmark test
func TestArgon2IDPerformance(t *testing.T) {
	password := []byte("testpassword123!")
	salt := make([]byte, 32)
	rand.Read(salt)

	// Measure key derivation time
	start := time.Now()
	key := deriveKeyArgon2ID(password, salt)
	duration := time.Since(start)

	t.Logf("Argon2ID key derivation took: %v", duration)

	// Verify key was generated
	if len(key) != 32 {
		t.Error("Key generation failed")
	}

	// Performance should be reasonable (less than 10 seconds for testing)
	if duration > 10*time.Second {
		t.Errorf("Key derivation too slow: %v", duration)
	}
}

// Test memory usage during key derivation
func TestMemoryClearing(t *testing.T) {
	password := []byte("testpassword123!")
	salt := make([]byte, 32)
	rand.Read(salt)

	// Test that key derivation completes without memory issues
	key := deriveKeyArgon2ID(password, salt)
	if len(key) != 32 {
		t.Error("Key derivation failed")
	}

	// Clear sensitive data (simulate memory clearing)
	for i := range password {
		password[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	// Test empty file encryption/decryption
	emptyData := []byte{}
	password := "testpassword123!"

	dataJS := createMockJSValue(emptyData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom")}

	encryptResult := encryptFile(js.Undefined(), args)
	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatal("Failed to encrypt empty data")
	}

	// Decrypt and verify
	decryptArgs := []js.Value{js.ValueOf(encryptedB64), js.ValueOf(password)}
	decryptResult := decryptFile(js.Undefined(), decryptArgs)

	decryptedB64, ok := decryptResult.(string)
	if !ok {
		t.Fatal("Failed to decrypt empty data")
	}

	decryptedData, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatal("Failed to decode empty decrypted data")
	}

	if len(decryptedData) != 0 {
		t.Error("Empty data should remain empty after encryption/decryption")
	}
}

// Test concurrent safety
func TestConcurrentSafety(t *testing.T) {
	password := []byte("testpassword123!")
	numGoroutines := 10
	results := make(chan []byte, numGoroutines)

	// Run concurrent key derivations
	for i := 0; i < numGoroutines; i++ {
		go func() {
			salt := make([]byte, 32)
			rand.Read(salt)
			key := deriveKeyArgon2ID(password, salt)
			results <- key
		}()
	}

	// Collect results
	keys := make([][]byte, 0, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		key := <-results
		if len(key) != 32 {
			t.Error("Invalid key length from concurrent derivation")
		}
		keys = append(keys, key)
	}

	// Verify all keys are different (different salts)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Error("Concurrent derivations produced identical keys (should be different due to different salts)")
			}
		}
	}
}

// Test large data encryption
func TestLargeDataEncryption(t *testing.T) {
	// Create 1MB of test data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	password := "testpassword123!"

	dataJS := createMockJSValue(largeData)
	args := []js.Value{dataJS, js.ValueOf(password), js.ValueOf("custom")}

	start := time.Now()
	encryptResult := encryptFile(js.Undefined(), args)
	encryptDuration := time.Since(start)

	t.Logf("Large data encryption took: %v", encryptDuration)

	encryptedB64, ok := encryptResult.(string)
	if !ok {
		t.Fatal("Failed to encrypt large data")
	}

	// Decrypt and verify
	decryptArgs := []js.Value{js.ValueOf(encryptedB64), js.ValueOf(password)}

	start = time.Now()
	decryptResult := decryptFile(js.Undefined(), decryptArgs)
	decryptDuration := time.Since(start)

	t.Logf("Large data decryption took: %v", decryptDuration)

	decryptedB64, ok := decryptResult.(string)
	if !ok {
		t.Fatal("Failed to decrypt large data")
	}

	decryptedData, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatal("Failed to decode large decrypted data")
	}

	if !bytes.Equal(largeData, decryptedData) {
		t.Error("Large data doesn't match after encryption/decryption")
	}
}
