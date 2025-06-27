//go:build js && wasm
// +build js,wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"syscall/js" // specifically for WASM build

	"golang.org/x/crypto/argon2"
)

// Device capability types - matching the server-side crypto package
type DeviceCapability int

const (
	DeviceMinimal DeviceCapability = iota
	DeviceInteractive
	DeviceBalanced
	DeviceMaximum
)

// ArgonProfile defines Argon2ID parameters for different device capabilities
type ArgonProfile struct {
	Time    uint32 // iterations
	Memory  uint32 // KB
	Threads uint8  // parallelism
	KeyLen  uint32 // output length in bytes
}

// Predefined profiles matching the server-side crypto package
var (
	// ArgonInteractive - for client-side pre-OPAQUE hardening (mobile-friendly)
	ArgonInteractive = ArgonProfile{
		Time:    1,
		Memory:  32 * 1024, // 32MB
		Threads: 2,
		KeyLen:  32,
	}

	// ArgonBalanced - for mid-range devices
	ArgonBalanced = ArgonProfile{
		Time:    2,
		Memory:  64 * 1024, // 64MB
		Threads: 2,
		KeyLen:  32,
	}

	// ArgonMaximum - for server-side post-OPAQUE hardening (maximum security)
	ArgonMaximum = ArgonProfile{
		Time:    4,
		Memory:  128 * 1024, // 128MB
		Threads: 4,
		KeyLen:  32,
	}

	// Salt length in bytes
	saltLength = 32

	// Key length in bytes
	keyLength = 32
)

// detectDeviceCapability detects device performance tier for adaptive Argon2ID parameters
func detectDeviceCapability() DeviceCapability {
	// Simple heuristic based on available memory and hardware concurrency
	// In a real implementation, this would include performance benchmarking

	// For WASM, we'll default to balanced but allow override
	// This can be enhanced with actual performance testing in the future
	return DeviceBalanced
}

// getProfileForCapability returns the ArgonProfile for a given device capability
func getProfileForCapability(capability DeviceCapability) ArgonProfile {
	switch capability {
	case DeviceMinimal:
		return ArgonProfile{
			Time:    1,
			Memory:  16 * 1024, // 16MB
			Threads: 1,
			KeyLen:  32,
		}
	case DeviceInteractive:
		return ArgonInteractive
	case DeviceBalanced:
		return ArgonBalanced
	case DeviceMaximum:
		return ArgonMaximum
	default:
		return ArgonInteractive // Safe default
	}
}

// deriveKeyArgon2ID generates a cryptographic key from a password using Argon2ID
// This provides memory-hard protection against GPU and ASIC-based attacks
func deriveKeyArgon2ID(password []byte, salt []byte, profile ArgonProfile) []byte {
	return argon2.IDKey(password, salt, profile.Time, profile.Memory, profile.Threads, profile.KeyLen)
}

// deriveKeyWithDeviceCapability derives a key using adaptive device parameters
func deriveKeyWithDeviceCapability(password []byte, salt []byte, capability DeviceCapability) []byte {
	profile := getProfileForCapability(capability)
	return deriveKeyArgon2ID(password, salt, profile)
}

// deriveSessionKey derives a session key for account-based encryption
// Uses domain separation to ensure session keys are different from password hashes
func deriveSessionKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "Invalid number of arguments"
	}

	password := args[0].String()
	encodedSalt := args[1].String()

	// Decode salt
	saltBytes, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return "Failed to decode salt"
	}

	// Domain separation: prepend a context string to the password for session key derivation
	// This ensures session keys are cryptographically different from password hashes
	contextualPassword := "ARKFILE_SESSION_KEY:" + password

	// Use Argon2ID for session key derivation with domain separation
	// Use device capability detection for adaptive parameters
	capability := detectDeviceCapability()
	sessionKey := deriveKeyWithDeviceCapability([]byte(contextualPassword), saltBytes, capability)
	return base64.StdEncoding.EncodeToString(sessionKey)
}

// calculateSHA256 calculates the SHA-256 hash of input data
func calculateSHA256(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "Invalid number of arguments"
	}

	data := make([]byte, args[0].Length())
	js.CopyBytesToGo(data, args[0])

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func encryptFile(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return "Invalid number of arguments"
	}

	data := make([]byte, args[0].Length())
	js.CopyBytesToGo(data, args[0])
	password := args[1].String()
	keyType := args[2].String()

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "Failed to generate salt"
	}

	// Format version 0x04 = Argon2ID KDF
	// We'll use the first byte as version, and the second byte as key type
	// 0x00 = custom password, 0x01 = account-derived session key
	result := []byte{0x04}

	var keyTypeByte byte = 0x00
	if keyType == "account" {
		keyTypeByte = 0x01
	}
	result = append(result, keyTypeByte)

	// For account password (session key), the password is already derived
	// For custom password, we need to derive it
	var key []byte

	if keyType == "account" {
		// For account password, the input is already a base64 encoded key
		var err error
		key, err = base64.StdEncoding.DecodeString(password)
		if err != nil {
			return "Failed to decode session key"
		}
	} else {
		// For custom password, derive key using Argon2ID
		capability := detectDeviceCapability()
		key = deriveKeyWithDeviceCapability([]byte(password), salt, capability)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "Failed to create cipher block"
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "Failed to create GCM"
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "Failed to generate nonce"
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Combine salt and ciphertext
	result = append(result, salt...)
	result = append(result, ciphertext...)

	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(result)
}

func decryptFile(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "Invalid number of arguments"
	}

	encodedData := args[0].String()
	password := args[1].String()

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "Failed to decode data"
	}

	// Check for minimum length (version + keyType + salt + minimum ciphertext)
	if len(data) < 2+16+16 {
		return "Data too short"
	}

	// Extract version byte and key type
	version := data[0]
	keyType := data[1]
	data = data[2:]

	// Extract salt (16 bytes)
	salt := data[:16]
	data = data[16:]

	// Derive key based on version and key type
	var key []byte

	if version == 0x04 {
		// Use Argon2ID KDF
		if keyType == 0x01 {
			// This is an account-password encrypted file
			var err error
			key, err = base64.StdEncoding.DecodeString(password)
			if err != nil {
				return "Failed to decode session key"
			}
		} else {
			// This is a custom password, derive key normally
			capability := detectDeviceCapability()
			key = deriveKeyWithDeviceCapability([]byte(password), salt, capability)
		}
	} else {
		return "Unsupported encryption version"
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "Failed to create cipher block"
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "Failed to create GCM"
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "Data too short for nonce"
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "Failed to decrypt data: " + err.Error()
	}

	// Return base64 encoded plaintext
	return base64.StdEncoding.EncodeToString(plaintext)
}

func generateSalt(this js.Value, args []js.Value) interface{} {
	salt := make([]byte, saltLength) // Use the configured salt length (32 bytes)
	if _, err := rand.Read(salt); err != nil {
		return "Failed to generate salt"
	}
	return base64.StdEncoding.EncodeToString(salt)
}

// Generate a random File Encryption Key (FEK)
func generateFileEncryptionKey() []byte {
	fek := make([]byte, keyLength)
	if _, err := rand.Read(fek); err != nil {
		panic("Failed to generate random key")
	}
	return fek
}

// Encrypt a FEK with a password-derived key
func encryptFEK(fek []byte, password []byte, keyType byte, keyID string) []byte {
	// Generate salt (use the same salt length as elsewhere for consistency)
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		panic("Failed to generate salt")
	}

	// Derive KEK using Argon2ID
	var kek []byte
	if keyType == 0x01 {
		// For account password (session key), it's already derived
		kek = password
	} else {
		// For custom password, derive using Argon2ID
		capability := detectDeviceCapability()
		kek = deriveKeyWithDeviceCapability(password, salt, capability)
	}

	// Encrypt the FEK using AES-GCM with the derived KEK
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	// Encrypt FEK
	encryptedFEK := gcm.Seal(nonce, nonce, fek, nil)

	// Create metadata entry including salt and encrypted FEK
	result := []byte{keyType}                 // Key type
	result = append(result, []byte(keyID)...) // Key ID
	result = append(result, 0x00)             // Null terminator for Key ID
	result = append(result, salt...)          // Salt
	result = append(result, encryptedFEK...)  // Encrypted FEK

	return result
}

// Multi-key encrypt file function
func encryptFileMultiKey(this js.Value, args []js.Value) interface{} {
	// Args: fileData, primary password, primary key type, optional additional passwords
	if len(args) < 3 {
		return "Invalid number of arguments"
	}

	data := make([]byte, args[0].Length())
	js.CopyBytesToGo(data, args[0])
	primaryPassword := args[1].String()
	primaryKeyType := args[2].String()

	// Generate a random FEK for this file
	fek := generateFileEncryptionKey()

	// Format version 0x05 = multi-key Argon2ID encryption
	result := []byte{0x05}

	// Add number of keys
	numKeys := 1 // Start with primary key
	if len(args) > 3 {
		numKeys += args[3].Length() // Add any additional keys
	}
	result = append(result, byte(numKeys))

	// Encrypt FEK with primary password
	var keyTypeByte byte = 0x00
	if primaryKeyType == "account" {
		keyTypeByte = 0x01
	}
	primaryKeyID := "primary"
	var primaryPasswordBytes []byte

	if primaryKeyType == "account" {
		// For account password, decode the base64 session key
		decoded, err := base64.StdEncoding.DecodeString(primaryPassword)
		if err != nil {
			return "Failed to decode session key"
		}
		primaryPasswordBytes = decoded
	} else {
		// For custom password, use directly
		primaryPasswordBytes = []byte(primaryPassword)
	}

	primaryKeyEntry := encryptFEK(fek, primaryPasswordBytes, keyTypeByte, primaryKeyID)
	result = append(result, primaryKeyEntry...)

	// Add additional keys if any
	if len(args) > 3 && !args[3].IsNull() && !args[3].IsUndefined() {
		additionalKeys := args[3]
		for i := 0; i < additionalKeys.Length(); i++ {
			keyInfo := additionalKeys.Index(i)
			password := keyInfo.Get("password").String()
			keyID := keyInfo.Get("id").String()
			// Additional keys are always custom
			keyEntry := encryptFEK(fek, []byte(password), 0x00, keyID)
			result = append(result, keyEntry...)
		}
	}

	// Now encrypt the actual file data with the FEK
	block, _ := aes.NewCipher(fek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Add encrypted file data
	result = append(result, ciphertext...)

	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(result)
}

// Decrypt multi-key encrypted file
func decryptFileMultiKey(this js.Value, args []js.Value) interface{} {
	// Args: encrypted data, password to try
	if len(args) != 2 {
		return "Invalid number of arguments"
	}

	encodedData := args[0].String()
	password := args[1].String()

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "Failed to decode data"
	}

	// Check format version
	if len(data) < 2 {
		return "Invalid data format"
	}

	if data[0] != 0x05 {
		return "Not a multi-key encrypted file"
	}

	// Get number of keys
	numKeys := int(data[1])
	data = data[2:]

	// Try each key entry
	var fek []byte
	var decryptionSuccessful bool

	for i := 0; i < numKeys; i++ {
		if len(data) < 1 {
			return "Corrupted key entry"
		}

		keyType := data[0]
		data = data[1:]

		// Extract key ID until null terminator and skip it
		// We don't need the key ID for decryption
		j := 0
		for j < len(data) && data[j] != 0x00 {
			j++
		}

		if j >= len(data) {
			return "Corrupted key entry: no null terminator"
		}

		// Skip the key ID and null terminator
		data = data[j+1:] // Skip null terminator

		if len(data) < saltLength {
			return "Corrupted key entry: salt too short"
		}

		// Extract salt (32 bytes for Argon2ID)
		salt := data[:saltLength]
		data = data[saltLength:]

		// Minimum size check for encrypted FEK
		if len(data) < 12+keyLength+16 { // nonce + key + tag
			return "Corrupted key entry: encrypted FEK too short"
		}

		// Extract encrypted FEK (nonce + ciphertext)
		// Determine encrypted FEK size based on nonce size (12) + key size (32) + GCM tag (16)
		encryptedFEKSize := 12 + keyLength + 16
		encryptedFEK := data[:encryptedFEKSize]
		data = data[encryptedFEKSize:]

		// Try to decrypt this FEK entry
		var keyToTry []byte

		if keyType == 0x01 {
			// This is an account key - password should be session key
			decodedKey, err := base64.StdEncoding.DecodeString(password)
			if err != nil {
				// If this fails, just try the next key
				continue
			}
			keyToTry = decodedKey
		} else {
			// This is a custom key - derive from password and salt
			capability := detectDeviceCapability()
			keyToTry = deriveKeyWithDeviceCapability([]byte(password), salt, capability)
		}

		// Try to decrypt the FEK
		block, err := aes.NewCipher(keyToTry)
		if err != nil {
			continue
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}

		// Extract nonce and ciphertext from encrypted FEK
		nonceSize := gcm.NonceSize()
		if len(encryptedFEK) < nonceSize {
			continue
		}

		nonce := encryptedFEK[:nonceSize]
		ciphertext := encryptedFEK[nonceSize:]

		// Try to decrypt the FEK
		decryptedFEK, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err == nil && !decryptionSuccessful {
			// This password worked and we haven't found a working key yet!
			fek = decryptedFEK
			decryptionSuccessful = true
		}
		// Continue processing ALL key entries to consume the data properly
	}

	if !decryptionSuccessful {
		return "Failed to decrypt: invalid password for all key entries"
	}

	// At this point we have the FEK and the remaining data is the encrypted file
	// Extract nonce and ciphertext for the file data
	if len(data) < 12 {
		return "Corrupted file data: too short"
	}

	// Decrypt the file data using the FEK
	block, err := aes.NewCipher(fek)
	if err != nil {
		return "Failed to create cipher block for file decryption"
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "Failed to create GCM for file decryption"
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "Corrupted file data: nonce too short"
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt file data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "Failed to decrypt file data: " + err.Error()
	}

	// Return base64 encoded plaintext
	return base64.StdEncoding.EncodeToString(plaintext)
}

// Helper functions for character validation
func isUpper(r rune) bool {
	return r >= 'A' && r <= 'Z'
}

func isLower(r rune) bool {
	return r >= 'a' && r <= 'z'
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func containsRune(s string, r rune) bool {
	for _, char := range s {
		if char == r {
			return true
		}
	}
	return false
}

// validatePasswordComplexity validates password complexity using the same rules as the server
// This function will be exported to WASM and used by all frontend validation
func validatePasswordComplexity(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid number of arguments",
		}
	}

	password := args[0].String()

	// Check minimum length (14 characters)
	if len(password) < 14 {
		return map[string]interface{}{
			"valid":   false,
			"message": "Password must be at least 14 characters long",
		}
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	// Use the exact same special characters as utils/validator.go
	specialChars := "`~!@#$%^&*()-_=+[]{}|;:,.<>?"

	for _, char := range password {
		switch {
		case isUpper(char):
			hasUpper = true
		case isLower(char):
			hasLower = true
		case isDigit(char):
			hasDigit = true
		case containsRune(specialChars, char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return map[string]interface{}{
			"valid":   false,
			"message": "Password must contain at least one uppercase letter",
		}
	}
	if !hasLower {
		return map[string]interface{}{
			"valid":   false,
			"message": "Password must contain at least one lowercase letter",
		}
	}
	if !hasDigit {
		return map[string]interface{}{
			"valid":   false,
			"message": "Password must contain at least one digit",
		}
	}
	if !hasSpecial {
		return map[string]interface{}{
			"valid":   false,
			"message": "Password must contain at least one special character: `~!@#$%^&*()-_=+[]{}|;:,.<>?",
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Password meets all requirements",
	}
}

// hashPasswordArgon2ID hashes a password using Argon2ID with the same parameters as the server
func hashPasswordArgon2ID(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "Invalid number of arguments"
	}

	password := args[0].String()
	encodedSalt := args[1].String()

	// Decode salt
	saltBytes, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return "Failed to decode salt"
	}

	// Use Argon2ID with same parameters as server: 4 iterations, 128MB, 4 threads
	// For password hashing, we use maximum security parameters
	capability := DeviceMaximum
	hash := deriveKeyWithDeviceCapability([]byte(password), saltBytes, capability)
	return base64.StdEncoding.EncodeToString(hash)
}

// generatePasswordSalt generates a secure salt for password hashing
func generatePasswordSalt(this js.Value, args []js.Value) interface{} {
	salt := make([]byte, saltLength) // 32 bytes
	if _, err := rand.Read(salt); err != nil {
		return "Failed to generate salt"
	}
	return base64.StdEncoding.EncodeToString(salt)
}

// OPAQUE Authentication WebAssembly Functions

// requestDeviceCapabilityPermission returns consent dialog data
func requestDeviceCapabilityPermission(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"title": "🔒 Optimize Security for Your Device",
		"message": `Arkfile can optimize password security based on your device capabilities.

We will check:
• Available memory (for optimal encryption strength)
• CPU cores (for parallel processing)
• Device type (mobile vs desktop optimization)
• Browser capabilities

This information:
✓ Stays on your device
✓ Is never sent to servers
✓ Only determines encryption strength
✓ Can be overridden manually`,
		"options": []interface{}{
			"Allow automatic optimization (recommended)",
			"Choose security level manually",
			"Use maximum security (may be slow on older devices)",
		},
	}
}

// detectDeviceCapabilityWithPermission detects device capability if permission granted
func detectDeviceCapabilityWithPermission(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "manual"
	}

	hasPermission := args[0].Bool()
	if !hasPermission {
		return "manual"
	}

	// In a real implementation, this would use JavaScript APIs to detect:
	// - navigator.deviceMemory
	// - navigator.hardwareConcurrency
	// - navigator.userAgent (mobile detection)
	// - Performance benchmarking

	// For now, return a safe default that works well on most devices
	return "interactive"
}

// opaqueRegisterFlow handles OPAQUE registration (placeholder for now)
func opaqueRegisterFlow(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid number of arguments",
		}
	}

	email := args[0].String()
	_ = args[1].String() // password - unused for now in placeholder
	capability := args[2].String()

	// For now, this is a placeholder that prepares the data for OPAQUE registration
	// The actual OPAQUE protocol implementation would go here
	return map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"email":            email,
			"deviceCapability": capability,
			// In real OPAQUE implementation, this would contain:
			// - Client registration message
			// - Client state for continuation
		},
	}
}

// opaqueLoginFlow handles OPAQUE login (placeholder for now)
func opaqueLoginFlow(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid number of arguments",
		}
	}

	email := args[0].String()
	_ = args[1].String() // password - unused for now in placeholder

	// For now, this is a placeholder that prepares the data for OPAQUE login
	// The actual OPAQUE protocol implementation would go here
	return map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"email": email,
			// In real OPAQUE implementation, this would contain:
			// - Client login message
			// - Client state for continuation
			// - Derived session key
		},
	}
}

// main function to register WASM functions
func main() {
	// File encryption functions
	js.Global().Set("encryptFile", js.FuncOf(encryptFile))
	js.Global().Set("decryptFile", js.FuncOf(decryptFile))
	js.Global().Set("generateSalt", js.FuncOf(generateSalt))
	js.Global().Set("deriveSessionKey", js.FuncOf(deriveSessionKey))
	js.Global().Set("calculateSHA256", js.FuncOf(calculateSHA256))
	js.Global().Set("encryptFileMultiKey", js.FuncOf(encryptFileMultiKey))
	js.Global().Set("decryptFileMultiKey", js.FuncOf(decryptFileMultiKey))

	// Password functions
	js.Global().Set("validatePasswordComplexity", js.FuncOf(validatePasswordComplexity))
	js.Global().Set("hashPasswordArgon2ID", js.FuncOf(hashPasswordArgon2ID))
	js.Global().Set("generatePasswordSalt", js.FuncOf(generatePasswordSalt))

	// OPAQUE authentication functions
	js.Global().Set("requestDeviceCapabilityPermission", js.FuncOf(requestDeviceCapabilityPermission))
	js.Global().Set("detectDeviceCapabilityWithPermission", js.FuncOf(detectDeviceCapabilityWithPermission))
	js.Global().Set("opaqueRegisterFlow", js.FuncOf(opaqueRegisterFlow))
	js.Global().Set("opaqueLoginFlow", js.FuncOf(opaqueLoginFlow))

	// Keep the program running
	select {}
}
