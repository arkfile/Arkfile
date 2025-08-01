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
	"encoding/json"
	"strings"
	"syscall/js" // specifically for WASM build
	"time"

	"github.com/84adam/arkfile/crypto"
)

// OPAQUE Export Key Storage
// This replaces the old Argon2ID-based key derivation system for authenticated operations
var opaqueExportKeys = make(map[string][]byte) // userEmail -> exportKey

// validateOPAQUEExportKey validates that an OPAQUE export key has the correct format
func validateOPAQUEExportKey(exportKey []byte) bool {
	if len(exportKey) != 64 {
		return false
	}

	// Check that key is not all zeros (indicates invalid/missing key)
	allZeros := true
	for _, b := range exportKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return false
	}

	return true
}

// storeOPAQUEExportKey securely stores an OPAQUE export key for a user
func storeOPAQUEExportKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected userEmail, exportKeyB64",
		}
	}

	userEmail := args[0].String()
	exportKeyB64 := args[1].String()

	// Decode the export key
	exportKey, err := base64.StdEncoding.DecodeString(exportKeyB64)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to decode export key: " + err.Error(),
		}
	}

	// Validate the export key
	if !validateOPAQUEExportKey(exportKey) {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid export key format",
		}
	}

	// Store the export key
	opaqueExportKeys[userEmail] = exportKey

	return map[string]interface{}{
		"success": true,
		"message": "OPAQUE export key stored successfully",
	}
}

// deriveAccountFileKey derives a file encryption key from OPAQUE export key for account password
func deriveAccountFileKey(exportKey []byte, userEmail, fileID string) ([]byte, error) {
	return crypto.DeriveAccountFileKey(exportKey, userEmail, fileID)
}

// deriveCustomFileKey derives a file encryption key from OPAQUE export key for custom password
func deriveCustomFileKey(exportKey []byte, fileID, userEmail string) ([]byte, error) {
	return crypto.DeriveOPAQUEFileKey(exportKey, fileID, userEmail)
}

// encryptFileOPAQUE encrypts a file using OPAQUE-derived keys (replaces old Argon2ID approach)
func encryptFileOPAQUE(this js.Value, args []js.Value) interface{} {
	if len(args) != 4 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected fileData, userEmail, keyType, fileID",
		}
	}

	// Extract arguments
	fileDataJS := args[0]
	userEmail := args[1].String()
	keyType := args[2].String() // "account" or "custom"
	fileID := args[3].String()

	// Convert file data from JavaScript Uint8Array to Go []byte
	fileData := make([]byte, fileDataJS.Length())
	js.CopyBytesToGo(fileData, fileDataJS)

	// Get the OPAQUE export key for this user
	exportKey, exists := opaqueExportKeys[userEmail]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No OPAQUE export key found for user",
		}
	}

	// Derive the file encryption key based on key type
	var fileEncKey []byte
	var err error
	var version byte

	if keyType == "account" {
		version = 0x01 // VersionOPAQUEAccount
		fileEncKey, err = deriveAccountFileKey(exportKey, userEmail, fileID)
	} else if keyType == "custom" {
		version = 0x02 // VersionOPAQUECustom
		fileEncKey, err = deriveCustomFileKey(exportKey, fileID, userEmail)
	} else {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid key type: must be 'account' or 'custom'",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive file encryption key: " + err.Error(),
		}
	}

	// Encrypt file data using AES-GCM
	block, err := aes.NewCipher(fileEncKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create cipher: " + err.Error(),
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create GCM: " + err.Error(),
		}
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to generate nonce: " + err.Error(),
		}
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, fileData, nil)

	// Build the result: version + keyType + ciphertext
	var keyTypeByte byte
	if keyType == "account" {
		keyTypeByte = 0x01
	} else {
		keyTypeByte = 0x02
	}

	result := []byte{version, keyTypeByte}
	result = append(result, ciphertext...)

	return map[string]interface{}{
		"success": true,
		"data":    base64.StdEncoding.EncodeToString(result),
	}
}

// decryptFileOPAQUE decrypts a file using OPAQUE-derived keys
func decryptFileOPAQUE(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected encryptedData, userEmail, fileID",
		}
	}

	encryptedDataB64 := args[0].String()
	userEmail := args[1].String()
	fileID := args[2].String()

	// Get the OPAQUE export key for this user
	exportKey, exists := opaqueExportKeys[userEmail]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No OPAQUE export key found for user",
		}
	}

	// Decode the encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to decode encrypted data: " + err.Error(),
		}
	}

	// Check minimum length
	if len(encryptedData) < 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Encrypted data too short",
		}
	}

	// Extract version and key type
	version := encryptedData[0]
	keyType := encryptedData[1]
	ciphertext := encryptedData[2:]

	// Derive the file encryption key based on version and key type
	var fileEncKey []byte

	switch version {
	case 0x01: // VersionOPAQUEAccount
		if keyType != 0x01 {
			return map[string]interface{}{
				"success": false,
				"error":   "Key type mismatch for account version",
			}
		}
		fileEncKey, err = deriveAccountFileKey(exportKey, userEmail, fileID)
	case 0x02: // VersionOPAQUECustom
		if keyType != 0x02 {
			return map[string]interface{}{
				"success": false,
				"error":   "Key type mismatch for custom version",
			}
		}
		fileEncKey, err = deriveCustomFileKey(exportKey, fileID, userEmail)
	default:
		return map[string]interface{}{
			"success": false,
			"error":   "Unsupported encryption version",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive file encryption key: " + err.Error(),
		}
	}

	// Decrypt the data
	block, err := aes.NewCipher(fileEncKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create cipher: " + err.Error(),
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create GCM: " + err.Error(),
		}
	}

	// Check minimum ciphertext length
	if len(ciphertext) < gcm.NonceSize() {
		return map[string]interface{}{
			"success": false,
			"error":   "Ciphertext too short",
		}
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:gcm.NonceSize()]
	encData := ciphertext[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to decrypt: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    base64.StdEncoding.EncodeToString(plaintext),
	}
}

// clearOPAQUEExportKey securely clears the export key for a user
func clearOPAQUEExportKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected userEmail",
		}
	}

	userEmail := args[0].String()

	// Securely zero the export key before deleting
	if exportKey, exists := opaqueExportKeys[userEmail]; exists {
		for i := range exportKey {
			exportKey[i] = 0
		}
		delete(opaqueExportKeys, userEmail)
	}

	return map[string]interface{}{
		"success": true,
		"message": "OPAQUE export key cleared",
	}
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

// generateSalt generates a secure salt
func generateSalt(this js.Value, args []js.Value) interface{} {
	salt := make([]byte, 32) // 32 bytes
	if _, err := rand.Read(salt); err != nil {
		return "Failed to generate salt"
	}
	return base64.StdEncoding.EncodeToString(salt)
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
			"message": "Password must contain at least one special character: `~!@#$%^&*()-_=+[]{}|;:,.<>?`",
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Password meets all requirements",
	}
}

// validatePasswordConfirmation validates that two passwords match
func validatePasswordConfirmation(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid number of arguments",
		}
	}

	password := args[0].String()
	confirmPassword := args[1].String()

	if password == "" && confirmPassword == "" {
		return map[string]interface{}{
			"valid":   false,
			"message": "Please enter confirmation password",
			"status":  "empty",
		}
	}

	if password != confirmPassword {
		return map[string]interface{}{
			"valid":   false,
			"message": "Passwords do not match",
			"status":  "not-matching",
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Passwords match",
		"status":  "matching",
	}
}

// main function to register WASM functions
func main() {
	// OPAQUE-based file encryption functions (NEW)
	js.Global().Set("storeOPAQUEExportKey", js.FuncOf(storeOPAQUEExportKey))
	js.Global().Set("encryptFileOPAQUE", js.FuncOf(encryptFileOPAQUE))
	js.Global().Set("decryptFileOPAQUE", js.FuncOf(decryptFileOPAQUE))
	js.Global().Set("clearOPAQUEExportKey", js.FuncOf(clearOPAQUEExportKey))

	// Phase 1: Chunked upload encryption functions
	js.Global().Set("encryptFileChunkedOPAQUE", js.FuncOf(encryptFileChunkedOPAQUE))
	js.Global().Set("decryptFileChunkedOPAQUE", js.FuncOf(decryptFileChunkedOPAQUE))
	js.Global().Set("createEnvelopeOPAQUE", js.FuncOf(createEnvelopeOPAQUE))
	js.Global().Set("validateChunkFormat", js.FuncOf(validateChunkFormat))

	// Utility functions
	js.Global().Set("generateSalt", js.FuncOf(generateSalt))
	js.Global().Set("calculateSHA256", js.FuncOf(calculateSHA256))

	// Password validation functions
	js.Global().Set("validatePasswordComplexity", js.FuncOf(validatePasswordComplexity))
	js.Global().Set("validatePasswordConfirmation", js.FuncOf(validatePasswordConfirmation))

	// Authentication and security functions
	js.Global().Set("validateTokenStructure", js.FuncOf(validateTokenStructure))
	js.Global().Set("sanitizeAPIResponse", js.FuncOf(sanitizeAPIResponse))

	// Call the registration function from crypto package
	crypto.RegisterAllWASMFunctions()

	// Keep the program running
	select {}
}

// validateTokenStructure validates JWT token structure and basic claims
func validateTokenStructure(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid number of arguments",
		}
	}

	token := args[0].String()
	if token == "" {
		return map[string]interface{}{
			"valid":   false,
			"message": "Token is empty",
		}
	}

	// Basic JWT structure validation (3 parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid JWT structure",
		}
	}

	// Try to decode the payload (middle part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid JWT payload encoding",
		}
	}

	// Basic validation - check if it's valid JSON and has required fields
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return map[string]interface{}{
			"valid":   false,
			"message": "Invalid JWT payload JSON",
		}
	}

	// Check for required claims
	if email, exists := claims["email"]; !exists || email == "" {
		return map[string]interface{}{
			"valid":   false,
			"message": "Missing or empty email claim",
		}
	}

	// Check expiration if present
	if exp, exists := claims["exp"]; exists {
		if expFloat, ok := exp.(float64); ok {
			if time.Now().Unix() > int64(expFloat) {
				return map[string]interface{}{
					"valid":   false,
					"message": "Token has expired",
				}
			}
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Token structure is valid",
		"email":   claims["email"],
	}
}

// sanitizeAPIResponse sanitizes API response data
func sanitizeAPIResponse(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid number of arguments",
		}
	}

	// This would contain logic to sanitize API responses
	// For now, we'll just pass through, but in a real implementation
	// this would validate and sanitize all response data
	return map[string]interface{}{
		"success": true,
		"data":    args[0],
	}
}

// Phase 1: Chunked Upload Functions

// createEnvelopeOPAQUE creates a crypto envelope for chunked files
func createEnvelopeOPAQUE(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected keyType",
		}
	}

	keyType := args[0].String()

	var version, keyTypeByte byte
	switch keyType {
	case "account":
		version = 0x01     // VersionOPAQUEAccount
		keyTypeByte = 0x01 // Account key type
	case "custom":
		version = 0x02     // VersionOPAQUECustom
		keyTypeByte = 0x02 // Custom key type
	default:
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid key type: must be 'account' or 'custom'",
		}
	}

	// Create envelope: [version][keyType]
	envelope := []byte{version, keyTypeByte}

	return map[string]interface{}{
		"success":  true,
		"envelope": base64.StdEncoding.EncodeToString(envelope),
		"version":  int(version),
		"keyType":  int(keyTypeByte),
	}
}

// validateChunkFormat validates that a chunk has the correct format
func validateChunkFormat(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid": false,
			"error": "Invalid arguments: expected chunkData",
		}
	}

	chunkDataB64 := args[0].String()
	chunkData, err := base64.StdEncoding.DecodeString(chunkDataB64)
	if err != nil {
		return map[string]interface{}{
			"valid": false,
			"error": "Failed to decode chunk data: " + err.Error(),
		}
	}

	// Validate chunk format: [nonce:12][encrypted_data][tag:16]
	// Minimum size: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
	if len(chunkData) < 29 {
		return map[string]interface{}{
			"valid": false,
			"error": "Chunk too short: minimum 29 bytes required",
		}
	}

	// Maximum size: 16MB + 28 bytes overhead
	maxSize := 16*1024*1024 + 28
	if len(chunkData) > maxSize {
		return map[string]interface{}{
			"valid": false,
			"error": "Chunk too large: maximum " + string(rune(maxSize)) + " bytes allowed",
		}
	}

	return map[string]interface{}{
		"valid":     true,
		"nonceSize": 12,
		"tagSize":   16,
		"dataSize":  len(chunkData) - 28,
	}
}

// encryptFileChunkedOPAQUE encrypts a file for chunked upload
func encryptFileChunkedOPAQUE(this js.Value, args []js.Value) interface{} {
	if len(args) != 5 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected fileData, userEmail, keyType, fileID, chunkSize",
		}
	}

	// Extract arguments
	fileDataJS := args[0]
	userEmail := args[1].String()
	keyType := args[2].String()
	fileID := args[3].String()
	chunkSize := args[4].Int()

	// Default chunk size to 16MB if not specified or invalid
	if chunkSize <= 0 || chunkSize > 16*1024*1024 {
		chunkSize = 16 * 1024 * 1024
	}

	// Convert file data from JavaScript Uint8Array to Go []byte
	fileData := make([]byte, fileDataJS.Length())
	js.CopyBytesToGo(fileData, fileDataJS)

	// Get the OPAQUE export key for this user
	exportKey, exists := opaqueExportKeys[userEmail]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No OPAQUE export key found for user",
		}
	}

	// Derive the file encryption key based on key type
	var fileEncKey []byte
	var err error
	var version, keyTypeByte byte

	if keyType == "account" {
		version = 0x01
		keyTypeByte = 0x01
		fileEncKey, err = deriveAccountFileKey(exportKey, userEmail, fileID)
	} else if keyType == "custom" {
		version = 0x02
		keyTypeByte = 0x02
		fileEncKey, err = deriveCustomFileKey(exportKey, fileID, userEmail)
	} else {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid key type: must be 'account' or 'custom'",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive file encryption key: " + err.Error(),
		}
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(fileEncKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create cipher: " + err.Error(),
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create GCM: " + err.Error(),
		}
	}

	// Create envelope
	envelope := []byte{version, keyTypeByte}

	// Split file into chunks and encrypt each chunk
	var chunks []map[string]interface{}
	totalChunks := (len(fileData) + chunkSize - 1) / chunkSize

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(fileData) {
			end = len(fileData)
		}

		chunkData := fileData[start:end]

		// Generate unique nonce for this chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return map[string]interface{}{
				"success": false,
				"error":   "Failed to generate nonce for chunk " + string(rune(i)) + ": " + err.Error(),
			}
		}

		// Encrypt chunk: AES-GCM(chunk_data, FEK, nonce)
		encryptedChunk := gcm.Seal(nonce, nonce, chunkData, nil)

		// Calculate SHA-256 hash of encrypted chunk
		hash := sha256.Sum256(encryptedChunk)

		chunks = append(chunks, map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(encryptedChunk),
			"hash": hex.EncodeToString(hash[:]),
			"size": len(encryptedChunk),
		})
	}

	return map[string]interface{}{
		"success":     true,
		"envelope":    base64.StdEncoding.EncodeToString(envelope),
		"chunks":      chunks,
		"totalChunks": totalChunks,
	}
}

// decryptFileChunkedOPAQUE decrypts a chunked file with envelope processing
func decryptFileChunkedOPAQUE(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected encryptedData, userEmail, fileID",
		}
	}

	encryptedDataB64 := args[0].String()
	userEmail := args[1].String()
	fileID := args[2].String()

	// Get the OPAQUE export key for this user
	exportKey, exists := opaqueExportKeys[userEmail]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No OPAQUE export key found for user",
		}
	}

	// Decode the encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to decode encrypted data: " + err.Error(),
		}
	}

	// Check minimum length for envelope
	if len(encryptedData) < 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Encrypted data too short: missing envelope",
		}
	}

	// Read envelope: [version][keyType] from first 2 bytes
	version := encryptedData[0]
	keyType := encryptedData[1]
	chunksData := encryptedData[2:]

	// Derive the file encryption key based on envelope
	var fileEncKey []byte

	switch version {
	case 0x01: // VersionOPAQUEAccount
		if keyType != 0x01 {
			return map[string]interface{}{
				"success": false,
				"error":   "Key type mismatch for account version",
			}
		}
		fileEncKey, err = deriveAccountFileKey(exportKey, userEmail, fileID)
	case 0x02: // VersionOPAQUECustom
		if keyType != 0x02 {
			return map[string]interface{}{
				"success": false,
				"error":   "Key type mismatch for custom version",
			}
		}
		fileEncKey, err = deriveCustomFileKey(exportKey, fileID, userEmail)
	default:
		return map[string]interface{}{
			"success": false,
			"error":   "Unsupported encryption version",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive file encryption key: " + err.Error(),
		}
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(fileEncKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create cipher: " + err.Error(),
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create GCM: " + err.Error(),
		}
	}

	// Process remaining data as chunks: [nonce][encrypted_data][tag]
	var plaintext []byte
	offset := 0

	for offset < len(chunksData) {
		// Check if we have enough data for a chunk (minimum: nonce + tag)
		if offset+gcm.NonceSize()+16 > len(chunksData) {
			return map[string]interface{}{
				"success": false,
				"error":   "Incomplete chunk data at offset " + string(rune(offset)),
			}
		}

		// Find the end of this chunk by looking for the next valid nonce position
		// For now, we'll assume chunks are properly formatted and parse sequentially

		// Read nonce
		nonce := chunksData[offset : offset+gcm.NonceSize()]
		offset += gcm.NonceSize()

		// Find the tag at the end of encrypted data
		// We need to determine chunk size, but for now assume remaining data
		remainingData := chunksData[offset:]

		// The tag is the last 16 bytes of the remaining data for this chunk
		// We need a better way to determine chunk boundaries
		// For now, try to decrypt what we can
		if len(remainingData) < 16 {
			return map[string]interface{}{
				"success": false,
				"error":   "Insufficient data for authentication tag",
			}
		}

		// Try different chunk sizes to find valid decryption
		// Start with maximum possible size and work down
		maxPossibleSize := len(remainingData)

		var decryptedChunk []byte
		var chunkProcessed bool

		// Try to decrypt starting from the maximum size down to minimum
		for chunkSize := maxPossibleSize; chunkSize >= 16; chunkSize-- {
			if chunkSize > len(remainingData) {
				continue
			}

			testChunk := remainingData[:chunkSize]
			testDecrypted, err := gcm.Open(nil, nonce, testChunk, nil)
			if err == nil {
				// Successfully decrypted with this chunk size
				decryptedChunk = testDecrypted
				offset += chunkSize
				chunkProcessed = true
				break
			}
		}

		if !chunkProcessed {
			return map[string]interface{}{
				"success": false,
				"error":   "Failed to decrypt any chunk at offset " + string(rune(offset-gcm.NonceSize())),
			}
		}

		plaintext = append(plaintext, decryptedChunk...)
	}

	return map[string]interface{}{
		"success": true,
		"data":    base64.StdEncoding.EncodeToString(plaintext),
	}
}
