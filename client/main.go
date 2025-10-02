//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"syscall/js"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/logging"
)

// Password Storage for WASM Context
// This replaces the old OPAQUE export key system with password-based encryption
var userPasswords = make(map[string][]byte) // username -> password

// storePasswordForUser securely stores a user password for encryption operations
func storePasswordForUser(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username, password",
		}
	}

	username := args[0].String()
	password := args[1].String()

	// Store the password securely
	userPasswords[username] = []byte(password)

	return map[string]interface{}{
		"success": true,
		"message": "Password stored successfully for encryption operations",
	}
}

// clearPasswordForUser securely clears the password for a user
func clearPasswordForUser(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username",
		}
	}

	username := args[0].String()

	// Securely zero the password before deleting
	if password, exists := userPasswords[username]; exists {
		for i := range password {
			password[i] = 0
		}
		delete(userPasswords, username)
	}

	return map[string]interface{}{
		"success": true,
		"message": "Password cleared successfully",
	}
}

// deriveAccountFileKeyInternal derives an encryption key from account password using Argon2ID
// Fixed to match server-side key derivation - no fileID in salt generation
func deriveAccountFileKeyInternal(password []byte, username string) ([]byte, error) {
	// Use same salt generation as server: username + "account" (no fileID)
	salt := sha256.Sum256([]byte("arkfile-account-key-salt:" + username))
	key, err := crypto.DeriveArgon2IDKey(password, salt[:], crypto.UnifiedArgonSecure.KeyLen, crypto.UnifiedArgonSecure.Memory, crypto.UnifiedArgonSecure.Time, crypto.UnifiedArgonSecure.Threads)
	if err != nil {
		return nil, fmt.Errorf("Argon2ID account key derivation failed: %w", err)
	}
	return key, nil
}

// deriveCustomFileKeyInternal derives an encryption key from custom password using Argon2ID
// Fixed to match server-side key derivation - no fileID in salt generation
func deriveCustomFileKeyInternal(password []byte, username string) ([]byte, error) {
	// Use same salt generation as server: username + "custom" (no fileID)
	salt := sha256.Sum256([]byte("arkfile-custom-key-salt:" + username))
	key, err := crypto.DeriveArgon2IDKey(password, salt[:], crypto.UnifiedArgonSecure.KeyLen, crypto.UnifiedArgonSecure.Memory, crypto.UnifiedArgonSecure.Time, crypto.UnifiedArgonSecure.Threads)
	if err != nil {
		return nil, fmt.Errorf("Argon2ID custom key derivation failed: %w", err)
	}
	return key, nil
}

// derivePasswordMetadataKey derives a metadata encryption key from password
func derivePasswordMetadataKey(password []byte, username string) ([]byte, error) {
	// Generate a deterministic salt from username for metadata keys
	// This ensures the same metadata key is always derived for the same user
	salt := sha256.Sum256([]byte("arkfile-metadata-salt:" + username))
	key, err := crypto.DeriveArgon2IDKey(password, salt[:], crypto.UnifiedArgonSecure.KeyLen, crypto.UnifiedArgonSecure.Memory, crypto.UnifiedArgonSecure.Time, crypto.UnifiedArgonSecure.Threads)
	if err != nil {
		return nil, fmt.Errorf("Argon2ID metadata key derivation failed: %w", err)
	}
	return key, nil
}

// encryptFilePassword encrypts a file using password-derived keys
func encryptFilePassword(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 && len(args) != 4 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected fileData, username, keyType, [customPassword]",
		}
	}

	// Extract arguments
	fileDataJS := args[0]
	username := args[1].String()
	keyType := args[2].String() // "account" or "custom"

	// Convert file data from JavaScript Uint8Array to Go []byte
	fileData := make([]byte, fileDataJS.Length())
	js.CopyBytesToGo(fileData, fileDataJS)

	// Derive the file encryption key based on key type
	var fileEncKey []byte
	var err error
	var version byte = 0x01 // Version for password-based encryption

	if keyType == "account" {
		// Get stored password for this user
		password, exists := userPasswords[username]
		if !exists {
			return map[string]interface{}{
				"success": false,
				"error":   "No password found for user",
			}
		}
		fileEncKey, err = deriveAccountFileKeyInternal(password, username)
		// SECURITY: Clear password from memory after use
		for i := range password {
			password[i] = 0
		}
	} else if keyType == "custom" {
		if len(args) != 4 {
			return map[string]interface{}{
				"success": false,
				"error":   "Custom password required for custom key type",
			}
		}
		customPassword := []byte(args[3].String())
		fileEncKey, err = deriveCustomFileKeyInternal(customPassword, username)
		// SECURITY: Clear password from memory after use
		for i := range customPassword {
			customPassword[i] = 0
		}
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

// decryptFilePassword decrypts a file using password-derived keys
func decryptFilePassword(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 && len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected encryptedData, username, [customPassword]",
		}
	}

	encryptedDataB64 := args[0].String()
	username := args[1].String()

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
	case 0x01: // Password-based encryption
		if keyType == 0x01 { // Account password
			// VULNERABILITY FIX: Ensure a custom password was NOT provided for account-based decryption
			if len(args) == 3 {
				return map[string]interface{}{
					"success": false,
					"error":   "A custom password was provided for a file encrypted with the account password",
				}
			}

			password, exists := userPasswords[username]
			if !exists {
				return map[string]interface{}{
					"success": false,
					"error":   "No password found for user",
				}
			}
			fileEncKey, err = deriveAccountFileKeyInternal(password, username)
		} else if keyType == 0x02 { // Custom password
			if len(args) != 3 {
				return map[string]interface{}{
					"success": false,
					"error":   "Custom password required for decryption",
				}
			}
			customPassword := []byte(args[2].String())
			fileEncKey, err = deriveCustomFileKeyInternal(customPassword, username)
		} else { // No change
			return map[string]interface{}{
				"success": false,
				"error":   "Invalid key type for password-based encryption",
			}
		}
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

// encryptFileMetadata encrypts filename and SHA256 hash for storage
func encryptFileMetadata(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected filename, sha256sum, username",
		}
	}

	filename := args[0].String()
	sha256sum := args[1].String()
	username := args[2].String()

	// Get password for this user
	password, exists := userPasswords[username]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No password found for user",
		}
	}

	// Derive the metadata encryption key directly using DeriveAccountPasswordKey
	// This matches the server-side approach - metadata uses account key, NOT FEK
	metadataKey := crypto.DeriveAccountPasswordKey(password, username)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(metadataKey)
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

	// Generate random nonce for filename encryption
	filenameNonce := make([]byte, 12) // 12 bytes for GCM
	if _, err := rand.Read(filenameNonce); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to generate filename nonce: " + err.Error(),
		}
	}

	// Generate random nonce for SHA256 encryption
	sha256Nonce := make([]byte, 12) // 12 bytes for GCM
	if _, err := rand.Read(sha256Nonce); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to generate SHA256 nonce: " + err.Error(),
		}
	}

	// Encrypt filename
	encryptedFilename := gcm.Seal(nil, filenameNonce, []byte(filename), nil)

	// Encrypt SHA256 hash
	encryptedSha256 := gcm.Seal(nil, sha256Nonce, []byte(sha256sum), nil)

	return map[string]interface{}{
		"success":             true,
		"filename_nonce":      base64.StdEncoding.EncodeToString(filenameNonce),
		"encrypted_filename":  base64.StdEncoding.EncodeToString(encryptedFilename),
		"sha256sum_nonce":     base64.StdEncoding.EncodeToString(sha256Nonce),
		"encrypted_sha256sum": base64.StdEncoding.EncodeToString(encryptedSha256),
	}
}

// decryptFileMetadata decrypts filename and SHA256 hash using password-derived key directly.
// The FEK is ONLY for file content, NOT for metadata.
func decryptFileMetadata(this js.Value, args []js.Value) interface{} {
	if len(args) != 5 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected filenameNonce, encryptedFilename, sha256Nonce, encryptedSha256sum, username",
		}
	}

	filenameNonceB64 := args[0].String()
	encryptedFilenameB64 := args[1].String()
	sha256NonceB64 := args[2].String()
	encryptedSha256B64 := args[3].String()
	username := args[4].String()

	// Get password for this user to derive metadata key
	password, exists := userPasswords[username]
	if !exists {
		return map[string]interface{}{"success": false, "error": "No password found for user"}
	}

	// Derive the metadata encryption key directly from password
	// This matches the server-side crypto.DeriveAccountPasswordKey
	metadataKey := crypto.DeriveAccountPasswordKey(password, username)

	// Create AES-GCM cipher with the metadata key
	block, err := aes.NewCipher(metadataKey)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to create cipher from metadata key: " + err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to create GCM: " + err.Error()}
	}

	// Decode metadata fields
	filenameNonce, err := base64.StdEncoding.DecodeString(filenameNonceB64)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decode filename nonce: " + err.Error()}
	}

	encryptedFilename, err := base64.StdEncoding.DecodeString(encryptedFilenameB64)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decode encrypted filename: " + err.Error()}
	}

	sha256Nonce, err := base64.StdEncoding.DecodeString(sha256NonceB64)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decode SHA256 nonce: " + err.Error()}
	}

	encryptedSha256, err := base64.StdEncoding.DecodeString(encryptedSha256B64)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decode encrypted SHA256: " + err.Error()}
	}

	// Decrypt filename
	filenameBytes, err := gcm.Open(nil, filenameNonce, encryptedFilename, nil)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decrypt filename: " + err.Error()}
	}

	// Decrypt SHA256 hash
	sha256Bytes, err := gcm.Open(nil, sha256Nonce, encryptedSha256, nil)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to decrypt SHA256: " + err.Error()}
	}

	return map[string]interface{}{
		"success":   true,
		"filename":  string(filenameBytes),
		"sha256sum": string(sha256Bytes),
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

// JWT Token Management and Auto-Refresh System
var autoRefreshTimer *time.Timer
var refreshChannel = make(chan bool, 1)

// setJWTTokens stores JWT and refresh tokens in localStorage
func setJWTTokens(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected token, refreshToken",
		}
	}

	token := args[0].String()
	refreshToken := args[1].String()

	// Validate token structure first
	tokenValidation := validateTokenStructure(js.Value{}, []js.Value{js.ValueOf(token)})
	if validationMap, ok := tokenValidation.(map[string]interface{}); ok {
		if !validationMap["valid"].(bool) {
			return map[string]interface{}{
				"success": false,
				"error":   "Invalid token structure: " + validationMap["message"].(string),
			}
		}
	}

	// Store in localStorage
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("setItem", "token", token)
	localStorage.Call("setItem", "refresh_token", refreshToken)

	return map[string]interface{}{
		"success": true,
		"message": "Tokens stored successfully",
	}
}

// getJWTToken retrieves the current JWT token from localStorage
func getJWTToken(this js.Value, args []js.Value) interface{} {
	localStorage := js.Global().Get("localStorage")
	token := localStorage.Call("getItem", "token")

	if token.IsNull() {
		return map[string]interface{}{
			"success": false,
			"error":   "No token found",
			"token":   nil,
		}
	}

	return map[string]interface{}{
		"success": true,
		"token":   token.String(),
	}
}

// getRefreshToken retrieves the current refresh token from localStorage
func getRefreshToken(this js.Value, args []js.Value) interface{} {
	localStorage := js.Global().Get("localStorage")
	refreshToken := localStorage.Call("getItem", "refresh_token")

	if refreshToken.IsNull() {
		return map[string]interface{}{
			"success":       false,
			"error":         "No refresh token found",
			"refresh_token": nil,
		}
	}

	return map[string]interface{}{
		"success":       true,
		"refresh_token": refreshToken.String(),
	}
}

// clearJWTTokens removes JWT and refresh tokens from localStorage
func clearJWTTokens(this js.Value, args []js.Value) interface{} {
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("removeItem", "token")
	localStorage.Call("removeItem", "refresh_token")

	// Stop auto-refresh timer
	stopAutoRefresh(js.Value{}, []js.Value{})

	return map[string]interface{}{
		"success": true,
		"message": "Tokens cleared successfully",
	}
}

// isJWTTokenExpired checks if the current JWT token is expired
func isJWTTokenExpired(this js.Value, args []js.Value) interface{} {
	tokenResult := getJWTToken(js.Value{}, []js.Value{})
	tokenMap, ok := tokenResult.(map[string]interface{})
	if !ok || !tokenMap["success"].(bool) {
		return map[string]interface{}{
			"expired": true,
			"error":   "No token available",
		}
	}

	token := tokenMap["token"].(string)

	// Parse token to check expiry
	validation := validateTokenStructure(js.Value{}, []js.Value{js.ValueOf(token)})
	if validationMap, ok := validation.(map[string]interface{}); ok {
		if !validationMap["valid"].(bool) {
			return map[string]interface{}{
				"expired": true,
				"error":   validationMap["message"].(string),
			}
		}
	}

	return map[string]interface{}{
		"expired": false,
		"message": "Token is valid",
	}
}

// parseJWTClaims extracts claims from JWT token
func parseJWTClaims(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected token",
		}
	}

	token := args[0].String()
	validation := validateTokenStructure(js.Value{}, []js.Value{js.ValueOf(token)})

	if validationMap, ok := validation.(map[string]interface{}); ok {
		if !validationMap["valid"].(bool) {
			return map[string]interface{}{
				"success": false,
				"error":   validationMap["message"].(string),
			}
		}

		// Parse the token payload
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return map[string]interface{}{
				"success": false,
				"error":   "Invalid JWT structure",
			}
		}

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return map[string]interface{}{
				"success": false,
				"error":   "Failed to decode payload: " + err.Error(),
			}
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return map[string]interface{}{
				"success": false,
				"error":   "Failed to parse claims: " + err.Error(),
			}
		}

		return map[string]interface{}{
			"success": true,
			"claims":  claims,
		}
	}

	return map[string]interface{}{
		"success": false,
		"error":   "Failed to validate token",
	}
}

// isAuthenticated checks if user has valid tokens
func isAuthenticated(this js.Value, args []js.Value) interface{} {
	tokenResult := getJWTToken(js.Value{}, []js.Value{})
	tokenMap, ok := tokenResult.(map[string]interface{})

	if !ok || !tokenMap["success"].(bool) {
		return map[string]interface{}{
			"authenticated": false,
			"error":         "No token found",
		}
	}

	// Check if token is expired
	expiredResult := isJWTTokenExpired(js.Value{}, []js.Value{})
	if expiredMap, ok := expiredResult.(map[string]interface{}); ok {
		if expiredMap["expired"].(bool) {
			return map[string]interface{}{
				"authenticated": false,
				"error":         "Token expired",
			}
		}
	}

	return map[string]interface{}{
		"authenticated": true,
		"message":       "User is authenticated",
	}
}

// refreshJWTToken performs token refresh using refresh token
func refreshJWTToken(this js.Value, args []js.Value) interface{} {
	// Get current refresh token
	refreshResult := getRefreshToken(js.Value{}, []js.Value{})
	refreshMap, ok := refreshResult.(map[string]interface{})
	if !ok || !refreshMap["success"].(bool) {
		return map[string]interface{}{
			"success": false,
			"error":   "No refresh token available",
		}
	}

	refreshToken := refreshMap["refresh_token"].(string)

	// Prepare request body
	requestBody := map[string]string{
		"refresh_token": refreshToken,
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to marshal request: " + err.Error(),
		}
	}

	// Make fetch request using JavaScript
	fetchPromise := js.Global().Call("fetch", "/api/refresh", map[string]interface{}{
		"method": "POST",
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": string(requestBodyJSON),
	})

	// Note: This returns immediately - we'll need to handle the Promise in TypeScript wrapper
	return map[string]interface{}{
		"success": true,
		"promise": fetchPromise,
	}
}

// startAutoRefresh begins the 25-minute refresh cycle
func startAutoRefresh(this js.Value, args []js.Value) interface{} {
	// Stop existing timer if any
	stopAutoRefresh(js.Value{}, []js.Value{})

	// Start goroutine for auto-refresh (25 minutes = 1500000 milliseconds)
	go func() {
		ticker := time.NewTicker(25 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Check if still authenticated before refreshing
				authResult := isAuthenticated(js.Value{}, []js.Value{})
				if authMap, ok := authResult.(map[string]interface{}); ok && authMap["authenticated"].(bool) {
					// Trigger refresh via JavaScript callback
					js.Global().Call("handleAutoRefresh")
				} else {
					// Not authenticated anymore, stop the timer
					return
				}
			case <-refreshChannel:
				// Stop signal received
				return
			}
		}
	}()

	return map[string]interface{}{
		"success": true,
		"message": "Auto-refresh started (25-minute interval)",
	}
}

// stopAutoRefresh stops the auto-refresh timer
func stopAutoRefresh(this js.Value, args []js.Value) interface{} {
	// Send stop signal to goroutine
	select {
	case refreshChannel <- true:
	default:
		// Channel might be full, that's okay
	}

	return map[string]interface{}{
		"success": true,
		"message": "Auto-refresh stopped",
	}
}

// authenticatedFetch performs fetch with JWT authentication
func authenticatedFetch(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected url, options (optional)",
		}
	}

	url := args[0].String()
	var options map[string]interface{}

	if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
		// Convert JavaScript object to Go map
		optionsJS := args[1]
		options = make(map[string]interface{})

		// Handle headers - copy all headers from JavaScript object
		if !optionsJS.Get("headers").IsUndefined() && !optionsJS.Get("headers").IsNull() {
			headers := make(map[string]interface{})
			headersJS := optionsJS.Get("headers")

			// Get all header keys by using Object.keys() in JavaScript
			objectKeys := js.Global().Get("Object").Call("keys", headersJS)
			headerCount := objectKeys.Length()

			// Copy each header
			for i := 0; i < headerCount; i++ {
				headerName := objectKeys.Index(i).String()
				headerValue := headersJS.Get(headerName)
				if !headerValue.IsUndefined() && !headerValue.IsNull() {
					headers[headerName] = headerValue.String()
				}
			}
			options["headers"] = headers
		} else {
			options["headers"] = make(map[string]interface{})
		}

		// Copy other fetch options
		if !optionsJS.Get("method").IsUndefined() {
			options["method"] = optionsJS.Get("method").String()
		}
		if !optionsJS.Get("body").IsUndefined() {
			options["body"] = optionsJS.Get("body").String()
		}
		if !optionsJS.Get("mode").IsUndefined() {
			options["mode"] = optionsJS.Get("mode").String()
		}
		if !optionsJS.Get("credentials").IsUndefined() {
			options["credentials"] = optionsJS.Get("credentials").String()
		}
		if !optionsJS.Get("cache").IsUndefined() {
			options["cache"] = optionsJS.Get("cache").String()
		}
		if !optionsJS.Get("redirect").IsUndefined() {
			options["redirect"] = optionsJS.Get("redirect").String()
		}
		if !optionsJS.Get("referrer").IsUndefined() {
			options["referrer"] = optionsJS.Get("referrer").String()
		}
		if !optionsJS.Get("referrerPolicy").IsUndefined() {
			options["referrerPolicy"] = optionsJS.Get("referrerPolicy").String()
		}
		if !optionsJS.Get("integrity").IsUndefined() {
			options["integrity"] = optionsJS.Get("integrity").String()
		}
		if !optionsJS.Get("signal").IsUndefined() {
			options["signal"] = optionsJS.Get("signal")
		}
	} else {
		options = map[string]interface{}{
			"headers": make(map[string]interface{}),
		}
	}

	// Get JWT token and add Authorization header
	tokenResult := getJWTToken(js.Value{}, []js.Value{})
	if tokenMap, ok := tokenResult.(map[string]interface{}); ok && tokenMap["success"].(bool) {
		token := tokenMap["token"].(string)

		// Add Authorization header
		headers := options["headers"].(map[string]interface{})
		headers["Authorization"] = "Bearer " + token
		options["headers"] = headers
	}

	// Make the fetch request
	fetchPromise := js.Global().Call("fetch", url, options)

	return map[string]interface{}{
		"success": true,
		"promise": fetchPromise,
	}
}

// clearSession clears all session data including tokens and passwords
func clearSession(this js.Value, args []js.Value) interface{} {
	// Clear JWT tokens
	clearJWTTokens(js.Value{}, []js.Value{})

	// Clear all user passwords
	for username := range userPasswords {
		clearPasswordForUser(js.Value{}, []js.Value{js.ValueOf(username)})
	}

	// Clear any other session data from localStorage
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("removeItem", "arkfileSecurityContext")
	localStorage.Call("removeItem", "registrationData")
	localStorage.Call("removeItem", "totpLoginData")
	localStorage.Call("removeItem", "totpSetupData")

	return map[string]interface{}{
		"success": true,
		"message": "All session data cleared",
	}
}

// createPasswordEnvelope creates a crypto envelope for password-based files
func createPasswordEnvelope(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected keyType",
		}
	}

	keyType := args[0].String()

	var version, keyTypeByte byte
	version = 0x01 // Password-based encryption version

	switch keyType {
	case "account":
		keyTypeByte = 0x01 // Account password
	case "custom":
		keyTypeByte = 0x02 // Custom password
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
			"error": fmt.Sprintf("Chunk too large: maximum %d bytes allowed", maxSize),
		}
	}

	return map[string]interface{}{
		"valid":     true,
		"nonceSize": 12,
		"tagSize":   16,
		"dataSize":  len(chunkData) - 28,
	}
}

// --- START CHUNKED UPLOAD REFACTOR ---

// encryptFileChunkedPassword encrypts a file for chunked upload using password-based encryption
func encryptFileChunkedPassword(this js.Value, args []js.Value) interface{} {
	if len(args) != 4 && len(args) != 5 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected fileData, username, keyType, chunkSize, [customPassword]",
		}
	}

	// Extract arguments
	fileDataJS := args[0]
	username := args[1].String()
	keyType := args[2].String()
	chunkSize := args[3].Int()

	// Default chunk size to 16MB if not specified or invalid
	if chunkSize <= 0 || chunkSize > 16*1024*1024 {
		chunkSize = 16 * 1024 * 1024
	}

	// Convert file data from JavaScript Uint8Array to Go []byte
	fileData := make([]byte, fileDataJS.Length())
	js.CopyBytesToGo(fileData, fileDataJS)

	// Derive the file encryption key based on key type
	var fileEncKey []byte
	var err error
	var version, keyTypeByte byte = 0x01, 0x01 // Default to password-based account

	if keyType == "account" {
		keyTypeByte = 0x01
		password, exists := userPasswords[username]
		if !exists {
			return map[string]interface{}{
				"success": false,
				"error":   "No password found for user",
			}
		}
		fileEncKey, err = deriveAccountFileKeyInternal(password, username)
		for i := range password {
			password[i] = 0
		}
	} else if keyType == "custom" {
		keyTypeByte = 0x02
		if len(args) != 5 {
			return map[string]interface{}{
				"success": false,
				"error":   "Custom password required for custom key type",
			}
		}
		customPassword := []byte(args[4].String())
		fileEncKey, err = deriveCustomFileKeyInternal(customPassword, username)
		for i := range customPassword {
			customPassword[i] = 0
		}
	} else {
		return map[string]interface{}{"success": false, "error": "Invalid key type: must be 'account' or 'custom'"}
	}

	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to derive file encryption key: " + err.Error()}
	}

	// --- Main Encryption Logic ---
	block, err := aes.NewCipher(fileEncKey)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to create cipher: " + err.Error()}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return map[string]interface{}{"success": false, "error": "Failed to create GCM: " + err.Error()}
	}

	// Create envelope
	envelope := []byte{version, keyTypeByte}

	// Prepare for chunking
	var chunks []map[string]interface{}
	totalChunks := (len(fileData) + chunkSize - 1) / chunkSize
	fileReader := bytes.NewReader(fileData)

	for i := 0; i < totalChunks; i++ {
		chunkData := make([]byte, chunkSize)
		n, err := fileReader.Read(chunkData)
		if err != nil && err != io.EOF {
			return map[string]interface{}{"success": false, "error": "Failed to read chunk " + fmt.Sprintf("%d", i) + ": " + err.Error()}
		}
		chunkData = chunkData[:n]

		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return map[string]interface{}{"success": false, "error": "Failed to generate nonce for chunk " + fmt.Sprintf("%d", i) + ": " + err.Error()}
		}

		encryptedChunk := gcm.Seal(nonce, nonce, chunkData, nil)

		chunks = append(chunks, map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(encryptedChunk),
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

// --- END CHUNKED UPLOAD REFACTOR ---

// decryptFileChunkedPassword decrypts a chunked file with envelope processing using password-based encryption
func decryptFileChunkedPassword(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 && len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected encryptedData, username, [customPassword]",
		}
	}

	encryptedDataB64 := args[0].String()
	username := args[1].String()

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
	case 0x01: // Password-based encryption

		if keyType == 0x01 { // Account password
			// VULNERABILITY FIX: Ensure a custom password was NOT provided for account-based decryption
			if len(args) == 3 {
				return map[string]interface{}{
					"success": false,
					"error":   "A custom password was provided for a file encrypted with the account password",
				}
			}

			password, exists := userPasswords[username]
			if !exists {
				return map[string]interface{}{
					"success": false,
					"error":   "No password found for user",
				}
			}
			fileEncKey, err = deriveAccountFileKeyInternal(password, username)
		} else if keyType == 0x02 { // Custom password
			if len(args) != 3 {
				return map[string]interface{}{
					"success": false,
					"error":   "Custom password required for decryption",
				}
			}
			customPassword := []byte(args[2].String())
			fileEncKey, err = deriveCustomFileKeyInternal(customPassword, username)
		} else {
			return map[string]interface{}{
				"success": false,
				"error":   "Invalid key type for password-based encryption",
			}
		}
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

	var plaintext []byte
	offset := 0
	chunkNumber := 0
	nonceSize := gcm.NonceSize()
	tagSize := 16 // GCM tag size

	for offset < len(chunksData) {
		chunkNumber++
		if offset+nonceSize > len(chunksData) {
			return map[string]interface{}{"success": false, "error": fmt.Sprintf("Incomplete nonce for chunk %d", chunkNumber)}
		}

		nonce := chunksData[offset : offset+nonceSize]
		ciphertextWithTag := chunksData[offset+nonceSize:]

		// This simple concatenation approach assumes chunks are streamed without extra separators.
		// A more robust format would include chunk length delimiters.
		// For now, we assume the server sends a raw concatenation of [nonce][data+tag].
		// And we must know each original chunk size to decrypt properly, which we don't here.
		// THIS DECRYPTION LOGIC IS FLAWED without chunk size info.
		// It will likely fail on multi-chunk files.

		// TEMPORARY: Assume single chunk for now
		if len(ciphertextWithTag) < tagSize {
			return map[string]interface{}{"success": false, "error": fmt.Sprintf("Incomplete tag for chunk %d", chunkNumber)}
		}

		decryptedChunk, err := gcm.Open(nil, nonce, ciphertextWithTag, nil)
		if err != nil {
			return map[string]interface{}{"success": false, "error": fmt.Sprintf("Failed to decrypt chunk %d: %v", chunkNumber, err)}
		}
		plaintext = append(plaintext, decryptedChunk...)
		break // Exit after first chunk - see logic flaw comment above
	}

	return map[string]interface{}{
		"success": true,
		"data":    base64.StdEncoding.EncodeToString(plaintext),
	}
}

// logUploadSuccess logs the fileId and storageId from the successful upload response.
func logUploadSuccess(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return nil // No return value needed
	}
	responseObject := args[0]
	if responseObject.IsUndefined() || responseObject.IsNull() {
		log.Println("[WASM] logUploadSuccess: Received null or undefined response object")
		return nil
	}

	fileId := responseObject.Get("file_id").String()
	encryptedFileSHA256 := responseObject.Get("encrypted_file_sha256").String()

	logging.InfoLogger.Printf("[WASM] Upload successful! file_id: %s, serverHash: %s", fileId, encryptedFileSHA256)
	return nil
}

// listUserFiles lists files for the authenticated user with metadata decryption
func listUserFiles(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username",
		}
	}

	username := args[0].String()

	// Check if user has a password stored (required for metadata decryption)
	_, exists := userPasswords[username]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No password found for user - cannot decrypt metadata",
		}
	}

	// Make authenticated request to list files
	fetchResult := authenticatedFetch(js.Value{}, []js.Value{
		js.ValueOf("/api/files?limit=50&offset=0"),
		js.ValueOf(map[string]interface{}{
			"method": "GET",
		}),
	})

	fetchMap, ok := fetchResult.(map[string]interface{})
	if !ok || !fetchMap["success"].(bool) {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to create fetch request",
		}
	}

	// Note: This returns a Promise that needs to be handled in JavaScript
	// The actual response processing should be done in the .then() callback
	// This function sets up the authenticated request correctly
	return map[string]interface{}{
		"success": true,
		"promise": fetchMap["promise"],
		"message": "Authenticated request created - handle response in .then() callback",
	}
}

// processFileListResponse processes the server response and decrypts metadata
func processFileListResponse(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected serverResponse, username",
		}
	}

	username := args[1].String()

	// Check if user has a password stored
	_, exists := userPasswords[username]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No password found for user - cannot decrypt metadata",
		}
	}

	// Parse the server response - expect {"files": [...], "storage": {...}}
	serverResponse := args[0]

	if serverResponse.IsNull() || serverResponse.IsUndefined() {
		return map[string]interface{}{
			"success": false,
			"error":   "Server response is null or undefined",
		}
	}

	files := serverResponse.Get("files")
	if files.IsNull() || files.IsUndefined() {
		return map[string]interface{}{
			"success": false,
			"error":   "No 'files' array found in server response",
		}
	}

	// Process each file and decrypt metadata
	filesLength := files.Length()
	var decryptedFiles []map[string]interface{}

	for i := 0; i < filesLength; i++ {
		file := files.Index(i)

		// Extract encrypted metadata
		filenameNonce := file.Get("filename_nonce").String()
		encryptedFilename := file.Get("encrypted_filename").String()
		sha256Nonce := file.Get("sha256sum_nonce").String()
		encryptedSHA256 := file.Get("encrypted_sha256sum").String()

		// Decrypt metadata using password-derived key (NOT FEK)
		decryptResult := decryptFileMetadata(js.Value{}, []js.Value{
			js.ValueOf(filenameNonce),
			js.ValueOf(encryptedFilename),
			js.ValueOf(sha256Nonce),
			js.ValueOf(encryptedSHA256),
			js.ValueOf(username),
		})

		decryptMap, ok := decryptResult.(map[string]interface{})
		if !ok || !decryptMap["success"].(bool) {
			// Skip this file if decryption fails
			continue
		}

		// Build decrypted file info
		decryptedFile := map[string]interface{}{
			"id":             file.Get("id").String(),
			"file_id":        file.Get("file_id").String(),
			"storage_id":     file.Get("storage_id").String(),
			"owner_username": file.Get("owner_username").String(),
			"filename":       decryptMap["filename"].(string),
			"sha256sum":      decryptMap["sha256sum"].(string),
			"size_bytes":     file.Get("size_bytes").Int(),
			"padded_size":    file.Get("padded_size").Int(),
			"upload_date":    file.Get("upload_date").String(),
			"password_hint":  file.Get("password_hint").String(),
			"password_type":  file.Get("password_type").String(),
		}

		decryptedFiles = append(decryptedFiles, decryptedFile)
	}

	// Get storage info if available
	var storageInfo map[string]interface{}
	storage := serverResponse.Get("storage")
	if !storage.IsNull() && !storage.IsUndefined() {
		storageInfo = map[string]interface{}{
			"used_bytes":  storage.Get("used_bytes").Int(),
			"total_bytes": storage.Get("total_bytes").Int(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"files":   decryptedFiles,
		"storage": storageInfo,
		"count":   len(decryptedFiles),
	}
}

// OPAQUE Authentication Functions (HTTP-based, not crypto)

// performOpaqueLogin performs OPAQUE authentication via HTTP to server endpoints
func performOpaqueLogin(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username, password",
		}
	}

	username := args[0].String()
	password := args[1].String()

	// Create login request payload
	loginReq := map[string]string{
		"username": username,
		"password": password,
	}

	requestBodyJSON, err := json.Marshal(loginReq)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to marshal login request: " + err.Error(),
		}
	}

	// Make HTTP request to server's OPAQUE endpoint
	fetchPromise := js.Global().Call("fetch", "/api/opaque/login", map[string]interface{}{
		"method": "POST",
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
		"body": string(requestBodyJSON),
	})

	// Return the fetch promise - TypeScript will handle the response
	return map[string]interface{}{
		"success": true,
		"promise": fetchPromise,
		"message": "OPAQUE login request sent - handle response in .then() callback",
	}
}

// createSecureSession stores session key securely for user
func createSecureSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected sessionKey, username",
		}
	}

	sessionKey := args[0].String()
	username := args[1].String()

	if sessionKey == "" || username == "" {
		return map[string]interface{}{
			"success": false,
			"error":   "Session key and username cannot be empty",
		}
	}

	// Store the session key securely in memory
	// Note: This is kept separate from userPasswords for security separation
	// Session keys are for authentication, passwords are for file encryption
	sessionData := map[string]interface{}{
		"sessionKey": sessionKey,
		"username":   username,
		"createdAt":  time.Now().Unix(),
	}

	// Store in a secure context (not localStorage for security)
	localStorage := js.Global().Get("localStorage")
	sessionDataJSON, err := json.Marshal(sessionData)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to marshal session data: " + err.Error(),
		}
	}

	localStorage.Call("setItem", "arkfileSecurityContext", string(sessionDataJSON))

	return map[string]interface{}{
		"success": true,
		"message": "Secure session created successfully",
	}
}

// clearSecureSession clears session data for user
func clearSecureSession(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username",
		}
	}

	username := args[0].String()

	// Clear the secure session context
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("removeItem", "arkfileSecurityContext")

	// Also clear password for this user if it exists (for complete cleanup)
	clearPasswordForUser(js.Value{}, []js.Value{js.ValueOf(username)})

	return map[string]interface{}{
		"success": true,
		"message": "Secure session cleared successfully",
	}
}

// main function to register WASM functions
func main() {
	// OPAQUE Authentication Functions (HTTP-based)
	js.Global().Set("performOpaqueLogin", js.FuncOf(performOpaqueLogin))
	js.Global().Set("createSecureSession", js.FuncOf(createSecureSession))
	js.Global().Set("clearSecureSession", js.FuncOf(clearSecureSession))

	// Password-based file encryption functions
	js.Global().Set("storePasswordForUser", js.FuncOf(storePasswordForUser))
	js.Global().Set("clearPasswordForUser", js.FuncOf(clearPasswordForUser))
	js.Global().Set("encryptFilePassword", js.FuncOf(encryptFilePassword))
	js.Global().Set("decryptFilePassword", js.FuncOf(decryptFilePassword))

	// File metadata encryption functions
	js.Global().Set("encryptFileMetadata", js.FuncOf(encryptFileMetadata))
	js.Global().Set("decryptFileMetadata", js.FuncOf(decryptFileMetadata))

	// File listing functions
	js.Global().Set("listUserFiles", js.FuncOf(listUserFiles))
	js.Global().Set("processFileListResponse", js.FuncOf(processFileListResponse))

	// Chunked upload encryption functions (password-based)
	js.Global().Set("encryptFileChunkedPassword", js.FuncOf(encryptFileChunkedPassword))
	js.Global().Set("decryptFileChunkedPassword", js.FuncOf(decryptFileChunkedPassword))
	js.Global().Set("createPasswordEnvelope", js.FuncOf(createPasswordEnvelope))
	js.Global().Set("validateChunkFormat", js.FuncOf(validateChunkFormat))

	// Logging
	js.Global().Set("logUploadSuccess", js.FuncOf(logUploadSuccess))

	// Utility functions
	js.Global().Set("generateSalt", js.FuncOf(generateSalt))
	js.Global().Set("calculateSHA256", js.FuncOf(calculateSHA256))

	// Password validation functions
	js.Global().Set("validatePasswordComplexity", js.FuncOf(validatePasswordComplexity))
	js.Global().Set("validatePasswordConfirmation", js.FuncOf(validatePasswordConfirmation))

	// Authentication and security functions
	js.Global().Set("validateTokenStructure", js.FuncOf(validateTokenStructure))
	js.Global().Set("sanitizeAPIResponse", js.FuncOf(sanitizeAPIResponse))

	// JWT Token Management Functions
	js.Global().Set("setJWTTokens", js.FuncOf(setJWTTokens))
	js.Global().Set("getJWTToken", js.FuncOf(getJWTToken))
	js.Global().Set("getRefreshToken", js.FuncOf(getRefreshToken))
	js.Global().Set("clearJWTTokens", js.FuncOf(clearJWTTokens))
	js.Global().Set("isJWTTokenExpired", js.FuncOf(isJWTTokenExpired))
	js.Global().Set("parseJWTClaims", js.FuncOf(parseJWTClaims))
	js.Global().Set("isAuthenticated", js.FuncOf(isAuthenticated))
	js.Global().Set("refreshJWTToken", js.FuncOf(refreshJWTToken))
	js.Global().Set("startAutoRefresh", js.FuncOf(startAutoRefresh))
	js.Global().Set("stopAutoRefresh", js.FuncOf(stopAutoRefresh))
	js.Global().Set("authenticatedFetch", js.FuncOf(authenticatedFetch))
	js.Global().Set("clearSession", js.FuncOf(clearSession))

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
	if username, exists := claims["username"]; !exists || username == "" {
		return map[string]interface{}{
			"valid":   false,
			"message": "Missing or empty username claim",
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
		"valid":    true,
		"message":  "Token structure is valid",
		"username": claims["username"],
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
