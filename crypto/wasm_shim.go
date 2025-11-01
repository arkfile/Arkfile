//go:build js && wasm
// +build js,wasm

package crypto

import (
	"encoding/base64"
	"syscall/js"
	"time"
)

// Password-based Argon2ID Processing Functions

// JavaScript-callable functions for WASM

// validatePasswordStrengthJS validates password strength format
func validatePasswordStrengthJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid": false,
			"error": "Invalid arguments: expected password",
		}
	}

	password := args[0].String()

	// Validate the password strength
	if err := ValidatePasswordStrength([]byte(password)); err != nil {
		return map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Password meets strength requirements",
	}
}

// deriveSecureSessionFromPasswordJS derives session key from password
func deriveSecureSessionFromPasswordJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected password, username",
		}
	}

	password := args[0].String()
	username := args[1].String()

	// Derive session key
	sessionKey, err := DeriveSecureSessionFromPassword([]byte(password), username)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive session key: " + err.Error(),
		}
	}

	// Convert session key to JavaScript Uint8Array
	sessionKeyJS := js.Global().Get("Uint8Array").New(len(sessionKey))
	js.CopyBytesToJS(sessionKeyJS, sessionKey)

	return map[string]interface{}{
		"success":    true,
		"sessionKey": sessionKeyJS,
	}
}

// RegisterWASMFunctions registers core password-based functions with JavaScript
func RegisterWASMFunctions() {
	js.Global().Set("validatePasswordStrength", js.FuncOf(validatePasswordStrengthJS))
	js.Global().Set("deriveSecureSessionFromPassword", js.FuncOf(deriveSecureSessionFromPasswordJS))
}

// RegisterExtendedWASMFunctions registers additional password-based functions
func RegisterExtendedWASMFunctions() {
	RegisterWASMFunctions() // Register basic functions first
	// Extended functions will be added here as needed
}

// passwordHealthCheckJS provides a simple health check for password-based readiness
func passwordHealthCheckJS(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"wasmReady":     true,
		"timestamp":     time.Now().Unix(),
		"passwordReady": true, // WASM is ready means password-based crypto can work
	}
}

// wasmSystemInfoJS provides basic system information for password-based operations
func wasmSystemInfoJS(this js.Value, args []js.Value) interface{} {
	return map[string]interface{}{
		"wasmReady":     true,
		"passwordReady": true,
		"timestamp":     time.Now().Unix(),
		"message":       "WASM crypto system ready for password-based operations",
	}
}

// Helper functions for secure session file operations

// encryptFileWithPasswordKey encrypts file data using a password-derived key
func encryptFileWithPasswordKey(fileData []byte, password []byte, username, keyType string) (string, error) {
	// Encrypt using password-based key derivation
	encryptedData, err := EncryptFileWithPassword(fileData, password, username, keyType)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// decryptFileWithPasswordKey decrypts file data using a password-derived key
func decryptFileWithPasswordKey(encryptedDataB64 string, password []byte, username string) (string, string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return "", "", err
	}

	// Decrypt using password-based key derivation
	decryptedData, keyType, err := DecryptFileWithPassword(data, password, username)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(decryptedData), keyType, nil
}

// Secure session storage - NEVER exposed to JavaScript
var secureSessionStorage = make(map[string][]byte)

// createSecureSessionFromPasswordJS creates a secure session from password
func createSecureSessionFromPasswordJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected password, username",
		}
	}

	password := args[0].String()
	username := args[1].String()

	if password == "" || username == "" {
		return map[string]interface{}{
			"success": false,
			"error":   "Password and username cannot be empty",
		}
	}

	// Derive session key using password-based derivation
	sessionKey, err := DeriveSecureSessionFromPassword([]byte(password), username)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to derive session key: " + err.Error(),
		}
	}

	// Store session key securely in WASM memory (NEVER in JavaScript)
	secureSessionStorage[username] = sessionKey

	return map[string]interface{}{
		"success": true,
		"message": "Secure session created successfully",
	}
}

// encryptFileWithSecureSessionJS encrypts file using secure session
func encryptFileWithSecureSessionJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected fileData, username, keyType",
		}
	}

	username := args[1].String()
	keyType := args[2].String()

	// Get session key from secure storage (this represents the password)
	password, exists := secureSessionStorage[username]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No secure session found for user",
		}
	}

	// Convert file data
	fileData := make([]byte, args[0].Length())
	js.CopyBytesToGo(fileData, args[0])

	// Encrypt file using password-based encryption
	encryptedData, err := encryptFileWithPasswordKey(fileData, password, username, keyType)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "File encryption failed: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    encryptedData,
	}
}

// decryptFileWithSecureSessionJS decrypts file using secure session
func decryptFileWithSecureSessionJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected encryptedData, username",
		}
	}

	encryptedData := args[0].String()
	username := args[1].String()

	// Get session key from secure storage (this represents the password)
	password, exists := secureSessionStorage[username]
	if !exists {
		return map[string]interface{}{
			"success": false,
			"error":   "No secure session found for user",
		}
	}

	// Decrypt the file
	decryptedData, keyType, err := decryptFileWithPasswordKey(encryptedData, password, username)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "File decryption failed: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    decryptedData,
		"keyType": keyType,
	}
}

// validateSecureSessionJS checks if a secure session exists for the user
func validateSecureSessionJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid": false,
			"error": "Invalid arguments: expected username",
		}
	}

	username := args[0].String()

	sessionKey, exists := secureSessionStorage[username]
	if !exists {
		return map[string]interface{}{
			"valid": false,
			"error": "No secure session found",
		}
	}

	// Validate session key format
	if err := ValidateSessionKey(sessionKey); err != nil {
		return map[string]interface{}{
			"valid": false,
			"error": "Invalid session key: " + err.Error(),
		}
	}

	return map[string]interface{}{
		"valid":   true,
		"message": "Secure session is valid",
	}
}

// clearSecureSessionJS securely clears the session for a user
func clearSecureSessionJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid arguments: expected username",
		}
	}

	username := args[0].String()

	// Get session key and securely zero it
	if sessionKey, exists := secureSessionStorage[username]; exists {
		SecureZeroSessionKey(sessionKey)
		delete(secureSessionStorage, username)
	}

	return map[string]interface{}{
		"success": true,
		"message": "Secure session cleared",
	}
}

// Password validation functions

// getPasswordRequirementsJS exposes password requirement constants to JavaScript
func getPasswordRequirementsJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"error": "password type required (account, custom, or share)",
		}
	}

	passwordType := args[0].String()

	var minLength int
	switch passwordType {
	case "account":
		minLength = MinAccountPasswordLength
	case "custom":
		minLength = MinCustomPasswordLength
	case "share":
		minLength = MinSharePasswordLength
	default:
		return map[string]interface{}{
			"error": "invalid password type: must be account, custom, or share",
		}
	}

	return map[string]interface{}{
		"minLength":  minLength,
		"minEntropy": MinEntropyBits,
	}
}

// validatePasswordComplexityJS provides password complexity validation
func validatePasswordComplexityJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return map[string]interface{}{
			"valid":   false,
			"score":   0,
			"message": "Invalid arguments: expected password string",
		}
	}

	password := args[0].String()

	// Use our password validation
	result := ValidateAccountPassword(password)

	// Calculate score out of 100 for legacy compatibility
	score := result.StrengthScore * 20 // Convert 0-4 scale to 0-80, then add entropy bonus
	if result.Entropy >= 60 {
		score += 20 // Bonus for meeting entropy requirement
	}

	// Determine message based on strength score and suggestions
	var message string
	valid := result.MeetsRequirement

	if valid {
		message = "Strong password! All requirements met"
	} else if len(result.Suggestions) > 0 {
		message = result.Suggestions[0] // Use first suggestion as main message
	} else {
		switch result.StrengthScore {
		case 0:
			message = "Very weak password"
		case 1:
			message = "Weak password"
		case 2:
			message = "Fair password, needs improvement"
		case 3:
			message = "Good password, but could be stronger"
		default:
			message = "Password needs improvement"
		}
	}

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	suggestionsJS := js.Global().Get("Array").New(len(result.Suggestions))
	for i, sug := range result.Suggestions {
		suggestionsJS.SetIndex(i, sug)
	}

	// Convert Requirements struct to JavaScript object
	requirementsJS := map[string]interface{}{
		"length": map[string]interface{}{
			"met":     result.Requirements.Length.Met,
			"current": result.Requirements.Length.Current,
			"needed":  result.Requirements.Length.Needed,
			"message": result.Requirements.Length.Message,
		},
		"uppercase": map[string]interface{}{
			"met":     result.Requirements.Uppercase.Met,
			"message": result.Requirements.Uppercase.Message,
		},
		"lowercase": map[string]interface{}{
			"met":     result.Requirements.Lowercase.Met,
			"message": result.Requirements.Lowercase.Message,
		},
		"number": map[string]interface{}{
			"met":     result.Requirements.Number.Met,
			"message": result.Requirements.Number.Message,
		},
		"special": map[string]interface{}{
			"met":     result.Requirements.Special.Met,
			"message": result.Requirements.Special.Message,
		},
	}

	return map[string]interface{}{
		"valid":        valid,
		"score":        score,
		"message":      message,
		"requirements": requirementsJS,
		"suggestions":  suggestionsJS,
		"entropy":      result.Entropy,
		"feedback":     feedbackJS,
	}
}

// validatePasswordConfirmationJS validates password confirmation matching
func validatePasswordConfirmationJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return map[string]interface{}{
			"match":   false,
			"message": "Invalid arguments: expected password and confirmation",
			"status":  "error",
		}
	}

	password := args[0].String()
	confirm := args[1].String()

	if password == "" && confirm == "" {
		return map[string]interface{}{
			"match":   false,
			"message": "Enter password confirmation",
			"status":  "empty",
		}
	}

	if password == "" || confirm == "" {
		return map[string]interface{}{
			"match":   false,
			"message": "Password confirmation required",
			"status":  "empty",
		}
	}

	if password == confirm {
		return map[string]interface{}{
			"match":   true,
			"message": "Passwords match",
			"status":  "match",
		}
	}

	return map[string]interface{}{
		"match":   false,
		"message": "Passwords do not match",
		"status":  "no-match",
	}
}

// validatePasswordEntropyJS validates password entropy from JavaScript
func validatePasswordEntropyJS(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		errorFeedback := js.Global().Get("Array").New(1)
		errorFeedback.SetIndex(0, "Invalid arguments: expected password, minLength, minEntropy")
		return map[string]interface{}{
			"meets_requirements": false,
			"feedback":           errorFeedback,
		}
	}

	password := args[0].String()
	minLength := args[1].Int()
	minEntropy := args[2].Float()

	result := ValidatePasswordEntropy(password, minLength, minEntropy)

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	penaltiesJS := js.Global().Get("Array").New(len(result.PatternPenalties))
	for i, penalty := range result.PatternPenalties {
		penaltiesJS.SetIndex(i, penalty)
	}

	return map[string]interface{}{
		"entropy":            result.Entropy,
		"strength_score":     result.StrengthScore,
		"feedback":           feedbackJS,
		"meets_requirements": result.MeetsRequirement,
		"pattern_penalties":  penaltiesJS,
	}
}

// calculatePasswordScoreJS provides real-time entropy scoring for responsive UI
func calculatePasswordScoreJS(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"entropy": 0,
			"score":   0,
			"level":   "Very Weak",
		}
	}

	password := args[0].String()
	result := ValidateAccountPassword(password)

	var level string
	switch result.StrengthScore {
	case 0:
		level = "Very Weak"
	case 1:
		level = "Weak"
	case 2:
		level = "Fair"
	case 3:
		level = "Good"
	case 4:
		level = "Excellent"
	default:
		level = "Unknown"
	}

	return map[string]interface{}{
		"entropy": result.Entropy,
		"score":   result.StrengthScore,
		"level":   level,
	}
}

// WASM validation functions

// validatePasswordEntropyWASM provides client-side password entropy validation
func validatePasswordEntropyWASM(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) < 3 {
		return map[string]interface{}{
			"error": "Password, minimum length, and minimum entropy required",
		}
	}

	password := inputs[0].String()
	minLength := inputs[1].Int()
	minEntropy := inputs[2].Float()

	result := ValidatePasswordEntropy(password, minLength, minEntropy)

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	penaltiesJS := js.Global().Get("Array").New(len(result.PatternPenalties))
	for i, penalty := range result.PatternPenalties {
		penaltiesJS.SetIndex(i, penalty)
	}

	return map[string]interface{}{
		"entropy":            result.Entropy,
		"strength_score":     result.StrengthScore,
		"feedback":           feedbackJS,
		"meets_requirements": result.MeetsRequirement,
		"pattern_penalties":  penaltiesJS,
	}
}

// validateAccountPasswordWASM validates account passwords with 60+ bit entropy
func validateAccountPasswordWASM(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) < 1 {
		return map[string]interface{}{
			"error": "Password required for validation",
		}
	}

	password := inputs[0].String()
	result := ValidateAccountPassword(password)

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	penaltiesJS := js.Global().Get("Array").New(len(result.PatternPenalties))
	for i, penalty := range result.PatternPenalties {
		penaltiesJS.SetIndex(i, penalty)
	}

	return map[string]interface{}{
		"entropy":            result.Entropy,
		"strength_score":     result.StrengthScore,
		"feedback":           feedbackJS,
		"meets_requirements": result.MeetsRequirement,
		"pattern_penalties":  penaltiesJS,
	}
}

// validateSharePasswordWASM validates share passwords with 60+ bit entropy
func validateSharePasswordWASM(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) < 1 {
		return map[string]interface{}{
			"error": "Password required for validation",
		}
	}

	password := inputs[0].String()
	result := ValidateSharePassword(password)

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	penaltiesJS := js.Global().Get("Array").New(len(result.PatternPenalties))
	for i, penalty := range result.PatternPenalties {
		penaltiesJS.SetIndex(i, penalty)
	}

	return map[string]interface{}{
		"entropy":            result.Entropy,
		"strength_score":     result.StrengthScore,
		"feedback":           feedbackJS,
		"meets_requirements": result.MeetsRequirement,
		"pattern_penalties":  penaltiesJS,
	}
}

// validateCustomPasswordWASM validates custom passwords with 60+ bit entropy
func validateCustomPasswordWASM(this js.Value, inputs []js.Value) interface{} {
	if len(inputs) < 1 {
		return map[string]interface{}{
			"error": "Password required for validation",
		}
	}

	password := inputs[0].String()
	result := ValidateCustomPassword(password)

	// Convert Go slices to JavaScript arrays
	feedbackJS := js.Global().Get("Array").New(len(result.Feedback))
	for i, fb := range result.Feedback {
		feedbackJS.SetIndex(i, fb)
	}

	penaltiesJS := js.Global().Get("Array").New(len(result.PatternPenalties))
	for i, penalty := range result.PatternPenalties {
		penaltiesJS.SetIndex(i, penalty)
	}

	return map[string]interface{}{
		"entropy":            result.Entropy,
		"strength_score":     result.StrengthScore,
		"feedback":           feedbackJS,
		"meets_requirements": result.MeetsRequirement,
		"pattern_penalties":  penaltiesJS,
	}
}

// RegisterAllWASMFunctions registers all WASM functions
func RegisterAllWASMFunctions() {
	RegisterExtendedWASMFunctions()

	// Add password-compatible functions
	js.Global().Set("passwordHealthCheck", js.FuncOf(passwordHealthCheckJS))
	js.Global().Set("wasmSystemInfo", js.FuncOf(wasmSystemInfoJS))

	// Add secure session management functions
	js.Global().Set("createSecureSessionFromPassword", js.FuncOf(createSecureSessionFromPasswordJS))
	js.Global().Set("encryptFileWithSecureSession", js.FuncOf(encryptFileWithSecureSessionJS))
	js.Global().Set("decryptFileWithSecureSession", js.FuncOf(decryptFileWithSecureSessionJS))
	js.Global().Set("validateSecureSession", js.FuncOf(validateSecureSessionJS))
	js.Global().Set("clearSecureSession", js.FuncOf(clearSecureSessionJS))

	// Add password validation functions
	js.Global().Set("getPasswordRequirements", js.FuncOf(getPasswordRequirementsJS))
	js.Global().Set("validatePasswordComplexity", js.FuncOf(validatePasswordComplexityJS))
	js.Global().Set("validatePasswordConfirmation", js.FuncOf(validatePasswordConfirmationJS))

	// Add enhanced password validation functions
	js.Global().Set("validatePasswordEntropy", js.FuncOf(validatePasswordEntropyJS))
	js.Global().Set("calculatePasswordScore", js.FuncOf(calculatePasswordScoreJS))

	// WASM exports for enhanced password validation
	js.Global().Set("validatePasswordEntropyWASM", js.FuncOf(validatePasswordEntropyWASM))
	js.Global().Set("validateAccountPasswordWASM", js.FuncOf(validateAccountPasswordWASM))
	js.Global().Set("validateSharePasswordWASM", js.FuncOf(validateSharePasswordWASM))
	js.Global().Set("validateCustomPasswordWASM", js.FuncOf(validateCustomPasswordWASM))
}
