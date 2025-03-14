package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"syscall/js"

	"golang.org/x/crypto/sha3"
)

var (
	// SHAKE-256 iterations for key stretching
	iterations = 10000
	/* Expected time to compute:
	 * - ~1700ms for an Intel Core i3-5005U 5th Gen 2-Core 2.0 GHz CPU
	 * - ~650ms for an Intel Core i5-8600T 8th Gen 6-core 3.70 GHz CPU
	 * - ~1200ms for an Apple M1 CPU
	 */

	// Key length in bytes
	keyLength = 32
)

// deriveKey generates a cryptographic key from a password using SHAKE-256
// This is quantum-resistant and provides sufficient computational cost
// to protect against brute force attacks
func deriveKey(password []byte, salt []byte) []byte {
	// Final key that will be returned
	output := make([]byte, keyLength)

	// Initial hash combines password and salt
	combinedInput := append([]byte{}, password...)
	combinedInput = append(combinedInput, salt...)

	// Working buffer that will be repeatedly hashed
	buffer := make([]byte, 64) // 512-bit buffer

	// First hash to initialize buffer
	d := sha3.NewShake256()
	d.Write(combinedInput)
	d.Read(buffer)

	// Iterative hashing to increase computational cost
	for i := 0; i < iterations; i++ {
		// Add iteration counter to prevent rainbow table attacks
		counterBytes := []byte{
			byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
		}

		d.Reset()
		d.Write(buffer)
		d.Write(counterBytes)
		d.Read(buffer)
	}

	// Final hash to derive output key
	d.Reset()
	d.Write(buffer)
	d.Write([]byte("key")) // Domain separation
	d.Read(output)

	return output
}

// deriveSessionKey derives a session key for account-based encryption
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

	// Use SHAKE-256 for key derivation with domain separation for session keys
	output := make([]byte, keyLength)
	combinedInput := append([]byte(password), saltBytes...)

	d := sha3.NewShake256()
	d.Write(combinedInput)
	d.Write([]byte("sessionkey")) // Domain separation for session keys
	d.Read(output)

	return base64.StdEncoding.EncodeToString(output)
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

	// Format version 0x02 = SHAKE256 KDF
	// We'll use the first byte as version, and the second byte as key type
	// 0x00 = custom password, 0x01 = account-derived session key
	result := []byte{0x02}

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
		// For custom password, derive key using SHAKE-256
		key = deriveKey([]byte(password), salt)
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

	if version == 0x02 {
		// Use quantum-resistant SHAKE-256 KDF
		if keyType == 0x01 {
			// This is an account-password encrypted file
			var err error
			key, err = base64.StdEncoding.DecodeString(password)
			if err != nil {
				return "Failed to decode session key"
			}
		} else {
			// This is a custom password, derive key normally
			key = deriveKey([]byte(password), salt)
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
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "Failed to generate salt"
	}
	return base64.StdEncoding.EncodeToString(salt)
}

func main() {
	c := make(chan struct{})

	// Register JavaScript functions
	js.Global().Set("encryptFile", js.FuncOf(encryptFile))
	js.Global().Set("decryptFile", js.FuncOf(decryptFile))
	js.Global().Set("generateSalt", js.FuncOf(generateSalt))
	js.Global().Set("deriveSessionKey", js.FuncOf(deriveSessionKey))
	js.Global().Set("calculateSHA256", js.FuncOf(calculateSHA256))

	// Keep the Go program running
	<-c
}
