package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// EncryptGCM encrypts data using AES-256-GCM
// Returns: nonce + ciphertext + tag (all concatenated)
func EncryptGCM(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptGCM decrypts data using AES-256-GCM
// Expects: nonce + ciphertext + tag (all concatenated)
func DecryptGCM(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length (nonce + tag)
	nonceSize := gcm.NonceSize()
	tagSize := AesGcmTagSize()
	minSize := nonceSize + tagSize

	if len(data) < minSize {
		// Enhanced debug logging for insufficient data
		if isDebugMode() {
			fmt.Printf("GCM decrypt: insufficient data length %d, need at least %d (nonce=%d + tag=%d)\n",
				len(data), minSize, nonceSize, tagSize)
			if len(data) > 0 {
				fmt.Printf("GCM decrypt: data preview first_8_bytes=%x\n", data[:min(8, len(data))])
			}
		}
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(data), minSize)
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Enhanced debug logging for GCM decryption context
	if isDebugMode() {
		fmt.Printf("GCM decrypt context: total_data=%d, nonce_size=%d, ciphertext_size=%d, nonce=%x\n",
			len(data), len(nonce), len(ciphertext), nonce)
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Enhanced debug logging for decryption failures
		if isDebugMode() {
			fmt.Printf("GCM decryption failed: %v\n", err)
			fmt.Printf("GCM decrypt failure context: key_len=%d, nonce_len=%d, ciphertext_len=%d\n",
				len(key), len(nonce), len(ciphertext))
			if len(ciphertext) >= 16 {
				fmt.Printf("GCM decrypt failure: last_16_bytes_of_ciphertext=%x (includes tag)\n",
					ciphertext[len(ciphertext)-16:])
			}
		}
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Debug logging for successful decryption
	if isDebugMode() {
		fmt.Printf("GCM decrypt successful: plaintext_len=%d\n", len(plaintext))
	}

	return plaintext, nil
}

// Helper function for safe min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isDebugMode checks if debug mode is enabled for crypto operations
func isDebugMode() bool {
	debug := os.Getenv("DEBUG_MODE")
	return debug == "true" || debug == "1"
}

// EncryptStreamGCM encrypts large data in chunks for memory efficiency
func EncryptStreamGCM(reader io.Reader, writer io.Writer, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	buffer := make([]byte, int(PlaintextChunkSize()))
	chunkIndex := 0

	for {
		n, err := reader.Read(buffer)
		if n == 0 {
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read chunk: %w", err)
			}
		}

		chunk := buffer[:n]

		// Generate nonce for this chunk (includes chunk index for uniqueness)
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("failed to generate nonce for chunk %d: %w", chunkIndex, err)
		}

		// Encrypt chunk
		ciphertext := gcm.Seal(nonce, nonce, chunk, nil)

		// Write encrypted chunk
		if _, err := writer.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write encrypted chunk %d: %w", chunkIndex, err)
		}

		chunkIndex++

		if err == io.EOF {
			break
		}
	}

	return nil
}

// DecryptStreamGCM decrypts large data that was encrypted in chunks
func DecryptStreamGCM(reader io.Reader, writer io.Writer, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	tagSize := AesGcmTagSize()
	minChunkSize := nonceSize + tagSize

	// Buffer for reading chunks
	buffer := make([]byte, int(PlaintextChunkSize())+minChunkSize)
	chunkIndex := 0

	for {
		// Read at least the minimum chunk size
		n, err := io.ReadAtLeast(reader, buffer[:minChunkSize], minChunkSize)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read chunk header %d: %w", chunkIndex, err)
		}

		// Try to read more data for this chunk
		additional, err := reader.Read(buffer[n:])
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk data %d: %w", chunkIndex, err)
		}
		totalRead := n + additional

		chunk := buffer[:totalRead]

		// Extract nonce and ciphertext
		nonce := chunk[:nonceSize]
		ciphertext := chunk[nonceSize:]

		// Decrypt chunk
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", chunkIndex, err)
		}

		// Write decrypted chunk
		if _, err := writer.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted chunk %d: %w", chunkIndex, err)
		}

		chunkIndex++

		if err == io.EOF {
			break
		}
	}

	return nil
}

// GenerateAESKey generates a cryptographically secure 256-bit AES key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// EncryptGCMWithAAD encrypts data using AES-256-GCM with Additional Authenticated Data
// AAD is authenticated but not encrypted - used to bind ciphertext to context
// Returns: nonce + ciphertext + tag (all concatenated)
func EncryptGCMWithAAD(data, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data with AAD
	ciphertext := gcm.Seal(nonce, nonce, data, aad)
	return ciphertext, nil
}

// DecryptGCMWithAAD decrypts data using AES-256-GCM with Additional Authenticated Data
// AAD must match the value used during encryption or decryption will fail
// Expects: nonce + ciphertext + tag (all concatenated)
func DecryptGCMWithAAD(data, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length (nonce + tag)
	nonceSize := gcm.NonceSize()
	tagSize := AesGcmTagSize()
	minSize := nonceSize + tagSize

	if len(data) < minSize {
		if isDebugMode() {
			fmt.Printf("GCM-AAD decrypt: insufficient data length %d, need at least %d\n", len(data), minSize)
		}
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(data), minSize)
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	if isDebugMode() {
		fmt.Printf("GCM-AAD decrypt: data=%d, nonce=%d, ciphertext=%d, aad=%d\n",
			len(data), len(nonce), len(ciphertext), len(aad))
	}

	// Decrypt data with AAD verification
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		if isDebugMode() {
			fmt.Printf("GCM-AAD decryption failed (AAD mismatch or tampering): %v\n", err)
		}
		return nil, fmt.Errorf("failed to decrypt with AAD (tampering detected or wrong context): %w", err)
	}

	if isDebugMode() {
		fmt.Printf("GCM-AAD decrypt successful: plaintext_len=%d\n", len(plaintext))
	}

	return plaintext, nil
}
