package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// ChunkSize for streaming operations (16MB)
const ChunkSize = 16 * 1024 * 1024

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
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
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

	buffer := make([]byte, ChunkSize)
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
	tagSize := 16 // GCM tag size
	minChunkSize := nonceSize + tagSize

	// Buffer for reading chunks
	buffer := make([]byte, ChunkSize+minChunkSize)
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
