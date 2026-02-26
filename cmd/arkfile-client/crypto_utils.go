// crypto_utils.go - Crypto helper functions for arkfile-client
// Wraps the crypto package functions for upload/download/share operations.
// All crypto parameters are sourced from centralized JSON configs via crypto package accessors.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/84adam/Arkfile/crypto"
)

// encryptChunk encrypts a single plaintext chunk with FEK using AES-GCM.
// For chunkIndex 0, prepends the 2-byte envelope header [version][keyType].
// Returns the encrypted chunk (nonce + ciphertext + tag, with optional header).
func encryptChunk(plaintext, fek []byte, chunkIndex int, keyType byte) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(fek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: result is nonce + ciphertext + tag
	encrypted := gcm.Seal(nonce, nonce, plaintext, nil)

	// Chunk 0 gets the envelope header prepended
	if chunkIndex == 0 {
		header := []byte{0x01, keyType} // version 1 + key type
		result := make([]byte, 0, len(header)+len(encrypted))
		result = append(result, header...)
		result = append(result, encrypted...)
		return result, nil
	}

	return encrypted, nil
}

// decryptChunk decrypts a single encrypted chunk with FEK using AES-GCM.
// For chunkIndex 0, strips the 2-byte envelope header first.
// Returns the plaintext.
func decryptChunk(ciphertext, fek []byte, chunkIndex int) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes for AES-256")
	}

	data := ciphertext

	// Chunk 0: strip 2-byte envelope header
	if chunkIndex == 0 {
		headerSize := crypto.EnvelopeHeaderSize()
		if len(data) < headerSize {
			return nil, fmt.Errorf("chunk 0 too short for envelope header: got %d bytes", len(data))
		}
		data = data[headerSize:]
	}

	block, err := aes.NewCipher(fek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+crypto.AesGcmTagSize() {
		return nil, fmt.Errorf("chunk too short: got %d bytes, need at least %d", len(data), nonceSize+crypto.AesGcmTagSize())
	}

	nonce := data[:nonceSize]
	encData := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("chunk %d decryption failed: %w", chunkIndex, err)
	}

	return plaintext, nil
}

// encryptMetadata encrypts filename and SHA-256 hex digest with accountKey.
// Returns base64-encoded values suitable for server API calls.
func encryptMetadata(filename, sha256hex string, accountKey []byte) (encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64 string, err error) {
	// Encrypt filename
	encFilenameRaw, err := crypto.EncryptGCM([]byte(filename), accountKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to encrypt filename: %w", err)
	}

	// Encrypt SHA-256 digest
	encSHA256Raw, err := crypto.EncryptGCM([]byte(sha256hex), accountKey)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to encrypt SHA-256: %w", err)
	}

	// Extract nonces (first 12 bytes of each encrypted blob)
	nonceSize := crypto.AesGcmNonceSize()

	fnNonce := encFilenameRaw[:nonceSize]
	encFilename := encFilenameRaw[nonceSize:]

	shaNonce := encSHA256Raw[:nonceSize]
	encSHA256 := encSHA256Raw[nonceSize:]

	// Base64 encode for API transmission
	encFilenameB64 = base64.StdEncoding.EncodeToString(encFilename)
	fnNonceB64 = base64.StdEncoding.EncodeToString(fnNonce)
	encSHA256B64 = base64.StdEncoding.EncodeToString(encSHA256)
	shaNonceB64 = base64.StdEncoding.EncodeToString(shaNonce)

	return encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64, nil
}

// decryptMetadataField decrypts a single metadata field given base64-encoded nonce and ciphertext.
func decryptMetadataField(encDataB64, nonceB64 string, accountKey []byte) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	encData, err := base64.StdEncoding.DecodeString(encDataB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Reconstruct nonce+ciphertext format expected by DecryptGCM
	combined := make([]byte, 0, len(nonce)+len(encData))
	combined = append(combined, nonce...)
	combined = append(combined, encData...)

	plaintext, err := crypto.DecryptGCM(combined, accountKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// wrapFEK encrypts the FEK with a KEK (account key or custom key) and prepends
// the 2-byte envelope header [0x01][keyType].
// Returns base64-encoded encrypted FEK suitable for server API.
func wrapFEK(fek, kek []byte, keyType string) (string, error) {
	keyTypeByte, err := crypto.KeyTypeForContext(keyType)
	if err != nil {
		return "", fmt.Errorf("invalid key type: %w", err)
	}

	// Encrypt FEK with KEK using AES-GCM
	encryptedFEK, err := crypto.EncryptGCM(fek, kek)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	// Prepend envelope header
	header := []byte{0x01, keyTypeByte}
	result := make([]byte, 0, len(header)+len(encryptedFEK))
	result = append(result, header...)
	result = append(result, encryptedFEK...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// unwrapFEK decrypts an encrypted FEK. Strips the 2-byte envelope header,
// determines key type, and decrypts with the provided KEK.
// Returns the plaintext FEK and the key type string ("account" or "custom").
func unwrapFEK(encryptedFEKB64 string, kek []byte) ([]byte, string, error) {
	encryptedFEK, err := base64.StdEncoding.DecodeString(encryptedFEKB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode encrypted FEK: %w", err)
	}

	headerSize := crypto.EnvelopeHeaderSize()
	if len(encryptedFEK) < headerSize {
		return nil, "", fmt.Errorf("encrypted FEK too short for envelope header")
	}

	// Parse envelope header
	version := encryptedFEK[0]
	keyTypeByte := encryptedFEK[1]

	if version != 0x01 {
		return nil, "", fmt.Errorf("unsupported envelope version: 0x%02x", version)
	}

	var keyType string
	switch keyTypeByte {
	case 0x01:
		keyType = "account"
	case 0x02:
		keyType = "custom"
	default:
		return nil, "", fmt.Errorf("unsupported key type: 0x%02x", keyTypeByte)
	}

	// Decrypt FEK (strip header)
	fek, err := crypto.DecryptGCM(encryptedFEK[headerSize:], kek)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt FEK: %w", err)
	}

	return fek, keyType, nil
}

// computeStreamingSHA256 computes SHA-256 of a file using streaming reads.
// Only ~16 MiB in memory at any point. Returns hex-encoded digest.
func computeStreamingSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	buf := make([]byte, crypto.PlaintextChunkSize())

	for {
		n, err := f.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// calculateTotalEncryptedSize computes the total encrypted size deterministically
// from the plaintext file size using chunking parameters.
func calculateTotalEncryptedSize(plaintextSize int64) int64 {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())
	headerSize := int64(crypto.EnvelopeHeaderSize())

	if plaintextSize == 0 {
		// Even empty files get one chunk with overhead + header
		return headerSize + overhead
	}

	numFullChunks := plaintextSize / chunkSize
	lastChunkPlaintext := plaintextSize % chunkSize

	var totalEncrypted int64
	if lastChunkPlaintext == 0 {
		// All chunks are full
		totalEncrypted = numFullChunks*(chunkSize+overhead) + headerSize
	} else {
		// Full chunks + partial last chunk
		totalEncrypted = numFullChunks*(chunkSize+overhead) + (lastChunkPlaintext + overhead) + headerSize
	}

	return totalEncrypted
}

// generateFEK generates a random 32-byte File Encryption Key.
func generateFEK() ([]byte, error) {
	fek := make([]byte, 32)
	if _, err := rand.Read(fek); err != nil {
		return nil, fmt.Errorf("failed to generate FEK: %w", err)
	}
	return fek, nil
}

// isSeekableFile checks if the given path is a regular file (seekable).
// Returns error if it's stdin, a pipe, or other non-seekable input.
func isSeekableFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("upload requires a seekable file (regular file on disk). Stdin/pipe input is not supported")
	}

	return nil
}
