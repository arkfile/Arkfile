// crypto_utils.go - Crypto helper functions for arkfile-client
//
// Wraps the crypto package functions for upload / download / share operations.
// Every AES-GCM call on the file path is AAD-bound so that an
// attacker with DB-write access cannot swap, reorder, or substitute chunks /
// FEK envelopes / metadata between or within a user's files without the
// AEAD tag failing on decrypt. See crypto/aad.go
//
// Chunk layout (uniform chunks):
//   Every chunk: [nonce (12)][ciphertext][tag (16)]
//   No per-chunk envelope header. The owner FEK envelope carries its version,
//   key type, KDF profile, and public salt in an authenticated fixed header.
//
// All crypto parameters are sourced from centralized JSON configs via the
// crypto package accessors.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/pquerna/otp/totp"
)

// encryptChunk encrypts a single plaintext chunk with the FEK using
// AES-256-GCM, binding the AAD to (fileID, chunkIndex, totalChunks).
// Returns [nonce(12)][ciphertext][tag(16)]. No per-chunk envelope header.
func encryptChunk(plaintext, fek []byte, fileID string, chunkIndex, totalChunks int64) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes for AES-256")
	}
	if fileID == "" {
		return nil, fmt.Errorf("fileID cannot be empty")
	}

	aad := crypto.BuildChunkAAD(fileID, chunkIndex, totalChunks)
	encrypted, err := crypto.EncryptGCMWithAAD(plaintext, fek, aad)
	if err != nil {
		return nil, fmt.Errorf("chunk %d encryption failed: %w", chunkIndex, err)
	}
	return encrypted, nil
}

// decryptChunk decrypts a single encrypted chunk with the FEK using
// AES-256-GCM, verifying the AAD bound at encrypt time. Any mismatch in
// fileID, chunkIndex, or totalChunks causes AEAD authentication failure
func decryptChunk(ciphertext, fek []byte, fileID string, chunkIndex, totalChunks int64) ([]byte, error) {
	if len(fek) != 32 {
		return nil, fmt.Errorf("FEK must be 32 bytes for AES-256")
	}
	if fileID == "" {
		return nil, fmt.Errorf("fileID cannot be empty")
	}

	aad := crypto.BuildChunkAAD(fileID, chunkIndex, totalChunks)
	plaintext, err := crypto.DecryptGCMWithAAD(ciphertext, fek, aad)
	if err != nil {
		return nil, fmt.Errorf("chunk %d decryption failed: %w", chunkIndex, err)
	}
	return plaintext, nil
}

// encryptMetadata encrypts filename and SHA-256 hex digest with the
// account key. AAD binds each ciphertext to (fileID, field_label,
// ownerUsername) so substituting metadata between files / fields / users
// is rejected by the AEAD layer.
//
// Returns base64-encoded values suitable for the server API.
func encryptMetadata(filename, sha256hex string, accountKey []byte, fileID, ownerUsername string) (encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64 string, err error) {
	if fileID == "" {
		return "", "", "", "", fmt.Errorf("fileID cannot be empty")
	}
	if ownerUsername == "" {
		return "", "", "", "", fmt.Errorf("ownerUsername cannot be empty")
	}

	aadFilename := crypto.BuildMetadataFieldAAD(fileID, crypto.AADFieldFilename, ownerUsername)
	encFilenameRaw, err := crypto.EncryptGCMWithAAD([]byte(filename), accountKey, aadFilename)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to encrypt filename: %w", err)
	}

	aadSha := crypto.BuildMetadataFieldAAD(fileID, crypto.AADFieldSha256, ownerUsername)
	encSHA256Raw, err := crypto.EncryptGCMWithAAD([]byte(sha256hex), accountKey, aadSha)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to encrypt SHA-256: %w", err)
	}

	// Extract nonces (first 12 bytes of each encrypted blob).
	nonceSize := crypto.AesGcmNonceSize()

	fnNonce := encFilenameRaw[:nonceSize]
	encFilename := encFilenameRaw[nonceSize:]

	shaNonce := encSHA256Raw[:nonceSize]
	encSHA256 := encSHA256Raw[nonceSize:]

	encFilenameB64 = base64.StdEncoding.EncodeToString(encFilename)
	fnNonceB64 = base64.StdEncoding.EncodeToString(fnNonce)
	encSHA256B64 = base64.StdEncoding.EncodeToString(encSHA256)
	shaNonceB64 = base64.StdEncoding.EncodeToString(shaNonce)

	return encFilenameB64, fnNonceB64, encSHA256B64, shaNonceB64, nil
}

// encryptPasswordHint encrypts an optional custom-password hint with the
// Account Key under AADFieldPasswordHint. Empty hint returns empty strings
// (callers must omit both fields from the upload init payload).
func encryptPasswordHint(hint string, accountKey []byte, fileID, ownerUsername string) (encHintB64, hintNonceB64 string, err error) {
	if hint == "" {
		return "", "", nil
	}
	if fileID == "" {
		return "", "", fmt.Errorf("fileID cannot be empty")
	}
	if ownerUsername == "" {
		return "", "", fmt.Errorf("ownerUsername cannot be empty")
	}

	aad := crypto.BuildMetadataFieldAAD(fileID, crypto.AADFieldPasswordHint, ownerUsername)
	encRaw, err := crypto.EncryptGCMWithAAD([]byte(hint), accountKey, aad)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt password hint: %w", err)
	}

	nonceSize := crypto.AesGcmNonceSize()
	nonce := encRaw[:nonceSize]
	ciphertext := encRaw[nonceSize:]

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

// encryptTags encrypts an optional canonical comma-separated tags string with
// the Account Key under AADFieldTags. Empty tags returns empty strings
// (callers must omit both fields from the upload init payload; on PUT after
// final tag removal, callers send both fields as empty strings instead).
func encryptTags(tagsPlaintext string, accountKey []byte, fileID, ownerUsername string) (encTagsB64, tagsNonceB64 string, err error) {
	if tagsPlaintext == "" {
		return "", "", nil
	}
	if fileID == "" {
		return "", "", fmt.Errorf("fileID cannot be empty")
	}
	if ownerUsername == "" {
		return "", "", fmt.Errorf("ownerUsername cannot be empty")
	}

	aad := crypto.BuildMetadataFieldAAD(fileID, crypto.AADFieldTags, ownerUsername)
	encRaw, err := crypto.EncryptGCMWithAAD([]byte(tagsPlaintext), accountKey, aad)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt tags: %w", err)
	}

	nonceSize := crypto.AesGcmNonceSize()
	nonce := encRaw[:nonceSize]
	ciphertext := encRaw[nonceSize:]

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

// decryptMetadataField decrypts a single metadata field (filename,
// SHA-256 digest, password hint, or tags), verifying the AAD bound to (fileID,
// fieldLabel, ownerUsername). fieldLabel must be one of
// crypto.AADFieldFilename, crypto.AADFieldSha256, crypto.AADFieldPasswordHint,
// or crypto.AADFieldTags.
func decryptMetadataField(encDataB64, nonceB64 string, accountKey []byte, fileID, fieldLabel, ownerUsername string) (string, error) {
	if fileID == "" {
		return "", fmt.Errorf("fileID cannot be empty")
	}
	if fieldLabel == "" {
		return "", fmt.Errorf("fieldLabel cannot be empty")
	}
	if ownerUsername == "" {
		return "", fmt.Errorf("ownerUsername cannot be empty")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}
	encData, err := base64.StdEncoding.DecodeString(encDataB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	combined := make([]byte, 0, len(nonce)+len(encData))
	combined = append(combined, nonce...)
	combined = append(combined, encData...)

	aad := crypto.BuildMetadataFieldAAD(fileID, fieldLabel, ownerUsername)
	plaintext, err := crypto.DecryptGCMWithAAD(combined, accountKey, aad)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}

// wrapFEK encrypts the FEK with a KEK and authenticates the complete owner
// envelope header together with the file ID.
//
// Cross-file FEK substitution fails at unwrap time because the AAD
// was bound to a different fileID.
func wrapFEK(fek, kek, salt []byte, keyType, fileID string) (string, error) {
	if fileID == "" {
		return "", fmt.Errorf("fileID cannot be empty")
	}

	header, err := crypto.CreateFEKEnvelopeHeader(keyType, salt)
	if err != nil {
		return "", fmt.Errorf("create FEK envelope header: %w", err)
	}

	aad := crypto.BuildFEKEnvelopeAAD(fileID, header)
	encryptedFEK, err := crypto.EncryptGCMWithAAD(fek, kek, aad)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt FEK: %w", err)
	}

	result := make([]byte, 0, len(header)+len(encryptedFEK))
	result = append(result, header...)
	result = append(result, encryptedFEK...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// unwrapFEK decrypts an encrypted FEK with a pre-derived KEK.
func unwrapFEK(encryptedFEKB64 string, kek []byte, fileID string) ([]byte, string, error) {
	if fileID == "" {
		return nil, "", fmt.Errorf("fileID cannot be empty")
	}

	encryptedFEK, err := base64.StdEncoding.DecodeString(encryptedFEKB64)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode encrypted FEK: %w", err)
	}

	headerSize := crypto.OwnerEnvelopeHeaderSize()
	expectedSize := headerSize + crypto.AesGcmNonceSize() + 32 + crypto.AesGcmTagSize()
	if len(encryptedFEK) != expectedSize {
		return nil, "", fmt.Errorf("encrypted FEK must be %d bytes, got %d", expectedSize, len(encryptedFEK))
	}

	headerBytes := encryptedFEK[:headerSize]
	header, err := crypto.ParseFEKEnvelopeHeader(headerBytes)
	if err != nil {
		return nil, "", err
	}
	keyType := header.PasswordType()

	aad := crypto.BuildFEKEnvelopeAAD(fileID, headerBytes)
	fek, err := crypto.DecryptGCMWithAAD(encryptedFEK[headerSize:], kek, aad)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt FEK: %w", err)
	}
	if len(fek) != 32 {
		clearBytes(fek)
		return nil, "", fmt.Errorf("decrypted FEK must be 32 bytes")
	}

	return fek, keyType, nil
}

func parseFEKEnvelopeHeader(encryptedFEKB64 string) (*crypto.FEKEnvelopeHeader, error) {
	encryptedFEK, err := base64.StdEncoding.DecodeString(encryptedFEKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted FEK: %w", err)
	}
	return crypto.ParseFEKEnvelopeHeader(encryptedFEK)
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

// calculateTotalEncryptedSize computes the total encrypted size
// deterministically from the plaintext file size, using uniform chunk
// layout (no per-chunk envelope header). Each chunk adds AES-GCM
// overhead (nonce + tag).
func calculateTotalEncryptedSize(plaintextSize int64) int64 {
	chunkSize := crypto.PlaintextChunkSize()
	overhead := int64(crypto.AesGcmOverhead())

	if plaintextSize == 0 {
		// Even empty files get one chunk with overhead.
		return overhead
	}

	numFullChunks := plaintextSize / chunkSize
	lastChunkPlaintext := plaintextSize % chunkSize

	if lastChunkPlaintext == 0 {
		// All chunks are full.
		return numFullChunks * (chunkSize + overhead)
	}
	// Full chunks + partial last chunk.
	return numFullChunks*(chunkSize+overhead) + (lastChunkPlaintext + overhead)
}

// base64URLEncode encodes bytes to URL-safe base64 without padding (43 chars for 32 bytes)
// Used for generating share IDs per server spec.
func base64URLEncode(data []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
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

// generateTOTPCode generates a current TOTP code from a base32 secret.
// Used by --totp-secret flag on login to avoid needing a separate TOTP binary.
func generateTOTPCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return code, nil
}
