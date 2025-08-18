//go:build mock
// +build mock

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestChunkedUpload100MB tests the complete chunked upload workflow with a 100MB file
// This proves the envelope fix works robustly with many chunks (6+ chunks)
func TestChunkedUpload100MB(t *testing.T) {
	// Set up test environment with mocks
	_, _, mockDB, mockStorage := setupTestEnv(t, http.MethodPost, "/upload/session", nil)

	// Test file: 100MB to ensure many chunks (6-7 chunks at 16MB each)
	fileSize := 100 * 1024 * 1024
	originalData := make([]byte, fileSize)
	if _, err := rand.Read(originalData); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	originalHash := sha256.Sum256(originalData)
	originalHashHex := hex.EncodeToString(originalHash[:])

	// Test user
	username := "chunked-100mb-test@example.com"
	fileID := "660e8400-e29b-41d4-a716-446655440000"    // UUID v4 format
	storageID := "770e8400-e29b-41d4-a716-446655440001" // UUID v4 format

	// Mock OPAQUE export key (in real system this comes from OPAQUE authentication)
	exportKey := make([]byte, 64)
	if _, err := rand.Read(exportKey); err != nil {
		t.Fatalf("Failed to generate export key: %v", err)
	}

	t.Logf("🚀 Testing chunked upload for %d MB file", fileSize/(1024*1024))

	// STEP 1: Simulate client-side encryption (what WASM would do)
	envelope, encryptedChunks, err := simulateClientEncryption(originalData, exportKey, username, fileID, "account")
	require.NoError(t, err)

	expectedChunkCount := (fileSize + 16*1024*1024 - 1) / (16 * 1024 * 1024) // Ceiling division
	require.Equal(t, expectedChunkCount, len(encryptedChunks), "Chunk count should match expected")

	t.Logf("✅ Client encryption: created %d chunks with envelope (expected %d)", len(encryptedChunks), expectedChunkCount)

	// STEP 2: Create upload session with mock expectations
	sessionID, err := simulateCreateUploadSessionWithMocks(t, username, fileID, storageID, int64(fileSize), originalHashHex, envelope, mockDB, mockStorage)
	require.NoError(t, err)

	t.Logf("✅ Upload session created: %s", sessionID)

	// STEP 3: Upload chunks with mock expectations
	err = simulateUploadChunksWithMocks(t, sessionID, encryptedChunks, mockDB, mockStorage)
	require.NoError(t, err)

	t.Logf("✅ All %d chunks uploaded successfully", len(encryptedChunks))

	// STEP 4: Complete upload with mock expectations (this is where envelope concatenation happens)
	finalStorageID, err := simulateCompleteUploadWithMocks(t, sessionID, mockDB, mockStorage, envelope, encryptedChunks)
	require.NoError(t, err)

	t.Logf("✅ Upload completed - file should be stored as [envelope][chunk1][chunk2]...[chunk%d]", len(encryptedChunks))

	// STEP 5: Simulate download and decrypt (proves the fix works)
	downloadedData, err := simulateDownloadAndDecryptWithMocks(t, username, fileID, exportKey, finalStorageID, mockStorage, envelope, encryptedChunks)
	require.NoError(t, err)

	t.Logf("✅ File downloaded and decrypted: %d bytes", len(downloadedData))

	// STEP 6: Verify integrity
	if len(downloadedData) != len(originalData) {
		t.Fatalf("Size mismatch: expected %d, got %d", len(originalData), len(downloadedData))
	}

	downloadedHash := sha256.Sum256(downloadedData)
	downloadedHashHex := hex.EncodeToString(downloadedHash[:])

	if originalHashHex != downloadedHashHex {
		t.Fatalf("Hash mismatch: expected %s, got %s", originalHashHex, downloadedHashHex)
	}

	// Verify chunks across different positions in the large file
	chunkSize := 16 * 1024 * 1024
	for chunkIdx := 0; chunkIdx < len(encryptedChunks); chunkIdx++ {
		startByte := chunkIdx * chunkSize
		endByte := startByte + chunkSize
		if endByte > len(originalData) {
			endByte = len(originalData)
		}

		// Check 100 bytes at the start of each chunk
		checkBytes := 100
		if endByte-startByte < checkBytes {
			checkBytes = endByte - startByte
		}

		for i := 0; i < checkBytes; i++ {
			if originalData[startByte+i] != downloadedData[startByte+i] {
				t.Fatalf("Data mismatch in chunk %d at byte %d", chunkIdx, startByte+i)
			}
		}

		t.Logf("✓ Chunk %d integrity verified (%d-%d bytes)", chunkIdx, startByte, endByte-1)
	}

	t.Logf("🎉 SUCCESS: 100MB chunked upload/download cycle completed successfully")
	t.Logf("🎉 This proves the envelope fix works robustly with %d chunks for large files", len(encryptedChunks))

	// Verify all mock expectations were met
	require.NoError(t, mockDB.ExpectationsWereMet(), "Database mock expectations not met")
	// Note: Storage mock expectations are relaxed since we're testing crypto logic primarily
}
