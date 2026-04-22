package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

const (
	verifyTestObjectKey = ".arkfile-verify-storage-test"
	verifyTestSize      = 1024 * 1024 // 1 MB
)

// VerificationResult holds the outcome of a storage round-trip test.
type VerificationResult struct {
	Verified    bool      `json:"verified"`
	Provider    string    `json:"provider"`
	Timestamp   time.Time `json:"timestamp"`
	Duration    string    `json:"duration"`
	Error       string    `json:"error,omitempty"`
	UploadOK    bool      `json:"upload_ok"`
	DownloadOK  bool      `json:"download_ok"`
	HashMatchOK bool      `json:"hash_match_ok"`
	DeleteOK    bool      `json:"delete_ok"`
}

var (
	lastVerification *VerificationResult
	verifyMu         sync.RWMutex
)

// GetLastVerification returns the most recent verification result (thread-safe).
func GetLastVerification() *VerificationResult {
	verifyMu.RLock()
	defer verifyMu.RUnlock()
	if lastVerification == nil {
		return nil
	}
	copy := *lastVerification
	return &copy
}

// RunVerification performs a full S3 round-trip test against the given provider.
// Upload 1 MB of zeros, download, verify SHA-256, delete.
// Stores the result internally and returns it.
func RunVerification(providerName string, provider ObjectStorageProvider) *VerificationResult {
	start := time.Now()
	result := &VerificationResult{
		Provider:  providerName,
		Timestamp: start,
	}

	defer func() {
		result.Duration = time.Since(start).String()
		verifyMu.Lock()
		lastVerification = result
		verifyMu.Unlock()
	}()

	if provider == nil {
		result.Error = "storage provider not initialized"
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create 1 MB test data (all zeros) with known hash
	testData := make([]byte, verifyTestSize)
	expectedHash := sha256.Sum256(testData)
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	// Upload
	_, err := provider.PutObject(ctx, verifyTestObjectKey, bytes.NewReader(testData), int64(verifyTestSize), PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		result.Error = fmt.Sprintf("upload failed: %v", err)
		return result
	}
	result.UploadOK = true

	// Download
	obj, err := provider.GetObject(ctx, verifyTestObjectKey, GetObjectOptions{})
	if err != nil {
		cleanupTestObject(ctx, provider)
		result.Error = fmt.Sprintf("download failed: %v", err)
		return result
	}

	downloadedData, err := io.ReadAll(obj)
	obj.Close()
	if err != nil {
		cleanupTestObject(ctx, provider)
		result.Error = fmt.Sprintf("failed to read downloaded data: %v", err)
		return result
	}
	result.DownloadOK = true

	// Verify hash
	actualHash := sha256.Sum256(downloadedData)
	actualHashHex := hex.EncodeToString(actualHash[:])
	if actualHashHex != expectedHashHex {
		cleanupTestObject(ctx, provider)
		result.Error = fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHashHex, actualHashHex)
		return result
	}
	result.HashMatchOK = true

	// Delete
	if err := provider.RemoveObject(ctx, verifyTestObjectKey, RemoveObjectOptions{}); err != nil {
		result.Error = fmt.Sprintf("delete failed (test object may remain in bucket): %v", err)
		return result
	}
	result.DeleteOK = true

	result.Verified = true
	return result
}

// RunStartupVerification runs a storage verification in the background after startup.
// Logs the result. Does not block the caller.
func RunStartupVerification(providerName string) {
	go func() {
		// Brief delay to let the server finish starting
		time.Sleep(2 * time.Second)

		if Registry == nil || Registry.Primary() == nil {
			log.Printf("Storage verification: skipped (no provider initialized)")
			return
		}

		log.Printf("Storage verification: starting round-trip test (provider: %s)...", providerName)
		result := RunVerification(providerName, Registry.Primary())

		if result.Verified {
			log.Printf("Storage verification: PASSED (provider: %s, duration: %s)", result.Provider, result.Duration)
		} else {
			log.Printf("Storage verification: FAILED (provider: %s, error: %s)", result.Provider, result.Error)
		}
	}()
}

func cleanupTestObject(ctx context.Context, provider ObjectStorageProvider) {
	if err := provider.RemoveObject(ctx, verifyTestObjectKey, RemoveObjectOptions{}); err != nil {
		log.Printf("Storage verification: warning: failed to clean up test object: %v", err)
	}
}
