package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/storage"
)

// handleVerifyStorageCommand performs a round-trip storage verification:
// upload a 1 MB test object, download it, verify the SHA-256 hash, then delete it.
// This uses the same storage.InitS3() code path as the Arkfile server, so it tests
// the exact configuration that will be used in production.
//
// Environment variables are loaded from /opt/arkfile/etc/secrets.env (or --secrets-env override).
// This command does NOT require a running Arkfile server or admin session.
func handleVerifyStorageCommand(args []string) error {
	fs := flag.NewFlagSet("verify-storage", flag.ExitOnError)
	secretsEnv := fs.String("secrets-env", "/opt/arkfile/etc/secrets.env", "Path to secrets.env file")

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin verify-storage [FLAGS]

Verify S3 storage connectivity with a full round-trip test:
  1. Upload a 1 MB test object (all zeros, known SHA-256 hash)
  2. Download the object back
  3. Verify the SHA-256 hash matches
  4. Delete the test object

This command reads storage configuration from secrets.env and uses the same
S3 initialization code as the Arkfile server. No running server or admin
session is required.

FLAGS:
    --secrets-env PATH  Path to secrets.env (default: /opt/arkfile/etc/secrets.env)
    --help              Show this help message

EXAMPLES:
    arkfile-admin verify-storage
    arkfile-admin verify-storage --secrets-env /opt/arkfile/etc/secrets.env
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Step 1: Load environment from secrets.env
	fmt.Printf("Loading storage configuration from %s...\n", *secretsEnv)
	if err := loadSecretsEnv(*secretsEnv); err != nil {
		return fmt.Errorf("failed to load secrets.env: %w", err)
	}

	provider := os.Getenv("STORAGE_PROVIDER")
	if provider == "" {
		provider = "generic-s3"
	}
	fmt.Printf("Storage provider: %s\n", provider)

	// Step 2: Initialize S3 storage using the same code path as the server
	fmt.Printf("Initializing S3 storage...\n")
	if err := storage.InitS3(); err != nil {
		return fmt.Errorf("S3 initialization failed: %w", err)
	}
	fmt.Printf("[OK] S3 storage initialized\n")

	// Step 3: Create 1 MB test data (all zeros) with known hash
	const testSize = 1024 * 1024 // 1 MB
	testData := make([]byte, testSize)
	// testData is already all zeros from make()

	expectedHash := sha256.Sum256(testData)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	testObjectKey := ".arkfile-verify-storage-test"

	fmt.Printf("Test object: %s (%d bytes)\n", testObjectKey, testSize)
	fmt.Printf("Expected SHA-256: %s\n", expectedHashHex)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 4: Upload test object
	fmt.Printf("Uploading test object...\n")
	_, err := storage.Provider.PutObject(ctx, testObjectKey, bytes.NewReader(testData), int64(testSize), storage.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	fmt.Printf("[OK] Upload successful\n")

	// Step 5: Download test object
	fmt.Printf("Downloading test object...\n")
	obj, err := storage.Provider.GetObject(ctx, testObjectKey, storage.GetObjectOptions{})
	if err != nil {
		// Attempt cleanup before returning
		cleanupTestObject(ctx, testObjectKey)
		return fmt.Errorf("download failed: %w", err)
	}

	downloadedData, err := io.ReadAll(obj)
	obj.Close()
	if err != nil {
		cleanupTestObject(ctx, testObjectKey)
		return fmt.Errorf("failed to read downloaded data: %w", err)
	}
	fmt.Printf("[OK] Download successful (%d bytes)\n", len(downloadedData))

	// Step 6: Verify SHA-256 hash
	fmt.Printf("Verifying SHA-256 hash...\n")
	actualHash := sha256.Sum256(downloadedData)
	actualHashHex := hex.EncodeToString(actualHash[:])

	if actualHashHex != expectedHashHex {
		cleanupTestObject(ctx, testObjectKey)
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHashHex, actualHashHex)
	}
	fmt.Printf("[OK] Hash verified: %s\n", actualHashHex)

	// Step 7: Delete test object
	fmt.Printf("Deleting test object...\n")
	if err := storage.Provider.RemoveObject(ctx, testObjectKey, storage.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete failed (test object may remain in bucket): %w", err)
	}
	fmt.Printf("[OK] Test object deleted\n")

	fmt.Printf("\nSUCCESS! Storage verification complete.\n")
	fmt.Printf("  Provider: %s\n", provider)
	fmt.Printf("  Round-trip: upload -> download -> verify hash -> delete\n")
	fmt.Printf("  All checks passed.\n")

	return nil
}

// cleanupTestObject attempts to remove the test object, logging but not failing on error
func cleanupTestObject(ctx context.Context, key string) {
	if err := storage.Provider.RemoveObject(ctx, key, storage.RemoveObjectOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to clean up test object %s: %v\n", key, err)
	}
}

// loadSecretsEnv reads a KEY=VALUE env file and sets environment variables.
// Lines starting with # are comments. Empty lines are skipped.
// This mirrors how systemd EnvironmentFile works.
func loadSecretsEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		os.Setenv(key, value)
	}
	return scanner.Err()
}
