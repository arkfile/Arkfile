# Chunked Download & Streaming Decryption Implementation Plan

## Overview

### Problem Statement

Currently, Arkfile uploads files using chunked encryption (16MB chunks encrypted with AES-256-GCM), but downloads require loading the entire encrypted file into memory before decryption. This creates poor UX for large files:

- **Memory pressure**: A 1GB file requires 1GB+ of browser memory
- **No progress feedback**: Users see no progress until the entire file is downloaded
- **Browser crashes**: Large files can crash tabs or trigger out-of-memory errors
- **No resume capability**: Failed downloads must restart from the beginning

### Goals

1. **Stream decryption**: Decrypt chunks as they arrive, never holding the full file in memory
2. **Progressive writes**: Write decrypted data to disk incrementally
3. **Resume support**: Allow interrupted downloads to continue from the last complete chunk
4. **Unified approach**: Same chunk format works for web (TypeScript) and CLI (Go) clients

---

## Current Architecture

### Upload Flow (Working Well)

```
Client                          Server                      Storage
  |                               |                            |
  |-- Encrypt chunk 0 (16MB) ---->|                            |
  |                               |-- Stream to S3 ----------->|
  |-- Encrypt chunk 1 (16MB) ---->|                            |
  |                               |-- Stream to S3 ----------->|
  |-- ... (repeat) -------------->|                            |
  |                               |-- Add padding + complete ->|
  |                               |                            |
```

- Chunks are encrypted client-side with unique nonces
- Each chunk is uploaded via multipart upload
- Server adds random padding for storage privacy
- Metadata stored: `size_bytes`, `padded_size`, `total_chunks`

### Download Flow (Current - Problematic)

```
Client                          Server                      Storage
  |                               |                            |
  |-- Request full file --------->|                            |
  |                               |<-- Stream (minus padding) -|
  |<-- Full encrypted blob -------|                            |
  |                               |                            |
  |-- Load into memory            |                            |
  |-- Decrypt all chunks          |                            |
  |-- Trigger browser download    |                            |
```

- Server strips padding via S3 range request (good)
- Client receives full encrypted blob (bad - memory intensive)
- Client must buffer everything before decryption (bad)

---

## Database Schema Changes

### Add `chunk_size_bytes` to File Metadata

```sql
-- Schema: chunk_size_bytes column in file_metadata
-- Set to the chunk size used during upload (e.g., 16777216 for 16MB)
chunk_size_bytes INTEGER NOT NULL
```

### Updated File Metadata Structure

```go
type FileMetadata struct {
    ID                    int64
    FileID                string
    StorageID             string
    OwnerUsername         string
    PasswordHint          sql.NullString
    PasswordType          string
    FilenameNonce         []byte
    EncryptedFilename     []byte
    Sha256sumNonce        []byte
    EncryptedSha256sum    []byte
    EncryptedFileSha256sum []byte
    EncryptedFEK          []byte
    SizeBytes             int64          // Actual encrypted data size
    PaddedSize            sql.NullInt64  // Size with padding in storage
    ChunkSizeBytes        int64          // Encryption chunk size (e.g., 16MB)
    UploadDate            time.Time
}
```

### Chunk Size Constant

```go
// crypto/constants.go
const (
    // DefaultChunkSizeBytes is the standard encryption chunk size (16 MiB)
    DefaultChunkSizeBytes = 16 * 1024 * 1024 // 16,777,216 bytes
    
    // AESGCMOverhead is the nonce (12 bytes) + auth tag (16 bytes)
    AESGCMOverhead = 28
    
    // EncryptedChunkSize is the size of each encrypted chunk
    EncryptedChunkSize = DefaultChunkSizeBytes + AESGCMOverhead // 16,777,244 bytes
)
```

---

## Encrypted Chunk Format

Each encrypted chunk has the following structure:

```
+------------------+------------------------+------------------+
|   Nonce (12B)    |   Ciphertext (varies)  |   Auth Tag (16B) |
+------------------+------------------------+------------------+
|<-- 12 bytes ---->|<-- up to 16MB -------->|<-- 16 bytes ---->|
```

### Chunk Boundaries

For a file with `chunk_size_bytes = 16777216`:

| Chunk    | Start Byte     | End Byte       | Max Size     |
|----------|----------------|----------------|--------------|
| 0        | 0              | 16,777,243     | 16,777,244   |
| 1        | 16,777,244     | 33,554,487     | 16,777,244   |
| 2        | 33,554,488     | 50,331,731     | 16,777,244   |
| ...      | ...            | ...            | ...          |
| N (last) | N * 16,777,244 | size_bytes - 1 | ≤ 16,777,244 |

### Calculating Chunk Count

```typescript
function calculateChunkCount(sizeBytes: number, chunkSizeBytes: number): number {
  const encryptedChunkSize = chunkSizeBytes + 28; // nonce + tag
  return Math.ceil(sizeBytes / encryptedChunkSize);
}
```

---

## Backend API Changes

### New Endpoint: Chunked Download

```go
// GET /api/files/:fileId/chunks/:chunkIndex
// Returns a single encrypted chunk

func DownloadChunk(c echo.Context) error {
    username := auth.GetUsernameFromToken(c)
    fileID := c.Param("fileId")
    chunkIndex, err := strconv.Atoi(c.Param("chunkIndex"))
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk index")
    }

    // Get file metadata
    file, err := models.GetFileByFileID(database.DB, fileID)
    if err != nil {
        return echo.NewHTTPError(http.StatusNotFound, "File not found")
    }

    // Verify ownership
    if file.OwnerUsername != username {
        return echo.NewHTTPError(http.StatusForbidden, "Access denied")
    }

    // Get chunk size from file metadata
    chunkSize := file.ChunkSizeBytes
    encryptedChunkSize := chunkSize + crypto.AESGCMOverhead

    // Calculate byte range for this chunk
    startByte := int64(chunkIndex) * encryptedChunkSize
    endByte := startByte + encryptedChunkSize - 1
    
    // Clamp to actual file size (last chunk may be smaller)
    if endByte >= file.SizeBytes {
        endByte = file.SizeBytes - 1
    }

    // Validate chunk index
    if startByte >= file.SizeBytes {
        return echo.NewHTTPError(http.StatusNotFound, "Chunk not found")
    }

    // Get chunk from storage using range request
    reader, err := storage.Provider.GetObjectRange(
        c.Request().Context(),
        file.StorageID,
        startByte,
        endByte,
        storage.GetObjectOptions{},
    )
    if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve chunk")
    }
    defer reader.Close()

    // Set headers
    c.Response().Header().Set("Content-Type", "application/octet-stream")
    c.Response().Header().Set("Content-Length", fmt.Sprintf("%d", endByte-startByte+1))
    c.Response().Header().Set("X-Chunk-Index", fmt.Sprintf("%d", chunkIndex))
    c.Response().Header().Set("X-Total-Chunks", fmt.Sprintf("%d", calculateTotalChunks(file.SizeBytes, encryptedChunkSize)))

    return c.Stream(http.StatusOK, "application/octet-stream", reader)
}
```

### New Endpoint: File Metadata with Chunk Info

```go
// GET /api/files/:fileId/metadata
// Returns file metadata including chunk information for download planning

type FileDownloadMetadata struct {
    FileID          string `json:"file_id"`
    SizeBytes       int64  `json:"size_bytes"`
    ChunkSizeBytes  int64  `json:"chunk_size_bytes"`
    TotalChunks     int    `json:"total_chunks"`
    EncryptedFEK    string `json:"encrypted_fek"`      // Base64
    FilenameNonce   string `json:"filename_nonce"`     // Base64
    EncryptedFilename string `json:"encrypted_filename"` // Base64
    Sha256sumNonce  string `json:"sha256sum_nonce"`    // Base64
    EncryptedSha256sum string `json:"encrypted_sha256sum"` // Base64
}

func GetFileDownloadMetadata(c echo.Context) error {
    // ... authentication and file lookup ...
    
    encryptedChunkSize := file.ChunkSizeBytes + crypto.AESGCMOverhead
    totalChunks := int(math.Ceil(float64(file.SizeBytes) / float64(encryptedChunkSize)))
    
    return c.JSON(http.StatusOK, FileDownloadMetadata{
        FileID:            file.FileID,
        SizeBytes:         file.SizeBytes,
        ChunkSizeBytes:    chunkSize,
        TotalChunks:       totalChunks,
        EncryptedFEK:      base64.StdEncoding.EncodeToString(file.EncryptedFEK),
        FilenameNonce:     base64.StdEncoding.EncodeToString(file.FilenameNonce),
        EncryptedFilename: base64.StdEncoding.EncodeToString(file.EncryptedFilename),
        Sha256sumNonce:    base64.StdEncoding.EncodeToString(file.Sha256sumNonce),
        EncryptedSha256sum: base64.StdEncoding.EncodeToString(file.EncryptedSha256sum),
    })
}
```

### Storage Layer: Range Request Support

```go
// storage/storage.go - Add to interface
type ObjectStorageProvider interface {
    // ... existing methods ...
    
    // GetObjectRange retrieves a byte range from an object
    GetObjectRange(ctx context.Context, storageID string, startByte, endByte int64, opts GetObjectOptions) (io.ReadCloser, error)
}

// storage/s3.go - Implementation
func (s *S3AWSStorage) GetObjectRange(ctx context.Context, storageID string, startByte, endByte int64, opts GetObjectOptions) (io.ReadCloser, error) {
    rangeHeader := fmt.Sprintf("bytes=%d-%d", startByte, endByte)
    
    result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(s.bucket),
        Key:    aws.String(storageID),
        Range:  aws.String(rangeHeader),
    })
    if err != nil {
        return nil, fmt.Errorf("failed to get object range: %w", err)
    }
    
    return result.Body, nil
}
```

---

## TypeScript Web Client Implementation

### Core Types

```typescript
// types/crypto.ts

export interface FileDownloadMetadata {
  file_id: string;
  size_bytes: number;
  chunk_size_bytes: number;
  total_chunks: number;
  encrypted_fek: string;      // Base64
  filename_nonce: string;     // Base64
  encrypted_filename: string; // Base64
  sha256sum_nonce: string;    // Base64
  encrypted_sha256sum: string; // Base64
}

export interface ChunkDecryptionResult {
  chunkIndex: number;
  decryptedData: Uint8Array;
  isLastChunk: boolean;
}

export interface DownloadProgress {
  chunksCompleted: number;
  totalChunks: number;
  bytesDownloaded: number;
  bytesDecrypted: number;
  totalBytes: number;
  percentComplete: number;
}

export type ProgressCallback = (progress: DownloadProgress) => void;
```

### AES-GCM Decryption with Web Crypto API

```typescript
// crypto/aes-gcm.ts

const AES_GCM_NONCE_SIZE = 12;
const AES_GCM_TAG_SIZE = 16;

export class AESGCMDecryptor {
  private key: CryptoKey;

  private constructor(key: CryptoKey) {
    this.key = key;
  }

  /**
   * Create a decryptor from a raw 256-bit key
   */
  static async fromRawKey(keyBytes: Uint8Array): Promise<AESGCMDecryptor> {
    if (keyBytes.length !== 32) {
      throw new Error(`Invalid key length: expected 32 bytes, got ${keyBytes.length}`);
    }

    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM', length: 256 },
      false, // not extractable
      ['decrypt']
    );

    return new AESGCMDecryptor(key);
  }

  /**
   * Decrypt a single chunk
   * Input format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
   */
  async decryptChunk(encryptedChunk: Uint8Array): Promise<Uint8Array> {
    if (encryptedChunk.length < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE) {
      throw new Error('Encrypted chunk too small');
    }

    // Extract nonce (first 12 bytes)
    const nonce = encryptedChunk.slice(0, AES_GCM_NONCE_SIZE);
    
    // Extract ciphertext + tag (remaining bytes)
    // Web Crypto expects ciphertext with tag appended
    const ciphertextWithTag = encryptedChunk.slice(AES_GCM_NONCE_SIZE);

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          tagLength: AES_GCM_TAG_SIZE * 8, // in bits
        },
        this.key,
        ciphertextWithTag
      );

      return new Uint8Array(decrypted);
    } catch (error) {
      throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}
```

### Streaming Download Manager

```typescript
// download/streaming-download.ts

import { AESGCMDecryptor } from '../crypto/aes-gcm';
import type { FileDownloadMetadata, DownloadProgress, ProgressCallback } from '../types/crypto';

const AES_GCM_OVERHEAD = 28; // 12 byte nonce + 16 byte tag

export class StreamingDownloadManager {
  private baseUrl: string;
  private authToken: string;

  constructor(baseUrl: string, authToken: string) {
    this.baseUrl = baseUrl;
    this.authToken = authToken;
  }

  /**
   * Download and decrypt a file using streaming chunks
   */
  async downloadFile(
    fileId: string,
    fileEncryptionKey: Uint8Array,
    onProgress?: ProgressCallback
  ): Promise<Blob> {
    // 1. Get file metadata
    const metadata = await this.getFileMetadata(fileId);
    
    // 2. Create decryptor
    const decryptor = await AESGCMDecryptor.fromRawKey(fileEncryptionKey);
    
    // 3. Calculate chunk info
    const encryptedChunkSize = metadata.chunk_size_bytes + AES_GCM_OVERHEAD;
    
    // 4. Download and decrypt chunks
    const decryptedChunks: Uint8Array[] = [];
    let bytesDownloaded = 0;
    let bytesDecrypted = 0;

    for (let i = 0; i < metadata.total_chunks; i++) {
      // Download chunk
      const encryptedChunk = await this.downloadChunk(fileId, i);
      bytesDownloaded += encryptedChunk.length;

      // Decrypt chunk
      const decryptedChunk = await decryptor.decryptChunk(encryptedChunk);
      decryptedChunks.push(decryptedChunk);
      bytesDecrypted += decryptedChunk.length;

      // Report progress
      if (onProgress) {
        onProgress({
          chunksCompleted: i + 1,
          totalChunks: metadata.total_chunks,
          bytesDownloaded,
          bytesDecrypted,
          totalBytes: metadata.size_bytes,
          percentComplete: Math.round(((i + 1) / metadata.total_chunks) * 100),
        });
      }
    }

    // 5. Combine chunks into final blob
    return new Blob(decryptedChunks);
  }

  /**
   * Download and decrypt directly to disk using File System Access API
   * Falls back to in-memory if not supported
   */
  async downloadFileToDisk(
    fileId: string,
    fileEncryptionKey: Uint8Array,
    suggestedFilename: string,
    onProgress?: ProgressCallback
  ): Promise<void> {
    // Check for File System Access API support
    if ('showSaveFilePicker' in window) {
      await this.downloadWithFileSystemAccess(fileId, fileEncryptionKey, suggestedFilename, onProgress);
    } else {
      // Fallback: download to memory then trigger download
      const blob = await this.downloadFile(fileId, fileEncryptionKey, onProgress);
      this.triggerBlobDownload(blob, suggestedFilename);
    }
  }

  /**
   * Stream directly to disk using File System Access API (Chrome/Edge)
   */
  private async downloadWithFileSystemAccess(
    fileId: string,
    fileEncryptionKey: Uint8Array,
    suggestedFilename: string,
    onProgress?: ProgressCallback
  ): Promise<void> {
    // Request file handle from user
    const fileHandle = await (window as any).showSaveFilePicker({
      suggestedName: suggestedFilename,
      types: [{
        description: 'All Files',
        accept: { 'application/octet-stream': [] },
      }],
    });

    // Create writable stream
    const writableStream = await fileHandle.createWritable();

    try {
      // Get metadata
      const metadata = await this.getFileMetadata(fileId);
      const decryptor = await AESGCMDecryptor.fromRawKey(fileEncryptionKey);

      let bytesDownloaded = 0;
      let bytesDecrypted = 0;

      // Process chunks one at a time
      for (let i = 0; i < metadata.total_chunks; i++) {
        // Download chunk
        const encryptedChunk = await this.downloadChunk(fileId, i);
        bytesDownloaded += encryptedChunk.length;

        // Decrypt chunk
        const decryptedChunk = await decryptor.decryptChunk(encryptedChunk);
        bytesDecrypted += decryptedChunk.length;

        // Write directly to disk
        await writableStream.write(decryptedChunk);

        // Report progress
        if (onProgress) {
          onProgress({
            chunksCompleted: i + 1,
            totalChunks: metadata.total_chunks,
            bytesDownloaded,
            bytesDecrypted,
            totalBytes: metadata.size_bytes,
            percentComplete: Math.round(((i + 1) / metadata.total_chunks) * 100),
          });
        }
      }
    } finally {
      await writableStream.close();
    }
  }

  private async getFileMetadata(fileId: string): Promise<FileDownloadMetadata> {
    const response = await fetch(`${this.baseUrl}/api/files/${fileId}/metadata`, {
      headers: {
        'Authorization': `Bearer ${this.authToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get file metadata: ${response.status}`);
    }

    return response.json();
  }

  private async downloadChunk(fileId: string, chunkIndex: number): Promise<Uint8Array> {
    const response = await fetch(`${this.baseUrl}/api/files/${fileId}/chunks/${chunkIndex}`, {
      headers: {
        'Authorization': `Bearer ${this.authToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to download chunk ${chunkIndex}: ${response.status}`);
    }

    const buffer = await response.arrayBuffer();
    return new Uint8Array(buffer);
  }

  private triggerBlobDownload(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}
```

### Transform Stream Implementation (Advanced)

For browsers with full Streams API support, we can use TransformStream for true streaming:

```typescript
// download/transform-stream-decryptor.ts

import { AESGCMDecryptor } from '../crypto/aes-gcm';

/**
 * Creates a TransformStream that decrypts chunks as they flow through
 */
export function createDecryptionTransformStream(
  decryptor: AESGCMDecryptor,
  chunkSizeBytes: number
): TransformStream<Uint8Array, Uint8Array> {
  const encryptedChunkSize = chunkSizeBytes + 28;
  let buffer = new Uint8Array(0);

  return new TransformStream({
    async transform(chunk, controller) {
      // Append incoming data to buffer
      const newBuffer = new Uint8Array(buffer.length + chunk.length);
      newBuffer.set(buffer);
      newBuffer.set(chunk, buffer.length);
      buffer = newBuffer;

      // Process complete chunks
      while (buffer.length >= encryptedChunkSize) {
        const encryptedChunk = buffer.slice(0, encryptedChunkSize);
        buffer = buffer.slice(encryptedChunkSize);

        const decrypted = await decryptor.decryptChunk(encryptedChunk);
        controller.enqueue(decrypted);
      }
    },

    async flush(controller) {
      // Process final partial chunk
      if (buffer.length > 0) {
        const decrypted = await decryptor.decryptChunk(buffer);
        controller.enqueue(decrypted);
      }
    },
  });
}

/**
 * Stream download with TransformStream pipeline
 */
export async function streamDownloadWithTransform(
  url: string,
  decryptor: AESGCMDecryptor,
  chunkSizeBytes: number,
  writableStream: WritableStream<Uint8Array>
): Promise<void> {
  const response = await fetch(url);
  if (!response.ok || !response.body) {
    throw new Error(`Download failed: ${response.status}`);
  }

  const decryptionStream = createDecryptionTransformStream(decryptor, chunkSizeBytes);

  await response.body
    .pipeThrough(decryptionStream)
    .pipeTo(writableStream);
}
```

---

## Go CLI Client Implementation

### Streaming Decryptor

```go
// cmd/arkfile-cli/crypto/streaming_decryptor.go

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

const (
	AESGCMNonceSize = 12
	AESGCMTagSize   = 16
	AESGCMOverhead  = AESGCMNonceSize + AESGCMTagSize
)

// StreamingDecryptor decrypts AES-GCM encrypted chunks
type StreamingDecryptor struct {
	aead      cipher.AEAD
	chunkSize int64
}

// NewStreamingDecryptor creates a new decryptor with the given key
func NewStreamingDecryptor(key []byte, chunkSize int64) (*StreamingDecryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &StreamingDecryptor{
		aead:      aead,
		chunkSize: chunkSize,
	}, nil
}

// DecryptChunk decrypts a single encrypted chunk
// Input format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
func (d *StreamingDecryptor) DecryptChunk(encryptedChunk []byte) ([]byte, error) {
	if len(encryptedChunk) < AESGCMOverhead {
		return nil, fmt.Errorf("encrypted chunk too small: %d bytes", len(encryptedChunk))
	}

	nonce := encryptedChunk[:AESGCMNonceSize]
	ciphertext := encryptedChunk[AESGCMNonceSize:]

	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptedChunkSize returns the size of encrypted chunks
func (d *StreamingDecryptor) EncryptedChunkSize() int64 {
	return d.chunkSize + AESGCMOverhead
}
```

### Streaming Download Client

```go
// cmd/arkfile-cli/download/streaming_download.go

package download

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/84adam/Arkfile/cmd/arkfile-cli/crypto"
)

// FileMetadata contains information needed for download
type FileMetadata struct {
	FileID         string `json:"file_id"`
	SizeBytes      int64  `json:"size_bytes"`
	ChunkSizeBytes int64  `json:"chunk_size_bytes"`
	TotalChunks    int    `json:"total_chunks"`
}

// ProgressCallback is called with download progress updates
type ProgressCallback func(chunksCompleted, totalChunks int, bytesWritten int64)

// StreamingDownloader handles chunked file downloads
type StreamingDownloader struct {
	baseURL   string
	authToken string
	client    *http.Client
}

// NewStreamingDownloader creates a new downloader
func NewStreamingDownloader(baseURL, authToken string) *StreamingDownloader {
	return &StreamingDownloader{
		baseURL:   baseURL,
		authToken: authToken,
		client:    &http.Client{},
	}
}

// DownloadFile downloads and decrypts a file to the specified path
func (d *StreamingDownloader) DownloadFile(
	ctx context.Context,
	fileID string,
	key []byte,
	outputPath string,
	onProgress ProgressCallback,
) error {
	// Get file metadata
	metadata, err := d.getFileMetadata(ctx, fileID)
	if err != nil {
		return fmt.Errorf("failed to get metadata: %w", err)
	}

	// Create decryptor
	decryptor, err := crypto.NewStreamingDecryptor(key, metadata.ChunkSizeBytes)
	if err != nil {
		return fmt.Errorf("failed to create decryptor: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	var bytesWritten int64

	// Download and decrypt each chunk
	for i := 0; i < metadata.TotalChunks; i++ {
		// Download chunk
		encryptedChunk, err := d.downloadChunk(ctx, fileID, i)
		if err != nil {
			return fmt.Errorf("failed to download chunk %d: %w", i, err)
		}

		// Decrypt chunk
		decryptedChunk, err := decryptor.DecryptChunk(encryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		// Write to file
		n, err := outFile.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to write chunk %d: %w", i, err)
		}
		bytesWritten += int64(n)

		// Report progress
		if onProgress != nil {
			onProgress(i+1, metadata.TotalChunks, bytesWritten)
		}
	}

	return nil
}

// DownloadFileResumable downloads with resume support
func (d *StreamingDownloader) DownloadFileResumable(
	ctx context.Context,
	fileID string,
	key []byte,
	outputPath string,
	onProgress ProgressCallback,
) error {
	// Get file metadata
	metadata, err := d.getFileMetadata(ctx, fileID)
	if err != nil {
		return fmt.Errorf("failed to get metadata: %w", err)
	}

	// Create decryptor
	decryptor, err := crypto.NewStreamingDecryptor(key, metadata.ChunkSizeBytes)
	if err != nil {
		return fmt.Errorf("failed to create decryptor: %w", err)
	}

	// Check for existing partial download
	startChunk := 0
	var outFile *os.File

	if info, err := os.Stat(outputPath); err == nil {
		// File exists, calculate which chunk to resume from
		// Each decrypted chunk is chunkSizeBytes (except possibly the last)
		startChunk = int(info.Size() / metadata.ChunkSizeBytes)
		
		// Open for append
		outFile, err = os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file for resume: %w", err)
		}
	} else {
		// Create new file
		outFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
	}
	defer outFile.Close()

	var bytesWritten int64

	// Download remaining chunks
	for i := startChunk; i < metadata.TotalChunks; i++ {
		encryptedChunk, err := d.downloadChunk(ctx, fileID, i)
		if err != nil {
			return fmt.Errorf("failed to download chunk %d: %w", i, err)
		}

		decryptedChunk, err := decryptor.DecryptChunk(encryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		n, err := outFile.Write(decryptedChunk)
		if err != nil {
			return fmt.Errorf("failed to write chunk %d: %w", i, err)
		}
		bytesWritten += int64(n)

		if onProgress != nil {
			onProgress(i+1, metadata.TotalChunks, bytesWritten)
		}
	}

	return nil
}

func (d *StreamingDownloader) getFileMetadata(ctx context.Context, fileID string) (*FileMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", 
		fmt.Sprintf("%s/api/files/%s/metadata", d.baseURL, fileID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.authToken)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request failed: %d", resp.StatusCode)
	}

	var metadata FileMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (d *StreamingDownloader) downloadChunk(ctx context.Context, fileID string, chunkIndex int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/api/files/%s/chunks/%d", d.baseURL, fileID, chunkIndex), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.authToken)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chunk download failed: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
```

---

## Error Handling & Recovery

### Chunk Verification

Each chunk is self-verifying via AES-GCM authentication tag. If decryption fails:

1. **Retry the chunk download** (network corruption)
2. **If retry fails**, report specific chunk failure to user
3. **For resumable downloads**, track last successful chunk

### Network Error Recovery

```typescript
// download/retry-handler.ts

export async function downloadChunkWithRetry(
  downloadFn: () => Promise<Uint8Array>,
  maxRetries: number = 3,
  delayMs: number = 1000
): Promise<Uint8Array> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await downloadFn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delayMs * (attempt + 1)));
      }
    }
  }

  throw new Error(`Download failed after ${maxRetries} attempts: ${lastError?.message}`);
}
```

### Integrity Verification

After download completes, verify the decrypted file hash matches the stored hash:

```typescript
async function verifyFileIntegrity(
  decryptedBlob: Blob,
  expectedHashNonce: Uint8Array,
  encryptedExpectedHash: Uint8Array,
  decryptor: AESGCMDecryptor
): Promise<boolean> {
  // Decrypt the expected hash
  const expectedHash = await decryptor.decryptChunk(
    new Uint8Array([...expectedHashNonce, ...encryptedExpectedHash])
  );

  // Calculate actual hash
  const fileBuffer = await decryptedBlob.arrayBuffer();
  const actualHash = await crypto.subtle.digest('SHA-256', fileBuffer);

  // Compare
  return arraysEqual(new Uint8Array(actualHash), expectedHash);
}
```

---

## Testing Strategy

### Unit Tests

```typescript
// __tests__/crypto/aes-gcm.test.ts

describe('AESGCMDecryptor', () => {
  const testKey = new Uint8Array(32).fill(0x42);
  
  it('should decrypt a valid chunk', async () => {
    const decryptor = await AESGCMDecryptor.fromRawKey(testKey);
    // ... test with known encrypted data
  });

  it('should reject invalid key length', async () => {
    await expect(AESGCMDecryptor.fromRawKey(new Uint8Array(16)))
      .rejects.toThrow('Invalid key length');
  });

  it('should reject tampered ciphertext', async () => {
    const decryptor = await AESGCMDecryptor.fromRawKey(testKey);
    const tamperedChunk = new Uint8Array(100);
    await expect(decryptor.decryptChunk(tamperedChunk))
      .rejects.toThrow('Decryption failed');
  });
});
```

### Integration Tests

```go
// handlers/chunked_download_test.go

func TestChunkedDownload(t *testing.T) {
    // Setup test file with known content
    // Upload using chunked upload
    // Download each chunk individually
    // Verify decrypted content matches original
}

func TestChunkedDownloadResume(t *testing.T) {
    // Upload test file
    // Download first N chunks
    // Simulate interruption
    // Resume from chunk N+1
    // Verify complete file
}
```

### Browser Compatibility Tests

| Browser     | Web Crypto | Streams API | File System Access |
|-------------|------------|-------------|--------------------|
| Chrome 90+  | ✅         | ✅          | ✅                 |
| Firefox 90+ | ✅         | ✅          | ❌ (fallback)      |
| Safari 15+  | ✅         | ✅          | ❌ (fallback)      |
| Edge 90+    | ✅         | ✅          | ✅                 |

---

## Migration Plan

### Phase 1: Database Schema Update

1. Add `chunk_size_bytes` column to `file_metadata` table
2. Update upload handlers to store chunk size
3. Deploy backend changes

### Phase 2: New API Endpoints

1. Implement `/api/files/:fileId/metadata` endpoint
2. Implement `/api/files/:fileId/chunks/:chunkIndex` endpoint
3. Add `GetObjectRange` to storage interface
4. Deploy and test

### Phase 3: TypeScript Client

1. Implement `AESGCMDecryptor` class
2. Implement `StreamingDownloadManager`
3. Add progress UI components
4. Test in all target browsers

### Phase 4: Go CLI Client

1. Implement `StreamingDecryptor`
2. Implement `StreamingDownloader` with resume support
3. Update CLI commands
4. Test on Linux/macOS/Windows

---

## Summary

This implementation provides:

1. **Memory-efficient downloads**: Only one chunk (~16MB) in memory at a time
2. **Progressive feedback**: Real-time progress updates
3. **Resume capability**: Interrupted downloads can continue
4. **Cross-platform**: Works in browsers (TypeScript) and CLI (Go)
5. **Secure**: AES-GCM authentication prevents tampering
6. **Standard APIs**: Uses Web Crypto and Streams API (no WASM required)

---

## List of all files to modify/create/delete:

### **DATABASE SCHEMA**

| File | Action | Description |
|------|--------|-------------|
| `database/unified_schema.sql` | **MODIFY** | Add `chunk_size_bytes INTEGER NOT NULL` column to `file_metadata` table |

---

### **GO BACKEND - Models**

| File | Action | Description |
|------|--------|-------------|
| `models/file.go` | **MODIFY** | Add `ChunkSizeBytes int64` field to `File` struct, update all query functions (`CreateFile`, `GetFileByFileID`, `GetFileByStorageID`, `GetFilesByOwner`), update `FileMetadataForClient` and `ToClientMetadata()` |

---

### **GO BACKEND - Crypto Constants**

| File | Action | Description |
|------|--------|-------------|
| `crypto/constants.go` | **CREATE** | New file with `DefaultChunkSizeBytes`, `AESGCMOverhead`, `EncryptedChunkSize` constants |
| `crypto/gcm.go` | **MODIFY** | May need to reference new constants |

---

### **GO BACKEND - Storage Layer**

| File | Action | Description |
|------|--------|-------------|
| `storage/storage.go` | **MODIFY** | Add `GetObjectRange(ctx, storageID, startByte, endByte, opts)` to `ObjectStorageProvider` interface |
| `storage/s3.go` | **MODIFY** | Implement `GetObjectRange` method using S3 Range header |
| `storage/mock_storage.go` | **MODIFY** | Add mock implementation of `GetObjectRange` for testing |
| `storage/types.go` | **MODIFY** | May need new types for range requests |

---

### **GO BACKEND - Handlers**

| File | Action | Description |
|------|--------|-------------|
| `handlers/downloads.go` | **MODIFY** | Add `DownloadChunk` handler, add `GetFileDownloadMetadata` handler |
| `handlers/route_config.go` | **MODIFY** | Add routes for `/api/files/:fileId/chunks/:chunkIndex` and `/api/files/:fileId/metadata` |
| `handlers/uploads.go` | **MODIFY** | Store `chunk_size_bytes` when creating file metadata during upload completion |

---

### **GO BACKEND - Unit Tests**

| File | Action | Description |
|------|--------|-------------|
| `handlers/chunked_download_test.go` | **CREATE** | New test file for chunked download handlers |
| `handlers/downloads_test.go` | **CREATE** | Tests for download handlers (if doesn't exist) |
| `storage/s3_test.go` | **CREATE/MODIFY** | Tests for `GetObjectRange` |

---

### **GO CLI CLIENT**

| File | Action | Description |
|------|--------|-------------|
| `cmd/arkfile-client/main.go` | **MODIFY** | Add chunked download command with progress and resume support |
| `cmd/arkfile-client/crypto/streaming_decryptor.go` | **CREATE** | New file with `StreamingDecryptor` struct |
| `cmd/arkfile-client/download/streaming_download.go` | **CREATE** | New file with `StreamingDownloader` and `DownloadFileResumable` |

---

### **GO CLI - cryptocli**

| File | Action | Description |
|------|--------|-------------|
| `cmd/cryptocli/main.go` | **MODIFY** | May need new commands for chunk decryption testing |
| `cmd/cryptocli/commands/commands.go` | **MODIFY** | Add chunk-related crypto commands if needed |

---

### **TYPESCRIPT CLIENT - Types**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/types/api.d.ts` | **MODIFY** | Add `FileDownloadMetadata`, `DownloadProgress`, `ChunkDecryptionResult` interfaces |
| `client/static/js/src/crypto/types.ts` | **MODIFY** | Add crypto-related types for streaming decryption |

---

### **TYPESCRIPT CLIENT - Crypto**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/crypto/aes-gcm.ts` | **CREATE** | New file with `AESGCMDecryptor` class using Web Crypto API |
| `client/static/js/src/crypto/constants.ts` | **MODIFY** | Add `AES_GCM_NONCE_SIZE`, `AES_GCM_TAG_SIZE`, `AES_GCM_OVERHEAD` constants |

---

### **TYPESCRIPT CLIENT - Download**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/files/download.ts` | **MODIFY** | Refactor to use `StreamingDownloadManager`, add progress callbacks |
| `client/static/js/src/files/streaming-download.ts` | **CREATE** | New file with `StreamingDownloadManager` class |
| `client/static/js/src/files/transform-stream-decryptor.ts` | **CREATE** | New file with `createDecryptionTransformStream` for advanced streaming |
| `client/static/js/src/files/retry-handler.ts` | **CREATE** | New file with `downloadChunkWithRetry` for error recovery |

---

### **TYPESCRIPT CLIENT - UI**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/ui/progress.ts` | **MODIFY** | Add download progress UI components |
| `client/static/js/src/ui/messages.ts` | **MODIFY** | Add chunk download status messages |

---

### **TYPESCRIPT CLIENT - Shares (if applicable)**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/shares/share-access.ts` | **MODIFY** | Update share download to use chunked approach |

---

### **E2E TESTING**

| File | Action | Description |
|------|--------|-------------|
| `scripts/testing/e2e-test.sh` | **MODIFY** | Add Phase 8.5 or update Phase 8 to test chunked downloads, verify resume capability, test progress reporting |

---

### **TYPESCRIPT UNIT TESTS**

| File | Action | Description |
|------|--------|-------------|
| `client/static/js/src/__tests__/crypto/aes-gcm.test.ts` | **CREATE** | Unit tests for `AESGCMDecryptor` |
| `client/static/js/src/__tests__/files/streaming-download.test.ts` | **CREATE** | Unit tests for `StreamingDownloadManager` |

---

### **DOCUMENTATION**

| File | Action | Description |
|------|--------|-------------|
| `docs/api.md` | **MODIFY** | Document new `/api/files/:fileId/chunks/:chunkIndex` and `/api/files/:fileId/metadata` endpoints |
| `docs/wip/chunk-download.md` | **MODIFY** | Update with implementation notes as work progresses |

---

### Files/Code to DELETE or REPLACE Entirely

| File | Action | Reason |
|------|--------|--------| 
| `handlers/downloads.go` | __REPLACE__ | Current `DownloadFile()` handler will be replaced with chunked download handlers only | 
| `client/static/js/src/files/download.ts` | __REPLACE__ | Current full-file-in-memory approach replaced with streaming |

---

## Implementation Order Recommendation

1. **Phase 1**: Database schema + Models (`unified_schema.sql`, `models/file.go`)
2. **Phase 2**: Storage layer (`storage/storage.go`, `storage/s3.go`, `storage/mock_storage.go`)
3. **Phase 3**: Backend handlers + routes (`handlers/downloads.go`, `handlers/route_config.go`, `handlers/uploads.go`)
4. **Phase 4**: Go CLI client (`cmd/arkfile-client/...`)
5. **Phase 5**: TypeScript crypto + download (`client/static/js/src/crypto/...`, `client/static/js/src/files/...`)
6. **Phase 6**: UI updates (`client/static/js/src/ui/...`)
7. **Phase 7**: Tests (`handlers/*_test.go`, `scripts/testing/e2e-test.sh`, TypeScript tests)
8. **Phase 8**: Documentation updates

---
