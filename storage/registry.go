package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

// CopyMultipartPartSize is the part size used for multipart uploads during
// cross-provider copy operations. This is independent of the client-side
// encryption chunk size (which is optimized for encrypt/decrypt streaming).
// Copy operations move raw S3 data, so larger parts reduce API calls and
// improve throughput. Adjust this value if copy performance needs tuning.
// Current value: 64 MB.
const CopyMultipartPartSize = 64 * 1024 * 1024

// CopyMultipartThreshold is the object size above which cross-provider copies
// use multipart upload on the destination instead of a single PutObject call.
// Objects at or below this size use a single PUT. Adjust alongside
// CopyMultipartPartSize if copy behavior needs tuning. Current value: 100 MB.
const CopyMultipartThreshold = 100 * 1024 * 1024

// CopyProgressFunc is called during cross-provider copy operations to report
// bytes transferred so far. Used by the task runner to update progress in the DB.
type CopyProgressFunc func(bytesCopied int64)

// ProviderRegistry holds references to the primary and optional secondary/tertiary
// ObjectStorageProvider instances. It replaces the single global Provider as the
// primary interface for handler code.
type ProviderRegistry struct {
	primary     ObjectStorageProvider
	secondary   ObjectStorageProvider // nil in single-provider mode
	tertiary    ObjectStorageProvider // nil if not configured
	primaryID   string                // e.g. "seaweedfs-local"
	secondaryID string                // e.g. "wasabi-us-central-1"
	tertiaryID  string                // e.g. "backblaze-us-west"
}

// Registry is the global provider registry instance.
var Registry *ProviderRegistry

// NewProviderRegistry creates a new ProviderRegistry with the given primary provider.
// Secondary and tertiary providers are optional and can be nil.
func NewProviderRegistry(primary ObjectStorageProvider, primaryID string) *ProviderRegistry {
	return &ProviderRegistry{
		primary:   primary,
		primaryID: primaryID,
	}
}

// SetSecondary configures the secondary provider.
func (r *ProviderRegistry) SetSecondary(provider ObjectStorageProvider, id string) {
	r.secondary = provider
	r.secondaryID = id
}

// SetTertiary configures the tertiary provider.
func (r *ProviderRegistry) SetTertiary(provider ObjectStorageProvider, id string) {
	r.tertiary = provider
	r.tertiaryID = id
}

// Primary returns the primary provider. Used by upload handlers.
func (r *ProviderRegistry) Primary() ObjectStorageProvider {
	return r.primary
}

// Secondary returns the secondary provider, or nil if not configured.
func (r *ProviderRegistry) Secondary() ObjectStorageProvider {
	return r.secondary
}

// Tertiary returns the tertiary provider, or nil if not configured.
func (r *ProviderRegistry) Tertiary() ObjectStorageProvider {
	return r.tertiary
}

// HasSecondary returns true if a secondary provider is configured and active.
func (r *ProviderRegistry) HasSecondary() bool {
	return r.secondary != nil
}

// HasTertiary returns true if a tertiary provider is configured and active.
func (r *ProviderRegistry) HasTertiary() bool {
	return r.tertiary != nil
}

// PrimaryID returns the human-readable primary provider ID.
func (r *ProviderRegistry) PrimaryID() string {
	return r.primaryID
}

// SecondaryID returns the human-readable secondary provider ID.
func (r *ProviderRegistry) SecondaryID() string {
	return r.secondaryID
}

// TertiaryID returns the human-readable tertiary provider ID.
func (r *ProviderRegistry) TertiaryID() string {
	return r.tertiaryID
}

// SwapPrimarySecondary swaps the primary and secondary providers in the in-memory
// registry. Used on startup when the DB role assignments (from a previous
// swap-providers or set-primary command) differ from the env-var ordering.
func (r *ProviderRegistry) SwapPrimarySecondary() {
	r.primary, r.secondary = r.secondary, r.primary
	r.primaryID, r.secondaryID = r.secondaryID, r.primaryID
}

// GetProvider returns the provider instance matching the given ID, or nil if not found.
func (r *ProviderRegistry) GetProvider(providerID string) ObjectStorageProvider {
	switch providerID {
	case r.primaryID:
		return r.primary
	case r.secondaryID:
		return r.secondary
	case r.tertiaryID:
		return r.tertiary
	default:
		return nil
	}
}

// GetObjectWithFallback attempts to GET from primary. On failure, tries secondary,
// then tertiary. Returns the object, the provider ID that served it, and any error.
func (r *ProviderRegistry) GetObjectWithFallback(ctx context.Context, objectName string, opts GetObjectOptions) (ReadableStoredObject, string, error) {
	// Try primary
	obj, err := r.primary.GetObject(ctx, objectName, opts)
	if err == nil {
		return obj, r.primaryID, nil
	}
	primaryErr := err

	// Try secondary if available
	if r.secondary != nil {
		log.Printf("Primary provider %s failed for GetObject(%s), trying secondary %s: %v", r.primaryID, objectName, r.secondaryID, primaryErr)
		obj, err = r.secondary.GetObject(ctx, objectName, opts)
		if err == nil {
			return obj, r.secondaryID, nil
		}
		log.Printf("Secondary provider %s also failed for GetObject(%s): %v", r.secondaryID, objectName, err)

		// Try tertiary if available
		if r.tertiary != nil {
			log.Printf("Trying tertiary provider %s for GetObject(%s)", r.tertiaryID, objectName)
			obj, err = r.tertiary.GetObject(ctx, objectName, opts)
			if err == nil {
				return obj, r.tertiaryID, nil
			}
			log.Printf("Tertiary provider %s also failed for GetObject(%s): %v", r.tertiaryID, objectName, err)
			return nil, "", fmt.Errorf("all providers failed for GetObject(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
		}

		return nil, "", fmt.Errorf("all providers failed for GetObject(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
	}

	// Single provider mode, just return the primary error
	return nil, "", primaryErr
}

// CopyObjectBetweenProviders streams data from source to destination S3 without
// writing to disk. A SHA-256 hash is computed during the stream via TeeReader for
// integrity verification against stored_blob_sha256sum. Returns the computed
// SHA-256 hex string and any error.
//
// For objects <= CopyMultipartThreshold (100 MB), a single PutObject call is used.
// For larger objects, multipart upload is used with CopyMultipartPartSize (64 MB) parts.
func (r *ProviderRegistry) CopyObjectBetweenProviders(
	ctx context.Context,
	objectName string,
	source ObjectStorageProvider,
	destination ObjectStorageProvider,
	objectSize int64,
	onProgress CopyProgressFunc,
) (string, error) {
	// Get the full object from source
	obj, err := source.GetObject(ctx, objectName, GetObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get object from source: %w", err)
	}
	defer obj.Close()

	// Wrap source reader with SHA-256 TeeReader for single-pass hash verification
	hasher := sha256.New()
	hashingReader := io.TeeReader(obj, hasher)

	if objectSize <= CopyMultipartThreshold {
		// Small object: buffer into seekable reader then single PUT.
		// Buffering is required because AWS SDK v2 needs a seekable body for
		// SigV4 payload signing on non-TLS (HTTP) destinations like local SeaweedFS.
		// Max buffer size is CopyMultipartThreshold (100 MB).
		buf, readErr := io.ReadAll(hashingReader)
		if readErr != nil {
			return "", fmt.Errorf("failed to read object from source: %w", readErr)
		}
		_, err = destination.PutObject(ctx, objectName, bytes.NewReader(buf), objectSize, PutObjectOptions{
			ContentType: "application/octet-stream",
		})
		if err != nil {
			return "", fmt.Errorf("failed to put object to destination: %w", err)
		}
		if onProgress != nil {
			onProgress(objectSize)
		}
	} else {
		// Large object: multipart upload on destination
		uploadID, err := destination.InitiateMultipartUpload(ctx, objectName, map[string]string{
			"copy-source": "cross-provider-copy",
		})
		if err != nil {
			return "", fmt.Errorf("failed to initiate multipart upload on destination: %w", err)
		}

		var parts []CompletePart
		partNumber := 1
		remaining := objectSize

		for remaining > 0 {
			// Check for cancellation between parts
			if ctx.Err() != nil {
				destination.AbortMultipartUpload(ctx, objectName, uploadID)
				return "", ctx.Err()
			}

			partSize := int64(CopyMultipartPartSize)
			if remaining < partSize {
				partSize = remaining
			}

			// Read part data into a seekable buffer. AWS SDK v2 needs seekable
			// readers for SigV4 payload signing on non-TLS (HTTP) destinations.
			// Memory bounded: max 64 MB per part, released after upload.
			partData := make([]byte, partSize)
			n, readErr := io.ReadFull(hashingReader, partData)
			if readErr != nil && readErr != io.ErrUnexpectedEOF {
				destination.AbortMultipartUpload(ctx, objectName, uploadID)
				return "", fmt.Errorf("failed to read part %d from source: %w", partNumber, readErr)
			}
			partData = partData[:n]

			part, err := destination.UploadPart(ctx, objectName, uploadID, partNumber, bytes.NewReader(partData), int64(n))
			if err != nil {
				destination.AbortMultipartUpload(ctx, objectName, uploadID)
				return "", fmt.Errorf("failed to upload part %d to destination: %w", partNumber, err)
			}

			parts = append(parts, part)
			partNumber++
			remaining -= partSize
			if onProgress != nil {
				onProgress(objectSize - remaining)
			}
		}

		if err := destination.CompleteMultipartUpload(ctx, objectName, uploadID, parts); err != nil {
			return "", fmt.Errorf("failed to complete multipart upload on destination: %w", err)
		}
	}

	// Finalize hash
	hashHex := hex.EncodeToString(hasher.Sum(nil))
	return hashHex, nil
}

// RemoveLocation describes a provider-specific location to delete an object from.
type RemoveLocation struct {
	ProviderID string
	StorageID  string
}

// RemoveResult describes the outcome of removing an object from one provider.
type RemoveResult struct {
	ProviderID string
	Success    bool
	Error      error
}

// RemoveObjectAll removes the object from all specified provider locations.
// Returns a result for each location attempted. Failures are logged but do not
// prevent attempts on remaining providers.
func (r *ProviderRegistry) RemoveObjectAll(ctx context.Context, locations []RemoveLocation) []RemoveResult {
	results := make([]RemoveResult, 0, len(locations))
	for _, loc := range locations {
		provider := r.GetProvider(loc.ProviderID)
		if provider == nil {
			log.Printf("RemoveObjectAll: provider %s not found in registry for object %s", loc.ProviderID, loc.StorageID)
			results = append(results, RemoveResult{
				ProviderID: loc.ProviderID,
				Success:    false,
				Error:      fmt.Errorf("provider %s not found in registry", loc.ProviderID),
			})
			continue
		}

		err := provider.RemoveObject(ctx, loc.StorageID, RemoveObjectOptions{})
		if err != nil {
			log.Printf("RemoveObjectAll: failed to remove object %s from provider %s: %v", loc.StorageID, loc.ProviderID, err)
			results = append(results, RemoveResult{
				ProviderID: loc.ProviderID,
				Success:    false,
				Error:      err,
			})
		} else {
			results = append(results, RemoveResult{
				ProviderID: loc.ProviderID,
				Success:    true,
			})
		}
	}
	return results
}

// GetObjectChunkWithFallback attempts chunked GET from primary, then secondary,
// then tertiary. Returns the chunk reader, the provider ID that served it, and any error.
func (r *ProviderRegistry) GetObjectChunkWithFallback(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, string, error) {
	// Try primary
	reader, err := r.primary.GetObjectChunk(ctx, objectName, offset, length)
	if err == nil {
		return reader, r.primaryID, nil
	}
	primaryErr := err

	// Try secondary if available
	if r.secondary != nil {
		log.Printf("Primary provider %s failed for GetObjectChunk(%s), trying secondary %s: %v", r.primaryID, objectName, r.secondaryID, primaryErr)
		reader, err = r.secondary.GetObjectChunk(ctx, objectName, offset, length)
		if err == nil {
			return reader, r.secondaryID, nil
		}
		log.Printf("Secondary provider %s also failed for GetObjectChunk(%s): %v", r.secondaryID, objectName, err)

		// Try tertiary if available
		if r.tertiary != nil {
			log.Printf("Trying tertiary provider %s for GetObjectChunk(%s)", r.tertiaryID, objectName)
			reader, err = r.tertiary.GetObjectChunk(ctx, objectName, offset, length)
			if err == nil {
				return reader, r.tertiaryID, nil
			}
			log.Printf("Tertiary provider %s also failed for GetObjectChunk(%s): %v", r.tertiaryID, objectName, err)
			return nil, "", fmt.Errorf("all providers failed for GetObjectChunk(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
		}

		return nil, "", fmt.Errorf("all providers failed for GetObjectChunk(%s): primary(%s): %v", objectName, r.primaryID, primaryErr)
	}

	// Single provider mode
	return nil, "", primaryErr
}
