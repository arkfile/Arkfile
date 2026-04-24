package storage

import (
	"context"
	"io"
	"time"
)

// ReadableStoredObject defines the minimal interface needed to read, close, and stat a stored object.
// This is used as the return type for GetObject to allow easier mocking.
type ReadableStoredObject interface {
	io.ReadCloser
	Stat() (ObjectInfo, error)
}

// ObjectStorageProvider defines the interface for object storage operations.
// Renamed from StorageProvider to avoid conflict with provider type constants.
// This allows mocking the storage layer for testing.
// Bucket name is handled by the implementation, not passed in methods.
type ObjectStorageProvider interface {
	PutObject(ctx context.Context, objectName string, reader io.Reader, objectSize int64, opts PutObjectOptions) (UploadInfo, error)
	// GetObject retrieves an object satisfying the ReadableStoredObject interface.
	GetObject(ctx context.Context, objectName string, opts GetObjectOptions) (ReadableStoredObject, error)
	RemoveObject(ctx context.Context, objectName string, opts RemoveObjectOptions) error
	GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error)
	InitiateMultipartUpload(ctx context.Context, objectName string, metadata map[string]string) (string, error)
	UploadPart(ctx context.Context, objectName, uploadID string, partNumber int, reader io.Reader, size int64) (CompletePart, error)
	CompleteMultipartUpload(ctx context.Context, objectName, uploadID string, parts []CompletePart) error
	AbortMultipartUpload(ctx context.Context, objectName, uploadID string) error
	GetObjectChunk(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, error)
	// HeadObject returns the size of an object in bytes without downloading it.
	// Returns an error if the object does not exist.
	HeadObject(ctx context.Context, objectName string) (int64, error)
}
