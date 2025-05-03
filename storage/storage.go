package storage

import (
	"context"
	"io"

	"github.com/minio/minio-go/v7"
)

// ReadableStoredObject defines the minimal interface needed to read, close, and stat a stored object.
// This is used as the return type for GetObject to allow easier mocking.
type ReadableStoredObject interface {
	io.ReadCloser
	Stat() (minio.ObjectInfo, error)
}

// ObjectStorageProvider defines the interface for object storage operations.
// Renamed from StorageProvider to avoid conflict with provider type constants.
// This allows mocking the storage layer for testing.
// Bucket name is handled by the implementation, not passed in methods.
type ObjectStorageProvider interface {
	PutObject(ctx context.Context, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	// GetObject retrieves an object satisfying the ReadableStoredObject interface.
	GetObject(ctx context.Context, objectName string, opts minio.GetObjectOptions) (ReadableStoredObject, error)
	RemoveObject(ctx context.Context, objectName string, opts minio.RemoveObjectOptions) error
	// Add other storage methods used by the application here if needed,
	// e.g., ListObjects, StatObject, etc.
}

// Global object storage provider instance (will be initialized with Minio or mock)
// Consider using dependency injection instead for larger applications.
var Provider ObjectStorageProvider
