package storage

import (
	"fmt"
	"time"
)

// PutObjectOptions represents options for putting an object
type PutObjectOptions struct {
	UserMetadata map[string]string
	ContentType  string
}

// UploadInfo represents information about a successful upload
type UploadInfo struct {
	Key  string
	ETag string
	Size int64
}

// GetObjectOptions represents options for getting an object
type GetObjectOptions struct {
	// Range header settings
	startOffset int64
	endOffset   int64
	hasRange    bool
}

// SetRange sets the byte range to retrieve
func (o *GetObjectOptions) SetRange(start, end int64) error {
	if start < 0 || (end >= 0 && start > end) {
		return fmt.Errorf("invalid range specified: start=%d end=%d", start, end)
	}
	o.startOffset = start
	o.endOffset = end
	o.hasRange = true
	return nil
}

// GetRange returns the start and end offsets and whether a range is set
func (o *GetObjectOptions) GetRange() (int64, int64, bool) {
	return o.startOffset, o.endOffset, o.hasRange
}

// ObjectInfo represents information about a stored object
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	ContentType  string
	UserMetadata map[string]string
}

// RemoveObjectOptions represents options for removing an object
type RemoveObjectOptions struct {
	Force bool // Bypass governance mode if applicable
}

// CompletePart represents a completed part of a multipart upload
type CompletePart struct {
	PartNumber int
	ETag       string
}

// Constants for storage provider types
type StorageProvider string

const (
	ProviderBackblaze    StorageProvider = "backblaze"
	ProviderWasabi       StorageProvider = "wasabi"
	ProviderVultr        StorageProvider = "vultr"
	ProviderCloudflareR2 StorageProvider = "cloudflare-r2"
	ProviderAmazonS3     StorageProvider = "aws-s3"
	ProviderGenericS3    StorageProvider = "generic-s3"
)
