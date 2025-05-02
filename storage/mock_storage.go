package storage

import (
	"context"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/mock"
)

// MockObjectStorageProvider is a mock implementation of ObjectStorageProvider using testify/mock
type MockObjectStorageProvider struct {
	mock.Mock
}

// Ensure MockObjectStorageProvider implements ObjectStorageProvider
var _ ObjectStorageProvider = (*MockObjectStorageProvider)(nil)

// PutObject mocks the PutObject method
func (m *MockObjectStorageProvider) PutObject(ctx context.Context, objectName string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	args := m.Called(ctx, objectName, reader, objectSize, opts)
	// Return type assertion based on what you expect PutObject to return
	// Assuming it returns UploadInfo and error
	info, _ := args.Get(0).(minio.UploadInfo) // Get(0) is the first return value
	return info, args.Error(1)                // Error(1) is the second return value (error)
}

// GetObject mocks the GetObject method
func (m *MockObjectStorageProvider) GetObject(ctx context.Context, objectName string, opts minio.GetObjectOptions) (*minio.Object, error) {
	args := m.Called(ctx, objectName, opts)
	// Assuming it returns *minio.Object and error
	obj, _ := args.Get(0).(*minio.Object)
	return obj, args.Error(1)
}

// RemoveObject mocks the RemoveObject method
func (m *MockObjectStorageProvider) RemoveObject(ctx context.Context, objectName string, opts minio.RemoveObjectOptions) error {
	args := m.Called(ctx, objectName, opts)
	return args.Error(0) // Only error is returned
}

// --- Mocking additional methods specific to MinioStorage (if needed for handler tests) ---
// These are not part of the interface but might be called via type assertion in handlers.

// GetPresignedURL mocks the GetPresignedURL method (example)
func (m *MockObjectStorageProvider) GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error) {
	args := m.Called(ctx, objectName, expiry)
	return args.String(0), args.Error(1)
}

// InitiateMultipartUpload mocks the InitiateMultipartUpload method (example)
func (m *MockObjectStorageProvider) InitiateMultipartUpload(ctx context.Context, objectName string, metadata map[string]string) (string, error) {
	args := m.Called(ctx, objectName, metadata)
	return args.String(0), args.Error(1)
}

// UploadPart mocks the UploadPart method (example)
func (m *MockObjectStorageProvider) UploadPart(ctx context.Context, objectName, uploadID string, partNumber int, reader io.Reader, size int64) (minio.CompletePart, error) {
	args := m.Called(ctx, objectName, uploadID, partNumber, reader, size)
	part, _ := args.Get(0).(minio.CompletePart)
	return part, args.Error(1)
}

// CompleteMultipartUpload mocks the CompleteMultipartUpload method (example)
func (m *MockObjectStorageProvider) CompleteMultipartUpload(ctx context.Context, objectName, uploadID string, parts []minio.CompletePart) error {
	args := m.Called(ctx, objectName, uploadID, parts)
	return args.Error(0)
}

// AbortMultipartUpload mocks the AbortMultipartUpload method (example)
func (m *MockObjectStorageProvider) AbortMultipartUpload(ctx context.Context, objectName, uploadID string) error {
	args := m.Called(ctx, objectName, uploadID)
	return args.Error(0)
}

// RemoveChunkedFile mocks the RemoveChunkedFile method (example)
func (m *MockObjectStorageProvider) RemoveChunkedFile(ctx context.Context, filename string, sessionID string) error {
	args := m.Called(ctx, filename, sessionID)
	return args.Error(0)
}

// GetObjectChunk mocks the GetObjectChunk method (example)
func (m *MockObjectStorageProvider) GetObjectChunk(ctx context.Context, objectName string, offset, length int64) (io.ReadCloser, error) {
	args := m.Called(ctx, objectName, offset, length)
	reader, _ := args.Get(0).(io.ReadCloser)
	return reader, args.Error(1)
}
