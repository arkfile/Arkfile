package storage

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockObjectStorageProvider is a mock implementation of ObjectStorageProvider using testify/mock
type MockObjectStorageProvider struct {
	mock.Mock
}

// Ensure MockObjectStorageProvider implements ObjectStorageProvider
var _ ObjectStorageProvider = (*MockObjectStorageProvider)(nil)

// PutObject mocks the PutObject method
func (m *MockObjectStorageProvider) PutObject(ctx context.Context, objectName string, reader io.Reader, objectSize int64, opts PutObjectOptions) (UploadInfo, error) {
	args := m.Called(ctx, objectName, reader, objectSize, opts)
	// Return type assertion based on what you expect PutObject to return
	// Assuming it returns UploadInfo and error
	info, _ := args.Get(0).(UploadInfo) // Get(0) is the first return value
	return info, args.Error(1)          // Error(1) is the second return value (error)
}

// GetObject mocks the GetObject method
// IMPORTANT: Changed return type to ReadableStoredObject to match the interface
func (m *MockObjectStorageProvider) GetObject(ctx context.Context, objectName string, opts GetObjectOptions) (ReadableStoredObject, error) {
	args := m.Called(ctx, objectName, opts)
	// Assert the type we are actually returning in the test setup (*MockStoredObject),
	// which satisfies the ReadableStoredObject interface.
	obj, _ := args.Get(0).(*MockStoredObject)
	// Need to handle the case where args.Get(0) is nil or not *MockStoredObject
	if obj == nil {
		// If the test didn't provide a MockStoredObject (e.g., returning an error),
		// return nil for the interface value.
		return nil, args.Error(1)
	}
	return obj, args.Error(1)
}

// RemoveObject mocks the RemoveObject method
func (m *MockObjectStorageProvider) RemoveObject(ctx context.Context, objectName string, opts RemoveObjectOptions) error {
	args := m.Called(ctx, objectName, opts)
	return args.Error(0) // Only error is returned
}

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
func (m *MockObjectStorageProvider) UploadPart(ctx context.Context, objectName, uploadID string, partNumber int, reader io.Reader, size int64) (CompletePart, error) {
	args := m.Called(ctx, objectName, uploadID, partNumber, reader, size)
	part, _ := args.Get(0).(CompletePart)
	return part, args.Error(1)
}

// CompleteMultipartUpload mocks the CompleteMultipartUpload method (example)
func (m *MockObjectStorageProvider) CompleteMultipartUpload(ctx context.Context, objectName, uploadID string, parts []CompletePart) error {
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

// PutObjectWithPadding mocks the PutObjectWithPadding method
func (m *MockObjectStorageProvider) PutObjectWithPadding(ctx context.Context, storageID string, reader io.Reader, originalSize, paddedSize int64, opts PutObjectOptions) (UploadInfo, error) {
	args := m.Called(ctx, storageID, reader, originalSize, paddedSize, opts)
	info, _ := args.Get(0).(UploadInfo)
	return info, args.Error(1)
}

// GetObjectWithoutPadding mocks the GetObjectWithoutPadding method
func (m *MockObjectStorageProvider) GetObjectWithoutPadding(ctx context.Context, storageID string, originalSize int64, opts GetObjectOptions) (io.ReadCloser, error) {
	args := m.Called(ctx, storageID, originalSize, opts)
	reader, _ := args.Get(0).(io.ReadCloser)
	return reader, args.Error(1)
}

// CompleteMultipartUploadWithPadding mocks the CompleteMultipartUploadWithPadding method
func (m *MockObjectStorageProvider) CompleteMultipartUploadWithPadding(ctx context.Context, storageID, uploadID string, parts []CompletePart, originalSize, paddedSize int64) error {
	args := m.Called(ctx, storageID, uploadID, parts, originalSize, paddedSize)
	return args.Error(0)
}

// Phase 3: CompleteMultipartUploadWithEnvelope mocks the CompleteMultipartUploadWithEnvelope method
func (m *MockObjectStorageProvider) CompleteMultipartUploadWithEnvelope(ctx context.Context, storageID, uploadID string, parts []CompletePart, envelope []byte, originalSize, paddedSize int64) error {
	args := m.Called(ctx, storageID, uploadID, parts, envelope, originalSize, paddedSize)
	return args.Error(0)
}

// Mock Stored Object
// MockStoredObject mocks the object returned by GetObject
type MockStoredObject struct {
	mock.Mock
	Content *bytes.Reader // Use bytes.Reader to simulate readable content
	Info    ObjectInfo    // Store ObjectInfo directly
	StatErr error         // Optional error for Stat
}

// Ensure MockStoredObject implements necessary interfaces (io.ReadCloser, potentially others)
var _ io.ReadCloser = (*MockStoredObject)(nil)

// Read mocks the Read method of the stored object
// It prioritizes reading from the internal Content buffer if set.
func (m *MockStoredObject) Read(p []byte) (n int, err error) {
	// If Content is set, use its Read method directly. This simulates reading the actual data.
	if m.Content != nil {
		return m.Content.Read(p)
	}
	// Otherwise, fall back to the standard testify/mock behavior.
	// This allows testing scenarios where Read might error without setting content.
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

// Close mocks the Close method of the stored object
func (m *MockStoredObject) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Stat mocks the Stat method of the stored object, returning stored info/error
func (m *MockStoredObject) Stat() (ObjectInfo, error) {
	// No need for testify's .Called() here, return directly
	return m.Info, m.StatErr
}

// Helpers to set content and stat info for MockStoredObject

// SetStatInfo sets the ObjectInfo and error to be returned by Stat()
func (m *MockStoredObject) SetStatInfo(info ObjectInfo, err error) {
	m.Info = info
	m.StatErr = err
}

func (m *MockStoredObject) SetContent(content string) {
	m.Content = bytes.NewReader([]byte(content))
}
