package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// newTestRegistry creates a registry with the given primary (required), optional secondary and tertiary.
func newTestRegistry(primary *MockObjectStorageProvider, primaryID string) *ProviderRegistry {
	return NewProviderRegistry(primary, primaryID)
}

// newMockStoredObject creates a MockStoredObject with content and a Close expectation.
func newMockStoredObject(content string) *MockStoredObject {
	obj := &MockStoredObject{}
	obj.SetContent(content)
	obj.On("Close").Return(nil)
	return obj
}

// --- GetProvider tests ---

func TestGetProvider_Primary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	assert.Equal(t, primary, reg.GetProvider("primary-1"))
}

func TestGetProvider_Secondary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")
	assert.Equal(t, secondary, reg.GetProvider("secondary-1"))
}

func TestGetProvider_Tertiary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	tertiary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	reg.SetTertiary(tertiary, "tertiary-1")
	assert.Equal(t, tertiary, reg.GetProvider("tertiary-1"))
}

func TestGetProvider_NotFound(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	assert.Nil(t, reg.GetProvider("nonexistent"))
}

// --- HasSecondary / HasTertiary tests ---

func TestHasSecondary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	assert.False(t, reg.HasSecondary())

	secondary := new(MockObjectStorageProvider)
	reg.SetSecondary(secondary, "secondary-1")
	assert.True(t, reg.HasSecondary())
}

func TestHasTertiary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	assert.False(t, reg.HasTertiary())

	tertiary := new(MockObjectStorageProvider)
	reg.SetTertiary(tertiary, "tertiary-1")
	assert.True(t, reg.HasTertiary())
}

// --- SwapPrimarySecondary tests ---

func TestSwapPrimarySecondary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	assert.Equal(t, "primary-1", reg.PrimaryID())
	assert.Equal(t, "secondary-1", reg.SecondaryID())
	assert.Equal(t, primary, reg.Primary())
	assert.Equal(t, secondary, reg.Secondary())

	reg.SwapPrimarySecondary()

	assert.Equal(t, "secondary-1", reg.PrimaryID())
	assert.Equal(t, "primary-1", reg.SecondaryID())
	assert.Equal(t, secondary, reg.Primary())
	assert.Equal(t, primary, reg.Secondary())
}

// --- GetObjectWithFallback tests ---

func TestGetObjectWithFallback_PrimarySucceeds(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	obj := newMockStoredObject("hello")
	primary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)

	reg := newTestRegistry(primary, "primary-1")
	result, providerID, err := reg.GetObjectWithFallback(context.Background(), "test-obj", GetObjectOptions{})

	assert.NoError(t, err)
	assert.Equal(t, "primary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
	primary.AssertExpectations(t)
}

func TestGetObjectWithFallback_PrimaryFails_SecondarySucceeds(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)

	primary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("primary down"))
	obj := newMockStoredObject("hello from secondary")
	secondary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	result, providerID, err := reg.GetObjectWithFallback(context.Background(), "test-obj", GetObjectOptions{})

	assert.NoError(t, err)
	assert.Equal(t, "secondary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
	primary.AssertExpectations(t)
	secondary.AssertExpectations(t)
}

func TestGetObjectWithFallback_PrimaryAndSecondaryFail_TertiarySucceeds(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)
	tertiary := new(MockObjectStorageProvider)

	primary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("primary down"))
	secondary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("secondary down"))
	obj := newMockStoredObject("hello from tertiary")
	tertiary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")
	reg.SetTertiary(tertiary, "tertiary-1")

	result, providerID, err := reg.GetObjectWithFallback(context.Background(), "test-obj", GetObjectOptions{})

	assert.NoError(t, err)
	assert.Equal(t, "tertiary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
}

func TestGetObjectWithFallback_AllFail(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)
	tertiary := new(MockObjectStorageProvider)

	primary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("primary down"))
	secondary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("secondary down"))
	tertiary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("tertiary down"))

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")
	reg.SetTertiary(tertiary, "tertiary-1")

	result, providerID, err := reg.GetObjectWithFallback(context.Background(), "test-obj", GetObjectOptions{})

	assert.Error(t, err)
	assert.Empty(t, providerID)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "all providers failed")
}

func TestGetObjectWithFallback_SingleProvider_Fails(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	primaryErr := errors.New("primary down")
	primary.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), primaryErr)

	reg := newTestRegistry(primary, "primary-1")
	result, providerID, err := reg.GetObjectWithFallback(context.Background(), "test-obj", GetObjectOptions{})

	assert.Error(t, err)
	assert.Equal(t, primaryErr, err)
	assert.Empty(t, providerID)
	assert.Nil(t, result)
}

// --- GetObjectChunkWithFallback tests ---

func TestGetObjectChunkWithFallback_PrimarySucceeds(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reader := io.NopCloser(bytes.NewReader([]byte("chunk-data")))
	primary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(reader, nil)

	reg := newTestRegistry(primary, "primary-1")
	result, providerID, err := reg.GetObjectChunkWithFallback(context.Background(), "test-obj", 0, 100)

	assert.NoError(t, err)
	assert.Equal(t, "primary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
}

func TestGetObjectChunkWithFallback_FallbackToSecondary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)

	primary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(nil, errors.New("primary down"))
	reader := io.NopCloser(bytes.NewReader([]byte("chunk-from-secondary")))
	secondary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(reader, nil)

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	result, providerID, err := reg.GetObjectChunkWithFallback(context.Background(), "test-obj", 0, 100)

	assert.NoError(t, err)
	assert.Equal(t, "secondary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
}

func TestGetObjectChunkWithFallback_FallbackToTertiary(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)
	tertiary := new(MockObjectStorageProvider)

	primary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(nil, errors.New("primary down"))
	secondary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(nil, errors.New("secondary down"))
	reader := io.NopCloser(bytes.NewReader([]byte("chunk-from-tertiary")))
	tertiary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(reader, nil)

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")
	reg.SetTertiary(tertiary, "tertiary-1")

	result, providerID, err := reg.GetObjectChunkWithFallback(context.Background(), "test-obj", 0, 100)

	assert.NoError(t, err)
	assert.Equal(t, "tertiary-1", providerID)
	assert.NotNil(t, result)
	result.Close()
}

func TestGetObjectChunkWithFallback_AllFail(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)

	primary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(nil, errors.New("primary down"))
	secondary.On("GetObjectChunk", mock.Anything, "test-obj", int64(0), int64(100)).Return(nil, errors.New("secondary down"))

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	_, providerID, err := reg.GetObjectChunkWithFallback(context.Background(), "test-obj", 0, 100)

	assert.Error(t, err)
	assert.Empty(t, providerID)
	assert.Contains(t, err.Error(), "all providers failed")
}

// --- RemoveObjectAll tests ---

func TestRemoveObjectAll_AllSucceed(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)

	primary.On("RemoveObject", mock.Anything, "obj-1", RemoveObjectOptions{}).Return(nil)
	secondary.On("RemoveObject", mock.Anything, "obj-1", RemoveObjectOptions{}).Return(nil)

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	locations := []RemoveLocation{
		{ProviderID: "primary-1", StorageID: "obj-1"},
		{ProviderID: "secondary-1", StorageID: "obj-1"},
	}
	results := reg.RemoveObjectAll(context.Background(), locations)

	assert.Len(t, results, 2)
	assert.True(t, results[0].Success)
	assert.True(t, results[1].Success)
	assert.Nil(t, results[0].Error)
	assert.Nil(t, results[1].Error)
}

func TestRemoveObjectAll_PartialFailure(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	secondary := new(MockObjectStorageProvider)

	primary.On("RemoveObject", mock.Anything, "obj-1", RemoveObjectOptions{}).Return(nil)
	secondary.On("RemoveObject", mock.Anything, "obj-1", RemoveObjectOptions{}).Return(errors.New("delete failed"))

	reg := newTestRegistry(primary, "primary-1")
	reg.SetSecondary(secondary, "secondary-1")

	locations := []RemoveLocation{
		{ProviderID: "primary-1", StorageID: "obj-1"},
		{ProviderID: "secondary-1", StorageID: "obj-1"},
	}
	results := reg.RemoveObjectAll(context.Background(), locations)

	assert.Len(t, results, 2)
	assert.True(t, results[0].Success)
	assert.False(t, results[1].Success)
	assert.NotNil(t, results[1].Error)
}

func TestRemoveObjectAll_ProviderNotFound(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")

	locations := []RemoveLocation{
		{ProviderID: "nonexistent", StorageID: "obj-1"},
	}
	results := reg.RemoveObjectAll(context.Background(), locations)

	assert.Len(t, results, 1)
	assert.False(t, results[0].Success)
	assert.Contains(t, results[0].Error.Error(), "not found in registry")
}

func TestRemoveObjectAll_EmptyLocations(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "primary-1")

	results := reg.RemoveObjectAll(context.Background(), []RemoveLocation{})
	assert.Empty(t, results)
}

// --- CopyObjectBetweenProviders tests ---

func TestCopyObjectBetweenProviders_SmallObject(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	// Source returns an object with known content
	content := "hello world test data"
	obj := newMockStoredObject(content)
	source.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)

	// Destination accepts the PutObject call
	dest.On("PutObject", mock.Anything, "test-obj", mock.Anything, int64(len(content)), mock.Anything).Return(UploadInfo{}, nil)

	reg := newTestRegistry(source, "source-1")

	hash, err := reg.CopyObjectBetweenProviders(
		context.Background(), "test-obj", source, dest, int64(len(content)), nil,
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	// SHA-256 hash should be 64 hex characters
	assert.Len(t, hash, 64)

	source.AssertExpectations(t)
	dest.AssertExpectations(t)
}

func TestCopyObjectBetweenProviders_SourceFails(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	source.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return((*MockStoredObject)(nil), errors.New("source unreachable"))

	reg := newTestRegistry(source, "source-1")

	hash, err := reg.CopyObjectBetweenProviders(
		context.Background(), "test-obj", source, dest, 100, nil,
	)

	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.Contains(t, err.Error(), "failed to get object from source")
}

func TestCopyObjectBetweenProviders_DestFails(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	content := "test data"
	obj := newMockStoredObject(content)
	source.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)
	dest.On("PutObject", mock.Anything, "test-obj", mock.Anything, int64(len(content)), mock.Anything).Return(UploadInfo{}, errors.New("dest write failed"))

	reg := newTestRegistry(source, "source-1")

	hash, err := reg.CopyObjectBetweenProviders(
		context.Background(), "test-obj", source, dest, int64(len(content)), nil,
	)

	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.Contains(t, err.Error(), "failed to put object to destination")
}

func TestCopyObjectBetweenProviders_ProgressCallback(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	content := "progress test data"
	obj := newMockStoredObject(content)
	source.On("GetObject", mock.Anything, "test-obj", GetObjectOptions{}).Return(obj, nil)
	dest.On("PutObject", mock.Anything, "test-obj", mock.Anything, int64(len(content)), mock.Anything).Return(UploadInfo{}, nil)

	reg := newTestRegistry(source, "source-1")

	var progressCalls []int64
	onProgress := func(bytesCopied int64) {
		progressCalls = append(progressCalls, bytesCopied)
	}

	_, err := reg.CopyObjectBetweenProviders(
		context.Background(), "test-obj", source, dest, int64(len(content)), onProgress,
	)

	assert.NoError(t, err)
	// For small objects, progress is called once with the full size
	assert.Len(t, progressCalls, 1)
	assert.Equal(t, int64(len(content)), progressCalls[0])
}

func TestCopyObjectBetweenProviders_ConsistentHash(t *testing.T) {
	// Verify that copying the same content produces the same hash
	source1 := new(MockObjectStorageProvider)
	source2 := new(MockObjectStorageProvider)
	dest1 := new(MockObjectStorageProvider)
	dest2 := new(MockObjectStorageProvider)

	content := "deterministic hash test"
	obj1 := newMockStoredObject(content)
	obj2 := newMockStoredObject(content)

	source1.On("GetObject", mock.Anything, "obj-a", GetObjectOptions{}).Return(obj1, nil)
	source2.On("GetObject", mock.Anything, "obj-b", GetObjectOptions{}).Return(obj2, nil)
	dest1.On("PutObject", mock.Anything, "obj-a", mock.Anything, int64(len(content)), mock.Anything).Return(UploadInfo{}, nil)
	dest2.On("PutObject", mock.Anything, "obj-b", mock.Anything, int64(len(content)), mock.Anything).Return(UploadInfo{}, nil)

	reg := newTestRegistry(source1, "s1")

	hash1, err1 := reg.CopyObjectBetweenProviders(context.Background(), "obj-a", source1, dest1, int64(len(content)), nil)
	hash2, err2 := reg.CopyObjectBetweenProviders(context.Background(), "obj-b", source2, dest2, int64(len(content)), nil)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, hash1, hash2)
}

// --- HeadObject tests (used by verify-all) ---

func TestHeadObject_Success(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	primary.On("HeadObject", mock.Anything, "test-obj").Return(int64(12345), nil)

	reg := newTestRegistry(primary, "primary-1")
	provider := reg.GetProvider("primary-1")
	size, err := provider.HeadObject(context.Background(), "test-obj")

	assert.NoError(t, err)
	assert.Equal(t, int64(12345), size)
	primary.AssertExpectations(t)
}

func TestHeadObject_NotFound(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	primary.On("HeadObject", mock.Anything, "missing-obj").Return(int64(0), errors.New("object not found"))

	reg := newTestRegistry(primary, "primary-1")
	provider := reg.GetProvider("primary-1")
	size, err := provider.HeadObject(context.Background(), "missing-obj")

	assert.Error(t, err)
	assert.Equal(t, int64(0), size)
	assert.Contains(t, err.Error(), "not found")
	primary.AssertExpectations(t)
}

// --- CopyObjectBetweenProviders large object (multipart) tests ---

func TestCopyObjectBetweenProviders_LargeObject_Multipart(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	// Create content larger than CopyMultipartThreshold (5 MB).
	// We use a real buffer here to exercise the multipart read path.
	// 150 MB = 2 full 64MB parts + 1 partial 22MB part = 3 parts total.
	objectSize := int64(150 * 1024 * 1024)
	content := make([]byte, objectSize)
	// Fill with a pattern so hashing is deterministic
	for i := range content {
		content[i] = byte(i % 251)
	}

	obj := &MockStoredObject{}
	obj.Content = bytes.NewReader(content)
	obj.On("Close").Return(nil)
	source.On("GetObject", mock.Anything, "large-obj", GetObjectOptions{}).Return(obj, nil)

	// Destination multipart sequence
	uploadID := "test-upload-id-123"
	dest.On("InitiateMultipartUpload", mock.Anything, "large-obj", mock.Anything).Return(uploadID, nil)

	// Expect 3 UploadPart calls: part 1 (64MB), part 2 (64MB), part 3 (22MB)
	part1Size := int64(CopyMultipartPartSize)       // 64 MB
	part2Size := int64(CopyMultipartPartSize)       // 64 MB
	part3Size := objectSize - part1Size - part2Size // 22 MB

	dest.On("UploadPart", mock.Anything, "large-obj", uploadID, 1, mock.Anything, part1Size).
		Return(CompletePart{PartNumber: 1, ETag: "etag-1"}, nil)
	dest.On("UploadPart", mock.Anything, "large-obj", uploadID, 2, mock.Anything, part2Size).
		Return(CompletePart{PartNumber: 2, ETag: "etag-2"}, nil)
	dest.On("UploadPart", mock.Anything, "large-obj", uploadID, 3, mock.Anything, part3Size).
		Return(CompletePart{PartNumber: 3, ETag: "etag-3"}, nil)

	expectedParts := []CompletePart{
		{PartNumber: 1, ETag: "etag-1"},
		{PartNumber: 2, ETag: "etag-2"},
		{PartNumber: 3, ETag: "etag-3"},
	}
	dest.On("CompleteMultipartUpload", mock.Anything, "large-obj", uploadID, expectedParts).Return(nil)

	reg := newTestRegistry(source, "source-1")

	var progressCalls []int64
	onProgress := func(bytesCopied int64) {
		progressCalls = append(progressCalls, bytesCopied)
	}

	hash, err := reg.CopyObjectBetweenProviders(
		context.Background(), "large-obj", source, dest, objectSize, onProgress,
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA-256 hex = 64 chars

	// Progress should be called once per part (3 parts)
	assert.Len(t, progressCalls, 3)
	assert.Equal(t, part1Size, progressCalls[0])
	assert.Equal(t, part1Size+part2Size, progressCalls[1])
	assert.Equal(t, objectSize, progressCalls[2])

	source.AssertExpectations(t)
	dest.AssertExpectations(t)
}

func TestCopyObjectBetweenProviders_LargeObject_PartUploadFails(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	objectSize := int64(150 * 1024 * 1024)
	content := make([]byte, objectSize)
	for i := range content {
		content[i] = byte(i % 251)
	}

	obj := &MockStoredObject{}
	obj.Content = bytes.NewReader(content)
	obj.On("Close").Return(nil)
	source.On("GetObject", mock.Anything, "large-fail-obj", GetObjectOptions{}).Return(obj, nil)

	uploadID := "fail-upload-id"
	dest.On("InitiateMultipartUpload", mock.Anything, "large-fail-obj", mock.Anything).Return(uploadID, nil)

	// First part succeeds, second part fails
	dest.On("UploadPart", mock.Anything, "large-fail-obj", uploadID, 1, mock.Anything, int64(CopyMultipartPartSize)).
		Return(CompletePart{PartNumber: 1, ETag: "etag-1"}, nil)
	dest.On("UploadPart", mock.Anything, "large-fail-obj", uploadID, 2, mock.Anything, int64(CopyMultipartPartSize)).
		Return(CompletePart{}, errors.New("upload part 2 failed"))
	dest.On("AbortMultipartUpload", mock.Anything, "large-fail-obj", uploadID).Return(nil)

	reg := newTestRegistry(source, "source-1")

	hash, err := reg.CopyObjectBetweenProviders(
		context.Background(), "large-fail-obj", source, dest, objectSize, nil,
	)

	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.Contains(t, err.Error(), "failed to upload part 2")

	source.AssertExpectations(t)
	dest.AssertExpectations(t)
}

func TestCopyObjectBetweenProviders_LargeObject_Cancellation(t *testing.T) {
	source := new(MockObjectStorageProvider)
	dest := new(MockObjectStorageProvider)

	objectSize := int64(200 * 1024 * 1024)
	content := make([]byte, objectSize)

	obj := &MockStoredObject{}
	obj.Content = bytes.NewReader(content)
	obj.On("Close").Return(nil)
	source.On("GetObject", mock.Anything, "cancel-obj", GetObjectOptions{}).Return(obj, nil)

	uploadID := "cancel-upload-id"
	dest.On("InitiateMultipartUpload", mock.Anything, "cancel-obj", mock.Anything).Return(uploadID, nil)

	// First part succeeds
	dest.On("UploadPart", mock.Anything, "cancel-obj", uploadID, 1, mock.Anything, int64(CopyMultipartPartSize)).
		Return(CompletePart{PartNumber: 1, ETag: "etag-1"}, nil)
	dest.On("AbortMultipartUpload", mock.Anything, "cancel-obj", uploadID).Return(nil)

	reg := newTestRegistry(source, "source-1")

	// Create a context that we cancel after part 1
	ctx, cancel := context.WithCancel(context.Background())
	onProgress := func(bytesCopied int64) {
		// Cancel after first part is uploaded
		if bytesCopied >= int64(CopyMultipartPartSize) {
			cancel()
		}
	}

	hash, err := reg.CopyObjectBetweenProviders(
		ctx, "cancel-obj", source, dest, objectSize, onProgress,
	)

	assert.Error(t, err)
	assert.Empty(t, hash)
	assert.ErrorIs(t, err, context.Canceled)

	source.AssertExpectations(t)
	// AbortMultipartUpload should have been called
	dest.AssertCalled(t, "AbortMultipartUpload", mock.Anything, "cancel-obj", uploadID)
}

// --- ID accessor tests ---

func TestIDAccessors(t *testing.T) {
	primary := new(MockObjectStorageProvider)
	reg := newTestRegistry(primary, "my-primary")

	assert.Equal(t, "my-primary", reg.PrimaryID())
	assert.Empty(t, reg.SecondaryID())
	assert.Empty(t, reg.TertiaryID())

	secondary := new(MockObjectStorageProvider)
	reg.SetSecondary(secondary, "my-secondary")
	assert.Equal(t, "my-secondary", reg.SecondaryID())

	tertiary := new(MockObjectStorageProvider)
	reg.SetTertiary(tertiary, "my-tertiary")
	assert.Equal(t, "my-tertiary", reg.TertiaryID())
}
