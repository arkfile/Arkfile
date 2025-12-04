# Project MaxIO: MinIO Dependency Removal Plan

## Objective
Completely remove the `github.com/minio/minio-go/v7` dependency from the Arkfile server codebase and replace it with the vendor-neutral `github.com/aws/aws-sdk-go-v2`. This ensures the project is not reliant on a single vendor's library while maintaining compatibility with S3-compatible storage providers (Wasabi, Backblaze, etc.).

## Core Principles
*   **Zero-Knowledge Preservation:** The refactor MUST NOT introduce any server-side decryption or encryption of user data. The server must continue to treat files and metadata as opaque blobs.
*   **Vendor Neutrality:** The new storage implementation must use standard S3 APIs via the official AWS SDK.
*   **Interface Abstraction:** The `ObjectStorageProvider` interface must be decoupled from any specific implementation details (no `minio.*` types in the interface).
*   **Padding Logic Preservation:** The custom padding logic used for encrypted files (adding random bytes to obfuscate exact file size) MUST be preserved exactly as implemented in the original MinIO-based code.

## Implementation Plan

### Phase 1: Interface Decoupling (COMPLETED)
**Goal:** Remove MinIO-specific types from `storage/storage.go`.

1.  **Create Generic Types (`storage/types.go`):** (Done)
    *   Defined `UploadOptions`, `UploadInfo`, `CompletePart`, `ObjectInfo`, etc.
    *   Types support necessary fields (ETags, PartNumbers, UserMetadata).

2.  **Update `ObjectStorageProvider` Interface:** (Done)
    *   Refactored methods to use the new generic types.
    *   Methods updated: `PutObject`, `GetObject`, `InitiateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `RemoveObject`.

3.  **Refactor Handlers:** (Done)
    *   Updated `handlers/uploads.go` to use generic interface methods.
    *   Removed type assertion `storage.Provider.(*storage.MinioStorage)`.
    *   Updated `handlers/downloads.go` to use generic `GetObjectOptions`.

### Phase 2: AWS SDK Implementation (COMPLETED)
**Goal:** Create a new storage provider using AWS SDK v2.

1.  **Add Dependencies:** (Done)
    *   Added `github.com/aws/aws-sdk-go-v2` and related modules.

2.  **Implement `storage/s3_aws.go`:** (Done)
    *   Created `S3AWSStorage` struct implementing `ObjectStorageProvider`.
    *   Mapped generic types to AWS SDK types.
    *   Implemented all interface methods using the AWS SDK client.
    *   **Critical:** Preserved padding logic in `PutObjectWithPadding` and `CompleteMultipartUploadWithPadding` by extracting shared logic into `storage/helpers.go` and ensuring `S3AWSStorage` uses the same `PaddingReader` and size calculation logic.

3.  **Shared Logic Extraction:** (Done)
    *   Created `storage/helpers.go` to hold `PaddingReader` and `HashingReader` structs, allowing them to be shared between the old `minio.go` (temporarily) and the new `s3_aws.go`.

### Phase 3: Switch & Cleanup (COMPLETED)
**Goal:** Activate the new provider and remove old code.

1.  **Update Initialization:** (Done)
    *   Updated `main.go` to use `InitS3` (renamed from `InitS3AWS`).
    *   Verified configuration loading works with the new provider.

2.  **Verify & Test:** (Done)
    *   Ran unit tests (`go test ./handlers/...`) - **PASSED**.
    *   Verified static library builds for `libopaque` and `liboprf` required for tests.

3.  **Remove MinIO:** (Done)
    *   Deleted `storage/minio.go`.
    *   Ran `go mod tidy` to remove `minio-go` from `go.mod`.
    *   Renamed `storage/s3_aws.go` to `storage/s3.go` for clarity.

## Verification Checklist
- [x] `go.mod` does not contain `minio-go`.
- [x] All `handlers/` code uses generic `storage.*` types.
- [x] `S3AWSStorage` implements `ObjectStorageProvider`.
- [x] Padding logic verified to be identical to original implementation.
- [x] Unit tests (`go test ./handlers/...`) pass.
- [ ] `e2e-test.sh` passes successfully.
- [x] No server-side decryption logic introduced.
