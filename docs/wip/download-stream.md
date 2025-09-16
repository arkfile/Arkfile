# Download Streaming Refactor Implementation Plan

## Overview and Objectives

The current download system has a critical memory limitation where the `DownloadFile()` function loads entire files into server memory using `io.ReadAll()` before wrapping them in JSON responses. This creates memory exhaustion issues with large files and violates the bounded-memory principles that should govern a file storage system. This refactor will replace the memory-bounded JSON download approach with a chunked streaming system that maintains the zero-knowledge architecture while enabling efficient handling of files of any size.

The refactor will implement fixed 16MB chunk downloads consistent with the existing upload system, provide client-side integrity verification through rolling hash computation, and reorganize handler files for better logical separation of concerns. All cryptographic operations will remain client-side, preserving the zero-knowledge design where the server never has access to plaintext file data, filenames, or user passwords.

## Architectural Decisions

**Chunk-Based Downloads:** Downloads will use fixed 16MB chunks matching the existing upload system for consistency across the application. This provides predictable memory usage, enables resumable downloads, and aligns with the established patterns already proven in the upload flow.

**Metadata-First Approach:** A new metadata endpoint will provide all encrypted file information needed for download initialization as a single source of truth. This eliminates the need to repeat large encrypted metadata headers on every chunk response, reducing bandwidth overhead and preventing header size limit issues with proxies.

**Client-Side Integrity Verification:** The client will compute a rolling SHA-256 hash over downloaded encrypted chunks and compare it against the `encrypted_file_sha256` value from the metadata response. This provides end-to-end transport integrity verification without requiring server-side download session state.

**No Download Sessions:** Unlike uploads which require stateful session tracking for multipart construction, downloads will remain stateless since the complete file already exists. This simplifies the implementation and avoids unnecessary complexity while still achieving the memory-bounded streaming objective.

## Handler File Reorganization

The current handler structure mixes different types of file operations, making it difficult to maintain and extend. The refactor will reorganize functionality into logically consistent files that reflect the different aspects of file management.

**handlers/files.go** will contain core file operations including `ListFiles()` for displaying user files with metadata, `GetFileMeta()` for retrieving encrypted metadata needed for download initialization, and `DeleteFile()` for file removal. The new `GetFileMeta()` function will return a JSON response containing `encrypted_filename`, `filename_nonce`, `encrypted_sha256sum`, `sha256sum_nonce`, `password_hint`, `password_type`, `size_bytes`, `chunk_size` (16MB), `total_chunks`, and `encrypted_file_sha256` for integrity verification.

**handlers/uploads.go** will retain all upload-related functionality including `CreateUploadSession()`, `UploadChunk()`, `CompleteUpload()`, `GetUploadStatus()`, and `CancelUpload()`. The current `DownloadFileChunk()` function will be moved out of this file since it handles downloads, not uploads, despite the current logical grouping.

**handlers/downloads.go** will be created as a new file dedicated to download operations. The existing `DownloadFileChunk()` function will be moved here from `uploads.go` and will handle streaming individual 16MB chunks of encrypted file data. This function already implements proper streaming without memory buffering and sets appropriate headers for chunk identification.

**handlers/file_shares.go** will remain unchanged and continue handling all anonymous file sharing functionality including `CreateFileShare()`, `ListShares()`, `DeleteShare()`, `GetShareInfo()`, `AccessSharedFile()`, and `DownloadSharedFile()`.

**handlers/file_keys.go** will remain unchanged and continue handling file encryption key management operations.

**handlers/handlers.go** will be cleaned up to contain only shared utility functions like `formatBytes()` and `AdminContactsHandler()`. The current memory-bounded `DownloadFile()` function will be removed entirely since it represents the problematic approach being replaced.

## API Endpoint Changes

The refactor will introduce new API endpoints while removing the problematic existing one. A new `GET /api/files/:fileId/meta` endpoint will provide encrypted file metadata and download parameters, requiring authentication and TOTP protection consistent with other sensitive operations. This endpoint will return JSON containing all information needed for the client to initialize decryption and chunk download loops.

The existing `DownloadFileChunk()` function will be exposed through a new route at `GET /api/files/:fileId/chunks/:chunkNumber`. This endpoint will stream raw encrypted bytes for the specified chunk without buffering, include minimal headers for chunk identification (X-Chunk-Number, X-Total-Chunks, X-Last-Chunk), and maintain authentication and TOTP protection requirements.

The current `GET /api/download/:fileId` endpoint that returns JSON-wrapped file data will be removed entirely. Since this is a greenfield project with no existing deployments, backwards compatibility is not required and the problematic endpoint can be eliminated without migration concerns.

## Implementation Steps

**File Structure Changes:** Create the new `handlers/downloads.go` file and move the `DownloadFileChunk()` function from `uploads.go`. Implement the `GetFileMeta()` function in `handlers/files.go` to return encrypted metadata in the format expected by clients. Remove the `DownloadFile()` function from `handlers/handlers.go` entirely.

**Route Configuration:** Update `handlers/route_config.go` to register the new `/api/files/:fileId/meta` and `/api/files/:fileId/chunks/:chunkNumber` routes under the TOTP-protected group. Remove the registration for the legacy `/api/download/:fileId` route.

**Client Integration:** Modify the client-side code to use the new two-step download process. The client will first call the metadata endpoint to retrieve encrypted file information and download parameters, then loop through chunk downloads while maintaining a rolling SHA-256 hash of the encrypted data. Upon completion, the client will compare the computed hash against the `encrypted_file_sha256` value from the metadata response to verify transport integrity.

**Testing Updates:** Update `scripts/testing/test-app-curl.sh` to exercise the new download flow including metadata retrieval, chunk downloading, and client-side integrity verification. Add test cases that verify the memory-bounded behavior with large files to ensure the refactor achieves its primary objective.

## Integrity Verification Details

The client will maintain a rolling SHA-256 hash computation across all downloaded chunks in the correct order. This hash will be computed over the raw encrypted bytes as received from the server, providing verification that the data was not corrupted during transport. The computed hash will be compared against the `encrypted_file_sha256` field returned by the metadata endpoint, which contains the SHA-256 hash of the complete encrypted file as stored on the server.

This approach provides end-to-end integrity verification without requiring server-side state management. The server computes and stores the `encrypted_file_sha256` during upload completion, and the client verifies it during download without the server needing to maintain download session state or recompute hashes.

## Memory and Performance Benefits

The refactor eliminates the memory exhaustion issue by streaming file chunks directly from storage to the client without intermediate buffering. Each chunk request will use bounded memory equal to the 16MB chunk size regardless of total file size. The metadata endpoint requires minimal memory to return encrypted database fields. The overall system memory usage for downloads becomes predictable and bounded rather than scaling linearly with file sizes.

Performance will improve for large files due to eliminated memory allocation overhead and reduced garbage collection pressure. The chunk-based approach also enables potential future enhancements like parallel chunk downloads and resumable transfers without requiring architectural changes.

## Zero-Knowledge Preservation

The refactor maintains all zero-knowledge properties of the existing system. All encryption and decryption operations remain client-side using the Go/WASM implementation. The server never has access to plaintext file data, original filenames, or file content hashes. Encrypted metadata fields are transmitted in the same base64-encoded format as the current implementation. The integrity verification uses hashes of encrypted data rather than plaintext, preserving the zero-knowledge model while enabling transport verification.

## Testing and Validation

The implementation will be validated using the existing development workflow with `sudo bash scripts/dev-reset.sh` for rebuilding and redeployment followed by `sudo bash scripts/testing/test-app-curl.sh` for end-to-end testing. Test cases will specifically verify memory-bounded behavior with large files, chunk boundary handling, metadata consistency, and client-side integrity verification. Integration tests will ensure the new endpoints work correctly with authentication and TOTP requirements.

## Future Considerations

This refactor establishes a foundation for potential future enhancements including resumable downloads through client-side chunk range tracking, parallel chunk downloads for improved performance, and server-side download verification if needed for compliance or auditing purposes. The clean separation between metadata and streaming endpoints provides flexibility for evolving download capabilities while maintaining the core zero-knowledge architecture.