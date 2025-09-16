## **Arkfile Streaming Download Fix - Complete Implementation Plan**

The current arkfile implementation suffers from critical memory scaling issues where the `DownloadFile` endpoint in `handlers/handlers.go` uses `io.ReadAll(reader)` to load entire files (including 10GB+ file sizes) into server memory before responding, leading to server crashes, memory exhaustion, and blocked concurrent downloads. To fix this, we need to implement streaming downloads that stream file data directly from MinIO to clients without buffering on the server.

### Core API Changes
Replace the current JSON-based file download API with a direct binary streaming endpoint that bypasses JSON serialization overhead and memory buffering. The new `DownloadFileStreaming` handler will call `GetObjectWithoutPadding()` (already optimized for streaming) and use `c.Stream()` to pipe data directly to clients, enabling scalable downloads of any file size without server-side memory pressure.

### Go Codebase Updates
**handlers/handlers.go** requires the main `DownloadFile` function to be rewrote or supplemented with `DownloadFileStreaming` that implements direct HTTP streaming instead of JSON wrapping, while **handlers/route_config.go** needs route updates to expose the new streaming endpoint. The **storage/minio.go** `GetObjectWithoutPadding` function is already streamlined for streaming and can remain unchanged. **models/ file.go** and **models/file_share.go** may need updates to support alternative metadata delivery mechanism (HTTP headers vs JSON payload).

### Client Updates  
**cmd/arkfile-client/main.go** `handleDownloadCommand` currently implements JSON-based downloads and must be adapted to handle binary streams, with metadata possibly delivered via HTTP headers instead of JSON response body. The **crypto/file_operations.go** padding removal logic is already stream-aware and won't require changes.

### Testing Infrastructure
Comprehensive unit tests should be added in **handlers/handlers_test.go** for the new streaming handler to verify correct HTTP streaming behavior, and **storage/minio_test.go** should include tests for stream padding removal. Integration tests in **handlers/files_test.go** and **crypto/file_operations_test.go** need updates to validate end-to-end streaming with various file sizes. All existing CSV upload tests should remain functional.

### Bash Script Updates
**scripts/testing/admin-auth-test.sh** and **scripts/testing/test-app-curl.sh** may require updates to test both JSON and streaming download APIs to ensure backward compatibility. **scripts/testing/test-typescript.sh** and **scripts/testing/test-wasm.sh** are likely unaffected. **scripts/complete-setup-test.sh** could benefit from adding infrastructure validation for streaming capability and large file handling.

### Configuration and Build
**config/config.go** may need settings to toggle between streaming and JSON modes for incremental rollout. **scripts/setup/build.sh** should include version markers indicating streaming support and **main.go** initialization might need updates for any new streaming-related dependencies.

### Optional Enhancements
Consider implementing HTTP range requests support for file seeking, content-length headers for progress indicators, and compression negotiation between client/server for network efficiency. Add metrics collection in **logging/logging.go** and **monitoring/health_endpoints.go** to track streaming performance versus JSON API usage.

### Migration Strategy
Maintain backward compatibility by keeping existing JSON API active during transition, with gradual client-side migration to binary streaming. Add feature flags in **config/dependency-hashes.json** to control rollout and validate through **utils/environment.go** checks. After successful production testing with 1-10GB files, the JSON API can be deprecated and eventually removed.

This architectural change transforms arkfile from a memory-bounded JSON-based API to a truly scalable binary streaming service capable of handling enterprise-scale file operations without memory constraints.