# Multi-Backend Object Storage

Design document for multi-provider storage redundancy in Arkfile.

## Overview

This feature adds support for up to three simultaneous S3-compatible storage backends (primary, secondary, and tertiary), enabling encrypted blob redundancy, download fallback, and zero-downtime provider migration. The three-tier model provides automatic replication between primary and secondary, manual copy operations to/from any provider including tertiary, and a three-level download fallback chain. All multi-backend operations are admin-only and controlled via the arkfile-admin CLI through the Admin API.

## Motivation

1. **Operational resilience**: If the primary storage provider experiences downtime, file downloads automatically fall back to the secondary provider (and then tertiary if secondary also fails). Users experience no interruption.

2. **Provider risk mitigation**: Storage providers can change pricing, terms, or availability at any time. With multi-backend support, the admin can add a new provider, copy all data to it, and decommission the old provider without any downtime or data loss. This eliminates vendor lock-in.

3. **Data redundancy**: Encrypted blobs stored identically across two or three independent providers provide an additional layer of protection against data loss beyond what any single provider offers.

4. **Non-disruptive**: The feature is entirely opt-in. When no secondary provider is configured, the system behaves identically to today (single-provider mode). No changes are required to client-side code, crypto, or user-facing functionality.

## Design Principles

- **Additive, not destructive**: No existing tables are modified. New tables are added. Existing single-provider deployments continue to work without configuration changes.
- **Admin-only**: All multi-backend management is performed through arkfile-admin CLI commands that hit Admin API endpoints. Nothing is surfaced to end users at this stage.
- **Encrypted blobs are opaque**: The same client-side-encrypted blob (identified by storage_id) can be PUT to any number of S3-compatible backends. No re-encryption or transformation is needed.
- **Task-based async operations**: All copy operations (bulk or individual) return a task ID immediately. The server performs the work in background goroutines. The admin polls task status.
- **Provider-ID is the identity, not provider-type**: Two backends can use the same provider type (e.g., both `wasabi`) with different regions, endpoints, buckets, and credentials. Each is identified by its unique `provider_id` (e.g., `wasabi-us-central-1`, `wasabi-eu-central-2`). The system treats them as fully independent backends.
- **Three-tier provider roles**: The system supports up to three providers with distinct roles: Primary (receives all uploads), Secondary (auto-replication target, download fallback), and Tertiary (manual copy/move target only, final download fallback). Only Primary and Secondary participate in automatic replication. Tertiary is available for admin-initiated copy operations and serves as a third-tier download fallback. Any provider can be promoted to any role.

### Three-Tier Role Reference

| Role | Uploads | Auto-Replication Target | Download Fallback | Manual Copy Target | Promotable To |
|-----------|---------|-------------------------|-------------------|--------------------|-------------------|
| Primary   | Yes     | N/A (source)            | 1st attempt       | Yes                | N/A               |
| Secondary | No      | Yes (background sync)   | 2nd attempt       | Yes                | Primary           |
| Tertiary  | No      | No (manual only)        | 3rd attempt       | Yes                | Primary, Secondary|

## Current Architecture (Single Provider)

The current storage layer uses a single global `storage.Provider` (type `ObjectStorageProvider`) initialized by `storage.InitS3()` on server startup. Configuration is read from environment variables (`STORAGE_PROVIDER`, `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`).

The `ObjectStorageProvider` interface defines: `PutObject`, `GetObject`, `RemoveObject`, `GetObjectChunk`, `GetPresignedURL`, `InitiateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`.

There are 17 call sites across the codebase that reference `storage.Provider.XXX()`:
- `handlers/uploads.go` -- multipart upload lifecycle, delete file, size mismatch cleanup
- `handlers/downloads.go` -- chunked file download (owner)
- `handlers/file_shares.go` -- chunked file download (share recipient)
- `handlers/export.go` -- full object download for backup export
- `cmd/arkfile-admin/verify_storage.go` -- storage connectivity verification

Each file in the database has a `storage_id` (UUID v4) which is the S3 object key. The `file_metadata` table tracks file ownership, encrypted metadata, and size information but does not record which provider or bucket holds the blob.

## Configuration and Environment Variables

### Primary Provider (Existing -- No Changes)

The existing environment variables continue to configure the primary storage provider:

```
STORAGE_PROVIDER=generic-s3
STORAGE_PROVIDER_ID=seaweedfs-local        # Optional human-readable ID (auto-generated if not set)
S3_ENDPOINT=http://localhost:9332
S3_ACCESS_KEY=arkfile-local
S3_SECRET_KEY=your_secret_here
S3_BUCKET=arkfile-local
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
```

If `STORAGE_PROVIDER_ID` is not set, the system auto-generates it as `"{STORAGE_PROVIDER}:{S3_BUCKET}"` (e.g. `"generic-s3:arkfile-local"`).

Note: For the primary provider, some endpoints can be auto-derived from the region (e.g., Wasabi endpoint from `S3_REGION`, Vultr endpoint from `S3_REGION`). This auto-generation logic lives in the env-var reading code that calls the `NewS3Provider` factory, not inside the factory itself.

### Secondary Provider (New -- Optional)

The three-tier model supports an optional secondary provider configured with a parallel set of environment variables prefixed with `STORAGE_2_`. The secondary provider serves as the automatic replication target and second-tier download fallback.

For all non-primary providers, `STORAGE_2_ENDPOINT` is required. Unlike the primary provider where some endpoints can be derived from region, secondary and tertiary providers always require an explicit endpoint.

```
STORAGE_PROVIDER_2=backblaze
STORAGE_PROVIDER_2_ID=backblaze-us-west    # Optional human-readable ID
STORAGE_2_ENDPOINT=s3.us-west-004.backblazeb2.com
STORAGE_2_ACCESS_KEY=your_key_id
STORAGE_2_SECRET_KEY=your_application_key
STORAGE_2_BUCKET=arkfile-backup
STORAGE_2_REGION=us-west-004
STORAGE_2_FORCE_PATH_STYLE=false
```

When `STORAGE_PROVIDER_2` is not set or empty, the system operates in single-provider mode. All multi-backend features are disabled and behavior is identical to the current implementation.

### Tertiary Provider (New -- Optional)

An optional tertiary provider is configured with `STORAGE_3_` prefixed environment variables. The tertiary provider is a manual-only copy target and serves as the third-tier download fallback. It does not participate in automatic upload replication.

```
STORAGE_PROVIDER_3=backblaze
STORAGE_PROVIDER_3_ID=backblaze-eu-west
STORAGE_3_ENDPOINT=s3.eu-west-004.backblazeb2.com
STORAGE_3_ACCESS_KEY=your_key_id
STORAGE_3_SECRET_KEY=your_application_key
STORAGE_3_BUCKET=arkfile-archive
STORAGE_3_REGION=eu-west-004
STORAGE_3_FORCE_PATH_STYLE=false
```

When `STORAGE_PROVIDER_3` is not set or empty, the system operates in two-provider mode (or single-provider if secondary is also unconfigured). The tertiary provider requires a configured secondary provider; you cannot have a tertiary without a secondary.

### Replication Flag

```
ENABLE_UPLOAD_REPLICATION=false
```

When set to `true` and a secondary provider is configured, newly uploaded files are automatically replicated to the secondary provider only via a background goroutine after the primary upload completes. The tertiary provider is never an automatic replication target. The upload response is returned to the user as soon as the primary upload succeeds; secondary replication happens asynchronously. If secondary replication fails, the file is recorded with status `"active"` on primary and `"failed"` on secondary, and the admin can retry via the `copy-file` command.

To populate the tertiary provider, use manual copy operations (`copy-all`, `copy-user-files`, `copy-file`) via the admin CLI.

### Provider-Specific Variable Overrides

For providers with their own credential variable names (Cloudflare R2, Backblaze B2), the secondary and tertiary configs use a consistent `STORAGE_2_` / `STORAGE_3_` prefix:

```
# Cloudflare R2 as secondary
STORAGE_PROVIDER_2=cloudflare-r2
STORAGE_2_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com
STORAGE_2_ACCESS_KEY=your_access_key_id
STORAGE_2_SECRET_KEY=your_secret_access_key
STORAGE_2_BUCKET=your-bucket-name

# Backblaze B2 as tertiary
STORAGE_PROVIDER_3=backblaze
STORAGE_3_ENDPOINT=s3.us-west-004.backblazeb2.com
STORAGE_3_ACCESS_KEY=your_key_id
STORAGE_3_SECRET_KEY=your_application_key
STORAGE_3_BUCKET=your-bucket-name
```

Note: The same provider type can appear in multiple slots. For example, primary and secondary can both be `wasabi` with different regions, endpoints, buckets, and credentials. Each is uniquely identified by its `provider_id`, not its `provider_type`.

The refactored `InitS3()` function reads env vars for primary, secondary (if configured), and tertiary (if configured), calling `NewS3Provider()` up to three times. It maps the unified `STORAGE_2_` / `STORAGE_3_` variables to the provider-specific SDK configuration internally.

---

## Schema Changes

Two new tables are added. No existing tables are modified.

### `storage_providers` Table

Tracks configured storage providers as first-class database entities. This allows the admin API to query and manage providers without relying solely on environment variables at runtime.

```sql
CREATE TABLE IF NOT EXISTS storage_providers (
    provider_id TEXT PRIMARY KEY,
    provider_type TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'us-east-1',
    role TEXT NOT NULL DEFAULT 'tertiary',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_storage_providers_role ON storage_providers(role);
CREATE INDEX IF NOT EXISTS idx_storage_providers_active ON storage_providers(is_active);
```

The `role` column replaces the previous `is_primary` boolean design. Valid values are `'primary'`, `'secondary'`, and `'tertiary'`. Constraints: only one provider can have `role = 'primary'`, only one can have `role = 'secondary'`, any number can be `'tertiary'` (though v1 supports at most one tertiary via env vars; the DB schema is N-capable for future expansion).

On startup, the server upserts rows for the configured primary (and optional secondary/tertiary) provider. The `role` field indicates each provider's current role. The `set-primary`, `set-secondary`, and `swap-providers` admin commands update this field.

### `file_storage_locations` Table

A join table that tracks which providers hold a copy of each file's encrypted blob. This is the core table that enables multi-backend awareness.

```sql
CREATE TABLE IF NOT EXISTS file_storage_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id VARCHAR(36) NOT NULL,
    provider_id TEXT NOT NULL,
    storage_id VARCHAR(36) NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES storage_providers(provider_id)
);

CREATE INDEX IF NOT EXISTS idx_fsl_file_id ON file_storage_locations(file_id);
CREATE INDEX IF NOT EXISTS idx_fsl_provider_id ON file_storage_locations(provider_id);
CREATE INDEX IF NOT EXISTS idx_fsl_status ON file_storage_locations(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fsl_file_provider ON file_storage_locations(file_id, provider_id);
```

Key fields:
- `file_id`: References `file_metadata.file_id`.
- `provider_id`: References `storage_providers.provider_id`.
- `storage_id`: The S3 object key (same UUID used across all providers for the same file).
- `status`: One of `"active"`, `"pending"`, `"failed"`, `"deleted"`. `"active"` means the blob is confirmed present. `"pending"` means a copy operation is in progress. `"failed"` means a copy was attempted but did not succeed.
- `verified_at`: Timestamp of the last successful integrity check (optional, for future use).

The unique index on `(file_id, provider_id)` ensures each file can only have one location record per provider.

### `admin_tasks` Table

Tracks background task progress for long-running admin operations (copy-all, copy-user-files, copy-file).

```sql
CREATE TABLE IF NOT EXISTS admin_tasks (
    task_id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_username TEXT NOT NULL,
    progress_current INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_tasks_status ON admin_tasks(status);
CREATE INDEX IF NOT EXISTS idx_admin_tasks_type ON admin_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_admin_tasks_admin ON admin_tasks(admin_username);
```

Key fields:
- `task_id`: UUID v4 returned to the admin CLI immediately.
- `task_type`: One of `"copy-all"`, `"copy-user-files"`, `"copy-file"`.
- `status`: One of `"pending"`, `"running"`, `"completed"`, `"failed"`, `"canceled"`.
- `progress_current` / `progress_total`: Integer counters (e.g. files copied / total files).
- `details`: JSON text field for task-specific metadata (e.g. source provider, destination provider, username filter, direction).
- `error_message`: Populated on failure with a description of what went wrong.

---

## Storage Layer Changes

### New File: `storage/registry.go`

The `ProviderRegistry` replaces the single global `storage.Provider` as the primary interface for handler code. It holds references to the primary and optional secondary and tertiary `ObjectStorageProvider` instances and provides high-level methods for redundant operations.

```go
type ProviderRegistry struct {
    primary     ObjectStorageProvider
    secondary   ObjectStorageProvider  // nil in single-provider mode
    tertiary    ObjectStorageProvider  // nil if not configured
    primaryID   string                // e.g. "seaweedfs-local"
    secondaryID string                // e.g. "backblaze-us-west"
    tertiaryID  string                // e.g. "backblaze-eu-west"
}

var Registry *ProviderRegistry
```

The existing `storage.Provider` global is retained as a backward-compatible alias that points to `Registry.primary`. This allows incremental migration of call sites without a big-bang refactor.

#### Registry Methods

**GetProvider(providerID string) ObjectStorageProvider** -- Returns the provider instance matching the given ID, or nil if not found. Used by admin copy operations to target a specific provider.

**Primary() ObjectStorageProvider** -- Returns the primary provider. Used by upload handlers.

**Secondary() ObjectStorageProvider** -- Returns the secondary provider, or nil if not configured.

**Tertiary() ObjectStorageProvider** -- Returns the tertiary provider, or nil if not configured.

**HasSecondary() bool** -- Returns true if a secondary provider is configured and active.

**HasTertiary() bool** -- Returns true if a tertiary provider is configured and active.

**PrimaryID() string** / **SecondaryID() string** / **TertiaryID() string** -- Return the human-readable provider IDs.

**GetObjectWithFallback(ctx, objectName, opts) (ReadableStoredObject, string, error)** -- Attempts to GET from primary. On failure, if secondary exists, attempts GET from secondary. On failure, if tertiary exists, attempts GET from tertiary. Returns the object, the provider ID that served it, and any error. Used by download and share download handlers.

**GetObjectChunkWithFallback(ctx, objectName, offset, length) (io.ReadCloser, string, error)** -- Same three-tier fallback pattern for chunked reads. Returns the chunk reader, the provider ID that served it, and any error.

**RemoveObjectAll(ctx, objectName, opts) error** -- Removes the object from all providers that have active `file_storage_locations` records. Logs warnings for partial failures but returns an error only if the primary deletion fails. The caller is responsible for updating `file_storage_locations` records.

### Modified File: `storage/s3.go`

Extract the S3 client creation logic from `InitS3()` into a reusable factory function that accepts a config struct:

```go
type S3ProviderConfig struct {
    ProviderType   StorageProvider
    ProviderID     string
    Endpoint       string  // Always explicit, no auto-generation inside factory
    AccessKey      string
    SecretKey      string
    Bucket         string
    Region         string
    ForcePathStyle bool
}

func NewS3Provider(config S3ProviderConfig) (*S3AWSStorage, error)
```

The factory takes explicit parameters via the config struct rather than reading from environment variables, allowing it to be called up to three times with different configurations (once for primary, once for secondary, once for tertiary).

Note: Endpoint auto-generation for Wasabi/Vultr from region stays in the env-var reading code that *calls* the factory, not inside the factory itself. The factory always receives a fully-resolved endpoint.

The existing `InitS3()` function is refactored to:
1. Read primary env vars, auto-generate endpoint if needed, and call `NewS3Provider()` to create the primary provider.
2. If `STORAGE_PROVIDER_2` is set, read secondary env vars and call `NewS3Provider()` to create the secondary provider.
3. If `STORAGE_PROVIDER_3` is set, read tertiary env vars and call `NewS3Provider()` to create the tertiary provider.
4. Build a `ProviderRegistry` with all configured providers.
5. Set `Registry = &ProviderRegistry{...}` and `Provider = Registry.primary` for backward compatibility.
6. Ensure the primary bucket exists (existing behavior). If secondary/tertiary are configured, ensure their buckets exist too (for `generic-s3` / local providers).

### Modified File: `storage/storage.go`

Add the `Registry` global alongside the existing `Provider` global:

```go
var Provider ObjectStorageProvider   // Backward-compatible, points to primary
var Registry *ProviderRegistry       // New: holds primary + optional secondary + optional tertiary
```

### Modified File: `storage/mock_storage.go`

Add a `MockProviderRegistry` for testing that wraps up to three `MockObjectStorageProvider` instances and implements the same registry methods. This allows handler tests to verify three-tier fallback behavior, multi-delete behavior, etc.

---

## Handler Updates

All 17 `storage.Provider.XXX()` call sites are updated to use the registry. The changes follow consistent patterns per operation type.

### Upload Flow (`handlers/uploads.go`)

**CreateUploadSession** -- No storage changes needed. This only creates DB records and initiates a multipart upload on the primary provider. The call to `storage.Provider.InitiateMultipartUpload()` becomes `storage.Registry.Primary().InitiateMultipartUpload()`.

**UploadChunk** -- The call to `storage.Provider.UploadPart()` becomes `storage.Registry.Primary().UploadPart()`. Chunks are only uploaded to the primary during the active upload session.

**CompleteUpload** -- After the primary multipart upload completes successfully:
1. Insert a `file_storage_locations` row with `provider_id = Registry.PrimaryID()`, `status = "active"`.
2. If `ENABLE_UPLOAD_REPLICATION` is true and `Registry.HasSecondary()`:
   - Insert a second `file_storage_locations` row with `provider_id = Registry.SecondaryID()`, `status = "pending"`.
   - Kick off a background goroutine that streams the completed object from primary to secondary using `CopyObjectBetweenProviders()` (a new registry helper).
   - On success, update the secondary location row to `status = "active"`.
   - On failure, update to `status = "failed"` and log the error.
   - Note: Tertiary is never an auto-replication target. To populate tertiary, use manual copy operations.
3. The HTTP response is returned immediately after the primary upload completes and the primary location is recorded. The user does not wait for secondary replication.

**CancelUpload** -- The call to `storage.Provider.AbortMultipartUpload()` becomes `storage.Registry.Primary().AbortMultipartUpload()`. No secondary/tertiary involvement since the upload was never completed.

### Delete Flow (`handlers/uploads.go` -- `DeleteFile`)

The current single `storage.Provider.RemoveObject()` call is replaced with:
1. Query `file_storage_locations` for all locations of this file.
2. For each location with `status = "active"`, call `RemoveObject()` on the corresponding provider (could be 1, 2, or 3 providers).
3. Update each location row to `status = "deleted"` (or delete the row entirely).
4. If removal fails on one provider but succeeds on others, log a warning but still proceed with the DB record deletion. The file is considered deleted from the user's perspective.
5. Delete the `file_metadata` row and update storage usage as before.

### Owner Download Flow (`handlers/downloads.go` -- `DownloadFileChunk`)

The call to `storage.Provider.GetObjectChunk()` is replaced with `storage.Registry.GetObjectChunkWithFallback()`. The three-tier fallback logic is transparent to the handler: if the primary fails, the secondary is tried, then the tertiary. The handler receives the chunk reader and streams it to the client as before.

### Share Download Flow (`handlers/file_shares.go` -- `DownloadShareChunk`)

Same pattern as owner download. The call to `storage.Provider.GetObjectChunk()` becomes `storage.Registry.GetObjectChunkWithFallback()`.

### Export Flow (`handlers/export.go`)

The call to `storage.Provider.GetObject()` becomes `storage.Registry.GetObjectWithFallback()`. Same three-tier fallback pattern.

### Size Mismatch Cleanup (`handlers/uploads.go` -- `CompleteUpload`)

The existing `storage.Provider.RemoveObject()` call for size mismatch cleanup becomes `storage.Registry.Primary().RemoveObject()`. Since the upload only ever goes to primary, cleanup only needs to target primary.

### Summary of Call Site Changes

| File | Function | Current Call | New Call |
|------|----------|-------------|---------|
| uploads.go | CreateUploadSession | `Provider.InitiateMultipartUpload()` | `Registry.Primary().InitiateMultipartUpload()` |
| uploads.go | CreateUploadSession (rollback) | `Provider.AbortMultipartUpload()` | `Registry.Primary().AbortMultipartUpload()` |
| uploads.go | CancelUpload | `Provider.AbortMultipartUpload()` | `Registry.Primary().AbortMultipartUpload()` |
| uploads.go | UploadChunk | `Provider.UploadPart()` | `Registry.Primary().UploadPart()` |
| uploads.go | CompleteUpload | `Provider.CompleteMultipartUpload()` | `Registry.Primary().CompleteMultipartUpload()` |
| uploads.go | CompleteUpload (mismatch) | `Provider.RemoveObject()` | `Registry.Primary().RemoveObject()` |
| uploads.go | DeleteFile | `Provider.RemoveObject()` | `Registry.RemoveObjectAll()` + location updates |
| downloads.go | DownloadFileChunk | `Provider.GetObjectChunk()` | `Registry.GetObjectChunkWithFallback()` |
| file_shares.go | DownloadShareChunk | `Provider.GetObjectChunk()` | `Registry.GetObjectChunkWithFallback()` |
| export.go | ExportFile | `Provider.GetObject()` | `Registry.GetObjectWithFallback()` |

---

## Admin API Endpoints

All endpoints below are admin-only, protected by the existing admin auth middleware. They are implemented in a new file `handlers/admin_storage.go`.

### `GET /api/admin/storage/status`

Returns the current storage configuration and sync status. The response can include up to 3 providers, each with a `role` field indicating its current role.

**Response:**
```json
{
    "providers": [
        {
            "provider_id": "seaweedfs-local",
            "provider_type": "generic-s3",
            "bucket_name": "arkfile-local",
            "role": "primary",
            "is_active": true,
            "file_count": 142,
            "active_count": 142,
            "pending_count": 0,
            "failed_count": 0
        },
        {
            "provider_id": "wasabi-us-central-1",
            "provider_type": "wasabi",
            "bucket_name": "arkfile-backup",
            "role": "secondary",
            "is_active": true,
            "file_count": 138,
            "active_count": 138,
            "pending_count": 2,
            "failed_count": 2
        },
        {
            "provider_id": "backblaze-eu-west",
            "provider_type": "backblaze",
            "bucket_name": "arkfile-archive",
            "role": "tertiary",
            "is_active": true,
            "file_count": 50,
            "active_count": 50,
            "pending_count": 0,
            "failed_count": 0
        }
    ],
    "total_files": 142,
    "fully_replicated": 138,
    "partially_replicated": 4,
    "replication_enabled": true
}
```

The file counts are derived by joining `file_metadata` with `file_storage_locations` and grouping by provider.

### `POST /api/admin/storage/copy-all`

Initiates a background task to copy all files from one provider to another.

**Request:**
```json
{
    "source_provider_id": "seaweedfs-local",
    "destination_provider_id": "wasabi-us-central-1",
    "verify": true,
    "skip_existing": true
}
```

- `verify`: If true, after copying each file, download it from the destination and verify the SHA-256 hash matches the `encrypted_file_sha256sum` in `file_metadata`.
- `skip_existing`: If true, skip files that already have an `"active"` location on the destination provider.

Note: The source and destination can be any combination of primary/secondary/tertiary providers. This makes copy operations fully flexible for populating any provider from any other.

**Response:**
```json
{
    "task_id": "a1b2c3d4-...",
    "task_type": "copy-all",
    "status": "pending",
    "progress_total": 142,
    "message": "Copy task queued"
}
```

### `POST /api/admin/storage/copy-user-files`

Same as copy-all but filtered to a single user's files.

**Request:**
```json
{
    "username": "alice12345",
    "source_provider_id": "seaweedfs-local",
    "destination_provider_id": "wasabi-us-central-1",
    "verify": true,
    "skip_existing": true
}
```

**Response:** Same format as copy-all with the task scoped to that user's files.

### `POST /api/admin/storage/copy-file`

Copies a single file from one provider to another. Also returns a task ID for consistency.

**Request:**
```json
{
    "file_id": "abcd1234-...",
    "source_provider_id": "seaweedfs-local",
    "destination_provider_id": "wasabi-us-central-1",
    "verify": true
}
```

**Response:**
```json
{
    "task_id": "e5f6g7h8-...",
    "task_type": "copy-file",
    "status": "pending",
    "progress_total": 1,
    "message": "Copy task queued"
}
```

### `GET /api/admin/storage/task/:taskId`

Returns the current status of a background task.

**Response:**
```json
{
    "task_id": "a1b2c3d4-...",
    "task_type": "copy-all",
    "status": "running",
    "progress_current": 87,
    "progress_total": 142,
    "started_at": "2026-04-16T15:00:00Z",
    "completed_at": null,
    "error_message": null,
    "details": {
        "source_provider_id": "seaweedfs-local",
        "destination_provider_id": "wasabi-us-central-1",
        "verify": true,
        "skip_existing": true,
        "files_skipped": 12,
        "files_copied": 75,
        "files_failed": 0,
        "bytes_copied": 5368709120
    }
}
```

### `POST /api/admin/storage/cancel-task/:taskId`

Requests cancellation of a running task. The background goroutine checks for cancellation between file copies and stops gracefully.

**Response:**
```json
{
    "task_id": "a1b2c3d4-...",
    "status": "canceled",
    "message": "Task cancellation requested"
}
```

### `GET /api/admin/storage/sync-status`

Returns a detailed breakdown of which files are on which providers and identifies any gaps.

**Response:**
```json
{
    "total_files": 142,
    "on_primary_only": 4,
    "on_secondary_only": 0,
    "on_all_three": 50,
    "on_primary_and_secondary": 88,
    "on_primary_and_tertiary": 0,
    "on_secondary_and_tertiary": 0,
    "on_tertiary_only": 0,
    "failed_locations": [
        {
            "file_id": "xyz789-...",
            "provider_id": "wasabi-us-central-1",
            "status": "failed",
            "owner_username": "alice12345"
        }
    ]
}
```

### `POST /api/admin/storage/add-provider`

Registers a new storage provider in the `storage_providers` table and hot-initializes an S3 client for it. This does not require a server restart. New providers default to `role = 'tertiary'`.

**Request:**
```json
{
    "provider_id": "wasabi-eu-central",
    "provider_type": "wasabi",
    "endpoint": "https://s3.eu-central-1.wasabi.com",
    "access_key": "...",
    "secret_key": "...",
    "bucket_name": "arkfile-eu",
    "region": "eu-central-1",
    "force_path_style": false
}
```

**Response:**
```json
{
    "provider_id": "wasabi-eu-central",
    "role": "tertiary",
    "is_active": true,
    "message": "Provider added and connectivity verified"
}
```

The endpoint performs a connectivity test (similar to `verify-storage`) before confirming the provider is active. Credentials are stored only in the database `storage_providers` table (encrypted at rest via rqlite disk encryption or the master key -- design TBD). On subsequent server restarts, the provider is re-initialized from the DB record alongside the env-configured providers.

Note: For v1, the simpler approach may be to require env var configuration for providers and use this endpoint only to register/verify them in the DB. Credential storage in the DB can be deferred to v2 if needed. V1 supports at most 3 total providers.

### `POST /api/admin/storage/set-primary`

Promotes a provider to primary. All new uploads will go to this provider. Existing files on other providers are not moved.

When a provider is promoted to primary, the role cascade is automatic: the old primary becomes secondary, and the old secondary becomes tertiary. This ensures no role conflicts.

**Request:**
```json
{
    "provider_id": "wasabi-us-central-1"
}
```

**Response:**
```json
{
    "previous_primary": "seaweedfs-local",
    "new_primary": "wasabi-us-central-1",
    "message": "Primary provider updated. New uploads will use wasabi-us-central-1. Previous primary seaweedfs-local demoted to secondary."
}
```

This updates the `role` field in `storage_providers` and swaps the registry references in memory. Download fallback continues to work for files on any provider.

### `POST /api/admin/storage/set-secondary`

Promotes a provider to secondary (auto-replication target and second-tier download fallback). If the target was tertiary, it moves to secondary. The displaced old secondary becomes tertiary.

**Request:**
```json
{
    "provider_id": "backblaze-eu-west"
}
```

**Response:**
```json
{
    "previous_secondary": "wasabi-us-central-1",
    "new_secondary": "backblaze-eu-west",
    "message": "Secondary provider updated. Auto-replication will target backblaze-eu-west. Previous secondary wasabi-us-central-1 demoted to tertiary."
}
```

### `POST /api/admin/storage/swap-providers`

Convenience endpoint that swaps primary and secondary in a single operation. Equivalent to calling `set-primary` with the current secondary's ID. Tertiary is unaffected.

**Request:**
```json
{}
```

**Response:**
```json
{
    "previous_primary": "seaweedfs-local",
    "new_primary": "wasabi-us-central-1",
    "previous_secondary": "wasabi-us-central-1",
    "new_secondary": "seaweedfs-local",
    "message": "Providers swapped. New uploads will use wasabi-us-central-1."
}
```

---

## arkfile-admin CLI Commands

All new commands are network commands that authenticate via the existing admin session and call the Admin API endpoints defined above. They are added to `cmd/arkfile-admin/main.go` (command routing) with implementation in a new file `cmd/arkfile-admin/storage_commands.go`.

### Updated Usage Block

The following commands are added to the `NETWORK COMMANDS` section of the usage text:

```
STORAGE MANAGEMENT COMMANDS (Admin API):
    storage-status        Show configured providers, file counts, and sync status
    storage-sync-status   Detailed breakdown of file locations and replication gaps
    copy-all              Copy all files from one provider to another
    copy-user-files       Copy all files for a specific user between providers
    copy-file             Copy a single file between providers
    task-status           Check status of a background storage task
    cancel-task           Cancel a running background storage task
    add-provider          Register and verify a new storage provider
    set-primary           Promote a provider to primary (new uploads go here)
    set-secondary         Promote a provider to secondary (auto-replication target)
    swap-providers        Swap primary and secondary provider roles
    verify-storage        Verify storage connectivity (any provider by --provider-id)
```

### `storage-status`

Calls `GET /api/admin/storage/status` and displays a formatted overview.

```
arkfile-admin storage-status
```

Example output:
```
Storage Providers:

  ID                    TYPE         BUCKET           ROLE       ACTIVE  FILES  SYNCED  PENDING  FAILED
  seaweedfs-local       generic-s3   arkfile-local    primary    yes     142    142     0        0
  wasabi-us-central-1   wasabi       arkfile-backup   secondary  yes     138    138     2        2
  backblaze-eu-west     backblaze    arkfile-archive  tertiary   yes     50     50      0        0

Replication: enabled
Total files: 142 | Fully replicated: 138 | Gaps: 4
```

### `storage-sync-status`

Calls `GET /api/admin/storage/sync-status` and displays detailed gap information.

```
arkfile-admin storage-sync-status
```

Flags:
- `--show-gaps` -- Only show files with replication gaps (not on all configured providers).

### `copy-all`

Calls `POST /api/admin/storage/copy-all` and displays the returned task ID.

```
arkfile-admin copy-all --from seaweedfs-local --to wasabi-us-central-1
arkfile-admin copy-all --from seaweedfs-local --to wasabi-us-central-1 --verify --skip-existing
arkfile-admin copy-all --from wasabi-us-central-1 --to backblaze-eu-west
```

Flags:
- `--from PROVIDER_ID` -- Source provider (required).
- `--to PROVIDER_ID` -- Destination provider (required).
- `--verify` -- Verify SHA-256 hash after each copy (default: false).
- `--skip-existing` -- Skip files already present on destination (default: true).
- `--dry-run` -- Show what would be copied without starting a task.

On success, prints:
```
Task queued: a1b2c3d4-...
Type: copy-all
Files to copy: 142
Use 'arkfile-admin task-status --task-id a1b2c3d4-...' to monitor progress.
```

### `copy-user-files`

Calls `POST /api/admin/storage/copy-user-files`.

```
arkfile-admin copy-user-files --username alice12345 --from seaweedfs-local --to wasabi-us-central-1
```

Flags: Same as `copy-all` plus:
- `--username USER` -- Target user (required).

### `copy-file`

Calls `POST /api/admin/storage/copy-file`.

```
arkfile-admin copy-file --file-id abcd1234-... --from seaweedfs-local --to wasabi-us-central-1
```

Flags:
- `--file-id ID` -- File to copy (required).
- `--from PROVIDER_ID` -- Source provider (required).
- `--to PROVIDER_ID` -- Destination provider (required).
- `--verify` -- Verify SHA-256 hash after copy (default: false).

### `task-status`

Calls `GET /api/admin/storage/task/:taskId`.

```
arkfile-admin task-status --task-id a1b2c3d4-...
```

Flags:
- `--task-id ID` -- Task to check (required).
- `--watch` -- Poll every 5 seconds and display live progress until the task completes.

Example output with `--watch`:
```
Task: a1b2c3d4-...
Type: copy-all
Status: running
Progress: 87/142 (61.3%)
  Copied: 75 | Skipped: 12 | Failed: 0
  Bytes copied: 5.0 GB
  Elapsed: 12m 34s
```

### `cancel-task`

Calls `POST /api/admin/storage/cancel-task/:taskId`.

```
arkfile-admin cancel-task --task-id a1b2c3d4-...
```

### `add-provider`

Calls `POST /api/admin/storage/add-provider`. Prompts for credentials interactively (they are not passed as CLI flags for security). New providers are added as tertiary by default. After adding, promote with `set-secondary` or `set-primary` as needed.

```
arkfile-admin add-provider --provider-id wasabi-eu --provider-type wasabi --bucket arkfile-eu --region eu-central-1 --endpoint https://s3.eu-central-1.wasabi.com
```

Flags:
- `--provider-id ID` -- Human-readable provider identifier (required).
- `--provider-type TYPE` -- One of: generic-s3, backblaze, cloudflare-r2, wasabi, vultr, aws-s3 (required).
- `--bucket NAME` -- Bucket name (required).
- `--region REGION` -- Region (default: us-east-1).
- `--endpoint URL` -- S3 endpoint URL (required for non-AWS providers).
- `--force-path-style` -- Use path-style addressing (default: false).

The command prompts for access key and secret key via secure terminal input (same pattern as password prompts in the existing login/bootstrap commands).

### `set-primary`

Calls `POST /api/admin/storage/set-primary`.

```
arkfile-admin set-primary --provider-id wasabi-us-central-1
```

Flags:
- `--provider-id ID` -- Provider to promote to primary (required).

Outputs the previous and new primary, notes the role cascade (old primary -> secondary, old secondary -> tertiary), and a reminder that new uploads will now go to the specified provider.

### `set-secondary`

Calls `POST /api/admin/storage/set-secondary`.

```
arkfile-admin set-secondary --provider-id backblaze-eu-west
```

Flags:
- `--provider-id ID` -- Provider to promote to secondary (required).

Outputs the previous and new secondary, notes that auto-replication will now target the specified provider.

### `swap-providers`

Calls `POST /api/admin/storage/swap-providers`.

```
arkfile-admin swap-providers
```

No flags required. Confirms the swap interactively before executing:
```
Current primary: seaweedfs-local
Current secondary: wasabi-us-central-1
Swap providers? New uploads will go to wasabi-us-central-1. [y/N]: y
Providers swapped. New primary: wasabi-us-central-1
```

### `verify-storage`

Performs a round-trip connectivity test against any configured provider. Generalized from the previous `verify-storage-2` concept to work with any of the three providers by provider ID.

```
arkfile-admin verify-storage --provider-id seaweedfs-local
arkfile-admin verify-storage --provider-id wasabi-us-central-1
arkfile-admin verify-storage --provider-id backblaze-eu-west
```

Flags:
- `--provider-id ID` -- Provider to verify (required). Can be any configured provider.

If `--provider-id` is omitted, defaults to verifying the primary provider (backward-compatible with existing `verify-storage` behavior).

---

## Background Task System

Background tasks are managed by a lightweight in-process task runner. This avoids the complexity of external job queues while providing reliable progress tracking and cancellation for long-running storage operations.

### Implementation: `handlers/admin_task_runner.go`

The task runner is a singleton that manages a pool of background goroutines for storage copy operations.

```go
type TaskRunner struct {
    mu          sync.RWMutex
    activeTasks map[string]context.CancelFunc // task_id -> cancel function
    maxWorkers  int                           // max concurrent copy tasks (default: 2)
    semaphore   chan struct{}                 // limits concurrent tasks
}

var taskRunner *TaskRunner
```

Key design decisions:

**Concurrency limit**: At most 2 copy tasks run concurrently by default. This prevents a bulk copy-all from saturating network bandwidth or starving normal upload/download operations. The limit is configurable but not exposed as a user-facing setting in v1.

**Cancellation**: Each task gets a `context.WithCancel()`. The cancel function is stored in the `activeTasks` map. When `cancel-task` is called, the context is canceled, and the copy loop checks `ctx.Err()` between files to stop gracefully.

**Progress updates**: The background goroutine updates `admin_tasks.progress_current` in the database after each file is processed. The `task-status` API reads directly from the database, so progress is visible even if the task runner is restarted (though in-flight tasks would not survive a server restart -- this is acceptable for v1).

### Task Lifecycle

1. **Creation**: The admin API handler validates the request, counts the files to be copied, inserts an `admin_tasks` row with `status = "pending"` and `progress_total = N`, and submits the task to the runner.

2. **Execution**: The runner acquires a semaphore slot, updates the task to `status = "running"`, and begins iterating over the file list. For each file:
   a. Check if the context is canceled. If so, update task to `status = "canceled"` and return.
   b. If `skip_existing` is true, check if a `file_storage_locations` row with `status = "active"` exists for this file on the destination. Skip if present.
   c. Stream the object from source provider to destination provider using `CopyObjectBetweenProviders()`.
   d. If `verify` is true, download from destination and compare SHA-256 hash with `file_metadata.encrypted_file_sha256sum`.
   e. Insert or update the `file_storage_locations` row for the destination provider.
   f. Increment `progress_current` in the `admin_tasks` row.

3. **Completion**: After all files are processed, update the task to `status = "completed"` with `completed_at` timestamp. Update the `details` JSON with final counts.

4. **Failure**: If an unrecoverable error occurs, update the task to `status = "failed"` with the error message. Individual file copy failures do not fail the entire task; they are recorded in the `details` JSON and the file's `file_storage_locations` row is set to `status = "failed"`.

### `CopyObjectBetweenProviders()`

This is the core streaming copy function implemented in `storage/registry.go`:

```go
func (r *ProviderRegistry) CopyObjectBetweenProviders(
    ctx context.Context,
    objectName string,
    source ObjectStorageProvider,
    destination ObjectStorageProvider,
    objectSize int64,
) error
```

The function streams data from source to destination without buffering the entire object in memory:

1. Call `source.GetObject()` to get a `ReadableStoredObject` (streaming reader).
2. If the object is small enough for a single PUT (under 100 MB), call `destination.PutObject()` with the reader directly. The source streams into the destination.
3. If the object is large, use multipart upload on the destination: call `destination.InitiateMultipartUpload()`, then read chunks from the source reader and upload each as a part via `destination.UploadPart()`, then call `destination.CompleteMultipartUpload()`.
4. The chunk size for multipart copy is the same as the upload chunk size (from `crypto.PlaintextChunkSize()` + overhead), ensuring consistency.

This approach keeps memory usage bounded regardless of file size, consistent with the project's design principle of supporting large files on constrained devices.

Note: Copy operations work with any combination of source and destination providers (primary/secondary/tertiary), making them fully flexible for populating any tier from any other.

### Server Restart Behavior

Tasks that are `"running"` when the server restarts will remain in `"running"` status in the database. On startup, the task runner scans for stale `"running"` tasks and marks them as `"failed"` with a message indicating the server was restarted. The admin can then re-trigger the operation. This is acceptable for v1; more sophisticated resume-from-checkpoint behavior can be added later if needed.

---

## Data Migration Plan

This section addresses the non-destructive migration path for existing deployments, specifically test.arkfile.net which has real beta users with data stored on the current single-node SeaweedFS S3 backend.

### Principle: No Existing Data is Modified or Lost

The migration is purely additive. It creates new tables and populates them with records that reflect the current state of the system. No columns are added to or removed from `file_metadata`. No existing rows are modified. No S3 objects are touched.

### Step 1: Schema Migration

Run the new `CREATE TABLE IF NOT EXISTS` statements for `storage_providers`, `file_storage_locations`, and `admin_tasks`. Since all three use `IF NOT EXISTS`, this is safe to run multiple times (idempotent). These statements are added to `database/unified_schema.sql` so they execute automatically on every startup via the existing schema initialization path.

### Step 2: Backfill `storage_providers`

On server startup, after `InitS3()` completes, the server upserts the primary provider into `storage_providers`:

```sql
INSERT OR IGNORE INTO storage_providers (provider_id, provider_type, bucket_name, endpoint, region, role, is_active)
VALUES (?, ?, ?, ?, ?, 'primary', true)
```

If a secondary provider is configured, a second upsert is performed with `role = 'secondary'`. If a tertiary provider is configured, a third upsert is performed with `role = 'tertiary'`. This runs on every startup and is idempotent due to the `INSERT OR IGNORE` on the primary key.

### Step 3: Backfill `file_storage_locations`

On server startup (after the provider upsert), a one-time backfill populates location records for all existing files that do not yet have a location entry:

```sql
INSERT INTO file_storage_locations (file_id, provider_id, storage_id, status, created_at)
SELECT file_id, ?, storage_id, 'active', upload_date
FROM file_metadata
WHERE file_id NOT IN (SELECT file_id FROM file_storage_locations)
```

The `?` parameter is the primary provider ID (e.g. `"seaweedfs-local"` or whatever the current `STORAGE_PROVIDER_ID` resolves to). This query is also idempotent: the `WHERE file_id NOT IN (...)` clause ensures it only inserts rows for files that have no location records yet.

After this backfill, every existing file has exactly one `file_storage_locations` row recording that it exists on the current primary provider. The system is now fully multi-backend-aware with no data loss and no downtime.

### Step 4: Ongoing Operation

From this point forward, all new uploads create `file_storage_locations` rows as part of the `CompleteUpload` handler. The backfill query continues to run on startup as a safety net, catching any files that might have been inserted by older code during a rolling upgrade window.

### Migration for test.arkfile.net

The specific migration path for the test deployment:

1. Update the codebase with the multi-backend changes.
2. Run `test-update.sh` to rebuild and redeploy. This restarts the server.
3. On startup, the new schema tables are created automatically.
4. On startup, the backfill runs automatically, inserting `storage_providers` row for `"generic-s3:arkfile-local"` (or whatever the SeaweedFS config resolves to) and `file_storage_locations` rows for all existing files pointing to that provider.
5. Verify with `arkfile-admin storage-status` that all files are accounted for.
6. Optionally, configure a secondary provider and run `arkfile-admin copy-all` to replicate everything.

No manual SQL, no data export/import, no downtime beyond the normal restart during `test-update.sh`.

---

## Concrete test.arkfile.net Migration Recipe

Step-by-step recipe for migrating the test deployment from SeaweedFS to Wasabi as primary, with optional tertiary archival.

```
Migration: test.arkfile.net SeaweedFS -> Wasabi Primary

1. SSH into test VPS, git pull latest code
2. Add to /opt/arkfile/etc/secrets.env:
   STORAGE_PROVIDER_ID=seaweedfs-test
   STORAGE_PROVIDER_2=wasabi
   STORAGE_PROVIDER_2_ID=wasabi-us-central-1
   STORAGE_2_ENDPOINT=https://s3.us-central-1.wasabi.com
   STORAGE_2_ACCESS_KEY=<key>
   STORAGE_2_SECRET_KEY=<secret>
   STORAGE_2_BUCKET=arkfile-test
   STORAGE_2_REGION=us-central-1
   STORAGE_2_FORCE_PATH_STYLE=false
3. sudo bash scripts/test-update.sh
4. arkfile-admin storage-status  (verify both providers, backfill complete)
5. arkfile-admin copy-all --from seaweedfs-test --to wasabi-us-central-1 --verify --skip-existing
6. arkfile-admin task-status --task-id <id> --watch
7. arkfile-admin storage-sync-status  (verify all files on both)
8. arkfile-admin set-primary --provider-id wasabi-us-central-1
9. Upload new file, verify it goes to Wasabi
10. Download old file, verify from Wasabi
11. Verify shared file downloads work
12. (Optional) Stop SeaweedFS, verify everything via Wasabi alone
13. (Optional) Add Backblaze B2 as tertiary for archival redundancy:
    - Add STORAGE_PROVIDER_3=backblaze, STORAGE_PROVIDER_3_ID=backblaze-eu-west,
      STORAGE_3_ENDPOINT=s3.eu-west-004.backblazeb2.com, etc. to secrets.env
    - Restart server
    - arkfile-admin copy-all --from wasabi-us-central-1 --to backblaze-eu-west --verify --skip-existing
    - arkfile-admin storage-status  (verify three providers)
```

---

## Testing Strategy

### Local Testing with Multiple S3 Backends

The primary testing environment for multi-backend features uses `local-deploy.sh` with multiple local S3-compatible backends. The simplest setup is two SeaweedFS instances on different ports, or one SeaweedFS and one or two MinIO containers.

**Option A: Two SeaweedFS instances**

The existing `local-deploy.sh` starts SeaweedFS on port 9332 (S3 gateway on 8333). A second instance can run on port 9333 (S3 gateway on 8334) with a separate data directory. This requires adding a second SeaweedFS configuration to the local deploy script.

**Option B: SeaweedFS + MinIO (+ optional second MinIO for tertiary)**

Run MinIO as a secondary via podman/docker:
```bash
podman run -d --name arkfile-minio \
    -p 9000:9000 -p 9001:9001 \
    -e MINIO_ROOT_USER=arkfile-secondary \
    -e MINIO_ROOT_PASSWORD=your_secret_here \
    minio/minio server /data --console-address ":9001"
```

Then configure:
```
STORAGE_PROVIDER_2=generic-s3
STORAGE_PROVIDER_2_ID=minio-local
STORAGE_2_ENDPOINT=http://localhost:9000
STORAGE_2_ACCESS_KEY=arkfile-secondary
STORAGE_2_SECRET_KEY=your_secret_here
STORAGE_2_BUCKET=arkfile-secondary
STORAGE_2_FORCE_PATH_STYLE=true
```

For tertiary testing, add a second MinIO container on a different port:
```bash
podman run -d --name arkfile-minio-tertiary \
    -p 9002:9000 -p 9003:9001 \
    -e MINIO_ROOT_USER=arkfile-tertiary \
    -e MINIO_ROOT_PASSWORD=your_secret_here \
    minio/minio server /data --console-address ":9001"
```

```
STORAGE_PROVIDER_3=generic-s3
STORAGE_PROVIDER_3_ID=minio-tertiary
STORAGE_3_ENDPOINT=http://localhost:9002
STORAGE_3_ACCESS_KEY=arkfile-tertiary
STORAGE_3_SECRET_KEY=your_secret_here
STORAGE_3_BUCKET=arkfile-tertiary
STORAGE_3_FORCE_PATH_STYLE=true
```

A tertiary provider can also be added at runtime via `arkfile-admin add-provider` during testing.

### `local-update.sh` Script

A new `scripts/local-update.sh` script is needed (analogous to `test-update.sh`) for the local deployment workflow. It rebuilds and redeploys without wiping data, keys, or config. Additionally, it supports multi-backend management flags:

```bash
# Basic rebuild and redeploy (same as test-update.sh pattern)
sudo bash scripts/local-update.sh

# Add a secondary storage provider to the local deployment
sudo bash scripts/local-update.sh --add-secondary-minio

# Remove secondary provider configuration
sudo bash scripts/local-update.sh --remove-secondary
```

The `--add-secondary-minio` flag would start a MinIO container and add the appropriate `STORAGE_2_*` variables to the local secrets.env. The `--remove-secondary` flag would stop the container and remove those variables.

### Unit Tests

**`storage/registry_test.go`**: Tests for the `ProviderRegistry` methods:
- `GetObjectWithFallback` returns from primary when primary succeeds.
- `GetObjectWithFallback` returns from secondary when primary fails.
- `GetObjectWithFallback` returns from tertiary when primary and secondary fail.
- `GetObjectWithFallback` returns error when all three fail.
- `GetObjectChunkWithFallback` same three-tier patterns.
- `RemoveObjectAll` removes from all configured providers, handles partial failures.
- `CopyObjectBetweenProviders` streams correctly for small and large objects.

These tests use the existing `MockObjectStorageProvider` and `MockStoredObject` from `storage/mock_storage.go`.

**`handlers/admin_storage_test.go`**: Tests for the admin API endpoints:
- `storage-status` returns correct provider information with `role` field.
- `copy-file` creates a task and returns a task ID.
- `task-status` returns correct progress.
- `set-primary` updates roles correctly with cascade.
- `set-secondary` updates roles correctly with cascade.

### e2e Test Extensions

Add multi-backend test scenarios to `scripts/testing/e2e-test.sh`:

1. **Single-provider mode (existing tests)**: All existing e2e tests continue to pass with no secondary provider configured. This validates backward compatibility.

2. **Multi-provider upload + download**: With `ENABLE_UPLOAD_REPLICATION=true`, upload a file, wait for replication, then verify:
   - `arkfile-admin storage-status` shows the file on both providers.
   - Download succeeds (from primary).
   - Simulate primary failure (stop SeaweedFS), download still succeeds (from secondary fallback).
   - Restart SeaweedFS, verify everything is back to normal.

3. **Copy operations**: Upload several files with replication disabled. Run `arkfile-admin copy-all`. Verify all files appear on secondary via `storage-sync-status`.

4. **Provider swap**: After copy-all, run `arkfile-admin swap-providers`. Upload a new file. Verify it goes to the new primary. Download an old file. Verify fallback works.

5. **Delete**: Delete a file. Verify it is removed from all providers via `storage-sync-status`.

6. **Tertiary provider**: Add a tertiary provider via `add-provider` or env config. Copy files to it. Verify three-tier fallback by stopping primary and secondary, confirming download from tertiary.

7. **Role promotion**: Test `set-secondary` to promote tertiary to secondary. Verify auto-replication targets the new secondary.

### Test Scenarios for Provider Migration

A complete provider migration test:

1. Deploy with SeaweedFS as primary (single provider).
2. Upload files, create shares, verify everything works.
3. Add MinIO as secondary via `arkfile-admin add-provider` or env config.
4. Run `arkfile-admin copy-all --from seaweedfs-local --to minio-local --verify`.
5. Monitor with `arkfile-admin task-status --task-id ... --watch`.
6. Verify with `arkfile-admin storage-sync-status` that all files are on both.
7. Run `arkfile-admin set-primary --provider-id minio-local`.
8. Upload a new file -- goes to MinIO.
9. Download old files -- served from MinIO (new primary).
10. Stop SeaweedFS entirely. All operations still work via MinIO.
11. Verify shares still work (share download uses fallback).
12. (Optional) Add a second MinIO as tertiary, copy all files to it, verify three-tier fallback.

---

## Implementation Order

The implementation is organized into phases that can each be developed, tested, and committed independently. Each phase builds on the previous one and produces a working system at every step.

### Phase 1: Storage Layer Foundation

**Goal**: Introduce the provider registry with three-tier support and the config-struct factory function without changing any handler behavior.

Files changed:
- `storage/s3.go` -- Extract `NewS3Provider(config S3ProviderConfig)` factory function from `InitS3()`. Config struct replaces positional parameters.
- `storage/registry.go` -- New file with `ProviderRegistry` struct (three fields: primary, secondary, tertiary), `Primary()`, `Secondary()`, `Tertiary()`, `HasSecondary()`, `HasTertiary()`, `PrimaryID()`, `SecondaryID()`, `TertiaryID()`.
- `storage/storage.go` -- Add `Registry` global.
- `storage/mock_storage.go` -- Add `MockProviderRegistry` supporting three providers.
- `storage/registry_test.go` -- Unit tests for registry methods.

Verification: All existing e2e tests pass unchanged. `storage.Provider` still points to the primary. No handler code is modified yet.

### Phase 2: Schema and Models

**Goal**: Add new database tables and model functions.

Files changed:
- `database/unified_schema.sql` -- Add `storage_providers` (with `role` column), `file_storage_locations`, `admin_tasks` tables with indexes.
- `models/file_storage_location.go` -- New file with `FileStorageLocation` struct and CRUD functions.
- `models/storage_provider.go` -- New file with `StorageProvider` struct and CRUD functions.
- `models/admin_task.go` -- New file with `AdminTask` struct and CRUD functions.

Verification: Run `dev-reset.sh`, confirm tables are created. Existing data and functionality unaffected.

### Phase 3: Startup Backfill and Provider Registration

**Goal**: On server startup, register the primary provider and backfill location records for all existing files.

Files changed:
- `main.go` -- After `storage.InitS3()`, upsert provider into `storage_providers` with `role = 'primary'` and run backfill query for `file_storage_locations`.
- `.env.example` -- Add `STORAGE_PROVIDER_ID`, `STORAGE_PROVIDER_2`, `STORAGE_PROVIDER_2_ID`, `STORAGE_2_*`, `STORAGE_PROVIDER_3`, `STORAGE_PROVIDER_3_ID`, `STORAGE_3_*`, `ENABLE_UPLOAD_REPLICATION` variables (all commented out).

Verification: Run `dev-reset.sh` and `e2e-test.sh`. After tests create files, verify `file_storage_locations` has one row per file with `status = "active"` pointing to the primary provider. All existing tests pass.

### Phase 4: Handler Updates -- Downloads with Fallback

**Goal**: Update download handlers to use `GetObjectChunkWithFallback()` with three-tier fallback.

Files changed:
- `storage/registry.go` -- Implement `GetObjectWithFallback()` and `GetObjectChunkWithFallback()` with primary -> secondary -> tertiary chain.
- `handlers/downloads.go` -- Replace `storage.Provider.GetObjectChunk()` with `storage.Registry.GetObjectChunkWithFallback()`.
- `handlers/file_shares.go` -- Same replacement in `DownloadShareChunk`.
- `handlers/export.go` -- Replace `storage.Provider.GetObject()` with `storage.Registry.GetObjectWithFallback()`.

Verification: All existing download/share/export tests pass. In single-provider mode, fallback is never triggered. With a secondary configured, manually test fallback by stopping the primary and confirming downloads still work.

### Phase 5: Handler Updates -- Uploads with Location Recording

**Goal**: Update upload handlers to record locations and optionally replicate to secondary.

Files changed:
- `handlers/uploads.go` -- In `CompleteUpload`, insert `file_storage_locations` row. If `ENABLE_UPLOAD_REPLICATION=true`, kick off background replication goroutine (targets secondary only, not tertiary).
- `storage/registry.go` -- Implement `CopyObjectBetweenProviders()`.
- Replace all remaining `storage.Provider.XXX()` calls in uploads.go with `storage.Registry.Primary().XXX()`.

Verification: Upload a file, confirm `file_storage_locations` row is created. With replication enabled, confirm the blob appears on both providers.

### Phase 6: Handler Updates -- Deletes from All Providers

**Goal**: Update delete handler to remove from all providers.

Files changed:
- `handlers/uploads.go` (`DeleteFile`) -- Query `file_storage_locations` for the file, remove from each active provider (could be 1, 2, or 3), update/delete location rows.
- `storage/registry.go` -- Implement `RemoveObjectAll()`.

Verification: Upload a file with replication, confirm it is on both providers, delete it, confirm it is removed from both.

### Phase 7: Background Task System

**Goal**: Implement the task runner and admin task management.

Files changed:
- `handlers/admin_task_runner.go` -- New file with `TaskRunner`, task execution loop, cancellation support.
- `models/admin_task.go` -- Finalize CRUD with progress update functions.
- `main.go` -- Initialize task runner on startup, mark stale tasks as failed.

Verification: Unit tests for task lifecycle (create, run, complete, cancel, fail).

### Phase 8: Admin API Endpoints

**Goal**: Implement all admin storage management endpoints.

Files changed:
- `handlers/admin_storage.go` -- New file with all endpoint handlers: `storage-status`, `sync-status`, `copy-all`, `copy-user-files`, `copy-file`, `task-status`, `cancel-task`, `add-provider`, `set-primary`, `set-secondary`, `swap-providers`.
- `handlers/route_config.go` -- Register new admin routes.

Verification: Test each endpoint with curl or arkfile-admin CLI.

### Phase 9: arkfile-admin CLI Commands

**Goal**: Add all storage management commands to the admin CLI.

Files changed:
- `cmd/arkfile-admin/main.go` -- Add command routing for new storage commands including `set-secondary`.
- `cmd/arkfile-admin/storage_commands.go` -- New file with all command handlers.

Verification: Run each command against a local deployment with two or three providers. Test the full provider migration workflow end-to-end.

### Phase 10: local-update.sh and e2e Test Extensions

**Goal**: Finalize the local deployment update script and extend e2e tests for multi-backend scenarios.

Files changed:
- `scripts/local-update.sh` -- New script for non-destructive local deployment updates.
- `scripts/testing/e2e-test.sh` -- Add multi-backend test scenarios (upload with replication, fallback download, copy-all, provider swap, delete from all, tertiary addition, role promotion).

Verification: Full e2e test suite passes in single-provider, dual-provider, and triple-provider modes.

## Files Changed Summary

### New Files
- `storage/registry.go`
- `storage/registry_test.go`
- `models/file_storage_location.go`
- `models/storage_provider.go`
- `models/admin_task.go`
- `handlers/admin_storage.go`
- `handlers/admin_storage_test.go`
- `handlers/admin_task_runner.go`
- `cmd/arkfile-admin/storage_commands.go`
- `scripts/local-update.sh`
- `docs/wip/multi-backend.md`

### Modified Files
- `storage/s3.go` -- Config struct factory function extraction, `InitS3()` reads three provider configs
- `storage/storage.go` -- Add Registry global
- `storage/mock_storage.go` -- Add mock registry with three-provider support
- `main.go` -- Registry init, backfill, task runner init
- `database/unified_schema.sql` -- New tables with `role` column
- `.env.example` -- New env var templates including `STORAGE_3_*`
- `handlers/uploads.go` -- Registry calls, location recording, replication (secondary only)
- `handlers/downloads.go` -- Three-tier fallback downloads
- `handlers/file_shares.go` -- Three-tier fallback downloads
- `handlers/export.go` -- Three-tier fallback downloads
- `handlers/route_config.go` -- New admin routes including `set-secondary`
- `cmd/arkfile-admin/main.go` -- New command routing including `set-secondary`
- `scripts/testing/e2e-test.sh` -- Multi-backend test scenarios including tertiary

### Unchanged
- All crypto code
- All client-side TypeScript code
- All auth code (OPAQUE, JWT, TOTP)
- The `file_metadata` table schema
- The `arkfile-client` CLI

---
