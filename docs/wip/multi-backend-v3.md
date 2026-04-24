# Multi-Backend Object Storage (v3)

Design document for multi-provider storage redundancy in Arkfile.

Supersedes: `docs/wip/archive/multi-backend-v1.md` and `docs/wip/archive/multi-backend-v2.md`

## Overview

This feature adds support for up to three simultaneous S3-compatible storage backends (primary, secondary, and tertiary), enabling encrypted blob redundancy, download fallback, and zero-downtime provider migration. The three-tier model provides automatic replication between primary and secondary, manual copy operations to/from any provider including tertiary, and a three-level download fallback chain. All multi-backend operations are admin-only and controlled via the arkfile-admin CLI through the Admin API.

## Motivation

1. **Operational resilience**: If the primary storage provider experiences downtime, file downloads automatically fall back to the secondary provider (and then tertiary if secondary also fails). Users experience no interruption.

2. **Provider risk mitigation**: Storage providers can change pricing, terms, or availability at any time. With multi-backend support, the admin can add a new provider, copy all data to it, and decommission the old provider without any downtime or data loss. This eliminates vendor lock-in.

3. **Data redundancy**: Encrypted blobs stored identically across two or three independent providers provide an additional layer of protection against data loss beyond what any single provider offers.

4. **Non-disruptive**: The feature is entirely opt-in. When no secondary provider is configured, the system behaves identically to single-provider mode. No changes are required to client-side code, crypto, or user-facing functionality.

## Design Principles

- **Additive, not destructive**: No existing tables are modified (except adding one new column to `file_metadata`). New tables are added. Existing single-provider deployments continue to work without configuration changes.
- **Admin-only**: All multi-backend management is performed through arkfile-admin CLI commands that hit Admin API endpoints. Nothing is surfaced to end users at this stage.
- **Encrypted blobs are opaque**: The same client-side-encrypted blob (identified by storage_id) can be PUT to any number of S3-compatible backends. No re-encryption or transformation is needed.
- **Task-based async operations**: All copy operations (bulk or individual) return a task ID immediately. The server performs the work in background goroutines. The admin polls task status.
- **Provider-ID is the identity, not provider-type**: Two backends can use the same provider type (e.g., both `wasabi`) with different regions, endpoints, buckets, and credentials. Each is identified by its unique `provider_id` (e.g., `wasabi-us-central-1`, `wasabi-eu-central-2`). The system treats them as fully independent backends.
- **Three-tier provider roles**: The system supports up to three providers with distinct roles: Primary (receives all uploads), Secondary (auto-replication target, download fallback), and Tertiary (manual copy/move target only, final download fallback). Only Primary and Secondary participate in automatic replication. Tertiary is available for admin-initiated copy operations and serves as a third-tier download fallback. Any provider can be promoted or demoted one level at a time.
- **Credentials from environment variables only**: All S3 credentials live in `secrets.env` and are read on server startup. No credentials are stored in the database, transmitted via the Admin API, or accepted through any endpoint. The database stores only provider metadata and operational state (roles, status, usage stats).
- **DB-authoritative roles**: After initial startup, the database is the authority for provider role assignments. Role changes via admin commands persist across server restarts. Environment variables provide credentials and initial defaults for new providers only.
- **No backward-compatibility aliases**: The legacy `storage.Provider` global is removed entirely. All call sites use `storage.Registry` methods. This is a greenfield app.
- **Streaming copy with single-pass verification**: Cross-provider copies stream data directly from source to destination S3 without writing to disk. Hash verification is computed during the copy stream via TeeReader, not as a separate download pass.

### Three-Tier Role Reference

| Role | Uploads | Auto-Replication Target | Download Fallback | Manual Copy Target | Can Promote To | Can Demote To |
|-----------|---------|-------------------------|-------------------|--------------------|----------------|---------------|
| Primary   | Yes     | N/A (source)            | 1st attempt       | Yes                | N/A            | Secondary     |
| Secondary | No      | Yes (background sync)   | 2nd attempt       | Yes                | Primary        | Tertiary      |
| Tertiary  | No      | No (manual only)        | 3rd attempt       | Yes                | Secondary      | N/A           |

### Role Change Rules

Role changes move providers one level at a time with connectivity verification at each step:

- **`set-primary <id>`**: Target must be secondary. Old primary demotes to secondary. Tertiary unchanged.
- **`set-secondary <id>`**: Target can be primary (demotion) or tertiary (promotion). The displaced provider takes the target's old role.
- **`set-tertiary <id>`**: Target must be secondary. Old tertiary promotes to secondary. Primary unchanged.
- **`swap-providers`**: Convenience shortcut that swaps primary and secondary roles.

Invalid operations are rejected with clear guidance:
- `set-primary` on tertiary: "Promote to secondary first, then to primary."
- `set-tertiary` on primary: "Demote to secondary first, then to tertiary."

Before completing any role change, both affected providers undergo a full connectivity verification (1 MB test upload, verify, delete). If either fails, the role change is rejected.

---

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

### Current Hash and Padding Behavior

During upload, the server appends crypto-random padding bytes to the last chunk before uploading it to S3. This obscures file sizes in the storage backend. The `file_metadata` table stores:
- `size_bytes`: The encrypted ciphertext size (before padding). Used for chunk byte-range calculations on download.
- `padded_size`: The actual S3 object size (encrypted data + padding).
- `encrypted_file_sha256sum`: SHA-256 of the encrypted data ONLY, computed via streaming hash BEFORE padding is appended.

The current `encrypted_file_sha256sum` does NOT represent the hash of the actual S3-stored blob (which includes padding). This means it cannot be used to verify the integrity of a blob copied between providers. This gap is addressed in the schema changes below with a new `stored_blob_sha256sum` column.

---

## Phase 0: Dead Code Cleanup (file_shares Legacy Table)

Before any multi-backend implementation begins, remove the dead `file_shares` table from the schema. This table was superseded by `file_share_keys` and has zero references anywhere in the codebase (Go, TypeScript, shell scripts -- all confirmed via search).

### What to Remove from `database/unified_schema.sql`

1. **The table definition** (currently in Phase 6 section):
```sql
-- File shares (legacy table for compatibility - may be deprecated in future)
CREATE TABLE IF NOT EXISTS file_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL,
    owner_username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE
);
```

2. **The three indexes** (currently in Phase 13 section):
```sql
CREATE INDEX IF NOT EXISTS idx_file_shares_share_id ON file_shares(share_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_file_id ON file_shares(file_id);
CREATE INDEX IF NOT EXISTS idx_file_shares_owner ON file_shares(owner_username);
```

3. **Add a DROP statement** for existing deployments (test.arkfile.net) at the top of the Phase 6 section:
```sql
-- Cleanup: Remove deprecated file_shares table (superseded by file_share_keys)
DROP TABLE IF EXISTS file_shares;
```

### Verification

After removal, run `dev-reset.sh` and `e2e-test.sh` to confirm nothing breaks. The `file_share_keys` table continues to handle all file sharing functionality.

---

## Configuration and Environment Variables

### Credential Storage Decision

All S3 credentials are stored in `/opt/arkfile/etc/secrets.env` and read by the server on startup. This is the same pattern used for all other secrets in the system (rqlite password, DESEC token, etc.). File permissions on secrets.env are the security boundary.

There is no API endpoint that accepts S3 credentials. There is no credential storage in the database. To add or change a storage provider, the admin edits secrets.env and restarts the server. This is acceptable because the system supports at most 3 providers -- this is not a scaling problem that needs a dynamic API.

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

Note: For the primary provider, some endpoints can be auto-derived from the region (e.g., Wasabi endpoint `https://s3.{region}.wasabisys.com` from `S3_REGION`, Vultr endpoint from `S3_REGION`). This auto-generation logic lives in the env-var reading code that calls the `NewS3Provider` factory, not inside the factory itself. Wasabi requires path-style addressing (`S3_FORCE_PATH_STYLE=true`).

### Secondary Provider (New -- Optional)

The three-tier model supports an optional secondary provider configured with a parallel set of environment variables prefixed with `STORAGE_2_`. The secondary provider serves as the automatic replication target and second-tier download fallback.

For all non-primary providers, `STORAGE_2_ENDPOINT` is required. Unlike the primary provider where some endpoints can be derived from region, secondary and tertiary providers always require an explicit endpoint.

```
STORAGE_PROVIDER_2=wasabi
STORAGE_PROVIDER_2_ID=wasabi-us-central-1  # Optional human-readable ID
STORAGE_2_ENDPOINT=https://s3.us-central-1.wasabisys.com
STORAGE_2_ACCESS_KEY=your_access_key
STORAGE_2_SECRET_KEY=your_secret_key
STORAGE_2_BUCKET=arkfile-backup
STORAGE_2_REGION=us-central-1
STORAGE_2_FORCE_PATH_STYLE=true
```

When `STORAGE_PROVIDER_2` is not set or empty, the system operates in single-provider mode. All multi-backend features are disabled and behavior is identical to the current implementation.

### Tertiary Provider (New -- Optional)

An optional tertiary provider is configured with `STORAGE_3_` prefixed environment variables. The tertiary provider is a manual-only copy target and serves as the third-tier download fallback. It does not participate in automatic upload replication.

```
STORAGE_PROVIDER_3=backblaze
STORAGE_PROVIDER_3_ID=backblaze-us-west
STORAGE_3_ENDPOINT=s3.us-west-004.backblazeb2.com
STORAGE_3_ACCESS_KEY=your_key_id
STORAGE_3_SECRET_KEY=your_application_key
STORAGE_3_BUCKET=arkfile-archive
STORAGE_3_REGION=us-west-004
STORAGE_3_FORCE_PATH_STYLE=false
```

When `STORAGE_PROVIDER_3` is not set or empty, the system operates in two-provider mode (or single-provider if secondary is also unconfigured). The tertiary provider requires a configured secondary provider; you cannot have a tertiary without a secondary.

### Replication Flag

```
ENABLE_UPLOAD_REPLICATION=false
```

When set to `true` and a secondary provider is configured, newly uploaded files are automatically replicated to the secondary provider only via a background goroutine after the primary upload completes. The tertiary provider is never an automatic replication target. The upload response is returned to the user as soon as the primary upload succeeds; secondary replication happens asynchronously. If secondary replication fails, the file is recorded with status `"active"` on primary and `"failed"` on secondary. Replication failures are logged at WARNING level and surfaced to admins via login alerts and the `storage-sync-status` command.

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

### Startup Sequence: Env Vars vs DB Roles

On server startup, the sequence is:

1. Read all `STORAGE_*` env var groups. Create S3 clients for each configured provider via `NewS3Provider()`.
2. Upsert each provider into `storage_providers` table (metadata only, no credentials). Set `env_var_prefix` to identify which env var group configures this provider.
3. Check if role assignments already exist in the `storage_providers` table from previous operation.
4. If role assignments exist in DB: use those roles (DB is authoritative). This preserves any `set-primary`/`set-secondary`/`swap-providers` changes from previous sessions.
5. If no role assignments exist (fresh install): assign roles based on env var ordering (primary from `STORAGE_*`, secondary from `STORAGE_2_*`, tertiary from `STORAGE_3_*`).
6. Build the `ProviderRegistry` with the correct role assignments.
7. Ensure buckets exist for each configured provider (existing behavior for generic-s3/local providers).

---

## Schema Changes

Three new tables are added and one new column is added to `file_metadata`.

### `storage_providers` Table

Tracks configured storage providers as first-class database entities with usage statistics and cost information. This allows the admin API to query and manage providers, track storage costs, and display operational status.

```sql
CREATE TABLE IF NOT EXISTS storage_providers (
    provider_id TEXT PRIMARY KEY,
    provider_type TEXT NOT NULL,
    bucket_name TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'us-east-1',
    role TEXT NOT NULL DEFAULT 'tertiary',
    env_var_prefix TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    total_objects INTEGER NOT NULL DEFAULT 0,
    total_size_bytes BIGINT NOT NULL DEFAULT 0,
    cost_per_tb_cents INTEGER,
    last_verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_storage_providers_role ON storage_providers(role);
CREATE INDEX IF NOT EXISTS idx_storage_providers_active ON storage_providers(is_active);
```

Key fields:
- `role`: One of `'primary'`, `'secondary'`, `'tertiary'`. Constraints: only one provider can have `role = 'primary'`, only one can have `role = 'secondary'`. The DB schema allows multiple tertiary for future expansion, but v1 supports at most one via env vars.
- `env_var_prefix`: Maps back to which env var group configures this provider. Values: `'STORAGE'` (primary), `'STORAGE_2'`, `'STORAGE_3'`. Used to identify which env vars to reference when the admin needs to update credentials for a provider.
- `total_objects` / `total_size_bytes`: Cached counts derived from `file_storage_locations`. Updated during upload, delete, and copy operations. Provides fast admin queries without expensive JOINs.
- `cost_per_tb_cents`: Admin-set monthly cost per TB in USD cents (e.g. 799 = $7.99/TB/month). Optional. Enables cost-awareness in `storage-status` output.
- `last_verified_at`: Updated by `verify-storage` command. Gives admins visibility into when connectivity was last confirmed.

On startup, the server upserts rows for the configured primary (and optional secondary/tertiary) provider. The `role` field indicates each provider's current role. The `set-primary`, `set-secondary`, `set-tertiary`, and `swap-providers` admin commands update this field. Role assignments in the DB persist across restarts.

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
- `status`: One of `"active"`, `"pending"`, `"failed"`, `"deleted"`, `"delete_failed"`. `"active"` means the blob is confirmed present. `"pending"` means a copy operation is in progress. `"failed"` means a copy was attempted but did not succeed. `"delete_failed"` means a deletion was attempted but failed, leaving an orphaned blob on this provider.
- `verified_at`: Timestamp of the last successful integrity check (set during copy verification).

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
- `details`: JSON text field for task-specific metadata (e.g. source provider, destination provider, username filter, files copied/skipped/failed counts, bytes copied).
- `error_message`: Populated on failure with a description of what went wrong.

### New Column on `file_metadata`: `stored_blob_sha256sum`

Add a new column to `file_metadata` for the SHA-256 hash of the complete S3 object (encrypted data + padding):

```sql
ALTER TABLE file_metadata ADD COLUMN stored_blob_sha256sum CHAR(64);
```

This column is populated during upload by computing a SHA-256 hash of ALL data sent to S3, including the crypto-random padding appended to the last chunk. Unlike `encrypted_file_sha256sum` (which hashes only the encrypted data before padding), `stored_blob_sha256sum` represents the exact bytes stored in the S3 object.

This hash is used for:
- **Copy verification**: During streaming copies between providers, a TeeReader computes the hash of data as it flows from source to destination. The computed hash is compared against `stored_blob_sha256sum`. Zero extra bandwidth.
- **Integrity checking**: Admin can verify that blobs on any provider match the expected hash.

**Backfill strategy for existing files:** Files uploaded before this feature will have `stored_blob_sha256sum = NULL`. These files can still be copied between providers but cannot be hash-verified during the copy. An optional `arkfile-admin hash-backfill` command can be implemented later to download each existing blob, compute its hash, and store it. For v1, NULL values are acceptable.

**Implementation in upload handler:** The current `StreamingHashState` hashes only encrypted data (before padding). A second hash state (`StoredBlobHashState`) is added that includes padding bytes. Alternatively, a single hash can be maintained that includes all bytes sent to S3, and the padding-exclusive hash can be derived separately. The simplest approach: maintain two streaming hashes in parallel during upload -- one for `encrypted_file_sha256sum` (pre-padding) and one for `stored_blob_sha256sum` (post-padding, the actual S3 bytes).

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
    secondaryID string                // e.g. "wasabi-us-central-1"
    tertiaryID  string                // e.g. "backblaze-us-west"
}

var Registry *ProviderRegistry
```

The legacy `storage.Provider` global is removed entirely. All 17 call sites are updated to use Registry methods directly.

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

**RemoveObjectAll(ctx, objectName, opts, fileID) error** -- Removes the object from all providers that have active `file_storage_locations` records for the given fileID. For each provider where deletion succeeds, updates the location row to `status = "deleted"`. For each provider where deletion fails, updates to `status = "delete_failed"` and logs a WARNING. Returns an error only if no deletions succeeded at all.

**CopyObjectBetweenProviders(ctx, objectName, source, destination, objectSize) (string, error)** -- Streams data from source to destination without buffering the entire object in memory. Returns the SHA-256 hash of the copied bytes (computed during the stream via TeeReader) and any error. See "Streaming Copy with TeeReader Verification" below.

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
5. Set `Registry = &ProviderRegistry{...}`.
6. Ensure the primary bucket exists (existing behavior). If secondary/tertiary are configured, ensure their buckets exist too (for `generic-s3` / local providers).

### Modified File: `storage/storage.go`

The `Provider` global is removed. Only the `Registry` global remains:

```go
var Registry *ProviderRegistry  // Holds primary + optional secondary + optional tertiary
```

### Modified File: `storage/mock_storage.go`

Add a `MockProviderRegistry` for testing that wraps up to three `MockObjectStorageProvider` instances and implements the same registry methods. This allows handler tests to verify three-tier fallback behavior, multi-delete behavior, etc.

### Streaming Copy with TeeReader Verification

The `CopyObjectBetweenProviders()` function is the core streaming copy mechanism. It streams data from source to destination without writing to disk, while simultaneously computing a SHA-256 hash for verification:

```go
func (r *ProviderRegistry) CopyObjectBetweenProviders(
    ctx context.Context,
    objectName string,
    source ObjectStorageProvider,
    destination ObjectStorageProvider,
    objectSize int64,
) (string, error)  // returns (sha256hex, error)
```

The flow:

1. Call `source.GetObject()` to get a `ReadableStoredObject` (streaming reader).
2. Wrap the source reader with a SHA-256 TeeReader: as bytes are read from source, they are simultaneously written to the hash.
3. If the object is small enough for a single PUT (under 100 MB), call `destination.PutObject()` with the TeeReader directly. Data flows: source S3 -> network -> server memory (small buffer) -> hash -> network -> destination S3.
4. If the object is large, use multipart upload on the destination: call `destination.InitiateMultipartUpload()`, then read chunks from the TeeReader and upload each as a part via `destination.UploadPart()`, then call `destination.CompleteMultipartUpload()`.
5. After the stream completes, finalize the hash and return the hex-encoded SHA-256.
6. The caller compares the returned hash against `file_metadata.stored_blob_sha256sum` (if available) to verify integrity. If `stored_blob_sha256sum` is NULL (pre-existing file), verification is skipped with a log note.

This approach keeps memory usage bounded regardless of file size, uses zero extra bandwidth for verification, and is consistent with the project's design principle of supporting large files on constrained devices.

---

## Handler Updates

All 17 `storage.Provider.XXX()` call sites are updated to use the registry. No `storage.Provider` alias exists. The changes follow consistent patterns per operation type.

### Upload Flow (`handlers/uploads.go`)

**CreateUploadSession** -- No storage changes needed. This only creates DB records and initiates a multipart upload on the primary provider. The call to `storage.Provider.InitiateMultipartUpload()` becomes `storage.Registry.Primary().InitiateMultipartUpload()`.

**UploadChunk** -- The call to `storage.Provider.UploadPart()` becomes `storage.Registry.Primary().UploadPart()`. Chunks are only uploaded to the primary during the active upload session. Two streaming hashes are maintained in parallel:
- The existing `StreamingHashState` continues to hash only encrypted data (before padding) for `encrypted_file_sha256sum`.
- A new `StoredBlobHashState` hashes ALL data sent to S3, including padding bytes appended to the last chunk, for `stored_blob_sha256sum`.

**CompleteUpload** -- After the primary multipart upload completes successfully:
1. Insert a `file_storage_locations` row with `provider_id = Registry.PrimaryID()`, `status = "active"`.
2. Update `storage_providers.total_objects` and `storage_providers.total_size_bytes` for the primary provider.
3. Store both `encrypted_file_sha256sum` (from StreamingHashState) and `stored_blob_sha256sum` (from StoredBlobHashState) in the `file_metadata` row.
4. If `ENABLE_UPLOAD_REPLICATION` is true and `Registry.HasSecondary()`:
   - Insert a second `file_storage_locations` row with `provider_id = Registry.SecondaryID()`, `status = "pending"`.
   - Kick off a background goroutine that streams the completed object from primary to secondary using `CopyObjectBetweenProviders()`.
   - On success, update the secondary location row to `status = "active"` and update secondary provider stats.
   - On failure, update to `status = "failed"` and log a WARNING.
   - Note: Tertiary is never an auto-replication target.
5. The HTTP response is returned immediately after the primary upload completes. The user does not wait for secondary replication.

**CancelUpload** -- The call to `storage.Provider.AbortMultipartUpload()` becomes `storage.Registry.Primary().AbortMultipartUpload()`. No secondary/tertiary involvement since the upload was never completed.

### Delete Flow (`handlers/uploads.go` -- `DeleteFile`)

The current single `storage.Provider.RemoveObject()` call is replaced with:
1. Query `file_storage_locations` for all locations of this file.
2. For each location with `status = "active"`, call `RemoveObject()` on the corresponding provider via `Registry.GetProvider(providerID)`.
3. For each provider where deletion succeeds, update the location row to `status = "deleted"` and decrement `storage_providers.total_objects` / `total_size_bytes`.
4. For each provider where deletion fails, update the location row to `status = "delete_failed"` and log a WARNING. The orphaned blob is tracked and visible via `storage-sync-status`.
5. Delete the `file_metadata` row and update user storage usage as before. The file is considered deleted from the user's perspective regardless of individual provider deletion outcomes.

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
| verify_storage.go | VerifyStorage | `Provider.PutObject()` etc. | `Registry.GetProvider(id).PutObject()` etc. |

---

## Admin API Endpoints

All endpoints below are admin-only, protected by the existing admin auth middleware. They are implemented in a new file `handlers/admin_storage.go`.

### `GET /api/admin/storage/status`

Returns the current storage configuration, sync status, and cost information.

**Response:**
```json
{
    "providers": [
        {
            "provider_id": "seaweedfs-local",
            "provider_type": "generic-s3",
            "bucket_name": "arkfile-local",
            "region": "us-east-1",
            "role": "primary",
            "env_var_prefix": "STORAGE",
            "is_active": true,
            "total_objects": 142,
            "total_size_bytes": 5368709120,
            "cost_per_tb_cents": null,
            "last_verified_at": "2026-04-20T10:00:00Z",
            "active_count": 142,
            "pending_count": 0,
            "failed_count": 0,
            "delete_failed_count": 0
        },
        {
            "provider_id": "wasabi-us-central-1",
            "provider_type": "wasabi",
            "bucket_name": "arkfile-backup",
            "region": "us-central-1",
            "role": "secondary",
            "env_var_prefix": "STORAGE_2",
            "is_active": true,
            "total_objects": 138,
            "total_size_bytes": 5100000000,
            "cost_per_tb_cents": 799,
            "last_verified_at": "2026-04-20T10:00:00Z",
            "active_count": 138,
            "pending_count": 2,
            "failed_count": 2,
            "delete_failed_count": 0
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

- `verify`: If true, the SHA-256 hash computed during the streaming copy is compared against `stored_blob_sha256sum`. Files with NULL `stored_blob_sha256sum` are copied but not hash-verified (logged as a note).
- `skip_existing`: If true, skip files that already have an `"active"` location on the destination provider.

Note: The source and destination can be any combination of primary/secondary/tertiary providers.

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

### `POST /api/admin/storage/copy-file`

Copies a single file from one provider to another. Returns a task ID for consistency.

**Request:**
```json
{
    "file_id": "abcd1234-...",
    "source_provider_id": "seaweedfs-local",
    "destination_provider_id": "wasabi-us-central-1",
    "verify": true
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

### `GET /api/admin/storage/sync-status`

Returns a detailed breakdown of which files are on which providers, identifies gaps, and reports orphaned blobs from failed deletions.

**Response:**
```json
{
    "total_files": 142,
    "on_primary_only": 4,
    "on_secondary_only": 0,
    "on_all_configured": 50,
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
    ],
    "orphaned_blobs": [
        {
            "file_id": "abc123-...",
            "provider_id": "wasabi-us-central-1",
            "status": "delete_failed"
        }
    ]
}
```

### `POST /api/admin/storage/set-primary`

Promotes a provider to primary. Target must currently be secondary.

**Request:**
```json
{
    "provider_id": "wasabi-us-central-1"
}
```

Before executing, both the target and the current primary undergo connectivity verification (1 MB upload, verify, delete). If either fails, the operation is rejected.

**Response:**
```json
{
    "previous_primary": "seaweedfs-local",
    "new_primary": "wasabi-us-central-1",
    "previous_secondary": "wasabi-us-central-1",
    "new_secondary": "seaweedfs-local",
    "message": "Primary provider updated. New uploads will use wasabi-us-central-1."
}
```

### `POST /api/admin/storage/set-secondary`

Promotes or demotes a provider to secondary. Target can be primary (demotion) or tertiary (promotion).

**Request:**
```json
{
    "provider_id": "backblaze-us-west"
}
```

If target is currently tertiary: target becomes secondary, old secondary becomes tertiary. If target is currently primary: target becomes secondary, old secondary becomes primary (equivalent to swap).

Both affected providers are verified before the change.

### `POST /api/admin/storage/set-tertiary`

Demotes a provider to tertiary. Target must currently be secondary.

**Request:**
```json
{
    "provider_id": "wasabi-us-central-1"
}
```

Old tertiary promotes to secondary. Both affected providers are verified.

### `POST /api/admin/storage/swap-providers`

Convenience endpoint that swaps primary and secondary. Both providers are verified before the swap.

**Request:**
```json
{}
```

### `POST /api/admin/storage/verify-storage`

Performs a round-trip connectivity test (1 MB upload, verify hash, delete) against any configured provider.

**Request:**
```json
{
    "provider_id": "wasabi-us-central-1"
}
```

If `provider_id` is omitted, defaults to verifying the primary provider.

Updates `storage_providers.last_verified_at` on success.

### `POST /api/admin/storage/set-cost`

Sets the monthly cost per TB for a provider. Admin-only utility for cost tracking.

**Request:**
```json
{
    "provider_id": "wasabi-us-central-1",
    "cost_per_tb_cents": 799
}
```

### `GET /api/admin/alerts/summary`

Returns unacknowledged alerts and storage health warnings. Called by the arkfile-admin CLI after successful login to surface issues immediately.

**Response:**
```json
{
    "storage_alerts": {
        "unreachable_providers": [],
        "replication_failures": 2,
        "sync_gaps": 4,
        "orphaned_blobs": 0,
        "stale_tasks": 0
    },
    "unacknowledged_security_alerts": 0,
    "message": "2 replication failures, 4 files not fully replicated. Run 'storage-sync-status' for details."
}
```

---

## arkfile-admin CLI Commands

All new commands are network commands that authenticate via the existing admin session and call the Admin API endpoints defined above. They are added to `cmd/arkfile-admin/main.go` (command routing) with implementation in a new file `cmd/arkfile-admin/storage_commands.go`.

### Updated Usage Block

The following commands are added to the usage text:

```
STORAGE MANAGEMENT COMMANDS (Admin API):
    storage-status        Show configured providers, file counts, sync status, and costs
    storage-sync-status   Detailed breakdown of file locations and replication gaps
    copy-all              Copy all files from one provider to another
    copy-user-files       Copy all files for a specific user between providers
    copy-file             Copy a single file between providers
    task-status           Check status of a background storage task
    cancel-task           Cancel a running background storage task
    set-primary           Promote a provider to primary (new uploads go here)
    set-secondary         Promote/demote a provider to secondary (auto-replication target)
    set-tertiary          Demote a provider to tertiary (manual-only)
    swap-providers        Swap primary and secondary provider roles
    verify-storage        Verify storage connectivity (any provider by --provider-id)
    set-cost              Set monthly cost per TB for a provider
```

Note: The existing `list-files` command will be enhanced to include storage location indicators (provider IDs where each file is stored). No separate `list-user-files` command is needed.

### `storage-status`

Calls `GET /api/admin/storage/status` and displays a formatted overview.

```
arkfile-admin storage-status
```

Example output:
```
Storage Providers:

  ID                    TYPE         BUCKET           ROLE       ACTIVE  FILES  SIZE     COST/TB  VERIFIED
  seaweedfs-local       generic-s3   arkfile-local    primary    yes     142    5.0 GB   --       2026-04-20
  wasabi-us-central-1   wasabi       arkfile-backup   secondary  yes     138    4.8 GB   $7.99    2026-04-20
  backblaze-us-west     backblaze    arkfile-archive  tertiary   yes     50     1.9 GB   $6.00    2026-04-19

Replication: enabled
Total files: 142 | Fully replicated: 138 | Gaps: 4
Estimated monthly cost: $0.08 (wasabi: $0.04, backblaze: $0.01, seaweedfs: self-hosted)
```

### `storage-sync-status`

Calls `GET /api/admin/storage/sync-status` and displays detailed gap information.

```
arkfile-admin storage-sync-status
arkfile-admin storage-sync-status --show-gaps
```

Flags:
- `--show-gaps` -- Only show files with replication gaps (not on all configured providers).

### `copy-all`

Calls `POST /api/admin/storage/copy-all`.

```
arkfile-admin copy-all --from seaweedfs-local --to wasabi-us-central-1 --verify --skip-existing
```

Flags:
- `--from PROVIDER_ID` -- Source provider (required).
- `--to PROVIDER_ID` -- Destination provider (required).
- `--verify` -- Verify SHA-256 hash during streaming copy (default: false).
- `--skip-existing` -- Skip files already present on destination (default: true).
- `--dry-run` -- Show what would be copied without starting a task.

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
arkfile-admin copy-file --file-id abcd1234-... --from seaweedfs-local --to wasabi-us-central-1 --verify
```

Flags:
- `--file-id ID` -- File to copy (required).
- `--from PROVIDER_ID` -- Source provider (required).
- `--to PROVIDER_ID` -- Destination provider (required).
- `--verify` -- Verify SHA-256 hash during streaming copy (default: false).

### `task-status`

Calls `GET /api/admin/storage/task/:taskId`.

```
arkfile-admin task-status --task-id a1b2c3d4-...
arkfile-admin task-status --task-id a1b2c3d4-... --watch
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

### `set-primary`

Calls `POST /api/admin/storage/set-primary`. Target must currently be secondary.

```
arkfile-admin set-primary --provider-id wasabi-us-central-1
```

Confirms interactively before executing:
```
Current primary: seaweedfs-local
Promote wasabi-us-central-1 to primary? seaweedfs-local will become secondary. [y/N]: y
Verifying wasabi-us-central-1... [OK]
Verifying seaweedfs-local... [OK]
Primary provider updated. New uploads will use wasabi-us-central-1.
```

### `set-secondary`

Calls `POST /api/admin/storage/set-secondary`. Target can be primary or tertiary.

```
arkfile-admin set-secondary --provider-id backblaze-us-west
```

### `set-tertiary`

Calls `POST /api/admin/storage/set-tertiary`. Target must currently be secondary.

```
arkfile-admin set-tertiary --provider-id wasabi-us-central-1
```

### `swap-providers`

Calls `POST /api/admin/storage/swap-providers`.

```
arkfile-admin swap-providers
```

Confirms interactively:
```
Current primary: seaweedfs-local
Current secondary: wasabi-us-central-1
Swap providers? New uploads will go to wasabi-us-central-1. [y/N]: y
Verifying both providers...
Providers swapped. New primary: wasabi-us-central-1
```

### `verify-storage`

Calls `POST /api/admin/storage/verify-storage`.

```
arkfile-admin verify-storage --provider-id wasabi-us-central-1
arkfile-admin verify-storage  # defaults to primary
```

### `set-cost`

Calls `POST /api/admin/storage/set-cost`.

```
arkfile-admin set-cost --provider-id wasabi-us-central-1 --cost 7.99
```

The `--cost` flag accepts a dollar amount (e.g. 7.99) which is converted to cents internally.

### Enhanced `list-files` Command

The existing `list-files` command is enhanced to include storage location indicators by joining `file_metadata` with `file_storage_locations`. No separate `list-user-files` command is needed -- one command shows all important info for a user's files.

```
arkfile-admin list-files --username alice12345
```

Example output (enhanced with storage locations):
```
Files for alice12345 (3 files, 2.5 GB total):

  FILE_ID         SIZE     CHUNKS  TYPE      UPLOADED            LOCATIONS
  abcd1234-...    1.2 GB   75      account   2026-04-23T18:05Z   wasabi-us-central-1
  efgh5678-...    800 MB   50      custom    2026-04-22T10:30Z   wasabi-us-central-1, backblaze-us-west
  ijkl9012-...    500 MB   32      account   2026-04-21T14:15Z   wasabi-us-central-1 (not replicated)
```

The LOCATIONS column shows all providers where the file has an `"active"` storage location. When multi-backend is configured and a file is not on all active providers, "(not replicated)" is appended.

### Admin Login Alerts

After a successful `arkfile-admin login`, the CLI calls `GET /api/admin/alerts/summary` and displays any active warnings:

```
arkfile-admin login
Username: myadmin
Password: ********
Login successful.

[!] Storage alerts:
  - 2 replication failures
  - 4 files not fully replicated
  Run 'arkfile-admin storage-sync-status' for details.
```

If there are no alerts, nothing extra is displayed.

---

## Background Task System

Background tasks are managed by a lightweight in-process task runner. This avoids the complexity of external job queues while providing reliable progress tracking and cancellation for long-running storage operations.

### Implementation: `handlers/admin_task_runner.go`

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

**Concurrency limit**: At most 2 copy tasks run concurrently by default. This prevents a bulk copy-all from saturating network bandwidth or starving normal upload/download operations.

**Cancellation**: Each task gets a `context.WithCancel()`. The cancel function is stored in the `activeTasks` map. When `cancel-task` is called, the context is canceled, and the copy loop checks `ctx.Err()` between files to stop gracefully.

**Progress updates**: The background goroutine updates `admin_tasks.progress_current` in the database after each file is processed. The `task-status` API reads directly from the database, so progress is visible immediately.

### Task Lifecycle

1. **Creation**: The admin API handler validates the request, counts the files to be copied, inserts an `admin_tasks` row with `status = "pending"` and `progress_total = N`, and submits the task to the runner.

2. **Execution**: The runner acquires a semaphore slot, updates the task to `status = "running"`, and begins iterating over the file list. For each file:
   a. Check if the context is canceled. If so, update task to `status = "canceled"` and return.
   b. If `skip_existing` is true, check if a `file_storage_locations` row with `status = "active"` exists for this file on the destination. Skip if present.
   c. Stream the object from source to destination using `CopyObjectBetweenProviders()`. The returned SHA-256 hash is checked against `stored_blob_sha256sum` if `verify` is true and the hash is not NULL.
   d. Insert or update the `file_storage_locations` row for the destination provider. Update `storage_providers` stats.
   e. Increment `progress_current` in the `admin_tasks` row.

3. **Completion**: After all files are processed, update the task to `status = "completed"` with `completed_at` timestamp and final counts in the `details` JSON.

4. **Failure**: Individual file copy failures do not fail the entire task. They are recorded in the `details` JSON and the file's `file_storage_locations` row is set to `status = "failed"`. The task continues with the next file. If an unrecoverable error occurs (e.g. source provider completely unreachable), the task is marked `status = "failed"` with the error message.

### Server Restart Behavior

Tasks that are `"running"` when the server restarts will remain in `"running"` status in the database. On startup, the task runner scans for stale `"running"` tasks and marks them as `"failed"` with a message indicating the server was restarted. The admin can then re-trigger the operation with `--skip-existing` to resume where it left off.

---

## Data Migration Plan

### Principle: No Existing Data is Modified or Lost

The migration is purely additive. New tables are created, new columns are added, and backfill queries populate them from existing data. No columns are removed from `file_metadata`. No existing rows are modified. No S3 objects are touched.

### Step 1: Schema Migration

Run the new `CREATE TABLE IF NOT EXISTS` statements for `storage_providers`, `file_storage_locations`, and `admin_tasks`. Run the `ALTER TABLE file_metadata ADD COLUMN stored_blob_sha256sum` statement. Since all three tables use `IF NOT EXISTS` and SQLite ALTER TABLE ADD COLUMN is idempotent (errors if column exists, but can be wrapped in a check), this is safe to run multiple times. These statements are added to `database/unified_schema.sql` so they execute automatically on every startup.

### Step 2: Backfill `storage_providers`

On server startup, after `InitS3()` completes, the server upserts the primary provider into `storage_providers`:

```sql
INSERT OR REPLACE INTO storage_providers (provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix, is_active)
VALUES (?, ?, ?, ?, ?, 'primary', 'STORAGE', true)
```

If a secondary provider is configured, a second upsert is performed with `role = 'secondary'` and `env_var_prefix = 'STORAGE_2'`. If a tertiary provider is configured, a third upsert with `role = 'tertiary'` and `env_var_prefix = 'STORAGE_3'`. Existing role assignments in the DB are preserved (DB is authoritative).

### Step 3: Backfill `file_storage_locations`

On server startup (after the provider upsert), a one-time backfill populates location records for all existing files that do not yet have a location entry:

```sql
INSERT INTO file_storage_locations (file_id, provider_id, storage_id, status, created_at)
SELECT file_id, ?, storage_id, 'active', upload_date
FROM file_metadata
WHERE file_id NOT IN (SELECT file_id FROM file_storage_locations)
```

The `?` parameter is the primary provider ID. This is idempotent: the `WHERE file_id NOT IN (...)` clause ensures it only inserts rows for files without location records.

After backfill, every existing file has exactly one `file_storage_locations` row recording that it exists on the current primary provider.

### Step 4: Backfill `storage_providers` Stats

After the location backfill, update the cached stats on the primary provider:

```sql
UPDATE storage_providers
SET total_objects = (SELECT COUNT(*) FROM file_storage_locations WHERE provider_id = ? AND status = 'active'),
    total_size_bytes = (SELECT COALESCE(SUM(fm.padded_size), 0) FROM file_storage_locations fsl
                        JOIN file_metadata fm ON fsl.file_id = fm.file_id
                        WHERE fsl.provider_id = ? AND fsl.status = 'active')
WHERE provider_id = ?
```

### Step 5: Ongoing Operation

From this point forward, all new uploads create `file_storage_locations` rows as part of the `CompleteUpload` handler. The backfill query continues to run on startup as a safety net.

### Concrete test.arkfile.net Migration Recipe

```
Migration: test.arkfile.net SeaweedFS -> Wasabi Primary

1. SSH into test VPS, git pull latest code
2. Add to /opt/arkfile/etc/secrets.env:
   STORAGE_PROVIDER_ID=seaweedfs-test
   STORAGE_PROVIDER_2=wasabi
   STORAGE_PROVIDER_2_ID=wasabi-us-central-1
    STORAGE_2_ENDPOINT=https://s3.us-central-1.wasabisys.com
    STORAGE_2_ACCESS_KEY=<key>
    STORAGE_2_SECRET_KEY=<secret>
    STORAGE_2_BUCKET=arkfile-test
    STORAGE_2_REGION=us-central-1
    STORAGE_2_FORCE_PATH_STYLE=true
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
13. (Optional) Add Backblaze B2 as tertiary:
    - Add STORAGE_PROVIDER_3=backblaze, STORAGE_PROVIDER_3_ID=backblaze-us-west,
      STORAGE_3_ENDPOINT=s3.us-west-004.backblazeb2.com, etc. to secrets.env
    - Restart server
    - arkfile-admin copy-all --from wasabi-us-central-1 --to backblaze-us-west --verify --skip-existing
    - arkfile-admin storage-status  (verify three providers)
```

### `stored_blob_sha256sum` Backfill for Existing Files

Files uploaded before the `stored_blob_sha256sum` feature will have NULL values. Options:

**(A) Accept NULL for existing files.** Copy operations work but cannot hash-verify pre-existing files. This is the default for v1.

**(B) Optional `hash-backfill` command.** A future `arkfile-admin hash-backfill` command downloads each blob from the primary provider, computes its SHA-256, and stores it. This is a one-time operation. It can be implemented post-launch when needed.

---

## Testing Strategy

### Local Testing with Real Cloud Providers

The primary testing environment uses 1 local SeaweedFS instance (primary) plus real cloud storage providers (secondary and/or tertiary). No containers, no multi-instance local S3 setups.

**Recommended test configurations:**

1. **Two-provider (primary development):** Local SeaweedFS + Wasabi cloud bucket
2. **Two-provider (same type, different regions):** Two Wasabi buckets in different regions (e.g. us-central-1 and eu-central-2)
3. **Three-provider:** Local SeaweedFS + Wasabi + Backblaze B2
4. **Single-provider (regression):** Local SeaweedFS only, confirming all existing functionality works unchanged

**Supported provider types to validate against:** generic-s3 (SeaweedFS), wasabi, backblaze, cloudflare-r2, vultr, aws-s3.

**Cloud accounts needed before implementation begins:** Wasabi (primary test target), Backblaze B2 (secondary test target, also cheap for tertiary testing).

### Unit Tests

**`storage/registry_test.go`**: Tests for the `ProviderRegistry` methods:
- `GetObjectWithFallback` returns from primary when primary succeeds.
- `GetObjectWithFallback` returns from secondary when primary fails.
- `GetObjectWithFallback` returns from tertiary when primary and secondary fail.
- `GetObjectWithFallback` returns error when all three fail.
- `GetObjectChunkWithFallback` same three-tier patterns.
- `RemoveObjectAll` removes from all configured providers, handles partial failures, tracks `delete_failed`.
- `CopyObjectBetweenProviders` streams correctly for small and large objects, returns correct SHA-256.

These tests use the existing `MockObjectStorageProvider` and `MockStoredObject` from `storage/mock_storage.go`.

**`handlers/admin_storage_test.go`**: Tests for the admin API endpoints:
- `storage-status` returns correct provider information with `role` field and stats.
- `copy-file` creates a task and returns a task ID.
- `task-status` returns correct progress.
- `set-primary` updates roles correctly (secondary -> primary, old primary -> secondary).
- `set-secondary` updates roles correctly for both promotion and demotion.
- `set-tertiary` updates roles correctly.
- Role change rejected when target is wrong tier (e.g. set-primary on tertiary).
- Role change rejected when connectivity verification fails.

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

6. **Tertiary provider**: Add a tertiary provider via env config. Copy files to it. Verify three-tier fallback by stopping primary and secondary, confirming download from tertiary.

7. **Role promotion**: Test `set-secondary` to promote tertiary to secondary. Verify auto-replication targets the new secondary.

8. **Stored blob hash verification**: Upload a file, verify `stored_blob_sha256sum` is populated. Copy with `--verify`, confirm hash match is logged.

---

## Implementation Order

The implementation is organized into phases that can each be developed, tested, and committed independently.

### Phase 0: Dead Code Cleanup [COMPLETE]

Remove the `file_shares` legacy table, its indexes, and add a DROP statement for existing deployments. Run `dev-reset.sh` and `e2e-test.sh` to confirm nothing breaks.

### Phase 1: Storage Layer Foundation [COMPLETE]

Introduce the provider registry and config-struct factory function without changing any handler behavior.

Files changed:
- `storage/s3.go` -- Extract `NewS3Provider(config S3ProviderConfig)` factory function from `InitS3()`.
- `storage/registry.go` -- New file with `ProviderRegistry` struct, `Primary()`, `Secondary()`, `Tertiary()`, `HasSecondary()`, `HasTertiary()`, ID methods.
- `storage/storage.go` -- Remove `Provider` global, add `Registry` global.
- `storage/mock_storage.go` -- Add `MockProviderRegistry` supporting three providers.
- `storage/registry_test.go` -- Unit tests for registry methods.

Verification: All existing e2e tests pass unchanged. `storage.Registry.Primary()` replaces all `storage.Provider` references.

### Phase 2: Schema and Models [COMPLETE]

Add new database tables, new column, and model functions.

Files changed:
- `database/unified_schema.sql` -- Add `storage_providers`, `file_storage_locations`, `admin_tasks` tables. Add `stored_blob_sha256sum` column to `file_metadata`. Remove `file_shares` table/indexes, add DROP statement.
- `models/file_storage_location.go` -- New file with `FileStorageLocation` struct and CRUD functions.
- `models/storage_provider.go` -- New file with `StorageProvider` struct and CRUD functions.
- `models/admin_task.go` -- New file with `AdminTask` struct and CRUD functions.

Verification: Run `dev-reset.sh`, confirm tables are created. Existing data and functionality unaffected.

### Phase 3: Startup Backfill and Provider Registration [COMPLETE]

On server startup, register providers and backfill location records.

Files changed:
- `main.go` -- After `storage.InitS3()`, upsert providers, run backfill, update stats, check DB for role assignments.
- `.env.example` -- Add `STORAGE_PROVIDER_ID`, `STORAGE_PROVIDER_2`, `STORAGE_2_*`, `STORAGE_PROVIDER_3`, `STORAGE_3_*`, `ENABLE_UPLOAD_REPLICATION` variables (all commented out).

Verification: Run `dev-reset.sh` and `e2e-test.sh`. Verify `file_storage_locations` has one row per file. All existing tests pass.

PROGRESS NOTE - 04/22/26 - local deploy/local update are still passing and functional with existing credentials for test wasabi cloud bucket as main (primary and only) storage in the local system

PROGRESS NOTE - 04/23/26 - Phases 4, 5, 6 (partial), and 7 (partial) implemented in a single session. All code compiles cleanly. Upload/download/delete verified working with Wasabi as single primary provider via local-update.sh. stored_blob_sha256sum is populated on new uploads. file_storage_locations rows are created on upload and cleaned up on delete. Three-tier download fallback is wired up (transparent in single-provider mode). Fixed missing ALTER TABLE for stored_blob_sha256sum migration. Also: consolidated list-user-files into existing list-files command, updated TOTP apps modal.

PROGRESS NOTE - 04/23/26 (session 2) - Completed Phases 6, 8, 9, 10 (partial). Full implementation of: CopyObjectBetweenProviders with TeeReader SHA-256 verification (64MB multipart parts, 100MB threshold), ENABLE_UPLOAD_REPLICATION config + replicateToSecondary() background goroutine, TaskRunner with semaphore concurrency (2 workers) and cancellation, all 14 admin API endpoints (storage-status, sync-status, copy-all, copy-user-files, copy-file, task-status, cancel-task, set-primary, set-secondary, set-tertiary, swap-providers, verify-storage, set-cost, alerts/summary), all routes registered, all 12 CLI commands in storage_commands.go, enhanced list-files with LOCATIONS column and password_type, displayLoginAlerts() wired into login flow, AdminVerifyStorage provider name fix for non-primary providers. Schema migration fix: moved stored_blob_sha256sum ALTER TABLE from unified_schema.sql to Go startup code (runSchemaMigrations() in main.go) to handle both fresh installs and existing deployments without fatal rqlite errors. Deployed and verified working via local-update.sh with Wasabi single-provider mode.

PROGRESS NOTE - 04/24/26 - First live multi-backend testing session. Added Wasabi cloud bucket as secondary provider to a local SeaweedFS deployment via secrets.env + systemctl restart. Tested and verified: storage-status (both providers detected with correct roles), copy-file (single file copied to Wasabi, confirmed via Wasabi web console by storage_id match), copy-user-files (4 files for a test user, all copied successfully), copy-all with --skip-existing (4 small files skipped, 1 large 1.95 GB file streamed via 64 MB multipart parts to Wasabi). list-files shows dual locations for all copied files. Bugs found and fixed during testing:
- (1) task-status HTTP 500: AdminTask.CreatedAt/UpdatedAt were time.Time but rqlite returns timestamps as strings. Fixed to sql.NullString in models/admin_task.go.
- (2) verify-storage CLI: Missing --provider-id flag, was hardcoded to primary only. Added flag and switched to /api/admin/storage/verify-storage endpoint in cmd/arkfile-admin/verify_storage.go.
- (3) Login alerts pluralization: formatAlertCount naively appended "s" producing "3 file not fully replicateds". Changed to accept singular/plural label pairs in handlers/admin_storage.go.
- (4) skip-existing not working: FileStorageLocation.CreatedAt was time.Time (same rqlite timestamp issue). GetActiveFileStorageLocations silently failed, returning empty results, so skip-existing always re-copied. Fixed to sql.NullString in models/file_storage_location.go.
- (5) No per-file byte progress for large copies: Added CopyProgressFunc callback to CopyObjectBetweenProviders (storage/registry.go), progress callback in task runner (handlers/admin_task_runner.go), UpdateAdminTaskDetails model function (models/admin_task.go), and "Current file: X / Y (Z%)" display in CLI task-status (cmd/arkfile-admin/storage_commands.go).
- (6) Task details not persisted after skip/fail: Details JSON was only written by the copy progress callback. Added persistDetails() helper called after every file operation (skip, copy start, copy progress, copy success, copy fail) so task-status always shows current state.
- (7) swap-providers not persisting across restart: InitS3() always built registry from env var ordering, ignoring DB roles. Added SwapPrimarySecondary() method to ProviderRegistry (storage/registry.go) and DB role reconciliation in registerAndBackfillStorageProviders() (main.go) that reads DB roles after upsert and swaps the in-memory registry if needed.
- (8) verify-storage and startup verification using env var provider name: Both AdminVerifyStorage handler and RunStartupVerification used os.Getenv("STORAGE_PROVIDER") for the display name, always showing "generic-s3" even after swap. Fixed both to use Registry.PrimaryID() and DB lookup.
- (9) Replication to non-TLS SeaweedFS failing: AWS SDK v2 requires seekable streams for SigV4 payload signing on HTTP connections. CopyObjectBetweenProviders used TeeReader (not seekable). Fixed by buffering data into bytes.Reader before PutObject/UploadPart. Memory bounded: max 100 MB for small files, 64 MB per part for multipart. Also added RequestChecksumCalculationWhenRequired for non-TLS S3 clients in NewS3Provider (storage/s3.go).

Additional tests verified in this session:
- [OK] swap-providers persists across restart (DB-authoritative roles applied on startup)
- [OK] Download fallback: stopped SeaweedFS, files served from Wasabi, sha256sum matches original
- [OK] verify-storage --provider-id for both providers
- [OK] Multi-provider delete: file removed from both Wasabi and SeaweedFS
- [OK] copy-all with --skip-existing: 4 files skipped, 1 large 1.95 GB file copied with hash verification
- [OK] ENABLE_UPLOAD_REPLICATION: Wasabi primary -> SeaweedFS secondary, blobs byte-identical (confirmed via sha256sum of raw objects from both provider consoles)
- [OK] Task status with per-file byte progress for large multipart copies
- [OK] Login alerts with correct singular/plural grammar

### Phase 4: Stored Blob Hash (Upload Enhancement) [COMPLETE]

Add the second streaming hash for `stored_blob_sha256sum` during upload.

Files changed:
- `handlers/uploads.go` -- Add `StoredBlobHashState` parallel to existing `StreamingHashState`. Include padding bytes in the stored blob hash. Write `stored_blob_sha256sum` to `file_metadata` on CompleteUpload.
- `handlers/streaming_hash.go` -- May need a second hash type or extend existing.

Verification: Upload a file, verify `stored_blob_sha256sum` is populated and differs from `encrypted_file_sha256sum`. All existing tests pass.

### Phase 5: Handler Updates -- Downloads with Fallback [COMPLETE]

Update download handlers to use three-tier fallback.

Files changed:
- `storage/registry.go` -- Implement `GetObjectWithFallback()` and `GetObjectChunkWithFallback()`.
- `handlers/downloads.go` -- Replace `storage.Provider.GetObjectChunk()` with `storage.Registry.GetObjectChunkWithFallback()`.
- `handlers/file_shares.go` -- Same replacement in `DownloadShareChunk`.
- `handlers/export.go` -- Replace `storage.Provider.GetObject()` with `storage.Registry.GetObjectWithFallback()`.

Verification: All existing download/share/export tests pass. In single-provider mode, fallback is never triggered.

### Phase 6: Handler Updates -- Uploads with Location Recording [COMPLETE]

Location recording on upload, provider stats update, CopyObjectBetweenProviders with TeeReader SHA-256 verification, and replicateToSecondary() background goroutine: all implemented. Awaiting multi-provider testing when secondary is configured.

Update upload handlers to record locations and optionally replicate.

Files changed:
- `handlers/uploads.go` -- In `CompleteUpload`, insert `file_storage_locations` row, update provider stats. If replication enabled, kick off background replication.
- `storage/registry.go` -- Implement `CopyObjectBetweenProviders()` with TeeReader hash verification.
- Replace all remaining `storage.Provider.XXX()` calls in uploads.go with `storage.Registry.Primary().XXX()`.

Verification: Upload a file, confirm `file_storage_locations` row is created. With replication enabled, confirm the blob appears on both providers.

### Phase 7: Handler Updates -- Deletes from All Providers [PARTIALLY COMPLETE]

Multi-provider delete with location tracking and stats decrement: done (inline in DeleteFile handler). RemoveObjectAll registry method: not yet extracted (logic is in handler directly).

Update delete handler to remove from all providers with failure tracking.

Files changed:
- `handlers/uploads.go` (`DeleteFile`) -- Query `file_storage_locations`, remove from each active provider, track `delete_failed`.
- `storage/registry.go` -- Implement `RemoveObjectAll()`.

Verification: Upload a file with replication, confirm on both providers, delete, confirm removed from both. Test partial failure handling.

### Phase 8: Background Task System [COMPLETE]

Implement the task runner and admin task management.

Files changed:
- `handlers/admin_task_runner.go` -- New file with `TaskRunner`, task execution loop, cancellation support.
- `models/admin_task.go` -- Finalize CRUD with progress update functions.
- `main.go` -- Initialize task runner on startup, mark stale tasks as failed.

Verification: Unit tests for task lifecycle (create, run, complete, cancel, fail).

### Phase 9: Admin API Endpoints and CLI Commands [COMPLETE]

Implement all admin storage management endpoints and CLI commands.

Files changed:
- `handlers/admin_storage.go` -- New file with all endpoint handlers.
- `handlers/route_config.go` -- Register new admin routes.
- `cmd/arkfile-admin/main.go` -- Add command routing for new storage commands.
- `cmd/arkfile-admin/storage_commands.go` -- New file with all CLI command handlers.

Verification: Test each command against a local deployment with a Wasabi secondary. Test the full provider migration workflow end-to-end.

### Phase 10: Admin Alerts, Enhanced list-files, and e2e Test Extensions [PARTIALLY COMPLETE]

Alerts summary endpoint, enhanced list-files with LOCATIONS column, and displayLoginAlerts() wired into login: all done. Sync-status response simplified vs spec (only on_primary_only/on_secondary_only, not full combination matrix). e2e test extensions not yet added.

Finalize admin login alerts, enhance existing `list-files` with storage locations, and extend e2e tests.

Files changed:
- `handlers/admin_storage.go` -- Add `alerts/summary` endpoint.
- `handlers/admin.go` -- Enhance `list-files` API response to include `file_storage_locations` data.
- `cmd/arkfile-admin/main.go` -- Update `list-files` CLI output to show LOCATIONS column.
- `cmd/arkfile-admin/storage_commands.go` -- Add login alert display.
- `scripts/testing/e2e-test.sh` -- Add multi-backend test scenarios.

Verification: Full e2e test suite passes in single-provider and multi-provider modes.

### Phase 11: Bulk Integrity Verification (verify-all) [NOT STARTED]

A `verify-all` command that performs HEAD requests against every `file_storage_locations` row with `status = "active"` to confirm the S3 object actually exists and its size matches `padded_size`. This catches out-of-band deletions, provider-side data loss, and DB/reality drift without downloading any file data.

#### New Status: `"missing"`

Add `"missing"` to the valid `file_storage_locations.status` values alongside "active", "pending", "failed", "deleted", "delete_failed". A `"missing"` status means the DB thought the blob was there but verification confirmed it is not. `copy-all --skip-existing` skips `"active"` but NOT `"missing"`, so a subsequent copy-all naturally re-copies the gaps.

#### New Interface Method: `HeadObject`

Add `HeadObject(ctx, objectName) (int64, error)` to the `ObjectStorageProvider` interface. Returns the object size in bytes (from S3 HEAD response Content-Length), or an error if the object does not exist. Implementation is a single `s3Client.HeadObject` call.

#### CLI Command

```
arkfile-admin verify-all [FLAGS]

FLAGS:
    --provider-id ID    Only verify files on this provider (default: all providers)
    --fix               Mark missing files as "missing" in DB (default: dry-run)
    --concurrency N     Parallel HEAD requests (default: 10)
    --json              Output as JSON
```

#### Admin UX Example (5000 files, 2 providers)

```
$ arkfile-admin verify-all

Verifying all file locations across 2 providers...

  Provider: generic-s3:arkfile-local
  Checking 5000 files... [5000/5000] (100.0%)
  Result: 5000 OK, 0 missing, 0 size mismatch

  Provider: wasabi-us-central-1
  Checking 5000 files... [5000/5000] (100.0%)
  Result: 4998 OK, 2 missing, 0 size mismatch

Summary:
  Total locations verified: 10000
  OK: 9998
  Missing: 2
  Size mismatch: 0

  Missing files (not updated, use --fix to mark):
    file: abc123-...  provider: wasabi-us-central-1  owner: user42
    file: def456-...  provider: wasabi-us-central-1  owner: user87
```

With `--fix`:
```
$ arkfile-admin verify-all --fix

  ...same output...

  2 locations updated: status changed from "active" to "missing"
  Run 'copy-all --skip-existing' to re-copy missing files.
```

#### Performance Estimates (5000 files, 2 providers)

- 5000 files x 2 providers = 10,000 HEAD requests
- HEAD requests are tiny (no data transfer, just metadata)
- At 10 concurrent requests: ~50-100ms per HEAD on cloud providers
- SeaweedFS (local): ~5000 HEADs at 10 concurrency = ~25-50 seconds
- Wasabi (cloud): ~5000 HEADs at 10 concurrency = ~2-5 minutes (network latency)
- Total: roughly 3-6 minutes for a full verification pass
- Wasabi does not charge for HEAD requests (included in API call allowance)

#### Implementation

Uses the existing TaskRunner infrastructure (background task with progress tracking):

Files to change:
- `storage/types.go` -- Add `HeadObject(ctx, objectName) (int64, error)` to `ObjectStorageProvider` interface
- `storage/s3.go` -- Implement `HeadObject` using `s3Client.HeadObject`
- `storage/mock_storage.go` -- Add mock `HeadObject`
- `handlers/admin_storage.go` -- Add `AdminVerifyAll` handler for `POST /api/admin/storage/verify-all`
- `handlers/admin_task_runner.go` -- Add `runVerifyTask` goroutine with concurrent HEAD workers
- `handlers/route_config.go` -- Register new route
- `cmd/arkfile-admin/storage_commands.go` -- Add `verify-all` CLI command
- `cmd/arkfile-admin/main.go` -- Add command routing

#### Task Type

New `admin_tasks.task_type` value: `"verify-all"`. Uses the same progress tracking (progress_current/progress_total) and details JSON (verified_ok, missing, size_mismatch counts).

---

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

### Modified Files
- `storage/s3.go` -- Config struct factory function extraction, `InitS3()` reads three provider configs
- `storage/storage.go` -- Remove `Provider` global, add `Registry` global
- `storage/mock_storage.go` -- Add mock registry with three-provider support
- `main.go` -- Registry init, backfill, task runner init, stale task cleanup
- `database/unified_schema.sql` -- Remove `file_shares` table/indexes, add `DROP TABLE IF EXISTS file_shares`, add `storage_providers`, `file_storage_locations`, `admin_tasks` tables, add `stored_blob_sha256sum` column
- `.env.example` -- New env var templates for secondary/tertiary providers
- `handlers/uploads.go` -- Registry calls, location recording, replication, dual streaming hash
- `handlers/streaming_hash.go` -- StoredBlobHashState for post-padding hash
- `handlers/downloads.go` -- Three-tier fallback downloads
- `handlers/file_shares.go` -- Three-tier fallback downloads
- `handlers/export.go` -- Three-tier fallback downloads
- `handlers/route_config.go` -- New admin routes
- `cmd/arkfile-admin/main.go` -- New command routing
- `cmd/arkfile-admin/verify_storage.go` -- Use Registry.GetProvider() instead of Provider
- `scripts/testing/e2e-test.sh` -- Multi-backend test scenarios

### Unchanged
- All crypto code
- All client-side TypeScript code
- All auth code (OPAQUE, JWT, TOTP)
- The `file_metadata` table schema (except the one new column)
- The `arkfile-client` CLI

---
