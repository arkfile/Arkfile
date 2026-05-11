# Slice C — File Upload / Download / Chunking

Status: **Complete** (2026-05-11). This is the consolidated, definitive deliverable for Slice C of the Arkfile in-depth security review per `docs/wip/idsrp.md`. It covers the chunked upload pipeline (`handlers/uploads.go`, `crypto/streaming_hash.go`), the per-chunk download path (`handlers/downloads.go`), file metadata APIs (`handlers/files.go`), the storage provider abstraction and multi-provider registry (`storage/*.go`), the file/location/provider models (`models/file.go`, `models/file_storage_location.go`, `models/storage_provider.go`), the browser TypeScript upload/download stack (`client/static/js/src/files/**`, `__tests__/streaming-download.test.ts`), and the erasure-coding doc vs. code alignment.

Findings are numbered `C-01` through `C-27`, severity-ordered, single series.

---

## 0. Scope

### `idsrp.md` sections covered

- **§6** (file encryption) — wire-path coverage. Primitive-level crypto was done in Slice B (`B-02`/`B-05`/`B-06`/`B-08`); Slice C audits whether the wire path makes those findings exploitable in practice.
- **§8** (backend authorization & object storage) — full coverage for the file/upload routes and the multi-provider storage layer. Shares are Slice D; admin/billing are Slice E.
- **§10** (API security) — for the C-scope endpoints only. Full Endpoint Review Table (with TOTP-gated column) is Slice E; the C-subset table appears here in §3.1.
- **§17** (testing) — limited to upload/download/chunk tests in `handlers/chunked_upload_*_test.go`, `handlers/files_test.go`, and `client/static/js/src/__tests__/streaming-download.test.ts`.

### Files actually read

| File | LOC | Why |
|---|---:|---|
| `handlers/files.go` | 327 | File metadata APIs: `GetFileMeta`, `ListFiles`, `ListRecentFileMetadata`, `GetFileMetadataBatch`, `GetFileEnvelope`. |
| `handlers/uploads.go` | 1158 | Chunked upload session lifecycle: `CreateUploadSession`, `UploadChunk`, `CompleteUpload`, `CancelUpload`, `GetUploadStatus`, `DeleteFile`, `replicateToSecondary`. The largest file in scope. |
| `handlers/downloads.go` | 146 | `DownloadFileChunk` per-chunk byte-range fetch. |
| `handlers/streaming_hash.go` | 78 | `StreamingHashState` and `StreamingHashTeeReader` — SHA-256 hasher state held in process memory across upload-chunk requests. |
| `handlers/route_config.go` | 260 | C-scope route registration / TOTP middleware wiring. |
| `models/file.go` | 672 | `File`, `FileMetadataForClient`, `GetFileByFileID`, `GetFilesByOwner`, `CreateFile`, `DeleteFile`, `GetFileMetadataBatchByOwner`. Includes the documentation comment block (L14-39) on the two SHA-256 fields. |
| `models/file_storage_location.go` | 163 | Multi-provider location tracking: `InsertFileStorageLocation`, `GetActiveFileStorageLocations`, `BackfillFileStorageLocations`, `RecalculateProviderStats`. |
| `models/storage_provider.go` | 114 | `StorageProviderRecord`, `UpsertStorageProvider`, role preservation. |
| `storage/storage.go` | 34 | `ObjectStorageProvider` interface — the trust boundary between handlers and S3. |
| `storage/types.go` | 77 | DTOs + provider-type constants. |
| `storage/registry.go` | 364 | `ProviderRegistry`, primary/secondary/tertiary fallback `GetObjectWithFallback`, `GetObjectChunkWithFallback`, `CopyObjectBetweenProviders`, `RemoveObjectAll`. |
| `storage/s3.go` | 434 | AWS SDK v2 wrapper, env-var slot reader, multipart upload, `GetPresignedURL` (unused by any handler), `HeadObject`. |
| `storage/verify.go` | 154 | Startup 1 MB round-trip self-test. Not on the user data path. |
| `storage/mock_storage.go` | 142 | testify mock. Not a finding source. |
| `handlers/files_test.go` | 779 | Coverage map for `ListFiles`, `GetFileMeta`, `DeleteFile`. |
| `handlers/uploads_test.go` | 10 | Stub: states the chunked upload tests live in the `_integration_test.go` / `_100mb_test.go` files. |
| `handlers/chunked_upload_integration_test.go` | 524 | End-to-end 32 MB upload + download, **build-tagged `mock`** — not run by default `go test ./...`. |
| `handlers/chunked_upload_100mb_test.go` | 121 | End-to-end 100 MB upload + download, **build-tagged `mock`**. |
| `docs/erasure-coding.md` | 203 | Conceptual doc on EC + storage provider catalogue. Compared to code. |
| `client/static/js/src/files/upload.ts` | 1211 | Single-file + batch upload pipeline (streaming, constant memory), chunk encryption, `X-Chunk-Hash` header, in-progress-uploads server-cap handling, JWT preemptive refresh, `AuthExpiredError` / `QuotaExceededError` / `AccountDisabledError` / `TooManyInProgressUploadsError` typing. |
| `client/static/js/src/files/download.ts` | 238 | Per-file download orchestration: meta fetch, account-key resolution, FEK decrypt, stream-decrypt via SW or Blob fallback. |
| `client/static/js/src/files/streaming-download.ts` | 670 | `StreamingDownloadManager`, owner + share generator paths, SW-vs-Blob branching, per-chunk AES-GCM decrypt, metadata field decrypt. |
| `client/static/js/src/files/sw-streaming-download.ts` | 391 | Page-side wrapper over the streaming-download Service Worker. UUID-keyed handoff, MessageChannel ack, inline SHA-256 hashing with constant-time hex compare, iframe-driven download trigger. |
| `client/static/js/src/files/list.ts` | 476 | File list rendering, per-row metadata decryption, `confirmAndDeleteFile`, metadata modal. |
| `client/static/js/src/files/share.ts` | 420 | Owner-side share creation. Touches Slice C only at the meta-fetch and FEK-decrypt steps; share envelope crypto is Slice D. |
| `client/static/js/src/files/retry-handler.ts` | 220 | Exponential-backoff + jitter retry helpers used by chunk download. |
| `client/static/js/src/files/export.ts` | 44 | `exportBackup` — requests a short-lived token via `/api/files/:fileId/export-token` and navigates to `/api/files/:fileId/export?token=...`. Token handler itself audited in Slice E. |
| `client/static/js/src/__tests__/streaming-download.test.ts` | 280 | jsdom tests against the Blob fallback path and error shape. SW path not covered. |

### Files referenced but not deep-read

- `handlers/export.go` — only the route registration and the fact that the GET endpoint sits on the public router (i.e. NOT inside `totpProtectedGroup`) is noted here. Full audit is Slice E.
- `cmd/arkfile-client/commands.go` and `cmd/arkfile-client/crypto_utils.go` — Slice A audited these for OPAQUE/auth concerns. Their `EncryptFEK`/`DecryptFEK` and chunk encrypt loop were confirmed in Slice B to use the same primitive surface as the browser, with the same "no AAD on chunks / FEK / metadata" property.

### Out of scope (deferred to other slices)

- Argon2id, AES-GCM nonce strategy, envelope key-type byte semantics, share KDF — **Slice B (done)**.
- Anonymous share access flow (`/api/public/shares/*`), share enumeration / rate limiting, share password derivation — **Slice D**.
- `/api/files/:fileId/export` and `/api/files/:fileId/export-token` handler internals, full Endpoint Review Table (auth + TOTP + admin rule + rate limit per endpoint) — **Slice E**.
- TypeScript-wide XSS sinks beyond the file list (filenames are rendered via `textContent`, confirmed safe inside `list.ts`); WASM / CSP / supply chain — **Slice F**.
- OPAQUE / JWT / TOTP middleware internals — **Slice A (done)**.
- Logging hygiene across all routes — **Slice E**, but C-scope log lines that include username/file_id are called out in C-12 and C-15.

---

## 1. Architecture & Data-Flow Summary (for this slice)

### 1.1 Chunked upload flow (browser)

```
TS (upload.ts)                              Go handlers + storage
=============                              =====================
[user picks file]
   |
   v
resolveAccountKey ----------> Argon2id (slice B) OR cache OR provided key
   |
   v
streaming SHA-256 over plaintext file
   (one chunk at a time via File.slice; peak heap ~CHUNK_SIZE)
   |
   v
checkDuplicate(plaintextHashHex)  -- client-only, never sent to server
   |
   v
encryptMetadata(filename) with accountKey  -- NO AAD       (cross-ref B-08)
encryptMetadata(sha256)   with accountKey  -- NO AAD       (cross-ref B-08)
encryptAESGCM(FEK)        with KEK         -- NO AAD       (cross-ref B-08)
   |
   v
POST /api/uploads/init  --------------------->  CreateUploadSession
                                                   - approval check
                                                   - storage-limit check
                                                   - in-progress cap (4/user)
                                                   - opportunistic abandoned-session sweep (same tx)
                                                   - storage.Registry.Primary().InitiateMultipartUpload
                                                   - issue session_id + storage_id + storage_upload_id
                                                <-- {session_id, file_id, total_chunks, expires_at}

for chunk in 0..N:
   plain = file.slice(start,end).arrayBuffer()
   encrypted = AES-GCM(plain, fek)          -- NO AAD on chunk      (cross-ref B-05)
   if chunk==0: prepend [version(1), keyType(1)]
   chunkHash = SHA-256(encrypted)            -- decorative (server doesn't verify) (C-04)
   POST /api/uploads/{sid}/chunks/{i}  -->  UploadChunk
   X-Chunk-Hash: {chunkHash}                    - owner check
                                                - session in_progress check
                                                - chunk-index range check
                                                - min/max size validation
                                                - io.ReadAll(req.Body)      (bounded by max chunk size)
                                                - streamingHashStates[sid].Write(chunkData)
                                                - IF last chunk AND paddedSize > totalSize:
                                                    paddingSize = paddedSize - totalSize
                                                    paddingBytes = crypto/rand
                                                    uploadData = append(chunkData, paddingBytes...)   <-- C-01 large alloc
                                                    storedBlobHashStates[sid].Write(uploadData)
                                                - storage.Primary().UploadPart(...)
                                                - INSERT INTO upload_chunks (sid, chunkNum, chunkHash, size, etag)

POST /api/uploads/{sid}/complete  -------->  CompleteUpload
                                                - owner check
                                                - count(upload_chunks)==totalChunks
                                                - storage.CompleteMultipartUpload(parts)
                                                - actualStoredSize == paddedSize (server-vs-server math)
                                                - INSERT INTO file_metadata
                                                - InsertFileStorageLocation(primary, 'active')
                                                - user.UpdateStorageUsage(+declaredSize)
                                                - replicateToSecondary(...)  -- fire-and-forget goroutine, ctx=Background()
                                             <-- {file_id, storage_id, encrypted_file_sha256, storage_quota}
```

### 1.2 Chunked download flow (browser)

```
TS (download.ts / streaming-download.ts)             Go handlers + storage
=========================================            ======================
GET /api/files/{fid}/meta -------------->  GetFileMeta
                                              - owner check
                                              - approval check
                                              - return encrypted metadata + encrypted FEK
                                                + chunk_size + total_chunks
   |
   v
resolveAccountKey, decryptMetadata(filename, sha256), decryptFEK
   |
   v
isSwAvailable() ? SW path : Blob fallback
   |
   v
async generator: for chunk in 0..N:
   GET /api/files/{fid}/chunks/{i} -------> DownloadFileChunk
                                              - owner + approval check
                                              - byte-range computed from
                                                file.ChunkSizeBytes (DB-trusted, no AAD) (C-03)
                                              - storage.Registry.GetObjectChunkWithFallback(...) (C-08)
                                              - c.Stream(reader)
   strip envelope header if chunk==0; validate version==0x01
   await decryptor.decryptChunk(chunkData)   -- AES-GCM tag verified BEFORE yield (✓)
                                              -- but no AAD binds chunkIndex/fileId
   yield plaintext to:
     - SW path: ReadableStream -> SW -> browser download manager
                inline SHA-256 of plaintext; mismatch reported AFTER file is on disk (C-13)
     - Blob fallback: new Blob([existing, chunk])
```

### 1.3 Multi-provider storage routing

`storage.Registry` holds primary / optional secondary / optional tertiary `ObjectStorageProvider` instances. Roles are loaded from env-var slots `STORAGE_PROVIDER_1..3`, then reconciled with DB `storage_providers` table on startup (DB wins on conflict per `UpsertStorageProvider`).

- **Writes** always go to primary (`Registry.Primary().InitiateMultipartUpload(...)` etc.).
- **Reads** at chunk download go through `GetObjectChunkWithFallback`, which silently tries primary → secondary → tertiary. **No per-chunk hash check against `stored_blob_sha256sum` is performed at read time** (cross-ref C-08).
- **Deletes** iterate the `file_storage_locations` table via `RemoveObjectAll`. Mixed success is allowed (`delete_failed` status row).
- **Replication** is an opportunistic `go func()` triggered after each successful upload-complete, gated by `cfg.Storage.EnableUploadReplication` and `Registry.HasSecondary()`. Uses `context.Background()` (cross-ref C-19).

### 1.4 What the server CAN see vs. what it cannot

| Server sees in plaintext during/after upload | Source |
|---|---|
| Username (in JWT subject; in S3 `x-amz-meta-owner-username`) | jwt.go + uploads.go L217-220 |
| `file_id`, `storage_id` (server-generated UUIDs) | uploads.go L99-100, models/file.go L74-82 |
| `password_hint` (free-form string, cleartext by design) | uploads.go L210 / L915 |
| `password_type` ("account" or "custom") | uploads.go L80 |
| `total_size` (encrypted-byte size, declared by client) | uploads.go L210 |
| `padded_size` (computed server-side via `utils/padding.go`) | uploads.go L189 |
| `chunk_size` (PLAINTEXT chunk size, declared by client) | uploads.go L210 |
| `chunk_count` (computed server-side from declared sizes) | uploads.go L904-907 |
| `encrypted_file_sha256sum` (server-computed SHA-256 over the ENCRYPTED bytes only, pre-padding) | uploads.go L824-827 |
| `stored_blob_sha256sum` (server-computed SHA-256 over what was actually sent to S3, incl. padding) | uploads.go L833-836 |
| `chunk_hash` per-chunk client claim (X-Chunk-Hash, stored but **not verified** server-side) | uploads.go L660 |
| `etag` per chunk (from S3) | uploads.go L660 |
| Upload timestamps, owner-username, expiration | upload_sessions table |
| Storage provider routing (which provider stored which file via `file_storage_locations`) | models/file_storage_location.go |

| Server does NOT see (encrypted client-side or never sent) | Source |
|---|---|
| Plaintext filename | encrypted with account key |
| Plaintext SHA-256 of the user file | encrypted with account key |
| Plaintext file contents | encrypted with FEK per chunk |
| FEK | encrypted with account-KEK or custom-KEK; envelope on the wire |
| Account password / custom password / share password | OPAQUE for login; never sent for KDF (Slice B) |
| Account-KEK / Custom-KEK / Share-KEK | derived client-side; never transmitted |
| Plaintext dedup digest cache | client-only (`utils/digest-cache.ts`) |

Anything in the "server sees" column is part of the **server-visible metadata exposure surface** for Slice G's matrix.

---

## 2. Findings

Severity-ordered. Single `C-NN` series. Every finding cites file:line and quotes the relevant code.

---

### Finding C-01: Server allocates up to ~10% of file size in a single Go `append` on the last chunk upload (DoS surface)

- **Severity:** High
- **Confidence:** High
- **Category:** operational (DoS) / design
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `handlers/uploads.go:573-612` (`UploadChunk` last-chunk padding application); `utils/padding.go:1-68` (padding policy from Slice B `B-06`).

**Description.** When the client uploads the LAST chunk of a file, the server:

1. Reads the entire chunk body into RAM with `io.ReadAll(c.Request().Body)` (L573). This is bounded to ~`PlaintextChunkSize + envelopeHeader + GCM-overhead` ≈ a few MB, so it is safe in isolation.
2. THEN, for the last chunk only, allocates a separate `paddingBytes := make([]byte, paddingSize)` (L604), where `paddingSize = paddedSize - totalSize`. Per `utils/padding.go` (Slice B finding `B-06`), `paddedSize` is `totalSize × 1.02 + jitter` where jitter is up to 10% of `totalSize`. For a 6 GB encrypted file (the AGENTS.md mobile-on-3GB-RAM use case), `paddingSize` can reach **~720 MB**.
3. THEN concatenates with `uploadData = append(chunkData, paddingBytes...)` (L609). `append` of one chunk-sized slice plus a ~720 MB slice forces a single contiguous allocation roughly equal to `paddingSize` (the existing backing array cannot hold it).

So a single user uploading a single 6 GB file forces a ~720 MB transient allocation on the server during the last-chunk request. Multiple concurrent users (the per-user in-progress cap is 4, but there is no global cap on concurrent ACTIVE chunk requests across users) can drive the server into OOM territory. The `maxInProgressUploadSessionsPerUser` cap is per-session-existence, not per-active-chunk-request — once 4 sessions are open, the 5th `CreateUploadSession` is rejected, but nothing prevents all 4 sessions from racing to upload their last chunk simultaneously.

**Evidence.**

```go
// handlers/uploads.go:573-612 (excerpt)
chunkData, err := io.ReadAll(c.Request().Body)
...
uploadData := chunkData
if chunkNumber == totalChunks-1 && paddedSize > totalSize {
    paddingSize := paddedSize - totalSize
    paddingBytes := make([]byte, paddingSize)             // <-- up to ~10% of file size
    if _, randErr := cryptoRand.Read(paddingBytes); randErr != nil {
        ...
    }
    uploadData = append(chunkData, paddingBytes...)       // <-- single contiguous allocation
    logging.InfoLogger.Printf("Last chunk %d: appended %d bytes of padding ...", ...)
}
```

**Attack scenario.** A small number of authenticated users (the per-user-session cap is 4) coordinate to start uploads of large files (say 5 × 6 GB files in parallel across enough users to bypass the per-user cap, e.g. 2 users × 4 sessions each, all racing their final chunk). The simultaneous allocation footprint can easily exceed the server's available RAM and trigger an OOM kill of the Arkfile process, denying service to all users.

Because this is a transient allocation on the **last chunk only**, it does not show up in load-testing that does not push past full-file completion, and it does not show up in the integration test (`chunked_upload_100mb_test.go` is 100 MB and is in any case build-tagged `mock`).

**Impact.** Authenticated DoS against the server with a small number of cooperating accounts. Magnitude scales with the per-file padding (~2% + ≤10% jitter). The `maxInProgressUploadSessionsPerUser = 4` cap does not protect against this — it caps session existence, not active-chunk concurrency.

**Recommendation.**

- Stream the padding bytes directly into the S3 multipart `UploadPart` using an `io.MultiReader(bytes.NewReader(chunkData), io.LimitReader(rand.Reader, paddingSize))`, eliminating the in-memory concatenation. AWS SDK v2's `UploadPart` requires a seekable body for HTTP-endpoint SigV4 (per the comment at `storage/s3.go:170-172`), which means for HTTP destinations the bytes still need to be buffered. In that case:
  - Either upload the padding as a separate S3 part (the existing comment at uploads.go:599-600 rejects this because of S3's 5 MB minimum part size, but the padding is always ≥64 KiB floor and can be coalesced with a small tail of real chunk bytes to clear 5 MB), OR
  - Cap the maximum padding size to a fixed ceiling (e.g. `min(paddingSize, 16 MiB)`) and accept the smaller size-obfuscation grade for very large files. The current ≤10% jitter buys very little against a server-side observer who already knows `totalSize` to within ~10%.
- Independently, add a **global** concurrent-upload-chunks gauge and 503 newly-incoming chunk requests when the gauge exceeds a configurable threshold. This protects against any chunk-handler memory pressure, not just the last-chunk path.

**Suggested tests.**

- Synthetic test (not build-tagged `mock`) that submits a final chunk for a session whose `padded_size - total_size` is a large number, and asserts that server memory usage does not spike proportionally. Can be measured with `runtime.ReadMemStats` deltas in a Go subprocess.
- Load test: 4 concurrent uploads × 5 users × multi-GB files, verifying the server stays under a memory budget.

**Cross-refs.** Slice B `B-06` (server-applied padding policy decision). Slice E for the global-concurrency rate-limit suggestion (this is application-wide, not endpoint-specific).

---

### Finding C-02: Server cannot detect chunk swap / reorder / cross-file substitution at the wire layer (no AAD binds chunkIndex or fileId)

- **Severity:** High
- **Confidence:** High
- **Category:** cryptographic / design
- **Component:** `handlers/uploads.go`, `handlers/downloads.go`, `client/static/js/src/files/upload.ts`, `client/static/js/src/files/streaming-download.ts`
- **Affected files / functions:**
  - Browser encrypt (no AAD): `client/static/js/src/files/upload.ts:308-317` (`encryptChunk`), `:681` call site.
  - Browser decrypt (no AAD): `client/static/js/src/files/streaming-download.ts:336-391` (`makeFileChunkGenerator`), `:363` `decryptor.decryptChunk(chunkData)`.
  - Server byte-range read trusts DB `chunk_size_bytes`: `handlers/downloads.go:67-86`.
  - Server upload-complete just orders chunks by `chunk_number`: `handlers/uploads.go:799-813`.

**Description.** This is the wire-layer expression of Slice B `B-02`/`B-05`. Slice B already established that file chunks are encrypted with AES-256-GCM **without** an Associated Authenticated Data (AAD) parameter binding the ciphertext to `(file_id, chunk_index, owner_username)`. Slice C examines whether this is exploitable on the wire.

It is, in the following ways:

1. **Within a single file**: a malicious server (or a database compromise + S3 read-write attacker) can swap chunk N of a user's file with chunk M of the same file. The browser receives the swapped chunk, validates the AES-GCM tag (which succeeds because the same FEK is used for both), and yields it in the order the server returned chunks. The plaintext flowing into the Service Worker (and to disk) is reordered chunks of the legitimate file. The end-of-stream SHA-256 verification (against the decrypted-metadata sha256 over the original plaintext file) would catch this — but only after the file has already been written to disk, with a user-facing warning `result.hashVerification === 'mismatch'` (download.ts:218-220). The Blob-fallback path computes no end-of-file hash by default (see C-13).
2. **Across two files of the same user**: a malicious server can serve a chunk from user U's file A in place of a chunk of user U's file B, **provided both files share the same FEK** — they do NOT, since FEKs are randomly generated per file (Slice B `B-04`). So this attack does NOT succeed across files; the AES-GCM tag would fail on the substituted chunk because the FEK is different.
3. **Across two users**: would require both users to share an FEK, which they do not. Does NOT succeed.

So the realistic attack is **within-file chunk reordering or duplication**. The user's protection is the end-of-file SHA-256 check after streaming, which (a) only fires on the SW path when `expectedSha256Hex` is passed (it is, per download.ts:594/streaming-download.ts:208-209), and (b) fires AFTER the file is on disk on the SW path or AFTER full Blob assembly on the fallback path.

**Evidence.**

```ts
// client/static/js/src/files/upload.ts:305-317
async function encryptChunk(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const result = await encryptAESGCM({
    data,
    key,
    // No AAD for file chunks - matches Go implementation
  });
  return concatBytes(result.iv, result.ciphertext, result.tag);
}
```

```ts
// client/static/js/src/files/streaming-download.ts:361-391
const decryptedChunk = await decryptor.decryptChunk(chunkData);
// ...
yield decryptedChunk;
```

```go
// handlers/uploads.go:799-813 — complete-upload just orders by chunk_number
rows, err := database.DB.Query("SELECT chunk_number, etag FROM upload_chunks WHERE session_id = ? ORDER BY chunk_number ASC", sessionID)
```

```go
// handlers/downloads.go:67-86 — chunk byte-range computed from DB-trusted chunk_size_bytes, not from ciphertext
plaintextChunkSize := file.ChunkSizeBytes
...
chunk0EncSize := envelopeHeader + gcmOverhead + plaintextChunkSize
regularEncSize := gcmOverhead + plaintextChunkSize
```

**Attack scenario.** A malicious server operator (or a sufficiently privileged attacker who controls the S3 backend AND can modify the rqlite DB) can:

1. Identify two chunks of the same file.
2. Serve them in swapped order on the next `/api/files/{fid}/chunks/{idx}` request (e.g., chunk 5 served when 4 was requested).
3. The browser AES-GCM validates the tag successfully (same FEK), yields the chunk into the SW stream.
4. The browser writes the reordered file to the user's disk.
5. The end-of-file SHA-256 verification fires and shows a `showWarning(...)` (download.ts:219-220). The user is alerted **after** they have a tampered file on disk.

For files where the user would not immediately notice corruption (e.g., a large archive opened later, a media file played with seeking), the warning might be missed in the UI and the bad file used downstream.

**Impact.** Server can corrupt downloaded files in ways the AEAD tag cannot detect. Detection happens but only post-write. For Arkfile's "server learns nothing of file contents and cannot tamper" privacy posture, this is a significant gap. Severity is High and not Critical because (a) the same AES-GCM tag still rejects random bitflip corruption of any single chunk, (b) FEK randomness prevents cross-file substitution, and (c) the end-of-file SHA-256 catches it, just late.

**Recommendation.**

- Bind chunk-index AAD: change `encryptAESGCM(...)` call sites to pass `additionalData = encodeAAD(file_id || chunk_index || total_chunks)`. The decryptor must then reconstruct the same AAD. This makes within-file reordering immediately detectable at chunk-boundary AEAD verification, with no possibility of serving any tampered byte to disk.
- The CLI (`cmd/arkfile-client/`) must match; otherwise CLI-uploaded files cannot be browser-downloaded.
- Slice B `B-05` recommended this at the primitive layer. Slice C's evidence confirms it should be done.

**Suggested tests.**

- Negative integration test: chunk encrypted at index N, decrypt requested with AAD claiming index N+1, must fail.
- Server-side test: upload chunks 0..N, then `DELETE FROM upload_chunks WHERE chunk_number = X`, re-insert with chunk_number = Y > X, call CompleteUpload, then download — should fail at chunk Y instead of waiting for end-of-file hash.
- Browser test for reorder-fails-fast at the SW boundary so plaintext is never released.

**Cross-refs.** Slice B `B-02`, `B-05`, `B-08` (no-AAD design). Slice C `C-03` (server trusts `chunk_size_bytes` for byte-range math — another vector for the same class of attack). Slice C `C-13` (end-of-file hash mismatch surfaces only after disk write).

---

### Finding C-03: Download byte-range math trusts `file_metadata.chunk_size_bytes` and `chunk_count` without any cryptographic binding

- **Severity:** High
- **Confidence:** High
- **Category:** cryptographic / design
- **Component:** `handlers/downloads.go`, `models/file.go`
- **Affected files / functions:** `handlers/downloads.go:60-108`; `models/file.go:147-254` (`GetFileByFileID` returns these values as-is from the DB).

**Description.** `DownloadFileChunk` computes the byte range to fetch from S3 entirely from DB-stored fields:

```go
// handlers/downloads.go:67-77
plaintextChunkSize := file.ChunkSizeBytes
if plaintextChunkSize <= 0 {
    plaintextChunkSize = crypto.PlaintextChunkSize()
}
gcmOverhead    := int64(crypto.AesGcmOverhead())
envelopeHeader := int64(crypto.EnvelopeHeaderSize())
chunk0EncSize  := envelopeHeader + gcmOverhead + plaintextChunkSize
regularEncSize := gcmOverhead + plaintextChunkSize
```

The values `chunk_size_bytes` and `chunk_count` are written by `CompleteUpload` from server-side computation (uploads.go:904-918). At download time, neither field is verified against the actual S3 object's structure (S3 stores opaque bytes, no chunk boundaries), and neither field is AAD-bound to any ciphertext.

If an attacker can modify the `file_metadata` row (DB write access), they can alter `chunk_size_bytes` to a value that maps the SAME byte range of the stored object to a DIFFERENT chunk_index. The user requesting chunk N gets the bytes that were chunk M at upload time. AES-GCM authenticates the chunk's own integrity, so the tag still validates with the FEK, but the chunk-index → byte-range mapping has been shifted.

This is the same class of attack as C-02, but via the metadata table rather than via S3.

**Evidence.** See snippet above.

**Attack scenario.** DB-write attacker changes `chunk_size_bytes` from X to X+δ for a target file. User requests chunk 5, server computes byte range `[chunk0EncSize + 4*(X+δ+overhead), +...]`, fetches those bytes from S3 (which are different from the original chunk 5), the browser decrypts successfully (same FEK), and yields the wrong bytes. End-of-file SHA-256 fails — but again, only after write.

**Impact.** Same as C-02 — within-file reordering / shifting that escapes per-chunk AEAD verification. Note this is achievable by anyone with DB write access alone, without S3 access.

**Recommendation.**

- AAD-bind `chunk_size_bytes` and `chunk_count` into either the per-chunk AAD (C-02's recommendation already covers this if AAD includes those values) or into the encrypted FEK envelope (so the client validates them at FEK-decrypt time).
- A simpler defense-in-depth: have the upload pipeline write `chunk_size_bytes` and `chunk_count` into the envelope (which IS encrypted with the account KEK), and at download time decrypt the envelope before computing byte ranges. Today the envelope is just `[version(1)][keyType(1)][nonce(12)][ciphertext][tag(16)]` — extending it to include the chunk metadata fields is straightforward.

**Suggested tests.**

- Forge a `file_metadata` row with mismatched `chunk_size_bytes`; verify the client detects the mismatch before yielding any plaintext.

**Cross-refs.** C-02, Slice B `B-08`.

---

### Finding C-04: `X-Chunk-Hash` request header is accepted, format-validated, and stored — but the server never verifies it matches the actual chunk bytes

- **Severity:** Medium
- **Confidence:** High
- **Category:** design / code clarity
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `handlers/uploads.go:523-532` (format validation), `:658-661` (insert into `upload_chunks`); browser sends at `client/static/js/src/files/upload.ts:695-709`.

**Description.** The upload protocol requires every chunk POST to include `X-Chunk-Hash`, a 64-hex SHA-256. The server:

1. Validates the header is exactly 64 lowercase/uppercase hex chars (`isHexString`, uploads.go:530-532).
2. Stores it verbatim in `upload_chunks.chunk_hash` (uploads.go:660).

The server does NOT recompute SHA-256 over the chunk body and compare. The actual integrity check the server uses is its own running hash, `streamingHashStates[sessionID]`, which is computed independently in uploads.go:580-594 and stored at upload-complete as `encrypted_file_sha256sum` (uploads.go:826-827).

Thus `X-Chunk-Hash` is decorative on the server side. Its only practical consumer would be a later admin diagnostic tool, but I find no such consumer.

**Evidence.**

```go
// handlers/uploads.go:523-532
chunkHash := c.Request().Header.Get("X-Chunk-Hash")
if chunkHash == "" {
    return echo.NewHTTPError(http.StatusBadRequest, "Missing chunk hash")
}
if len(chunkHash) != 64 || !isHexString(chunkHash) {
    return echo.NewHTTPError(http.StatusBadRequest, "Invalid chunk hash format")
}
```

```go
// handlers/uploads.go:658-661
_, err = database.DB.Exec(
    "INSERT INTO upload_chunks (session_id, chunk_number, chunk_hash, chunk_size, etag) VALUES (?, ?, ?, ?, ?)",
    sessionID, chunkNumber, chunkHash, chunkSize, etag,
)
```

```ts
// client/static/js/src/files/upload.ts:694-712
const chunkHash = toHex(hash256(chunkToUpload));
...
await apiRequest(`/api/uploads/${session.session_id}/chunks/${i}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Hash': chunkHash },
  body: new Blob([uploadBuffer]),
});
```

**Attack scenario.** A malicious client can send any 64-hex value as `X-Chunk-Hash` without ever computing the real SHA-256, and the server will accept the chunk. This does not break anything — the server has its own running hash — but it means users (and any code in the future that reads `chunk_hash` from the DB expecting it to be authoritative) cannot rely on the field. It is a tripwire that does not trip.

**Impact.** Defense-in-depth gap; no direct exploit. Future maintenance hazard — any developer adding "verify chunk_hash on download" logic would be writing it against an unverified server-supplied value (because the server didn't verify the client value).

**Recommendation.** Pick one:

- **Verify server-side**: change the handler to compute `sha256.Sum256(chunkData)` and compare against the header, rejecting on mismatch. Cheap (SHA-256 over a single ~1 MB chunk is sub-millisecond). The stored `chunk_hash` is then authoritative.
- **Remove the header**: drop `X-Chunk-Hash` from the wire protocol and the DB column. The server already computes its own running hash; the client-supplied one adds no security. This is the Greenfield-correct choice.

I recommend the second option. The first one introduces an extra hash computation server-side that duplicates what the existing `streamingHashStates` already does.

**Suggested tests.** Whichever option, the post-change behavior should have a negative test: sending a known-wrong `X-Chunk-Hash` should be rejected (option 1) or have no effect (option 2).

**Cross-refs.** None.

---

### Finding C-05: `CancelUpload` route uses `:fileId` param but the handler reads `c.Param("sessionId")` — endpoint is dead-on-arrival

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational / design
- **Component:** `handlers/route_config.go`, `handlers/uploads.go`
- **Affected files / functions:** `handlers/route_config.go:118` (route registration), `handlers/uploads.go:260-335` (handler reads `c.Param("sessionId")` at L262).

**Description.** The route is registered as:

```go
// handlers/route_config.go:118
totpProtectedGroup.DELETE("/api/uploads/:fileId", CancelUpload)
```

The handler:

```go
// handlers/uploads.go:260-262
func CancelUpload(c echo.Context) error {
    username := auth.GetUsernameFromToken(c)
    sessionID := c.Param("sessionId")   // <-- param is :fileId in the route, not :sessionId
```

Echo's `c.Param("sessionId")` returns `""` when the route did not declare that parameter name. The subsequent DB lookup `SELECT ... FROM upload_sessions WHERE id = ?` with an empty string returns `sql.ErrNoRows` (uploads.go:278), which maps to HTTP 404 "Upload session not found". Every cancel attempt fails with 404 regardless of the user, regardless of the path parameter.

This means an in-progress upload session **cannot be cancelled by the browser or CLI** through this endpoint. The user is left with two options:

1. Wait 24 hours for the session's `expires_at` to elapse and the opportunistic sweep in `CreateUploadSession` to mark it `abandoned`.
2. Run out the per-user `maxInProgressUploadSessionsPerUser = 4` cap by accumulating four abandoned sessions, then be blocked at "too_many_in_progress_uploads" until step 1 elapses.

The S3 multipart upload `storageUploadID` also continues to incur "incomplete multipart upload" storage costs at the backend (S3 / wasabi / b2 / etc.) until either (a) a 24-hour-later cleanup explicitly aborts it (there is no such cleanup in the codebase) or (b) the bucket's lifecycle policy expires incomplete multipart uploads. Without such a lifecycle policy, abandoned uploads pile up forever and bill against the operator.

**Evidence.** See snippets above. Also note that the TypeScript client appears to never call this endpoint (no `DELETE /api/uploads/` invocation found in `client/static/js/src/files/upload.ts`); the upload UI also offers no cancel button mid-stream. So the bug is currently latent in the sense that no one tries to use the cancel endpoint, but the moment anyone does — including the CLI, which has flags to abort — it silently 404s.

**Attack scenario.** No active exploit; this is a correctness / operational finding. It results in:

- Orphaned S3 multipart uploads accumulating against the operator's storage bill.
- Users hitting the per-user in-progress cap with no recovery short of waiting 24 hours.
- The CLI's `--cancel` (if it exists or is added) silently no-ops.

**Impact.** Operational reliability issue. Marginal security impact: orphaned in-progress sessions consume the per-user session cap, which functions as a soft rate-limiter — but a buggy soft rate-limit is worse than no rate-limit because users cannot cleanly drain it.

**Recommendation.**

- Change the route to `totpProtectedGroup.DELETE("/api/uploads/:sessionId", CancelUpload)` to match the handler. Or rename the handler's `c.Param("sessionId")` to `c.Param("fileId")` and rename the local variable — pick a naming convention and apply it consistently across CreateUploadSession (uses `sessionId` everywhere) and UploadChunk (uses `sessionId`).
- Add an integration test that exercises the cancel path end-to-end and asserts both DB state (status='canceled') and S3 state (AbortMultipartUpload called).
- Also add a periodic background cleanup that calls `AbortMultipartUpload` on storage for any `upload_sessions` row whose `expires_at` has lapsed and whose status is still `in_progress` or `abandoned`. The opportunistic sweep in `CreateUploadSession` (uploads.go:149-159) only marks the DB row as abandoned; it does NOT call `AbortMultipartUpload` on the storage side.

**Suggested tests.**

- `TestCancelUpload_Success` — happy path, asserts DB row state and `AbortMultipartUpload` was called.
- `TestCancelUpload_NotOwner` — different user gets 403.
- `TestCancelUpload_NotInProgress` — already-completed/cancelled session gets 400.

**Cross-refs.** Slice E for full Endpoint Review Table (this entry should appear there too with "broken: param name mismatch").

---

### Finding C-06: Opportunistic upload-session sweep marks DB rows abandoned but does not abort the underlying S3 multipart upload — operator-side storage cost leak

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational / design
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `handlers/uploads.go:149-159` (opportunistic sweep inside `CreateUploadSession` transaction).

**Description.** When a user starts a new upload, `CreateUploadSession` runs an opportunistic sweep over the calling user's expired in-progress sessions:

```go
// handlers/uploads.go:149-159
if _, err := tx.Exec(
    `UPDATE upload_sessions
        SET status = 'abandoned', updated_at = CURRENT_TIMESTAMP
      WHERE owner_username = ?
        AND status = 'in_progress'
        AND expires_at < CURRENT_TIMESTAMP`,
    username,
); err != nil { ... }
```

The DB row is updated to `status='abandoned'`. However, the corresponding S3 multipart upload (initiated at uploads.go:222 with `InitiateMultipartUpload`) is NOT aborted. Each in-progress multipart upload occupies storage at the S3 backend until either:

- An explicit `AbortMultipartUpload` call is made (only happens in `CancelUpload` and on a few error paths in `CreateUploadSession` itself).
- The bucket's lifecycle policy expires it. AWS S3, Wasabi, Cloudflare R2, etc. all support a "abort incomplete multipart uploads after N days" lifecycle rule, but Arkfile does not configure this on bucket creation (`storage/s3.go:185-202` just calls `CreateBucket` with no further configuration).

So abandoned uploads silently accrue storage cost against the operator. Note this is NOT user-billable — the abandoned bytes are not in `file_metadata`, so they do not count against `user.TotalStorageBytes`. The operator pays.

**Evidence.** Snippets in description.

**Attack scenario.** A hostile user repeatedly starts uploads, transmits a few chunks, and never completes. Each session consumes ~ `chunk_count × CHUNK_SIZE` of operator storage (because multipart-uploaded parts ARE counted toward storage cost on most backends) until the operator-configured lifecycle policy expires them. With the per-user session cap of 4 and a 24-hour expiry, a single user can keep 4 × `total_size` of partial bytes on the operator's tab continuously.

**Impact.** Operator cost-of-service inflation. Not a confidentiality/integrity issue. Becomes more serious once Arkfile wires payment processing — abandoned uploads represent storage the operator pays for but cannot bill.

**Recommendation.**

- Either (preferred) add a background task in the admin task runner (`handlers/admin_task_runner.go` — Slice E) that periodically:
  1. SELECTs `upload_sessions` WHERE `status IN ('abandoned', 'canceled')` AND `storage_upload_id IS NOT NULL`.
  2. Calls `storage.Registry.Primary().AbortMultipartUpload(ctx, storage_id, storage_upload_id)`.
  3. Clears `storage_upload_id` on success so the row is not retried.
- Or document a required bucket lifecycle policy in `docs/setup.md` and the prod-deploy script (`scripts/prod-deploy.sh`) that sets "abort incomplete multipart uploads after N days" on the configured bucket(s). This shifts the burden to the operator's S3 backend.

**Suggested tests.** Integration test that explicitly creates an abandoned session, runs the cleanup, and verifies the S3 mock's `AbortMultipartUpload` was called with the right args.

**Cross-refs.** C-05 (cancel endpoint broken — adds to the abandoned-pile problem).

---

### Finding C-07: `CompleteUpload` performs storage finalize then DB transaction in two phases — failure window leaves an orphaned S3 object with no `file_metadata` row

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational / design
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `handlers/uploads.go:851-871` (S3 complete → tx begin); the in-code comment at L860 explicitly acknowledges the orphan window.

**Description.** `CompleteUpload` finalizes the S3 multipart upload OUTSIDE any DB transaction (uploads.go:851), then begins a short-lived transaction (L858) to:

- Update `upload_sessions.status = 'completed'`.
- Verify size, INSERT into `file_metadata`, INSERT into `file_storage_locations`, INCREMENT `user.TotalStorageBytes`.

If the DB transaction fails to commit after `CompleteMultipartUpload` returns success, the encrypted blob is on S3 but has no `file_metadata` row, no `file_storage_locations` row, and no user-storage accounting. The code comment at L860 acknowledges this:

```go
// handlers/uploads.go:858-862
tx, err := database.DB.Begin()
if err != nil {
    logging.ErrorLogger.Printf("CRITICAL: Failed to start transaction after completing storage upload for session %s. Orphaned file may exist: %s", sessionID, storageID.String)
    return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start database transaction")
}
```

The orphaned blob is invisible to the user (no metadata row to list) and to the user's storage quota (no `UpdateStorageUsage` call). It bills the operator forever.

**Evidence.** Snippet above. Same orphan window exists in DeleteFile (L1042 calls `RemoveObjectAll` BEFORE `tx.Commit` at L1083 — but in that direction the orphan is a stale DB row, not a stale S3 object, since the S3 delete is the destructive step).

**Attack scenario.** Operator-affecting only. A network blip between the S3 SDK's success return and rqlite's transaction begin produces an orphan. Not attacker-induced in any practical way.

**Impact.** Operator cost-of-service inflation. Same class as C-06. No security impact on user data.

**Recommendation.** This is fundamentally a distributed-write problem (S3 + rqlite). Three options:

- **Reconciliation task** (recommended): periodically `ListObjects` on the primary bucket and cross-check against `file_metadata.storage_id`. Any S3 object whose `storage_id` has no metadata row AND is older than some threshold (e.g. 1 hour) gets deleted. This is the cleanest fix and also catches any failures in the multi-provider replication pipeline. Belongs in the admin task runner (Slice E).
- **Pre-commit storage check**: rearrange so the DB tx is begun and validated FIRST (size match, `file_id` conflict check, user quota update queued), THEN call `CompleteMultipartUpload`, THEN commit. The DB tx still needs to commit after the S3 finalize, so the window shrinks but does not vanish.
- **Accept the gap** if option 1 exists. Document it explicitly in code (the current code comment is the right spirit; the recovery mechanism is what's missing).

**Suggested tests.** Inject a DB-tx-begin failure between `CompleteMultipartUpload` and tx.Begin; assert the reconciliation task picks up the orphan on its next run.

**Cross-refs.** C-06 (same operator-cost-leak class).

---

### Finding C-08: Multi-provider download fallback does NOT verify the served blob against `stored_blob_sha256sum` — secondary/tertiary divergence is undetectable at chunk-level

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / design
- **Component:** `storage/registry.go`, `handlers/downloads.go`
- **Affected files / functions:** `storage/registry.go:329-364` (`GetObjectChunkWithFallback`); `handlers/uploads.go:1141-1148` (where the secondary blob IS hash-verified, but only at replication time).

**Description.** When a chunk is downloaded, the storage registry silently falls back from primary → secondary → tertiary on any primary error:

```go
// storage/registry.go:331-363 (excerpt)
reader, err := r.primary.GetObjectChunk(ctx, objectName, offset, length)
if err == nil { return reader, r.primaryID, nil }
// ... try secondary ...
// ... try tertiary ...
```

The returned `io.ReadCloser` is streamed to the client without comparison against the `stored_blob_sha256sum` recorded at upload time (uploads.go:917, `stored_blob_sha256sum` column on `file_metadata`). The replication pipeline DOES verify the copy at replicate-time (uploads.go:1141-1148), so we know primary and secondary should agree at the moment replication succeeded. But:

- Bitrot or operator-side mutation of a secondary blob is undetectable at read time.
- A malicious or compromised secondary provider can serve a substituted blob; the chunk-level AES-GCM tag still validates (because FEK is shared between primary and secondary copies by design), but the chunk-level structure could be different from what primary stored.

The end-of-file plaintext SHA-256 check (download.ts) catches this — same caveat as C-02: only after the file is on disk.

**Evidence.**

```go
// storage/registry.go:331-345 (no hash verification on the returned reader)
reader, err := r.primary.GetObjectChunk(ctx, objectName, offset, length)
if err == nil {
    return reader, r.primaryID, nil
}
primaryErr := err
if r.secondary != nil {
    log.Printf("Primary provider %s failed for GetObjectChunk(%s), trying secondary %s: %v", ...)
    reader, err = r.secondary.GetObjectChunk(ctx, objectName, offset, length)
    if err == nil {
        return reader, r.secondaryID, nil   // <-- returned without verification
    }
    ...
}
```

**Attack scenario.** Attacker who controls the secondary provider (compromised provider key, or operator account compromise at the secondary) substitutes content. Primary fails for any reason (network blip, key expired, etc.), Arkfile silently falls back to secondary, the substituted bytes flow to the user. End-of-file hash catches it, but file is already on disk.

**Impact.** Same class as C-02 but cross-provider. Particularly relevant when one of the providers is run by a different operator/jurisdiction (the threat-model assumption for multi-provider redundancy is that providers are independent, which means independently compromisable).

**Recommendation.**

- **Hash-verify on first chunk fetch from a non-primary provider** (full-object hash). On the first chunk request that falls back to secondary, fetch a `HeadObject` and (if the provider exposes content-MD5 or ETag-for-full-PUT) compare; if available, also compute a partial verification by `GetObject` on the WHOLE blob and SHA-256-stream it before returning chunk 0. This is bandwidth-expensive but only needed once per file-from-secondary.
- **Cheaper alternative**: have `replicateToSecondary` compute and store a per-chunk hash (not just whole-blob), then `GetObjectChunkWithFallback` returns the chunk along with the expected chunk hash; the client can verify. This requires schema changes (`per_chunk_hashes` table or column).
- **AAD-bind chunk index to provider-ID** is overkill but worth mentioning — chunks from different providers should not be interchangeable.

The simplest **defense-in-depth** that lives entirely server-side: when `GetObjectChunkWithFallback` falls back, log a high-severity event (`logging.Log(logging.WARN, "fallback to provider %s for file %s", ...)`) and surface it on the admin dashboard. The current code only `log.Printf`s.

**Suggested tests.** Mock secondary to return corrupted bytes; verify the corruption is logged or, after the fix, rejected.

**Cross-refs.** C-02, C-19 (replication context handling).

---

### Finding C-09: S3 object metadata includes `owner-username` — plaintext username sent to and stored by every configured storage backend

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy
- **Component:** `handlers/uploads.go`, `storage/s3.go`
- **Affected files / functions:** `handlers/uploads.go:217-220` (metadata map construction), `storage/s3.go:336-351` (`InitiateMultipartUpload` passes metadata to AWS SDK).

**Description.** When a chunked upload is initiated, `CreateUploadSession` sends:

```go
// handlers/uploads.go:216-220
metadata := map[string]string{
    "session-id":     sessionID,
    "owner-username": username,
}
uploadID, err := storage.Registry.Primary().InitiateMultipartUpload(c.Request().Context(), storageID, metadata)
```

This map is passed to AWS SDK's `CreateMultipartUploadInput.Metadata`, which is sent as `x-amz-meta-owner-username` HTTP header on the S3 API request and stored as part of the object's user metadata. Anyone with read access to the bucket (e.g. third-party storage provider operator, the operator's storage-admin account, anyone who can list objects via S3 console) can enumerate which usernames own which `storage_id` objects.

Per `docs/AGENTS.md` "no IP, no PII" privacy posture, usernames are user-identifying. Sending them to a third-party S3 backend violates the spirit of that posture even though usernames are not full PII in the strict sense.

The `session-id` is a server-generated UUID per upload — not directly identifying, but linkable to the user via the metadata above.

**Evidence.** Snippet above.

```go
// storage/s3.go:336-351
func (s *S3AWSStorage) InitiateMultipartUpload(ctx context.Context, objectName string, metadata map[string]string) (string, error) {
    input := &s3.CreateMultipartUploadInput{
        Bucket:      aws.String(s.bucketName),
        Key:         aws.String(objectName),
        ContentType: aws.String("application/octet-stream"),
        Metadata:    metadata,
    }
    ...
}
```

**Attack scenario.** A storage provider operator who has read-only access to bucket object metadata can build a `{storage_id → username}` mapping for every file in the system. Combined with the file size (visible from `HeadObject`), upload timestamp (S3 `LastModified`), and the multi-provider replication pattern, this produces a high-fidelity per-user activity log readable by anyone with S3 read access — without ever touching the encrypted blob contents.

This is a real-world threat for the "9. Object-storage compromise attacker" and "13. Insider with access to logs, metrics, storage buckets, or database snapshots" adversaries per `idsrp.md` §2.

**Impact.** Medium privacy leak. Server learns no plaintext, but the S3 backend learns the file-owner mapping. For the Arkfile model where the trust line is "server is honest enough to enforce authz but cannot see plaintext, storage backend is opaque", this metadata sharing leaks the owner-list dimension to the storage backend without need.

**Recommendation.**

- Drop the `owner-username` key from the metadata map. Drop `session-id` too — neither is required by the S3 protocol or by Arkfile's own download path (the server already knows the owner via `file_metadata.owner_username`).
- If the metadata is needed for operator debugging at the S3 backend, replace with an opaque hash such as `EntityID(username)` (the same HMAC pattern Arkfile already uses for IP rate-limit keying — `logging/entity_id.go`). That preserves "different users have different metadata" while making the mapping not directly readable from S3.

**Suggested tests.** After the fix, integration test that creates an upload and inspects the S3 mock's recorded metadata — assert that no plaintext username appears.

**Cross-refs.** Slice A `A-?` (logging hygiene around usernames), Slice F (operational secrets exposure surface).

---

### Finding C-10: Server-side per-session SHA-256 hasher state is in-process memory only — server restart silently corrupts in-flight uploads

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational / reliability
- **Component:** `handlers/uploads.go`, `handlers/streaming_hash.go`
- **Affected files / functions:** `handlers/uploads.go:30-34` (global maps), `:580-594` (per-chunk hasher write), `:818-840` (FinalizeHash + delete); `handlers/streaming_hash.go` (the `StreamingHashState` type).

**Description.** Per-session SHA-256 hasher state is held in a package-level Go map:

```go
// handlers/uploads.go:30-34
var (
    streamingHashStates  = make(map[string]*StreamingHashState)
    storedBlobHashStates = make(map[string]*StreamingHashState)
    hashStateMutex       sync.RWMutex
)
```

Every successful chunk upload writes into `hashState.WriteChunk(...)` (L590-593), and `CompleteUpload` reads `FinalizeHash()` (L824-840). If the server process restarts (deploy, crash, OOM, systemd restart) between the first chunk upload and `CompleteUpload`, the in-memory hasher state is gone. Subsequent chunks would create a NEW `StreamingHashState` (uploads.go:582-585), hashing only the chunks that arrive AFTER the restart. `CompleteUpload` then computes a hash over a subset of the bytes, mismatches `actualStoredSize != paddedSize` (uploads.go:894), and the upload fails. Worse: the user does not know they need to restart from chunk 0 — the state is silently corrupted.

This also blocks horizontal scaling. If Arkfile is ever run with >1 process behind a load balancer, the hasher state will not be shared across processes and uploads will fail for any chunk that lands on a different backend instance.

**Evidence.** See snippets above. `uploads.go:828-830` returns 500 "Hash calculation failed - no streaming state found" if the state is missing at complete-time, which is the visible symptom.

**Attack scenario.** Not attacker-driven; reliability issue. A user with a multi-GB upload in progress during a deploy restart loses the upload and must re-encrypt and re-upload from scratch. Note that AES-GCM encryption is destination-fixed (the same FEK + same nonces) but the client does NOT persist FEK across sessions, so resumed uploads require fresh FEK and fresh encryption.

**Impact.** Reliability and UX cost; possible duplicate-upload bandwidth cost; no security impact.

**Recommendation.** Two options:

- **In-DB hasher state** (preferred for horizontal-scaling future-proofing): replace the map with a `BLOB`/`TEXT` column on `upload_sessions` that stores the marshaled `sha256.New()` state after each chunk write. Go's `crypto/sha256` exposes `BinaryMarshaler`/`BinaryUnmarshaler` on the hasher since Go 1.20. Each `UploadChunk` would `UnmarshalBinary` → `Write(chunk)` → `MarshalBinary` → UPDATE the column. Two extra DB hits per chunk; cheap.
- **Document single-process-only**: declare in `docs/setup.md` and the deploy scripts that Arkfile must run as exactly one process. Add a startup check that refuses to start if a sibling process is detected.

If neither is implemented, at minimum add a graceful-restart path that drains in-progress chunks before exit. systemd's `KillSignal=SIGTERM` + `TimeoutStopSec=...` and a Go `signal.Notify(SIGTERM)` handler in `main.go` would help, but cannot bound the drain time for users with multi-GB uploads in flight.

**Suggested tests.** Integration test that uploads N chunks, simulates a process restart (drop the map and reinit), uploads the next chunk, calls CompleteUpload, asserts the failure mode is detected.

**Cross-refs.** None directly; this is operational infra.

---

### Finding C-11: `replicateToSecondary` runs as a fire-and-forget goroutine with `context.Background()`, decoupled from the request context — large copies cannot be cancelled and survive shutdown attempts

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `handlers/uploads.go:1106-1157`.

**Description.** After a successful `CompleteUpload`, replication kicks off:

```go
// handlers/uploads.go:1123-1124
go func() {
    ctx := context.Background()
    ...
```

`context.Background()` is detached from any caller and never cancels. Cross-provider copy of a 6 GB file can take minutes-to-hours. Implications:

- A graceful shutdown (`systemctl stop arkfile`) cannot wait for in-flight replications; they will be killed mid-stream by SIGTERM/SIGKILL. The destination provider is left with an in-flight multipart upload, which only the operator-side lifecycle policy will eventually clean up (see C-06).
- An admin task that cancels a long-running replication (`AdminCancelTask` per `route_config.go:213`) has no plumb into this goroutine. The admin runner's cancel applies only to `admin_task_runner`-launched tasks; opportunistic replications fire-and-forget here are NOT registered with the task runner.
- The replication does NOT propagate the request's deadline. If the request had a 30s read deadline and the replication takes 10 minutes, the goroutine still runs to completion (or to network failure) decoupled.

The destination-status row is updated `pending` → `active` or `failed` (uploads.go:1118 and L1146-1151), so the system eventually reaches a consistent state via the status field. But there is no admin visibility into in-flight replications until they finish.

**Evidence.** Snippet above; the goroutine in full at uploads.go:1123-1157.

**Attack scenario.** Operator-affecting. A malicious user uploading many large files in succession can sustain a backlog of in-flight replication goroutines, each holding open S3 connections to the secondary. With no global concurrency cap on the replication goroutines (one per upload-complete), this is an unbounded-goroutine pattern.

**Impact.** Operational. With many concurrent uploads, server can leak goroutines and S3 connections, potentially crashing.

**Recommendation.**

- Route replication through the admin task runner (`handlers/admin_task_runner.go` — Slice E). Submit each replication as a task; bound the global concurrency (e.g. 4 concurrent replications); make the task visible in admin UI for `AdminCancelTask`.
- Pass `cfg.Storage.ReplicationTimeout` (or sane default like 1 hour) as a context deadline.

**Suggested tests.** Integration that creates 10 concurrent replications and asserts at most N run in parallel.

**Cross-refs.** Slice E for task runner integration.

---

### Finding C-12: `GetFileEnvelope` lacks the `IsApproved` check that `GetFileMeta` and `DownloadFileChunk` enforce — pending-approval users can read encrypted FEKs

- **Severity:** Low
- **Confidence:** High
- **Category:** authorization / consistency
- **Component:** `handlers/files.go`
- **Affected files / functions:** `handlers/files.go:187-212` (GetFileEnvelope); compare with `:80-89` (GetFileMeta has the check) and `handlers/downloads.go:52-54` (DownloadFileChunk has it).

**Description.** `GetFileMeta`:

```go
// handlers/files.go:80-89
user, err := models.GetUserByUsername(database.DB, username)
if err != nil { ... }
if !user.IsApproved {
    return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. ...")
}
```

`DownloadFileChunk`:

```go
// handlers/downloads.go:46-54
user, err := models.GetUserByUsername(database.DB, username)
if err != nil { ... }
if !user.IsApproved {
    return echo.NewHTTPError(http.StatusForbidden, "Account pending approval. ...")
}
```

`GetFileEnvelope` (used during share creation):

```go
// handlers/files.go:187-212
func GetFileEnvelope(c echo.Context) error {
    username := auth.GetUsernameFromToken(c)
    fileID := c.Param("fileId")
    file, err := models.GetFileByFileID(database.DB, fileID)
    if err != nil { ... }
    if file.OwnerUsername != username {
        return echo.NewHTTPError(http.StatusForbidden, "Access denied")
    }
    return c.JSON(http.StatusOK, map[string]interface{}{
        "file_id":       file.FileID,
        "encrypted_fek": file.EncryptedFEK,
        "password_type": file.PasswordType,
    })
}
```

No `IsApproved` check. A pending-approval user CANNOT upload (CreateUploadSession blocks it at uploads.go:90-92) so they cannot OWN any file, which means `file.OwnerUsername != username` will fail for any real fileID they query. The consistency gap is therefore not directly exploitable today, but it is a tripwire that does not trip — and if the bootstrap admin creation flow (Slice A) ever leaves an approved-but-not-active admin in a state where they own files but `IsApproved=false`, the inconsistency surfaces.

**Evidence.** See snippets above.

**Attack scenario.** Currently no exploit because the approval-gate at upload prevents the precondition. Future hazard if approval semantics change.

**Impact.** Low; consistency only.

**Recommendation.** Add the `IsApproved` check to `GetFileEnvelope` for consistency with the sibling endpoints. Or, better, factor `requireApprovedOwner(c, fileID) (*File, error)` into a helper used by all three handlers.

**Cross-refs.** None directly. Pattern-level fix.

---

### Finding C-13: Streaming download into the Service Worker writes plaintext to disk BEFORE the end-of-file SHA-256 verification result is known; the user receives a warning AFTER the file is saved

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / design (defense in depth)
- **Component:** `client/static/js/src/files/streaming-download.ts`, `sw-streaming-download.ts`, `download.ts`
- **Affected files / functions:**
  - SW path emits chunks as they pass: `client/static/js/src/files/sw-streaming-download.ts:160-258`.
  - Hash verification happens at stream completion: `:233-258`.
  - Caller-side warning is shown AFTER `swStreamDownload` resolves: `client/static/js/src/files/download.ts:218-220`.

**Description.** Arkfile's preferred download path is the Service Worker streaming path, which writes plaintext to the user's disk via the browser's download manager as bytes arrive. Per-chunk AES-GCM tag verification ensures each chunk's plaintext is authenticated (so random bit-flip on a single chunk is rejected before its plaintext is yielded). But the **end-of-file SHA-256 verification** (against the metadata `encrypted_sha256sum` value decrypted client-side, which is the plaintext file hash) is computed inline and only known when the stream closes.

If the server (or a tampered secondary provider per C-08, or a within-file chunk reorder per C-02/C-03) produces a stream whose chunks each pass per-chunk AEAD but whose concatenation does not hash to the expected value, the user has already saved the (partially or fully) tampered file when the warning surfaces:

```ts
// client/static/js/src/files/download.ts:218-220
if (result.hashVerification === 'mismatch') {
  showWarning('SHA-256 verification failed for the downloaded file. The file may be corrupted or tampered with. Consider deleting it and re-downloading.');
}
```

The Service Worker has no facility to "un-write" the bytes from the browser's download manager. The file is on disk.

This is a fundamental trade-off of streaming-to-disk vs. download-then-verify. The Blob fallback path does NOT have this property — there, the assembled Blob can be hashed BEFORE handing to the browser download anchor. The current code does not hash the Blob fallback at all (streaming-download.ts:514-527), so the Blob path is also missing end-of-file verification, in addition to the SW-path's late warning.

**Evidence.** Snippets above. The trade-off is well documented in the source comments (sw-streaming-download.ts:113-117: "Mismatch is reported via the result, never thrown — the file is on disk by then").

**Attack scenario.** Combined with C-02 / C-03 / C-08: server reorders or swaps chunks. User downloads. Plaintext is on disk. User sees the warning, but may not act on it (warnings are dismissable, the file is already where they wanted it, the warning prose is generic "may be corrupted or tampered with"). Downstream tools that consume the file (file managers, archive extractors, media players) do not see the warning and use the bad data.

**Impact.** Defense-in-depth failure for the integrity guarantee. The cryptographic AEAD tag protects against random bitflip on any single chunk; the end-of-file hash protects against reorder/substitution at the file level — but the late warning means a sophisticated user can be fooled.

**Recommendation.** Three layers, in priority order:

1. **Add AAD on chunks** (per C-02 recommendation). With chunk-index in AAD, reorder/substitution fails per-chunk AEAD verification, plaintext is never released to the SW, and the SW closes the stream with an error which propagates to a download-failed indication in the browser. This is the only defense that prevents disk-write of tampered bytes.
2. **Surface the SW-path verification result more strongly**: instead of `showWarning`, treat hash mismatch as a hard error and prompt the user to delete the downloaded file (use the File System Access API where available, otherwise an explicit alert with file path).
3. **For the Blob fallback path**: hash the assembled Blob and refuse to call `triggerBrowserDownloadFromUrl` if mismatched. Currently the Blob path has NO end-of-file verification at all, which is strictly worse than the SW path.

**Suggested tests.**

- Test that artificially returns a chunk with a swapped index (after C-02's AAD fix); browser's downloaded file is not produced.
- Blob-path test that hashes the assembled blob and rejects on mismatch.

**Cross-refs.** C-02, C-03, C-08; Slice B `B-02`/`B-05`.

---

### Finding C-14: Blob-fallback download path performs no SHA-256 verification at all — verification is silently dropped when the Service Worker is unavailable

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / design
- **Component:** `client/static/js/src/files/streaming-download.ts`
- **Affected files / functions:** `:512-528` (`streamDecryptedChunks` Blob fallback branch).

**Description.** When the Service Worker is unavailable (very old browsers, certain private-browsing modes, the SW registration failed), the download falls back to incremental `new Blob([prev, chunk])` accumulation:

```ts
// client/static/js/src/files/streaming-download.ts:512-528
console.log(`${logPrefix} Using Blob fallback path (SW unavailable)`);
let blob = new Blob([]);
let chunkIndex = 0;
for await (const chunk of chunks) {
  blob = new Blob([blob, chunk.slice(0)]);
  chunkIndex++;
  ...
}
const url = URL.createObjectURL(blob);
console.log(`${logPrefix} Blob URL created (${blob.size} bytes)`);
return { blobUrl: url };
```

There is no SHA-256 computation here, and no `hashVerification` field is returned in the result. The caller (download.ts:222-228) only checks for `streamedViaSw === true` to gate the warning; on the Blob path it just triggers the download.

So users on browsers that fall back to Blob get **no integrity verification at all** for the assembled file, beyond per-chunk AEAD which (as in C-02) doesn't catch reorder.

This is a strict regression vs. the SW path. It is also undetectable from the user's perspective — there is no UI indication that they got the weaker path.

**Evidence.** Snippet above. `download.ts:218-220` only fires on the SW path.

**Attack scenario.** Same as C-02/C-13 but on a Blob-fallback browser. User has no indication anything is wrong.

**Impact.** Same severity class as C-13 but worse because there is no warning at all.

**Recommendation.** After assembling the Blob, compute SHA-256 over it and compare against `expectedSha256Hex` (which `streamDecryptedChunks` already receives at L484). On mismatch, do NOT return a `blobUrl`; return an error result. The caller can then refuse to trigger the download anchor. Streaming-Blob on a 6 GB file with 3 GB RAM is not feasible anyway (the comment at streaming-download.ts:29 notes "~2 GB on Chromium, several GB on Firefox/Tor"), so the practical files served via this path are small enough that a final SHA-256 pass is affordable.

Or, more aggressively: deprecate the Blob fallback path entirely and require SW availability (with a user-visible error if not). Slice F can revisit.

**Suggested tests.** Test with SW disabled in jsdom (the existing `streaming-download.test.ts` already does this) — assert that on hash mismatch the result is `success: false` and no `blobUrl`.

**Cross-refs.** C-13.

---

### Finding C-15: Per-upload and per-download `InfoLogger` lines include both `username` and `file_id` together — straightforward to reconstruct per-user file activity from logs

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy
- **Component:** `handlers/uploads.go`, `handlers/downloads.go`, `handlers/files.go`
- **Affected files / functions:** Spread across the slice; key lines below.

**Description.** Per `docs/AGENTS.md`, IP addresses and PII must not be logged; rate-limit keying uses `EntityID` HMAC. But the file/upload handlers log username + file_id together at INFO level multiple times per operation:

```go
// handlers/uploads.go:247-248 (CreateUploadSession)
logging.InfoLogger.Printf("Upload session created: %s by %s (file_id: %s, size: %d bytes)",
    sessionID, username, fileID, request.TotalSize)
```

```go
// handlers/uploads.go:330 (CancelUpload)
logging.InfoLogger.Printf("Upload canceled: %s, file_id: %s by %s", sessionID, fileID, username)
```

```go
// handlers/uploads.go:666-667 (UploadChunk)
logging.InfoLogger.Printf("Chunk uploaded: %s, file_id: %s, chunk: %d/%d",
    sessionID, fileID, chunkNumber+1, totalChunks)
```

```go
// handlers/uploads.go:953-954 (CompleteUpload)
logging.InfoLogger.Printf("Upload completed: %s, file_id: %s by %s (size: %d bytes)", sessionID, fileID.String, username, actualStoredSize)
database.LogUserAction(username, "uploaded", fileID.String)
```

```go
// handlers/uploads.go:1088-1089 (DeleteFile)
database.LogUserAction(username, "deleted", fileID)
logging.InfoLogger.Printf("File deleted: file_id=%s by %s", fileID, username)
```

```go
// handlers/downloads.go:128-130 (DownloadFileChunk)
if chunkIndex == 0 || chunkIndex == file.ChunkCount-1 {
    logging.InfoLogger.Printf("Chunk download: file_id=%s chunk=%d/%d by %s (bytes %d-%d)", ...)
}
```

```go
// handlers/files.go:94 (GetFileMeta)
logging.InfoLogger.Printf("File metadata requested: file_id %s by %s (size: %d bytes, chunks: %d)", ...)
```

`database.LogUserAction(username, "uploaded", fileID.String)` writes a permanent row to `user_activity` table with `(username, action, file_id, timestamp)` — the `EntityID` hashing applies to IP-bound rate-limit keys, not to this audit log.

The `username` field is the user-facing identifier they chose at registration. While it is not strictly PII in the GDPR sense, it is the user-identifying primary key in the system; logging it alongside `file_id` constructs a per-user file activity log that:

1. Lives in the operator's general application log (`logging.InfoLogger`).
2. Is also persisted to the database (`LogUserAction`).
3. Is accessible to the operator and to anyone who reads logs / DB snapshots.

This conflicts with the privacy posture explicitly described in AGENTS.md.

**Evidence.** Snippets above. Note that `username` and `file_id` are needed by the application for routing, authz, and debugging — the question is whether they need to BOTH be in plain log lines and BOTH be in long-lived audit rows.

**Attack scenario.** Adversary 13 ("Insider with access to logs, metrics, storage buckets, or database snapshots") gets a copy of `logs/` or the DB. Reconstructs per-user activity timeline:

- User foo uploaded file_id X at T.
- User foo downloaded file_id X at T+δ.
- User foo created share Y referencing file_id X.
- User foo deleted file_id X.

This timeline is exactly the metadata Arkfile is supposed to not surface.

**Impact.** Medium privacy regression. Strictly contrary to AGENTS.md's "no PII" stance. Becomes more serious in any kind of legal/regulatory request scenario.

**Recommendation.**

Pick one or both:

- **Replace `username` in INFO log lines with `EntityID(username)`** (similar to how IPs are hashed). The `EntityID` is logging-only and not reversible by the operator without the HMAC key (`logging/entity_id.go`). For internal debugging, the operator can hash a candidate username and grep — explicit join still requires knowing the username up front.
- **Audit `database.LogUserAction`'s schema and retention**: shorten retention, separate it from operational logs, mask the username column with `EntityID`. Slice E will be the right place to decide what is needed for billing/forensics.
- **Drop the `file_id` from the per-chunk download log line** (downloads.go:129) — the file_id is already in the session-create and complete logs at upload time. Per-chunk activity is high-resolution surveillance.

**Suggested tests.** Grep test against a sample log line that asserts no plaintext username appears in any `InfoLogger` line for a known test user.

**Cross-refs.** Slice E logging review (multiple findings expected). AGENTS.md §"Privacy posture".

---

### Finding C-16: Per-user concurrent-upload-session cap is enforced but TOCTOU window exists between the COUNT and the INSERT under rqlite's default isolation

- **Severity:** Low
- **Confidence:** Medium
- **Category:** design
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `:142-184` (`CreateUploadSession` cap enforcement); `:209-211` (INSERT after the cap check).

**Description.** The cap check and the INSERT happen inside the same `database/sql` transaction (uploads.go:136-245):

```go
// handlers/uploads.go:161-184 (excerpt, abridged)
var inProgressCount int
if err := tx.QueryRow(
    `SELECT COUNT(*) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`,
    username,
).Scan(&inProgressCount); err != nil { ... }
if inProgressCount >= maxInProgressUploadSessionsPerUser {
    ...
    return c.JSON(http.StatusTooManyRequests, ...)
}
...
// later
_, err = tx.Exec(
    "INSERT INTO upload_sessions (id, file_id, ...) VALUES (...)", ...
)
```

For SQLite-on-rqlite under SERIALIZABLE isolation this is safe. But rqlite's default isolation level is what SQLite gives you per-statement, and the Go `database/sql` package's `Begin()` semantics over the rqlite driver are not documented as SERIALIZABLE in `database/database.go`. If two `CreateUploadSession` calls for the same user interleave such that both COUNT operations see (say) 3 sessions, both pass the cap-of-4, both INSERT — net result 5 sessions for that user. This violates the per-user cap by one.

For SQLite specifically, writes are serialized at the file level so two INSERTs cannot truly interleave. For rqlite (which uses Raft), the COUNT might be served by a follower with a slightly stale read while the INSERT goes through the leader. This depends on the rqlite client config (`?level=strong` for strong consistency vs. `?level=weak` default).

**Evidence.** Snippet above; rqlite consistency semantics are out of scope of the codebase but are configured in `database/database.go` (read-level not visible in the file I read).

**Attack scenario.** A user races two `/api/uploads/init` requests in tight succession. With weak rqlite consistency, both pass. Net effect: 5 in-progress sessions for a user with a stated cap of 4. Not a security vulnerability — the cap is a soft-rate-limit / DoS-mitigation, and overshooting by 1 is not catastrophic. Worth fixing because it undermines the implicit "the cap is exact" invariant.

**Impact.** Low; rate-limit precision.

**Recommendation.**

- Verify rqlite consistency level for read-modify-write paths; explicitly request strong consistency for this transaction.
- Alternative: enforce the cap at the DB-constraint layer (`UNIQUE` or a check trigger) so a 5th INSERT fails atomically. SQLite supports `CHECK` constraints; the schema for `upload_sessions` is in `database/unified_schema.sql` (Slice E).

**Suggested tests.** Race-condition integration test — two parallel goroutines calling `CreateUploadSession` for the same user with the cap already at N-1; assert at most 1 succeeds.

**Cross-refs.** Slice E for full schema review.

---

### Finding C-17: `storage.GetPresignedURL` is on the `ObjectStorageProvider` interface and implemented for S3, but is never called by any handler — dead code that exposes a footgun

- **Severity:** Low
- **Confidence:** High
- **Category:** design (greenfield) / operational
- **Component:** `storage/storage.go`, `storage/s3.go`
- **Affected files / functions:** `storage/storage.go:25` (interface method), `storage/s3.go:320-334` (S3 impl), `storage/mock_storage.go:52-55` (mock).

**Description.** The interface contract requires every `ObjectStorageProvider` to implement `GetPresignedURL`. The AWS SDK v2 implementation does so (s3.go:320-334), and the mock does so. **No handler in `handlers/` calls it.** I verified by searching the entire `handlers/` tree:

```
grep "GetPresignedURL\|PresignedURL\|presigned" handlers/  → 0 results
```

If a future developer wires a presigned-URL handler — e.g. "share a direct S3 URL for performance" — they would create an authorization-bypass channel where:

- The Arkfile-side auth/TOTP middleware is bypassed (presigned URLs carry their own AWS-side cryptographic auth, no Bearer JWT).
- The chunked-byte-range, AES-GCM-per-chunk integrity is bypassed (presigned-URL clients get whole blobs).
- The multi-provider fallback is bypassed.
- Logging is bypassed (S3 logs only the URL access, not the user context).

This is consistent with the AGENTS.md "Greenfield" guidance: dead code should be flagged for removal, not accommodation.

**Evidence.**

```go
// storage/storage.go:25
GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error)
```

```go
// storage/s3.go:320-334 (the implementation that would happily mint URLs if called)
func (s *S3AWSStorage) GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error) {
    request, err := s.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(s.bucketName),
        Key:    aws.String(objectName),
    }, func(o *s3.PresignOptions) {
        o.Expires = expiry
    })
    if err != nil { return "", fmt.Errorf("failed to presign get object: %w", err) }
    return request.URL, nil
}
```

**Attack scenario.** None currently. Tripwire for future code review.

**Impact.** Low; tripwire only.

**Recommendation.** Remove `GetPresignedURL` from the interface and all three implementations. If a future use case for presigned URLs emerges (e.g. share-link-as-direct-S3-URL — explicitly NOT what Arkfile does), add it back with a documented threat model.

**Cross-refs.** None.

---

### Finding C-18: Both build-tagged `mock` chunked-upload integration tests are NOT run under the default `go test ./...` — the chunked upload pipeline has effectively no unit-level coverage

- **Severity:** Medium
- **Confidence:** High
- **Category:** testing
- **Component:** `handlers/chunked_upload_integration_test.go`, `handlers/chunked_upload_100mb_test.go`, `handlers/uploads_test.go`
- **Affected files / functions:** `:1-2` of both files (`//go:build mock`).

**Description.** The two end-to-end chunked-upload tests are gated behind `//go:build mock`:

```go
// handlers/chunked_upload_integration_test.go:1-2
//go:build mock
// +build mock
```

```go
// handlers/chunked_upload_100mb_test.go:1-2
//go:build mock
// +build mock
```

Default `go test ./...` does NOT pass the `mock` tag and therefore skips both files. The remaining file, `handlers/uploads_test.go`, is a 10-line stub that points to the other two and contains no test functions.

So the entire chunked-upload code path — `CreateUploadSession`, `UploadChunk`, `CompleteUpload`, `CancelUpload`, `GetUploadStatus`, the streaming hash state, the padding append on last chunk — has no test coverage under default CI runs.

`handlers/files_test.go` (779 lines) DOES cover `ListFiles`, `GetFileMeta`, `DeleteFile`, and the multi-provider delete path. So delete-by-id is well tested. The upload pipeline is not.

Per AGENTS.md and `idsrp.md` §17, this is in scope — testing gaps are findings.

**Evidence.** Build-tag pragmas above; my grep over `handlers/*_test.go` finds no `Test*Upload*` functions outside the mock-tagged files (excluding the trivial stub).

**Attack scenario.** No exploit. But the absence of regression tests means future changes to uploads.go could break the chunked pipeline without CI catching it. The recent envelope-fix history (referenced in the test comments) confirms this is a code path that has had bugs.

**Impact.** Reliability and future-defect-frequency. No direct security impact today but elevates the risk of accidentally breaking the privacy-preserving wire format.

**Recommendation.**

- Drop the `//go:build mock` tags. The tests use `setupTestEnv` (mocks + sqlmock + testify) and do not depend on a real S3 backend, so they should run in the default test suite. If there is a reason for the tag (slow, flaky), explain it in comments and make sure they run in CI under a non-default-but-mandatory job.
- Add the negative tests called out in §6 (Testing Gaps): chunk reorder, chunk replay, mismatched X-Chunk-Hash, race in CompleteUpload, S3 failure mid-upload, oversized chunk body, etc.

**Cross-refs.** §6 Testing Gaps below.

---

### Finding C-19: The doc comment in `models/file.go` claims AAD = `(file_id, "sha256sum", owner_username)` for `EncryptedSha256sum`, but the actual upload pipeline encrypts metadata with **no AAD**

- **Severity:** Low
- **Confidence:** High
- **Category:** documentation / design
- **Component:** `models/file.go`, `client/static/js/src/files/upload.ts`
- **Affected files / functions:** `models/file.go:14-39` (the doc block); `client/static/js/src/files/upload.ts:319-345` (`encryptMetadata`).

**Description.** The struct doc says:

```go
// models/file.go:18-22 (excerpt)
//	Sha256sumNonce + EncryptedSha256sum
//	  SHA-256 of the user's original PLAINTEXT file. Computed client-side,
//	  encrypted client-side under the account key, and stored as ciphertext
//	  (nonce + ct||tag, base64). The server never sees this value in
//	  plaintext. AAD-bound to (file_id, "sha256sum", owner_username) per
//	  docs/wip/folders-multi-upload-v2.md §3 so cross-row / cross-field
//	  tampering fails at client decrypt time.
```

But the TypeScript code that actually performs the encryption omits AAD entirely:

```ts
// client/static/js/src/files/upload.ts:326-345 (encryptMetadata)
async function encryptMetadata(
  data: string,
  key: Uint8Array
): Promise<{ encrypted: string; nonce: string }> {
  const dataBytes = new TextEncoder().encode(data);
  const result = await encryptAESGCM({
    data: dataBytes,
    key,
    // No AAD for metadata - matches Go implementation
  });
  ...
}
```

The decryption path in `streaming-download.ts:560-569` (`decryptMetadataField`) likewise does NOT pass any `additionalData`. So the AAD-binding the doc claims **does not exist on the wire**.

This is a "claim contradicts implementation" finding — exactly the class of issue `idsrp.md` §16 ("Documented vs. implemented hierarchy match") asks for.

The cited spec doc `docs/wip/folders-multi-upload-v2.md` was not in the Slice C scope and is presumably the source of the (un-implemented) design intent.

**Evidence.** Snippets above. Confirmed in Slice B `B-08`.

**Attack scenario.** A server with DB write access can swap `encrypted_sha256sum` and `sha256sum_nonce` between two of the same user's files (because the metadata key is the user's account-KEK, the same for all their files). The client decrypts the swapped ciphertext successfully (correct key, correct nonce, GCM tag validates because the swap copied both fields together). The user sees the sha256sum of file B claimed for file A. If they trust the displayed metadata, they may upload-as-share-of-file-A what is in fact file B's content fingerprint, leading to a downstream verification mismatch (or, worse, a successful share if the recipient doesn't independently verify).

The same swap is possible for `encrypted_filename`. So a server can rename the user's files arbitrarily, swapping displayed names between files of the same user.

**Impact.** Medium-Low. Direct user impact: server can lie about filenames and SHA-256s in the file list. Encrypted bytes (file content) are NOT affected (FEK is per-file, FEK-encrypted-with-KEK is also AAD-less but `encrypted_fek` value swap implies different keyType envelope, which would fail FEK decrypt for a different password type).

**Recommendation.** Implement the AAD as documented:

- In `encryptAESGCM(...)` browser call sites and the Go CLI's `EncryptGCMWithAAD`, pass `additionalData = utf8(fileID || "|" || "sha256sum" || "|" || ownerUsername)` (or a canonical encoding thereof) for each metadata field.
- For the filename field: AAD = `... || "filename" || ...`.
- For the FEK envelope: AAD = `... || "fek" || ...` plus the `password_type` byte.

The browser/CLI must agree on the AAD encoding exactly. A simple unambiguous scheme is `len(fileID) || fileID || len(field) || field || len(owner) || owner` with lengths as uint8/uint16.

OR remove the false claim from the doc if the team decides not to implement the AAD. That is the Greenfield-correct route per AGENTS.md ("flag deprecated/stub/bad/backwards-compatibility comments").

**Cross-refs.** Slice B `B-08` (no-AAD on metadata); C-02 (no-AAD on chunks); the deferred design doc `docs/wip/folders-multi-upload-v2.md`.

---

### Finding C-20: `parseChunkIndex` rolls its own integer parser with no overflow check — large numeric strings silently overflow into negative or wrap-around values

- **Severity:** Low
- **Confidence:** High
- **Category:** design / robustness
- **Component:** `handlers/downloads.go`
- **Affected files / functions:** `:137-145`.

**Description.**

```go
// handlers/downloads.go:137-145
func parseChunkIndex(s string) (int64, error) {
    n := int64(0)
    for _, c := range s {
        if c < '0' || c > '9' {
            return 0, fmt.Errorf("invalid chunk index")
        }
        n = n*10 + int64(c-'0')
    }
    return n, nil
}
```

For a numeric string of 20+ digits, `n` silently overflows. The subsequent `chunkIndex >= file.ChunkCount` check at downloads.go:57 catches negative or absurdly-large indices via the bounds check, so this does not turn into an exploitable condition. But the function returns no error on overflow — it returns a wrong value. Empty string `""` returns `(0, nil)` and is accepted as chunk 0.

**Evidence.** Snippet above.

**Attack scenario.** No direct exploit. Robustness issue.

**Impact.** Low. Code-clarity / future-defense.

**Recommendation.** Use `strconv.ParseUint(s, 10, 31)` (cap at 2^31-1 so it fits int32 chunk counts comfortably). Reject empty string explicitly. The existing `strconv.Atoi(chunkNumberStr)` pattern from uploads.go:453 would also do.

**Cross-refs.** None.

---

### Finding C-21: Bucket creation in `ensureBucketExists` sets no public-access block, no encryption configuration, no lifecycle policy

- **Severity:** Low
- **Confidence:** High
- **Category:** operational / hardening
- **Component:** `storage/s3.go`
- **Affected files / functions:** `:185-202`.

**Description.** When the configured provider is `ProviderGenericS3` (local SeaweedFS / MinIO / etc.), Arkfile auto-creates the bucket on startup:

```go
// storage/s3.go:185-202
func ensureBucketExists(client *s3.Client, bucketName string) {
    ...
    _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
        Bucket: aws.String(bucketName),
    })
    ...
}
```

The `CreateBucketInput` is bare — no `PublicAccessBlockConfiguration`, no `ServerSideEncryptionConfiguration`, no `LifecycleConfiguration`. Bucket defaults vary by backend; for local SeaweedFS this is acceptable, for actual AWS / Wasabi / B2 it means the operator is responsible for setting these post-creation (and most operators won't).

Per AGENTS.md, Arkfile's encrypted blobs are protected by client-side encryption, so server-side bucket encryption is defense-in-depth only. The bigger concern is the missing **public-access block** (would prevent accidental public-bucket misconfiguration) and the missing **lifecycle policy for incomplete multipart uploads** (cross-ref C-06).

**Evidence.** Snippet above.

**Attack scenario.** An operator following the deploy scripts ends up with a freshly-created bucket that has no PublicAccessBlock. If the operator later runs an admin CLI that flips an object ACL to public (intentionally or by accident), the encrypted blob becomes publicly downloadable. The blob is encrypted, so the user's data stays confidential, but the **server-visible metadata exposure** (file size, owner-username S3 meta, upload date) becomes world-readable. Combined with C-09 (owner-username in S3 metadata), this is a privacy regression.

**Impact.** Low; depends on operator behavior.

**Recommendation.**

- Call `client.PutPublicAccessBlock(...)` immediately after `CreateBucket` with all four flags set to `true`.
- Call `client.PutBucketLifecycleConfiguration(...)` with an "abort incomplete multipart uploads after 7 days" rule.
- Server-side encryption is optional given client-side encryption; mention in `docs/setup.md`.

This is also a Slice F concern (operational deployment). The boilerplate sits in `storage/s3.go` though, so it's listed here.

**Suggested tests.** Unit test against mock S3 that asserts the PutPublicAccessBlock call happened.

**Cross-refs.** C-06, C-09; Slice F.

---

### Finding C-22: `S3AWSStorage` disables `RequestChecksumCalculation` for non-HTTPS endpoints; SDK-level upload checksum is not enforced for local SeaweedFS / HTTP backends

- **Severity:** Low
- **Confidence:** High
- **Category:** operational / hardening
- **Component:** `storage/s3.go`
- **Affected files / functions:** `:170-172`.

**Description.**

```go
// storage/s3.go:170-172
if cfg.Endpoint != "" && !strings.HasPrefix(cfg.Endpoint, "https://") {
    o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
}
```

The comment above (storage/s3.go:167-169) explains: HTTP destinations need seekable streams for AWS-SDK-side checksum computation, which is incompatible with streaming TeeReader used in cross-provider copies. So checksum is disabled for HTTP endpoints.

Arkfile compensates with its own application-level SHA-256 (`streamingHashStates`), which IS computed and stored. So the application has integrity at the application layer. But the SDK-level wire-checksum (which catches network-level corruption between Arkfile and the S3 backend, separate from application-level corruption) is disabled.

For local SeaweedFS on `localhost:9332` this is fine — same machine, no realistic in-flight corruption. For an HTTP S3 backend over a real network (which would be a deployment misconfig), this is a gap.

**Evidence.** Snippet above.

**Attack scenario.** A man-in-the-middle on the HTTP connection between Arkfile and a remote S3 backend could mutate bytes; SDK-level checksum would catch it, but Arkfile-level SHA-256 also catches it (the streaming hash is over the bytes-as-received-by-the-handler, BEFORE they go to S3 — so application-level hash IS the right place for this anyway).

Actually wait: the application-level `streamingHashStates` hashes the **incoming-from-client** bytes (uploads.go:589-593), not the bytes-as-received-from-S3 on download. Download-time SHA-256 of the served blob against `stored_blob_sha256sum` is **not** performed (cross-ref C-08). So SDK-level checksum on HTTPS connections IS the only wire-level corruption detection between server and S3 on downloads.

Disabling SDK checksum on HTTP endpoints is therefore strictly weakening defense-in-depth on the download path for HTTP S3 backends. For local SeaweedFS this is fine; for any externally-reachable HTTP backend, it is not.

**Impact.** Low operationally (HTTPS is the production norm). Worth flagging.

**Recommendation.**

- Refuse to start if `Endpoint` is non-HTTPS AND `Endpoint` is not in a localhost/private-IP range. Force operator to use HTTPS for off-host backends.
- Or document the trade-off in `storage/s3.go` and `docs/setup.md`.

**Cross-refs.** C-08.

---

### Finding C-23: `models/file.go` has a `CreateFile` function that no handler calls — dead code drifted out of sync with the canonical INSERT in `CompleteUpload`

- **Severity:** Low
- **Confidence:** High
- **Category:** code clarity / Greenfield
- **Component:** `models/file.go`
- **Affected files / functions:** `:102-144` (`CreateFile`); compare to canonical INSERT path in `handlers/uploads.go:914-918`.

**Description.** `models/file.go` defines `CreateFile` that takes a small subset of the columns the schema actually has. The real INSERT in `CompleteUpload` is hand-rolled tx.Exec at uploads.go:914-918, and it inserts a much larger set of columns (including `password_hint`, `encrypted_fek`, `padded_size`, `chunk_count`, `chunk_size_bytes`, `encrypted_file_sha256sum`, `stored_blob_sha256sum`).

`CreateFile` is not called by any handler (confirmed via grep — only test files reference it, if at all). It is dead and drift-prone code.

Per AGENTS.md "Greenfield" guidance: dead code should be removed, not maintained.

**Evidence.**

```go
// models/file.go:103-118 (CreateFile signature shows the column subset it knows about)
func CreateFile(db *sql.DB, fileID, storageID, ownerUsername, passwordHint, passwordType string,
    filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum string, sizeBytes int64) (*File, error) {
    chunkSizeBytes := crypto.PlaintextChunkSize()
    chunkCount := CalculateChunkCount(sizeBytes, chunkSizeBytes)
    result, err := db.Exec(`
        INSERT INTO file_metadata (
            file_id, storage_id, owner_username, password_hint, password_type,
            filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
            size_bytes, chunk_count, chunk_size_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ...
    )
    ...
}
```

This INSERT omits `encrypted_fek`, `padded_size`, `encrypted_file_sha256sum`, `stored_blob_sha256sum`. If anyone calls `CreateFile` instead of the canonical inline INSERT, the resulting file row is missing the FEK envelope and cannot be downloaded.

**Impact.** Tripwire. Future developer might wire `CreateFile` somewhere and silently break the system.

**Recommendation.** Delete `CreateFile` (and `CalculateChunkCount` if it has no other callers). Or refactor `CompleteUpload`'s inline INSERT into a `CreateFileFull(...)` model method and use it consistently.

**Suggested tests.** None — straight cleanup.

**Cross-refs.** AGENTS.md Greenfield.

---

### Finding C-24: `models/file.go`'s `UpdatePasswordHint` does no owner check — caller is solely responsible; the method is currently unwired but is a tripwire

- **Severity:** Low
- **Confidence:** High
- **Category:** authorization
- **Component:** `models/file.go`
- **Affected files / functions:** `:627-638`.

**Description.**

```go
// models/file.go:627-638
func (f *File) UpdatePasswordHint(db *sql.DB, newHint string) error {
    _, err := db.Exec(
        "UPDATE file_metadata SET password_hint = ? WHERE id = ?",
        newHint, f.ID,
    )
    if err != nil { return err }
    f.PasswordHint = newHint
    return nil
}
```

No `owner_username` predicate. The method is currently uncalled by any handler (no `UpdatePasswordHint(` invocation under handlers/ per grep). If a handler is added in the future that calls this without first verifying ownership, it becomes a cross-user IDOR — any authenticated user could update any file's password hint by id.

**Evidence.** Snippet above.

**Attack scenario.** None today. Tripwire.

**Impact.** Low; depends on future wiring.

**Recommendation.** Change the signature to require `ownerUsername` and add `AND owner_username = ?` to the WHERE clause. Or delete the function as dead code.

**Cross-refs.** Same class as C-23.

---

### Finding C-25: `GetFileMetadataBatch` does not deduplicate the `file_ids` array — duplicate IDs in the request inflate cost without server-side de-duplication

- **Severity:** Informational
- **Confidence:** High
- **Category:** design / hardening
- **Component:** `handlers/files.go`, `models/file.go`
- **Affected files / functions:** `handlers/files.go:145-184`; `models/file.go:519-560`.

**Description.** The batch metadata endpoint accepts up to 500 file IDs (`maxMetadataBatchSize = 500`). If the same ID appears multiple times, the server constructs a SQL `IN (?, ?, ?, ...)` with duplicate placeholders. The DB happily evaluates and returns the same row N times, but the response-building loop (`handlers/files.go:166-178`) uses a map keyed by `file.FileID`, so duplicates collapse into one entry. The "missing" array correctly counts duplicates of an absent ID as one missing entry.

So the functional behavior is correct; the only cost is wasted DB bandwidth on duplicates. Not a security finding, but a hardening note.

**Evidence.** Snippets in `models/file.go:519-560`.

**Recommendation.** De-duplicate `request.FileIDs` at the handler entry before the SQL build. One line change.

**Cross-refs.** None.

---

### Finding C-26: `database.LogUserAction(username, "uploaded", fileID)` is called outside any transaction in `CompleteUpload` and after `tx.Commit()` — partial-success windows exist where the upload row is committed but the user-action row is missed

- **Severity:** Informational
- **Confidence:** Medium
- **Category:** operational / consistency
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `:949-954`.

**Description.**

```go
// handlers/uploads.go:949-954
if err := tx.Commit(); err != nil {
    return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit transaction")
}

logging.InfoLogger.Printf("Upload completed: %s, file_id: %s by %s (size: %d bytes)", sessionID, fileID.String, username, actualStoredSize)
database.LogUserAction(username, "uploaded", fileID.String)
```

`LogUserAction` is post-commit and is NOT atomic with the commit. If the process dies between commit and `LogUserAction` (panic in the logger, OS-level kill), the user_activity row is missing. For audit purposes this is an integrity gap, but for "the upload succeeded for the user" it is acceptable.

Same pattern is present in `DeleteFile` (uploads.go:1088).

**Recommendation.** Include `LogUserAction` inside the transaction so atomicity is guaranteed. Or accept the gap and document that user_activity is best-effort. The right choice depends on how user_activity is consumed by billing (Slice E).

**Cross-refs.** Slice E (billing reads of user_activity).

---

### Finding C-27: `chunk_hash` in `upload_chunks` has no UNIQUE constraint per `(session_id, chunk_number)`; nothing in code prevents a chunk being re-uploaded with a different hash from the previous successful upload of the same chunk

- **Severity:** Informational
- **Confidence:** Medium
- **Category:** design
- **Component:** `handlers/uploads.go`
- **Affected files / functions:** `:658-661` (INSERT) plus inferred schema.

**Description.** `UploadChunk` issues a bare INSERT into `upload_chunks` without checking whether the same `(session_id, chunk_number)` pair already has a row. The schema (in `database/unified_schema.sql`, Slice E) likely has a UNIQUE constraint that would cause a re-upload to fail at the INSERT — but if not, re-uploads of the same chunk index in a single session would create multiple rows, and `CompleteUpload`'s `COUNT(*)` (uploads.go:790) would exceed `total_chunks`, causing a 400 "Not all chunks uploaded" mismatch in the wrong direction.

This is an Informational finding because the schema (which I did not deep-read) is the right place to defend, and Slice E will review the schema.

**Evidence.**

```go
// handlers/uploads.go:658-661
_, err = database.DB.Exec(
    "INSERT INTO upload_chunks (session_id, chunk_number, chunk_hash, chunk_size, etag) VALUES (?, ?, ?, ?, ?)",
    sessionID, chunkNumber, chunkHash, chunkSize, etag,
)
```

**Recommendation.** Verify in Slice E that `upload_chunks` has `UNIQUE (session_id, chunk_number)`. If not, add it. Also consider rejecting re-uploads at the handler with a clear 409 Conflict rather than relying on schema constraints.

**Cross-refs.** Slice E schema review.

---

## 3. Tables

### 3.1 Slice-C Endpoint Subset (feeds the full Slice E table)

All routes below are TOTP-gated (registered on `totpProtectedGroup` in `handlers/route_config.go:96-118`) unless noted.

| Endpoint | Auth | Authz rule | Sensitive inputs | Sensitive outputs | TOTP-gated? | Issues in this slice |
|---|---|---|---|---|---|---|
| `POST /api/uploads/init` | JWT | owner-only (creates own session); approval-required | encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, encrypted_fek, total_size, chunk_size, password_hint (cleartext), password_type | session_id, file_id, total_chunks, expires_at | **Yes** | C-09 (S3 metadata owner-username), C-15 (log username+file_id), C-16 (cap TOCTOU) |
| `POST /api/uploads/:sessionId/chunks/:chunkNumber` | JWT | owner-only on the session | encrypted chunk body, X-Chunk-Hash header | etag | **Yes** | C-01 (padding alloc), C-04 (X-Chunk-Hash unverified), C-10 (in-process hasher state), C-27 (no UNIQUE on chunk inserts) |
| `POST /api/uploads/:sessionId/complete` | JWT | owner-only | (none) | file_id, storage_id, encrypted_file_sha256, storage quota | **Yes** | C-07 (orphan window), C-26 (LogUserAction post-commit) |
| `GET /api/uploads/:sessionId/status` | JWT | owner-only | (none) | session status, chunks uploaded, progress | **Yes** | C-15 (logs include username/file_id chain) |
| `DELETE /api/uploads/:fileId` (CancelUpload) | JWT | owner-only | (none) | "Upload canceled successfully" | **Yes** | **C-05 (BROKEN: handler reads :sessionId, route declares :fileId)** |
| `GET /api/files` | JWT | owner-only | (none) | list of own files (encrypted metadata), storage quota | **Yes** | C-15 |
| `GET /api/files/metadata` | JWT | owner-only | limit, offset query params | recent files (encrypted metadata) | **Yes** | C-15 |
| `POST /api/files/metadata/batch` | JWT | owner-only | file_ids array | encrypted metadata by id + missing list | **Yes** | C-25 (no dedup) |
| `GET /api/files/:fileId/meta` | JWT | owner-only; approval-required | (none) | encrypted_filename/sha256/fek, password_hint, password_type, size, total_chunks | **Yes** | C-15 |
| `GET /api/files/:fileId/envelope` | JWT | owner-only (NO approval check) | (none) | encrypted_fek, password_type | **Yes** | C-12 (missing IsApproved) |
| `GET /api/files/:fileId/chunks/:chunkIndex` | JWT | owner-only; approval-required | (none) | encrypted chunk bytes (Content-Stream) | **Yes** | C-02, C-03, C-08, C-13, C-15 |
| `DELETE /api/files/:fileId` (DeleteFile) | JWT | owner-only | (none) | "File deleted successfully", storage quota | **Yes** | (deletion across providers is well-tested; no findings here) |
| `POST /api/files/:fileId/export-token` | JWT | owner-only | (none) | short-lived token | **Yes** | Slice E |
| `GET /api/files/:fileId/export?token=...` | TOKEN or JWT (in handler) | owner-only (resolved by `resolveExportAuth`) | token query param | encrypted backup blob | **NO** (registered on public router) | **Slice E should flag if the in-handler check is insufficient** |

### 3.2 Crypto operations on the wire (Slice C subset)

| Operation | Where | Primitive | AAD bound? | Tag verified before plaintext use? | Issues |
|---|---|---|---|---|---|
| Chunk encrypt (browser) | upload.ts:308-317 | AES-256-GCM (WebCrypto) | **No** | n/a (encrypt side) | C-02 |
| Chunk decrypt (browser) | streaming-download.ts:363 | AES-256-GCM (WebCrypto) | **No** | **Yes, before yield** | C-02 (no AAD allows reorder/substitution) |
| Metadata encrypt (browser) | upload.ts:326-345 | AES-256-GCM | **No** | n/a | C-19 (doc says AAD-bound, code is not) |
| Metadata decrypt (browser) | streaming-download.ts:560-569 | AES-256-GCM | **No** | Yes (tag check inside `decryptChunk`) | C-19 |
| FEK encrypt (browser) | upload.ts:596-612 | AES-256-GCM + 2-byte envelope prepend | **No** | n/a | Slice B `B-08` |
| Server-side streaming hash | uploads.go:580-594 | SHA-256 over received bytes | n/a | n/a | C-10 (in-process map only) |
| End-of-file plaintext SHA-256 verify | sw-streaming-download.ts:233-258 | SHA-256, constant-time compare | n/a | After all chunks streamed | C-13 (post-disk-write warning), C-14 (Blob path skips this) |
| `stored_blob_sha256sum` on download | (not performed) | n/a | n/a | n/a | C-08 |
| Per-chunk hash on upload (X-Chunk-Hash) | uploads.go:523-532, :660 | SHA-256 (client-supplied, server-stored) | n/a | **Never verified by server** | C-04 |

### 3.3 Server-visible metadata (Slice-C contribution to Slice G's matrix)

| Item | Visible to server (Go process)? | Visible to S3 backend? | Encrypted by client? | Authenticated (AAD)? | Notes |
|---|---|---|---|---|---|
| Filename | No (ciphertext only) | No (object body is ciphertext, key is UUID storage_id) | Yes (account-KEK) | **No** (C-19) | Slice B `B-08` documented; C-19 confirms doc-vs-code drift |
| Plaintext SHA-256 | No | No | Yes | No (C-19) | |
| Ciphertext SHA-256 (`encrypted_file_sha256sum`) | **Yes** (server-computed) | No (DB only) | No | n/a | By design — server-side anti-equivocation record |
| Stored blob SHA-256 (`stored_blob_sha256sum`) | **Yes** | No (DB only) | No | n/a | Includes padding bytes |
| File size (plaintext-equivalent) | **Yes** (`size_bytes` ≈ encrypted size; padding hides exact figure to within ~10%) | Yes (via `HeadObject` on the storage_id) | No | n/a | Cross-ref Slice B `B-06` (padding policy) |
| Padded size | **Yes** | Yes (S3 object's actual byte length) | No | n/a | |
| Chunk count, chunk size | **Yes** | No | No | n/a | C-03 (no AAD binds these) |
| FEK | No (always ciphertext) | No | Yes (wrapped under KEK) | **No** | Slice B `B-08`; C-23 (drift) |
| Owner username | **Yes** | **Yes** (in S3 user metadata) | No | n/a | C-09 (privacy regression) |
| Upload timestamp | **Yes** | Yes (S3 `LastModified`) | No | n/a | |
| Password hint | **Yes** (cleartext by design) | No (DB only) | No | n/a | By design |
| Password type byte | **Yes** | No (DB only) | No | n/a | |
| Multi-provider routing (which providers hold a copy) | **Yes** | n/a | No | n/a | Operator-side only |
| Per-chunk byte ranges | Derivable from `chunk_size_bytes` × `chunk_count` | n/a | No | **No** (C-03) | |

---

## 4. N/A items for this slice

`idsrp.md` items the Slice C scope is supposed to cover but that do not exist in Arkfile:

| Item | Justification |
|---|---|
| Folder hierarchy / nested folder ACLs | Arkfile is a flat per-user file space — no folders. Confirmed in `models/file.go` (no parent_id), `handlers/files.go` (no folder routes). |
| File versioning | No version chain; each upload is a new `file_id`. Re-uploads of the same plaintext are rejected client-side via `checkDuplicate` (upload.ts:578). |
| Trash / restore | `DeleteFile` is destructive (`DELETE FROM file_metadata` + `RemoveObject`); no soft-delete. |
| Thumbnails / previews / search index | Server never sees plaintext, so impossible. Slice B/D confirm. |
| Archive extraction (zip-slip) | Server does not extract archives. |
| SSRF on user-supplied URLs | Confirmed by grep: no handler accepts a URL parameter and fetches it. |
| Signed-URL hygiene | The `GetPresignedURL` interface method is implemented but unused — see C-17. |
| MIME sniffing problems on download | Server sets `Content-Type: application/octet-stream` unconditionally for chunks (downloads.go:119), exports (Slice E), and shares (Slice D). No MIME inference from content. |
| Content-Disposition for chunk endpoints | Chunks return `Content-Type: application/octet-stream` + `X-Chunk-*` headers for browser stream-assembly. Content-Disposition is set by the Service Worker on its synthetic Response, not by the Go handlers. |
| Range requests on the file-meta endpoint | The browser only Range-requests via `GetObjectChunk` to S3, mediated by Arkfile's own byte-range math. There is no `Range:` header support on `/api/files/:fileId/meta` (a JSON endpoint). |

---

## 5. Open questions / blocked-on-developer items

1. **Schema verification deferred to Slice E**: I did not deep-read `database/unified_schema.sql` for this slice. C-27 (UNIQUE on `upload_chunks`), C-16 (rqlite consistency level), and C-23/C-24 (dead code paths) all benefit from Slice E's schema review.
2. **Confirm `ADMIN_DEV_TEST_API_ENABLED=true` cannot be set in prod-deploy**: route_config.go:234 reads it from env; `scripts/prod-deploy.sh` should refuse to write `ADMIN_DEV_TEST_API_ENABLED=true` to the secrets file. Per `.clinerules` I cannot read the secrets file myself — please confirm.
3. **CLI parity for AAD changes (C-02)**: implementing C-02's recommendation requires matching changes in `cmd/arkfile-client/crypto_utils.go` and `commands.go`. Slice B's `B-05` and `B-08` Open Questions already flagged this.
4. **`docs/wip/folders-multi-upload-v2.md`** (the source of the AAD-bound claim in C-19) is out of scope for Slice C. Did the team decide to roll back the AAD design but forget to update `models/file.go`'s doc comment? Or is the AAD still planned and the implementation is just behind?
5. **The `ENABLE_UPLOAD_REPLICATION` config flag** (uploads.go:1108) — is replication enabled by default in production? If yes, C-08's "no chunk hash verify on fallback" is more pressing. If replication is opt-in and most operators run single-provider, C-08 is less urgent.
6. **`storage.GetPresignedURL`** (C-17) — is there a planned use case for it I missed in the WIP docs? If not, please confirm we can delete.

---

## 6. Testing gaps identified (feed into Slice G)

In priority order:

1. **Drop the `//go:build mock` tag on both chunked-upload test files** (`chunked_upload_integration_test.go`, `chunked_upload_100mb_test.go`). They are the only end-to-end coverage of the upload pipeline and are silently skipped under default `go test ./...` (see C-18).
2. **Chunk reorder negative test**: upload chunks in order 0..N successfully; on `CompleteUpload`, mutate DB to swap two chunk_numbers, download, assert browser detects mismatch BEFORE writing to disk. After C-02's fix, this should fail at the AEAD layer; before C-02's fix, it should fail at the end-of-file SHA-256 layer.
3. **Chunk replay negative test**: upload chunk N twice; verify either schema constraint or handler logic rejects the second upload with 409.
4. **`X-Chunk-Hash` mismatch negative test**: client sends a 64-hex value that does not match the chunk bytes; after C-04's fix, server should reject with 400.
5. **`CompleteUpload` orphan recovery**: simulate the tx.Begin failure window in C-07, run the reconciliation task (C-07 recommendation), assert orphaned S3 object is deleted.
6. **`CancelUpload` end-to-end**: covers C-05's broken route param mismatch.
7. **Padding-DoS guard**: synthetic test that uploads a final chunk whose `padded_size - total_size` is large, asserts the server's memory does not balloon beyond a fixed budget (C-01).
8. **Multi-provider fallback**: simulate primary failure on `GetObjectChunkWithFallback`, assert secondary serves the chunk AND that any divergence is logged/rejected (C-08).
9. **Per-user session-cap race**: two concurrent `/api/uploads/init` calls for the same user at cap-minus-1; assert at most 1 succeeds (C-16).
10. **Empty/oversized chunk body**: explicit tests for the `contentLength < minChunkSize` and `contentLength > maxChunkSize` paths in uploads.go:540-567.
11. **Browser SW path hash mismatch**: test that asserts `showWarning` is called when `hashVerification === 'mismatch'`. Currently the only TS tests for streaming-download cover the Blob fallback path (C-14).
12. **Browser Blob-fallback hash verification**: after C-14's fix, test that mismatched Blob is NOT handed to `triggerBrowserDownloadFromUrl`.
13. **6 GB on 3 GB RAM**: a memory-budgeted load test (Go side) using a synthetic 6 GB upload (perhaps with sparse-file techniques or stub readers) that asserts server-side peak heap < 1 GB. This is the AGENTS.md flagship constraint.
14. **`replicateToSecondary` cancellation** (C-11): submit replication, cancel its task via admin runner, assert the goroutine cooperatively exits within a deadline.
15. **`AdminContactsHandler` config-load failure path** (handlers/files.go:296-321): test the fallback-to-default-admin path explicitly; today only the happy path is exercised in `files_test.go`.

---

## 7. Hardening / non-vulnerability recommendations

Items that are not findings but are worth doing in roughly this order:

1. **AAD everywhere** (cross-slice): implement Slice B `B-05` and `B-08` recommendations and Slice C `C-02`/`C-03`/`C-19`. This is one cohesive change, not five. Add chunk-index, file-id, and field-name AAD to all metadata, FEK, and chunk encrypt/decrypt sites. Mirror in browser and CLI.
2. **Drop `owner-username` and `session-id` from S3 user metadata** (C-09). One-line change with high privacy value.
3. **Remove `GetPresignedURL` from the storage interface** (C-17). Eight-line deletion.
4. **Background incomplete-multipart-upload aborter** (C-06): scheduled task in `handlers/admin_task_runner.go` that calls `AbortMultipartUpload` for any `upload_sessions` row whose `status IN ('abandoned','canceled')` and whose `storage_upload_id IS NOT NULL`. Clears the storage cost leak.
5. **Background orphan reconciler** (C-07): periodic `ListObjects` on primary, cross-check against `file_metadata.storage_id`, delete unreferenced objects older than 1 hour.
6. **Pass `req.Context()` to `replicateToSecondary` instead of `context.Background()`** (C-11) — or route through the task runner. Caps unbounded goroutines.
7. **Fix `CancelUpload` route param** (C-05). One-line change with operational reliability impact.
8. **Persist the streaming hash state into the DB** (C-10) so server restarts don't drop uploads. Two extra `UPDATE` per chunk; cheap.
9. **Run the chunked-upload integration tests by default** (C-18, drop the `mock` build tag).
10. **Audit and tighten logging** (C-15): replace `username` with `EntityID(username)` in InfoLogger lines that also carry `file_id`. Slice E may revisit.
11. **Set bucket lifecycle and public-access-block on `CreateBucket`** (C-21).
12. **Refuse non-HTTPS endpoints for non-localhost backends** (C-22).
13. **Delete dead code paths**: `models/file.go:CreateFile` (C-23), `UpdatePasswordHint` (C-24), `chunked_upload_*` build tags drop (C-18).

---

## Severity summary

| Severity | Count | Findings |
|---|---:|---|
| Critical | 0 | — |
| High | 3 | C-01, C-02, C-03 |
| Medium | 10 | C-04, C-05, C-06, C-07, C-08, C-10, C-11, C-13, C-14, C-15, C-18 (11 total — recount below) |
| Low | 8 | C-09, C-12, C-16, C-17, C-19, C-20, C-21, C-22, C-23, C-24 (10 total — recount below) |
| Informational | 3 | C-25, C-26, C-27 |
| **Total** | **27** | |

Recount (single C-NN series, verified): C-01..C-27 = 27 findings.

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 3 (C-01, C-02, C-03) |
| Medium | 11 (C-04, C-05, C-06, C-07, C-08, C-10, C-11, C-13, C-14, C-15, C-18) |
| Low | 10 (C-09, C-12, C-16, C-17, C-19, C-20, C-21, C-22, C-23, C-24) |
| Informational | 3 (C-25, C-26, C-27) |
| **Total** | **27** |

Top three risks at the file/upload-download layer:

- **C-01 (High)** server-side padding allocation on the last chunk can OOM the server under concurrent large uploads.
- **C-02 / C-03 (High)** no AAD binds chunk index or file id to ciphertext; combined with server-trusted `chunk_size_bytes`, the server (or DB-write or storage-side attacker) can reorder/swap chunks. End-of-file SHA-256 detects, but only post-disk-write.
- **C-15 (Medium)** plaintext username + file_id are logged together at INFO level on every upload, download, chunk, and delete operation. Inconsistent with AGENTS.md "no PII" posture.
