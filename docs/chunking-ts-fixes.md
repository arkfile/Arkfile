
# Chunked Upload/Download: TS & Go CLI Client Fixes Plan

## Status: PLAN — Pending Implementation

## Context

The e2e-test.sh (Go CLI → server) passes all tests. The frontend TypeScript client needs fixes to match the working server API for encrypting files client-side and uploading them via the chunked upload API. Additionally, `cryptocli` needs to be updated to use streaming per-chunk encryption (no `.enc` temp files, no full-file memory buffering).

---

## Architecture Summary (Working Server API)

From `handlers/uploads.go` and `handlers/route_config.go`:

1. **Init session**: `POST /api/uploads/init` → returns `sessionId`
2. **Upload chunks**: `POST /api/uploads/{sessionId}/chunks/{chunkNumber}` with raw binary body + `X-Chunk-Hash` header (SHA-256 hex of the encrypted chunk bytes)
3. **Complete upload**: `POST /api/uploads/{sessionId}/complete` (no JSON body)

### Server Chunk Validation (`handlers/uploads.go`)

- Chunk 0 must include 2-byte envelope header: minimum 31 bytes (`[2-byte envelope][12-byte nonce][1+ byte ciphertext][16-byte tag]`)
- Chunks 1-N: minimum 29 bytes (`[12-byte nonce][1+ byte ciphertext][16-byte tag]`)
- Maximum chunk size: 16 MiB + 2 bytes envelope overhead (chunk 0 only) + 28 bytes crypto overhead
- Each chunk's `X-Chunk-Hash` is verified server-side (SHA-256 of raw bytes received)
- Server computes a streaming hash of all encrypted chunk bytes
- On complete, chunks are stored via multipart upload to S3/MinIO

### Encrypted Chunk Format (Per-Chunk AES-GCM)

Both TS and Go CLI must produce chunks in this format:

- **Chunk 0**: `[0x01][key_type][nonce (12)][ciphertext][tag (16)]`
- **Chunks 1-N**: `[nonce (12)][ciphertext][tag (16)]`

Where:
- `0x01` = Version 1 (unified FEK-based encryption)
- `key_type`: `0x01` = account, `0x02` = custom
- Each chunk is encrypted independently with a unique random nonce
- Plaintext chunk size: 16 MiB (last chunk may be smaller)

### Metadata Encryption

Client encrypts metadata fields before upload:
- `encrypted_filename` + `filename_nonce`: AES-GCM encryption of original filename using account-derived key
- `encrypted_sha256sum` + `sha256sum_nonce`: AES-GCM encryption of original file's SHA-256 hash using account-derived key
- `encrypted_fek`: FEK encrypted with password-derived KEK, prepended with 2-byte envelope header

The server stores nonces and encrypted data separately. Format: `EncryptGCM` produces `[12-byte nonce][ciphertext + 16-byte tag]`; the nonce is split off and stored as `*_nonce`, the remainder as `encrypted_*`.

---

## Cross-Platform Compatibility: Salt Derivation ✅

**Go and TS salt derivation already match.** Both use the same approach:

**Go** (`crypto/key_derivation.go`):
```go
salt := sha256.Sum256([]byte(fmt.Sprintf("arkfile-%s-key-salt:%s", keyType, username)))
```

**TS** (`file-encryption.ts`):
```typescript
const SALT_DOMAIN_PREFIXES = {
  account: 'arkfile-account-key-salt:',
  custom: 'arkfile-custom-key-salt:',
  share: 'arkfile-share-key-salt:',
};
// salt = SHA256(prefix + username).slice(0, 32)
```

Both produce `SHA256("arkfile-{context}-key-salt:{username}")` → 32-byte salt. **No fix needed.**

**Important**: Go does NOT normalize username to lowercase. TS `file-encryption.ts` correctly uses `username.trim()` without lowercasing.

---

## Password Contexts (Account / Custom)

The upload system supports 2 password contexts:

| Context | Salt Prefix | Use Case |
|---|---|---|
| `account` | `arkfile-account-key-salt:{username}` | Default — uses login password |
| `custom` | `arkfile-custom-key-salt:{username}` | User-chosen per-file password |

**Note**: `share` is a separate workflow for share creation, not for file upload. The server's `CreateUploadSession` only accepts `password_type` of `account` or `custom`.

### Key Caching Behavior

- **Account password**: Argon2id runs once per session (~3-8 sec in browser), then cached in sessionStorage. Subsequent encrypt/decrypt operations are instant.
- **Custom password**: Argon2id runs **every time** (~3-8 sec per operation). No caching by design.

### Upload Init Metadata Fields

The `/api/uploads/init` endpoint expects:
- `encrypted_filename` (base64)
- `filename_nonce` (base64)
- `encrypted_sha256sum` (base64)
- `sha256sum_nonce` (base64)
- `encrypted_fek` (base64)
- `total_size` (int, total encrypted bytes)
- `chunk_size` (int, e.g. 16777216)
- `password_type`: `"account"` | `"custom"`
- `password_hint`: Optional string hint for custom passwords

---

## Existing TS Code: What Needs Fixing

### Fix 1: API URL Paths and HTTP Methods in `upload.ts`

`client/static/js/src/files/upload.ts` already exists with full upload logic but uses **wrong API paths and methods**:

| What | Current (WRONG) | Correct |
|------|-----------------|---------|
| Init upload | `/api/upload/init` | `/api/uploads/init` |
| Upload chunk | `PUT /api/upload/{sessionId}/chunk/{i}` | `POST /api/uploads/{sessionId}/chunks/{i}` |
| Complete upload | `/api/upload/{sessionId}/complete` | `/api/uploads/{sessionId}/complete` |

**Fixes needed:**
- Change all `/api/upload/` to `/api/uploads/`
- Change chunk path from `/chunk/` to `/chunks/`
- Change chunk upload method from `PUT` to `POST`

### Fix 2: Chunk Upload Is Raw Binary, Not Multipart Form

The server's `UploadChunk` handler expects:
- **Raw binary body** (the encrypted chunk bytes)
- `X-Chunk-Hash` header (SHA-256 hex of the chunk bytes)
- `Content-Type: application/octet-stream`

The TS client must NOT use `FormData` or multipart. It should send the chunk as a raw `ArrayBuffer`/`Blob` body with the hash header.

### Fix 3: Remove `file_hash` from Complete Upload

The `POST /api/uploads/{sessionId}/complete` endpoint has **no JSON body**. The server computes the encrypted file hash via streaming. Do not send `file_hash` or any other fields in the complete request.

### Fix 4: Chunk Hash Is SHA-256 of Encrypted Chunk Bytes

Each chunk's hash must be SHA-256 of the **encrypted chunk bytes** (including envelope on chunk 0, nonce, ciphertext, and tag). This is sent via the `X-Chunk-Hash` header.

### Fix 5: Per-Chunk Encryption (Not Whole-File-Then-Chunk)

The TS `upload.ts` already encrypts **each plaintext chunk separately** with AES-GCM. This is the correct approach and matches the server's chunk validation expectations. Each chunk gets its own random nonce. Chunk 0 gets the 2-byte envelope prefix prepended.

---

## Cryptocli Streaming Encryption (No `.enc` Files, No Full-File Memory)

### Goal

Update `cryptocli` so Go CLI users can encrypt and upload files **streaming chunk-by-chunk**, without ever holding the full plaintext or full encrypted file in memory. No `.enc` temp files are produced.

### Current Limitation

The current CLI workflow uses `crypto.EncryptFileWorkflow` which reads the **entire file** into memory, encrypts it as one AES-GCM blob, writes a `.enc` file, then `arkfile-client upload` reads the `.enc` file fully into memory and chunks it for transport. This is not scalable and wastes disk space.

### Target Streaming Model

`cryptocli` will handle encryption AND upload in a single streaming operation:

1. **Generate FEK** (random 32 bytes)
2. **Compute plaintext SHA-256** by streaming the file once
3. **Encrypt metadata** (filename, SHA-256) with account-derived key
4. **Encrypt FEK** with password-derived KEK → Owner Envelope
5. **Init upload session** via `POST /api/uploads/init` with encrypted metadata
6. **Stream-encrypt and upload chunks**:
   - Read plaintext in 16 MiB chunks
   - Encrypt each chunk with FEK using AES-GCM (unique nonce per chunk)
   - Prepend 2-byte envelope header to chunk 0
   - Compute SHA-256 of each encrypted chunk
   - Upload each chunk immediately via `POST /api/uploads/{sessionId}/chunks/{chunkNumber}` with `X-Chunk-Hash`
7. **Complete upload** via `POST /api/uploads/{sessionId}/complete`

### Compatibility Guarantees

- Server already validates chunk hashes and computes streaming file hash
- Server already expects chunk 0 envelope header and per-chunk AES-GCM format
- This aligns with the TS client's per-chunk encryption path
- Both TS and Go CLI produce identical encrypted chunk formats

### Download (Streaming Decryption)

`cryptocli decrypt-file` must also switch to streaming:
1. Download chunks via `GET /api/files/{fileId}/chunks/{chunkIndex}`
2. Parse 2-byte envelope from chunk 0
3. Decrypt each chunk independently (each has its own nonce)
4. Write plaintext streaming to output
5. No full encrypted file ever assembled in memory or on disk

### Changes to e2e-test.sh

The e2e test must be updated to reflect the new streaming workflow:
- **Remove**: `cryptocli encrypt-file` step (no more `.enc` file creation)
- **Replace with**: A single `cryptocli upload` command that streams encrypt+upload
- **Remove**: `arkfile-client upload --file *.enc` step
- **Update**: Download step to use streaming decryption
- **Keep**: All SHA-256 and content verification checks
- **Keep**: All share operation tests (unchanged)

---

## Download Flow (TS Client)

The TS `streaming-download.ts` already exists and handles chunked downloads. It uses:
- `GET /api/files/{fileId}/metadata` — chunk count, sizes
- `GET /api/files/{fileId}/chunks/{chunkIndex}` — individual encrypted chunk data

The download module:
1. Fetches metadata (chunk count, sizes, encrypted filename/SHA-256/nonces)
2. Downloads each encrypted chunk
3. Decrypts each chunk independently using FEK via `AESGCMDecryptor.decryptChunk`
4. Decrypts filename and SHA-256 from metadata using FEK
5. Combines decrypted chunks and triggers browser download

**Potential issue to verify**: `decryptMetadataField` in `streaming-download.ts` combines nonce + encrypted data as `[nonce][encrypted]` before decryption. This must match the server's storage format where nonce and ciphertext+tag are stored separately.

---

## Constants Reference

| Constant | Value | Source |
|---|---|---|
| Chunk size (plaintext) | 16 MiB (16,777,216 bytes) | `crypto/constants.ts`, `handlers/uploads.go` |
| AES-GCM nonce | 12 bytes | Both |
| AES-GCM tag | 16 bytes | Both |
| AES-GCM overhead per chunk | 28 bytes (nonce + tag) | Both |
| Envelope header | 2 bytes (chunk 0 only) | Both |
| Argon2id memory | 262,144 KiB (256 MiB) | `crypto/argon2id-params.json` |
| Argon2id time | 8 iterations | `crypto/argon2id-params.json` |
| Argon2id parallelism | 4 | `crypto/argon2id-params.json` |
| Key length | 32 bytes | `crypto/argon2id-params.json` |
| Salt length | 32 bytes | Both |
| Salt domain (account) | `arkfile-account-key-salt:` | Both Go and TS ✅ |
| Salt domain (custom) | `arkfile-custom-key-salt:` | Both Go and TS ✅ |
| Salt domain (share) | `arkfile-share-key-salt:` | Both Go and TS ✅ |
| Salt algorithm | SHA-256 of `{prefix}{username}` | Both Go and TS ✅ |

---

## Implementation Plan

### Phase 1: Fix Existing TS Upload Module

1. Fix API paths in `client/static/js/src/files/upload.ts`:
   - `/api/upload/init` → `/api/uploads/init`
   - `/api/upload/${sessionId}/chunk/${i}` → `/api/uploads/${sessionId}/chunks/${i}`
   - `/api/upload/${sessionId}/complete` → `/api/uploads/${sessionId}/complete`
2. Fix HTTP method: chunk upload from `PUT` to `POST`
3. Fix chunk upload format: raw binary body + `X-Chunk-Hash` header (not multipart form)
4. Remove any `file_hash` from complete upload request body
5. Ensure per-chunk encryption with envelope on chunk 0
6. Ensure `password_type` only sends `account` or `custom` (not `share`)

### Phase 2: Verify TS Download Module

1. Verify `streaming-download.ts` metadata field decryption matches server storage format
2. Verify per-chunk decryption handles envelope stripping on chunk 0
3. Test cross-platform: upload via Go CLI, download via TS client

### Phase 3: Update Cryptocli to Streaming Encrypt+Upload

1. Create new `cryptocli upload` command that:
   - Reads plaintext file streaming
   - Computes SHA-256 of plaintext (streaming)
   - Encrypts metadata, FEK
   - Calls `/api/uploads/init`
   - Encrypts each 16 MiB chunk with FEK (per-chunk AES-GCM)
   - Uploads each chunk immediately with `X-Chunk-Hash`
   - Calls `/api/uploads/{sessionId}/complete`
2. Create new `cryptocli download` command that:
   - Downloads chunks via API
   - Decrypts each chunk streaming
   - Writes plaintext to stdout or file
3. Remove old `encrypt-file` / `decrypt-file` commands (no `.enc` files)
4. Update `encrypt-metadata` and `decrypt-metadata` to work with the new flow

### Phase 4: Update e2e-test.sh

1. Replace `cryptocli encrypt-file` + `arkfile-client upload` with `cryptocli upload`
2. Replace `arkfile-client download` + `cryptocli decrypt-file` with `cryptocli download`
3. Keep all verification checks (SHA-256, content match, share operations)
4. Ensure all tests still pass

### Phase 5: Wire Up UI

1. Connect fixed upload module to `chunked-upload.html` UI
2. Connect download module to file list UI in `index.html`
3. Add progress indicators for:
   - Key derivation (~3-8 sec, show spinner)
   - Per-chunk encryption + upload (show progress bar with chunk count)
   - Download + decryption (show progress bar)
4. Add custom password UI toggle

### Phase 6: Cross-Platform Testing

1. Upload file via TS client, download via Go CLI → verify identical
2. Upload file via Go CLI, download via TS client → verify identical
3. Test with various file sizes (small, exactly 16 MiB, multi-chunk, 50+ MB)
4. Test custom password: encrypt with custom password in TS, decrypt in Go CLI
5. Test error cases (network failure mid-upload, wrong password, wrong context)

---

## Priority Order

1. **Fix TS upload module** — Correct paths, methods, format (Phase 1)
2. **Verify TS download module** — Ensure cross-platform compatibility (Phase 2)
3. **Streaming cryptocli** — No `.enc` files, no full-file memory (Phase 3)
4. **Update e2e tests** — Ensure no regressions (Phase 4)
5. **UI wiring** — User-facing integration (Phase 5)
6. **Cross-platform testing** — Full validation (Phase 6)

---