# Chunked Upload and Download: TS and Go CLI Client Fixes Plan

## Status: PLAN - Pending Implementation

## Context

The e2e-test.sh (Go CLI to server) passes all tests (100 percent). The frontend TypeScript client needs fixes to match the working server API for encrypting files client-side and uploading them via the chunked upload API. Additionally, cryptocli needs to be updated to use streaming per-chunk encryption (no .enc temp files, no full-file memory buffering).

---

## Phase 1: Unified Chunking Constants (Single Source of Truth)

### Problem: Constants Are Scattered Across 9+ Locations

The same chunk size (16 * 1024 * 1024) is hardcoded in at least:
- crypto/gcm.go -> const ChunkSize
- models/file.go -> const DefaultChunkSizeBytes
- handlers/uploads.go -> inline 16 * 1024 * 1024 (2 places)
- handlers/files.go -> local const chunkSize
- handlers/file_shares.go -> inline (2 places)
- handlers/downloads.go -> uses DB value, no constant
- cmd/arkfile-client/main.go -> CLI default flag
- client/static/js/src/crypto/constants.ts -> DEFAULT_CHUNK_SIZE_BYTES

AES-GCM constants (nonce=12, tag=16) are similarly scattered with inline magic numbers.

Note: LIMITS.ENCRYPTION_CHUNK_SIZE in constants.ts is 64 * 1024 * 1024. This is distinct from DEFAULT_CHUNK_SIZE_BYTES (16 MiB). Decide whether to remove it or document it as intentionally different (streaming buffer limit). Preference is for it to be removed if it is not being used anywhere.

### Solution: Create crypto/chunking-params.json

Following the proven pattern of crypto/argon2id-params.json and crypto/password-requirements.json:

```json
{
  "plaintextChunkSizeBytes": 16777216,
  "envelope": {
    "version": 1,
    "headerSizeBytes": 2,
    "keyTypes": {
      "account": 1,
      "custom": 2
    }
  },
  "aesGcm": {
    "nonceSizeBytes": 12,
    "tagSizeBytes": 16,
    "keySizeBytes": 32
  }
}
```

Distribution pipeline (same as argon2id-params.json):

1. Go: //go:embed chunking-params.json in a new crypto/chunking_constants.go
   - All Go code references the embedded struct
   - Replace all 9+ hardcoded 16 * 1024 * 1024 with loaded value
2. API: GET /api/config/chunking -> new handler in handlers/config.go returns raw JSON
3. TS: loadChunkingConfig() in crypto/constants.ts fetches from API, caches in memory
   - Replace hardcoded DEFAULT_CHUNK_SIZE_BYTES, AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE

What is NOT in this file: Salt domain prefixes (arkfile-account-key-salt:, arkfile-custom-key-salt:) remain in their respective modules (crypto/key_derivation.go, client/static/js/src/crypto/file-encryption.ts). Each prefix appears in exactly one place per language and they already match.

### Implementation Steps

1. Create crypto/chunking-params.json
2. Create crypto/chunking_constants.go with //go:embed and GetEmbeddedChunkingParamsJSON()
3. Add GetChunkingConfig handler in handlers/config.go
4. Add route publicGroup.GET("/api/config/chunking", GetChunkingConfig) in handlers/route_config.go
5. Update crypto/constants.ts to fetch and cache from /api/config/chunking
6. Replace all hardcoded chunk and crypto constants across Go and TS with references to loaded values

---

## Phase 2: Unify the Two Go Envelope Implementations

### Problem: Two Competing FEK Envelope Formats in Go

There are currently two different Go functions that create encrypted FEK envelopes:

1. crypto/file_operations.go -> EncryptFEK() and DecryptFEK()
   - Format: [version(1)][keyType(1)][nonce+ciphertext+tag]
   - This is what the e2e test currently uses (via cryptocli)

2. crypto/envelope.go -> CreatePasswordKeyEnvelope() and ExtractFEKFromPasswordEnvelope()
   - Format: [version(1)][keyType(1)][salt(32)][nonce+ciphertext+tag]
   - Includes a 32-byte deterministic salt in the envelope (redundant since salt is derivable from username+keyType)

These produce incompatible encrypted FEK blobs. The server stores whatever encrypted_fek the client sends, so both could exist depending on which code path was used.

### Decision

Keep the simpler format from file_operations.go ([version][keyType][encrypted_fek] without redundant salt). This is what the working e2e test uses, and the salt is always derivable from username + keyType.

### Dead Code Removal: share Key Type (0x03) and Unused Salts

The share key type (0x03) exists in envelope.go and file_operations.go but is never used by the actual share system. The share system uses a different mechanism (random salt + AES-GCM-AAD via share_kdf.go). The DeriveSharePasswordKey function and the share salt prefix in TS file-encryption.ts are dead code.

Also remove unused FEKAccountSalt, FEKCustomSalt, and FEKShareSalt constants in key_derivation.go.

Per project policy: no unused code hanging around for potential future use.

### Implementation Steps

1. Remove dead share key type code:
   - crypto/envelope.go: remove KeyTypeShare = 0x03 constant and case branches
   - crypto/file_operations.go: remove case "share" and case 0x03 branches
   - crypto/key_derivation.go: remove DeriveSharePasswordKey() function
   - client/static/js/src/crypto/file-encryption.ts: remove share prefix from SALT_DOMAIN_PREFIXES
2. Remove competing envelope functions:
   - Remove CreatePasswordKeyEnvelope() and ExtractFEKFromPasswordEnvelope() from envelope.go
   - Keep KeyTypeAccount = 0x01 and KeyTypeCustom = 0x02 (will be sourced from chunking-params.json in Phase 1)
3. Remove unused FEKAccountSalt, FEKCustomSalt, FEKShareSalt constants in key_derivation.go
4. Verify no callers reference removed functions:
   - grep -r "CreatePasswordKeyEnvelope|ExtractFEKFromPasswordEnvelope|DeriveSharePasswordKey|KeyTypeShare|FEKAccountSalt|FEKCustomSalt|FEKShareSalt" --include="*.go" --include="*.ts"
5. Run dev-reset.sh with sudo, then run e2e-test.sh to confirm (must still pass 100 percent)

---

## Architecture Summary (Working Server API)

From handlers/uploads.go and handlers/route_config.go:

1. Init session: POST /api/uploads/init -> returns sessionId
2. Upload chunks: POST /api/uploads/{sessionId}/chunks/{chunkNumber} with raw binary body + X-Chunk-Hash header (SHA-256 hex of the encrypted chunk bytes)
3. Complete upload: POST /api/uploads/{sessionId}/complete (no JSON body)

### Server Chunk Validation (handlers/uploads.go)

- Chunk 0 must include 2-byte envelope header: minimum 31 bytes ([2-byte envelope][12-byte nonce][1+ byte ciphertext][16-byte tag])
- Chunks 1-N: minimum 29 bytes ([12-byte nonce][1+ byte ciphertext][16-byte tag])
- Maximum chunk size: 16 MiB + 2 bytes envelope overhead (chunk 0 only) + 28 bytes crypto overhead
- Each chunk's X-Chunk-Hash is verified server-side (SHA-256 of raw bytes received)
- Server computes a streaming hash of all encrypted chunk bytes
- On complete, chunks are stored via multipart upload to S3 or MinIO
- Client and server must hash the identical encrypted byte stream. The per-chunk X-Chunk-Hash and the final encrypted-file SHA-256 include the envelope header on chunk 0 and the raw nonce+ciphertext+tag bytes for all chunks. No envelope or header bytes should be stripped for hashing.

### Encrypted Chunk Format (Per-Chunk AES-GCM)

Both TS and Go CLI must produce chunks in this format:

- Chunk 0: [0x01][key_type][nonce (12)][ciphertext][tag (16)]
- Chunks 1-N: [nonce (12)][ciphertext][tag (16)]

Where:
- 0x01 = Version 1 (unified FEK-based encryption)
- key_type: 0x01 = account, 0x02 = custom
- Each chunk is encrypted independently with a unique random nonce
- Plaintext chunk size: 16 MiB (last chunk may be smaller)

### Metadata Encryption

Client encrypts metadata fields before upload:
- encrypted_filename + filename_nonce: AES-GCM encryption of original filename using account-derived key
- encrypted_sha256sum + sha256sum_nonce: AES-GCM encryption of original file SHA-256 hash using account-derived key
- encrypted_fek: FEK encrypted with password-derived KEK, prepended with 2-byte envelope header

The server stores nonces and encrypted data separately. Format: EncryptGCM produces [12-byte nonce][ciphertext + 16-byte tag]; the nonce is split off and stored as *_nonce, the remainder as encrypted_*.

---

## Cross-Platform Compatibility: Salt Derivation

Go and TS salt derivation already match. Both use the same approach:

Go (crypto/key_derivation.go):
```go
salt := sha256.Sum256([]byte(fmt.Sprintf("arkfile-%s-key-salt:%s", keyType, username)))
```

TS (file-encryption.ts):
```typescript
const SALT_DOMAIN_PREFIXES = {
  account: 'arkfile-account-key-salt:',
  custom: 'arkfile-custom-key-salt:',
};
// salt = SHA256(prefix + username).slice(0, 32)
```

Both produce SHA256("arkfile-{context}-key-salt:{username}") -> 32-byte salt. No fix needed.

Important: Go does not normalize username to lowercase. TS file-encryption.ts correctly uses username.trim() without lowercasing.

---

## Password Contexts (Account and Custom)

The upload system supports two password contexts for file encryption:

| Context | Salt Derivation | Use Case |
|---|---|---|
| account | Deterministic: SHA256("arkfile-account-key-salt:{username}") | Default - uses login password |
| custom | Deterministic: SHA256("arkfile-custom-key-salt:{username}") | User-chosen per-file password |

Note: The share context uses a different mechanism. Share passwords do not use DeriveSharePasswordKey or deterministic username-based salts. Instead, the share system:
1. Generates a random salt (via crypto.GenerateShareSalt())
2. Derives a key via Argon2id(share_password, random_salt)
3. Encrypts a Share Envelope ({fek, download_token} as JSON) with AES-GCM-AAD
4. AAD = share_id + file_id for context binding
5. The recipient uses the same random salt (retrieved from server) + share password to decrypt

The server CreateUploadSession only accepts password_type of account or custom. Share operations are handled by separate endpoints (/api/shares/*).

### Key Caching Behavior

- Account password: Argon2id runs once per session (estimated to take between 3 and 8 seconds in browser with curreng Argon2id configuration), then cached in sessionStorage. Subsequent encrypt or decrypt operations are instant.
- Custom password: Argon2id runs every time (3 to 8 seconds per operation). No caching by design.

### Upload Init Metadata Fields

The /api/uploads/init endpoint expects:
- encrypted_filename (base64)
- filename_nonce (base64)
- encrypted_sha256sum (base64)
- sha256sum_nonce (base64)
- encrypted_fek (base64)
- total_size (int, total encrypted bytes)
- chunk_size (int, e.g. 16777216)
- password_type: "account" or "custom"
- password_hint: optional string hint for custom passwords

---

## Phase 3: Fix Existing TS Upload Module

### Fix 1: API URL Paths and HTTP Methods in upload.ts

client/static/js/src/files/upload.ts already exists with full upload logic but uses wrong API paths and methods:

| What | Current (Wrong) | Correct |
|---|---|---|
| Init upload | /api/upload/init | /api/uploads/init |
| Upload chunk | PUT /api/upload/{sessionId}/chunk/{i} | POST /api/uploads/{sessionId}/chunks/{i} |
| Complete upload | /api/upload/{sessionId}/complete | /api/uploads/{sessionId}/complete |

Fixes needed:
- Change all /api/upload/ to /api/uploads/
- Change chunk path from /chunk/ to /chunks/
- Change chunk upload method from PUT to POST

### Fix 2: Chunk Upload Is Raw Binary, Not Multipart Form

The server UploadChunk handler expects:
- Raw binary body (the encrypted chunk bytes)
- X-Chunk-Hash header (SHA-256 hex of the chunk bytes)
- Content-Type: application/octet-stream

The TS client must not use FormData or multipart. It should send the chunk as a raw ArrayBuffer or Blob body with the hash header.

### Fix 3: Complete Upload Body

The POST /api/uploads/{sessionId}/complete endpoint has no JSON body. The server computes the encrypted file hash via streaming. The current TS code already sends no body; this is correct and needs no change.

### Fix 4: Chunk Hash Is SHA-256 of Encrypted Chunk Bytes

Each chunk's hash must be SHA-256 of the encrypted chunk bytes (including envelope on chunk 0, nonce, ciphertext, and tag). This is sent via the X-Chunk-Hash header.

### Fix 5: Per-Chunk Encryption (Not Whole-File-Then-Chunk)

The TS upload.ts already encrypts each plaintext chunk separately with AES-GCM. This is correct and matches the server's chunk validation expectations. Each chunk gets its own random nonce. Chunk 0 gets the 2-byte envelope prefix prepended.

### Fix 6: Envelope Key Type Byte Must Reflect Password Type

The TS upload.ts currently hardcodes ENVELOPE_TYPE_AES_GCM = 0x01 for all uploads. This means the envelope always writes [0x01, 0x01] regardless of password type. This is wrong for custom password uploads.

The envelope byte should be:
- [0x01, 0x01] for account password
- [0x01, 0x02] for custom password

Fix: Use the passwordType option to set the correct key_type byte in the envelope header.

### Fix 7: Ensure password_type Only Sends account or custom

The upload init request must not send share as password_type. Only account and custom are valid for file uploads.

### Fix 8: encrypted_fek Must Include the 2-Byte Envelope Header

During upload, the FEK is encrypted and sent as encrypted_fek. The TS client must prepend the 2-byte envelope header (version, key type) to encrypted_fek before base64 encoding. This matches crypto.EncryptFEK in Go.

---

## Phase 4: Verify TS Download Module

### Verify 1: Metadata Field Decryption Matches Server Storage Format

streaming-download.ts combines nonce + encrypted data as [nonce][encrypted] before decryption. This must match the server's storage format where nonce and ciphertext+tag are stored separately. The current implementation looks correct: it reconstructs [nonce][ciphertext+tag] which is the format AESGCMDecryptor.decryptChunk expects.

### Verify 2: Envelope Stripping on Chunk 0 (Critical)

When downloading chunks:
- The server returns raw byte ranges from the stored S3 object via DownloadFileChunk()
- Chunk 0 of the stored data includes the 2-byte envelope header: [0x01][key_type][nonce][ciphertext][tag]
- The TS AESGCMDecryptor.decryptChunk expects [nonce][ciphertext][tag] and does not strip the envelope

Fix needed: The download code must strip the 2-byte envelope header from chunk 0 before passing it to decryptChunk. For chunks 1-N, no stripping is needed.

### Verify 3: FEK Decryption Must Strip Envelope Header (Critical)

download.ts currently does:
```typescript
const encryptedFek = base64ToBytes(encryptedFekBase64);
const fek = await decryptChunk(encryptedFek, accountKey);
```

This assumes encrypted_fek is [nonce][ciphertext][tag]. But the server stores encrypted_fek with the 2-byte envelope header: [version(1)][keyType(1)][nonce(12)][ciphertext][tag(16)] (produced by crypto.EncryptFEK).

Fix needed: Strip the first 2 bytes (envelope header) from encryptedFek before passing to decryptChunk. The envelope header can also be used to determine the password context (account vs custom) for key derivation.

### Verify 4: Metadata Sources and Actual Endpoints

There are two distinct endpoints in the Go handlers:

- GET /api/files/:fileId/metadata (handlers/downloads.go -> GetFileDownloadMetadata) returns only chunking info: {file_id, size_bytes, chunk_count, chunk_size_bytes}. It does not include encrypted filename, encrypted sha256, or encrypted FEK.
- GET /api/files/:fileId/meta (handlers/files.go -> GetFileMeta) returns the encrypted metadata needed for client-side decryption: encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, encrypted_fek, password_type, and size info. It also computes chunk_size and total_chunks server-side.

The TS StreamingDownloadManager currently calls /api/files/:fileId/metadata and expects encryptedFilename, filenameNonce, encryptedSha256sum, sha256sumNonce, totalChunks, and chunkSizeBytes. That is a mismatch.

Action item: either (A) change the TS download path to call /api/files/:fileId/meta and update the expected response shape, or (B) expand /api/files/:fileId/metadata to include the encrypted fields and keep the TS path as-is. Option A aligns with current server routing. Also verify the share path: /api/public/shares/:id/metadata returns only size_bytes, chunk_count, chunk_size_bytes, while encrypted metadata for shares is returned by GetShareEnvelope and/or share list endpoints.

### Verify 5: Cross-Platform Test

Upload via Go CLI, download via TS client, then verify identical plaintext output.

---

## Phase 5: Update Cryptocli to Streaming Encrypt and Upload

### Goal

Update cryptocli so Go CLI users can encrypt and upload files streaming chunk-by-chunk, without holding the full plaintext or full encrypted file in memory. No .enc temp files are produced.

### Current Limitation

The current CLI workflow uses crypto.EncryptFileWorkflow which reads the entire file into memory, encrypts it as one AES-GCM blob, writes a .enc file, then arkfile-client upload reads the .enc file fully into memory and chunks it for transport. This is not scalable and wastes disk space.

### Critical: This Changes the Encrypted Data Format

Currently, cryptocli encrypt-file produces a single AES-GCM blob: [2-byte envelope][nonce][entire-file-ciphertext][tag]. The arkfile-client upload then splits this blob into transport chunks (raw byte ranges).

The new streaming model produces per-chunk encrypted data: each chunk is independently encrypted with its own nonce. These are different formats:

| Aspect | Old Format | New Format |
|---|---|---|
| Encryption granularity | Whole file = one AES-GCM operation | Per-chunk = one AES-GCM per 16 MiB |
| Nonces | 1 nonce for entire file | 1 nonce per chunk |
| Server storage | Raw byte ranges of one big blob | Per-chunk encrypted segments |
| Decryption | Need entire blob to decrypt | Can decrypt chunk-by-chunk |

Files uploaded with the old format cannot be decrypted with new format logic, and vice versa. Per AGENTS.md: no need to build backwards compatibility. A dev-reset.sh must be run to clear test data when switching.

Important note: The current e2e test works by accident because the server chunk validation only checks minimum sizes and hashes. It does not verify that each chunk is independently AES-GCM encrypted. The new streaming model makes the data format match the server's intended per-chunk design.

### Target Streaming Model

cryptocli will handle encryption and upload in a single streaming operation:

1. Generate FEK (random 32 bytes)
2. Compute plaintext SHA-256 of original file
3. Encrypt metadata (filename, SHA-256) with account-derived key (Metadata fields (filename, sha256sum) are always encrypted with the account-derived key. The password_type only governs FEK encryption and chunk encryption. This keeps file lists and metadata readable without requiring custom passwords.)
4. Encrypt FEK with password-derived KEK -> Owner Envelope (with 2-byte header)
5. Init upload session via POST /api/uploads/init with encrypted metadata
6. Stream-encrypt and upload chunks:
   - Read plaintext in 16 MiB chunks
   - Encrypt each chunk with FEK using AES-GCM (unique nonce per chunk)
   - Prepend 2-byte envelope header to chunk 0
   - Compute SHA-256 of each encrypted chunk
   - Upload each chunk immediately via POST /api/uploads/{sessionId}/chunks/{chunkNumber} with X-Chunk-Hash
7. Complete upload via POST /api/uploads/{sessionId}/complete

### Compatibility Guarantees

- Server already validates chunk hashes and computes streaming file hash
- Server already expects chunk 0 envelope header and per-chunk AES-GCM format
- This aligns with the TS client's per-chunk encryption path
- Both TS and Go CLI produce identical encrypted chunk formats

### Download (Streaming Decryption)

cryptocli download (new command) must also use streaming:
1. Download chunks via GET /api/files/{fileId}/chunks/{chunkIndex}
2. Strip 2-byte envelope from chunk 0
3. Decrypt each chunk independently (each has its own nonce)
4. Write plaintext streaming to output
5. No full encrypted file ever assembled in memory or on disk

### encrypted_fek Output Requirement

The new cryptocli upload command must output encrypted_fek (base64) to stdout or in JSON output. This is required because:
- The e2e test share operations need encrypted_fek to create share envelopes
- Currently, cryptocli encrypt-file outputs this value in its JSON metadata file
- The new cryptocli upload must provide it equivalently (for example, output a JSON summary on success that includes file_id and encrypted_fek)

---

## Phase 6: Update e2e-test.sh

Critical: Phase 5 and Phase 6 must ship atomically.

If Phase 5 changes cryptocli commands but Phase 6 is not updated simultaneously, the e2e test will break. These two phases must be implemented and committed together.

### Changes Required

1. Remove: cryptocli encrypt-file step (no more .enc file creation)
2. Replace with: a single cryptocli upload command that streams encrypt and upload
3. Remove: arkfile-client upload --file *.enc step
4. Update: download step to use cryptocli download (streaming decryption)
5. Remove: cryptocli decrypt-file step
6. Keep: all SHA-256 and content verification checks
7. Keep: all share operation tests (shares use the FEK from upload output)
8. Update: parse encrypted_fek from cryptocli upload output instead of from .enc.json metadata file
9. Run dev-reset.sh before testing (old encrypted data format is incompatible)

### Post-Update Verification

After Phase 5 and Phase 6, e2e-test.sh must pass 100 percent with all existing test phases:
- Phase 1-4: Auth (register, login, TOTP)
- Phase 5-7: Server checks and basic operations
- Phase 8: File operations (upload, download, verify) now using streaming crypto
- Phase 9: Share operations (uses encrypted_fek from upload output)
- Phase 10-11: Cleanup

---

## Phase 7: Wire Up UI

1. Connect fixed upload module to chunked-upload.html UI
2. Connect download module to file list UI in index.html
3. Add progress indicators for:
   - Key derivation (3 to 8 seconds, show spinner)
   - Per-chunk encryption and upload (show progress bar with chunk count)
   - Download and decryption (show progress bar)
4. Add custom password UI toggle

---

## Phase 8: Cross-Platform Testing

1. Upload file via TS client, download via Go CLI, verify identical
2. Upload file via Go CLI, download via TS client, verify identical
3. Test with various file sizes (small, exactly 16 MiB, multi-chunk, 50+ MB)
4. Test custom password: encrypt with custom password in TS, decrypt in Go CLI
5. Test error cases (network failure mid-upload, wrong password, wrong context)

---

## Constants Reference

All values sourced from crypto/chunking-params.json (after Phase 1) and crypto/argon2id-params.json:

| Constant | Value | Source |
|---|---|---|
| Chunk size (plaintext) | 16 MiB (16,777,216 bytes) | crypto/chunking-params.json |
| AES-GCM nonce | 12 bytes | crypto/chunking-params.json |
| AES-GCM tag | 16 bytes | crypto/chunking-params.json |
| AES-GCM key | 32 bytes | crypto/chunking-params.json |
| AES-GCM overhead per chunk | 28 bytes (nonce + tag) | Derived |
| Envelope version | 0x01 | crypto/chunking-params.json |
| Envelope header size | 2 bytes (chunk 0 only) | crypto/chunking-params.json |
| Key type: account | 0x01 | crypto/chunking-params.json |
| Key type: custom | 0x02 | crypto/chunking-params.json |
| Argon2id memory | 262,144 KiB (256 MiB) | crypto/argon2id-params.json |
| Argon2id time | 8 iterations | crypto/argon2id-params.json |
| Argon2id parallelism | 4 | crypto/argon2id-params.json |
| Key length | 32 bytes | crypto/argon2id-params.json |
| Salt length | 32 bytes | Fixed (SHA-256 output) |
| Salt domain (account) | arkfile-account-key-salt: | crypto/key_derivation.go |
| Salt domain (custom) | arkfile-custom-key-salt: | crypto/key_derivation.go |
| Salt algorithm | SHA-256 of {prefix}{username} | crypto/key_derivation.go |

Share-specific constants (separate system, not in chunking-params.json):

| Constant | Value | Source |
|---|---|---|
| Share salt | Random 32 bytes | crypto/share_kdf.go -> GenerateShareSalt() |
| Share KDF | Argon2id with same params as above | crypto/share_kdf.go (uses UnifiedArgonSecure) |
| Share envelope | JSON {fek, download_token} encrypted with AES-GCM-AAD | crypto/share_kdf.go |
| Share AAD | share_id + file_id (UTF-8 concatenation) | crypto/share_kdf.go -> CreateAAD() |

---

## Priority Order

1. Phase 1: Unified constants JSON (prerequisite for all other phases)
2. Phase 2: Unify Go envelope implementations (prerequisite for Phase 5)
3. Phase 3: Fix TS upload module - correct paths, methods, format
4. Phase 4: Verify TS download module - ensure cross-platform compatibility
5. Phase 5 and Phase 6 (atomic): Streaming cryptocli and update e2e tests
6. Phase 7: UI wiring - user-facing integration
7. Phase 8: Cross-platform testing - full validation

---

## Risk Assessment

| Phase | e2e-test.sh Risk | Notes |
|---|---|---|
| Phase 1 | Zero | Only changes where constants are sourced, not their values |
| Phase 2 | Low | Must verify EncryptFEK and DecryptFEK still produce same output |
| Phase 3 | Zero | TS-only changes; e2e test uses Go CLI exclusively |
| Phase 4 | Zero | TS-only verification and fixes |
| Phase 5 and 6 | High | Changes encrypted data format and CLI commands; must be atomic |
| Phase 7 | Zero | UI-only changes |
| Phase 8 | Zero | Testing only, no code changes |