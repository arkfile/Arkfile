# Unified arkfile-client: Streaming Crypto + Network CLI

## Status: PLANNING

## Context

Phases 1-4 of the chunking-ts-fixes refactor are complete. The TS client compiles cleanly with correct per-chunk encryption/decryption logic. The Go server is stable.

The current Go CLI workflow uses two separate tools:
- `cryptocli` -- pure crypto operations (encrypt, decrypt, key management, share envelopes)
- `arkfile-client` -- authenticated server communication (upload, download, share API calls)

This separation forces a multi-step workflow with `.enc` temp files and whole-file AES-GCM encryption. The whole-file format does not match the server's intended per-chunk AES-GCM design, and the `.enc` temp files double disk usage (unacceptable for large files up to 100 GB).

## Design Policies

### No Hardcoded Crypto/Chunking Values

All crypto parameters, chunking sizes, and password requirements MUST be sourced from
the centralized JSON config files via the `crypto` package's accessor functions. Never
use literal values in `arkfile-client` code.

| Parameter | Source | Accessor |
|---|---|---|
| Plaintext chunk size | `crypto/chunking-params.json` | `crypto.PlaintextChunkSize()` |
| AES-GCM overhead (nonce + tag) | `crypto/chunking-params.json` | `crypto.AesGcmOverhead()` |
| AES-GCM nonce size | `crypto/chunking-params.json` | `crypto.AesGcmNonceSize()` |
| AES-GCM tag size | `crypto/chunking-params.json` | `crypto.AesGcmTagSize()` |
| Envelope header size | `crypto/chunking-params.json` | `crypto.EnvelopeHeaderSize()` |
| Key type for context | `crypto/chunking-params.json` | `crypto.KeyTypeForContext("account"\|"custom")` |
| Argon2id params | `crypto/argon2id-params.json` | `crypto.UnifiedArgonSecure` (loaded at init) |
| Password min lengths | `crypto/password-requirements.json` | `crypto.GetPasswordRequirements()` |
| Password min entropy | `crypto/password-requirements.json` | `crypto.GetPasswordRequirements().MinEntropyBits` |

These JSON files are embedded at build time via `//go:embed`. The `arkfile-client` binary
imports the `crypto` package and gets all params automatically. No API calls needed.

**Forbidden patterns:**
```go
// WRONG - hardcoded values
chunkSize := 16777216
overhead := 28
nonceSize := 12

// RIGHT - use accessors
chunkSize := crypto.PlaintextChunkSize()
overhead := crypto.AesGcmOverhead()
nonceSize := crypto.AesGcmNonceSize()
```

### AAD (Additional Authenticated Data) Policy

Currently AAD is used only for share envelope encryption (`EncryptGCMWithAAD` / `DecryptGCMWithAAD`
with `CreateAAD(shareID, fileID)`). No changes to AAD scope in this refactor. Regular file
chunk encryption, FEK wrapping, and metadata encryption continue to use `EncryptGCM` / `DecryptGCM`
without AAD.

### Secure Password Entry

All password prompts MUST use `golang.org/x/term.ReadPassword()` which disables terminal echo.
Password byte slices MUST be zeroed immediately after use:

```go
import "golang.org/x/term"

password, err := term.ReadPassword(int(syscall.Stdin))
defer func() {
    for i := range password {
        password[i] = 0
    }
}()
// Derive key, then password is zeroed by defer
```

**Memory clearing rules:**
- Account password: zeroed after Argon2id derivation completes (account key goes to agent)
- Custom password: zeroed after custom key derivation completes
- Share password: zeroed after share key derivation completes
- FEK: zeroed after upload/download operation completes (not cached anywhere)
- Account key: the ONLY secret that persists (in the agent process memory)

### Password Strength Feedback (CLI)

After password entry, validate using `crypto.ValidatePasswordEntropy()` and display
results using ASCII-only indicators. No Unicode symbols or emoji.

**Strength labels** (from zxcvbn score 0-4):
```
Score 0: "VERY WEAK"
Score 1: "WEAK"
Score 2: "FAIR"
Score 3: "STRONG"
Score 4: "VERY STRONG"
```

**Example output (password not meeting requirements):**
```
Enter password:
Password strength: WEAK (score 1/4)
  [X] Length: 8/14 characters (need 6 more)
  [OK] Uppercase letter present
  [OK] Lowercase letter present
  [X] Missing: number (0-9)
  [X] Missing: special character
  [!] WARNING: Contains dictionary word - try something unique
  [!] Entropy too low (32.5 bits, need 60.0 bits)

Enter password (try again):
```

**Example output (password meeting requirements):**
```
Enter password:
Password strength: VERY STRONG (score 4/4)
  [OK] Length: 22/14 characters
  [OK] Uppercase letter present
  [OK] Lowercase letter present
  [OK] Number present
  [OK] Special character present
  [OK] Entropy: 89.3 bits (need 60.0 bits)

Confirm password:
```

Loop until requirements are met. Use the appropriate validator for context:
- `crypto.ValidateAccountPassword()` for account passwords
- `crypto.ValidateCustomPassword()` for custom file passwords
- `crypto.ValidateSharePassword()` for share passwords

### rqlite Data Format Reference

When reading from or writing to rqlite (via the server API), follow these conventions:

| Data Type | Storage Format | Go Encoding | Go Decoding |
|---|---|---|---|
| Binary blobs (keys, nonces, ciphertext) | Base64 string | `base64.StdEncoding.EncodeToString()` | `base64.StdEncoding.DecodeString()` |
| SHA-256 hashes | Hex string | `hex.EncodeToString()` | `hex.DecodeString()` |
| Booleans | Integer (0 or 1) | `0` / `1` in SQL | Cast to `bool` on read |
| Timestamps | ISO 8601 string | `time.Now().UTC().Format(time.RFC3339)` | `time.Parse(time.RFC3339, s)` |
| UUIDs | String | Direct string | Direct string |
| File sizes | Integer | Direct int64 | Direct int64 |

**Critical:** Always use parameterized queries, never string interpolation.
The JSON API responses from the server use base64 for binary data. When the CLI
receives these, decode with `base64.StdEncoding.DecodeString()` before passing
to crypto functions. When sending data to the server, encode with
`base64.StdEncoding.EncodeToString()`.

---

## Decision: Merge into Single `arkfile-client` Binary

`arkfile-client` becomes the unified CLI tool handling both crypto and network operations. `cryptocli` is removed as a separate binary.

### Rationale

1. **Streaming requires interleaving crypto and network**: encrypt chunk -> upload chunk -> next chunk. Two separate tools cannot do this without fragile pipe/IPC protocols.
2. **Disk efficiency**: No `.enc` temp files. A 100 GB file on a 200 GB disk would otherwise fill the disk.
3. **Memory efficiency**: Peak ~32 MiB (one plaintext chunk + one encrypted chunk). Works for any file size.
4. **The agent already holds key material**: The account key is cached in the agent process. The crypto boundary was already crossed.
5. **Simpler UX**: One command to upload, one command to download, one command to share.

---

## Command Reference (New)

```
arkfile-client register --username <user>
arkfile-client login --username <user>
arkfile-client upload --file <path> --username <user> [--password-type account|custom]
arkfile-client download --file-id <id> --output <path> --username <user>
arkfile-client list-files [--json]
arkfile-client share create --file-id <id>
arkfile-client share download --share-id <id> --output <path>
arkfile-client share list
arkfile-client share delete <id>
arkfile-client share revoke <id>
arkfile-client logout
arkfile-client agent start|stop|status
arkfile-client generate-test-file --filename <path> --size <bytes> --pattern deterministic
arkfile-client version
```

### Commands Removed

All `cryptocli` commands are absorbed into `arkfile-client`:
- `cryptocli encrypt-file` -> absorbed into `arkfile-client upload`
- `cryptocli decrypt-file` -> absorbed into `arkfile-client download`
- `cryptocli encrypt-metadata` -> absorbed into `arkfile-client upload`
- `cryptocli decrypt-metadata` -> absorbed into `arkfile-client download` and `list-files`
- `cryptocli create-share` -> absorbed into `arkfile-client share create`
- `cryptocli decrypt-share` -> absorbed into `arkfile-client share download`
- `cryptocli generate-test-file` -> kept as `arkfile-client generate-test-file`

---

## Upload Flow (Streaming Per-Chunk Encryption)

```
arkfile-client upload --file doc.pdf --username alice
```

### Internal Steps

1. **Load session** -- verify auth token is valid
2. **Get account key** -- from agent cache, or prompt for password + Argon2id derivation
3. **Pass 1: Compute plaintext SHA-256** -- stream-read the file in 16 MiB chunks, compute SHA-256 incrementally. Only ~16 MiB in memory at any point.
4. **Dedup check** -- retrieve digest cache from agent. Compare plaintext SHA-256 against cached digests. If match found:
   - Fetch file metadata for the matching file_id from server (`GET /api/files/{fileId}/meta`)
   - Decrypt filename with account key
   - Display: `Duplicate file detected. File with name <FILENAME> and matching plaintext SHA-256 digest <HASH> has been uploaded previously.`
   - Exit with non-zero status (no upload)
5. **Generate FEK** -- random 32 bytes
6. **Encrypt metadata** -- encrypt filename and SHA-256 with account key (AES-GCM, separate nonces)
7. **Encrypt FEK** -- encrypt FEK with account key, prepend 2-byte envelope header `[0x01][keyType]`
8. **Calculate total encrypted size** -- deterministic from plaintext file size + chunk params:
   - `numFullChunks = fileSize / plaintextChunkSize`
   - `lastChunkPlaintext = fileSize % plaintextChunkSize`
   - `totalEncrypted = numFullChunks * (plaintextChunkSize + 28) + (lastChunkPlaintext + 28) + 2`
   - The `+28` is AES-GCM overhead (12 nonce + 16 tag) per chunk, `+2` is envelope header on chunk 0
9. **Init upload** -- POST `/api/uploads/init` with encrypted metadata, encrypted_fek, total_size, chunk_size, password_type
10. **Pass 2: Stream encrypt + upload** -- seek to start of file, for each 16 MiB plaintext chunk:
    - Read plaintext chunk from file
    - Encrypt with FEK using AES-GCM (random nonce per chunk)
    - Chunk 0: prepend 2-byte envelope header
    - Compute SHA-256 of the encrypted chunk
    - POST `/api/uploads/{sessionId}/chunks/{chunkNumber}` with `X-Chunk-Hash` header
    - Discard encrypted chunk from memory
11. **Complete upload** -- POST `/api/uploads/{sessionId}/complete`
12. **Update digest cache** -- add new entry to agent: `{fileId: plaintextSHA256}`
13. **Output** -- print file_id, encrypted_fek (base64), and encrypted file SHA-256

### Custom Password Support

When `--password-type custom` is specified:
- Prompt for custom password (in addition to account password)
- Account key still used for metadata encryption (filename, sha256 -- keeps file lists readable)
- Custom password is Argon2id-derived into a Custom Key (KEK) used for FEK wrapping
- The envelope header key_type byte is set to 0x02 (custom)

### FEK vs KEK (Key Encryption Key) Architecture

The FEK (File Encryption Key) is ALWAYS a random 32-byte key generated via `crypto/rand`.
It is never derived from any password. The password-derived key is a KEK that wraps the FEK:

```
Account password flow:
  account_password --> Argon2id --> AccountKey (KEK, 32 bytes)
  FEK = crypto/rand (32 bytes)              <-- truly random
  encrypted_fek = AES-GCM(FEK, AccountKey)  <-- KEK wraps FEK
  each chunk = AES-GCM(plaintext, FEK)      <-- FEK encrypts file data

Custom password flow:
  custom_password --> Argon2id --> CustomKey (KEK, 32 bytes)
  FEK = crypto/rand (32 bytes)              <-- truly random (same as above)
  encrypted_fek = AES-GCM(FEK, CustomKey)   <-- KEK wraps FEK
  each chunk = AES-GCM(plaintext, FEK)      <-- FEK encrypts file data
```

This design enables:
- **File sharing** without re-encrypting the file (re-wrap FEK with share key)
- **Password changes** without re-encrypting all files (re-wrap FEKs with new KEK)
- **Per-file unique encryption** even if the same password is used for multiple files

---

## Download Flow (Streaming Per-Chunk Decryption)

```
arkfile-client download --file-id abc123 --output doc.pdf --username alice
```

### Internal Steps

1. **Load session** -- verify auth token
2. **Get account key** -- from agent cache or prompt
3. **Fetch metadata** -- GET `/api/files/{fileId}/meta` -> encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, encrypted_fek, password_type, chunk_count, chunk_size_bytes
4. **Decrypt FEK** -- strip 2-byte envelope header from encrypted_fek, determine key type. If account: decrypt with account key. If custom: prompt for custom password, derive custom key, decrypt.
5. **Decrypt metadata** -- decrypt filename and sha256 with account key (always account key, regardless of password_type)
6. **Display info** -- show filename, size, chunk count before downloading
7. **Stream download + decrypt** -- for each chunk:
   - GET `/api/files/{fileId}/chunks/{chunkIndex}`
   - Chunk 0: strip 2-byte envelope header
   - Decrypt with FEK (AES-GCM: extract nonce, decrypt ciphertext+tag)
   - Write plaintext to output file
8. **Verify SHA-256** -- compute SHA-256 of the written plaintext file, compare against decrypted sha256sum
9. **Output** -- print filename, file size, verification result

---

## Share Create Flow

```
arkfile-client share create --file-id abc123
```

### Internal Steps

1. **Load session** + **get account key**
2. **Fetch file metadata** -- GET `/api/files/{fileId}/meta`
3. **Decrypt metadata** -- decrypt filename, sha256 with account key
4. **Decrypt FEK** -- strip envelope, decrypt with account key (or custom key if custom password_type -- prompt if needed)
5. **Prompt for share password** -- interactive prompt, confirm
6. **Generate share ID** -- random UUID
7. **Generate download token** -- random bytes
8. **Generate share salt** -- random 32 bytes via `crypto.GenerateShareSalt()`
9. **Derive share key** -- Argon2id(share_password, share_salt)
10. **Build share envelope JSON**:
    ```json
    {
      "fek": "<base64-FEK>",
      "download_token": "<base64-download-token>",
      "filename": "doc.pdf",
      "size_bytes": 52428800,
      "sha256": "abcdef..."
    }
    ```
11. **Encrypt envelope** -- AES-GCM with share key, AAD = share_id + file_id
12. **Compute download token hash** -- SHA-256 of download token
13. **Create share** -- POST `/api/shares` with share_id, file_id, encrypted_envelope, salt, download_token_hash
14. **Output** -- print share_id, share URL, salt

---

## Share Download Flow

```
arkfile-client share download --share-id abc123 --output doc.pdf
```

### Internal Steps (No authentication required -- public endpoint)

1. **Get share envelope** -- GET `/api/public/shares/{shareId}/envelope` -> encrypted_envelope, salt
2. **Prompt for share password**
3. **Derive share key** -- Argon2id(share_password, salt)
4. **Decrypt envelope** -- AES-GCM with share key, AAD = share_id + file_id -> get FEK, download_token, filename, size_bytes, sha256
5. **Display info** -- show filename, size, sha256 digest before downloading
6. **Get chunk metadata** -- GET `/api/public/shares/{shareId}/metadata` -> chunk_count, chunk_size_bytes
7. **Stream download + decrypt** -- for each chunk:
   - GET `/api/public/shares/{shareId}/chunks/{chunkIndex}` with `X-Download-Token` header
   - Chunk 0: strip 2-byte envelope header
   - Decrypt with FEK
   - Write plaintext to output
8. **Verify SHA-256** -- compare against sha256 from envelope
9. **Output** -- print filename, size, sha256 digest, verification result

---

## Agent Extensions

### Current Agent Data

- `accountKey []byte` -- 32-byte AES key derived from account password via Argon2id

### New Agent Data

- `digestCache map[string]string` -- fileID -> plaintext SHA-256 hex digest

### New Agent Methods

| Method | Purpose |
|---|---|
| `store_digest_cache` | Bulk store after login (fetch + decrypt all file sha256 values) |
| `get_digest_cache` | Retrieve full cache for dedup check |
| `add_digest` | Add single entry after successful upload |
| `remove_digest` | Remove entry after file deletion |

### Digest Cache Lifecycle

1. **Login** -- after successful auth, fetch `/api/files`, decrypt each `encrypted_sha256sum` with account key, store map in agent
2. **Upload** -- after successful upload, call `add_digest` with new file_id + plaintext sha256
3. **Delete** -- after successful file deletion, call `remove_digest`
4. **Logout** -- `clear` wipes both account key and digest cache
5. **Agent restart** -- cache is empty, rebuilt on next login

### Security Properties (Unchanged)

- In-memory only (never written to disk)
- Unix domain socket with 0600 permissions
- UID-specific socket path
- Socket ownership validation before connection
- Secure memory clearing on clear/stop

---

## Deduplication

### CLI Behavior

Before encrypting and uploading, the client:
1. Computes SHA-256 of the plaintext file (pass 1)
2. Retrieves digest cache from agent
3. Compares against all cached digests
4. If match found:
   - Ask server to confirm encrypted file is still present and intact in backend storage system
   - Fetches encrypted metadata for the matching file from server
   - Decrypts filename with account key
   - Displays: `Duplicate file detected. File with name <FILENAME> and matching plaintext SHA-256 digest <HASH> has been uploaded previously.`
   - Exits with non-zero status
5. If no match: proceeds with encrypt + upload

No force-upload option. Duplicates are always blocked.

### TS Browser Behavior

Same dedup logic, using `sessionStorage` for the digest cache:
1. After login, fetch file list and decrypt sha256 values, cache in `sessionStorage`
2. Before upload, compute SHA-256 of selected file, check cache
3. Block upload if duplicate found, show message to user
4. Update cache after successful upload

---

## Encrypted Chunk Format (Per-Chunk AES-GCM)

Unchanged from current server expectations. Both TS and Go must produce:

- Chunk 0: `[0x01][key_type][nonce(12)][ciphertext][tag(16)]`
- Chunks 1-N: `[nonce(12)][ciphertext][tag(16)]`

Where:
- `0x01` = version 1
- `key_type`: `0x01` = account, `0x02` = custom
- Plaintext chunk size: 16 MiB (last chunk may be smaller)
- Each chunk encrypted independently with unique random nonce

---

## e2e-test.sh Changes

**NOTE: Do not start on any changes to e2e-test.sh until the full chunking-ts-fixes.md project is done. This is for reference only so we can return to it later and know what needs to be updated.**

### Current Flow (Multiple Tools)

```
cryptocli generate-test-file -> test_file.bin
cryptocli encrypt-file -> test_file.bin.enc + encrypted_fek
cryptocli encrypt-metadata -> nonces + encrypted values
manual: construct metadata.json
arkfile-client upload --file .enc --metadata metadata.json
arkfile-client download --file-id ... --output downloaded.enc
cryptocli decrypt-file --file downloaded.enc -> decrypted.bin
verify SHA-256 match

cryptocli create-share -> envelope, salt, token, token_hash
arkfile-client share create -> server stores share
arkfile-client download-share -> shared.enc
cryptocli decrypt-share -> shared_decrypted.bin
verify SHA-256 match
```

### New Flow (Single Tool)

```
arkfile-client generate-test-file -> test_file.bin (with SHA-256 output)
arkfile-client upload --file test_file.bin --username alice
  -> outputs file_id, encrypted_fek
arkfile-client download --file-id ... --output downloaded.bin --username alice
  -> outputs plaintext file + SHA-256 verification
verify SHA-256 match (should already be verified by download command)

arkfile-client share create --file-id ...
  -> outputs share_id, share_url
arkfile-client share download --share-id ... --output shared.bin
  -> outputs plaintext file + SHA-256 verification
verify SHA-256 match (should already be verified by share download command)
```

### Negative Tests (Keep)

- Wrong share password -> decrypt fails
- Wrong share ID in AAD -> decrypt fails
- Duplicate upload -> dedup blocks it (NEW test)

---

## Implementation Phases

### Phase A: Agent Extensions

1. Add `digestCache map[string]string` field to `Agent` struct
2. Add `store_digest_cache`, `get_digest_cache`, `add_digest`, `remove_digest` methods
3. Update `handleClear` to also zero and nil `digestCache`
4. Add corresponding `AgentClient` methods
5. Verify: agent start, store, retrieve, clear cycle works

### Phase B: Merge Crypto into arkfile-client

1. Move relevant crypto operations from cryptocli into arkfile-client's command handlers
2. The `crypto` package is already a dependency -- just call it directly
3. Key operations needed in arkfile-client:
   - `crypto.DeriveKeyFromPassword()` -- Argon2id key derivation
   - `crypto.EncryptGCM()` / `crypto.DecryptGCM()` -- AES-GCM encrypt/decrypt
   - `crypto.EncryptFEK()` / `crypto.DecryptFEK()` -- FEK envelope operations
   - `crypto.CreateShareEnvelope()` / `crypto.DecryptShareEnvelope()` -- share operations
   - `crypto.GenerateShareSalt()` -- random salt generation
   - `crypto.CreateAAD()` -- AAD for share envelope
4. Remove `cryptocli` binary target from build

### Phase C: Streaming Upload Command

1. Rewrite `handleUploadCommand`:
   - Accept plaintext file (not `.enc`)
   - No `--metadata` flag (metadata generated internally)
   - Add `--username` flag (for salt derivation)
   - Add `--password-type` flag (account or custom, default: account)
   - Implement two-pass: SHA-256 then encrypt+upload
   - Implement dedup check against agent digest cache
   - Output file_id and encrypted_fek
2. Remove `UploadMetadata` struct and metadata file parsing
3. Remove references to `.enc` files in help text and usage

### Phase D: Streaming Download Command

1. Rewrite `handleDownloadCommand`:
   - Output is plaintext (not encrypted)
   - Add `--username` flag
   - Decrypt FEK from metadata (strip envelope header)
   - Stream download chunks -> decrypt each -> write plaintext
   - Verify SHA-256 after completion
   - Remove `.metadata.json` sidecar file creation
2. Remove `ChunkDownloadMetadata` struct (use unified `/meta` response)

### Phase E: Share Commands

1. Rewrite `handleShareCreate`:
   - No longer needs `--encrypted-envelope`, `--salt`, `--download-token-hash` flags
   - Only needs `--file-id`
   - Fetches metadata, decrypts, builds envelope internally
   - Prompts for share password
2. Add `handleShareDownload` (replaces `handleDownloadShareCommand`):
   - Only needs `--share-id` and `--output`
   - Prompts for share password
   - Decrypts envelope, streams download+decrypt, verifies SHA-256
   - No `--download-token` flag needed (token comes from envelope)

### Phase F: Login Digest Cache Population

1. After successful login in `handleLoginCommand`:
   - Fetch `/api/files` (paginated if needed)
   - For each file, decrypt `encrypted_sha256sum` with account key
   - Store `{fileId: plaintextSHA256}` map in agent via `store_digest_cache`
2. Handle empty file list gracefully

### Phase G: Remove cryptocli

1. Delete `cryptocli` source files (identify location -- likely part of the build but separate from `cmd/arkfile-client/`)
2. Update `dev-reset.sh` build script to not build cryptocli
3. Update any documentation referencing cryptocli

### Phase H: TS Browser Dedup

1. After login, fetch file list and decrypt sha256 values
2. Cache in `sessionStorage`
3. Before upload, check cache for duplicate
4. Update cache after successful upload
5. Display duplicate message to user if match found

### Phase I: Update e2e-test.sh -- DO NOT ATTEMPT UNTIL CONFIRMED THAT chunking-ts-fixes.md PROJECT 100% DONE:

1. Replace all `cryptocli` invocations with `arkfile-client` commands
2. Remove `.enc` file steps
3. Remove `metadata.json` construction
4. Add dedup test (upload same file twice, verify rejection)
5. Update share workflow to use single-command create and download
6. Run `dev-reset.sh` then verify all tests pass

---

## Risk Assessment

| Phase | Risk | Notes |
|---|---|---|
| Phase A | Low | Agent extension, no behavior change to existing commands |
| Phase B | Low | Moving code, not changing logic |
| Phase C | High | Core upload rewrite, changes encrypted data format |
| Phase D | Medium | Download rewrite, must match upload format exactly |
| Phase E | Medium | Share commands change, envelope format already updated |
| Phase F | Low | New feature addition after login |
| Phase G | Medium | Must ensure nothing still references cryptocli |
| Phase H | Low | TS-only, independent of Go changes |
| Phase I | High | e2e test must be updated to match all code changes, but only after full refactor project done |

---

## Files Affected

### Modified
- `cmd/arkfile-client/main.go` -- major rewrite of upload, download, share commands
- `cmd/arkfile-client/agent.go` -- add digest cache support
- `scripts/dev-reset.sh` -- remove cryptocli build step
- `scripts/setup/build.sh` -- remove cryptocli build target
- `scripts/testing/e2e-test.sh` -- update all test phases (later)

### Deleted
- `cryptocli` source files (location TBD -- check build scripts)
- Any `.enc` / `.enc.json` references in scripts or docs

### New (Possible)
- `cmd/arkfile-client/crypto_ops.go` -- helper functions wrapping crypto package calls for upload/download/share operations (keeps main.go manageable)
- `cmd/arkfile-client/dedup.go` -- dedup check logic

### TS Changes (Phase I)
- `client/static/js/src/files/upload.ts` -- add dedup check before upload
- `client/static/js/src/utils/digest-cache.ts` -- new module for sessionStorage digest cache

---

## Parallelism-Ready Architecture

The streaming upload/download code should be structured to support future parallel
chunk operations. Even though Phase 1 (this refactor) is sequential, the architecture
should use Go channels and goroutines so that parallelism can be added later by
changing only the consumer/producer count.

### Go Upload Pipeline

```go
// Types for the pipeline
type PlaintextChunk struct {
    Index int
    Data  []byte
}

type EncryptedChunk struct {
    Index      int
    Data       []byte
    SHA256Hash string
}

// Phase 1 (this refactor): Sequential, channel-based
readChan := make(chan PlaintextChunk, 2)    // buffered for overlap
encChan  := make(chan EncryptedChunk, 2)    // buffered for overlap

go readChunks(file, readChan)               // producer: reads file sequentially
go encryptChunks(readChan, encChan, fek)    // transformer: encrypts each chunk
uploadChunksSequential(encChan, client)     // consumer: uploads one at a time

// Phase 2 (future): Parallel uploads -- only change the consumer
go uploadChunksParallel(encChan, client, workers=4)
```

### Go Download Pipeline

```go
// Phase 1: Sequential
chunkChan := make(chan EncryptedChunk, 2)
plainChan := make(chan PlaintextChunk, 2)

go downloadChunksSequential(client, fileID, chunkCount, chunkChan)
go decryptChunks(chunkChan, plainChan, fek)
writeChunks(plainChan, outputFile, sha256Hasher)

// Phase 2 (future): Parallel downloads
go downloadChunksParallel(client, fileID, chunkCount, chunkChan, workers=4)
```

### Key Design Rules for Parallelism Readiness

1. **Each chunk is self-contained**: carries its own index, data, and hash
2. **Chunks can arrive out of order**: writer must reassemble by index
3. **No shared mutable state**: each goroutine operates on its own chunk
4. **Channel-based communication**: producer -> transformer -> consumer
5. **Buffered channels**: allow pipeline stages to overlap (read while encrypting)
6. **Server already supports out-of-order chunks**: chunks stored by index, not arrival order

### TS Browser Parallel Readiness

Same principle for the TypeScript frontend:

```typescript
// Phase 1: Sequential upload
for (let i = 0; i < chunkCount; i++) {
    const plaintext = await readChunk(file, i);
    const encrypted = await encryptChunk(plaintext, fek, i);
    await uploadChunk(sessionId, i, encrypted);
}

// Phase 2 (future): Parallel upload with concurrency limit
const queue = new ChunkQueue(chunkCount, concurrency=4);
await queue.process(async (i) => {
    const plaintext = await readChunk(file, i);
    const encrypted = await encryptChunk(plaintext, fek, i);
    await uploadChunk(sessionId, i, encrypted);
});
```

Both Go and TS implementations should follow this same pattern: independent chunk
operations that can be dispatched to a worker pool without architectural changes.

---

## Privacy Preservation Checklist

- [x] Server never sees plaintext file contents (encrypted with FEK client-side)
- [x] Server never sees plaintext filename (encrypted with account key client-side)
- [x] Server never sees plaintext SHA-256 digest (encrypted with account key client-side)
- [x] Server never sees FEK (encrypted with account/custom key client-side)
- [x] Server never sees account password (OPAQUE protocol)
- [x] Server never sees share password (only salt stored; key derived client-side)
- [x] Dedup is fully client-side (server stores only encrypted sha256sum)
- [x] Digest cache is in-memory only (never written to disk)
- [x] Share envelope metadata is inside AES-GCM-AAD encryption (opaque to server)
- [x] Download token is inside encrypted envelope (server only stores SHA-256 hash)
