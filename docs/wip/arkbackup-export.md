# Arkfile Backup Export & Offline Decryption

## Overview

This feature enables users to export encrypted files as self-contained `.arkbackup` bundles that can be decrypted offline using only `arkfile-client`, a username, and a password. No network access to the Arkfile server is required for decryption.

**Use cases:**
- Disaster recovery: server is down, user has a backup bundle from before
- Offline verification: admin or user wants to prove a file is intact and decryptable
- E2E testing: verify the full encryption/decryption pipeline end-to-end against raw S3 blobs
- Compliance: demonstrate that encrypted data is recoverable by the data owner

---

## `.arkbackup` Bundle Format

A single concatenated binary file containing all metadata needed for offline decryption plus the raw encrypted blob (including padding).

### Binary Layout

```
Offset    Size        Field                Description
──────    ────        ─────                ───────────
0         4 bytes     Magic                ASCII "ARKB" (0x41 0x52 0x4B 0x42)
4         2 bytes     Version              uint16 big-endian (currently 1)
6         4 bytes     Header Length        uint32 big-endian (byte length of JSON metadata)
10        N bytes     JSON Metadata        UTF-8 encoded JSON (no trailing newline)
10+N      remainder   Encrypted Blob       Raw S3 object bytes (encrypted chunks + padding)
```

### JSON Metadata Schema (Version 1)

```json
{
  "version": 1,
  "file_id": "3520a121-f6bc-4e1d-bdf5-a85a69381014",
  "encrypted_fek": "AQHxyz...base64...",
  "password_type": "account",
  "size_bytes": 52428914,
  "padded_size": 53482905,
  "encrypted_filename": "base64...",
  "filename_nonce": "base64...",
  "encrypted_sha256sum": "base64...",
  "sha256sum_nonce": "base64...",
  "chunk_size_bytes": 16777216,
  "chunk_count": 4,
  "envelope_version": 1,
  "created_at": "2026-04-08T10:44:32Z"
}
```

**Field descriptions:**

| Field | Source | Purpose |
|---|---|---|
| `version` | Constant | Bundle format version for forward compatibility |
| `file_id` | `file_metadata.file_id` | Unique file identifier |
| `encrypted_fek` | `file_metadata.encrypted_fek` | Base64-encoded wrapped FEK (2-byte envelope header + AES-GCM encrypted 32-byte key) |
| `password_type` | `file_metadata.password_type` | `"account"` or `"custom"` — determines which key unwraps the FEK |
| `size_bytes` | `file_metadata.size_bytes` | Encrypted data size (without padding). Used to know where real data ends |
| `padded_size` | `file_metadata.padded_size` | Total S3 object size including padding. For integrity verification |
| `encrypted_filename` | `file_metadata.encrypted_filename` | Base64-encoded AES-GCM ciphertext of original filename |
| `filename_nonce` | `file_metadata.filename_nonce` | Base64-encoded 12-byte nonce for filename decryption |
| `encrypted_sha256sum` | `file_metadata.encrypted_sha256sum` | Base64-encoded AES-GCM ciphertext of plaintext file SHA-256 hex |
| `sha256sum_nonce` | `file_metadata.sha256sum_nonce` | Base64-encoded 12-byte nonce for SHA-256 decryption |
| `chunk_size_bytes` | `file_metadata.chunk_size_bytes` | Plaintext chunk size used during encryption (typically 16 MiB) |
| `chunk_count` | `file_metadata.chunk_count` | Number of encrypted chunks |
| `envelope_version` | Parsed from `encrypted_fek[0]` | Envelope format version (currently 1) |
| `created_at` | `file_metadata.created_at` | Timestamp of original upload |

---

## Server-Side: Export Endpoint

### `GET /api/files/:fileId/export`

**Authentication:** JWT (user must own the file)

**Response:** Streaming binary `.arkbackup` file

**Headers:**
```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="<file_id>.arkbackup"
Content-Length: <total bundle size>
```

**Implementation:** `handlers/export.go`

```
1. Authenticate user, verify file ownership
2. Read file_metadata row from rqlite
3. Build JSON metadata from DB fields
4. Calculate total size: 10 (fixed header) + len(JSON) + padded_size
5. Set Content-Length header
6. Write 4-byte magic "ARKB"
7. Write 2-byte version (1, big-endian)
8. Write 4-byte header length (big-endian)
9. Write JSON metadata bytes
10. Stream S3 object to response (full blob including padding)
```

**Memory usage:** O(1) — the blob is streamed directly from S3 to the HTTP response. Only the JSON metadata (~500 bytes) is buffered.

**Error handling:**
- 404 if file not found or not owned by user
- 500 if S3 read fails (with cleanup)

### `GET /api/admin/files/:fileId/export` (Optional)

Same behavior but accessible by admin for any user's file. For disaster recovery when the user cannot log in.

### Route Registration

In `handlers/route_config.go`:
```go
files.GET("/:fileId/export", handlers.ExportFile)
// Optional admin route:
admin.GET("/files/:fileId/export", handlers.AdminExportFile)
```

---

## Client-Side: Export Command

### `arkfile-client export`

Downloads a `.arkbackup` bundle from the server.

```bash
arkfile-client export --file-id <uuid> --output myfile.arkbackup
```

**Implementation:** `cmd/arkfile-client/export.go`

```
1. Call GET /api/files/<fileId>/export with auth token
2. Stream response body to --output file
3. Print: "Exported <file_id> to myfile.arkbackup (<size> bytes)"
```

This is a thin wrapper around the server endpoint. Requires an active authenticated session.

---

## Key Hierarchy & Password Requirements

Understanding which passwords are needed for decryption:

**Metadata (filename, SHA-256 hash):** Always encrypted with the **account key** (derived from the user's account password via Argon2id), regardless of password type. This means the account password is ALWAYS required for full decryption with verification.

**FEK (File Encryption Key):** Wrapped with either:
- **Account key** (if `password_type` = `"account"`) — same key used for metadata
- **Custom KEK** (if `password_type` = `"custom"`) — derived from a separate custom password via Argon2id

**File data chunks:** Always encrypted with the FEK.

| Password Type | To decrypt metadata | To unwrap FEK | To decrypt file data | Passwords needed |
|---|---|---|---|---|
| `"account"` | Account password | Account password (same) | FEK (from unwrap) | **1 password** |
| `"custom"` | Account password | Custom file password | FEK (from unwrap) | **2 passwords** |

---

## Client-Side: Offline Decrypt Command

### `arkfile-client decrypt-blob`

Decrypts a `.arkbackup` bundle using only local computation. No network required.

**Usage — account-password file (interactive):**
```bash
arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --username "myuser" \
  --output decrypted-file.dat
# Prompts: "Enter your account password: " (no echo)
```

**Usage — custom-password file (interactive):**
```bash
arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --username "myuser" \
  --output decrypted-file.dat
# Prompts: "Enter your account password: " (no echo)
# Then:    "Enter the custom file password: " (no echo)
```

The tool reads `password_type` from the bundle metadata and prompts accordingly. For `"account"` files, one prompt. For `"custom"` files, two prompts.

**Usage (stdin passwords for automation):**
```bash
# Account-password file: one password on stdin
echo "$ACCOUNT_PASSWORD" | arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --username "myuser" \
  --password-stdin \
  --output decrypted-file.dat

# Custom-password file: two passwords on stdin (one per line)
printf "%s\n%s\n" "$ACCOUNT_PASSWORD" "$FILE_PASSWORD" | arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --username "myuser" \
  --password-stdin \
  --output decrypted-file.dat
```

When `--password-stdin` is used with a custom-password file, the tool reads two lines from stdin: first the account password, then the file password.

**Usage (account key from file, no account password needed):**
```bash
arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --account-key-file /path/to/key.hex \
  --output decrypted-file.dat
# For custom-password files, still prompts: "Enter the file password: "
```

**Usage (account key from running agent):**
```bash
arkfile-client decrypt-blob \
  --bundle myfile.arkbackup \
  --use-agent \
  --output decrypted-file.dat
# For custom-password files, still prompts: "Enter the file password: "
```

### Password Handling Rules

- **Passwords are NEVER accepted as command-line arguments.** They would be visible in shell history, `ps` output, and `/proc/<pid>/cmdline`.
- Interactive prompt uses `golang.org/x/term` `ReadPassword()` (no terminal echo).
- `--password-stdin` reads one line from stdin (for piped automation, same pattern as `docker login --password-stdin`).
- `--account-key-file` reads a hex-encoded 32-byte key from a `chmod 600` file.
- `--use-agent` reads the cached account key from the running arkfile-client agent.

### Decryption Algorithm

**Implementation:** `cmd/arkfile-client/offline_decrypt.go`

```
Step 1: Parse Bundle
  - Open bundle file
  - Read and validate magic bytes ("ARKB")
  - Read version (must be 1)
  - Read header length (uint32 big-endian)
  - Read and parse JSON metadata

Step 2: Obtain Account Key
  - If --account-key-file: read hex key from file
  - If --use-agent: read from agent Unix socket
  - If --password-stdin: read first line as account password
  - Otherwise: prompt "Enter your account password: " interactively (no echo)
  - Derive account key: argon2id(password, sha256(username), params)
    - Parameters from crypto/argon2id-params.json
    - Salt = SHA-256(username) truncated to configured salt length

Step 3: Unwrap FEK
  - Base64-decode encrypted_fek from metadata
  - Strip 2-byte envelope header [version][keyType]
  - Verify keyType matches password_type ("account"=0x01, "custom"=0x02)
  - If password_type = "account":
    - Decrypt with account key via AES-256-GCM → 32-byte FEK
  - If password_type = "custom":
    - If --password-stdin: read second line as custom file password
    - Otherwise: prompt "Enter the file password: " interactively (no echo)
    - Derive custom KEK: argon2id(custom_password, sha256(username), params)
    - Decrypt with custom KEK via AES-256-GCM → 32-byte FEK

Step 4: Decrypt File Data
  - Seek to blob offset in bundle (10 + header_length)
  - Read exactly size_bytes of encrypted data (ignore padding beyond)
  - Split into chunks:
    - Chunk 0 size: min(chunk_size_bytes + AES-GCM overhead + envelope_header, remaining)
    - Chunk N size: min(chunk_size_bytes + AES-GCM overhead, remaining)
  - For each chunk: decryptChunk(chunkData, fek, chunkIndex)
  - Write plaintext to --output

Step 5: Verify & Report
  - Decrypt filename from metadata (encrypted_filename + filename_nonce + account key)
  - Decrypt SHA-256 from metadata (encrypted_sha256sum + sha256sum_nonce + account key)
  - Compute SHA-256 of decrypted output file
  - Compare with decrypted expected SHA-256
  - Print results:
    "Decrypted: <original_filename>"
    "SHA-256: <computed_hash>"
    "Verified: ✓ (matches encrypted metadata)" or "MISMATCH: ✗"
```

### Chunk Splitting Logic

The encrypted blob is a concatenation of chunks with the following sizes:

```
Chunk 0: envelope_header (2 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
         Total: 2 + 12 + plaintext_chunk_size + 16 = plaintext_chunk_size + 30

Chunk N: nonce (12 bytes) + ciphertext + tag (16 bytes)
         Total: 12 + plaintext_chunk_size + 16 = plaintext_chunk_size + 28

Last chunk: may be smaller (remainder of file)
```

The splitting algorithm reads `size_bytes` from the bundle and splits greedily:
```
offset = 0
for i = 0; offset < size_bytes; i++ {
    overhead = AES_GCM_OVERHEAD  // 28 bytes (nonce + tag)
    if i == 0 { overhead += ENVELOPE_HEADER_SIZE }  // +2 bytes
    max_chunk = chunk_size_bytes + overhead
    actual_chunk = min(max_chunk, size_bytes - offset)
    chunks[i] = blob[offset : offset+actual_chunk]
    offset += actual_chunk
}
```

---

## E2E Test Integration

Add a new test section to `scripts/testing/e2e-test.sh` after the existing file upload/download/verify tests:

```bash
# ═══════════════════════════════════════════════════════════════
# 9: OFFLINE EXPORT & DECRYPT VERIFICATION
# ═══════════════════════════════════════════════════════════════

echo ""
echo "# 9: OFFLINE EXPORT & DECRYPT VERIFICATION"
echo ""

# Export the previously uploaded file as a .arkbackup bundle
EXPORT_OUTPUT="/tmp/arkfile-e2e-export-$$.arkbackup"
DECRYPT_OUTPUT="/tmp/arkfile-e2e-decrypt-$$.dat"

echo "Exporting file as .arkbackup bundle..."
EXPORT_RESULT=$(arkfile-client export \
  --file-id "$FILE_ID" \
  --output "$EXPORT_OUTPUT" 2>&1)
check_result $? "File export" "$EXPORT_RESULT"

# Verify bundle file exists and is larger than the encrypted data
BUNDLE_SIZE=$(stat -c%s "$EXPORT_OUTPUT" 2>/dev/null || echo 0)
if [ "$BUNDLE_SIZE" -lt 1000 ]; then
  echo "[X] Bundle file too small: $BUNDLE_SIZE bytes"
  exit 1
fi
echo "[OK] Bundle created: $BUNDLE_SIZE bytes"

# Decrypt the bundle offline using --password-stdin
# TEST_PASSWORD is the password used during registration
echo "Decrypting bundle offline (no network)..."
DECRYPT_RESULT=$(echo "$TEST_PASSWORD" | arkfile-client decrypt-blob \
  --bundle "$EXPORT_OUTPUT" \
  --username "$TEST_USER" \
  --password-stdin \
  --output "$DECRYPT_OUTPUT" 2>&1)
check_result $? "Offline decrypt" "$DECRYPT_RESULT"

# Verify SHA-256 of decrypted file matches the original plaintext
DECRYPTED_SHA=$(sha256sum "$DECRYPT_OUTPUT" | cut -d' ' -f1)
if [ "$DECRYPTED_SHA" = "$ORIGINAL_FILE_SHA" ]; then
  echo "[OK] Offline decrypt SHA-256 verified: $DECRYPTED_SHA"
else
  echo "[X] SHA-256 mismatch!"
  echo "    Expected: $ORIGINAL_FILE_SHA"
  echo "    Got:      $DECRYPTED_SHA"
  exit 1
fi

# Verify decrypted file size matches original
DECRYPTED_SIZE=$(stat -c%s "$DECRYPT_OUTPUT")
if [ "$DECRYPTED_SIZE" = "$ORIGINAL_FILE_SIZE" ]; then
  echo "[OK] Decrypted file size matches original: $DECRYPTED_SIZE bytes"
else
  echo "[X] Size mismatch! Expected: $ORIGINAL_FILE_SIZE, Got: $DECRYPTED_SIZE"
  exit 1
fi

# Cleanup
rm -f "$EXPORT_OUTPUT" "$DECRYPT_OUTPUT"

echo "[OK] Offline export & decrypt verification complete"
```

---

## Browser/Frontend: Export Button

### Overview

Browser users can export `.arkbackup` bundles directly from the file list UI. Since the bundle is an opaque encrypted binary (not decrypted client-side), the browser just triggers a download — no crypto processing needed in the browser.

**Important UX note:** The browser CANNOT decrypt `.arkbackup` bundles. The export button should clearly communicate that offline decryption requires `arkfile-client`.

### Large File Download Challenge

The existing browser download uses `fetch()` → `Blob` → `createObjectURL()`, which buffers the entire response in browser memory. For a 1GB `.arkbackup` bundle, this would consume 1GB of browser RAM — unacceptable.

**Solution: Short-lived download token**

Instead of streaming via `fetch()` with an `Authorization` header, the browser requests a short-lived download token, then opens a plain URL that the browser handles natively (no memory buffering).

### Server-Side: Export Token Endpoint

**`POST /api/files/:fileId/export-token`**

Returns a short-lived signed token that authorizes a single export download.

```json
// Request: POST /api/files/<fileId>/export-token
// (JWT auth in header)

// Response:
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "expires_in": 60
}
```

The token is a JWT (or HMAC-signed string) containing:
- `file_id` (the specific file authorized for export)
- `username` (the requesting user)
- `exp` (expiration: 60 seconds from now)
- `action: "export"` (scoped to export only, not reusable for other operations)

**Updated export endpoint accepts token:**

`GET /api/files/:fileId/export?token=<token>`

When a `?token=` query parameter is present, the endpoint validates the token instead of requiring a JWT `Authorization` header. This allows the browser to open it as a regular link.

### Browser Implementation

**New file:** `client/static/js/src/files/export.ts`

```typescript
import { getAuthHeaders } from '../utils/auth';
import { showError, showSuccess } from '../app';

/**
 * Export a file as an encrypted .arkbackup bundle.
 * Uses a download token so the browser handles the download natively
 * (no memory buffering for large files).
 */
export async function exportBackup(fileId: string): Promise<void> {
  try {
    // Step 1: Request a short-lived download token
    const response = await fetch(`/api/files/${fileId}/export-token`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const err = await response.json();
      showError(err.message || 'Failed to request export token');
      return;
    }

    const { token } = await response.json();

    // Step 2: Open the export URL with the token — browser handles download natively
    window.location.href = `/api/files/${fileId}/export?token=${encodeURIComponent(token)}`;

    showSuccess(
      'Encrypted backup export started. ' +
      'To decrypt offline, use: arkfile-client decrypt-blob --bundle <file>.arkbackup --username <your-username> --output <output>'
    );
  } catch (error) {
    console.error('Export error:', error);
    showError('An error occurred during export.');
  }
}
```

### UI Integration

In `client/static/js/src/files/list.ts`, add an export button for each file in the file list:

```typescript
// In the file row rendering function:
const exportBtn = document.createElement('button');
exportBtn.className = 'btn btn-sm btn-outline';
exportBtn.title = 'Export encrypted backup (.arkbackup)';
exportBtn.textContent = '📦 Export';
exportBtn.addEventListener('click', () => exportBackup(file.file_id));
actionCell.appendChild(exportBtn);
```

**Tooltip/title text:**
- For account-password files: "Export encrypted backup. Decrypt offline with arkfile-client using your account password."
- For custom-password files: "Export encrypted backup. Decrypt offline with arkfile-client using your account password and file password."

### Playwright Test Addition

Add to `scripts/testing/e2e-playwright.ts`:

```typescript
test('export encrypted backup from browser', async ({ page }) => {
  // Login and navigate to file list
  // ... (existing auth flow)

  // Find the export button for the test file
  const exportBtn = page.locator(`button[title*="Export encrypted backup"]`).first();
  await expect(exportBtn).toBeVisible();

  // Click export and wait for download
  const downloadPromise = page.waitForEvent('download');
  await exportBtn.click();
  const download = await downloadPromise;

  // Verify download filename ends with .arkbackup
  expect(download.suggestedFilename()).toMatch(/\.arkbackup$/);

  // Save and verify file starts with ARKB magic
  const filePath = await download.path();
  const fs = require('fs');
  const header = Buffer.alloc(4);
  const fd = fs.openSync(filePath!, 'r');
  fs.readSync(fd, header, 0, 4, 0);
  fs.closeSync(fd);
  expect(header.toString('ascii')).toBe('ARKB');
});
```

### Additional Server Routes

In `handlers/route_config.go`, add the token endpoint:
```go
files.POST("/:fileId/export-token", handlers.CreateExportToken)
```

---

## Files Changed / Created

| File | Status | Description |
|---|---|---|
| **Server** | | |
| `handlers/export.go` | **NEW** | `ExportFile` + `CreateExportToken` handlers |
| `handlers/route_config.go` | Modified | Add export + export-token routes |
| **CLI Client** | | |
| `cmd/arkfile-client/export.go` | **NEW** | `export` command — downloads bundle from server |
| `cmd/arkfile-client/offline_decrypt.go` | **NEW** | `decrypt-blob` command — offline decryption |
| `cmd/arkfile-client/commands.go` | Modified | Add `export` and `decrypt-blob` command cases |
| **Browser Frontend** | | |
| `client/static/js/src/files/export.ts` | **NEW** | Export backup helper (token + download trigger) |
| `client/static/js/src/files/list.ts` | Modified | Add export button to file list UI |
| **Tests** | | |
| `scripts/testing/e2e-test.sh` | Modified | Add CLI offline export & decrypt test section |
| `scripts/testing/e2e-playwright.ts` | Modified | Add browser export download test |
| **Docs** | | |
| `docs/wip/arkbackup-export.md` | **NEW** | This specification document |

**No changes to:**
- Database schema
- Existing crypto code (`crypto/` package)
- Existing storage layer (`storage/` package)
- Existing upload/download handlers

---

## Security Considerations

1. **The `.arkbackup` bundle contains encrypted data only.** The FEK is wrapped with the user's account key — it cannot be unwrapped without the user's password.

2. **No plaintext is stored in the bundle.** Filename, SHA-256 hash, and file contents are all encrypted. Only the `file_id`, sizes, and crypto parameters are in cleartext.

3. **Padding is included in the bundle.** This means the bundle size reveals the padded size (which is intentionally obscured), but since the bundle is for the file owner, this is acceptable.

4. **Password entry:** Interactive prompt with no echo, or `--password-stdin` for automation. Never as a CLI argument.

5. **Account key derivation:** Uses the same Argon2id parameters as the rest of Arkfile (from `crypto/argon2id-params.json`). The salt is `SHA-256(username)`.

6. **Admin export:** If implemented, the admin can export any user's file, but the admin CANNOT decrypt it (they don't know the user's password). The bundle is useless without the password.

---

## Future Considerations

- **Bundle signing:** Could add an optional HMAC or Ed25519 signature to the bundle header for tamper detection. Not needed for v1.

- **Streaming decryption:** For very large files, `decrypt-blob` could decrypt chunk-by-chunk and write incrementally instead of buffering all plaintext. The current chunk-at-a-time approach already supports this naturally.
