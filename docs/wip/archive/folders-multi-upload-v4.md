# Multi-File Upload and Folder Organization (v4)

Status: Active plan. Supersedes v3. The tranche-based, non-breaking-first ordering in v3 has been retired; this revision adopts a pure greenfield-reset posture consistent with AGENTS.md ("there are no production deployments of this app anywhere at present ... 'backwards compatibility' is not needed at this stage"). The beta at `test.arkfile.net` will be reset once as part of deploying this change; beta users receive a short notice and re-register.

## What Changed From v3

- **Work ordering is by dependency layer, not by deployment safety.** v3's Tranches 1–4 are replaced with four ordered implementation phases: Phase A (shared primitives), Phase B (server surface), Phase C (client features), Phase D (integration tests).
- **The T4 "AAD cutover" is gone.** All four in-scope client-encrypted per-file metadata fields (`folder_path`, `filename`, `sha256sum`, `fek`) are AAD-bound from day one in Phase C. There is no intermediate shipped state in which any of them decrypt without AAD.
- **The deploy story is explicit.** `test-deploy.sh` is used (not `test-update.sh`) because `unified_schema.sql` is `CREATE TABLE IF NOT EXISTS`-only and the app emits no `ALTER TABLE ADD COLUMN` statements anywhere. Re-running the schema file against an existing rqlite database correctly skips the existing tables (as the IF NOT EXISTS contract dictates) but never adds the new columns to them. v4 makes that choice deliberately rather than hiding it inside a tranche argument.
- **One new verification finding is surfaced** (the schema-evolution gap above). The rest of v3's verification findings are preserved where still load-bearing.
- **"Open Decisions (resolved)" section is dropped.** Those rationales existed to defend the v3 tranche ordering; they are no longer needed.
- **Technical design is unchanged.** Canonical path rules, AAD construction bytes, per-field threat rationale, the 2-session cap, `padded_size`-aware quota accounting, tree-view scale targets, and privacy analysis are carried over from v3 verbatim where applicable.

## How to Read This Document

- **Sections 1–4** are framing: overview, current state, design decisions, verification findings against the actual codebase.
- **Section 5** is the work breakdown: four phases, each self-contained, each ending in a unit-test gate. Implement phases in order.
- **Sections 6–9** are reference: files touched, deploy story, privacy, deferred items.

---

## 1. Overview

Two related features for Arkfile:

1. **Multi-file upload.** Allow uploading multiple files at once, or an entire folder at a time, from both the web frontend and `arkfile-client` CLI.
2. **Folder organization.** Display files in a folder hierarchy in the frontend UI and provide `tree`-style listing output in `arkfile-client`.

These features build on top of the existing single-file chunked upload pipeline. No changes to the encryption model, core server upload flow, or storage backend are required.

### What This Project Does Not Touch

- **OPAQUE authentication** (registration, login, session issuance, refresh tokens) is untouched.
- **TOTP** enrollment, verification, and backup codes are untouched.
- **Share flow internals** are untouched. Owner-facing `encrypted_fek` will gain AAD binding (see Section 3.3), but the share envelope format, share-envelope AAD, `file_share_keys` table, recipient-facing download path, and share-password KDF are unchanged. Existing and future shares continue to work; see Section 4 for the self-containment proof.
- **Chunk ciphertext** does not gain AAD. Unique per-file random FEKs prevent cross-file chunk substitution at the AES-GCM level, and the server's order-dependent streaming SHA-256 prevents within-file chunk reordering.
- **Storage backend** code (S3, SeaweedFS, multi-provider registry, erasure coding) is unchanged.
- **rqlite schema for auth-related tables** (`users`, `opaque_*`, `refresh_tokens`, `revoked_tokens`, `user_totp`, `totp_*`) is unchanged. Only `file_metadata` and `upload_sessions` grow two columns each.

### Guiding Principles (from AGENTS.md)

- **Zero-knowledge preserved.** Folder structure must never leak to the server. All folder paths are client-side encrypted metadata; server treats the encrypted blob and its nonce as opaque bytes.
- **Constrained-device friendly.** Must work on a mobile device with ~3 GB RAM for arbitrarily large batches, including individual files up to 6 GB. One-chunk-at-a-time streaming per file stays mandatory.
- **Single way to do things per client.** TS frontend and Go CLI functions mirror each other in naming, structure, and logic for upload, list, tree, and download operations.
- **Greenfield reset permitted.** There are no production deployments. Any deployment receiving this change is reset — `dev-reset.sh` locally, `test-deploy.sh` on the beta. No legacy paths, no per-row version flags, no dual-decrypt branches.

### Greenfield-Reset Stance

Because `unified_schema.sql` is `CREATE TABLE IF NOT EXISTS`-only and the app has no column-evolution mechanism (see Section 4), shipping a schema change to any existing database requires a wipe. v4 accepts that stance explicitly:

- **Local:** `sudo bash scripts/dev-reset.sh` is the standard dev iteration tool and already wipes state. No impact on the developer workflow.
- **Beta (`test.arkfile.net`):** Deploy via `scripts/test-deploy.sh` (fresh install), not `scripts/test-update.sh`. Beta testers are notified in advance that accounts and files will be reset on a specific date and that they will need to re-register after the deploy. See Section 7 for a copy-pasteable notice template.
- **Future (this project only):** After this project lands, subsequent code-only changes to folder/multi-upload functionality can use `test-update.sh` as normal. The wipe is a one-time cost for introducing the new columns and the new AAD-bound encryption of existing metadata fields.

The one-shot wipe replaces v3's intricate tranche choreography with a single coherent deploy. It costs one email to beta users and buys the elimination of an entire class of intermediate states, dual-decrypt paths, and session-cutover edge cases.

### Glossary

- **AAD** — Additional Authenticated Data. Extra context bytes passed to an AEAD cipher (here, AES-GCM). AAD is not encrypted but is cryptographically bound to the ciphertext: the same ciphertext decrypted with different AAD fails with an authentication error. Used here to bind each per-file metadata ciphertext to a specific `(file_id, field, username)` tuple.
- **AES-GCM** — AES in Galois/Counter Mode. The AEAD cipher used throughout Arkfile for client-side encryption.
- **FEK** — File Encryption Key. A random 256-bit key generated per file and used to encrypt the file's chunk data. The FEK is itself wrapped (encrypted) by a KEK.
- **KEK** — Key Encryption Key. A key whose only job is to encrypt other keys. In Arkfile, the Account Key and Custom Key act as KEKs; the FEK they wrap is the actual file-encrypting key.
- **OPAQUE** — Asymmetric PAKE protocol (RFC draft). Used for authentication without ever transmitting the password.
- **Account Key** — Argon2id-derived key bound to the user's account password. Acts as KEK for per-file metadata and (by default) for the FEK.
- **Custom Key** — Argon2id-derived key bound to an optional per-file custom password. Acts as KEK for the FEK when `password_type = custom`.
- **Canonical folder path** — A folder path in the normalized form defined in § 3.2 (forward slashes, no leading/trailing slash, NFC-normalized, no dot segments, no empty segments, etc.).
- **`upload_sessions`** — Server-side table tracking in-progress chunked uploads. Row transitions `in_progress` → `completed` | `abandoned`.
- **`file_metadata`** — Server-side table holding finalized file metadata after a successful `CompleteUpload`.

---

## 2. Current State

### Upload Flow
- The HTML file input in `client/static/index.html` is `<input type="file" id="fileInput">` — single file only, no `multiple` attribute, no `webkitdirectory`.
- The TS frontend reads `fileInput.files[0]` in `client/static/js/src/files/upload.ts` and calls the single-file upload helper exactly once.
- The backend exposes a per-file pipeline in `handlers/uploads.go`:
  - `POST /api/uploads/init` → `CreateUploadSession`
  - `POST /api/uploads/:sessionId/chunks/:chunkNumber` → `UploadChunk` (repeated N times)
  - `POST /api/uploads/:sessionId/complete` → `CompleteUpload`
  - `GET /api/uploads/:sessionId/status` → `GetUploadStatus`
  - `DELETE /api/uploads/:fileId` → `CancelUpload`
- Each file is an independent upload session. `CreateUploadSession` generates the authoritative `file_id` via `models.GenerateFileID()` and returns it to the client in the response JSON (`{"session_id": ..., "file_id": ..., "chunk_size": ...}`).
- `arkfile-client` accepts `--file FILE` (a single path) on the `upload` subcommand.

### File Listing
- `GET /api/files` returns a flat array of file metadata entries for the authed user, plus a `storage` summary block.
- The TS frontend `list.ts` renders a flat list of file cards (name, size, date, actions).
- `arkfile-client list-files` renders a flat numbered list or JSON output.

### Database
- `file_metadata` has no folder/path columns. Files are a flat collection per `owner_username`.
- `upload_sessions` carries per-file encrypted metadata (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek`, plus corresponding nonces) during the in-progress upload.
- Filenames are encrypted client-side. The server cannot see, sort, or filter by filename or path.
- Schema is defined in `database/unified_schema.sql` and applied by `database/database.go::createTables()` at app startup via a single whole-file `DB.Exec`. All statements are `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` — no `ALTER TABLE` statements anywhere. See Section 4 for the implication.

### Per-File AAD Scope Today
- Currently, only share envelopes use AAD (`share_id || file_id`, no separator), in `handlers/file_shares.go` and `client/static/js/src/shares/`.
- Per-file ciphertext metadata fields on `file_metadata` and `upload_sessions` (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek`) do **not** currently use AAD.
- `encrypted_folder_path` does not exist yet.

### Why the Upload Pipeline Is Strictly Sequential (Per File)
The server maintains two running SHA-256 hashes per upload session (`streamingHashStates` and `storedBlobHashStates` in `handlers/uploads.go`) that are **order-dependent**: chunks must arrive in numerical order for the hashes to be correct. The last-chunk padding logic in `UploadChunk` also assumes the last chunk is hashed last. Parallelizing chunks within a single file would require a redesign of these hashes and of padding placement; that is explicitly out of scope (see Section 9, Deferred Items).

We therefore keep a single file's chunks sequential and batch at the file level.

---

## 3. Design Decisions

### 3.1 Folder Path Storage: Separate Columns on Two Tables

- `encrypted_folder_path TEXT` + `folder_path_nonce TEXT` added to both:
  - `file_metadata` (final home after `CompleteUpload`).
  - `upload_sessions` (so the path round-trips from `CreateUploadSession` through `UploadChunk` into `CompleteUpload` without the client needing to resend it).
- The path stored is the **directory portion only** (e.g., `photos/2025/vacation`). The filename stays as the file's base name (`img001.jpg`) and is encrypted separately into `encrypted_filename`.
- Both columns nullable. `NULL` on either column = "root level" (no folder path). For any given row the two columns are set together (both NULL or both non-NULL).

### 3.2 Canonical Path Format (Enforced Identically in TS and Go)

Stored plaintext (pre-encryption) paths must conform to this canonical form. Both the TS client and the Go CLI reject non-canonical input with identical error codes and error-message strings. The shared test-vectors file (§ 5 Phase A, item A6) is the authoritative source of truth; the two implementations are proved byte-identical in unit tests.

| Rule | Value |
| --- | --- |
| Separator | Forward slash `/` only |
| Leading slash | Forbidden |
| Trailing slash | Forbidden |
| Empty path | Allowed (= root, equivalent to `NULL`) |
| Empty segment (`a//b`) | Forbidden |
| Dot segments (`.`, `..`) | Forbidden |
| Unicode normalization | NFC |
| Forbidden characters per segment | `/`, `\`, NUL, ASCII control chars `0x00`–`0x1F` |
| Max segment length | 255 bytes (UTF-8) |
| Max depth | 32 segments |
| Max total path length | 1024 bytes (UTF-8) |
| Case sensitivity | Preserved (NFC-normalized, not case-folded) |

**Rationale:**
- 255-byte segment limit matches POSIX `NAME_MAX` and Windows component limits, so any accepted path round-trips safely if users ever download with `--preserve-folders`.
- 32-segment depth covers real-world personal data (photo libraries ~6–8, source trees ~10–15) with headroom.
- 1024-byte total keeps encrypted blob + nonce + tag around ~1.1 KB per file.
- Case sensitivity preserved: `Photos/2025` and `photos/2025` are distinct folders. Matches POSIX behavior and avoids any server-visible collation rules. Canonicalization applies NFC Unicode normalization but does **not** case-fold.

**Implementation:**
- TS: `client/static/js/src/files/folder-path.ts` exports `canonicalizeFolderPath(input: string): string` and `validateFolderPath(path: string): {ok: boolean, code?: string, message?: string}`.
- Go CLI: `cmd/arkfile-client/folderpath.go` exports `CanonicalizeFolderPath(input string) (string, error)` and `ValidateFolderPath(path string) error`.
- Both load rules from `crypto/folder-path-params.json` via the same loader pattern used by `crypto/chunking-params.json`, `crypto/argon2id-params.json`, and `crypto/password-requirements.json`.
- A shared test-vectors file at `scripts/testing/folder-path-test-vectors.json` is authoritative. Both TS and Go unit tests load it and assert byte-identical canonicalization and byte-identical AAD bytes. This is the mechanism that prevents the two clients from drifting.

**Walker inputs:**
- Browser: `file.webkitRelativePath` is split on `/`, the last segment (the filename) is dropped, the remainder is canonicalized.
- CLI: `filepath.Walk` results are converted from the OS separator to `/`, the filename is dropped, the remainder is canonicalized.

If canonicalization fails for a particular file, that file is flagged as rejected in the batch progress UI with the specific rule it violated; the rest of the batch continues.

### 3.3 AAD Binding for Encrypted Metadata Blobs

Encrypted per-file metadata blobs use AES-GCM with **Additional Authenticated Data (AAD)** that cryptographically binds the ciphertext to a specific file, field, and user. **All four in-scope client-encrypted per-file metadata fields are AAD-bound from the day they ship** (Phase C). There is no intermediate state in this project where any of them decrypts without AAD.

**AAD construction (byte-identical in TS and Go):**

```
AAD = file_id_bytes || 0x00 || field_name_bytes || 0x00 || username_bytes
```

- `file_id_bytes`: UTF-8 bytes of the `file_id` string (as returned by the server from `CreateUploadSession`).
- `field_name_bytes`: UTF-8 bytes of a short ASCII field tag — one of: `"folder_path"`, `"filename"`, `"sha256sum"`, `"fek"`.
- `username_bytes`: UTF-8 bytes of the owner username (immutable, per Section 4).
- `0x00`: NUL separator between fields. NUL is forbidden inside all three values (forbidden in folder-path segments per § 3.2; not present in usernames per the username validator; not present in file-id strings which are alphanumeric), so the encoding is unambiguous.

**Field tags and the separator byte are hardcoded as language-level constants** in both `crypto/aad.go` (Go) and `client/static/js/src/crypto/aad.ts` (TS). They are not loaded from JSON. Renaming any of them is a hard-fork decryption event — every pre-rename ciphertext stops decrypting — so they should be treated as part of the on-the-wire ciphertext contract and never altered. The shared test vectors (§ 5 Phase A, item A6) catch any divergence between the two implementations immediately.

**Field / tag / column mapping:**

| Tag | Column(s) | Meaning |
| --- | --- | --- |
| `folder_path` | `encrypted_folder_path` + `folder_path_nonce` | Directory portion of the path (new in this project) |
| `filename` | `encrypted_filename` + `filename_nonce` | Base filename |
| `sha256sum` | `encrypted_sha256sum` + `sha256sum_nonce` | SHA-256 of the plaintext file (client-computed, client-encrypted) |
| `fek` | `encrypted_fek` | Wrapped File Encryption Key (inside the existing envelope wrapper) |

**Not in AAD scope:** the column `file_metadata.encrypted_file_sha256sum` is excluded. Despite the `encrypted_` prefix, its stored value is a **plaintext** SHA-256 computed on the server over the already-client-side-encrypted data stream (pre-padding) as chunks arrive. The server holds it in plaintext by construction, so there is nothing there to protect with AAD. The column keeps its historical name; a clarifying block comment is added to `models.File.EncryptedFileSha256sum` in `models/file.go` (§ 5 Phase A, item A2). The related server-side field `stored_blob_sha256sum` (hash of all bytes written to S3 including padding) is likewise plaintext and not in AAD scope.

**Per-field protection rationale.** Each of the four in-scope fields gains a distinct defense from AAD, not just uniformity:

- `folder_path`: cross-row swap would mis-render the tree and, more importantly, cause `download --preserve-folders` in the CLI to write decrypted bytes into an attacker-chosen filesystem location under the target output directory. AAD plus the explicit re-validation + containment check in § 5 Phase C, item C12 is belt-and-suspenders.
- `filename`: cross-row swap would cause decrypted bytes of file A to be saved under file B's user-visible name — a confusion-of-identity attack on download. Also underpins the dedup key `(filename, canonical_folder_path)` in § 5 Phase C, item C6.
- `sha256sum` (plaintext-file hash): the underlying value is privacy-sensitive (file-fingerprinting risk). Cross-row swap would break the client-side integrity check that confirms decrypted plaintext matches what was uploaded. AAD binds the integrity record to `(file_id, field, username)`.
- `fek`: the wrapped FEK is the root of the per-file encryption chain. Cross-file FEK substitution without AAD is only caught downstream at per-chunk AEAD tag failure; AAD on the wrapped FEK surfaces the fault at the wrapper layer and prevents silent reliance on chunk-level detection.

**Key wrapping for each field (AAD is orthogonal to KEK choice):**

- `folder_path`, `filename`, `sha256sum` always use the **Account Key** as KEK regardless of the file's `password_type`, per AGENTS.md "File metadata encryption and decryption always uses the Account Key."
- `fek` uses the **Account Key** or the **per-file Custom Key** depending on the file's `password_type` (envelope `key_type = 0x01` for account, `0x02` for custom).
- AAD binding applies uniformly in both cases — the KEK choice is orthogonal to the AAD-verified context (`file_id`, field, username).

**Helper (shared between TS and Go):** both define their tags and separator byte as language-level constants (no JSON load).

```go
// crypto/aad.go (new file)
package crypto

const aadSeparator byte = 0x00

const (
    AADFieldFolderPath = "folder_path"
    AADFieldFilename   = "filename"
    AADFieldSha256sum  = "sha256sum"
    AADFieldFEK        = "fek"
)

// BuildFileMetadataAAD constructs:
//   file_id || 0x00 || field || 0x00 || username
func BuildFileMetadataAAD(field, fileID, username string) []byte {
    buf := make([]byte, 0, len(fileID)+1+len(field)+1+len(username))
    buf = append(buf, fileID...)
    buf = append(buf, aadSeparator)
    buf = append(buf, field...)
    buf = append(buf, aadSeparator)
    buf = append(buf, username...)
    return buf
}
```

```ts
// client/static/js/src/crypto/aad.ts (new file)
const AAD_SEPARATOR = 0x00;

export const AAD_FIELD = {
  FOLDER_PATH: 'folder_path',
  FILENAME:    'filename',
  SHA256SUM:   'sha256sum',
  FEK:         'fek',
} as const;

export type AADField = typeof AAD_FIELD[keyof typeof AAD_FIELD];

export function buildFileMetadataAAD(
  field: AADField,
  fileID: string,
  username: string,
): Uint8Array {
  const enc = new TextEncoder();
  const fid = enc.encode(fileID);
  const fld = enc.encode(field);
  const usr = enc.encode(username);
  const out = new Uint8Array(fid.length + 1 + fld.length + 1 + usr.length);
  let p = 0;
  out.set(fid, p); p += fid.length;
  out[p++] = AAD_SEPARATOR;
  out.set(fld, p); p += fld.length;
  out[p++] = AAD_SEPARATOR;
  out.set(usr, p);
  return out;
}
```

Both implementations must produce byte-identical output for the same inputs — proved by A6's shared test vectors. The Go helper sits in the shared `crypto/` package alongside `gcm.go` and `share_kdf.go`; the CLI imports it directly.

**Folder-path bucket padding (folder_path field only).**

To reduce length-based fingerprinting of the encrypted folder path, the canonical plaintext is padded to a 64-byte bucket before encryption. Other fields (`filename`, `sha256sum`, `fek`) are not bucket-padded here — `sha256sum` and `fek` are always exactly 32 bytes, and `filename` padding is handled elsewhere in the existing envelope flow.

```
Encrypt:
  canonical    = canonicalizeFolderPath(input)            // may be ""
  L            = byteLength(canonical)
  padLen       = ((L / 64) + 1) * 64 - L                  // 1..64 bytes
  plaintext    = canonical || (0x00 repeated padLen times) // multiple of 64, >= 64

Decrypt:
  ...AES-GCM decrypt as before...
  canonical    = stripTrailingNUL(plaintext)
  // pass canonical through ValidateFolderPath for the C12 belt-and-suspenders check
```

Padding bytes are unambiguously strippable on decrypt because NUL is forbidden in canonical folder paths (§ 3.2's forbidden-character set). The empty path `""` pads to 64 NUL bytes. With max canonical length of 1024 bytes (§ 3.2), there are 16 distinguishable buckets total instead of 1025.

**Encrypt (client, all four fields):**

```
plaintext  = canonical_path_or_padded   (folder_path: bucket-padded per above)
           = base_filename              (filename)
           = sha256_digest_32_bytes     (sha256sum)
           = random_256_bit_FEK         (fek)
key        = Account Key   (for folder_path / filename / sha256sum,
                            and for fek when password_type = account)
           = Custom Key    (for fek when password_type = custom)
nonce      = random 12 bytes
aad        = BuildFileMetadataAAD(field_tag, file_id, username)
(ct, tag)  = AES-GCM-Encrypt(key, nonce, plaintext, aad)
```

**Decrypt (client, all four fields):**

```
aad        = BuildFileMetadataAAD(field_tag, file_id, username)
plaintext  = AES-GCM-Decrypt(key, nonce, ct, tag, aad)   // fails if AAD doesn't match
                                                          // strip NUL padding for folder_path
```

**Wire format.** Two distinct shapes are used.

- **`folder_path`, `filename`, `sha256sum`** — two separate base64 columns:
  - `<field>_nonce` carries the 12-byte AES-GCM nonce.
  - `encrypted_<field>` carries `ciphertext || 16-byte AES-GCM tag` (the tag is appended by AES-GCM).
- **`encrypted_fek`** — one base64 column carrying the existing envelope wrapper `[0x01][key_type][nonce][ct][tag]`. The envelope header bytes (`0x01` magic + `key_type`) sit **outside** the AAD-protected region; only the wrapped FEK's ciphertext carries the AAD binding. The 12-byte nonce and 16-byte tag inside the envelope are the AES-GCM nonce and tag for the wrapped-FEK encryption.

**What this prevents:**
- **Cross-file swap.** Attacker or bug copies file X's metadata blob onto file Y — without AAD this decrypts cleanly with the wrong file's key bindings and silently displays the wrong value. With AAD, decryption fails.
- **Cross-field swap.** Attacker swaps `encrypted_filename` onto the `encrypted_folder_path` slot (or vice versa). With a field tag in AAD, that decryption fails.
- **Cross-user confusion.** Defense in depth against any code path that accidentally mixes user rows (note: username is immutable per Section 4, so this binding is permanent).

**Does not prevent (accepted):**
- Rollback to a previous ciphertext for the **same** `(file_id, field, username)` tuple. Would require a monotonic version counter in AAD; overkill for this project.

**Share-envelope AAD is untouched.** Existing share envelopes use AAD = `share_id || file_id` (no separator) and that wire format is left alone. Changing it would invalidate existing shares and provides no additional security benefit. New per-file-metadata AAD is NUL-separated; old share AAD is left alone. See Section 4 for the proof that the share flow does not depend on the owner-facing columns this project rebinds.

### 3.4 Multi-File Upload: Sequential, One File at a Time

- Files in a batch upload one at a time. The existing single-file pipeline (init → chunks → complete) is used per file.
- Rationale: preserves the constrained-device memory model (one chunk resident in browser/mobile memory at a time), keeps the order-dependent server hash architecture untouched, and avoids rqlite Raft write contention from parallel sessions.
- Parallel-across-files (2–3 concurrent sessions) is a plausible future optimization but deferred; see Section 9. The server-side 2-in-progress-sessions cap in § 3.12 is chosen to accommodate this future work without a second round of server changes.
- Parallel-within-a-file (parallel chunks) is a larger project with real prerequisites; see Section 9.

### 3.5 Folder Creation Model: Implicit Only

- Folders exist only because files have that path. No empty-folder entities.
- Deleting the last file in a folder makes the folder disappear from the tree.
- No server-side folder state, no folder CRUD endpoints.
- Server cannot enumerate folders (it never sees plaintext paths); folder listing is a client-side aggregation over the user's decrypted `encrypted_folder_path` values.

### 3.6 Default File List View

- When any file in the user's listing has a non-NULL folder path: **default to tree view**. The "any file has a folder path" signal is read from the `has_folder_paths` boolean on the `GET /api/user/storage` response (§ 3.9 / § B4) so the client can decide the default before fetching `GET /api/files`.
- When all files are at root: default to flat view.
- User can toggle between tree and flat at any time. Toggle preference is remembered in `localStorage` under the key `arkfile:file-list-view` → `"tree"` or `"flat"`. The key is not username-qualified — Arkfile is single-user-per-browser-profile (you must be logged in to use the SPA), and a view-rendering preference is not sensitive enough to justify writing the username into `localStorage`.

### 3.7 Multi-File / Folder Share: Not in This Round

- Single-file sharing only for now. The current per-file metadata model does not paint us into a corner: sharing a folder later becomes "iterate files whose decrypted path matches a prefix, build a manifest envelope."
- Deferred to a separate design doc; see Section 9.

### 3.8 Export / Backup: Include Folder Paths

- The encrypted export bundle format carries `encrypted_folder_path` and `folder_path_nonce` per file, AAD-bound like every other per-file metadata field.
- Import/restore (if/when implemented) round-trips folder structure.
- Small surgical change to `handlers/export.go`, `client/static/js/src/files/export.ts`, and `cmd/arkfile-client/offline_decrypt.go` (§ 5 Phase B and Phase C).

### 3.9 Pre-flight Quota Endpoint

New lightweight authenticated endpoint:

```
GET /api/user/storage

Response:
{
  "total_bytes":     1234567890,    // SUM(padded_size) across both committed files and in-progress sessions
  "limit_bytes":     10737418240,
  "available_bytes": 9502850350,
  "usage_percent":   11.5
}
```

**Rationale:**
- Current clients infer storage info as a side-effect of `POST /api/login`, `GET /api/files`, and `POST /api/uploads/:session/complete`. For batch upload we want a cheap, purpose-built "how much room do I have?" primitive that does not require fetching the full file list.
- Both web and CLI use this for batch pre-flight: before any hashing/encryption/upload begins, sum `calculateTotalEncryptedSize(file.size) + padding` over the selected files and compare against `available_bytes`. If the batch doesn't fit, show the user "This batch needs X MB; you have Y MB available — remove N files" before any work starts.
- Slots into `totpProtectedGroup` in `handlers/route_config.go` alongside `/api/credits`.
- `total_bytes` includes both `SUM(padded_size) FROM file_metadata WHERE owner_username = ?` and `SUM(padded_size) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. Since `padded_size` is computed deterministically at `CreateUploadSession` time (see Section 4), the sum is exact, not estimated.

### 3.10 Tree View Scale Targets

- **Eager decrypt** of all filename + SHA256 + folder-path blobs up to **1,000 files**.
  - Expected: ~3 AES-GCM-Decrypt calls per file on small blobs; on mid-range mobile (~0.5 ms/call) that is ~1.5 s worst case for 1,000 files. No progress indicator needed — sub-second for typical libraries.
- **Above 1,000 files**: always paginate via `GET /api/files?limit=&offset=` (the API already supports it). Flat view decrypts filenames only for the current page. Tree view decrypts folder paths lazily as the user expands each node.
- **Metadata cache: in-memory `Map<fileID, DecryptedMeta>` scoped to the SPA lifetime.**
  - Rationale: decrypted plaintext in `sessionStorage` or `localStorage` is readable by any script running on the page, including any future XSS. An in-memory `Map` is wiped on tab close or full page reload, which matches the expected security posture for decrypted metadata. The cost is re-decrypting after a refresh, which is acceptable given the sub-second times for typical libraries.

### 3.11 Single-File "Add to Virtual Folder?" Input

The single-file upload form gets an opt-in **"Add to virtual folder?"** text input.

- Empty (default) → file goes to root; `encrypted_folder_path` and `folder_path_nonce` are omitted from the request.
- Non-empty → value is run through the shared canonicalize+validate helper, rejected inline if invalid, otherwise encrypted with the account key + AAD (tag = `folder_path`) and included in `CreateUploadSession`.

This is cheap (one text input + one optional field in the request) and makes the tree view useful immediately for users who don't do bulk folder uploads.

### 3.12 Concurrent-Upload Cap and Rate Limits

- **Server-side cap of 2 in-progress upload sessions per user**, enforced in `CreateUploadSession` before inserting a new session row (§ 5 Phase B, item B3). Returns HTTP 429 with a clear message if exceeded.
- **Lazy stale-session cleanup** in the same SQL path: any session past `expires_at` is marked `abandoned` opportunistically before re-checking the count. Prevents dead sessions from permanently blocking new uploads.
- **Client discipline is strictly sequential (1 session at a time).** The 2-session headroom accommodates power users with the web app open in two tabs, or a CLI running alongside a browser upload. No normal workflow trips the cap.
- **No changes to rate-limiting infrastructure.** Per Section 4: `/api/uploads/*` is not per-endpoint throttled for authed users, and `FloodGuardMiddleware` only escalates on 401/404 from unauthenticated requests. Batch upload of hundreds of files will not trip any limit at this layer.

### 3.13 Account Key Residency During Batch Uploads

The Account Key is the Argon2id-derived KEK used to wrap per-file `fek`s and to encrypt/decrypt all per-file metadata (folder paths, filenames, sha256sums). Today it is held in an in-memory cache via `client/static/js/src/crypto/account-key-cache.ts` for a configurable duration (1–4 hours) with an inactivity timeout. Batch and folder uploads extend the residency window in user-visible ways, so v4 tightens and extends the contract:

- **Mandatory clearing events.** The Account Key cache must be wiped on each of the following:
  - **Logout** (already wired via `cleanupAccountKeyCache()` in `auth/login.ts`).
  - **JWT session expiry / refresh-token rotation** (new wiring: route the existing session-expiry handler into `cleanupAccountKeyCache()`).
  - **Page navigation away from the SPA** (new wiring: `registerAccountKeyCleanupHandlers` registers `beforeunload` and `pagehide` listeners that call `cleanupAccountKeyCache()`).
  - **Inactivity timeout** (existing; `inactivityTimeoutMinutes` is already configurable in the cache module).
- **Opt-in extension for long uploads.** Before starting a batch upload whose estimated duration exceeds the configured `inactivityTimeoutMinutes`, show a one-time confirmation:
  > "This upload is estimated to take ~N minutes. Keep your file-encryption key cached for the duration? [Yes, extend for this batch] [No, re-prompt per file]"
  - Yes → extend the cache lifetime to cover the batch and only the batch (revert at batch completion or abort).
  - No → fall through to the existing per-file password-prompt path.
  - The default is whichever is least surprising given the current cache state (if the user is already in a long cache window, default Yes; if cache is off or near expiry, default No).
- **Rationale.** The Account Key in browser memory is the worst-case blast-radius asset for any future XSS on the SPA — it can decrypt every metadata blob and unwrap every account-wrapped FEK. The mandatory clearing events above keep the residency window tight by default, and the opt-in extension gives the user explicit control over the long-upload tradeoff rather than silently extending the window for them.
- **Out of scope but worth flagging.** The existing cache stores the wrapping `CryptoKey` (non-extractable) in JS memory and the wrapped Account Key ciphertext in `sessionStorage`. The § 3.10 reasoning that "decrypted plaintext in `sessionStorage` is readable by any script on the page" applies in mitigated form here: the wrapped ciphertext is useless without the in-memory wrapping key. Whether to revisit this is a separate review, not part of this folders project.

---

## 4. Verification Findings

Each finding below has been confirmed by reading the code at the commit referenced in this document's git history. These are load-bearing for the design and for Section 5's work breakdown.

### 4.1 Username Is Immutable

No `UPDATE users SET username ...` path exists anywhere in the codebase. `owner_username` is used as a persistent key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, and `upload_sessions`. Using `username` as the stable user identifier in AAD (§ 3.3) is safe. A short header comment is added to `models/user.go` in Phase A (A2) to document this invariant for future contributors.

### 4.2 `/api/uploads/*` Is Not Rate-Limited for Authed Users

The upload init/chunk/complete/status/cancel endpoints sit in `totpProtectedGroup` (in `handlers/route_config.go`) with no per-endpoint throttle in `handlers/rate_limiting.go` or `handlers/route_config.go`. Batch upload of hundreds of files via the multi-file or folder-upload UIs will not trip any limit at this layer.

### 4.3 `FloodGuardMiddleware` Only Escalates on Unauthed 401/404

Authenticated, approved users performing sequential batch uploads cannot trip flood-guard escalation. Source: `handlers/flood_guard.go`.

### 4.4 `handlers/export.go` Has a Clean Extension Point

Adding `encrypted_folder_path` and `folder_path_nonce` to the export bundle's JSON metadata header is additive and NULL-safe for pre-existing rows (though this project wipes, so there are no pre-existing rows post-deploy).

### 4.5 Current AAD Coverage in the Code Is Narrow

Only share envelopes use AAD (`share_id || file_id`, no separator). Per-file ciphertext metadata fields (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek`) on `file_metadata` and `upload_sessions` do **not** currently use AAD. Phase C of this project adds AAD binding to all four in-scope client-encrypted per-file metadata fields (`folder_path`, `filename`, `sha256sum`, `fek`) in a single coherent change. The column `encrypted_file_sha256sum` is **not** in AAD scope despite its name (§ 3.3); a clarifying comment lands on `models.File.EncryptedFileSha256sum` in Phase A.

### 4.6 Three Hand-Written SQL Call Sites on `upload_sessions` in `handlers/uploads.go`

Phase B must update all three to include `encrypted_folder_path` and `folder_path_nonce`:

1. `INSERT INTO upload_sessions (...) VALUES (...)` in `CreateUploadSession` — add the two columns to the INSERT list and the corresponding bindings.
2. `SELECT owner_username, file_id, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, status, total_chunks, total_size, created_at, expires_at FROM upload_sessions WHERE id = ?` in `GetUploadStatus` — add the two fields to the SELECT list and the receiving variables.
3. Multi-line `SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks, total_size, chunk_size, padded_size, password_hint, password_type, encrypted_filename, filename_nonce, encrypted_sha256sum, sha256sum_nonce, encrypted_fek FROM upload_sessions WHERE id = ?` in `CompleteUpload` preamble — add the two fields to the SELECT list and carry them through into the `file_metadata` INSERT.

`UploadChunk` does not touch these columns and does not need changes in this path. `CancelUpload` also does not need column-list changes.

### 4.7 `CreateUploadSession` Does Not Currently Cap Concurrent In-Progress Sessions

Multiple in-progress sessions per user can be created in parallel today. A server-side cap of 2 sessions is added in Phase B (item B3), with lazy stale-session cleanup.

### 4.8 `padded_size` Is Computed Deterministically at Session-Init Time

`padded_size` is computed from `request.TotalSize` via `utils.NewPaddingCalculator().CalculatePaddedSize(...)` in `CreateUploadSession`, before any chunk arrives. It is persisted on `upload_sessions` and carried to `file_metadata` at `CompleteUpload` time. Quota accounting for in-flight sessions (§ 3.9, B3, B4) can therefore include `padded_size` exactly, without estimation.

### 4.9 `file_id` Generation: Client-Generated, Server-Validated

Today the server generates `file_id` inside `CreateUploadSession` via `models.GenerateFileID()` (which is `uuid.New().String()` — a plain UUIDv4 with 122 bits of randomness) and echoes it back to the client alongside `session_id`:

```json
{"session_id": "...", "file_id": "...", "chunk_size": ...}
```

For this project, AAD on per-file metadata must bind to a `file_id` that the client knows **before** it calls `CreateUploadSession` (because `encrypted_folder_path`, `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_fek` are all part of that request body and all carry AAD).

**v4 resolves this by having the client generate `file_id` locally** and pass it into `CreateUploadSession`:

- TS: `crypto.randomUUID()` (UUIDv4, available in all modern browsers and Bun).
- Go CLI: `uuid.NewString()` from `github.com/google/uuid` (already imported).
- Server-side validation in `CreateUploadSession`:
  - Parse and validate the supplied `file_id` is a well-formed UUIDv4. Reject with HTTP 400 + `{"error": "invalid_file_id"}` if not.
  - Reject with HTTP 409 Conflict + `{"error": "file_id_collision"}` if the `file_id` already exists in `upload_sessions` or `file_metadata` (UUIDv4 collision is cosmologically unlikely, but checked for defense-in-depth so any client bug that reuses an ID surfaces immediately).
  - On success, proceed with the existing INSERT flow.
- The `CreateUploadSession` response continues to echo `file_id` back so the client can confirm round-trip correctness.

**Why client-generated rather than a server pre-init endpoint:** UUIDv4 is opaque, has no server-secret content, and `file_id` is purely a label. A server pre-init endpoint would add a round trip per file (significant for batch uploads of 100+ files on flaky mobile connections), require a reservation table or a new `status = 'reserved'` state on `upload_sessions`, create an abuse surface (unbounded reservations per JWT), and provide no privacy or security benefit. Client-generated `file_id` with server-side validation is simpler and equivalent on every other axis.

### 4.10 A Cancel-Upload Endpoint Already Exists

`DELETE /api/uploads/:fileId` → `CancelUpload` in `handlers/uploads.go` and `handlers/route_config.go`. Users or the client can cleanly abandon any in-progress session. Useful for partial-failure recovery during batch upload (§ 5 Phase C, item C3) and for abandoning sessions that fail pre-flight validation.

### 4.11 Share Flow Is Self-Contained and Does Not Depend on the Owner's Per-File Metadata Columns

This is the key finding that lets us rebind owner-side `encrypted_fek` AAD without breaking the share flow.

- `file_share_keys` has its own `encrypted_fek` column wrapped by the **Share Key** derived from the share password + random 32-byte salt — **not** by the owner's account key. Source: `database/unified_schema.sql` (table `file_share_keys`) and `handlers/file_shares.go`.
- Filename and SHA-256 metadata live inside the client-side-encrypted `ShareEnvelope` decrypted by the recipient with the share password, not via the owner's `encrypted_filename` / `encrypted_sha256sum` columns.
- `handlers/file_shares.go` comments this explicitly: "*plaintext metadata like filename/sha256 is inside the encrypted ShareEnvelope, decrypted client-side with the share password — no need to send server-side encrypted metadata that share recipients cannot decrypt*."

**Implications for this project:**

- The share-envelope AAD (`share_id || file_id`, no separator) is **not** touched. The new per-file-metadata AAD construction (NUL-separated) is independent.
- New shares created after this project ships: the owner-side share-creation code path first decrypts the owner's own `encrypted_fek` (now AAD-bound) and re-wraps it with the Share Key for the recipient. This works because the owner-side unwrap goes through the updated decrypt path in `download.ts` / `list.ts` / the CLI. `client/static/js/src/files/share.ts` does **not** need direct new AAD wiring for the share-creation path beyond what the owner's download/list code already receives.
- Recipient-facing decrypt of shares does not read the owner's rebinding columns and is unaffected.

### 4.12 Schema Evolution Gap: `unified_schema.sql` Is `CREATE TABLE IF NOT EXISTS`-Only

**This is the finding that drives the Section 7 deploy decision.**

- `database/database.go::createTables()` runs on every app startup and executes the entire `unified_schema.sql` file via a single `DB.Exec`.
- Every `CREATE TABLE` statement in `unified_schema.sql` uses `CREATE TABLE IF NOT EXISTS`. Likewise every index uses `CREATE INDEX IF NOT EXISTS`.
- There are **no** `ALTER TABLE` statements in `unified_schema.sql` and no migration framework anywhere in the codebase.
- `scripts/test-update.sh` copies updated `database/` files into `/opt/arkfile/database/` and restarts services. The app's startup then re-runs `createTables()` — but on an existing rqlite database, the `CREATE TABLE IF NOT EXISTS` statements are no-ops. **The newly-added `encrypted_folder_path` and `folder_path_nonce` columns would silently not appear on the live database.**

**Consequence for this project:** any deployment that currently has the pre-v4 schema cannot receive the v4 schema via `test-update.sh`. It must be wiped (`test-deploy.sh`, which does a fresh install) or recreated (`dev-reset.sh` locally). See Section 7 for the concrete deploy plan.

**Future note (out of scope for this project):** introducing a column-evolution mechanism in `database/database.go` (e.g., inspecting `PRAGMA table_info(table_name)` and emitting conditional `ALTER TABLE` statements for known additions, or adopting a minimal migrations runner) would remove this constraint for future schema-adding projects. That is deliberately not pursued here — it is its own small infrastructure project, unrelated to folders/multi-upload, and conflating the two would muddy the review. Section 9 records it as a deferred item.

---

## 5. Work Items by Phase

Four phases. Each phase ships as a coherent unit and ends with an explicit **unit-test gate** before moving to the next. Within a phase, items are listed in dependency order and may be batched in one or more PRs.

- **Phase A** — Shared primitives (no runtime behavior yet). Ends with TS + Go unit tests on canonicalization and AAD helpers, both driven by the shared test-vectors file.
- **Phase B** — Server surface (endpoints, SQL sites, concurrency cap, quota). Ends with Go handler tests.
- **Phase C** — Client features (TS web + Go CLI, paired). Encrypt/decrypt paths for all four AAD-bound fields ship here. Ends with TS + Go unit tests on AAD round-trips, folder upload logic, tree rendering, and containment checks.
- **Phase D** — Integration and browser tests (`e2e-test.sh` + `e2e-playwright.ts`). No new unit tests — exercises what A/B/C built.

**Guiding principle for ordering:** each item's encrypt path ships together with its decrypt path in the same PR. There is never a shipped state where a new field can be written but not read, or read but not written.

---

### Phase A — Shared Primitives

Goal: land all the pieces that every downstream phase depends on. None of these items changes runtime behavior on their own.

#### A1. Schema additions to `unified_schema.sql`

**Prereq:** none.

Add two nullable columns to each of the two affected tables in `database/unified_schema.sql`:

- `file_metadata`:
  - `encrypted_folder_path TEXT`
  - `folder_path_nonce TEXT`
- `upload_sessions`:
  - `encrypted_folder_path TEXT`
  - `folder_path_nonce TEXT`

Both columns are nullable with no default value. A fresh `dev-reset.sh` applies these cleanly (the whole schema is `CREATE TABLE IF NOT EXISTS` executed against an empty DB).

**Important:** this item, by itself, is useless on an existing `test.arkfile.net` database because of the schema-evolution gap in Finding 4.12. That is expected — the deploy story in Section 7 wipes the beta before the code ships.

**Files touched:** `database/unified_schema.sql`.

#### A2. Immutability / clarification comments

**Prereq:** none.

Pure-comment changes. Land early to make subsequent diffs easier to read.

- `models/user.go`: short header comment noting that username is a permanent, immutable identifier used as a stable key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, `upload_sessions`, and as part of AAD binding for per-file metadata (§ 3.3). No rename path exists; adding one would require re-encrypting all per-file AAD-bound metadata for the renamed user.
- `models/file.go`: clarifying block comment on `FileMetadata.EncryptedFileSha256sum` explaining that despite the `encrypted_` prefix this column stores a **plaintext server-computed SHA-256** over the already-client-encrypted chunk stream (pre-padding), and is therefore **not** in AAD scope.

**Files touched:** `models/user.go`, `models/file.go`.

#### A3. Shared-params JSON file

**Prereq:** none.

One new file, loaded by both TS and Go via the same pattern used for `crypto/argon2id-params.json`, `crypto/chunking-params.json`, and `crypto/password-requirements.json`.

- `crypto/folder-path-params.json` — defines the rules table from § 3.2:
  - `max_depth` (integer, = 32)
  - `max_segment_bytes` (integer, = 255)
  - `max_total_bytes` (integer, = 1024)
  - `forbidden_chars_per_segment` (array of code points, covering `/`, `\`, NUL, control chars `0x00`–`0x1F`)
  - `unicode_normalization` (string, = `"NFC"`)
  - `separator` (string, = `"/"`)
  - `allow_empty` (boolean, = `true`)
  - `allow_leading_slash` (boolean, = `false`)
  - `allow_trailing_slash` (boolean, = `false`)
  - `allow_empty_segment` (boolean, = `false`)
  - `allow_dot_segments` (boolean, = `false`)
  - `padding_bucket_bytes` (integer, = 64) — bucket size for the folder-path NUL-pad described in § 3.3.

The AAD field tags and separator byte from § 3.3 are **not** in JSON — they are language-level constants in `crypto/aad.go` and `client/static/js/src/crypto/aad.ts` (see § 3.3 and Phase A item A5). They are part of the on-the-wire ciphertext contract and a JSON indirection would only obscure a hard-fork rename event, not enable a safe one.

Nothing consumes this file yet; it is read by A4.

**Files touched (new):** `crypto/folder-path-params.json`.

#### A4. Canonicalization helpers (Go + TS)

**Prereq:** A3.

Two mirrored helpers, each driven entirely by A3's JSON rules.

- Go CLI: `cmd/arkfile-client/folderpath.go` (new file).
  - `func CanonicalizeFolderPath(input string) (string, error)` — applies NFC normalization, splits on `/`, validates each segment against the rules, re-joins, returns the canonical form. Returns a typed error for each rule violation (one of a small set of exported error values or a shared error type carrying an error code string).
  - `func ValidateFolderPath(path string) error` — non-mutating validator (accepts an already-canonical path and returns nil or an error). Used by § 5 Phase C item C12's belt-and-suspenders check.
- TS: `client/static/js/src/files/folder-path.ts` (new file).
  - `canonicalizeFolderPath(input: string): string` — throws a typed error on rule violations.
  - `validateFolderPath(path: string): {ok: boolean, code?: string, message?: string}` — non-throwing validator suitable for inline UI feedback (§ 3.11, § 5 Phase C item C4/C5).
  - Error codes are identical string tokens to the Go side (e.g., `"FP_DOT_SEGMENT"`, `"FP_SEGMENT_TOO_LONG"`, `"FP_DEPTH_EXCEEDED"`, `"FP_FORBIDDEN_CHAR"`, `"FP_LEADING_SLASH"`, `"FP_TRAILING_SLASH"`, `"FP_EMPTY_SEGMENT"`, `"FP_TOTAL_TOO_LONG"`).

Not wired into any existing code path yet. Phase C consumes them.

**Files touched (new):** `cmd/arkfile-client/folderpath.go`, `client/static/js/src/files/folder-path.ts`.

#### A5. AAD helper (Go + TS)

**Prereq:** none (no JSON dependency).

Two mirrored helpers, with field tags and separator byte hardcoded as language-level constants. See § 3.3 for the full code listings; this item ships those files verbatim.

- Go: `crypto/aad.go` (new file). Exports `AADFieldFolderPath`, `AADFieldFilename`, `AADFieldSha256sum`, `AADFieldFEK` constants and `BuildFileMetadataAAD(field, fileID, username string) []byte`. Placement alongside `crypto/gcm.go`, `crypto/share_kdf.go`. Pure helper with no server state dependency. The CLI imports `crypto/` directly.
- TS: `client/static/js/src/crypto/aad.ts` (new file). Exports `AAD_FIELD` const object, `AADField` type, and `buildFileMetadataAAD(field, fileID, username): Uint8Array`. Placed alongside `src/crypto/aes-gcm.ts`, `src/crypto/file-encryption.ts`, `src/crypto/metadata-helpers.ts`.

Both implementations must produce byte-identical output for the same inputs — proved by A6's shared test vectors.

Dead code at rest after this item. Phase C is the first consumer.

**Files touched (new):** `crypto/aad.go`, `client/static/js/src/crypto/aad.ts`.

#### A6. Shared test-vectors JSON

**Prereq:** A4, A5.

Single authoritative file used by both TS and Go unit tests.

- `scripts/testing/folder-path-test-vectors.json` (new file). A JSON array of test-case objects. Each object has:
  - `description` (string, required) — human-readable name of the case.
  - `kind` (string, required) — one of `"canonicalize_ok"`, `"canonicalize_reject"`, `"aad_bytes"`.
  - For `canonicalize_ok`: `input` (string), `canonical_output` (string).
  - For `canonicalize_reject`: `input` (string), `error_code` (string, from the A4 code set).
  - For `aad_bytes`: `field` (string, one of the four AAD tags), `file_id` (string), `username` (string), `expected_aad_hex` (string, lowercase hex of the full AAD bytes).
- For `folder_path_padded` (new in v4): `canonical_input` (string, already canonical), `expected_padded_hex` (string, lowercase hex of the NUL-padded plaintext), `expected_padded_len_bytes` (integer, must be a multiple of 64 and ≥ 64).

Initial vector coverage (not exhaustive; these are the categories — the actual file enumerates specific concrete cases):
- `canonicalize_ok`: empty string → empty string; simple `photos/2025`; mixed-case preserved; NFC fusion of composed vs. decomposed Unicode; exactly 255-byte segment; exactly 32 segments; exactly 1024-byte total.
- `canonicalize_reject`: leading slash, trailing slash, double slash, `.` segment, `..` segment, backslash in segment, NUL byte in segment, control char in segment, 256-byte segment (over limit), 33 segments (over limit), 1025-byte total (over limit).
- `aad_bytes`: all four tags × two file-id samples × two username samples × ASCII-and-Unicode combinations, with the expected hex pre-computed by whoever writes the vectors (and asserted in both runtimes).
- `folder_path_padded`: `""` → 64 bytes (all NUL); `"a"` (1 byte) → 64 bytes; 63-byte path → 64 bytes; 64-byte path → 128 bytes; 65-byte path → 128 bytes; 1024-byte max-length path → 1088 bytes (17 buckets × 64 — ensures the maximum-length plaintext still gets at least one byte of padding).

#### A7. Unit tests gate for Phase A

**Prereq:** A1–A6.

Four new test files, all driven by the A6 shared vectors:

- `crypto/aad_test.go` — loads `scripts/testing/folder-path-test-vectors.json`, iterates `aad_bytes` entries, asserts `hex.EncodeToString(BuildFileMetadataAAD(field, file_id, username)) == expected_aad_hex`.
- `cmd/arkfile-client/folderpath_test.go` — loads the same vectors, iterates `canonicalize_ok` and `canonicalize_reject` entries, asserts `CanonicalizeFolderPath(input)` returns `canonical_output` or the expected `error_code`.
- `client/static/js/src/__tests__/aad.test.ts` — TS mirror of `crypto/aad_test.go`.
- `client/static/js/src/__tests__/folder-path.test.ts` — TS mirror of `cmd/arkfile-client/folderpath_test.go`.

Run gates before declaring Phase A complete:

```
go test ./crypto/... ./cmd/arkfile-client/...
cd client/static/js && bun test
```

Both suites pass. Neither exercises any server code or storage backend. Phase A is purely library-level.

**Files touched (new):** `crypto/aad_test.go`, `cmd/arkfile-client/folderpath_test.go`, `client/static/js/src/__tests__/aad.test.ts`, `client/static/js/src/__tests__/folder-path.test.ts`.

---

### Phase B — Server Surface

Goal: teach the server to accept, persist, and return the new folder-path fields; add the pre-flight quota endpoint; add the concurrent-session cap. All server changes ship as a coherent set and are covered by Go handler tests.

#### B0. HTTP status codes and error-body shape

**Prereq:** none (contract spec for the rest of Phase B).

All new endpoints and updated handlers in this phase return well-known HTTP status codes with a structured JSON error body. The contract:

| Status | When | Error body `error` field |
| --- | --- | --- |
| 200 | Success | (no body, or normal response shape) |
| 400 | Malformed request: invalid UUID format for `file_id`, `encrypted_folder_path` present without `folder_path_nonce`, folder path exceeds documented limits, etc. | `"invalid_request"`, `"invalid_file_id"`, `"folder_path_pair_required"` (one of a small set of stable codes) |
| 401 | Missing or invalid JWT | `"unauthorized"` |
| 403 | Account disabled, approval revoked, TOTP missing on a TOTP-protected route, **or storage quota exceeded** | `"account_disabled"`, `"approval_revoked"`, `"totp_required"`, `"storage_quota_exceeded"` |
| 409 | Client-supplied `file_id` collides with an existing row | `"file_id_collision"` |
| 429 | 2-session concurrent-upload cap tripped | `"concurrent_upload_limit"` |

**Error body shape (all non-200 responses):**

```json
{
  "error":   "<stable_string_code>",
  "message": "<human-readable display text>",
  "details": { /* optional, code-specific structured fields */ }
}
```

**Storage quota example** (most common new error in this project):

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error":   "storage_quota_exceeded",
  "message": "This upload would exceed your storage quota.",
  "details": {
    "request_bytes":   2147483648,
    "available_bytes": 1073741824,
    "limit_bytes":     10737418240
  }
}
```

**Why 403 (not 507) for quota:** RFC 4918's 507 Insufficient Storage is ambiguous between "the server itself is out of disk" and "this user's allowance is full." Major REST APIs (GitHub, Google Drive, Box) settled on `403 Forbidden` + a typed code for per-user quota. v4 follows that convention to avoid the ambiguity. Clients should switch on the structured `error` field, not on the message text.

#### B1. Persist and return `encrypted_folder_path` + `folder_path_nonce` across the three `upload_sessions` SQL sites

**Prereq:** A1 (schema), B0 (status-code contract).

In `handlers/uploads.go`:

1. **`CreateUploadSession`** — update the `INSERT INTO upload_sessions (...)` statement:
   - Add `file_id`, `encrypted_folder_path`, and `folder_path_nonce` to the request body parsing and INSERT bindings.
   - Validate the client-supplied `file_id` per § 4.9: well-formed UUIDv4 (HTTP 400 + `invalid_file_id` if not), no collision with existing `upload_sessions` or `file_metadata` rows (HTTP 409 + `file_id_collision` if already present).
   - Pull `encrypted_folder_path` and `folder_path_nonce` from the request body. Both optional; if absent or empty, bind `sql.NullString{Valid: false}` for each. If one is present but not the other, reject with HTTP 400 + `folder_path_pair_required`.
   - Do **not** canonicalize, decrypt, or inspect the encrypted values server-side. They are opaque ciphertext + nonce bytes from the client's perspective. (Per § 3.5, the server never sees plaintext paths.)
   - The response continues to echo `file_id` back so the client can confirm round-trip correctness.

2. **`GetUploadStatus`** — update the `SELECT` list to include `encrypted_folder_path` and `folder_path_nonce`, add them to the `Scan()` targets, and include them in the JSON response alongside the existing `encrypted_filename` / `filename_nonce` / `encrypted_sha256sum` / `sha256sum_nonce` fields. Both nullable; NULL is serialized as `null` in the response.

3. **`CompleteUpload`** — update the multi-line `SELECT` in the preamble to include the two new fields; carry them as `sql.NullString` through the handler; include them in the final `INSERT INTO file_metadata (...)` statement (also update that INSERT to include the two columns + placeholders).

`UploadChunk` is not touched.

**Files touched:** `handlers/uploads.go`.

#### B2. Request/response shape updates

**Prereq:** B1.

- `handlers/uploads.go`: extend the request body type for `CreateUploadSession`:
  - `file_id` (string, **required**, UUIDv4) — client-generated per § 4.9.
  - `encrypted_folder_path` (string, omitempty)
  - `folder_path_nonce` (string, omitempty)
  - Presence validation per B1 (both or neither for the folder-path pair; UUIDv4 format and non-collision for `file_id`).
- `handlers/files.go`: `ListFiles` and `GetFileMeta` include the two new fields in their response payloads. NULL serializes as `null`. Both `encrypted_` fields are base64 strings per the existing wire convention.
- `models/file.go`: add the two fields to `FileMetadata` as `sql.NullString` (or `*string`, matching whatever existing nullable string pattern is used in the struct). Update any SELECT lists that populate this struct (in `handlers/files.go` and anywhere `SELECT ... FROM file_metadata` is written).

**Files touched:** `handlers/uploads.go`, `handlers/files.go`, `models/file.go`.

#### B3. Server-side 2-in-progress-sessions cap + lazy stale-session cleanup + in-progress-aware quota

**Prereq:** A1, B1 (touches the same table shape and the same handler).

In `handlers/uploads.go` `CreateUploadSession`, before inserting the new session row:

1. **Lazy stale-session cleanup.** Run:
   ```sql
   UPDATE upload_sessions
      SET status = 'abandoned', updated_at = CURRENT_TIMESTAMP
    WHERE owner_username = ?
      AND status = 'in_progress'
      AND expires_at < CURRENT_TIMESTAMP
   ```
   Swallow errors here (log and continue) — if the cleanup fails, the count query below will reflect reality including stale rows; that is at worst a false "cap exceeded."

2. **Concurrent-session cap.** Run `SELECT COUNT(*) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. If the count ≥ 2, return HTTP 429 (`echo.NewHTTPError(http.StatusTooManyRequests, "Maximum 2 concurrent uploads per user. Cancel an existing upload or wait for it to complete.")`).

3. **In-progress-aware quota check.** Replace (or augment) the existing `user.CheckStorageAvailable(request.TotalSize)` with a check that also accounts for `SUM(padded_size)` from in-progress sessions for the same user. Use the same rqlite query shape that `GetUserStorage` in B4 uses — extract into a shared helper (`models/user.go` or a new helper in `handlers/uploads.go`) to avoid drift between the two code sites.

**Files touched:** `handlers/uploads.go` (primarily), optionally `models/user.go` for the shared quota helper.

#### B4. `GET /api/user/storage` endpoint

**Prereq:** A1, B3 (so the quota helper exists and B3 can call it).

- New handler `GetUserStorage(c echo.Context) error` in `handlers/files.go` (or a new file `handlers/storage.go` if the former is growing too large; placement decision is the implementer's).
- Handler body:
  1. Extract username from the JWT via `auth.GetUsernameFromToken(c)`.
  2. Compute `committed := SUM(padded_size) FROM file_metadata WHERE owner_username = ?`. NULL-safe (empty sum → 0).
  3. Compute `in_flight := SUM(padded_size) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. NULL-safe.
  4. `total_bytes := committed + in_flight`.
  5. Compute `has_folder_paths := EXISTS(SELECT 1 FROM file_metadata WHERE owner_username = ? AND encrypted_folder_path IS NOT NULL)`.
  6. Look up the user's storage limit via the existing `models.User.StorageLimit` pathway.
  7. Respond:
     ```json
     {
       "total_bytes":      <int>,
       "limit_bytes":      <int>,
       "available_bytes":  <int>,    // max(0, limit - total)
       "usage_percent":    <float>,
       "has_folder_paths": <bool>    // true iff at least one committed file has a non-NULL folder path
     }
     ```
- Route: add to `handlers/route_config.go`:
  ```go
  totpProtectedGroup.GET("/api/user/storage", GetUserStorage)
  ```
  Place alongside `/api/credits`.

**Why `has_folder_paths` here.** The web frontend uses this on page load to decide whether to default to tree view (§ 3.6). Piggybacking the boolean on this already-fetched response avoids a separate round trip. The `EXISTS` query is cheap; if it ever gets slow on a large-per-user file count, a partial index `CREATE INDEX ... ON file_metadata(owner_username) WHERE encrypted_folder_path IS NOT NULL` is a pure additive optimization (not part of v4). No schema column needed.

**Files touched:** `handlers/files.go` (or new `handlers/storage.go`), `handlers/route_config.go`.

#### B5. Export bundle carries folder-path fields

**Prereq:** A1, B2.

- `handlers/export.go`: extend the per-file entry in the exported JSON bundle to include `encrypted_folder_path` and `folder_path_nonce`. Both optional; NULL omitted from the JSON (or serialized as `null` — pick whichever matches the existing export shape).
- The encrypted body of the export bundle is not changed by this work — only the per-file metadata block at the top of the bundle grows two optional fields.

**Files touched:** `handlers/export.go`.

#### B6. Unit tests gate for Phase B

**Prereq:** B1–B5.

All new tests are Go handler tests using the existing sqlmock-based patterns in `handlers/*_test.go`. No new test harness is needed.

- `handlers/uploads_test.go`:
  - New test: `CreateUploadSession` with folder-path fields present — asserts INSERT bindings include them and the session row's `encrypted_folder_path` / `folder_path_nonce` are set correctly.
  - New test: `CreateUploadSession` with folder-path fields absent — asserts INSERT bindings pass NULL for both columns.
  - New test: `CreateUploadSession` with exactly one of the two fields present — asserts HTTP 400 with the "must be provided together" message.
  - New test: `GetUploadStatus` returns the two fields in the response when set.
  - New test: `CompleteUpload` carries folder-path from `upload_sessions` to `file_metadata`.
  - New test: 2-session cap — create two in-progress sessions via sqlmock, assert the third returns HTTP 429.
  - New test: lazy stale-session cleanup — seed one in-progress session with `expires_at < NOW`, assert it is updated to `abandoned` and the cap check then passes.
  - New test: in-progress-aware quota — seed an in-progress session with `padded_size = X`, attempt to create another with `total_size` such that `X + padded(Y) > limit`, assert HTTP 403 with `{"error": "storage_quota_exceeded"}` and the `details` block populated per § B0.
- `handlers/files_test.go`:
  - New test: `ListFiles` includes the two new fields in the response.
  - New test: `GetFileMeta` includes the two new fields in the response.
  - New test: `GetUserStorage` returns the expected shape with correct sums (committed-only, committed-plus-in-flight, zero-state).
- `handlers/export_test.go`:
  - New test: export bundle for a file with folder-path set includes both fields; export bundle for a root-level file omits (or nulls) both fields.

Run gate:

```
go test ./handlers/...
```

All new tests pass; existing tests still pass. Phase B is complete.

**Files touched (test-only):** `handlers/uploads_test.go`, `handlers/files_test.go`, `handlers/export_test.go`.

---

### Phase C — Client Features

Goal: ship all four AAD-bound client fields, multi-file upload, folder upload, tree view, pre-flight quota, dedup, `--dir`/`--tree`/`--preserve-folders`, and offline-decrypt support — in both the TypeScript web frontend and the Go CLI. Every item pairs TS and Go changes; the order within the phase pairs up each feature's encrypt and decrypt paths so the test suite can always round-trip what it writes.

**Critical invariant for the whole phase:** every AAD construction uses the **client-generated `file_id`** (UUIDv4) for that file (§ 3.3, § 4.9). The same `file_id` is built once locally before any encryption, used as AAD input for all four per-file fields, and passed verbatim into `CreateUploadSession`. The server validates and echoes it back so the client can confirm round-trip correctness.

#### C1. TS: AAD on encrypt paths for all four fields

**Prereq:** A5 (TS AAD helper), A4 (TS canonicalization helper), B1, B2–B4 (server accepts the new fields).

Update the TS encrypt path in `client/static/js/src/files/upload.ts` so each of the four client-encrypted per-file metadata fields carries AAD built via `buildFileMetadataAAD` (§ 3.3).

Per-file flow:

1. Generate `file_id = crypto.randomUUID()` locally (UUIDv4, per § 4.9).
2. Build the four AAD-bound blobs against `file_id` and the logged-in `username`:
   - `folder_path` (if set): Account Key + AAD(tag=`folder_path`, fileID=`<file_id>`, username=`<username>`) + random 12-byte nonce. Encrypt the bucket-padded canonical folder path (§ 3.3 padding scheme).
   - `filename`: Account Key + AAD(tag=`filename`, ...) + random nonce. Encrypt base filename.
   - `sha256sum`: Account Key + AAD(tag=`sha256sum`, ...) + random nonce. Encrypt the client-computed plaintext SHA-256.
   - `fek`: KEK (Account Key when `password_type = account`, Custom Key when `password_type = custom`) + AAD(tag=`fek`, ...) + random nonce. Wrap the random 256-bit FEK, then embed inside the envelope wrapper `[0x01][key_type][nonce][ct][tag]` (envelope header bytes are outside the AAD-protected region; only the wrapped FEK ciphertext carries the AAD binding).
3. Call `CreateUploadSession` with `file_id` plus all four blobs and their nonces (base64). The server validates the UUIDv4 format, checks for collisions, and echoes `file_id` back in the response so the client can assert round-trip correctness (mismatch → abort, retry with a fresh UUID).
4. Proceed with chunked upload as today.

Shared helper placement (implementer's choice):
- If the existing metadata construction is centralized in `client/static/js/src/crypto/metadata-helpers.ts` or `file-encryption.ts`, thread `fileID` + `username` + per-field AAD tag through those helpers.
- Otherwise update the call sites in `upload.ts` directly.

Every call site must receive `fileID` + `username`. Username comes from the logged-in session context; `fileID` is generated locally per file just before the AAD construction.

**Files touched:** `client/static/js/src/files/upload.ts`, `client/static/js/src/crypto/metadata-helpers.ts` and/or `client/static/js/src/crypto/file-encryption.ts` as applicable.


#### C2. TS: AAD on decrypt paths for all four fields

**Prereq:** C1.

Every location that currently decrypts `encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek` needs the AAD input added, plus the new `encrypted_folder_path` decrypt.

- `client/static/js/src/files/list.ts`:
  - When decrypting each file's metadata for display, build AAD with `file_id` + `username` per-field and pass to `aes-gcm.ts`.
  - `file_id` is present in each `ServerFileEntry` from `GET /api/files`. Username is the logged-in user (a constant for the session; resolved once per page load, passed into helpers or read from a context).
- `client/static/js/src/files/download.ts`:
  - Decrypt `encrypted_fek` with AAD (tag = `fek`) when unwrapping the FEK for a download.
  - Decrypt `encrypted_filename` with AAD (tag = `filename`) when computing the download's filename.
  - Decrypt `encrypted_sha256sum` with AAD (tag = `sha256sum`) when performing the post-download integrity check.
- `client/static/js/src/files/streaming-download.ts`: check if it independently decrypts metadata. If so, apply the same AAD updates.
- `client/static/js/src/crypto/metadata-helpers.ts` / `file-encryption.ts`: thread AAD through whatever shared helpers exist.

**Files touched:** `client/static/js/src/files/list.ts`, `client/static/js/src/files/download.ts`, `client/static/js/src/files/streaming-download.ts`, `client/static/js/src/crypto/metadata-helpers.ts` (as applicable).

#### C3. TS: multi-file upload (sequential batch)

**Prereq:** C1 (AAD on encrypt), B4 (`/api/user/storage` endpoint).

- `client/static/index.html`: add the `multiple` attribute to `<input type="file" id="fileInput">`. Add a dedicated folder-upload input (separate element, with `webkitdirectory` — see C5) so the user explicitly chooses between "pick files" and "pick folder."
- `client/static/js/src/files/upload.ts`:
  - Refactor the single-file `handleFileUpload()` into `handleMultiFileUpload()`:
    - Read all files from `fileInput.files`.
    - **Pre-flight quota:** call `GET /api/user/storage`, sum `calculateTotalEncryptedSize(file.size) + padding` over the batch. If `totalRequired > available_bytes`, show a rejection dialog with "This batch needs X MB; you have Y MB available — remove N files" and abort before any work.
    - Resolve the Account Key once (cached per-session via the existing `account-key-cache.ts`).
    - Per file: upload sequentially via the existing per-file pipeline (pre-init → init → chunks → complete), using the cached key. All four AAD-bound blobs are built per-file.
  - **Batch progress UI:**
    - Overall: "Uploading file 3 of 17 — 45% of batch."
    - Per-file: current **base filename only** (never the folder path, to limit what's displayed in logs or screenshots). Reuse the existing per-chunk progress component from `src/ui/progress.ts`.
  - **Partial-failure handling:**
    - On file-level failure (network, validation, quota), log it in a per-file error list, continue with remaining files.
    - At end of batch, show summary: "14 uploaded, 3 failed" with per-file error reasons.
    - **Stop-on-fatal:** abort the batch on any of: HTTP 401 (`unauthorized`, session expired), HTTP 403 with any `error` code (account disabled / approval revoked / TOTP required / `storage_quota_exceeded`), HTTP 429 (`concurrent_upload_limit` — should not happen in sequential mode but treat as fatal). All other failures (network, transient 5xx, per-file validation) are per-file and the batch continues.
  - Tests (see C15 gate): mix of account-password and custom-password file entries in one batch; validates that Account Key is reused and Custom Keys are derived per-file as needed.

**Files touched:** `client/static/index.html`, `client/static/js/src/files/upload.ts`.

#### C4. TS: "Add to virtual folder?" single-file input

**Prereq:** C1, A4 (TS canonicalization), C3 (shared `CreateUploadSession` wiring, since the same request body is reused).

- `client/static/index.html`: add a text input (initially hidden or expanded on a "Show more options" toggle) labeled "Add to virtual folder? (optional)" adjacent to the single-file upload form. Placeholder: "e.g., photos/2025/vacation".
- `client/static/js/src/files/upload.ts`:
  - Read the input value. Empty → no folder path.
  - Non-empty → run through `canonicalizeFolderPath`; on failure, display the error inline with the rule name and error code. Block submission until the input is either canonical or cleared.
  - On canonical value: encrypt with Account Key + AAD (tag = `folder_path`, file_id generated locally per § 4.9), include in the `CreateUploadSession` body.
- `client/static/js/src/files/folder-path.ts` is already in place (A4).

**Files touched:** `client/static/index.html`, `client/static/js/src/files/upload.ts`.

#### C5. TS: folder upload via `webkitdirectory`

**Prereq:** C1, A4, C3.

- `client/static/index.html`: add a second file input (e.g., `<input type="file" id="folderInput" webkitdirectory multiple />`) with its own button label ("Upload folder…"). Display a selected-count summary: "17 files selected across 3 folders."
- `client/static/js/src/files/upload.ts`:
  - On folder input change, enumerate `folderInput.files`. Each file has a `webkitRelativePath` like `photos/2025/vacation/img001.jpg`.
  - For each file:
    - Split `webkitRelativePath` on `/`, drop the last segment (the filename), rejoin for the directory portion.
    - Canonicalize via `canonicalizeFolderPath`. On failure, mark the file as rejected with the rule-violation message and skip it (continue with the rest of the batch).
    - Encrypt the canonical folder path with Account Key + AAD (tag = `folder_path`, file_id generated locally per § 4.9).
    - Encrypt filename, sha256sum, fek with AAD as per C1 (all four built against the same locally-generated `file_id`).
  - Feed the validated-and-prepared batch into the same sequential upload loop from C3.
- **Round-trip sanity check** (not a gate, but useful during implementation): upload a 3-deep folder with 5 files, refresh the page, confirm the tree view renders the same structure.

**Files touched:** `client/static/index.html`, `client/static/js/src/files/upload.ts`.

#### C6. TS: batch dedup by `(filename, canonical_folder_path)` + digest-cache key refinement

**Prereq:** A4, C3.

Two dedup layers:

1. **Pre-flight dedup (batch only, before any hashing).** Before upload starts, group selected files by `(base_filename, canonical_folder_path)`. If any group has more than one entry, prompt the user once per cluster:
   > "N files in this batch have the same name in the same folder. Upload one copy only?  [Yes, skip duplicates]  [No, upload all]"
   Default action: skip. Free check — no hashing.
2. **In-stream content dedup (refines the existing `src/utils/digest-cache.ts`).** The current cache key is `sha256`. Refine to `(sha256, canonical_folder_path)` so the same bytes into two different virtual folders is allowed, but the same bytes re-uploaded into the same folder is skipped and reported in the batch summary.

**No batch-wide pre-upload hash pass.** Hashing cost scales with total bytes, not file count. Reuse the encrypt-time hash.

**Tree view does no additional dedup.** If the DB somehow ends up with two rows sharing `(canonical_folder_path, filename, sha256)`, both render — we never silently hide data. (`file_id` is the primary key on `file_metadata`, so it cannot collide; the meaningful identity-class for the tree is the user-visible triple.)

**Files touched:** `client/static/js/src/files/upload.ts`, `client/static/js/src/utils/digest-cache.ts`.

#### C7. TS: tree view render, flat/tree toggle, localStorage preference, in-memory cache, pagination

**Prereq:** C2 (decrypt paths with AAD), C3 (so uploaded files have folder paths to render).

In `client/static/js/src/files/list.ts`:

- **Decrypt strategy at fetch time:**
  - For each `ServerFileEntry` returned by `GET /api/files`, decrypt `encrypted_filename`, `encrypted_sha256sum`, and (if present) `encrypted_folder_path`, all with AAD (see C2).
  - Cache the decrypted triple in an in-memory `Map<fileID, DecryptedMeta>` keyed by `file_id`.
- **Tree construction:**
  - Parse canonical folder paths into nested objects. Files with NULL or empty `folder_path` go at the root.
  - Each tree node knows its children (folders and files). Folder nodes show an expand/collapse chevron and a file count.
- **Render:**
  - Build a new collapsible tree component (DOM-level, no new framework). File nodes reuse the existing file-card layout from today's flat view, minimized slightly to fit inside the tree indent.
  - Breadcrumb / current-path indicator above the tree.
- **Flat/tree toggle:**
  - A small button or segment control above the list. Default per § 3.6.
  - Selection persisted in `localStorage` under `arkfile:file-list-view` (no username qualifier; see § 3.6 rationale).
- **Scale thresholds (§ 3.10):**
  - ≤ 1,000 files returned by `GET /api/files`: eagerly decrypt all metadata at load time. No progress indicator needed.
  - \> 1,000 files: paginate via `GET /api/files?limit=&offset=`. Flat view decrypts filenames only for the current page. Tree view decrypts folder paths lazily on node expand.
- **Cache scope:** the `Map` lives at module scope in `list.ts` and is cleared implicitly on page reload / tab close. Never persisted to `sessionStorage` / `localStorage` / IndexedDB.

**Files touched:** `client/static/js/src/files/list.ts`, `client/static/css/styles.css` (tree styles).

#### C8. TS: folder-path in export consumer

**Prereq:** B5 (server includes folder-path in export bundle), C2 (AAD decrypt infrastructure).

- `client/static/js/src/files/export.ts`: extend the export-bundle parser to read the optional `encrypted_folder_path` and `folder_path_nonce` per-file entries. When decrypting per-file metadata as part of a restore preview, decrypt the folder path with AAD (tag = `folder_path`, file_id from the bundle, username from the bundle's owner context).
- Import path is deferred (Section 9); for now just parse and display the decrypted folder path alongside the filename in any bundle-preview UI.

**Files touched:** `client/static/js/src/files/export.ts`.

#### C9. Go CLI: AAD on encrypt paths for all four fields

**Prereq:** A5 (Go AAD helper), A4 (Go canonicalization helper), B1–B4, C1 (parity — same client-generated `file_id` + AAD construction pattern as the TS side).

Mirror of C1 on the CLI side.

- `cmd/arkfile-client/commands.go` / `crypto_utils.go`:
  - Upload command path: generate `file_id := uuid.NewString()` locally per § 4.9 (UUIDv4).
  - Build AAD via `crypto.BuildFileMetadataAAD(field, fileID, username)` for each of the four fields.
  - Encrypt each metadata blob with AES-GCM using the appropriate KEK (Account or Custom for `fek`; Account for the rest) and the per-field AAD. The `folder_path` plaintext goes through the 64-byte bucket padding from § 3.3 before encryption.
  - Submit the `CreateUploadSession` request with `file_id` plus all four encrypted blobs. Verify the server's echo of `file_id` matches what was sent; abort and retry with a fresh UUID on mismatch.
- The CLI and the web frontend must produce byte-identical AAD bytes for the same `(field, file_id, username)` — proved by A6's shared vectors.

**Files touched:** `cmd/arkfile-client/commands.go`, `cmd/arkfile-client/crypto_utils.go`.

#### C10. Go CLI: AAD on decrypt paths for all four fields

**Prereq:** C9.

Mirror of C2.

- `cmd/arkfile-client/commands.go` / `crypto_utils.go`:
  - `list-files`: when decrypting per-file metadata for display (in both flat and `--tree` modes), pass AAD for `filename`, `sha256sum`, and (when present) `folder_path`.
  - `download`: unwrap `encrypted_fek` with AAD; decrypt `encrypted_filename` and `encrypted_sha256sum` with AAD.
  - `offline_decrypt` (see C13) uses the same decrypt helpers.

**Files touched:** `cmd/arkfile-client/commands.go`, `cmd/arkfile-client/crypto_utils.go`.

#### C11. Go CLI: `--dir` flag for `upload`

**Prereq:** A4, A5, B4, C9.

- `cmd/arkfile-client/commands.go`:
  - Add `--dir DIR` flag to the `upload` command. Conflicts with `--file`; exactly one must be given.
  - Walk the directory with `filepath.Walk`, collect regular files (skip symlinks, device files, sockets), produce a list of `{absolutePath, relativeDirPath}` entries where `relativeDirPath` is the portion relative to `DIR` with the OS separator converted to `/` and the filename segment dropped.
  - Canonicalize each `relativeDirPath` via `CanonicalizeFolderPath`. On failure, log the rejection with the error code and the skipped file path, continue with the rest of the batch.
  - **Pre-flight quota:** call `GET /api/user/storage`, sum encrypted+padded sizes, error out with a clear message if the batch won't fit.
  - Upload sequentially via the existing per-file pipeline (pre-init → init → chunks → complete), using the AAD construction from C9 for each file.
  - Per-file progress line: `Uploading 3/17: photos/2025/vacation/img001.jpg (2.3 MB)`.
  - Summary at end: `42 uploaded, 2 rejected (invalid path), 1 failed (network error)`. Exit code 0 on any success, non-zero only if 0 succeeded.

**Files touched:** `cmd/arkfile-client/commands.go`.

#### C12. Go CLI: `--tree`, `--folder PATH`, `--preserve-folders` with containment re-validation

**Prereq:** A4, C10.

- `cmd/arkfile-client/commands.go`:
  - `list-files --tree`: render a `tree`-style ASCII output of the user's files, grouped by decrypted folder path. Default output stays flat (justified by scripting/piping use). Example:
    ```
    /
    +-- photos/
    |   +-- 2025/
    |   |   +-- vacation/
    |   |   |   +-- img001.jpg  (2.3 MB)
    |   |   +-- avatar.png  (45 KB)
    +-- documents/
    |   +-- taxes.pdf  (512 KB)
    +-- backup.tar.gz  (4.1 GB)
    ```
  - `list-files --folder PATH`: filter the listing to files whose decrypted folder path starts with the canonicalized form of `PATH` (treating `PATH` as a prefix with proper segment boundaries — `photos` matches `photos/2025` but not `photosfoo/`). Works with both flat and `--tree` output.
  - `download --preserve-folders`:
    - Without the flag (current behavior): write to `--output PATH` (filename appended if `PATH` is a directory).
    - With the flag: construct the target path as `{output_dir}/{decrypted_folder_path}/{filename}`, creating directories as needed. Print a confirmation prompt before writing:
      ```
      Will save to: /home/user/downloads/photos/2025/vacation/img001.jpg — proceed? (y/N)
      ```
    - `-y` / `--yes` suppresses the prompt for scripting use.
  - **Belt-and-suspenders validation for `--preserve-folders`.**
    - Re-run `ValidateFolderPath` on the **decrypted plaintext** folder path before constructing the filesystem path. Any failure here is hard-fail (decrypt aborts, nothing written). AAD binding on `encrypted_folder_path` already cryptographically prevents an attacker from inserting a crafted path via DB tampering (the attacker does not hold the user's Account Key), so this validation is defense-in-depth against a future canonicalizer bug or bad decrypt, not mitigation for an active attacker.
    - After computing the target path, verify the absolute form is still under `output_dir`: compute `absTarget` and `absOutputDir`, then `rel, err := filepath.Rel(absOutputDir, absTarget)` — reject if `err != nil` or `rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))`. Fail with a clear error if the containment check doesn't hold.

**Files touched:** `cmd/arkfile-client/commands.go`.

#### C13. Go CLI: offline-decrypt bundle-parser extension

**Prereq:** B5, C10.

- `cmd/arkfile-client/offline_decrypt.go`:
  - Update the `bundleMeta` struct to include the two new optional fields (`encrypted_folder_path`, `folder_path_nonce`).
  - In the `decrypt-blob` display path: when decrypting per-file metadata from an export bundle, decrypt the folder path with AAD (tag = `folder_path`, `file_id` from the bundle, `username` from the bundle's owner context). Display it in the output alongside filename and size.

**Files touched:** `cmd/arkfile-client/offline_decrypt.go`.

#### C14. Go CLI: dedup key refinement

**Prereq:** A4, C11.

- `cmd/arkfile-client/dedup.go`: refine the dedup cache key (currently keyed on content hash) to `(sha256, canonical_folder_path)`, mirroring C6.

**Files touched:** `cmd/arkfile-client/dedup.go`.

#### C15. Unit tests gate for Phase C

**Prereq:** C1–C14.

TS and Go unit tests, paired like the production code.

**TS tests (in `client/static/js/src/__tests__/`):**

- Extend `file-encryption.test.ts` (or add `aad-round-trip.test.ts`):
  - For each of the four fields, encrypt a plaintext with a random key + AAD, decrypt with the same AAD, assert round-trip.
  - For each of the four fields, encrypt with one AAD, attempt to decrypt with a different AAD (wrong `file_id` or wrong `field` tag or wrong `username`), assert decrypt fails.
- New `folder-upload.test.ts`:
  - Given a synthetic `File[]` with `webkitRelativePath` values, assert the derived canonical folder paths match expectations.
  - Given a batch with two files at `(name, path)` = `("a.txt", "x/y")` × 2, assert the pre-flight dedup flags the duplicate pair.
  - Given a batch that exceeds quota (mocked `/api/user/storage` response), assert the pre-flight error fires and no `CreateUploadSession` call is made.
- New `tree-view.test.ts`:
  - Synthetic `ServerFileEntry[]` at counts 1, 10, 999, 1000, 1001, 5000. For each:
    - Assert tree construction produces the expected shape (correct nesting, correct file counts at each node).
    - For counts ≤ 1000, assert eager decrypt is triggered.
    - For counts > 1000, assert pagination is used and only the current page's filenames are decrypted.
  - Test the `arkfile:file-list-view` `localStorage` roundtrip (single key, no username qualifier).

**Go tests:**

- Extend `cmd/arkfile-client/crypto_utils_test.go`:
  - AAD round-trip for each of the four fields. Use the shared vectors for input conformance and custom round-trip cases for the full encrypt+decrypt+AAD cycle.
  - Wrong-AAD rejection cases mirroring the TS side.
  - **Folder-path padding round-trip**: drive the `folder_path_padded` vectors from A6 — assert encrypt produces the expected padded plaintext length and that decrypt-then-strip recovers the canonical input exactly.
- Extend `cmd/arkfile-client/folderpath_test.go` with a **belt-and-suspenders `ValidateFolderPath` test set**: hand-crafted inputs that exercise every error code (`FP_DOT_SEGMENT`, `FP_FORBIDDEN_CHAR`, `FP_LEADING_SLASH`, etc.) by calling `ValidateFolderPath` directly. This stands in for the dropped dev-only AAD-bypass endpoint from D1 — the validator is testable in isolation at the unit-test layer, which is the right place for it.
- New `cmd/arkfile-client/commands_test.go`:
  - `--dir` walker: given a synthetic directory tree (created in a temp dir), assert the collected `{abs, relDir}` pairs match expectations, and that rejected paths are enumerated correctly.
  - `--preserve-folders` containment check: construct decrypted folder paths that (a) pass `ValidateFolderPath` and resolve under the output dir, (b) pass `ValidateFolderPath` but would join to a path outside the output dir (attempt). Assert (a) writes, (b) errors with containment-violation message. Use a mocked write sink to observe attempted writes without touching the real FS. (Case (c) — `ValidateFolderPath` failure — is covered by the `folderpath_test.go` extension above.)

Run gates:

```
go test ./crypto/... ./cmd/arkfile-client/... ./handlers/...
cd client/static/js && bun test
```

All new tests pass; all pre-existing tests (Phase A, Phase B) still pass. Phase C is complete.

**Files touched (test-only):** `client/static/js/src/__tests__/file-encryption.test.ts` (extensions), `client/static/js/src/__tests__/folder-upload.test.ts` (new), `client/static/js/src/__tests__/tree-view.test.ts` (new), `cmd/arkfile-client/crypto_utils_test.go` (extensions), `cmd/arkfile-client/commands_test.go` (new).

---

### Phase D — Integration & Browser Tests

Goal: validate the whole stack end-to-end. No new unit tests or production code here — Phase D exercises what Phases A–C built.

#### D1. `scripts/testing/e2e-test.sh`: multi-file, folder, quota, dedup, tamper, containment

**Prereq:** Phases A–C complete.

Add new test groups to `e2e-test.sh`, following the existing style (`curl` + `arkfile-client`, dev-admin account, dev/test API enabled). Target total file count: ~50 real files with a nested folder structure (about 5 folders, mixed sizes including one medium file to exercise chunking within a batch).

- **Multi-file upload via `curl`.** Upload N files via the `/api/uploads/*` pipeline in a loop, with AAD-bound blobs built via a small helper (or by invoking `arkfile-client` as the oracle). Confirm all N appear in `GET /api/files`.
- **Multi-file upload via `arkfile-client --dir`.** Invoke `arkfile-client upload --dir /tmp/test-folder`. Confirm the expected nested paths round-trip via `arkfile-client list-files --tree`.
- **Folder-path round-trip.** For a known file uploaded via `--dir`, confirm `arkfile-client download --preserve-folders --output /tmp/round-trip` writes the file at the correct nested path and the decrypted bytes match.
- **Pre-flight quota rejection.** Artificially lower the user's `storage_limit_bytes` via the admin API, attempt to upload a batch that exceeds the limit, assert HTTP 403 with `{"error": "storage_quota_exceeded"}` (per § B0) and that no session rows are created.
- **Partial-failure handling.** Upload a batch where one file is deliberately corrupted mid-stream (interrupt mid-chunk). Assert the rest of the batch succeeds and the summary reports the one failure.
- **Export round-trip with folder paths.** Upload several files with folder paths, export, parse the bundle, confirm the folder-path fields are present and decrypt correctly.
- **Canonicalization edge cases.** Attempt to upload with plaintext folder paths that should be rejected by the canonicalizer (`.` segment, `..` segment, NUL byte). Assert the client rejects before any server call.
- **Server-side 2-session cap.** Open two `CreateUploadSession` calls in parallel without completing them, then attempt a third; assert HTTP 429.
- **AAD tamper tests (all four fields).** For each of `encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek`, `encrypted_folder_path`:
  - Upload two files A and B.
  - Directly in rqlite, swap the blob of that field between A and B's rows.
  - Confirm client-side decryption surfaces the AAD-failure error message in both list and download paths, and that the download path refuses to proceed.
- **`download --preserve-folders` containment negative tests.**
  - Tamper `encrypted_folder_path` in rqlite so the AAD check fails (primary defense). Assert the CLI's error message matches the AAD-failure contract.
  - Hand-craft a test case where a decrypted folder path would join to a filesystem path that escapes `output_dir`. Assert the containment check catches it and the CLI writes nothing.
  - Note: the belt-and-suspenders `ValidateFolderPath` check is exercised at the unit-test layer in C15's extension to `cmd/arkfile-client/folderpath_test.go` — no special server endpoint is needed, and v4 deliberately does not introduce an AAD-bypass endpoint (that would itself be an attack surface even when gated by `ADMIN_DEV_TEST_API_ENABLED`).

**Files touched:** `scripts/testing/e2e-test.sh`.

#### D2. `scripts/testing/e2e-playwright.ts`: browser-level folder + tree + tamper

**Prereq:** D1.

Add new Playwright test groups, staying within ~20 total files (reuses what D1 set up; does not re-upload thousands).

- **Browser folder upload.** Drive the `webkitdirectory` input with a synthetic folder of ~10 files across 3 nested folders (Playwright supports this via `setInputFiles` with a directory). Assert the upload completes and all files appear in the tree view.
- **Tree view render.** After D1 uploaded a known structure, load the web app, assert the tree renders the expected nodes, expand/collapse works, breadcrumb updates.
- **Flat/tree toggle + `localStorage` persistence.** Toggle to flat, reload, assert the toggle is remembered. Toggle to tree, reload, same.
- **In-memory cache behavior after tab reload.** Load list, confirm cached decrypt is used on subsequent renders (e.g., by watching for zero re-decrypt calls in an instrumented test). Then reload the page; confirm decrypts happen again.
- **AAD-tamper UI surfacing.** After D1 tampers a row, open the browser, confirm the tree view renders the row with the error message and that clicking download surfaces the same error without crashing the SPA.

**Files touched:** `scripts/testing/e2e-playwright.ts`.

#### D3. End-to-end run gate

**Prereq:** D1, D2, and all of Phases A–C.

Full sequence from a clean state:

```
sudo bash scripts/dev-reset.sh
bash scripts/testing/e2e-test.sh
sudo bash scripts/testing/e2e-playwright.sh
```

All tests pass. Section 7 deploy gate is now reachable.

---

## 6. Files That Will Be Modified

### Backend (Go)

- `database/unified_schema.sql` — add `encrypted_folder_path TEXT` + `folder_path_nonce TEXT` on both `file_metadata` and `upload_sessions`.
- `handlers/uploads.go` — accept client-generated `file_id` (UUIDv4 validation, collision check) plus folder-path fields in `CreateUploadSession`; persist on `upload_sessions`; carry to `file_metadata` on `CompleteUpload`; enforce 2-session concurrency cap; lazy stale-session cleanup; in-progress-aware quota check; structured error responses per § B0.
- `handlers/files.go` — include folder-path fields in `ListFiles` / `GetFileMeta` responses; add `GetUserStorage` handler (or split into new `handlers/storage.go`) returning `total_bytes`/`limit_bytes`/`available_bytes`/`usage_percent`/`has_folder_paths`.
- `handlers/route_config.go` — wire `GET /api/user/storage` into `totpProtectedGroup`.
- `handlers/export.go` — include folder-path fields in export bundle.
- `models/file.go` — add `EncryptedFolderPath` + `FolderPathNonce` fields to `FileMetadata`; clarifying block comment on `EncryptedFileSha256sum` (A2).
- `models/user.go` — short header comment noting username immutability (A2).

### Shared crypto (Go)

- `crypto/aad.go` — new file: generic `BuildFileMetadataAAD(field, fileID, username)`.
- `crypto/aad_test.go` — new file: unit tests driven by the shared test-vectors JSON.

### Frontend (TypeScript)

- `client/static/index.html` — `multiple` attribute on the file input; folder-upload input with `webkitdirectory`; "Add to virtual folder?" text input on single-file form; flat/tree toggle element.
- `client/static/js/src/files/upload.ts` — multi-file loop, folder-path encryption with AAD, client-generated `file_id` (UUIDv4) wiring, pre-flight quota check, "Add to virtual folder?" wiring, folder upload via `webkitdirectory`, batch progress UI, partial-failure handling, opt-in Account-Key-cache extension prompt for long batches (§ 3.13).
- `client/static/js/src/files/list.ts` — AAD-bound decrypt of `filename` / `sha256sum` / `folder_path`; tree building; tree rendering; flat/tree toggle with `localStorage`; in-memory `Map<fileID, DecryptedMeta>` cache; pagination + lazy decrypt above 1,000 files.
- `client/static/js/src/files/download.ts` — AAD-bound unwrap of `encrypted_fek`, AAD-bound decrypt of `encrypted_filename` / `encrypted_sha256sum`.
- `client/static/js/src/files/streaming-download.ts` — same AAD updates as `download.ts` where applicable.
- `client/static/js/src/files/share.ts` — **not modified.** The share-creation path uses the owner's updated unwrap via `download.ts` / `list.ts` automatically (§ 4.11). Recipient-facing decrypt is untouched.
- `client/static/js/src/utils/digest-cache.ts` — refine cache key to `(sha256, canonical_folder_path)` (C6).
- `client/static/js/src/files/folder-path.ts` — new file: `canonicalizeFolderPath`, `validateFolderPath`.
- `client/static/js/src/crypto/aad.ts` — new file: `buildFileMetadataAAD`.
- `client/static/js/src/crypto/metadata-helpers.ts` and/or `file-encryption.ts` — thread AAD inputs through shared metadata construction helpers where centralized.
- `client/static/js/src/files/export.ts` — extend export-bundle parser to handle folder-path fields with AAD.
- `client/static/css/styles.css` — tree component styles.
- `client/static/js/src/types/api.d.ts` — add folder-path fields to `ServerFileEntry`; add `GET /api/user/storage` response type (including `has_folder_paths`); add typed-error-response shape per § B0.
- `client/static/js/src/crypto/account-key-cache.ts` — wire `beforeunload` / `pagehide` listeners and JWT-session-expiry hook into `cleanupAccountKeyCache()`; add the opt-in batch-extension flow per § 3.13.

### CLI (Go)

- `cmd/arkfile-client/commands.go` — `--dir` flag for `upload`; `--tree` and optional `--folder PATH` flags for `list-files`; `--preserve-folders` flag for `download`; client-generated `file_id` (UUIDv4) per file; AAD construction for all four fields; structured-error parsing per § B0.
- `cmd/arkfile-client/crypto_utils.go` — thread AAD inputs into metadata encrypt/decrypt helpers.
- `cmd/arkfile-client/folderpath.go` — new file: `CanonicalizeFolderPath`, `ValidateFolderPath` (mirrors TS).
- `cmd/arkfile-client/folderpath_test.go` — new file: Go unit tests driven by the shared test-vectors JSON.
- `cmd/arkfile-client/offline_decrypt.go` — extend `bundleMeta` struct + `decrypt-blob` display path for the new folder-path fields (C13).
- `cmd/arkfile-client/dedup.go` — refine dedup key to `(sha256, canonical_folder_path)` (C14).
- `cmd/arkfile-client/commands_test.go` — new file: `--dir` walker tests, `--preserve-folders` containment tests.
- The AAD helper is not CLI-local; the CLI imports `crypto/aad.go` directly.

### Config / shared spec

- `crypto/folder-path-params.json` — new file: canonicalization rules and `padding_bucket_bytes` (§ 3.2, § 3.3, A3).
- AAD field tags + separator byte are language-level constants in `crypto/aad.go` and `client/static/js/src/crypto/aad.ts` (no JSON file — see § 3.3 / A3 / A5 for rationale).

### Docs

- `docs/wip/arkbackup-export.md` — add the two new optional folder-path fields and their AAD binding to the bundle-format spec.

### Test assets

- `scripts/testing/folder-path-test-vectors.json` — new file: shared canonicalization and AAD test vectors (authoritative source consumed by both TS and Go unit tests).

### Tests

- `handlers/uploads_test.go` — folder-path field handling in `CreateUploadSession` / `CompleteUpload`; 2-session cap enforcement; stale-session cleanup; in-progress-aware quota with `storage_quota_exceeded` error code; client-supplied `file_id` validation (UUIDv4 format and collision-rejection).
- `handlers/files_test.go` — folder-path in list/meta responses; `GetUserStorage` endpoint tests.
- `handlers/export_test.go` — folder-path included in export bundle.
- `scripts/testing/e2e-test.sh` — multi-file upload tests, folder-path round-trip, pre-flight quota rejection, partial-failure handling, export round-trip, canonicalization edge cases, 2-session cap, AAD tamper tests (all four fields), `--preserve-folders` containment negative tests.
- `scripts/testing/e2e-playwright.ts` — browser-level folder upload, tree view, flat/tree toggle, `localStorage` persistence, in-memory cache behavior after reload, AAD-tamper UI surfacing.

---

## 7. Deploy & Reset Story

This project introduces a schema change and an AAD-binding change that together make existing file rows undecryptable. Because of the `CREATE TABLE IF NOT EXISTS`-only constraint in `unified_schema.sql` (§ 4.12), a wipe is the only clean path.

### 7.1 Local Development

Standard dev loop:

```
sudo bash scripts/dev-reset.sh
go test ./...
cd client/static/js && bun test
bash scripts/testing/e2e-test.sh
sudo bash scripts/testing/e2e-playwright.sh
```

`dev-reset.sh` wipes all data, rebuilds the app, redeploys, and enables the dev/test API. The schema change lands cleanly because the DB starts empty.

### 7.2 Beta Deployment (`test.arkfile.net`)

**Procedure:** use `scripts/test-deploy.sh` (fresh install), **not** `scripts/test-update.sh`.

Why: `test-update.sh` copies updated `database/` files but relies on the app's startup `createTables()` to apply schema — which is a no-op for adding columns to existing tables (§ 4.12). Using `test-update.sh` here would silently fail to add `encrypted_folder_path` / `folder_path_nonce` to the live rqlite, and every downstream feature in this project would break.

Beta-user notice template (to send out ~1 week before the deploy, and again the day of):

```
Subject: Arkfile beta reset notice — YYYY-MM-DD

Hi Arkfile beta testers,

We are deploying a significant update to test.arkfile.net on YYYY-MM-DD
that introduces folder organization, multi-file upload, and stronger
per-file encryption bindings.

Because this update changes how file metadata is cryptographically bound
to your account, and because Arkfile is still in pre-release with no
backwards-compatibility commitments (see AGENTS.md), we have to wipe
the beta database as part of the deploy. That means:

- Your account will need to be re-registered after the deploy.
- Any files you currently have on test.arkfile.net will be deleted
  from rqlite and from the object store. Please download anything
  you want to keep before YYYY-MM-DD.
- Your local copies of downloaded files are unaffected.
- TOTP secrets and any shared URLs will stop working after the deploy
  (you'll set up a new TOTP after re-registration; any shares you want
  to keep will need to be re-created on re-uploaded files).

If you have any files you want to preserve, download them before the deploy
date. After YYYY-MM-DD the beta will be a fresh, empty instance ready for
folder uploads, multi-file uploads, and the other new features.

Thanks for testing,
The Arkfile team
```

### 7.3 Post-Deploy Verification (Beta)

After `test-deploy.sh` completes, before opening the beta back up:

1. Confirm the admin bootstrap account was created.
2. Run a sanity smoke: re-register as a normal test user via the web UI, enable TOTP, upload a single file to root, upload a 3-file batch into a virtual folder, list files in tree view, download and verify bytes, decrypt `.ark` export bundle.
3. Trip each of: 2-session cap (HTTP 429), pre-flight quota rejection, canonicalization reject (`.` segment, NUL byte).
4. If any of the above fails, roll back via re-deploy of the previous binary + schema; the beta remains down until resolved.

### 7.4 Future Schema-Adding Projects

This deploy story assumes the schema-evolution gap (§ 4.12) remains in place. For the next schema-adding project after this one, the team should decide whether to:

- Continue using `test-deploy.sh` + a beta-reset notice as the standard pattern; or
- Introduce a column-evolution mechanism in `database/database.go` (see Section 9 deferred item).

v4 does not make that decision — it only makes the one-time call for this project.

---

## 8. Privacy Considerations

- **Folder paths are encrypted with AAD binding to `(file_id, field, username)`** (§ 3.3). The server learns nothing about folder structure, names, or hierarchy. `encrypted_folder_path` is AAD-bound from the first row that has it (Phase C).
- **Folder-path ciphertext length is bucketed.** Per § 3.3, plaintext folder paths are NUL-padded to a 64-byte bucket before encryption. The server can still observe which 64-byte bucket a path falls into, but cannot distinguish, e.g., `photos/2025` (11 bytes → bucket 1) from `documents/x` (11 bytes → bucket 1) from any other 1–63-byte path. Reduces a potential 1024-class length leak to 16 classes.
- **Number of files per batch is visible to the server** (N independent `CreateUploadSession` calls). Unavoidable without a more complex batching protocol. The timing pattern of those N calls (and any subsequent `CancelUpload` calls if a batch aborts mid-stream) is also observable as a batch signature, even if no upload completes.
- **Batch size-distribution is observable.** A folder upload via `webkitdirectory` produces a distinctive size histogram (many small files plus a few large) that the server can passively classify as "this was a folder upload, not a hand-picked set" even without seeing folder names. Considered acceptable for v1; documented honestly here.
- **File sizes remain visible** (needed for quota and streaming allocation). Existing deterministic padding already obscures exact sizes.
- **Folder structure (depth, breadth, naming patterns) is hidden** since paths are encrypted per-file with bucket-padded length and AAD-bound ciphertext.
- **`file_id` is client-generated and opaque** (UUIDv4, per § 4.9). It carries no server-secret content and reveals nothing about the user, file, or folder beyond what `CreateUploadSession` would have observed anyway.
- **The pre-flight quota endpoint returns only the user's own storage summary.** No PII. No cross-user information. The new `has_folder_paths` boolean reveals only whether the user has at least one foldered file (a one-bit signal, no folder names or counts). Same JWT auth as every other user-scoped endpoint.
- **Decrypted metadata is held in an in-memory `Map`** scoped to the SPA lifetime — not `sessionStorage`, not `localStorage`, not IndexedDB. This minimizes the blast radius of any future XSS: decrypted plaintext filenames and folder paths never touch a storage API that can be read by arbitrary scripts on the page. The tradeoff is having to re-decrypt after a full page reload, which is acceptable given the sub-second times for libraries under 1,000 files and the lazy-decrypt path for larger libraries.
- **Account Key residency is bounded and user-controlled.** Per § 3.13, the Account Key cache is wiped on logout, JWT session expiry, page navigation, and inactivity timeout. Long batch uploads that would exceed the inactivity timeout require an explicit opt-in to extend the cache for the duration of the batch.
- **Tamper visibility.** AAD on all four fields means that cross-row swaps, cross-field swaps, or cross-user confusion all surface as decryption failures rather than silent wrong-data display. The tamper E2E tests in D1 are the functional proof.

---

## 9. Deferred Items

Each item below is explicitly **out of scope for this project**. One-line notes confirm that the schema / API decisions in v4 do not paint any of them into a corner.

### Multi-file / folder sharing

- Not addressed here. Requires a separate design doc covering envelope format, recipient UX (do they see folder structure?), anonymous-download rate limits.
- **Corner check:** per-file metadata model means "share a folder" is reachable as "iterate files matching a path prefix, build a manifest envelope." No decision in v4 blocks this.

### Move / rename files between folders

- Metadata-only update: new `encrypted_folder_path` + `folder_path_nonce` + same AAD binding (tag = `folder_path`, same file_id). Useful but deferred.
- Would need: new endpoint (e.g., `PATCH /api/files/:fileId/folder-path`), UI ("Move to…" modal, drag-and-drop), CLI (`arkfile-client move --file-id X --to PATH`).
- **Corner check:** since paths are per-file and AAD-bound to `(file_id, field, username)`, a move is always "decrypt old, re-encrypt with same AAD and new plaintext path, PATCH." No decision in v4 blocks this.

### Parallel-across-files upload

- Upload 2–3 files simultaneously rather than strictly sequential. Purely client-side change (TS + Go CLI); the server-side 2-in-progress-sessions cap already accommodates this.
- **Corner check:** the single-file server pipeline is unchanged; a client that opens K ≤ 2 sessions in parallel is already supported by the server.

### Parallel-within-a-file chunk upload

- Significant prerequisites: redesign server streaming SHA-256 to accept out-of-order chunks (or drop server-side linear hashing and rely on client-attested per-chunk hashes); move last-chunk padding from `UploadChunk` into `CompleteUpload`; benchmark rqlite write load; add flood-guard carve-outs; reconsider mobile memory model.
- **Corner check:** none of v4's decisions lock this in or out.

### Lazy metadata decryption for very large libraries

- Already partially handled in C7: pagination and lazy-decrypt above 1,000 files. Further lazy schemes (e.g., virtual scroller that decrypts only visible tree nodes with fine-grained IntersectionObserver tracking) are a natural extension.

### "Download all in this folder as zip" (web)

- Single-file download on web goes to the browser's download folder with the decrypted filename — the browser UX doesn't support per-download folder structure. A future feature could pack the decrypted tree into an in-memory zip client-side and offer it as a single download. Not in this round.

### Column-evolution mechanism in `database/database.go`

- **Directly motivated by § 4.12.** Current `unified_schema.sql` is `CREATE TABLE IF NOT EXISTS`-only and cannot add columns to existing tables. Future schema-adding projects would either require another wipe or this mechanism.
- Minimum viable form: on startup, for each expected-column set defined in a new Go-side manifest, run `PRAGMA table_info(table_name)` against rqlite, compare to the manifest, emit conditional `ALTER TABLE ... ADD COLUMN ...` statements for any missing columns. No row-migration, only additive columns.
- More ambitious: a proper migrations runner (`migrations/0001_add_folder_path.sql`, recorded in a `schema_migrations` table).
- **Corner check:** v4 deliberately does **not** adopt either. Doing so would turn a scoped feature project into a broader infrastructure project. This deferral is explicit so the next project that wants to add a column can decide to tackle it without conflating scopes.

### Import / restore from export bundle

- The export bundle already carries encrypted folder-path fields after B5 (and is parsable client-side after C8 / C13). A matching import path — upload the bundle, re-materialize each file into `file_metadata` + `file_storage_locations`, re-encrypt content into S3 — is a separate project.
- **Corner check:** v4 preserves the information needed to do the restore round-trip; no decision here blocks future import work.

---


