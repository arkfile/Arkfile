# Multi-File Upload and Folder Organization (v2)

Status: WIP / design finalized after discussion. All previously open decisions are resolved (see "Open Decisions" — kept for record). Work is tracked as a flat, dependency-ordered list — no version or phase labels.

## Overview

Two related features for Arkfile:

1. **Multi-file upload.** Allow uploading multiple files at once, or an entire folder at a time, from both the web frontend and `arkfile-client` CLI.
2. **Folder organization.** Display files in a folder hierarchy in the frontend UI and provide `tree`-style listing output in `arkfile-client`.

These features build on top of the existing single-file chunked upload pipeline. No changes to the encryption model, core server upload flow, or storage backend are required.

## Guiding Principles (from AGENTS.md)

- **Zero-knowledge preserved.** Folder structure must never leak to the server. All folder paths are client-side encrypted metadata.
- **Constrained-device friendly.** Must work on a mobile device with ~3 GB RAM for arbitrarily large batches, including uploading a 6 GB file. This means one-chunk-at-a-time streaming per file stays mandatory.
- **Single way to do things per client.** TS frontend and Go CLI functions mirror each other in naming, structure, and logic for upload/list/tree operations.
- **No backward-compatibility cruft.** Greenfield project with no production deployments. Only local dev and the `test.arkfile.net` beta are affected by any schema or crypto changes, and both are cleared/recreatable. No "legacy mode," no per-row version flags, no dual-decrypt paths.

---

## Verification Findings

The following were confirmed by reading the code before finalizing this revision:

- **Username is immutable.** No `UPDATE users SET username ...` path exists anywhere in the codebase. `owner_username` is used as a persistent key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, etc. Using `username` as the stable user identifier in AAD is safe.
- **`/api/uploads/*` is not rate-limited for authed users.** The upload init/chunk/complete endpoints sit in `totpProtectedGroup` with no per-endpoint throttle in `handlers/rate_limiting.go` or `handlers/route_config.go`. Batch upload of hundreds of files will not trip any limit at this layer.
- **`FloodGuardMiddleware` only escalates on 401/404 from unauthenticated requests.** Authenticated, approved users doing sequential batch upload cannot trip it.
- **`handlers/export.go` export struct has a clean extension point.** Adding `encrypted_folder_path` and `folder_path_nonce` (and any other new fields) to the export bundle is additive.
- **Current AAD coverage in the code is narrow.** Only share envelopes use AAD (`share_id || file_id`, no separator). Per-file metadata fields (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_file_sha256sum`, `encrypted_fek`) do **not** currently use AAD. All per-file metadata fields get AAD under this plan (see "Design Decisions § 3").
- **`upload_sessions` has three hand-written SQL call sites in `handlers/uploads.go` that must be updated for new columns.** The `INSERT INTO upload_sessions (...)` in `CreateUploadSession`, the `SELECT ... FROM upload_sessions WHERE id = ?` in `GetUploadStatus`, and the multi-line `SELECT ... FROM upload_sessions WHERE id = ?` used in the `CompleteUpload` preamble. The `UploadChunk` path does not need the new columns (it only validates ownership and chunk number).
- **`CreateUploadSession` does not currently limit concurrent in-progress sessions per user.** Multiple sessions can be created in parallel. A server-side cap is added in Work Item F-1.
- **`padded_size` is computed deterministically at session-init time** from `request.TotalSize` via `utils.NewPaddingCalculator().CalculatePaddedSize(...)`, before any chunk arrives. It is persisted on `upload_sessions` and carried to `file_metadata` at `CompleteUpload` time. This means quota accounting can include in-flight sessions exactly, without estimation.
- **`test-update.sh` preserves data, keys, and config.** Account records, OPAQUE registration, approval status, TOTP secrets, refresh tokens, and contact info are not touched. After the AAD change is deployed via `test-update.sh`, files uploaded before the cutover on `test.arkfile.net` will be undecryptable. Accounts and auth records are preserved.

---

## Current State

### Upload Flow
- The HTML file input is `<input type="file" id="fileInput">` — single file only, no `multiple` attribute, no `webkitdirectory`.
- The frontend `handleFileUpload()` reads `fileInput.files[0]` and calls `uploadFile(file, options)` for exactly one file.
- The backend exposes a per-file pipeline: `POST /api/uploads/init` → `POST /api/uploads/:sessionId/chunks/:chunkNumber` x N → `POST /api/uploads/:sessionId/complete`. Each file is an independent upload session.
- `arkfile-client` takes `--file FILE` (one path) on the upload command.

### File Listing
- `GET /api/files` returns a flat array of file metadata entries per user, plus a `storage` summary block.
- The frontend `displayFiles()` renders a flat list of file cards with name, size, date, actions.
- `arkfile-client list-files` renders a flat numbered list or JSON output.

### Database
- `file_metadata` has no folder/path columns. Files are a flat collection per `owner_username`.
- Filenames are encrypted client-side (`encrypted_filename` + `filename_nonce`). The server cannot see, sort, or filter by filename or path.

### Why Upload Pipeline Is Strictly Sequential (Per File)
The server maintains two running SHA-256 hashes per upload session (`streamingHashStates` and `storedBlobHashStates` in `handlers/uploads.go`) that are **order-dependent**: chunks must arrive in numerical order for the hashes to be correct. Additionally, the last-chunk padding logic in `UploadChunk` assumes the last chunk is hashed last. Parallelizing chunks within a single file would require a redesign of these hashes and of padding placement. See "Deferred Items."

We therefore keep a single file's chunks sequential and batch at the file level.

---

## Design Decisions

### 1. Folder Path Storage: Separate Columns on Two Tables
- `encrypted_folder_path TEXT` + `folder_path_nonce TEXT` added to both:
  - `file_metadata` (final home after `CompleteUpload`).
  - `upload_sessions` (so the path round-trips from `CreateUploadSession` to `CompleteUpload` without requiring the client to resend it).
- Path is the directory portion only (e.g., `photos/2025/vacation`). The filename stays as the file's base name (`img001.jpg`).
- Both columns nullable. `NULL` on either column = "root level" (no folder path).

### 2. Canonical Path Format (Enforced Identically in TS and Go)

Stored plaintext (pre-encryption) path must conform to this canonical form. Both the TS client and the Go CLI reject non-canonical input with identical error codes/strings.

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

Rationale:
- 255-byte segment limit matches POSIX `NAME_MAX` and Windows component limits so any accepted path round-trips safely if users ever download with "preserve structure."
- 32-segment depth covers real-world personal data (photo libraries ~6–8, source trees ~10–15) with headroom.
- 1024-byte total keeps encrypted blob + nonce + tag ~1.1 KB per file.

Implementation:
- TS: `client/static/js/src/files/folder-path.ts` exports `canonicalizeFolderPath(input: string): string` and `validateFolderPath(path: string): Result`.
- Go CLI: `cmd/arkfile-client/folderpath.go` exports `CanonicalizeFolderPath` and `ValidateFolderPath`.
- Both read the same limits from `crypto/folder-path-params.json` (mirrors the loading pattern used for `chunking-params.json`, `argon2id-params.json`, `password-requirements.json`).
- A shared test-vectors file at `scripts/testing/folder-path-test-vectors.json` is authoritative. Both the TS and Go unit tests load it and assert byte-identical canonicalization and AAD bytes. This is the mechanism that prevents the two clients from drifting.

Walker inputs:
- Browser: `file.webkitRelativePath` is split on `/`, the last segment (the filename) is dropped, the remainder is canonicalized.
- CLI: `filepath.Walk` results are converted from the OS separator to `/`, the filename is dropped, the remainder is canonicalized.

If canonicalization fails for a particular file, that file is flagged as rejected in the batch progress UI with the specific rule it violated; the rest of the batch continues.

### 3. AAD Binding for Encrypted Metadata Blobs

Encrypted per-file metadata blobs use AES-GCM with **Additional Authenticated Data (AAD)** that cryptographically binds the ciphertext to a specific file, field, and user.

**AAD construction (byte-identical in TS and Go):**

```
AAD = file_id_bytes || 0x00 || field_name_bytes || 0x00 || username_bytes
```

- `file_id_bytes`: UTF-8 bytes of the `file_id` string.
- `field_name_bytes`: UTF-8 bytes of a short ASCII field tag — one of: `"folder_path"`, `"filename"`, `"sha256sum"`, `"file_sha256sum"`, `"fek"`.
- `username_bytes`: UTF-8 bytes of the owner username (immutable, per Verification Findings).
- `0x00`: NUL separator between fields (NUL is forbidden inside all three values, so the encoding is unambiguous).

**Field tags are defined in `crypto/aad-params.json`** and consumed by both TS and Go via the same shared-params loading pattern as `chunking-params.json`, `argon2id-params.json`, `password-requirements.json`. This prevents string drift between the two clients — if either side ever diverges by one character, every decryption fails and the shared test vectors catch it immediately.

The five tags map to per-file metadata fields as follows:

| Tag | Field | Meaning |
| --- | --- | --- |
| `folder_path` | `encrypted_folder_path` | Directory portion of the path (new in this plan) |
| `filename` | `encrypted_filename` | Base filename |
| `sha256sum` | `encrypted_sha256sum` | SHA-256 of the plaintext file |
| `file_sha256sum` | `encrypted_file_sha256sum` | SHA-256 of the encrypted/stored blob |
| `fek` | `encrypted_fek` | Wrapped File Encryption Key |

**Helper (shared between TS and Go):**

```
BuildFileMetadataAAD(field, file_id, username) -> bytes
```

- TS: `buildFileMetadataAAD(field: string, fileID: string, username: string): Uint8Array`
- Go: `BuildFileMetadataAAD(field, fileID, username string) []byte`

Placement of the helper: `crypto/aad.go` on the Go side; `client/static/js/src/crypto/aad.ts` in the web frontend.

**Encrypt (client):**

```
key        = account_key
nonce      = random 12 bytes
aad        = BuildFileMetadataAAD("folder_path", fileID, username)
(ct, tag)  = AES-GCM-Encrypt(key, nonce, canonicalPath, aad)
send:      nonce, ct||tag   (base64-encoded per existing convention)
```

**Decrypt (client):**

```
aad       = BuildFileMetadataAAD("folder_path", fileID, username)
plaintext = AES-GCM-Decrypt(key, nonce, ct, tag, aad)   // fails if AAD doesn't match
```

What this prevents:
- **Cross-file swap.** Attacker or bug copies file X's metadata blob onto file Y — without AAD this decrypts cleanly with the wrong file's key bindings and silently displays the wrong value.
- **Cross-field swap.** Attacker swaps `encrypted_filename` onto the `encrypted_folder_path` slot (or vice versa). With a field tag in AAD, that decryption fails.
- **Cross-user confusion.** Defense in depth against any code path that accidentally mixes user rows.

Does not prevent (accepted):
- Rollback to a previous ciphertext for the **same** (file_id, field, username) tuple. Would require a monotonic version counter in AAD; overkill.

**Scope: all five per-file metadata fields above get AAD in this round of work.** Existing rows on local dev and `test.arkfile.net` become undecryptable after the cutover; accounts and auth are preserved (see Verification Findings). Chunk ciphertext is intentionally left without AAD — unique per-file random FEKs prevent cross-file chunk substitution at the AES-GCM level, and the server's order-dependent streaming SHA-256 (stored in `encrypted_file_sha256sum`) prevents within-file chunk reordering, so chunk-level AAD would add nothing.

**All five fields use the same construction:** key = account key (the Argon2id-derived Account Key used as KEK), nonce = random 12 bytes per blob, AAD = `BuildFileMetadataAAD(field_tag, file_id, username)`, ciphertext-and-tag = `AES-GCM-Encrypt(key, nonce, plaintext, aad)`. Wire format per field: `nonce` + `ct||tag`, each base64-encoded, sent and stored as separate columns (e.g. `filename_nonce` + `encrypted_filename`). The `encrypt`/`decrypt` pseudocode above uses `"folder_path"` as a concrete example; substitute any of the five field tags and the corresponding plaintext for the other fields.

The existing share-envelope AAD (`share_id || file_id`, no separator) is **not** touched — changing it would break all existing shares. New helpers are NUL-separated; old share AAD is left alone.

### 4. Multi-File Upload: Sequential, One File at a Time
- Files in a batch upload one at a time. The existing single-file pipeline (init → chunks → complete) is used per file.
- Rationale: preserves the constrained-device memory model (one chunk resident), keeps the order-dependent server hash architecture untouched, and avoids rqlite Raft write contention from parallel sessions.
- Parallel-across-files (2–3 concurrent sessions) is a plausible future optimization but deferred; see "Deferred Items."
- Parallel-within-a-file (parallel chunks) is a larger project with real prerequisites; see "Deferred Items."

### 5. Folder Creation Model: Implicit Only
- Folders exist only because files have that path. No empty-folder entities.
- Deleting the last file in a folder makes the folder disappear from the tree.
- No server-side folder state, no folder CRUD endpoints.

### 6. Default File List View
- When any file in the user's listing has a non-NULL folder path: **default to tree view**.
- When all files are at root: default to flat view.
- User can toggle between tree and flat at any time. Toggle preference is remembered in `localStorage` per-user.

### 7. Multi-File Share / Folder Share: Not in This Round
- Single-file sharing only for now.
- Multi-file / folder sharing deferred to a separate design doc. See "Deferred Items."
- The current per-file metadata model does not paint us into a corner: sharing a folder becomes "iterate files whose decrypted path matches a prefix, build a manifest envelope."

### 8. Export / Backup: Include Folder Paths
- The encrypted export bundle format carries `encrypted_folder_path` and `folder_path_nonce` per file.
- Import/restore (if/when implemented) round-trips folder structure.
- Small surgical change to `handlers/export.go` + `client/static/js/src/files/export.ts`.

### 9. Rate Limits & Flood Guard for Batch Uploads
- Confirmed during Verification Findings: no changes needed. `/api/uploads/*` is not per-endpoint throttled for authed users, and `FloodGuardMiddleware` only escalates on 401/404 from unauthenticated requests.

### 10. Pre-flight Quota Endpoint
Add a new lightweight authenticated endpoint:

```
GET /api/user/storage
Response:
{
  "total_bytes":     1234567890,
  "limit_bytes":     10737418240,
  "available_bytes": 9502850350,
  "usage_percent":   11.5
}
```

Rationale:
- Current clients infer storage info as a side-effect of `POST /api/login`, `GET /api/files`, and `POST /api/uploads/:session/complete`. For batch upload we want a cheap, purpose-built "how much room do I have?" primitive that doesn't require fetching the full file list.
- Both web and CLI use this for batch pre-flight: before any hashing/encryption/upload begins, sum `calculateTotalEncryptedSize(file.size) + padding` over the selected files and compare against `available_bytes`. If the batch doesn't fit, show the user "This batch needs X MB; you have Y MB available — remove N files" before any work starts.
- Slots into `totpProtectedGroup` in `handlers/route_config.go` alongside `/api/credits`.

### 11. Tree View Scale Targets
- **Eager decrypt** of all filename + SHA256 + folder-path blobs up to **1,000 files**.
  - Expected: ~3 AES-GCM-Decrypt calls per file on small blobs; on mid-range mobile (~0.5 ms/call) that is ~1.5 s worst case for 1,000 files. No progress indicator needed for eager mode — it is sub-second for typical libraries.
- **Above 1,000 files**: always paginate via `GET /api/files?limit=&offset=` (the API already supports it). Flat view decrypts filenames only for the current page. Tree view decrypts folder paths lazily as the user expands each node.
- **Metadata cache: in-memory `Map<fileID, DecryptedMeta>` scoped to the SPA lifetime.**
  - Rationale: decrypted plaintext in `sessionStorage` or `localStorage` is readable by any script running on the page, including any future XSS. An in-memory `Map` is wiped on tab close or full page reload, which matches the expected security posture for decrypted metadata. The cost is re-decrypting after a refresh, which is acceptable given the sub-second times for typical libraries.

---

## Single-File Upload Ergonomics

The single-file upload form gets an opt-in **"Add to virtual folder?"** text input shipped day one, in the same PR as the multi-file work.

- Empty (default) → file goes to root; `encrypted_folder_path` and `folder_path_nonce` are omitted from the request.
- Non-empty → value is run through the shared canonicalize+validate helper, rejected inline if invalid, otherwise encrypted with the account key + AAD and included in `CreateUploadSession`.

This is cheap (one text input + one optional field in the request) and makes the tree view useful immediately for users who don't do bulk folder uploads. It replaces the "Phase 4 polish, defer" framing from the prior doc.

---

## Work Items

Ordered by dependency, not by ceremony. Each item lists prerequisites. No "phase" / "version" labels.

### A. Schema migration
**Prereq:** none.
- `database/unified_schema.sql`: add `encrypted_folder_path TEXT` and `folder_path_nonce TEXT` to both `file_metadata` and `upload_sessions`. Both columns nullable; no default value needed since new rows always specify them (as NULL if no folder path) and existing rows on `test.arkfile.net` will no longer be decryptable anyway due to the AAD cutover.
- Run `scripts/dev-reset.sh` to apply locally.
- For `test.arkfile.net`: deploy via `scripts/test-update.sh`. Accounts, OPAQUE registration, approval status, TOTP secrets, refresh tokens, and contact info are preserved. Files uploaded before the cutover become undecryptable after the AAD change; no cleanup or migration tooling is planned.

### B. Shared params file
**Prereq:** none.
- `crypto/folder-path-params.json` — defines max depth, max segment length, max total length, forbidden-char ranges, normalization form.
- Follows the existing loading pattern of `chunking-params.json`, `argon2id-params.json`, `password-requirements.json`.

### C. Canonicalization helpers (TS + Go)
**Prereq:** B.
- TS: `client/static/js/src/files/folder-path.ts` — `canonicalizeFolderPath`, `validateFolderPath`.
- Go: `cmd/arkfile-client/folderpath.go` — `CanonicalizeFolderPath`, `ValidateFolderPath`.
- Both load rules from the JSON in B; identical error codes/strings.

### D. Shared test-vectors file + unit tests
**Prereq:** C, E.
- `scripts/testing/folder-path-test-vectors.json` — JSON array of `{description, input, canonical_output OR error_code, aad_field?, aad_file_id?, aad_username?, expected_aad_hex?}`.
- TS unit tests (Jest or equivalent) and Go unit tests (`_test.go`) both load this file and assert byte-identical canonicalization results and byte-identical AAD outputs. This is the mechanism that keeps the two clients from drifting.

### E. AAD helper (TS + Go) + shared field-tag spec
**Prereq:** none.
- Generic helper `BuildFileMetadataAAD(field, file_id, username)`.
- TS file location: `client/static/js/src/crypto/aad.ts` (new file).
- Go file location: `crypto/aad.go` (pure helper, shareable with server-side verification tooling in future).
- Field tags (`folder_path`, `filename`, `sha256sum`, `file_sha256sum`, `fek`) and the AAD separator byte are defined in `crypto/aad-params.json`, consumed by both TS and Go via the same shared-params pattern as `chunking-params.json` / `argon2id-params.json` / `password-requirements.json`. Never hard-code tag strings in either client.
- All five per-file metadata fields are AAD-wrapped at encrypt and AAD-verified at decrypt in this round.

### F. `GET /api/user/storage` endpoint
**Prereq:** none.
- New handler `GetUserStorage` in `handlers/files.go` (or a new file).
- Route wired into `totpProtectedGroup` in `handlers/route_config.go` alongside `/api/credits`.
- `total_bytes` is computed as `SUM(padded_size) FROM file_metadata WHERE owner_username = ?` plus `SUM(padded_size) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. `padded_size` is known at session-init time (see Verification Findings), so the sum is exact, not estimated.
- Go + TS integration tests.

### F-1. Server-side concurrent-upload cap
**Prereq:** A.
- In `handlers/uploads.go` `CreateUploadSession`: before inserting the new session row, run `SELECT COUNT(*) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. If count >= 2, return HTTP 429 (or 409 Conflict) with a clear message ("Maximum 2 concurrent uploads per user. Cancel an existing upload or wait for it to complete.").
- Lazy stale-session cleanup: if any matching session is past `expires_at`, mark it `abandoned` (or `expired`) opportunistically in the same SQL path, then re-check the count. This prevents dead sessions from permanently blocking new uploads when a user closes a tab mid-upload.
- Also update the storage-availability check in `CreateUploadSession` (currently `user.CheckStorageAvailable(request.TotalSize)`) so it includes in-progress session `padded_size` in the "used" total — consistent with Work Item F.
- Rationale: client discipline (web batch upload and CLI `--dir`) is strictly sequential, so normal use never trips the cap. The 2-session headroom accommodates power users with the web app open in two tabs or a CLI running alongside a browser upload. The cap plus exact quota accounting makes it impossible to blow past the user's storage limit via parallel sessions.

### G. Server accepts + persists + returns folder-path fields
**Prereq:** A, C.
- `handlers/uploads.go`: three hand-written SQL statements need the two new columns:
  1. The `INSERT INTO upload_sessions (...) VALUES (...)` in `CreateUploadSession` — add `encrypted_folder_path`, `folder_path_nonce` to column list and bindings.
  2. The `SELECT ... FROM upload_sessions WHERE id = ?` in `GetUploadStatus` — add the two fields to the SELECT list and the receiving variables.
  3. The multi-line `SELECT ... FROM upload_sessions WHERE id = ?` in the `CompleteUpload` preamble — add the two fields to the SELECT list and carry them through to the `file_metadata` INSERT.
- `UploadChunk` is not touched; it only validates ownership and chunk number.
- `CreateUploadSession` accepts optional `encrypted_folder_path` and `folder_path_nonce` in the JSON request body.
- `handlers/files.go`: `ListFiles` and `GetFileMeta` include the two fields in responses.
- `models/file.go`: add the fields to `FileMetadata`.
- Note: the server treats these as opaque blobs and does **not** canonicalize them — the server cannot see the plaintext. Canonicalization is entirely a client-side enforcement.

### H. Export bundle carries folder-path fields
**Prereq:** A, G.
- `handlers/export.go`: add `encrypted_folder_path` + `folder_path_nonce` to the export bundle's JSON metadata header.
- `client/static/js/src/files/export.ts`: mirror the two new fields in the web-side export consumer.
- `cmd/arkfile-client/offline_decrypt.go`: update the `bundleMeta` struct and the `decrypt-blob` display path to parse, decrypt (with AAD), and display the folder path. Bundle parser must accept the new fields as optional so bundles produced before this change still parse (they will simply have no folder path) — though after the AAD cutover the metadata inside them will not decrypt anyway.
- `docs/wip/arkbackup-export.md`: update the bundle format spec to document the two new optional fields and their AAD binding.
- Round-trip test.

### I. Web: multi-file upload (sequential batch)
**Prereq:** F.
- `client/static/index.html`: add `multiple` attribute on the file input.
- `client/static/js/src/files/upload.ts`: refactor `handleFileUpload()` into `handleMultiFileUpload()`.
  - Read all files from `fileInput.files`.
  - Pre-flight: call `GET /api/user/storage`, compute batch total, show error if the batch doesn't fit.
  - Resolve account key once (cached after first derivation).
  - Upload sequentially via existing `uploadFile()`.
- Batch progress UI:
  - Overall: "Uploading file 3 of 17 — 45% of batch."
  - Per-file: current **base filename only** (never the folder path) + chunk progress. Reuse the existing progress overlay component, which already displays `file.name` today.
- Partial-failure handling:
  - On file-level failure (network, validation, quota), log it, continue with remaining files.
  - At end of batch, show summary: "14 uploaded, 3 failed" with per-file error reasons.
  - Stop-on-fatal: if the server returns 403 (approval revoked, global quota), stop the batch.
- Tests: both account-password and custom-password types mixed within a single batch.

### I-a. Batch dedup (pre-flight and in-stream)
**Prereq:** C, I.
- **Pre-flight dedup by `(base filename, canonical_folder_path)`.** Before any upload starts, group selected files by that key. If any group has more than one entry, prompt the user once per cluster: "N files in this batch have the same name in the same folder. Upload one copy only? [Yes, skip duplicates] / [No, upload all]". Default action: skip duplicates. This is a free check — no hashing.
- **In-stream content dedup via the existing `digest-cache.ts`.** The current digest cache dedups by plaintext SHA-256 alone (globally). Refine the cache key to `(sha256, canonical_folder_path)` so that the same content uploaded into two different virtual folders is allowed (user-intent: organize the same file two ways), but the same content re-uploaded into the same folder is skipped and reported in the batch summary.
- **No batch-wide pre-upload hash pass.** Hashing cost scales with total bytes, not file count, and is unbounded for large batches. The existing encrypt-time hash is reused for dedup; no separate pass is added.
- **Tree view does no additional dedup.** If the DB somehow ends up with two rows sharing `(file_id, canonical_folder_path, filename, sha256)` (which the above rules prevent under normal use), both are rendered — we never silently hide data.

### J. Web: "Add to virtual folder?" text input on single-file upload
**Prereq:** C, E, G, I (only for the `CreateUploadSession` wiring).
- One optional text input on the single-file upload form.
- Empty = root, non-empty = canonicalize, validate, encrypt with AAD, include in request.
- Shared UI component with K (same canonicalize-and-reject-inline path).

### K. Web: folder upload via `webkitdirectory`
**Prereq:** C, E, G, I.
- Separate folder-upload button/input using `webkitdirectory`.
- Update file-input label to show selected count: "17 files, 3 folders selected."
- For each selected file:
  - Derive folder path from `file.webkitRelativePath` (drop the filename segment).
  - Canonicalize + validate via shared helper. Invalid files are marked rejected with clear reason; rest of batch continues.
  - Encrypt canonical path with account key and AAD binding.
  - Include `encrypted_folder_path` + `folder_path_nonce` in `CreateUploadSession`.
- Round-trip test: upload a folder, verify file list returns the expected blobs, decrypt round-trips to the same canonical form.

### L. Web: tree view + flat/tree toggle + in-memory cache + pagination
**Prereq:** G, E, C.
- In the files listing fetch, decrypt `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_folder_path` per file, all with AAD verification.
- Build a client-side tree:
  - Parse canonical paths into nested objects.
  - Group files by folder. Files with no folder path go to root.
- Render a collapsible tree component: folder nodes (expand/collapse, file count), file nodes (reuse existing file-card UI), breadcrumb/path indicator.
- Flat/tree toggle with `localStorage` preference persisted per-user.
- In-memory `Map<fileID, DecryptedMeta>` cache. Scope: module-level, lifetime = SPA page lifetime. Cleared implicitly on tab close / full reload. No persistent storage API used.
- **Scale thresholds:**
  - **≤ 1,000 files**: eagerly decrypt all metadata at load time. No progress indicator needed.
  - **> 1,000 files**: always paginate via `GET /api/files?limit=&offset=`. Flat view decrypts filenames only for the current page. Tree view decrypts folder paths lazily when the user expands a node.

### M. CLI: `--dir` flag on upload
**Prereq:** C, E, F, G.
- New flag on the `upload` command; conflicts with `--file`.
- Walk the directory (`filepath.Walk`), collect regular files with relative paths.
- Pre-flight: call `GET /api/user/storage`, sum batch, error out if it won't fit.
- For each file: canonicalize relative path, encrypt with AAD, upload sequentially using the existing single-file pipeline.
- Print per-file progress line (`Uploading 3/17: sub/file.txt …`).
- Summary at end including rejected files and per-file failures.

### N. CLI: `--tree`, `--folder`, `--preserve-folders`
**Prereq:** G, E, C.
- `list-files --tree`: render a `tree`-style output. Default remains flat (justified by scripting/piping).
  ```
  /
  +-- photos/
  |   +-- 2025/
  |   |   +-- vacation/
  |   |   |   +-- img001.jpg  (2.3 MB)
  |   +-- avatar.png  (45 KB)
  +-- documents/
  |   +-- taxes.pdf  (512 KB)
  +-- backup.tar.gz  (4.1 GB)
  ```
- `list-files --folder PATH`: filter listing to a specific subtree.
- `download --preserve-folders`:
  - Without the flag (default): behave as today — output the file at `--output PATH` (filename appended if PATH is a directory).
  - With the flag: construct the target path `{output_dir}/{decrypted_folder_path}/{filename}`, creating directories as needed. Print a confirmation prompt before writing:
    ```
    Will save to: /home/user/downloads/photos/2025/vacation/img001.jpg — proceed? (y/N)
    ```
  - `-y` / `--yes` suppresses the prompt for scripting use.
  - **Belt-and-suspenders validation.** Re-run `ValidateFolderPath` on the decrypted plaintext folder path before constructing the filesystem path, and verify the final joined absolute path is still under `output_dir` (via `filepath.Rel` / absolute-path containment). AAD binding already cryptographically prevents an attacker from inserting a crafted path via DB tampering (the attacker does not have the user's account key), so this is defense-in-depth against a future canonicalizer regression, not mitigation for an active attacker. Fail the download with a clear error if either check fails.

### O. End-to-end tests
**Prereq:** all prior items for their respective paths.

**Testing flow (must be respected):** `dev-reset.sh` first, then `e2e-test.sh`, then `e2e-playwright.sh`.

- `scripts/testing/e2e-test.sh`: multi-file upload via `curl` and `arkfile-client --dir`, folder path round-trip, pre-flight quota rejection, partial-failure handling, export/restore preserves folder structure, canonicalization edge cases, AAD-binding tamper test (manually swap a blob between two files in the DB and confirm decryption fails client-side), server-side max-2-concurrent-session enforcement. Target file count: up to ~50 real files with a nested folder structure (~5 folders, mixed sizes including one medium file to exercise chunking within a batch). This is the primary functional test for batch + folder upload.
- `scripts/testing/e2e-playwright.ts`: browser-level folder upload, tree view, flat/tree toggle, localStorage persistence, in-memory cache behavior after tab reload. Stays **≤ ~20 files** total — leverages what `e2e-test.sh` has already set up rather than creating more. No attempt to reproduce scale behavior in the browser.
- **Scale behavior above 1,000 files is covered only by unit tests** (TS Jest + Go `_test.go`) that feed synthetic mocked `/api/files` responses at counts of 1, 10, 999, 1000, 1001, 5000. No e2e or Playwright test uploads thousands of real files.

---

## Open Decisions (all resolved, kept for record)

### A — AAD scope: RESOLVED as full coverage

All five per-file metadata fields get AAD in this round: `folder_path`, `filename`, `sha256sum`, `file_sha256sum`, `fek`. Existing encrypted metadata on local dev and `test.arkfile.net` becomes undecryptable after the AAD cutover; `test-update.sh` preserves accounts and auth records. No migration tooling is planned.

The rejected options ("folder_path only" and "versioned-per-row `aad_version` column") are not pursued. The latter is the kind of legacy/dual-decrypt tech debt AGENTS.md tells us to avoid.

### B — Go AAD helper placement: RESOLVED as `crypto/aad.go`

Alongside `crypto/gcm.go`, `crypto/share_kdf.go`. Pure helper (no server state dependency), shareable with server-side verification tooling in the future. CLI imports `crypto/` freely.

### C — `models/user.go` immutability comment: RESOLVED as yes

Short header comment noting that username is a permanent, immutable identifier used as a stable key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, and as part of AAD binding for per-file metadata. There is no rename path; adding one would require re-encrypting all per-file AAD-bound metadata.

### D — Field-tag naming in shared JSON: RESOLVED as `crypto/aad-params.json`

Field tags (`folder_path`, `filename`, `sha256sum`, `file_sha256sum`, `fek`) and the AAD separator byte live in `crypto/aad-params.json`, consumed by both TS and Go. Same pattern as `chunking-params.json` / `argon2id-params.json` / `password-requirements.json`. Prevents tag-string drift between the two clients.

### E — Concurrent-upload cap + quota accounting: RESOLVED

- Server-side cap of **2 in-progress upload sessions per user** (see Work Item F-1). Client discipline is strictly sequential (1 at a time); the 2-session headroom accommodates power users with the web app open in two tabs or a CLI running alongside a browser upload.
- Quota accounting includes both committed `file_metadata.padded_size` and in-progress `upload_sessions.padded_size`. `padded_size` is computed deterministically at session-init time, so the sum is exact.

### F — Canonical path case sensitivity: RESOLVED as case-sensitive, NFC-normalized

`Photos/2025` and `photos/2025` are distinct folders. Canonicalization applies NFC Unicode normalization but does not case-fold. Matches POSIX behavior and avoids any server-visible collation rules.

---

## Deferred Items

Each item below is explicitly **out of scope for this round of work**. One-line notes confirm that the schema / API decisions in this doc do not paint any of them into a corner.

### Multi-file / folder sharing
- Not addressed here. Requires a separate design doc covering envelope format, recipient UX (do they see folder structure?), and anonymous-download rate limits.
- **Corner check:** per-file metadata model means "share a folder" is reachable as "iterate files matching a path prefix, build a manifest envelope." No v1 decision blocks this.

### Move / rename files between folders
- Metadata-only update: new `encrypted_folder_path` + `folder_path_nonce` + same AAD binding. Useful but deferred.
- Would need: new endpoint (`PATCH /api/files/:fileId/folder-path`), UI ("Move to…" modal, drag-and-drop), CLI (`arkfile-client move --file-id X --to PATH`).
- **Corner check:** since paths are per-file and AAD-bound to `file_id + username`, a move is always "decrypt old, re-encrypt with same AAD and new path, PATCH." No v1 decision blocks this.

### Parallel-across-files upload
- Upload 2–3 files simultaneously rather than strictly sequential. Purely client-side change (TS + Go CLI), no server changes. Deferred until we see whether sequential feels slow in practice.
- **Corner check:** the single-file server pipeline is unchanged; a client that opens K sessions in parallel is already supported by the server.

### Parallel-within-a-file chunk upload
- Significant prerequisites: redesign server streaming SHA-256 to accept out-of-order chunks (or drop server-side linear hashing entirely and rely on client-attested per-chunk hashes); move last-chunk padding from `UploadChunk` into `CompleteUpload`; benchmark rqlite write load; add flood-guard carve-outs; reconsider mobile memory model.
- **Corner check:** none of the current-round decisions lock this in or out.

### Lazy metadata decryption for very large libraries
- Already partially handled: Work Item L paginates and lazy-decrypts folder paths above 1,000 files. Further lazy schemes (e.g., decrypt only visible tree-view nodes with a virtual scroller) are a natural extension.

### "Download all in this folder as zip" (web)
- Single-file download on web goes to the browser's download folder with the decrypted filename — the browser UX doesn't support per-download folder structure. A future "download folder as zip" feature would pack the decrypted tree into an in-memory zip client-side and offer it as a single download. Not in this round.

---

## Files That Will Be Modified

### Backend (Go)
- `database/unified_schema.sql` — add `encrypted_folder_path`, `folder_path_nonce` columns on both `file_metadata` and `upload_sessions`.
- `handlers/uploads.go` — accept folder path fields in `CreateUploadSession`; persist on `upload_sessions`; carry to `file_metadata` on `CompleteUpload`.
- `handlers/files.go` — include folder path fields in list/meta responses; add `GetUserStorage` handler.
- `handlers/route_config.go` — wire `GET /api/user/storage` into `totpProtectedGroup`.
- `handlers/export.go` — include folder path in export bundle.
- `models/file.go` — add fields to `FileMetadata` struct.
- `models/user.go` — short header comment noting username immutability.

### Shared crypto (Go)
- `crypto/aad.go` — new file: generic `BuildFileMetadataAAD(field, file_id, username)`.
- `crypto/aad_test.go` — new file: unit tests driven by the shared test-vectors JSON.

### Frontend (TypeScript)
- `client/static/index.html` — multi-file input (`multiple`), folder upload button (`webkitdirectory`), "Add to virtual folder?" text input on single-file form.
- `client/static/js/src/files/upload.ts` — multi-file loop, folder path encryption, pre-flight quota check, "Add to virtual folder?" wiring.
- `client/static/js/src/files/list.ts` — tree building, tree rendering, flat/tree toggle, in-memory decrypted-metadata cache, pagination + lazy decrypt above 1000 files.
- `client/static/js/src/files/folder-path.ts` — new file: `canonicalizeFolderPath`, `validateFolderPath`.
- `client/static/js/src/crypto/aad.ts` — new file: `buildFileMetadataAAD`.
- `client/static/js/src/files/export.ts` — plumb folder path fields into export bundle.
- `client/static/css/styles.css` — tree component styles.
- `client/static/js/src/types/api.d.ts` — add folder path fields to `ServerFileEntry`; add `GET /api/user/storage` response type.

### CLI (Go)
- `cmd/arkfile-client/commands.go` — `--dir` flag for upload; `--tree` and optional `--folder PATH` flags for `list-files`; `--preserve-folders` flag for `download`.
- `cmd/arkfile-client/folderpath.go` — new file: `CanonicalizeFolderPath`, `ValidateFolderPath` (mirrors TS).
- `cmd/arkfile-client/folderpath_test.go` — new file: Go unit tests driven by the shared test-vectors JSON.
- `cmd/arkfile-client/offline_decrypt.go` — extend `bundleMeta` + `decrypt-blob` display path for the new folder-path fields (see Work Item H).
- The AAD helper is not CLI-local; the CLI imports `crypto/aad.go` directly.

### Config / shared spec
- `crypto/folder-path-params.json` — new file: max depth / segment length / total length / forbidden char ranges / Unicode normalization form (NFC) flag.
- `crypto/aad-params.json` — new file: per-field AAD tag strings (`folder_path`, `filename`, `sha256sum`, `file_sha256sum`, `fek`) and the AAD separator byte (`0x00`). Consumed by both TS and Go via the shared-params loading pattern.

### Docs
- `docs/wip/arkbackup-export.md` — add the two new optional folder-path fields and their AAD binding to the bundle-format spec.

### Test assets
- `scripts/testing/folder-path-test-vectors.json` — new file: shared canonicalization and AAD test vectors (authoritative source consumed by both TS and Go unit tests).

### Tests
- `scripts/testing/e2e-test.sh` — multi-file upload tests, folder path round-trip, pre-flight quota rejection, AAD tamper test, partial-failure simulation.
- `scripts/testing/e2e-playwright.ts` — browser-level folder upload, tree view, flat/tree toggle, localStorage persistence, in-memory cache behavior after reload.
- `handlers/uploads_test.go` — folder path field handling in `CreateUploadSession` / `CompleteUpload`.
- `handlers/files_test.go` — folder path in list/meta responses; `GetUserStorage` endpoint tests.
- `handlers/export_test.go` — folder path included in export bundle.

---

## Privacy Considerations

- Folder paths are encrypted with the same account key used for other per-file metadata, with AAD binding to `file_id || 0x00 || field || 0x00 || username`. The server learns nothing about folder structure, names, or hierarchy.
- Number of files per batch is visible to the server (N independent upload sessions). Unavoidable without a more complex batching protocol.
- File sizes remain visible (needed for quota). Existing deterministic padding already obscures exact sizes.
- Folder structure (depth, breadth, naming patterns) is hidden since paths are encrypted per-file.
- The pre-flight quota endpoint returns only the user's own storage summary; no PII.
- Decrypted metadata is held in an **in-memory `Map`** scoped to the SPA lifetime — not `sessionStorage`, not `localStorage`, not IndexedDB. This minimizes the blast radius of any future XSS: decrypted plaintext filenames and folder paths never touch a storage API that can be read by arbitrary scripts on the page. The tradeoff is having to re-decrypt after a full page reload, which is acceptable given the sub-second times for libraries under 1,000 files and the lazy-decrypt path for larger libraries.

---
