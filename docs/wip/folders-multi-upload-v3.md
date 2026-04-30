# Multi-File Upload and Folder Organization (v3)

Status: WIP. Supersedes v2 by reordering the work into deployment tranches so that the single breaking change (AAD cutover on pre-existing encrypted metadata fields) is isolated at the very end. Technical design is unchanged from v2; only the work ordering and two explicit splits are new.

## What Changed From v2

- **Deployment-ordered work items.** All non-breaking work comes first, grouped into three tranches deployable to `test.arkfile.net` via `scripts/test-update.sh` with zero impact on existing beta-user files. The fourth tranche contains the one breaking cutover.
- **Split Work Item E** into **E1 (AAD helper rollout, non-breaking)** and **E2 (AAD cutover on existing fields, breaking)**. v2 bundled them, which hid the fact that only the cutover invalidates existing files.
- **Split Work Item L** into **L1 (tree render, non-breaking)** and **L2 (AAD verification on existing metadata fields, part of the cutover)**.
- **New section "Deployment Tranches & Non-Breaking-First Principle"** spells out what breaking means for the beta and how each tranche relates.
- **No technical design changes.** Canonical path rules, AAD construction, per-field tag spec, concurrent-session cap, quota accounting, tree-view scale targets, and privacy analysis are all carried over verbatim from v2.

---

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
- **Non-breaking-first deployment.** Work is ordered so that the maximum possible surface lands before the single AAD-cutover step, keeping beta users' existing files decryptable for as long as possible.

---

## Deployment Tranches & Non-Breaking-First Principle

### What "breaking" means for `test.arkfile.net`

The Verification Findings below confirm that `scripts/test-update.sh` preserves: account records, OPAQUE registration, approval status, TOTP secrets, refresh tokens, and contact info. No code or schema change in this project threatens any of those.

The one and only user-visible destructive event in this project is:

> **Turning on AAD verification when decrypting the pre-existing per-file metadata fields `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_fek`, and turning on AAD binding when encrypting new writes to those fields.**

Once that flips, every file uploaded before the cutover is permanently undecryptable from the client side. Accounts survive; files effectively do not.

**Nothing else in this project breaks existing deployments.** Everything else is either additive (new columns, new endpoint, new helper code, new UI), limited to new fields that have no pre-existing rows (`encrypted_folder_path`), or purely internal (server-side concurrency cap that is never tripped under normal client discipline).

### Tranche structure

- **Tranche 1 — Foundations.** Schema additions, shared params files, canonicalization helpers, AAD helper code, shared test vectors, immutability/clarification comments. Nothing in this tranche is called from any existing code path, so existing beta files continue to encrypt, upload, list, and decrypt exactly as before.
- **Tranche 2 — New Server Surface.** `GET /api/user/storage`, concurrent-upload cap + quota refinement, server acceptance of `encrypted_folder_path` + `folder_path_nonce` on new writes, export bundle extension. All additive. New fields are AAD-bound from birth; there are zero pre-existing rows with these columns set.
- **Tranche 3 — New Client Features.** Multi-file upload, batch dedup, folder upload via `webkitdirectory`, tree view render, flat/tree toggle, in-memory cache, pagination, CLI `--dir` / `--tree` / `--folder` / `--preserve-folders`. **Existing files still decrypt** during this tranche because the decrypt path for the pre-existing fields does not yet require AAD.
- **Tranche 4 — AAD Cutover (breaking).** A single coordinated deploy flips AAD binding on `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_fek` for both encrypt (new writes) and decrypt (all reads). E2E and Playwright tests that depend on post-cutover behavior (tamper test) run here.

### Deploy cadence

- Tranches 1–3 may be deployed in separate `test-update.sh` rounds or together; order is flexible within the tranche, but **no item from tranche 4 may ship before any item from tranches 1–3** without losing the non-breaking guarantee.
- Between tranche 3 and tranche 4, beta users enjoy a period where: folder uploads work, tree view works, multi-file upload works, quota pre-flight works, and all their pre-cutover files still decrypt normally. New files uploaded during this window already carry their AAD-bound `encrypted_folder_path` (if any) but do **not** yet have AAD on `filename` / `sha256sum` / `fek`. Tranche 4 then backfills AAD on those three fields for all **future** writes and enforces it on all reads — causing pre-cutover files to stop decrypting.

---

## Verification Findings

The following were confirmed by reading the code before finalizing this revision:

- **Username is immutable.** No `UPDATE users SET username ...` path exists anywhere in the codebase. `owner_username` is used as a persistent key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, etc. Using `username` as the stable user identifier in AAD is safe.
- **`/api/uploads/*` is not rate-limited for authed users.** The upload init/chunk/complete endpoints sit in `totpProtectedGroup` with no per-endpoint throttle in `handlers/rate_limiting.go` or `handlers/route_config.go`. Batch upload of hundreds of files will not trip any limit at this layer.
- **`FloodGuardMiddleware` only escalates on 401/404 from unauthenticated requests.** Authenticated, approved users doing sequential batch upload cannot trip it.
- **`handlers/export.go` export struct has a clean extension point.** Adding `encrypted_folder_path` and `folder_path_nonce` (and any other new fields) to the export bundle is additive.
- **Current AAD coverage in the code is narrow.** Only share envelopes use AAD (`share_id || file_id`, no separator). Per-file ciphertext metadata fields (`encrypted_filename`, `encrypted_sha256sum`, `encrypted_fek`) do **not** currently use AAD. All client-encrypted per-file metadata fields get AAD under this plan, but only at Tranche 4 for the three pre-existing fields; `encrypted_folder_path` is AAD-bound from birth in Tranche 2. The column `encrypted_file_sha256sum` is **not** in AAD scope despite its name — see the note in § 3 and the comment on `models.File.EncryptedFileSha256sum`.
- **`upload_sessions` has three hand-written SQL call sites in `handlers/uploads.go` that must be updated for new columns.** The `INSERT INTO upload_sessions (...)` in `CreateUploadSession`, the `SELECT ... FROM upload_sessions WHERE id = ?` in `GetUploadStatus`, and the multi-line `SELECT ... FROM upload_sessions WHERE id = ?` used in the `CompleteUpload` preamble. The `UploadChunk` path does not need the new columns.
- **`CreateUploadSession` does not currently limit concurrent in-progress sessions per user.** Multiple sessions can be created in parallel. A server-side cap is added in Work Item T2-b.
- **`padded_size` is computed deterministically at session-init time** from `request.TotalSize` via `utils.NewPaddingCalculator().CalculatePaddedSize(...)`, before any chunk arrives. It is persisted on `upload_sessions` and carried to `file_metadata` at `CompleteUpload` time. This means quota accounting can include in-flight sessions exactly, without estimation.
- **`test-update.sh` preserves data, keys, and config.** Account records, OPAQUE registration, approval status, TOTP secrets, refresh tokens, and contact info are not touched. Tranche 4 is the only step that causes pre-existing files on `test.arkfile.net` to become undecryptable.

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
- `field_name_bytes`: UTF-8 bytes of a short ASCII field tag — one of: `"folder_path"`, `"filename"`, `"sha256sum"`, `"fek"`.
- `username_bytes`: UTF-8 bytes of the owner username (immutable, per Verification Findings).
- `0x00`: NUL separator between fields (NUL is forbidden inside all three values, so the encoding is unambiguous).

**Field tags are defined in `crypto/aad-params.json`** and consumed by both TS and Go via the same shared-params loading pattern as `chunking-params.json`, `argon2id-params.json`, `password-requirements.json`. This prevents string drift between the two clients — if either side ever diverges by one character, every decryption fails and the shared test vectors catch it immediately.

The four tags map to per-file ciphertext metadata fields as follows:

| Tag | Field | Meaning | AAD-bound starting |
| --- | --- | --- | --- |
| `folder_path` | `encrypted_folder_path` | Directory portion of the path (new in this plan) | Tranche 2 (from birth) |
| `filename` | `encrypted_filename` | Base filename | Tranche 4 (cutover) |
| `sha256sum` | `encrypted_sha256sum` | SHA-256 of the plaintext file (client-computed, client-encrypted) | Tranche 4 (cutover) |
| `fek` | `encrypted_fek` | Wrapped File Encryption Key | Tranche 4 (cutover) |

**Not in AAD scope:** the column `file_metadata.encrypted_file_sha256sum` is excluded. Despite the `encrypted_` prefix, its stored value is a **plaintext** SHA-256 computed on the server over the already-client-side-encrypted data stream (pre-padding) as chunks arrive. The server holds it in plaintext by construction, so there is nothing there to protect with AAD. The column keeps its historical name; a clarifying block comment is added to `models.File.EncryptedFileSha256sum` in `models/file.go` so the name does not keep misleading future readers. The related server-side field `stored_blob_sha256sum` (hash of all bytes written to S3 including padding) is likewise plaintext and not in AAD scope.

**Per-field protection rationale.** Each of the four in-scope fields gains a distinct defense from AAD, not just uniformity:

- `folder_path`: cross-row swap would mis-render the tree and, more importantly, cause `download --preserve-folders` in the CLI to write decrypted bytes into an attacker-chosen filesystem location under `output_dir`. AAD plus the explicit re-validation + containment check in Work Item T3-h is belt-and-suspenders.
- `filename`: cross-row swap would cause decrypted bytes of file A to be saved under file B's user-visible name — a confusion-of-identity attack on download. Also underpins the dedup key `(filename, canonical_folder_path)` in Work Item T3-b.
- `sha256sum` (plaintext-file hash): the underlying value is privacy-sensitive (file-fingerprinting risk). Cross-row swap breaks the client-side integrity check that confirms decrypted plaintext matches what was uploaded. AAD binds the integrity record to `(file_id, field, username)`.
- `fek`: the wrapped FEK is the root of the per-file encryption chain. Cross-file FEK substitution without AAD is only caught downstream at per-chunk AEAD tag failure; AAD on the FEK surfaces the fault at the wrapper layer and prevents silent reliance on chunk-level detection. Note that the FEK is wrapped by either the Account Key or the per-file Custom Key depending on `password_type` (envelope `key_type = 0x01` or `0x02`); AAD binding applies uniformly in both cases — the KEK choice is orthogonal to the AAD-verified context (`file_id`, field, username). The other three fields above (`folder_path`, `filename`, `sha256sum`) are always wrapped with the Account Key regardless of the file's `password_type`, per AGENTS.md "File metadata encryption and decryption always uses the Account Key."

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

**Scope: all four client-encrypted per-file metadata fields above get AAD in this round of work.** `encrypted_folder_path` is AAD-bound from the moment it exists (Tranche 2). `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_fek` flip to AAD-bound at the Tranche 4 cutover; until that cutover their encrypt/decrypt paths remain exactly as they are today, so pre-cutover beta files continue to work. After the cutover, pre-cutover rows fail AAD verification and become undecryptable; accounts and auth are preserved (see Verification Findings). Chunk ciphertext is intentionally left without AAD — unique per-file random FEKs prevent cross-file chunk substitution at the AES-GCM level, and the server's order-dependent streaming SHA-256 (stored in plaintext as `encrypted_file_sha256sum`) prevents within-file chunk reordering, so chunk-level AAD would add nothing.

**All four fields use the same construction:** nonce = random 12 bytes per blob, AAD = `BuildFileMetadataAAD(field_tag, file_id, username)`, ciphertext-and-tag = `AES-GCM-Encrypt(key, nonce, plaintext, aad)`. The wrapping key depends on the field: `folder_path`, `filename`, and `sha256sum` always use the Account Key (per AGENTS.md "File metadata encryption and decryption always uses the Account Key"); `fek` uses the Account Key or the per-file Custom Key depending on the file's `password_type`. Wire format per field: `nonce` + `ct||tag`, each base64-encoded, sent and stored as separate columns (e.g. `filename_nonce` + `encrypted_filename`). For `encrypted_fek` specifically, the base64'd `ct||tag` payload sits inside the existing envelope: `[0x01][key_type][nonce][ct][tag]` — the envelope header bytes are outside the AAD-protected region; only the wrapped FEK ciphertext carries the AAD binding. The `encrypt`/`decrypt` pseudocode above uses `"folder_path"` as a concrete example; substitute any of the four field tags and the corresponding plaintext for the other fields.

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

The single-file upload form gets an opt-in **"Add to virtual folder?"** text input shipped in Tranche 3 alongside the multi-file work.

- Empty (default) → file goes to root; `encrypted_folder_path` and `folder_path_nonce` are omitted from the request.
- Non-empty → value is run through the shared canonicalize+validate helper, rejected inline if invalid, otherwise encrypted with the account key + AAD (using the `folder_path` tag, AAD-bound from birth) and included in `CreateUploadSession`.

This is cheap (one text input + one optional field in the request) and makes the tree view useful immediately for users who don't do bulk folder uploads.

---

## Work Items

Work items are grouped into four tranches. Within a tranche, items are listed in dependency order. Items use a `T{tranche}-{letter}` naming scheme so reorderings are unambiguous.

**Non-breaking guarantee.** Every item in Tranches 1, 2, and 3 is deployable to `test.arkfile.net` via `scripts/test-update.sh` without breaking any existing beta-user file. The only tranche that breaks pre-existing files is Tranche 4.

---

### Tranche 1 — Foundations (non-breaking; no user-visible change)

Nothing in this tranche is called from any existing code path. Beta users see no change in behavior.

#### T1-a. Immutability / clarification comments
**Prereq:** none.
- Short header comment on `models/user.go` noting that username is a permanent, immutable identifier used as a stable key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, and (after Tranche 2/4) as part of AAD binding for per-file metadata. No rename path exists; adding one would require re-encrypting all per-file AAD-bound metadata.
- Clarifying block comment on `models.File.EncryptedFileSha256sum` in `models/file.go` explaining that despite the `encrypted_` prefix, this column stores a **plaintext server-computed SHA-256** over the already-client-encrypted chunk stream (pre-padding), and is therefore **not** in AAD scope. Landing this comment early reduces the risk that a future contributor assumes the name reflects reality and adds AAD to it.
- Landing this first (tiny, zero-risk) also makes subsequent diffs easier to read.

#### T1-b. Schema migration
**Prereq:** none.
- `database/unified_schema.sql`: add `encrypted_folder_path TEXT` and `folder_path_nonce TEXT` to both `file_metadata` and `upload_sessions`. Both columns nullable; no default value. Existing rows get NULL.
- Run `scripts/dev-reset.sh` to apply locally.
- Deploy to `test.arkfile.net` via `scripts/test-update.sh`. Accounts, OPAQUE registration, approval status, TOTP secrets, refresh tokens, and contact info are preserved. **Existing files remain decryptable** — this tranche does not touch any existing encrypt/decrypt path.

#### T1-c. Shared params files
**Prereq:** none.
- `crypto/folder-path-params.json` — defines max depth, max segment length, max total length, forbidden-char ranges, Unicode normalization form.
- `crypto/aad-params.json` — defines per-field AAD tag strings (`folder_path`, `filename`, `sha256sum`, `fek`) and the AAD separator byte (`0x00`).
- Both follow the existing loading pattern of `chunking-params.json`, `argon2id-params.json`, `password-requirements.json`.
- Nothing consumes these files yet; they are read by T1-d and T1-e.

#### T1-d. Canonicalization helpers (TS + Go)
**Prereq:** T1-c.
- TS: `client/static/js/src/files/folder-path.ts` — `canonicalizeFolderPath`, `validateFolderPath`.
- Go: `cmd/arkfile-client/folderpath.go` — `CanonicalizeFolderPath`, `ValidateFolderPath`.
- Both load rules from `crypto/folder-path-params.json`; identical error codes/strings.
- Not wired into any existing code path yet (the multi-file and folder-upload UIs that call these helpers land in Tranche 3).

#### T1-e. AAD helper (TS + Go) — **helper only, no existing call sites changed**
**Prereq:** T1-c.
- Generic helper `BuildFileMetadataAAD(field, file_id, username)`.
- TS file location: `client/static/js/src/crypto/aad.ts` (new file).
- Go file location: `crypto/aad.go` (new file; pure helper, shareable with server-side verification tooling in future).
- Field tags (`folder_path`, `filename`, `sha256sum`, `fek`) and the AAD separator byte are read from `crypto/aad-params.json`. Never hard-coded in either client.
- **Critical non-breaking constraint:** this item does **not** modify any of the existing encrypt or decrypt code paths for `encrypted_filename`, `encrypted_sha256sum`, or `encrypted_fek`. The helper is dead code at rest after this item — it is first consumed in Tranche 2 (for the brand-new `encrypted_folder_path` field) and then for the three pre-existing fields only at the Tranche 4 cutover.

#### T1-f. Shared test-vectors file + unit tests
**Prereq:** T1-d, T1-e.
- `scripts/testing/folder-path-test-vectors.json` — JSON array of `{description, input, canonical_output OR error_code, aad_field?, aad_file_id?, aad_username?, expected_aad_hex?}`.
- TS unit tests (Jest or equivalent) and Go unit tests (`_test.go`) both load this file and assert byte-identical canonicalization results and byte-identical AAD outputs. This is the mechanism that keeps the two clients from drifting.
- Tests exercise the helpers in isolation; no production code path depends on the outcome yet.

---

### Tranche 2 — New Server Surface (non-breaking; additive endpoints and fields)

All items in this tranche are additive. Existing clients neither call the new endpoint nor send the new fields, so their behavior is unchanged. New fields on new writes are AAD-bound from birth (applies only to `encrypted_folder_path`); the pre-existing three fields still encrypt/decrypt without AAD until Tranche 4.

#### T2-a. `GET /api/user/storage` endpoint
**Prereq:** none.
- New handler `GetUserStorage` in `handlers/files.go` (or a new file).
- Route wired into `totpProtectedGroup` in `handlers/route_config.go` alongside `/api/credits`.
- `total_bytes` is computed as `SUM(padded_size) FROM file_metadata WHERE owner_username = ?` plus `SUM(padded_size) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. `padded_size` is known at session-init time (see Verification Findings), so the sum is exact, not estimated.
- Response:
  ```
  { "total_bytes": N, "limit_bytes": N, "available_bytes": N, "usage_percent": N }
  ```
- Go unit + integration tests. No TS consumer yet (added in Tranche 3).

#### T2-b. Server-side concurrent-upload cap + in-progress-aware quota
**Prereq:** T1-b (the schema migration touches the same table shape; land after it for a clean diff).
- In `handlers/uploads.go` `CreateUploadSession`: before inserting the new session row, run `SELECT COUNT(*) FROM upload_sessions WHERE owner_username = ? AND status = 'in_progress'`. If count >= 2, return HTTP 429 (or 409 Conflict) with a clear message ("Maximum 2 concurrent uploads per user. Cancel an existing upload or wait for it to complete.").
- Lazy stale-session cleanup: if any matching session is past `expires_at`, mark it `abandoned` (or `expired`) opportunistically in the same SQL path, then re-check the count. Prevents dead sessions from permanently blocking new uploads when a user closes a tab mid-upload.
- Update the storage-availability check in `CreateUploadSession` (currently `user.CheckStorageAvailable(request.TotalSize)`) so "used" includes in-progress session `padded_size` — consistent with T2-a.
- **Non-breaking rationale.** Web uploads one file at a time. CLI runs one `upload` command at a time. In normal beta use the cap of 2 is never hit. The 2-session headroom accommodates power users with the web app open in two tabs, or a CLI running alongside a browser upload. No existing workflow trips the cap.

#### T2-c. Server accepts / persists / returns `encrypted_folder_path` + `folder_path_nonce`
**Prereq:** T1-b.
- `handlers/uploads.go`: update the three hand-written SQL statements that touch `upload_sessions`:
  1. `INSERT INTO upload_sessions (...) VALUES (...)` in `CreateUploadSession` — add `encrypted_folder_path`, `folder_path_nonce` to column list and bindings.
  2. `SELECT ... FROM upload_sessions WHERE id = ?` in `GetUploadStatus` — add the two fields to the SELECT list and the receiving variables.
  3. Multi-line `SELECT ... FROM upload_sessions WHERE id = ?` in the `CompleteUpload` preamble — add the two fields to the SELECT list and carry them through to the `file_metadata` INSERT.
- `UploadChunk` is not touched; it only validates ownership and chunk number.
- `CreateUploadSession` accepts optional `encrypted_folder_path` and `folder_path_nonce` in the JSON request body. Absent = NULL = root level.
- `handlers/files.go`: `ListFiles` and `GetFileMeta` include the two fields in responses (NULL allowed).
- `models/file.go`: add the fields to `FileMetadata`.
- **Server treats these as opaque blobs** and does **not** canonicalize them — the server cannot see the plaintext. Canonicalization is entirely a client-side enforcement.
- **Non-breaking rationale.** Existing clients do not send these fields; they remain NULL for all pre-Tranche-3 uploads. Existing clients that read the list response simply ignore unknown fields. `encrypted_folder_path` is AAD-bound from the first row that has it (there are no pre-existing rows).

#### T2-d. Export bundle carries folder-path fields
**Prereq:** T1-b, T2-c.
- `handlers/export.go`: add `encrypted_folder_path` + `folder_path_nonce` to the export bundle's JSON metadata header (optional fields; NULL-safe).
- `client/static/js/src/files/export.ts`: mirror the two new fields in the web-side export consumer.
- `cmd/arkfile-client/offline_decrypt.go`: update the `bundleMeta` struct and the `decrypt-blob` display path to parse, decrypt (with AAD, using the `folder_path` tag), and display the folder path. Parser accepts the new fields as optional so bundles produced before T2-d still parse (they simply have no folder path).
- `docs/wip/arkbackup-export.md`: update the bundle format spec to document the two new optional fields and their AAD binding.
- Round-trip test: export a file uploaded with a folder path (post-T3-a/c/d), verify the bundle parses, the folder path decrypts, and re-import round-trips (import path is deferred, so this test stops at bundle parse + decrypt).
- **Non-breaking rationale.** Pre-Tranche-3 exports have NULL folder-path fields, which the consumer treats as "root level." Existing decrypt paths for `filename` / `sha256sum` / `fek` remain AAD-free in this tranche.

---

### Tranche 3 — New Client Features (non-breaking; existing files still decrypt)

All client features below either operate exclusively on the new `encrypted_folder_path` field (AAD-bound from birth), or read existing `encrypted_filename` / `encrypted_sha256sum` without requiring AAD on them (so pre-Tranche-4 rows still decrypt). The Tranche 4 cutover is what eventually flips AAD enforcement on those existing fields.

#### T3-a. Web: multi-file upload (sequential batch)
**Prereq:** T1-d, T2-a, T2-c.
- `client/static/index.html`: add `multiple` attribute on the file input.
- `client/static/js/src/files/upload.ts`: refactor `handleFileUpload()` into `handleMultiFileUpload()`.
  - Read all files from `fileInput.files`.
  - Pre-flight: call `GET /api/user/storage`, compute batch total, show error if the batch doesn't fit.
  - Resolve account key once (cached after first derivation).
  - Upload sequentially via existing `uploadFile()`.
- Batch progress UI:
  - Overall: "Uploading file 3 of 17 — 45% of batch."
  - Per-file: current **base filename only** (never the folder path) + chunk progress. Reuse the existing progress overlay component.
- Partial-failure handling:
  - On file-level failure (network, validation, quota), log it, continue with remaining files.
  - At end of batch, show summary: "14 uploaded, 3 failed" with per-file error reasons.
  - Stop-on-fatal: if the server returns 403 (approval revoked, global quota), stop the batch.
- Tests: both account-password and custom-password types mixed within a single batch.
- **Non-breaking rationale.** Existing single-file upload path is unchanged for users who select one file. No existing field changes encrypt/decrypt semantics.

#### T3-b. Batch dedup (pre-flight and in-stream)
**Prereq:** T1-d, T3-a.
- **Pre-flight dedup by `(base filename, canonical_folder_path)`.** Before any upload starts, group selected files by that key. If any group has more than one entry, prompt the user once per cluster: "N files in this batch have the same name in the same folder. Upload one copy only? [Yes, skip duplicates] / [No, upload all]". Default action: skip duplicates. Free check — no hashing.
- **In-stream content dedup via the existing `digest-cache.ts`.** Refine the cache key from `sha256` alone to `(sha256, canonical_folder_path)` so that the same content uploaded into two different virtual folders is allowed, but the same content re-uploaded into the same folder is skipped and reported in the batch summary.
- **No batch-wide pre-upload hash pass.** Hashing cost scales with total bytes, not file count. Reuse the existing encrypt-time hash.
- **Tree view does no additional dedup.** If the DB somehow ends up with two rows sharing `(file_id, canonical_folder_path, filename, sha256)`, both are rendered — we never silently hide data.
- **Non-breaking rationale.** This refines a client-side, ephemeral cache key. For single-file uploads into root (the pre-Tranche-3 status quo), `canonical_folder_path = ""`, so the effective key is identical to today's `sha256` and no user-visible behavior changes for existing workflows.

#### T3-c. Web: "Add to virtual folder?" text input on single-file upload
**Prereq:** T1-d, T1-e, T2-c, T3-a (for the shared `CreateUploadSession` wiring).
- One optional text input on the single-file upload form.
- Empty = root, non-empty = canonicalize, validate, encrypt with AAD (tag = `folder_path`), include in request.
- Shared UI component with T3-d (same canonicalize-and-reject-inline path).

#### T3-d. Web: folder upload via `webkitdirectory`
**Prereq:** T1-d, T1-e, T2-c, T3-a.
- Separate folder-upload button/input using `webkitdirectory`.
- Update file-input label to show selected count: "17 files, 3 folders selected."
- For each selected file:
  - Derive folder path from `file.webkitRelativePath` (drop the filename segment).
  - Canonicalize + validate via shared helper. Invalid files are marked rejected with clear reason; rest of batch continues.
  - Encrypt canonical path with account key and AAD binding (tag = `folder_path`).
  - Include `encrypted_folder_path` + `folder_path_nonce` in `CreateUploadSession`.
- Round-trip test: upload a folder, verify file list returns the expected blobs, decrypt round-trips to the same canonical form.

#### T3-e. Web (L1): tree view render + flat/tree toggle + in-memory cache + pagination (no AAD on existing fields yet)
**Prereq:** T2-c, T1-d, T1-e.
- In the files listing fetch, decrypt:
  - `encrypted_filename` — **without AAD** (Tranche 4 will add AAD here).
  - `encrypted_sha256sum` — **without AAD** (Tranche 4 will add AAD here).
  - `encrypted_folder_path` — **with AAD** (tag = `folder_path`), because this field is AAD-bound from birth.
- Build a client-side tree:
  - Parse canonical paths into nested objects.
  - Group files by folder. Files with no folder path go to root.
- Render a collapsible tree component: folder nodes (expand/collapse, file count), file nodes (reuse existing file-card UI), breadcrumb/path indicator.
- Flat/tree toggle with `localStorage` preference persisted per-user.
- In-memory `Map<fileID, DecryptedMeta>` cache. Scope: module-level, lifetime = SPA page lifetime. Cleared implicitly on tab close / full reload. No persistent storage API used.
- **Scale thresholds:**
  - ≤ 1,000 files: eagerly decrypt all metadata at load time. No progress indicator needed.
  - \> 1,000 files: paginate via `GET /api/files?limit=&offset=`. Flat view decrypts filenames only for the current page. Tree view decrypts folder paths lazily when the user expands a node.
- **Non-breaking rationale.** Pre-Tranche-4 rows have no AAD on `filename` / `sha256sum`; decrypting them without AAD succeeds. New `folder_path` rows always carry AAD; decrypting them with AAD succeeds. Everything renders correctly in this intermediate state.
- **Tranche 4 upgrade note (T4-b):** when AAD enforcement is flipped on, these two decrypt calls in `list.ts` change to pass AAD. The code change is small and localized; no re-architecture.

#### T3-f. CLI: `--dir` flag on upload
**Prereq:** T1-d, T1-e, T2-a, T2-c.
- New flag on the `upload` command; conflicts with `--file`.
- Walk the directory (`filepath.Walk`), collect regular files with relative paths.
- Pre-flight: call `GET /api/user/storage`, sum batch, error out if it won't fit.
- For each file: canonicalize relative path, encrypt with AAD (tag = `folder_path`), upload sequentially using the existing single-file pipeline.
- Print per-file progress line (`Uploading 3/17: sub/file.txt …`).
- Summary at end including rejected files and per-file failures.

#### T3-g. CLI: `--tree`, `--folder`, `--preserve-folders` (list + download, no AAD on existing fields yet)
**Prereq:** T2-c, T1-d, T1-e.
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
  - **Belt-and-suspenders validation.** Re-run `ValidateFolderPath` on the decrypted plaintext folder path before constructing the filesystem path, and verify the final joined absolute path is still under `output_dir` (via `filepath.Rel` / absolute-path containment). AAD binding on `encrypted_folder_path` already cryptographically prevents an attacker from inserting a crafted path via DB tampering (the attacker does not have the user's account key), so this is defense-in-depth against a future canonicalizer regression, not mitigation for an active attacker. Fail the download with a clear error if either check fails.
- Decrypt calls in this item: `encrypted_filename` **without AAD**, `encrypted_sha256sum` **without AAD**, `encrypted_folder_path` **with AAD**. Same rationale as T3-e.

#### T3-h. E2E tests for Tranches 1–3
**Prereq:** all prior items in T1/T2/T3.
- **Testing flow (must be respected):** `dev-reset.sh` first, then `e2e-test.sh`, then `e2e-playwright.sh`.
- `scripts/testing/e2e-test.sh`: multi-file upload via `curl` and `arkfile-client --dir`, folder path round-trip (AAD on `folder_path`), pre-flight quota rejection, partial-failure handling, export/restore preserves folder structure, canonicalization edge cases, server-side max-2-concurrent-session enforcement. Target file count: up to ~50 real files with a nested folder structure (~5 folders, mixed sizes including one medium file to exercise chunking within a batch).
- `scripts/testing/e2e-playwright.ts`: browser-level folder upload, tree view, flat/tree toggle, `localStorage` persistence, in-memory cache behavior after tab reload. Stays ≤ ~20 files total — leverages what `e2e-test.sh` has already set up. No attempt to reproduce scale behavior in the browser.
- **Scale behavior above 1,000 files is covered only by unit tests** (TS Jest + Go `_test.go`) that feed synthetic mocked `/api/files` responses at counts of 1, 10, 999, 1000, 1001, 5000. No e2e or Playwright test uploads thousands of real files.
- **Tamper tests deferred to T4-d.** An AAD-binding tamper test (swap a blob between two files in the DB and confirm client-side decryption fails) only meaningfully tests the Tranche 4 cutover. It does not run here.

---

### Tranche 4 — AAD Cutover (BREAKING; coordinated deploy)

**This is the only tranche that breaks pre-existing files on `test.arkfile.net`.** Accounts, OPAQUE, TOTP, refresh tokens, and contact info are preserved (see Verification Findings), but every file uploaded before this tranche lands becomes permanently undecryptable from the client side, because the decrypt paths for `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_fek` now require AAD that those rows were not written with.

Tranche 4 is intentionally small and should be landed as a single coordinated deploy.

#### T4-a. Flip AAD on existing encrypt paths (`filename`, `sha256sum`, `fek`)
**Prereq:** T1-e, T3-a, T3-c, T3-d, T3-f (i.e., all writers that produce these three fields are in place and can receive the AAD change in one diff).
- In both TS (`client/static/js/src/files/upload.ts`, wherever `encrypted_filename` / `encrypted_sha256sum` / `encrypted_fek` are constructed) and Go CLI (`cmd/arkfile-client/...` upload path):
  - `encrypted_filename`: `aad = BuildFileMetadataAAD("filename", fileID, username)`.
  - `encrypted_sha256sum`: `aad = BuildFileMetadataAAD("sha256sum", fileID, username)`.
  - `encrypted_fek`: `aad = BuildFileMetadataAAD("fek", fileID, username)`, applied to the wrapped-FEK ciphertext inside the existing envelope (`[0x01][key_type][nonce][ct][tag]`). Envelope header bytes are outside the AAD-protected region.
- The `file_id` used in AAD must be the one assigned by the server at `CreateUploadSession` time and echoed back in the response. The client must not synthesize a `file_id` locally.
- Wire format unchanged; only the AAD input to AES-GCM changes.

#### T4-b. Flip AAD on existing decrypt paths (`filename`, `sha256sum`, `fek`)
**Prereq:** T4-a (so that all new writes produce AAD-bound ciphertext before readers begin requiring it) — but in practice these two items land in the same deploy.
- TS: `client/static/js/src/files/list.ts` (and any sibling file listing / detail views), `client/static/js/src/files/download.ts`, `client/static/js/src/files/share.ts`:
  - `encrypted_filename` decrypt: pass `aad = BuildFileMetadataAAD("filename", fileID, username)`.
  - `encrypted_sha256sum` decrypt: pass `aad = BuildFileMetadataAAD("sha256sum", fileID, username)`.
  - `encrypted_fek` decrypt (wrapped-FEK unwrap): pass `aad = BuildFileMetadataAAD("fek", fileID, username)`.
- Go CLI: `cmd/arkfile-client/...` download + list-files + offline_decrypt paths — same three call sites.
- Failure mode: pre-cutover rows fail AES-GCM tag verification and surface as a clear error ("This file was encrypted before an incompatible security upgrade and cannot be decrypted. It remains listed but is no longer readable.") rather than a generic "decryption failed." The tree/flat view continues to render the row (we never silently hide data); individual file actions error out with the above message.
- **Share envelope AAD is NOT touched.** The existing `share_id || file_id` (no separator) AAD remains as-is to keep existing shares working — though shares created before the cutover depend on `encrypted_filename` / `encrypted_sha256sum` from the shared file record, so they will practically fail at the metadata-decrypt step. This is acceptable; shares are ephemeral.

#### T4-c. `list.ts` L2 wiring — AAD verification on existing fields in the tree/flat path
**Prereq:** T4-a, T4-b.
- This is the tree-view-specific slice of T4-b, called out separately because the list decrypt path is the highest-volume consumer and worth explicitly verifying in CI.
- The two decrypt calls in `list.ts` identified in T3-e as "without AAD" now pass AAD.
- No logic change beyond that; the surrounding tree / flat / cache / pagination machinery from T3-e stays as-is.

#### T4-d. AAD tamper E2E test
**Prereq:** T4-a, T4-b, T4-c.
- In `scripts/testing/e2e-test.sh`: after uploading two files A and B, directly swap `encrypted_filename` (or `encrypted_fek`) between the two rows in rqlite. Confirm that both file-list decrypt attempts surface the AAD-failure error message on the client, and that the download path refuses to proceed.
- In `scripts/testing/e2e-playwright.ts`: same swap, browser verifies the error surfaces in the UI without crashing the SPA.
- These tests are only meaningful once AAD enforcement is live. They are the functional proof that the cutover took effect.

#### T4-e. Dev-reset / test-update deploy procedure
**Prereq:** T4-a through T4-d.
- Running `sudo bash scripts/dev-reset.sh` destroys local dev state, so local dev is fine.
- `scripts/test-update.sh` is the procedure used to deploy this tranche to `test.arkfile.net`. Accounts, OPAQUE, TOTP, refresh tokens, approval status, and contact info survive. Pre-cutover file rows remain in the database and in S3 but cannot be decrypted; users see them listed with the "incompatible security upgrade" error on any action. No cleanup tooling is planned for stale pre-cutover rows — the beta is small enough that users can delete-and-reupload on their own cadence.

---

## Open Decisions (all resolved, kept for record)

### A — AAD scope: RESOLVED as all client-encrypted per-file metadata fields

All four client-encrypted per-file metadata fields get AAD in this round: `folder_path`, `filename`, `sha256sum`, `fek`. `encrypted_folder_path` is AAD-bound from birth in Tranche 2. The other three flip at the Tranche 4 cutover. Each has a distinct per-field threat motivation (see § 3 "Per-field protection rationale"), not just uniformity-for-uniformity's-sake. Existing encrypted metadata on local dev and `test.arkfile.net` becomes undecryptable after the Tranche 4 cutover; `test-update.sh` preserves accounts and auth records. No migration tooling is planned.

The column `file_metadata.encrypted_file_sha256sum` is excluded from AAD scope. Despite the `encrypted_` prefix, its stored value is a plaintext server-computed SHA-256 of the already-client-encrypted data stream — there is nothing there to protect with AAD. The column keeps its historical name; a clarifying block comment is added to `models.File.EncryptedFileSha256sum` in `models/file.go` (T1-a).

The rejected options ("folder_path only" and "versioned-per-row `aad_version` column") are not pursued. The latter is the kind of legacy/dual-decrypt tech debt AGENTS.md tells us to avoid.

### B — Go AAD helper placement: RESOLVED as `crypto/aad.go`

Alongside `crypto/gcm.go`, `crypto/share_kdf.go`. Pure helper (no server state dependency), shareable with server-side verification tooling in the future. CLI imports `crypto/` freely.

### C — `models/user.go` immutability comment: RESOLVED as yes

Short header comment noting that username is a permanent, immutable identifier used as a stable key across `file_metadata`, `file_encryption_keys`, `file_storage_locations`, and as part of AAD binding for per-file metadata. There is no rename path; adding one would require re-encrypting all per-file AAD-bound metadata. Landed in T1-a.

### D — Field-tag naming in shared JSON: RESOLVED as `crypto/aad-params.json`

Field tags (`folder_path`, `filename`, `sha256sum`, `fek`) and the AAD separator byte live in `crypto/aad-params.json`, consumed by both TS and Go. Same pattern as `chunking-params.json` / `argon2id-params.json` / `password-requirements.json`. Prevents tag-string drift between the two clients.

### E — Concurrent-upload cap + quota accounting: RESOLVED

- Server-side cap of **2 in-progress upload sessions per user** (see Work Item T2-b). Client discipline is strictly sequential (1 at a time); the 2-session headroom accommodates power users with the web app open in two tabs or a CLI running alongside a browser upload.
- Quota accounting includes both committed `file_metadata.padded_size` and in-progress `upload_sessions.padded_size`. `padded_size` is computed deterministically at session-init time, so the sum is exact.

### F — Canonical path case sensitivity: RESOLVED as case-sensitive, NFC-normalized

`Photos/2025` and `photos/2025` are distinct folders. Canonicalization applies NFC Unicode normalization but does not case-fold. Matches POSIX behavior and avoids any server-visible collation rules.

### G — Work-item ordering: RESOLVED as four deployment tranches

All non-breaking work is grouped into Tranches 1–3 and may be deployed incrementally to `test.arkfile.net` via `test-update.sh` without affecting any existing beta file. Tranche 4 is the single coordinated cutover that turns on AAD for the three pre-existing fields and, as a side effect, invalidates all pre-cutover files for client-side decryption. See "Deployment Tranches & Non-Breaking-First Principle" and the per-tranche work-item lists above.

---

## Deferred Items

Each item below is explicitly **out of scope for this round of work**. One-line notes confirm that the schema / API decisions in this doc do not paint any of them into a corner.

### Multi-file / folder sharing
- Not addressed here. Requires a separate design doc covering envelope format, recipient UX (do they see folder structure?), and anonymous-download rate limits.
- **Corner check:** per-file metadata model means "share a folder" is reachable as "iterate files matching a path prefix, build a manifest envelope." No decision in this doc blocks this.

### Move / rename files between folders
- Metadata-only update: new `encrypted_folder_path` + `folder_path_nonce` + same AAD binding. Useful but deferred.
- Would need: new endpoint (`PATCH /api/files/:fileId/folder-path`), UI ("Move to…" modal, drag-and-drop), CLI (`arkfile-client move --file-id X --to PATH`).
- **Corner check:** since paths are per-file and AAD-bound to `file_id + username`, a move is always "decrypt old, re-encrypt with same AAD and new path, PATCH." No decision in this doc blocks this.

### Parallel-across-files upload
- Upload 2–3 files simultaneously rather than strictly sequential. Purely client-side change (TS + Go CLI), no server changes. Deferred until we see whether sequential feels slow in practice. The server-side concurrent-session cap of 2 is the only constraint, and it was chosen to accommodate this future work without a second round of server changes.
- **Corner check:** the single-file server pipeline is unchanged; a client that opens K ≤ 2 sessions in parallel is already supported by the server.

### Parallel-within-a-file chunk upload
- Significant prerequisites: redesign server streaming SHA-256 to accept out-of-order chunks (or drop server-side linear hashing entirely and rely on client-attested per-chunk hashes); move last-chunk padding from `UploadChunk` into `CompleteUpload`; benchmark rqlite write load; add flood-guard carve-outs; reconsider mobile memory model.
- **Corner check:** none of the current-round decisions lock this in or out.

### Lazy metadata decryption for very large libraries
- Already partially handled: Work Item T3-e paginates and lazy-decrypts folder paths above 1,000 files. Further lazy schemes (e.g., decrypt only visible tree-view nodes with a virtual scroller) are a natural extension.

### "Download all in this folder as zip" (web)
- Single-file download on web goes to the browser's download folder with the decrypted filename — the browser UX doesn't support per-download folder structure. A future "download folder as zip" feature would pack the decrypted tree into an in-memory zip client-side and offer it as a single download. Not in this round.

### Cleanup tooling for pre-Tranche-4 rows
- After the Tranche 4 cutover, pre-cutover rows remain in rqlite and in S3 but are permanently undecryptable. No tooling is planned to bulk-delete them; users can delete-and-reupload at their own cadence, and the beta is small enough that this is tractable. A future "prune undecryptable rows" admin script could be added but is explicitly deferred.

---

## Files That Will Be Modified

### Backend (Go)
- `database/unified_schema.sql` — add `encrypted_folder_path`, `folder_path_nonce` columns on both `file_metadata` and `upload_sessions`.
- `handlers/uploads.go` — accept folder path fields in `CreateUploadSession`; persist on `upload_sessions`; carry to `file_metadata` on `CompleteUpload`; enforce 2-session concurrency cap; lazy stale-session cleanup; in-progress-aware quota check.
- `handlers/files.go` — include folder path fields in list/meta responses; add `GetUserStorage` handler.
- `handlers/route_config.go` — wire `GET /api/user/storage` into `totpProtectedGroup`.
- `handlers/export.go` — include folder path in export bundle.
- `models/file.go` — add fields to `FileMetadata` struct; clarifying comment on `EncryptedFileSha256sum`.
- `models/user.go` — short header comment noting username immutability.

### Shared crypto (Go)
- `crypto/aad.go` — new file: generic `BuildFileMetadataAAD(field, file_id, username)`.
- `crypto/aad_test.go` — new file: unit tests driven by the shared test-vectors JSON.

### Frontend (TypeScript)
- `client/static/index.html` — multi-file input (`multiple`), folder upload button (`webkitdirectory`), "Add to virtual folder?" text input on single-file form.
- `client/static/js/src/files/upload.ts` — multi-file loop, folder path encryption (with AAD from Tranche 3 onward), pre-flight quota check, "Add to virtual folder?" wiring. Tranche 4 changes the AAD inputs for `encrypted_filename` / `encrypted_sha256sum` / `encrypted_fek` construction.
- `client/static/js/src/files/list.ts` — tree building, tree rendering, flat/tree toggle, in-memory decrypted-metadata cache, pagination + lazy decrypt above 1,000 files. Tranche 4 changes the AAD inputs for `encrypted_filename` / `encrypted_sha256sum` decrypt.
- `client/static/js/src/files/download.ts` — Tranche 4 changes the AAD inputs for `encrypted_fek` unwrap and any metadata decrypts.
- `client/static/js/src/files/share.ts` — Tranche 4 changes the AAD inputs for share-side metadata decrypts; the share envelope's own AAD is unchanged.
- `client/static/js/src/files/digest-cache.ts` — refine cache key to `(sha256, canonical_folder_path)` (T3-b).
- `client/static/js/src/files/folder-path.ts` — new file: `canonicalizeFolderPath`, `validateFolderPath`.
- `client/static/js/src/crypto/aad.ts` — new file: `buildFileMetadataAAD`.
- `client/static/js/src/files/export.ts` — plumb folder path fields into export bundle (AAD-bound from birth).
- `client/static/css/styles.css` — tree component styles.
- `client/static/js/src/types/api.d.ts` — add folder path fields to `ServerFileEntry`; add `GET /api/user/storage` response type.

### CLI (Go)
- `cmd/arkfile-client/commands.go` — `--dir` flag for upload; `--tree` and optional `--folder PATH` flags for `list-files`; `--preserve-folders` flag for `download`. Tranche 4 changes the AAD inputs for the three pre-existing fields in encrypt/decrypt paths.
- `cmd/arkfile-client/folderpath.go` — new file: `CanonicalizeFolderPath`, `ValidateFolderPath` (mirrors TS).
- `cmd/arkfile-client/folderpath_test.go` — new file: Go unit tests driven by the shared test-vectors JSON.
- `cmd/arkfile-client/offline_decrypt.go` — extend `bundleMeta` + `decrypt-blob` display path for the new folder-path fields (see T2-d). Tranche 4 changes the AAD inputs for `filename` / `sha256sum` / `fek` decrypt here.
- The AAD helper is not CLI-local; the CLI imports `crypto/aad.go` directly.

### Config / shared spec
- `crypto/folder-path-params.json` — new file: max depth / segment length / total length / forbidden char ranges / Unicode normalization form (NFC) flag.
- `crypto/aad-params.json` — new file: per-field AAD tag strings (`folder_path`, `filename`, `sha256sum`, `fek`) and the AAD separator byte (`0x00`). Consumed by both TS and Go via the shared-params loading pattern.

### Docs
- `docs/wip/arkbackup-export.md` — add the two new optional folder-path fields and their AAD binding to the bundle-format spec.

### Test assets
- `scripts/testing/folder-path-test-vectors.json` — new file: shared canonicalization and AAD test vectors (authoritative source consumed by both TS and Go unit tests).

### Tests
- `scripts/testing/e2e-test.sh` — multi-file upload tests, folder path round-trip, pre-flight quota rejection, partial-failure simulation (Tranche 3). AAD tamper test added at Tranche 4.
- `scripts/testing/e2e-playwright.ts` — browser-level folder upload, tree view, flat/tree toggle, localStorage persistence, in-memory cache behavior after reload (Tranche 3). AAD tamper test added at Tranche 4.
- `handlers/uploads_test.go` — folder path field handling in `CreateUploadSession` / `CompleteUpload`; concurrent-session cap enforcement; in-progress-aware quota.
- `handlers/files_test.go` — folder path in list/meta responses; `GetUserStorage` endpoint tests.
- `handlers/export_test.go` — folder path included in export bundle.

---

## Privacy Considerations

- Folder paths are encrypted with the same account key used for other per-file metadata, with AAD binding to `file_id || 0x00 || field || 0x00 || username`. The server learns nothing about folder structure, names, or hierarchy. `encrypted_folder_path` is AAD-bound from birth (Tranche 2); the other three fields join it at the Tranche 4 cutover.
- Number of files per batch is visible to the server (N independent upload sessions). Unavoidable without a more complex batching protocol.
- File sizes remain visible (needed for quota). Existing deterministic padding already obscures exact sizes.
- Folder structure (depth, breadth, naming patterns) is hidden since paths are encrypted per-file.
- The pre-flight quota endpoint returns only the user's own storage summary; no PII.
- Decrypted metadata is held in an **in-memory `Map`** scoped to the SPA lifetime — not `sessionStorage`, not `localStorage`, not IndexedDB. This minimizes the blast radius of any future XSS: decrypted plaintext filenames and folder paths never touch a storage API that can be read by arbitrary scripts on the page. The tradeoff is having to re-decrypt after a full page reload, which is acceptable given the sub-second times for libraries under 1,000 files and the lazy-decrypt path for larger libraries.
- During the window between Tranche 3 landing and Tranche 4 cutover, new files carry AAD-bound `encrypted_folder_path` but not AAD-bound `encrypted_filename` / `encrypted_sha256sum` / `encrypted_fek`. This is a strictly narrower defense-in-depth posture than post-Tranche-4 (the cross-row / cross-field / cross-user protections on those three fields are not active yet), but it is **no weaker than the pre-v3 status quo** — so operating in this window does not reduce any existing privacy guarantee. Tranche 4 closes the gap.

---

