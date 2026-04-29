# Multi-File Upload and Folder Organization

Status: WIP / Design Locked for v1. Ready for pre-implementation verification steps, then Phase 1.

## Overview

Two related features for Arkfile:

1. **Multi-file upload**: Allow uploading multiple files at once, or an entire folder at a time, from both the web frontend and `arkfile-client` CLI.
2. **Folder organization**: Display files in a folder hierarchy in the frontend UI and provide `tree`-style listing output in `arkfile-client`.

These features build on top of the existing single-file chunked upload pipeline. No changes to the encryption model, core server upload flow, or storage backend are required for v1.

## Guiding Principles (from AGENTS.md)

- **Zero-knowledge preserved.** Folder structure must never leak to the server. All folder paths are client-side encrypted metadata.
- **Constrained-device friendly.** Must work on a mobile device with ~3 GB RAM for arbitrarily large batches, including uploading a 6 GB file. This means one-chunk-at-a-time streaming per file stays mandatory.
- **Single way to do things per client.** TS frontend and Go CLI functions mirror each other in naming, structure, and logic for upload/list/tree operations.
- **No backward-compatibility cruft.** Greenfield app. No "legacy mode," no fallback paths for "old flat uploads." Existing files without folder path metadata simply have `NULL` path columns and render at root.

---

## Current State

### Upload Flow
- The HTML file input is `<input type="file" id="fileInput">` — single file only, no `multiple` attribute, no `webkitdirectory`.
- The frontend `handleFileUpload()` reads `fileInput.files[0]` and calls `uploadFile(file, options)` for exactly one file.
- The backend exposes a per-file pipeline: `POST /api/uploads/init` -> `POST /api/uploads/:sessionId/chunks/:chunkNumber` x N -> `POST /api/uploads/:sessionId/complete`. Each file is an independent upload session.
- `arkfile-client` takes `--file FILE` (one path) on the upload command.

### File Listing
- `GET /api/files` returns a flat array of file metadata entries per user, plus a `storage` summary block.
- The frontend `displayFiles()` renders a flat list of file cards with name, size, date, actions.
- `arkfile-client list-files` renders a flat numbered list or JSON output.

### Database
- `file_metadata` has no folder/path columns. Files are a flat collection per `owner_username`.
- Filenames are encrypted client-side (`encrypted_filename` + `filename_nonce`). The server cannot see, sort, or filter by filename or path.

### Why Upload Pipeline Is Strictly Sequential (Per File)
The server maintains two running SHA-256 hashes per upload session (`streamingHashStates` and `storedBlobHashStates` in `handlers/uploads.go`) that are **order-dependent**: chunks must arrive in numerical order for the hashes to be correct. Additionally, the last-chunk padding logic in `UploadChunk` assumes the last chunk is hashed last. Parallelizing chunks within a single file would require a redesign of these hashes and of padding placement. See "Future Work" for notes on what that investigation would require.

For v1 we therefore keep a single file's chunks sequential and batch at the file level.

---

## Design Decisions (Locked for v1)

### 1. Folder Path Storage: Separate Columns
- `encrypted_folder_path TEXT` + `folder_path_nonce TEXT` added to `file_metadata`.
- Path is the directory portion only (e.g., `photos/2025/vacation`). Filename stays as the file's base name (`img001.jpg`).
- Both columns nullable. `NULL` on either column = "root level" (no folder path).
- Existing rows get `NULL` via additive migration.

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
- 255-byte segment limit matches POSIX `NAME_MAX` and Windows component limits, so any path accepted round-trips safely if users ever download with "preserve structure."
- 32-segment depth covers real-world personal data (photo libraries ~6–8, source trees ~10–15) with plenty of headroom.
- 1024-byte total keeps encrypted blob + nonce + tag ~1.1 KB per file. 10,000 files × ~1.1 KB = ~11 MB of folder-path ciphertext in a listing, which is the ceiling we're willing to pay.

Implementation: a shared spec helper in both clients.
- TS: `client/static/js/src/files/folder-path.ts` exports `canonicalizeFolderPath(input: string): string` and `validateFolderPath(path: string): Result`.
- Go CLI: `cmd/arkfile-client/folderpath.go` (or similar) exports `CanonicalizeFolderPath` and `ValidateFolderPath`.
- Both read the same limits from a shared source of truth. Proposal: `crypto/folder-path-params.json` alongside the other config files, loaded the same way as `chunking-params.json`.

Walker inputs:
- Browser: `file.webkitRelativePath` is split on `/`, the last segment (the filename itself) is dropped, the remainder is canonicalized.
- CLI: `filepath.Walk` results are converted from the OS separator to `/`, the filename is dropped, the remainder is canonicalized.

If canonicalization fails for a particular file, that file is flagged as rejected in the batch progress UI with the specific rule it violated; the rest of the batch continues.

### 3. AAD Binding for Folder Path Ciphertext
The folder-path blob uses AES-GCM with **Additional Authenticated Data (AAD)** to cryptographically bind the ciphertext to a specific file and user.

**AAD construction (byte-identical in TS and Go):**
```
AAD = file_id_bytes || 0x00 || username_bytes
```
- `file_id_bytes`: UTF-8 bytes of the `file_id` string.
- `0x00`: single NUL separator (not a valid character in either field).
- `username_bytes`: UTF-8 bytes of the owner username.

**Encryption (client):**
```
key        = account_key
nonce      = random 12 bytes
aad        = buildFolderPathAAD(fileID, username)
(ct, tag)  = AES-GCM-Encrypt(key, nonce, canonicalPath, aad)
send:      nonce, ct||tag   (base64-encoded per existing convention)
```

**Decryption (client):**
```
aad       = buildFolderPathAAD(fileID, username)
plaintext = AES-GCM-Decrypt(key, nonce, ct, tag, aad)   // fails if AAD doesn't match
```

Helpers to add:
- TS: `buildFolderPathAAD(fileID: string, username: string): Uint8Array` in `client/static/js/src/crypto/aad.ts` (new file) or alongside the existing AES-GCM helpers.
- Go CLI: `BuildFolderPathAAD(fileID, username string) []byte` in a shared `cmd/arkfile-client/aad.go` (or a new `crypto/aad.go` if we want to share with server-side code later).

What this prevents:
- **Cross-file swap** (attacker or bug copies file X's folder-path blob onto file Y within the same user account — without AAD, decrypts cleanly with the wrong file).
- **Cross-user confusion** (defense in depth: even if somehow a path blob is assigned to another user's row, the username AAD mismatch prevents silent successful decryption).
- **Silent corruption propagation** — any mix-up of which blob belongs to which file surfaces as an explicit decryption error rather than silently displaying the wrong folder.

Does not prevent (accepted for v1):
- Rollback attacks on the same `(file_id, username)` pair (would require a version counter in AAD; overkill for v1).

**Related open question:** existing `encrypted_filename` and `encrypted_sha256sum` blobs don't currently appear to use AAD. Extending them to use the same binding pattern would be a small, consistent improvement, but is **out of scope for v1**. See "Open Questions" below.

### 4. Multi-File Upload: Sequential, One File at a Time
- Files in a batch upload one at a time. The existing single-file pipeline (init -> chunks -> complete) is used per file.
- Rationale: preserves the constrained-device memory model (one chunk resident), keeps the order-dependent server hash architecture untouched, and avoids rqlite Raft write contention from parallel sessions.
- Parallel-across-files (2–3 concurrent sessions) is a plausible future optimization but deferred; see "Future Work."
- Parallel-within-a-file (parallel chunks) is a larger project with real prerequisites; see "Future Work."

### 5. Folder Creation Model: Implicit Only
- Folders exist only because files have that path. No empty-folder entities.
- Deleting the last file in a folder makes the folder disappear from the tree.
- No server-side folder state, no folder CRUD endpoints.

### 6. Default File List View
- When any file in the user's listing has a non-NULL folder path: **default to tree view**.
- When all files are at root: default to flat view.
- User can toggle between tree and flat at any time. Toggle preference is remembered in `localStorage` per-user.

### 7. Multi-File Share / Folder Share: Not in v1
- Keep single-file sharing only for v1.
- Multi-file/folder sharing deferred to a separate design doc. See "Future Work."

### 8. Export / Backup: Include Folder Paths
- The encrypted export bundle format must carry `encrypted_folder_path` and `folder_path_nonce` per file.
- Import/restore (if/when implemented) round-trips folder structure.
- This is a small surgical change to `handlers/export.go` + `client/static/js/src/files/export.ts` and is tracked in Phase 1.

### 9. Rate Limits & Flood Guard for Batch Uploads
- `FloodGuardMiddleware` (in `handlers/flood_guard.go`) only escalates on 401/404 responses from **unauthenticated** requests. Authenticated approved users making many successful `POST /api/uploads/init` calls in sequence will not trip it. No change needed there.
- **Action item for Phase 1:** verify `handlers/rate_limiting.go` and `handlers/route_config.go` do not impose a per-endpoint burst limit on `/api/uploads/*` for authenticated approved users that would interfere with batch upload. If any limit exists, either exempt these endpoints for authed+approved users or raise the threshold to comfortably accommodate sequential upload of 1,000+ small files.

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
- Both web and CLI use this for **batch pre-flight**: before any hashing/encryption/upload begins, sum the client-side-computable `calculateTotalEncryptedSize(file.size) + padding` over the selected files and compare against `available_bytes`. If the batch doesn't fit, show the user "This batch needs X MB; you have Y MB available — remove N files" before any work starts.
- Padding is deterministic (size -> padded-size mapping), so the client can compute both the encrypted size and the padded size locally.

### 11. Performance Targets for Tree View
- **v1 target:** Eager decrypt of all filename + SHA256 + folder-path blobs on listing load.
- Expected cost (rough): ~3 AES-GCM-Decrypt calls per file on small blobs. On mid-range mobile (~0.5 ms/call) that is:
  - 1,000 files ≈ 1.5 s
  - 2,000 files ≈ 3 s (acceptable with a progress indicator)
  - 10,000 files ≈ 15 s (unacceptable — triggers v1.5 work)
- Show a visible progress indicator ("Decrypting N/M…") when total count exceeds 500.
- Cache decrypted metadata in `sessionStorage` keyed by `file_id` so navigating away and back doesn't re-pay the cost.
- If any real user hits >2,000 files, add lazy decryption: only decrypt folder paths when tree view is active; flat view only needs filenames. That's a v1.5 follow-up, not blocking v1.

---

## Implementation Phases

### Phase 1: Foundation (Backend + Shared Spec)
1. **Additive schema migration** in `database/unified_schema.sql`:
   ```sql
   ALTER TABLE file_metadata ADD COLUMN encrypted_folder_path TEXT;
   ALTER TABLE file_metadata ADD COLUMN folder_path_nonce TEXT;
   ```
2. Accept optional `encrypted_folder_path` + `folder_path_nonce` fields in `CreateUploadSession` request body (`handlers/uploads.go`). Persist them on `upload_sessions`.
3. Pass them through to the `file_metadata` INSERT in `CompleteUpload`.
4. Include them in `GET /api/files` (`ListFiles`) and `GET /api/files/:fileId/meta` (`GetFileMeta`) responses. Update `models.FileMetadata` struct accordingly.
5. Add the new **`GET /api/user/storage`** endpoint (handler, route wiring, tests).
6. Add `crypto/folder-path-params.json` defining max depth / segment length / total length. TS and Go both load from this single source of truth.
7. Add shared AAD helper (`buildFolderPathAAD`) in TS and Go, byte-identical.
8. Extend encrypted export bundle to include folder-path fields. Round-trip test.
9. **Verify rate-limiting posture** (`handlers/rate_limiting.go`, `handlers/route_config.go`): confirm or adjust so `POST /api/uploads/init` and chunk endpoints are not burst-limited for authenticated approved users in a way that would break sequential 100+-file batch upload.

### Phase 2: Multi-File Upload — Web Frontend (Sequential)
1. Add `multiple` attribute to `<input type="file" id="fileInput">`.
2. Refactor `handleFileUpload()` into `handleMultiFileUpload()`:
   - Read all files from `fileInput.files`.
   - Pre-flight: call `GET /api/user/storage`, compute batch total, show error if batch doesn't fit.
   - Resolve account key once (cached after first derivation).
   - Upload files sequentially, calling existing `uploadFile()` per file.
3. Batch progress UI:
   - Overall: "Uploading file 3 of 17 — 45% of batch"
   - Per-file: current filename + chunk progress (reuse existing progress overlay component).
4. Partial-failure handling:
   - If a file fails (network error, validation, quota), log it, continue with remaining files.
   - At end of batch, show summary: "14 uploaded, 3 failed" with per-file error reasons.
   - **Stop-on-fatal exceptions:** if the server returns 403 (approval revoked, quota exceeded mid-batch), stop the batch rather than continuing; the remaining files will just keep failing for the same reason.
5. Test with both account password and custom password types, mixed within a batch.

### Phase 3: Folder Upload — Web Frontend
1. Add a separate folder upload button/input using `webkitdirectory`.
2. Update file input label to show selected count: "17 files, 3 folders selected."
3. For each selected file:
   - Derive folder path from `file.webkitRelativePath` (drop the filename segment).
   - Canonicalize + validate via shared helper. If invalid, mark file as rejected with clear reason; continue with rest.
   - Encrypt canonical path with account key and AAD binding.
   - Include `encrypted_folder_path` + `folder_path_nonce` in `CreateUploadSession` body.
4. Round-trip test: upload a folder, verify file list API returns the expected encrypted paths, decrypt round-trips to the same canonical form.

### Phase 4: Folder Display — Web Frontend
1. In the files listing fetch, decrypt `encrypted_filename`, `encrypted_sha256sum`, and `encrypted_folder_path` per file.
2. Build a client-side tree:
   - Parse canonical paths into nested objects.
   - Group files by folder.
   - Files with no folder path go to root.
3. Render a collapsible tree component:
   - Folder nodes: expand/collapse, show folder name + file count.
   - File nodes: reuse existing file card UI.
   - Breadcrumb/path indicator.
4. Flat/tree toggle, preference persisted per-user in `localStorage`.
5. Progress indicator for decrypt phase when file count > 500.
6. `sessionStorage` cache of decrypted metadata keyed by `file_id`.
7. **Polish (optional sub-phase):** add an optional folder-path text input to the single-file upload form so users can organize individual uploads without using the folder-upload feature. Defer unless the tree view feels empty for casual users. (See "Open Questions.")

### Phase 5: `arkfile-client` Multi-File + Folder Upload
1. Add `--dir DIR` flag to the upload command.
2. Walk directory (`filepath.Walk`), collect regular files with relative paths.
3. Pre-flight: call `GET /api/user/storage`, sum batch, error out if it won't fit.
4. For each file: canonicalize relative path, encrypt with AAD binding, upload sequentially using existing single-file pipeline.
5. Print per-file progress line (`Uploading 3/17: sub/file.txt ...`).
6. Summary at end including any rejected files and per-file failures.

### Phase 6: `arkfile-client` Tree Listing
1. Add `--tree` flag to `list-files`. (Default remains flat — justified by UX and scripting/piping, NOT by backward compatibility.)
2. Decrypt all filenames + folder paths.
3. Build in-memory tree.
4. Render `tree`-style output:
   ```
   /
   +-- photos/
   |   +-- 2025/
   |   |   +-- vacation/
   |   |   |   +-- img001.jpg  (2.3 MB)
   |   |   |   +-- img002.jpg  (1.8 MB)
   |   +-- avatar.png  (45 KB)
   +-- documents/
   |   +-- taxes.pdf  (512 KB)
   +-- backup.tar.gz  (4.1 GB)
   ```
5. Optional `--folder PATH` flag to filter listing to a specific subtree.

### Phase 7: e2e Tests
1. Multi-file upload via web (Playwright) and CLI (curl + `arkfile-client`).
2. Folder upload with path preservation, round-trip between CLI upload and web listing (and vice versa).
3. Mixed batch: some files with folder paths, some at root.
4. Pre-flight quota rejection: select a batch larger than available storage; verify nothing gets uploaded.
5. Partial-failure handling: simulate network error mid-batch, verify remaining files still proceed.
6. Export/restore round-trip preserves folder structure.
7. Canonicalization edge cases: trailing slashes, dot-segments, NFC vs NFD unicode, very long segments, max depth.
8. AAD binding correctness: manually swap a folder-path blob between two files in the DB; verify decryption fails client-side.

---

## Open Questions

### OQ-1. Optional Folder-Path Text Input for Single-File Uploads
Should the single-file upload form include an optional text field letting the user specify a folder path (e.g., `documents/invoices`) without needing to use the folder-upload button?
- **Pro:** low-friction way to organize one-off uploads into the tree.
- **Con:** adds UI that many users will ignore.
- **Current stance:** defer to Phase 4 polish. Implement if the tree view feels empty for users who don't do bulk folder uploads. Decision can be deferred until we see the v1 UX in use.

### OQ-2. Extend AAD Binding to Filename + SHA256 Blobs
Currently `encrypted_filename` and `encrypted_sha256sum` do not use AAD. Applying the same `file_id || 0x00 || username` binding to them would be a small, consistent improvement that prevents cross-file swaps of those fields too.
- **Out of scope for v1 folder-upload work**, but should be flagged as a standalone refactor.
- Tracked here so it isn't forgotten.

### OQ-3. Rate-Limit Posture for `/api/uploads/*`
Phase 1 includes reading `handlers/rate_limiting.go` and `handlers/route_config.go` to confirm current behavior. The answer shapes whether any adjustment is needed. Decision deferred until that reading is done.

### OQ-4. Sharing a Set of Files / a Folder
Genuine future capability, not v1. Needs a separate design doc covering:
- Envelope format (one envelope per file vs single manifest envelope).
- Whether the recipient sees folder structure.
- Quota/rate-limiting for multi-file anonymous downloads.

See "Future Work."

### OQ-5. Move / Rename Files Between Folders
Metadata-only update (new `encrypted_folder_path` + `folder_path_nonce`, same AAD binding). Useful but **deferred to v2**. Requires:
- New endpoint (e.g., `PATCH /api/files/:fileId/folder-path`).
- UI (drag-and-drop, "Move to…" modal, etc.).
- CLI command (`arkfile-client move --file-id X --to PATH`).

Not on the critical path for folder *upload*.

---

## Pre-Implementation Verification Items

Before Phase 1 code changes begin, read the following files and confirm the assumptions this doc makes:

1. **`handlers/rate_limiting.go`** — verify `/api/uploads/*` is either unrestricted or comfortably tolerant for authed+approved users doing sequential batch uploads. Document findings; adjust if needed.
2. **`handlers/route_config.go`** — confirm the route registration for upload endpoints doesn't attach any per-endpoint middleware that would throttle batch uploads. Confirm the new `GET /api/user/storage` route fits the existing auth-required group cleanly.
3. **`handlers/export.go` + `client/static/js/src/files/export.ts`** — map out where folder-path fields need to be plumbed in the export bundle format and the import/restore path. Confirm the export format has a clean extension point rather than a rigid schema.
4. **Existing AAD helper style (`handlers/file_shares.go` for share-envelope AAD construction)** — make sure the new `buildFolderPathAAD` helper matches the project's existing naming/style for AAD byte layout.
5. **`crypto/chunking-params.json` pattern** — follow the same loading pattern for the new `crypto/folder-path-params.json` so both TS and Go read it uniformly.

---

## Files That Will Be Modified

### Backend (Go)
- `database/unified_schema.sql` — add `encrypted_folder_path`, `folder_path_nonce` columns
- `handlers/uploads.go` — accept folder path in `CreateUploadSession`; persist through `CompleteUpload`
- `handlers/files.go` — include folder path fields in list/meta responses; add `GetUserStorage` handler
- `handlers/route_config.go` — wire `GET /api/user/storage`
- `handlers/export.go` — include folder path in export bundle
- `models/file.go` — add fields to `FileMetadata` struct

### Frontend (TypeScript)
- `client/static/index.html` — multi-file input (`multiple`), folder upload button (`webkitdirectory`)
- `client/static/js/src/files/upload.ts` — multi-file loop, folder path encryption, pre-flight quota check
- `client/static/js/src/files/list.ts` — tree building, tree rendering, flat/tree toggle
- `client/static/js/src/files/folder-path.ts` — new file: canonicalize + validate shared helper
- `client/static/js/src/crypto/aad.ts` — new file (or extend existing crypto helpers): `buildFolderPathAAD`
- `client/static/js/src/files/export.ts` — plumb folder path into export bundle
- `client/static/css/styles.css` — tree component styles
- `client/static/js/src/types/api.d.ts` — add folder path fields to `ServerFileEntry`; add `GET /api/user/storage` response type

### CLI (Go)
- `cmd/arkfile-client/commands.go` — `--dir` flag for upload; `--tree` and optional `--folder` flags for `list-files`
- `cmd/arkfile-client/folderpath.go` — new file: canonicalize + validate shared helper (mirrors TS)
- `cmd/arkfile-client/aad.go` — new file (or extend existing): `BuildFolderPathAAD` (mirrors TS)

### Config
- `crypto/folder-path-params.json` — new file: max depth / segment length / total length / forbidden chars

### Tests
- `scripts/testing/e2e-test.sh` — multi-file upload tests, folder path round-trip, pre-flight quota rejection
- `scripts/testing/e2e-playwright.ts` — browser-level folder upload + tree view
- `handlers/uploads_test.go` — folder path field handling
- `handlers/files_test.go` — folder path in responses; `GetUserStorage` endpoint tests
- `handlers/export_test.go` — folder path included in export bundle

---

## Privacy Considerations

- Folder paths are encrypted with the same account key used for filenames, with AAD binding to `file_id || 0x00 || username`. The server learns nothing about folder structure.
- The number of files in a batch is visible to the server (it sees N independent upload sessions). Unavoidable without a more complex batching protocol that would not be worth the review-surface cost for v1.
- File sizes remain visible (needed for quota). Existing padding already obscures exact sizes.
- Folder structure (depth, breadth, naming patterns) is hidden since paths are encrypted per-file.
- Pre-flight quota endpoint returns only the user's own storage summary; no PII.

---

## Future Work (Not v1)

### Parallel-Across-Files Upload
Upload 2–3 files simultaneously rather than strictly sequential. Purely client-side change (TS + Go CLI), no server changes. Respects the existing memory model (one chunk per file, K files in flight). Would mostly help users uploading many small files. Deferred until we see whether sequential feels slow in practice.

### Parallel-Within-A-File Chunk Upload
Upload multiple chunks of the same file concurrently. Significant prerequisites:
- Redesign the server-side streaming SHA-256 to accept out-of-order chunks, or drop server-side linear hashing entirely and rely on client-attested per-chunk hashes. Spec-level change.
- Move last-chunk padding from `UploadChunk` into `CompleteUpload` (or a dedicated finalize endpoint) so padding placement is order-independent.
- Benchmark rqlite write load to confirm parallel chunk inserts don't just queue at Raft.
- Add a flood-guard / rate-limit carve-out that understands "N chunks of the same session in flight is not abuse."
- Reconsider mobile memory model (K plaintext+ciphertext pairs resident instead of one).

This is a larger project than the entire folder-upload feature as designed. Needs its own doc if/when prioritized.

### Multi-File / Folder Sharing
See OQ-4. Requires a separate design doc covering share-envelope shape, recipient UX, and anonymous-download rate limits.

### Move / Rename Files Between Folders
See OQ-5. Metadata-only endpoint + UI/CLI affordances.

### Lazy Metadata Decryption for Very Large File Counts
If real users hit >2,000 files, add lazy folder-path decryption (only when tree view is active) and pagination of the list API. The API already accepts `limit`/`offset` — the work is on the client side.

### Extend AAD Binding to Filename + SHA256 Blobs
See OQ-2. Independent refactor.
