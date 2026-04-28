# Multi-File Upload and Folder Organization

Status: WIP / Planning

## Overview

Two related features for Arkfile:

1. **Multi-file upload**: Allow uploading multiple files at once, or an entire folder at a time, from both the web frontend and arkfile-client CLI.
2. **Folder organization**: Display files in a folder hierarchy in the frontend UI and provide `tree`-style listing output in arkfile-client.

These features build on top of the existing single-file chunked upload pipeline. No changes to the encryption model, server upload flow, or storage backend are required.

## Current State

### Upload Flow
- The HTML file input is `<input type="file" id="fileInput">` -- single file only, no `multiple` attribute, no `webkitdirectory`.
- The frontend `handleFileUpload()` reads `fileInput.files[0]` and calls `uploadFile(file, options)` for exactly one file.
- The backend exposes a per-file pipeline: `POST /api/uploads/init` -> `POST /api/uploads/:sessionId/chunks/:chunkNumber` x N -> `POST /api/uploads/:sessionId/complete`. Each file is an independent upload session.
- arkfile-client takes `--file FILE` (one path) on the upload command.

### File Listing
- `GET /api/files` returns a flat array of file metadata entries per user.
- The frontend `displayFiles()` renders a flat list of file cards with name, size, date, actions.
- arkfile-client `list-files` renders a flat numbered list or JSON output.

### Database
- `file_metadata` has no folder/path columns. Files are a flat collection per `owner_username`.
- Filenames are encrypted client-side (`encrypted_filename` + `filename_nonce`). The server cannot see, sort, or filter by filename or path.

### Key Constraint: Encrypted Metadata
All file metadata (filename, SHA-256, and by extension any folder path) is encrypted with the user's account key. The server is zero-knowledge about file names and paths. This means:
- All folder/tree organization must happen **client-side** after decrypting metadata.
- The server returns encrypted blobs; the client decrypts, parses paths, and builds the tree locally.
- No server-side folder CRUD, search-by-folder, or path-based sorting is possible (by design).

---

## Feature 1: Multi-File / Folder Upload

### Approach

Each file in a batch is still uploaded as an independent upload session. There is no "batch upload" API on the server. The client simply loops over selected files and runs the existing single-file upload pipeline for each one.

### Changes Required

#### HTML (`client/static/index.html`)
- Add `multiple` attribute to the file input for multi-file selection.
- Add a separate folder upload button/input using `webkitdirectory` attribute (browser support: Chrome, Edge, Firefox, Safari).
- Update the file input label/display to show count of selected files.

#### Frontend TypeScript (`client/static/js/src/files/upload.ts`)
- New `handleMultiFileUpload()` (or refactor `handleFileUpload()`) to:
  - Read all files from `fileInput.files`.
  - Derive/resolve the account key once (already cached after first derivation).
  - Upload files sequentially, calling `uploadFile()` for each.
  - On folder upload via `webkitdirectory`: capture `file.webkitRelativePath` for each file and encrypt it as the folder path metadata.
- New batch progress UI:
  - Overall progress: "Uploading file 3 of 17"
  - Per-file progress: current file name + chunk progress (reuse existing progress overlay).
  - Error handling: if one file fails, continue with remaining files and report failures at the end.

#### arkfile-client (`cmd/arkfile-client/commands.go`)
- Add `--dir DIR` flag to the upload command.
- When `--dir` is provided: walk the directory tree, collect all regular files, upload each sequentially.
- Preserve relative path (e.g., `mydir/sub/file.txt`) as encrypted folder path metadata.
- Progress: print per-file progress line (`Uploading 3/17: sub/file.txt ...`).

#### Backend (Go server)
- **No changes to the upload pipeline.** Each file is still an independent session.
- Add `encrypted_folder_path` and `folder_path_nonce` columns to `file_metadata` (see Database section below).
- Accept `encrypted_folder_path` and `folder_path_nonce` in `CreateUploadSession` request body (optional fields).
- Pass them through to the `file_metadata` INSERT in `CompleteUpload`.

#### Database
```sql
-- Additive migration (nullable columns, safe for existing data)
ALTER TABLE file_metadata ADD COLUMN encrypted_folder_path TEXT;
ALTER TABLE file_metadata ADD COLUMN folder_path_nonce TEXT;
```
- Existing files will have `NULL` for both columns (no folder path = root level).
- New files uploaded via folder upload will have encrypted folder paths.

### Difficulty: Low-Medium
- The upload pipeline does not change. Multi-file is a client-side loop.
- Main work: batch progress UI, error handling for partial failures, folder path metadata columns.

---

## Feature 2: Folder Organization / Tree Display

### Approach

Folders are **virtual** -- derived entirely from encrypted folder path metadata on files. There is no server-side folder entity. The client decrypts all file metadata, extracts folder paths, and builds a tree structure in memory.

### Changes Required

#### Backend (`handlers/files.go`)
- Include `encrypted_folder_path` and `folder_path_nonce` in the `GET /api/files` response (and `GET /api/files/:fileId/meta`).
- No other backend changes. No folder CRUD endpoints.

#### Frontend TypeScript (`client/static/js/src/files/list.ts`)
- After decrypting file metadata, also decrypt `encrypted_folder_path` for each file.
- Build a client-side tree:
  - Parse decrypted paths like `photos/2025/vacation/` into nested objects.
  - Group files by their folder path.
  - Files with no folder path (NULL or empty) go to root level.
- Render as a collapsible tree UI:
  - Folder nodes: click to expand/collapse. Show folder name + file count.
  - File nodes (leaves): same as current file cards (name, size, date, actions).
  - Breadcrumb or path indicator at the top.
  - Toggle between flat view (current) and tree view.
- Estimated size: 300-500 lines of TypeScript + associated CSS for the tree component.

#### Frontend CSS (`client/static/css/styles.css`)
- Tree indentation, expand/collapse icons, folder icons.
- Responsive design for mobile (tree indentation on small screens).

#### arkfile-client (`cmd/arkfile-client/commands.go`)
- Add `--tree` flag to `list-files` command.
- When `--tree` is set:
  - Decrypt all filenames + folder paths.
  - Build an in-memory tree structure.
  - Render `tree`-style output:
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
- Optionally add `--folder PATH` to filter listing to a specific subtree.
- Default `list-files` (without `--tree`) remains flat for backward compatibility.
- Estimated size: 150-250 lines of Go for tree building + rendering.

### Difficulty: Medium
- Backend changes are minimal (add fields to response).
- CLI tree renderer is moderate Go work.
- Frontend tree UI is the largest single task -- needs a proper collapsible component with good UX.

---

## Design Decisions To Be Determined

### 1. Folder Path Storage

**Option A (Recommended):** Separate `encrypted_folder_path` + `folder_path_nonce` columns.
- Clean separation from filename.
- Folder path is the directory portion only (e.g., `photos/2025/vacation/`), filename stays as-is (e.g., `img001.jpg`).
- Easy to query "has folder path" vs "no folder path" for migration/display purposes.

**Option B:** Encode full path into the encrypted filename (e.g., encrypt `photos/2025/vacation/img001.jpg` as the filename).
- No schema change needed.
- But breaks the current meaning of "filename" -- existing code everywhere assumes filename is just the file's base name.
- Harder to separate folder from filename on the client side.

**Decision needed:** Option A or B?

### 2. Multi-File Upload Concurrency

**Option A (Recommended):** Sequential uploads -- one file at a time.
- Simpler to implement and reason about.
- Predictable memory usage (one file's chunks in memory at a time).
- Matches the constrained-device use case from AGENTS.md (3 GB RAM, 6 GB file).
- Progress is easy to display.

**Option B:** Limited parallelism (e.g., 2-3 concurrent uploads).
- Faster for many small files.
- More complex: multiple upload sessions active, harder progress tracking, higher peak memory.
- Risk of overwhelming the server or hitting rate limits.

**Decision needed:** Sequential or parallel? If parallel, what concurrency limit?

### 3. Folder Creation Model

**Option A (Recommended):** Implicit folders only -- folders exist because files have that path.
- No empty folders. Deleting the last file in a folder makes the folder disappear.
- Simplest model. No server-side folder state.
- Consistent with the zero-knowledge design (server stores nothing about folders).

**Option B:** Allow creating empty folders (client-side metadata entries with no file).
- Requires a "folder" record in the database (or a special marker file).
- More complex. Debatable value.

**Decision needed:** Implicit only, or support empty folders?

### 4. Default File List View

**Option A:** Default to flat view. Show a "Tree View" toggle when folder paths exist.
**Option B:** Default to tree view when any files have folder paths, flat view otherwise.
**Option C:** Always show tree view (root-level files are just at the top level of the tree).

**Decision needed:** Which default?

### 5. Folder Path for Single-File Uploads

When a user uploads a single file (not via folder upload), should there be an optional "folder path" text input in the upload form?
- Pro: Users can organize files into folders without using the folder upload feature.
- Con: Adds UI complexity. Users might not understand it.

**Decision needed:** Include optional folder path input for single-file uploads?

### 6. Rename / Move Files Between Folders

Should users be able to change a file's folder path after upload (move to a different folder)?
- Requires re-encrypting the folder path metadata and updating the database.
- The server endpoint would accept new `encrypted_folder_path` + `folder_path_nonce` and overwrite.
- Does not touch file data or FEK -- only metadata update.
- Adds another UI interaction (drag-and-drop or "Move to..." action).

**Decision needed:** In scope for v1 or deferred?

---

## Implementation Order (Suggested)

### Phase 1: Database + Backend (foundation)
1. Add `encrypted_folder_path` and `folder_path_nonce` columns to `file_metadata`.
2. Accept optional folder path fields in `CreateUploadSession`.
3. Pass them through to `CompleteUpload` INSERT.
4. Include them in `GET /api/files` and `GET /api/files/:fileId/meta` responses.

### Phase 2: Multi-File Upload (web frontend)
1. Add `multiple` attribute to file input.
2. Refactor `handleFileUpload()` to handle multiple files sequentially.
3. Build batch progress UI.
4. Test with account password and custom password types.

### Phase 3: Folder Upload (web frontend)
1. Add `webkitdirectory` input/button.
2. Capture `webkitRelativePath`, encrypt as folder path metadata.
3. Upload files with folder path metadata.

### Phase 4: Folder Display (web frontend)
1. Decrypt folder paths in `displayFiles()`.
2. Build client-side tree structure.
3. Render collapsible tree UI.
4. Add flat/tree view toggle.

### Phase 5: arkfile-client Multi-File + Folder Upload
1. Add `--dir` flag to upload command.
2. Walk directory, upload files with relative path metadata.
3. Test round-trip: upload folder via CLI, list via CLI and web.

### Phase 6: arkfile-client Tree Listing
1. Add `--tree` flag to `list-files`.
2. Build tree structure from decrypted metadata.
3. Render tree-style output.

### Phase 7: e2e Tests
1. Test multi-file upload (web + CLI).
2. Test folder upload with path preservation.
3. Test folder path round-trip (upload via CLI, verify in web frontend tree view and vice versa).
4. Test files with no folder path (backward compatibility).

---

## Performance Considerations

- **Large file counts**: For users with hundreds or thousands of files, decrypting all metadata and building a tree client-side could be slow. Consider:
  - Pagination of the file list API (already supported: `limit`/`offset` params).
  - Lazy tree expansion (only decrypt/display files in expanded folders).
  - Caching decrypted metadata in session storage.
- **Memory on constrained devices**: Multi-file upload should still respect the one-chunk-at-a-time streaming model. Sequential upload ensures only one file's data is in memory at a time.
- **Upload session cleanup**: If a batch upload is interrupted (browser closed, network failure), there may be orphaned upload sessions. The existing session expiry (24h) handles cleanup.

## Privacy Considerations

- Folder paths are encrypted with the same account key used for filenames. The server learns nothing about folder structure.
- The number of files in each upload batch is visible to the server (it sees N independent upload sessions). This is unavoidable without a more complex batching protocol.
- File sizes remain visible to the server (needed for storage quota enforcement). Padding already obscures exact sizes.
- Folder structure (depth, breadth, naming patterns) is hidden from the server since paths are encrypted per-file.

## Files That Will Be Modified

### Backend (Go)
- `database/unified_schema.sql` -- add columns
- `handlers/uploads.go` -- accept folder path in CreateUploadSession, pass through to CompleteUpload
- `handlers/files.go` -- include folder path fields in list/meta responses
- `models/file.go` -- add fields to FileMetadata struct

### Frontend (TypeScript)
- `client/static/index.html` -- multi-file input, folder upload button
- `client/static/js/src/files/upload.ts` -- multi-file loop, folder path encryption
- `client/static/js/src/files/list.ts` -- tree building, tree rendering
- `client/static/css/styles.css` -- tree UI styles
- `client/static/js/src/types/api.d.ts` -- add folder path fields to ServerFileEntry

### CLI (Go)
- `cmd/arkfile-client/commands.go` -- `--dir` flag, `--tree` flag, tree renderer

### Tests
- `scripts/testing/e2e-test.sh` -- multi-file upload tests, folder path round-trip
- `handlers/uploads_test.go` -- folder path field handling
- `handlers/files_test.go` -- folder path in responses
