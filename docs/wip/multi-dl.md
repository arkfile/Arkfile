# Multi-File Select and Download

## Reasoning

Owners already encrypt and upload many files in one batch from the browser or `arkfile-client`, and they organize those files with client-side tags, but retrieval is still one file at a time. Multi-file select and download closes that gap so an owner can filter by tags, select everything that matches (or a subset of the listed rows), and stream-decrypt the set to one chosen folder without zip packaging, without giving the server plaintext names or tags, and without breaking the same sequential, low-RAM streaming model used for large single-file downloads on constrained devices.

## Status

Planning. Decisions below are locked for implementation unless this document is explicitly revised. Paginated `GET /api/files` and client adoption of that pagination must land before selection UI or batch download work.

## Overview

This work adds multi-select download on the TypeScript frontend and `arkfile-client`, with tag-filter-aware selection including select-all matching the active filter, sequential streaming (never parallel), custom-password files deferred to the end of each download round with prompt/retry/timeout rules, and a clear account-vs-custom success/failure report with up to three retry rounds.

Pagination is a prerequisite. Today `GET /api/files` returns the full owner set via `models.GetFilesByOwner`; the CLI sends `limit`/`offset` query parameters but the handler ignores them. A separate lightweight `GET /api/files/metadata` already paginates but omits tags and is unused by live clients once the main list is paged. Infinite-scroll selection and honest "select all matching filter" both require a stable, newest-first paged owner list that still carries opaque tag ciphertext for client-side AND filtering after decrypt. The new owner list uses cursor pagination, not offsets, so uploads that occur during a page walk cannot shift later offsets and cause duplicate or skipped rows.

Browser multi-download prefers one directory chooser (`showDirectoryPicker`) and streams each decrypted file into that folder. Where the File System Access API is unavailable, fall back to sequential browser downloads into the default Downloads folder (no per-file Save As under default browser settings). CLI uses `--output-dir` with the same basename collision rule. No zip packaging -- each file streams to its own path so constrained devices stay within chunk-bounded memory.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Work order | Paginate `GET /api/files`, adopt it on both clients, remove dead list endpoints, and update tests before selection UI or batch download |
| Primary list API | `GET /api/files` is the sole paginated owner list for the vault UI and `list-files` |
| Page params | `limit` (default 100, max 500) and optional opaque `cursor`; response includes `files`, `storage`, `limit`, `returned`, `has_more`, and nullable `next_cursor` |
| Cursor semantics | Cursor represents the last returned `(upload_date, file_id)` tuple; later pages use the descending keyset predicate and never use SQL offsets. Treat the cursor as opaque in both clients |
| Exact `has_more` | Query for `limit + 1` rows, return at most `limit`, set `has_more` from the extra row, and emit `next_cursor` only when another page exists |
| Stable sort | `ORDER BY upload_date DESC, file_id DESC` (newest uploads first; `file_id` tie-break for stable keyset pages). No new schema columns; do not add `updated_at` in this work |
| Create time field | Keep exposing `upload_date` as upload/create time; tag edits do not re-order the list |
| Remove endpoint | Remove `GET /api/files/metadata` (`ListRecentFileMetadata`) and its model helper if unused elsewhere; update routes, docs, and tests |
| Keep endpoint | Keep `POST /api/files/metadata/batch` for share-list filename enrichment (no tags); do not use it for vault multi-select |
| Tag filtering | Remains client-side AND after decrypt; no server tag query params |
| Infinite scroll UI | File list (and selection) scrolls inside a container capped at 80% of rendered page height; load next page near bottom when `has_more` |
| Select all shown | Selects all currently loaded rows that match the active filter (visible set) |
| Select all matching filter | Required from the start: snapshot the active filter, continue fetching pages, decrypting, deduplicating by `file_id`, and AND-filtering until `has_more` is false, then select every match; show progress ("Loading matches… N so far") and allow cancel. If the filter changes during the scan, cancel the scan and do not apply its stale result |
| Selection prune | Changing the tag filter prunes selection to IDs still in the loaded matching set; clearing the filter does not invent selections |
| Download parallelism | Sequential only; mirror upload batch JWT refresh between files |
| Archive/zip | Out of scope; one stream per file |
| Browser output (Chromium) | One `showDirectoryPicker({ mode: 'readwrite' })` on Download click (user-gesture), then `getFileHandle` + `createWritable` per file |
| Browser output (fallback) | Sequential SW/Blob downloads to the browser default Downloads folder; warn that the browser may request permission for multiple automatic downloads or block them, detect/report blocked starts where possible, and recommend a supported directory-picker browser or `arkfile-client` if the batch cannot proceed |
| CLI output | `--output-dir` required when downloading more than one file; single-file may keep `--output` |
| Basename collisions | Auto-increment before extension: `photo.png`, `photo-1.png`, `photo-2.png` (same helper on CLI and directory-handle writer; consider existing dir entries and names claimed earlier in the batch) |
| Partial output safety | CLI writes to a unique temporary file in the destination directory, verifies plaintext SHA-256, then atomically renames to the reserved final name. Directory-handle downloads use a temporary entry and publish by move/rename where supported; on any failure they remove the temporary or partial entry when possible and warn clearly if browser limitations prevent confirmed cleanup. SW/Blob fallback retains its existing honest warning that a partial browser-managed download may remain |
| Reserved output names | Resolve and reserve the final basename once per batch target; retries reuse that reservation and must not increment the basename merely because an earlier attempt failed |
| Batch partition | Each round: all selected account-password files first (list order), then all selected custom-password files |
| Custom password prompts | Prompt per custom file at end of account phase; max 3 attempts per file per round; 2 minute timeout waiting for each password entry (6 minutes maximum prompt-wait time for one file in one round). Argon2id derivation and download time are not part of the prompt timeout |
| Prompt failure reasons | `wrong_custom_password`, `prompt_timeout`, `prompt_cancelled`, plus download/network/integrity reasons as applicable |
| Retry rounds | After each round, offer retry of all still-failed files (same partition and prompt rules); max 3 rounds per file; succeeded files never retried |
| Round summary | Always report account succeeded/failed counts and custom succeeded/failed counts with per-file reasons; final report after round 3 or user declines retry |
| Custom prompt cancel | Cancelling a custom password prompt fails that file for the round (non-fatal); the batch continues |
| CLI custom passwords | Interactive prompt per custom file; non-TTY without a defined unattended policy fails clearly for custom files (optional later: `--skip-custom`) |
| Batch cancellation | Frontend Cancel and CLI interrupt abort the active stream, clean partial output where possible, mark unstarted targets skipped, securely dispose of secrets, and produce the normal final report |
| Secret lifetime | Custom passwords, custom KEKs, FEKs, plaintext chunk buffers, and batch-owned Account Key material are sensitive and must be minimized, never logged or persisted, and disposed on every success, failure, timeout, cancellation, and retry path as specified in Secure Secret Handling |
| CLI selection | Repeated `--file-id` and/or `--tags` (client-side AND after decrypt over a cursor-paginated full scan); `--dry-run` lists targets without downloading |
| CLI list output | `list-files` internally exhausts cursor pages by default; human output remains a complete list and `--json` remains a complete JSON array, preserving `[]` vs `null` tag semantics. Remove `--offset`; `--limit` becomes the requested server page size, not a cap on total returned files |
| CLI `--tags` on list/download | Always scan all cursor pages until exhausted before declaring the complete filtered target set |
| Bulk delete/share/export | Out of scope (selection model may be reused later) |
| Clients | TypeScript frontend and `arkfile-client` parity for batch state machine, summaries, and collision rules |
| Naming in code | Do not encode planning labels (phase, section, tier, tranche, or lettered plan steps) into function names, variables, comments, or tests; use descriptive names only |
| Docs | Update `docs/api.md`; user-facing FAQ only if end-user behavior needs a Q&A (prose paragraphs per `docs/user-faq.md` rules) |

## Validation Workflow

All product code changes and all corresponding unit, integration, and e2e/Playwright script updates are made first as one body of work. After that, an LLM coding agent runs every relevant unit test suite (Go with the CGO flags from `AGENTS.md`, and TypeScript/Bun tests for the frontend modules touched) and fixes bugs or coverage gaps those runs reveal. Only after unit tests are green does the developer run `dev-reset.sh` and then `e2e-test.sh` / `e2e-playwright.sh` himself. Agents must not invoke `dev-reset.sh`, `local-deploy.sh`, `prod-deploy.sh`, `prod-update.sh`, `test-update.sh`, `fdre2e.sh`, or the e2e shell scripts.

## Paginated Owner File List

### Server

Replace the full-list `GetFilesByOwner` path used by `ListFiles` with a cursor-paginated query (for example `GetFilesByOwnerPage`) using `ORDER BY upload_date DESC, file_id DESC`, a descending keyset predicate derived from the cursor, and limit clamping (default 100, max 500). Fetch `limit + 1` rows so `has_more` is exact, return at most `limit`, and derive `next_cursor` from the last returned row only when another page exists. The cursor is an opaque URL-safe representation authenticated or strictly decoded and validated by the server; malformed cursors return a stable `400` error without exposing SQL details. Response keeps `files` and `storage` and adds `limit`, `returned`, `has_more`, and `next_cursor`. Prefer deleting unused full-fetch helpers over leaving dead code. Remove `GET /api/files/metadata`, its handler, and `GetRecentFileMetadataByOwner` if nothing else calls it. Keep `POST /api/files/metadata/batch`. Update `docs/api.md`.

### Frontend

`loadFiles()` fetches the first page; infinite scroll in a max 80% page-height container loads later pages and appends after decrypt. Track loaded rows, `nextCursor`, `hasMore`, an in-flight guard, and a `file_id` deduplication set. Tag filter applies to loaded rows; while a filter is active, near-bottom fetch continues until matches fill the view or pages are exhausted, with a "Loading more matches…" state. Storage info still updates from the latest list response.

### CLI

`list-files` follows `next_cursor` until the server reports exhaustion, deduplicates defensively by `file_id`, and applies tag filtering after local decrypt. Remove `--offset`; retain `--limit` as the requested server page size rather than a total-result cap. Human output is the complete list. `--json` remains a complete JSON array of decrypted entries so existing `[]` for decrypted untagged files and `null` for unavailable tags remain unambiguous; do not emit a partial array as though it were complete.

### Tests for pagination

Go handler/model tests cover page boundaries, duplicate upload timestamps, cursor validation, exact-multiple page sizes, exact `has_more`, concurrent insertion between page requests, and removal of the recent-metadata endpoint. Frontend unit tests cover append loading, `file_id` deduplication, stale-filter scan cancellation, and stop-when-exhausted with mocked fetch. e2e and Playwright coverage proves newest-first order, later-page / scroll loading, and tag filtering across pages. Remove assertions that assumed a single unpaged full-list response.

## Selection Model (Frontend)

Maintain a client-side set of selected `file_id` values with toggle, clear, and prune-on-filter-change. Per-row checkboxes; a control for select-all shown (loaded visible matches); and a separate control for select-all matching filter (or all owner files when no filter) that snapshots the filter and walks every remaining page with cancelable progress before Download uses that set. Deduplicate scanned targets by `file_id`; if the filter changes, discard the stale scan result. Toolbar shows selected count, Download selected, and Clear selection. Unit-test shown vs matching-filter selection, cancellation, filter changes during scans, and deduplication against a mocked paged list.

## Batch Download State Machine

Implement the same control flow in TypeScript and Go (names may differ; behavior must match). Build the target list from UI selection, repeated `--file-id`, and/or `--tags`, then partition it into account-password files followed by custom-password files while preserving list order within each group.

For each round (three maximum), download account targets sequentially. Then process custom targets sequentially, allowing up to three password-entry attempts with a two-minute wait for each entry before stream-decrypting on success. Emit a round summary splitting account vs custom succeeded and failed with per-file reasons. If failures remain and rounds remain, offer retry of failed files only; never retry a succeeded file. Emit the final report after the last round or when the user declines retry.

Fatal auth loss aborts the current round and marks remaining targets skipped (same spirit as upload batch). Non-fatal per-file errors continue. Cancelling a custom password prompt fails that file for the round only. Retrying a custom-password file requires a fresh prompt and fresh key derivation; do not retain its plaintext password or derived custom key between attempts, files, or rounds.

## Secure Secret Handling

Secret disposal is a correctness and privacy requirement, not optional cleanup. Every per-attempt and per-file path must use `finally`-style cleanup in TypeScript and tightly scoped `defer` cleanup in Go so success, wrong password, derivation error, network error, integrity failure, timeout, user cancellation, batch cancellation, and retry all execute the same disposal logic.

In the frontend, clear the password input immediately after submission, never place a custom password in application state, storage, logs, error objects, result summaries, closures that outlive the attempt, or retry records, and drop all string references as soon as derivation begins. JavaScript strings are immutable and cannot be reliably overwritten, so the implementation and documentation must not claim that the password string itself is securely wiped. Minimize its lifetime and convert to mutable bytes inside the narrowest possible derivation boundary if the Argon2id interface permits it. Every mutable custom-password byte buffer, derived custom KEK, decrypted FEK, plaintext chunk buffer, and batch-owned Account Key copy must be wiped with the established `secureWipe` helper in `finally` blocks. A key owned by the shared Account Key cache must follow that cache's lock/expiry lifecycle rather than wiping shared storage out from under another operation; any batch-local copy must still be wiped when the batch ends.

In `arkfile-client`, read custom passwords into mutable byte slices rather than immutable Go strings, avoid conversions that create un-wipeable copies, and call `clearBytes` on the terminal input buffer, derivation input, custom KEK, FEK, plaintext chunk buffers, and batch-owned Account Key material at the narrowest scope. Each password attempt gets fresh buffers and its own cleanup scope. Timeout and interrupt handling must not leave an abandoned goroutine retaining a password buffer; use a terminal-input design that can be cancelled or otherwise guarantees the read and its buffer are joined and cleared before the attempt finishes. Never cache a custom password or custom KEK for another file or retry round.

Unit tests must inject or observe cleanup boundaries without logging secret values and prove disposal callbacks run for successful download, wrong password, timeout, derivation failure, transfer failure, integrity failure, cancellation, and retry. Tests cannot prove physical erasure in a managed JavaScript runtime, but they must prove that mutable cryptographic buffers are wiped and references are not intentionally retained.

### Frontend download sink

On Download selected, open the directory picker when the File System Access API is available (must stay user-gesture safe), otherwise use the sequential SW/Blob fallback with a short note about multiple-download permission and browser blocking. Drive a sequential `downloadFiles` (or equivalent) that reuses per-file crypto and streaming, writing through the selected sink. Show file i of N progress, a two-minute countdown on each custom-password prompt, and a Cancel control for the whole batch. Never report a file as successful before plaintext integrity verification and output finalization.

### CLI

```text
arkfile-client download --file-id ID [--file-id ID ...] --output-dir DIR
arkfile-client download --tags TAGS --output-dir DIR [--dry-run]
arkfile-client download --file-id ID --output PATH
```

Single-file `--output` stays unchanged. Multi-file requires `--output-dir`. Summary lines mirror upload style (downloaded / failed / skipped) plus account vs custom breakdown. Interrupt handling cancels the current transfer, cleans its temporary file, disposes secrets, marks remaining targets skipped, and prints the final report.

### Basename collision helper

Shared rule on both clients: split on the final extension; if `name + ext` exists, try `name-1 + ext`, `name-2 + ext`, and so on. Consider files already on disk (or in the directory handle) and names claimed earlier in the same batch. Reserve the chosen name once for that target and reuse it through retries. CLI output must remain in the destination directory so verified temporary files can be atomically renamed without crossing filesystems. Unit-test naming, reservation across retries, temporary cleanup, integrity failure, and finalization in Go and TypeScript.

## Tests for Multi-Download

### Unit

TypeScript coverage for selection, collision helper, reserved names across retries, partial cleanup, batch cancellation, batch partition order, fatal vs non-fatal download errors, two-minute prompt timeout (fake timers), secret-disposal callbacks, and round/retry accounting. Go coverage for target collection from IDs and tags, collision helper, temporary-file finalization/cleanup, interrupt handling, secret disposal, partition order, and round/retry counters without requiring a live server where possible.

### e2e-test.sh

Seed multi-file uploads with tags; exercise paginated list; `download --tags` into `--output-dir` with SHA-256 checks; collision renames; `--dry-run`; mixed account and custom password behavior as far as the harness can drive interactively or via documented non-interactive policy; summary line assertions.

### e2e-playwright.sh

Infinite scroll; select all shown; select all matching filter when matches span pages; directory picker path or fallback download path; custom password prompts after account files; batch summary UI; multi-file upload UI if still uncovered.

## Out of Scope

- Server-side zip or bulk chunk API
- Parallel downloads
- Bulk delete, share, export, or retag
- Reconstructing upload folder trees on download
- Blind indexes or server-side tag search
- Schema changes for list ordering (`updated_at` or similar)

## Implementation Checklist

- Cursor-paginate `ListFiles` / model query with `upload_date DESC, file_id DESC` and exact `has_more`
- Remove `GET /api/files/metadata` and dead helpers
- Frontend paged list and 80% height infinite scroll
- CLI list and download cursor paging / full-scan behavior
- Update `docs/api.md` and all unit / e2e / Playwright coverage for pagination
- Selection model including select all shown and select all matching filter
- Batch download machine on frontend and CLI (directory picker / `--output-dir`, safe partial output, cancellation, collisions, custom-password deferral, two-minute prompts, secret disposal, retries, summaries)
- LLM agent runs relevant Go and TypeScript unit tests and fixes failures
- Developer runs `dev-reset.sh` then `e2e-test.sh` and `e2e-playwright.sh`
