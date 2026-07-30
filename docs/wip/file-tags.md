# Owner File Tags (Client-Encrypted Organization Metadata)

## Status

Draft planning document with design decisions locked. No implementation code has been written yet. This captures the agreed tag model, privacy boundaries, client-side filter approach, and the files and tests expected to change when the feature is built.

## Overview

Arkfile stores owner files under basename-only uploads so paths stay simple across devices and operating systems. That choice leaves owners without folders or other structural organization. Owner file tags are the intended way to label, browse, and filter files after upload without giving the server any plaintext taxonomy. Tags are owner-only metadata: they are encrypted client-side under the Account Key, never appear in share envelopes, and are never inherited by anonymous share recipients. Go CLI (`arkfile-client`) and TypeScript frontend must keep feature parity for validate, encrypt, decrypt, add/remove one tag at a time, list display, and filter.

The locked wire shape is a single optional encrypted string field, not a structured tag object and not a relational tags table. Plaintext before encryption is a comma-separated list such as `tag-1,Food,activity,FUN,234`. Each tag consists of ASCII alphanumeric segments separated by single dashes; leading, trailing, and consecutive dashes and spaces inside tags are not allowed. Limits (max tags per file, max characters per tag, max tags per filter query) live in a shared JSON config read by both clients, matching the pattern used for Argon2id and password requirements. Whitespace around commas is accepted and trimmed, and clients canonicalize to comma-only joining with no spaces before encryption. Display preserves the typed casing; uniqueness within a file and filter matching use ASCII case-folded comparison so `fun` matches `FUN` and `food` / `Food` cannot both occupy a slot on the same file. When canonicalizing duplicates, keep the first-seen spelling. No per-tag color is stored; the UI may use one or two fixed CSS accents (for example from the existing `biolum` / `phosphor` palette) so chips read as tags without encoding theme in ciphertext.

All tag parsing, validation, encryption, decryption, searching, and filtering happen on the client. The server stores only opaque `encrypted_tags` and `tags_nonce` (both present or both absent/empty as a pair). There are no blind indexes, no plaintext tag columns, and no server-side tag query parameters. Because the server cannot decrypt the list, it cannot verify that a client changed only one tag or prevent a custom client from replacing or emptying the whole list. Arkfile's official TypeScript and Go CLI clients enforce the one-tag-at-a-time product rule; the server enforces ownership, pair structure, size limits, and optimistic revision only. Filter logic runs against already-decrypted in-memory metadata after the owner list is loaded. At large vault sizes (for example 10,000 files each with five max-length tags), matching itself is expected to be milliseconds; the dominant costs remain full-list fetch, Account Key metadata decrypt, and (on the web) DOM rendering -- the same costs owners already pay for encrypted filenames. Tag reuse rates do not reduce decrypt work because each file still carries its own ciphertext blob.

Post-upload editing requires a new authenticated owner metadata update path, because today owner metadata is written at upload init and is not otherwise mutable. Tags may also be supplied at upload time. After upload, owners add, remove, or replace one tag at a time on one file at a time; there is no "delete all tags" / clear-all action and no multi-file batch retag in v1. The wire still carries one ciphertext for the full tag list: the client decrypts, mutates a single tag in memory, re-encrypts, and PUTs. Shares, public share metadata, and share envelopes stay unchanged. Owner `.arkbackup` export must carry the encrypted tags fields in the version-2 JSON header so offline decrypt can restore organization (for example tags that encode former folder paths or topics); admin export continues to be undecryptable without the owner's password.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Storage shape | Single optional encrypted string + nonce (`encrypted_tags`, `tags_nonce`) |
| Plaintext format | Comma-separated tags, canonical form with no spaces around commas |
| Input whitespace | Accept and trim whitespace surrounding comma-separated segments; spaces inside a tag remain invalid |
| Allowed syntax | ASCII alphanumeric segments separated by single dashes: `^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`; no leading, trailing, or consecutive dashes and no spaces |
| Limits source | Shared `crypto/file-tags-params.json` served via public `/api/config/file-tags` (same pattern as Argon2 / password-requirements / chunking) |
| Default limits (in that JSON) | Max 5 tags per file; max 32 characters per tag; max 10 tags per filter query |
| Case | Preserve on display; ASCII `ToLower` / `toLowerCase` for uniqueness and filter match |
| Duplicate spelling | First-seen casing wins when canonicalizing |
| Tag order | Preserve insertion order; replacement stays in the replaced tag's position |
| Replacement collisions | Permit casing-only replacement such as `Food` to `FOOD`; reject replacement with another tag already present under case-folded comparison |
| Multi-tag filter | AND (file must contain every queried tag); OR deferred |
| Duplicate filter terms | Collapse query tags case-insensitively before applying the configured query-tag limit |
| Filter UI | A `Filter by tags` chip combobox below `Your Files`, with removable selected chips, `Match all`, result count, and `Show all files`; do not label exact tag filtering as generic search |
| Autocomplete | Derive a case-insensitive vocabulary only from the decrypted in-memory file list; show prefix matches first, then usage frequency and display spelling; never send queries or vocabulary to the server or persist them in browser storage |
| Colors | Not in ciphertext; fixed UI accents only |
| Search location | Client-side only after decrypt; no blind indexes |
| Share / recipient visibility | Never; tags excluded from share create and envelopes |
| Encryption | Account Key, AES-256-GCM, AAD label `encrypted_tags` bound to `(file_id, field_label, owner_username)` |
| Compartmentalization | Tags always under Account Key (same as filename/hint), including for custom-password files; not isolated by custom file password |
| Empty / absent tags | Omit both fields at upload when no tags are supplied; after removing the final tag, send both `encrypted_tags` and `tags_nonce` as empty strings with `expected_revision` |
| Post-upload edit model | One file at a time; add, remove, or replace one tag per user action; replace is a first-class UI action and CLI command; no clear-all / delete-all-tags |
| Server enforcement boundary | Official clients enforce one-tag-at-a-time mutation and no clear-all control; the privacy-preserving server cannot inspect or compare plaintext lists, so it validates only ownership, field pairing, encoded size, and revision |
| Upload-time tags | A single upload may assign several initial tags through the canonical comma-separated input; the one-tag-at-a-time restriction applies to post-upload mutation |
| Batch/folder upload | Apply the entered initial tags to every selected file only after the UI clearly states `Apply these tags to all N files` |
| Multi-file batch retag | Out of scope for v1 |
| Clients | TypeScript frontend and `arkfile-client` parity |
| CLI commands | Group post-upload mutations under `arkfile-client tags add`, `tags remove`, and `tags replace`, each requiring `--file-id` |
| Primary list surface | `GET /api/files` / `FileMetadataForClient` must include opaque tag fields (this is what the owner list UX decrypts and filters) |
| Lightweight metadata endpoints | Do not include tags on `/api/files/metadata` or `/api/files/metadata/batch`; these filename-focused endpoints support lightweight and share-list workflows, while owner tag display/filter uses `GET /api/files` |
| Limits loading | One physical source file embedded into the Go binary with `go:embed`; Go and CLI use the parsed embedded values directly, while `/api/config/file-tags` serves the exact embedded bytes to the browser |
| Config fetch failure | Disable browser tag controls and tag-bearing upload attempts, but do not block untagged upload, list, download, share, or other file operations; do not use hardcoded browser fallback limits |
| Concurrent edits | Optimistic concurrency using `tags_revision`; every post-upload update supplies the revision it read and atomically increments it; stale updates receive `409 Conflict` instead of silently overwriting another session's tags |
| Conflict handling | Return `409 Conflict` with stable code `tags_revision_conflict` and no refreshed metadata; clients fetch current metadata, reload/decrypt, and reapply add/remove once automatically; replace retries only if its original tag still exists, otherwise it stops and tells the user that the tags changed |
| Conflict no-op | After refresh, add is successful if the tag is already present and remove is successful if it is already absent; do not issue another PUT and preserve refreshed casing |
| `.arkbackup` packaging | Optional `encrypted_tags` + `tags_nonce` in existing version-2 JSON header next to filename fields; omit when untagged; greenfield additive fields, no sidecar |
| Offline decrypt presentation | After successful Account Key decrypt, print a `Tags: ...` line alongside the decrypted filename (same spirit as today's `Decrypted: <filename>`); if tag decrypt fails while other metadata succeeds, warn and continue (defensive edge case) |
| CLI JSON shape | `list-files --json` emits a JSON string array when tags decrypt; use `[]` for successfully decrypted untagged files and `null` when tags are unavailable or fail to decrypt |
| Undecryptable filter state | When a tag filter is active, exclude files whose tags cannot be decrypted and show a local warning that some files could not be evaluated |
| Server-visible residue | Server may observe tagged vs untagged, opaque blob size, and tag-edit revision count; documented as operational metadata, not a search surface |

## Detailed Implementation Outline

### 1. Shared limits config

- Add `crypto/file-tags-params.json` with the numeric limits (per-file max, per-tag max length, per-filter max).
- Embed that exact file into the Go binary with `go:embed`. Go tag helpers and `arkfile-client` use the parsed embedded values directly, including for offline validation.
- Serve it from a public `GET /api/config/file-tags` handler alongside existing config routes in `handlers/route_config.go` / `handlers/config.go`.
- The endpoint returns the exact embedded JSON bytes; the TypeScript client fetches and caches this response before tag validation.
- If the browser cannot load the config, disable tag controls and reject attempts to upload with tags using a clear local error. Ordinary untagged upload, listing, download, sharing, and other file operations remain available. Do not fall back to duplicated hardcoded browser limits.
- Unit tests pin the JSON values so clients cannot silently drift.

### 2. Shared tag string helpers (Go + TypeScript)

Add mirrored parse / validate / canonicalize helpers used by both clients (and unit-tested in both languages):

- Split on `,`, accept and trim surrounding whitespace per segment, and reject empty segments after trim. Whitespace inside a tag remains invalid.
- Validate each tag against `^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$`, with the length upper bound from shared config. Tags must start and end with an ASCII letter or digit; only one dash may separate adjacent alphanumeric segments, so `ab-cd` is valid while `-abcd-`, `ab--cd`, and `---` are invalid.
- Enforce max tags per file after parse (from shared config).
- ASCII case-fold for duplicate detection within a file (`Food` and `food` are the same tag).
- Canonical serialize as `strings.Join(tags, ",")` with first-seen spelling for each case-folded key.
- Preserve insertion order. Add appends; remove closes the gap; replace retains the original tag's position.
- Single-tag mutators used by edit UX: add one tag, remove one tag (by case-folded match), or replace one tag with another; each produces a new canonical list for re-encryption. A casing-only replacement such as `Food` to `FOOD` is valid, while replacement with another case-fold-equivalent tag already in the list is rejected. Removing the last remaining tag results in omitting both ciphertext and nonce on the next PUT (empty list), which is allowed as the outcome of removing tags one by one -- there is still no dedicated "clear all" control or command.
- Filter helper: parse query, collapse duplicate terms case-insensitively, enforce the configured max against the resulting unique set, and return whether a file's tag set contains all query tags (AND).
- Reject oversized or invalid input before any encrypt or network call.

Prefer a small dedicated module on each side (for example `crypto/file_tags.go` and `client/static/js/src/crypto/file-tags.ts`) rather than burying rules inside upload UI code.

### 3. Cryptographic metadata field

- Add permanent AAD field-label constant `encrypted_tags` in `crypto/aad.go` and `client/static/js/src/crypto/aad.ts`.
- Encrypt/decrypt via existing metadata-field helpers (`Encrypt` / `Decrypt` with `buildMetadataFieldAAD`), same as filename, SHA-256, and password hint.
- Extend shared AAD conformance fixtures and tests so Go and TypeScript agree on the new label encoding.
- Update `docs/security.md` server-visible vs opaque metadata table to list `encrypted_tags` / `tags_nonce` as opaque owner metadata; note owner-only / absent from shares; note Account Key binding even for custom-password files; note that presence, opaque size, and tag-edit revision count are server-visible.

### 4. Schema and models

- Add nullable columns to `file_metadata` and `upload_sessions` in `database/unified_schema.sql`:
  - `encrypted_tags TEXT`
  - `tags_nonce TEXT`
- Add `tags_revision INTEGER NOT NULL DEFAULT 0` to `file_metadata`. Upload-created metadata starts at revision 0 whether tags are present or absent; each successful post-upload mutation increments it.
- Add matching idempotent `ALTER TABLE ... ADD COLUMN` migrations in `main.go` `runSchemaMigrations` for existing deployments.
- Extend `models.File`, `FileMetadataForClient`, `ToClientMetadata`, and all SELECT/INSERT paths that currently project password-hint fields (`GetFileByFileID`, `GetFilesByOwner`, upload-complete insert, etc.).
- Ensure `GET /api/files` list responses include the opaque tag fields and `tags_revision` (required for list chips, client-side filter, and conditional updates).
- Keep tags and `tags_revision` out of the lightweight `/api/files/metadata` and `/api/files/metadata/batch` shapes. Those endpoints remain filename-focused for share-list and other lightweight workflows.
- Update test schema helpers that recreate `file_metadata` / `upload_sessions` (for example `handlers/payments_test_helpers.go` and any sqlmock column lists).
- Cap opaque ciphertext and nonce string lengths on upload init and the tags PUT (reject absurd sizes even though contents stay opaque).

### 5. Upload init and completion

- `POST /api/uploads/init`: accept optional `encrypted_tags` + `tags_nonce`; both present or both omitted; treat as opaque; do not parse plaintext tags server-side; reject half-present pairs.
- Persist through `upload_sessions` and copy into `file_metadata` on upload complete (same pattern as encrypted password hint).
- TypeScript `upload.ts` and CLI upload path: optional tags input, validate/canonicalize, encrypt under candidate `file_id` AAD, include in init body; retry on `file_id_conflict` must re-encrypt tags under the new candidate id (same as other metadata fields).

### 6. Post-upload tag update API

There is no owner metadata mutation API today. Add an authenticated MFA-protected endpoint, for example:

- `PUT /api/files/:fileId/tags` with body requiring `expected_revision` plus both `encrypted_tags` and `tags_nonce`. A non-empty list sends the ciphertext and nonce; removing the final tag sends both fields explicitly as empty strings.
- No dedicated clear-all API, request flag, or CLI/UI control that wipes every tag in one user gesture. Clients only expose add / remove / replace one tag.
- This restriction is enforceable only in official clients. The server cannot distinguish a legitimate final single-tag removal from a custom client emptying a larger encrypted list because inspecting that distinction would violate the privacy model.
- Ownership check required; server only replaces opaque columns. Update atomically with `WHERE file_id = ? AND owner_username = ? AND tags_revision = ?`, increment `tags_revision`, and return the new revision.
- A stale `expected_revision` returns `409 Conflict` with stable application error code `tags_revision_conflict` and no current metadata in the error response; it must never silently overwrite a newer ciphertext written by another tab or device.
- On conflict, clients fetch current metadata through the normal authenticated metadata endpoint and decrypt the current tags. An add whose tag is already present and a remove whose tag is already absent are successful no-ops, preserve refreshed casing, and issue no PUT. Otherwise reapply add/remove and retry once with the new revision. A replace operation retries only when the original tag still exists in the refreshed list; otherwise the client stops and reports that the file's tags changed. A second conflict is reported rather than retried again.
- Register route in `handlers/route_config.go`.
- Frontend and CLI call this after a single-tag in-memory mutation on one file.

### 7. List, meta, and export surfaces

- Include `encrypted_tags`, `tags_nonce`, and `tags_revision` on `GET /api/files` and `GET /api/files/:fileId/meta` (and client list types).
- Decrypt tags during owner list decrypt (frontend `list.ts`, CLI `list-files`) and keep plaintext tags on the in-memory decrypted entry for filtering and display.
- Interactive filter must not re-decrypt; operate on the decrypted array.
- If tag ciphertext fails to decrypt while filename (or other fields) succeed, show the file without chips and emit a quiet warning (same defensive class as a bad password-hint blob); do not fail the whole list row.
- When no tag filter is active, an undecryptable tag field does not hide the file. When a tag filter is active, exclude that file because a match cannot be established and show a local warning with the number of files that could not be evaluated.
- `.arkbackup`: add optional `encrypted_tags` and `tags_nonce` to `bundleMetadata` in `handlers/export.go` and matching `bundleMeta` in `cmd/arkfile-client/offline_decrypt.go`. Keep bundle version 2; omit fields when untagged. Offline `decrypt-blob` decrypts tags with the Account Key after FEK unwrap setup and prints `Tags: ...` next to the decrypted filename when present; no separate on-disk tags sidecar.
- Do **not** add tags to share envelope JSON, share create requests, public share endpoints, or share UI.

### 8. TypeScript frontend UX

- Upload: optional comma-separated tags field that may assign several initial tags to one file. Batch/folder flows apply the same validated initial tag string to every selected file at upload time only; the UI must clearly state `Apply these tags to all N files` before upload.
- File list: show small fixed-accent tag chips beneath or beside the filename, without per-tag color mapping or crowding the existing size, date, encryption-type, and action controls. Clicking a file's tag chip adds it to the active filter.
- Place a compact control directly below `Your Files` and label it `Filter by tags`, not `Search`, because v1 performs exact case-insensitive tag matching rather than filename or substring search.
- Implement the filter as a keyboard-accessible combobox with placeholder `Type a tag to filter`, removable selected-tag chips, a visible `Match all` label, a result count such as `12 of 240 files`, and a `Show all files` action. `Show all files` resets only the local filter and never changes stored tags.
- Enter up to the configured max unique filter tags. Selecting a suggestion or entering an exact valid tag adds a chip and applies the client-side AND filter immediately.
- Build autocomplete entirely from the decrypted in-memory file entries. Deduplicate vocabulary case-insensitively while retaining the established display spelling; omit already-selected tags; display at most a small bounded set (for example eight suggestions), with prefix matches before other local matches, then usage frequency and display spelling.
- Autocomplete must support keyboard navigation and accessible combobox/listbox semantics. On narrow/mobile displays, the filter control, selected chips, and file-row tags wrap without horizontal scrolling.
- Keep the autocomplete vocabulary and typed query only in memory, update it after tag mutations, and never send it to the server, store it in `localStorage` or other persistent browser storage, or include it in logs.
- Until the Account Key and tag metadata are decrypted, disable the filter and autocomplete with text such as `Unlock file metadata to filter by tags`. Config-load failure follows the separately locked graceful-degradation rule.
- File detail / actions: add, remove, or replace one tag on the selected file; decrypt current tags, mutate one, re-encrypt, PUT with the revision that was read. Replace is a first-class single action, not a remove followed by an add. No "clear all tags" button. No multi-select batch retag in v1.
- Ensure share and anonymous recipient pages never show or request tags.

### 9. Go CLI UX

- `upload --tags 'tag-1,Food,activity'` (and multi-file / `--dir` parity: same tags applied to each uploaded file in v1 at upload time only).
- `list-files --tags 'Food,FUN'` client-side AND filter after decrypt; duplicate filter terms collapse case-insensitively before the configured query limit is applied. Files with undecryptable tags are excluded while filtering and the CLI warns how many could not be evaluated. `--json` emits decrypted tags as a JSON string array, `[]` for successfully decrypted untagged files, and `null` when tags are unavailable or fail to decrypt; it never exposes the internal comma-separated representation. `--raw` must not invent plaintext `tags` from the server (only opaque fields from API).
- Group single-tag mutation under `arkfile-client tags add`, `arkfile-client tags remove`, and `arkfile-client tags replace`; each requires `--file-id`, decrypts current tags when needed, mutates one tag, re-encrypts, and calls the update API with the revision that was read. There is no `tags clear` command.
- `decrypt-blob`: when bundle metadata includes tag ciphertext and Account Key decrypt succeeds, print `Tags: ...`; on tag decrypt failure, warn and continue with file output.
- Help text and usage strings updated; reject invalid tags locally before network.

### 10. Privacy and logging

- Never log plaintext tags, tag strings, or decrypted metadata in server logs.
- Client debug/trace logging must follow existing filename privacy rules (no dumping full tag lists in production paths).
- E2E privacy canaries: raw list JSON may contain `encrypted_tags` / `tags_nonce` but must not contain plaintext `tags` from the server; share envelope responses must not contain tag fields.

### 11. Performance notes (non-blocking for v1)

- Filter after decrypt is expected to be negligible even at ~10k files.
- Building autocomplete from at most five tags per file is also bounded and client-local; deduplicate once after list decrypt and update incrementally after edits rather than rescanning on every keystroke.
- Full-vault decrypt cost already exists for filenames; tags add one small AES-GCM field per file (~164 bytes max plaintext at default limits).
- List payload grows by roughly a few MiB at 10k fully tagged files.
- Frontend sequential `await` decrypt loops may dominate large-list UX; optional follow-on is bounded concurrency for metadata decrypt and/or list virtualization. Not required to ship tags, but call out if large-vault testing on mobile is painful.
- Do not add server-side search to "fix" large vaults; that would break the privacy model.

### 12. Documentation

- `docs/api.md`: upload init fields, tags update route (single opaque replace after client-side one-tag mutation), explicit empty-string pair after final tag removal, optimistic revision contract and `tags_revision_conflict`, list/meta field additions, pair-presence rules, client-only no-clear-all restriction, config endpoint for limits.
- `docs/security.md`: opaque metadata row for tags; owner-only and absent from shares; Account Key even for custom-password files; server may see presence, size, and revision count only.
- `docs/user-faq.md`: Q&A prose only (no lists inside answers) covering what tags are, limits, that recipients never see them, that search is on-device after unlock, and that tags travel with owner `.arkbackup` exports for offline organization restore.
- CLI help / man-style usage in `cmd/arkfile-client`.

### 13. Testing strategy

- Unit tests for parse/validate/canonicalize/filter and single-tag add/remove/replace (Go + TypeScript), including case-fold duplicates, first-seen casing, insertion order, replacement position, casing-only replacement, replacement collision, max counts from shared JSON, illegal characters, spaces, empty segments.
- Config endpoint / JSON load tests for `file-tags-params.json`.
- Browser tests prove config failure disables tag controls and tag-bearing uploads without blocking unrelated file operations, and prove there is no hardcoded fallback limit.
- AAD constant and fixture updates for `encrypted_tags`.
- Handler tests: init accepts/rejects half-present pairs; final-tag removal accepts an explicit empty-string pair; update ownership and opaque replace; successful update increments revision; stale revision returns `409 Conflict` with code `tags_revision_conflict`, no refreshed metadata, and no ciphertext change; reject absurd ciphertext sizes; full list/meta include opaque fields and revision; lightweight recent/batch endpoints omit tags; share paths unchanged.
- Client tests: one automatic add/remove retry after a revision conflict; refreshed add-present/remove-absent are successful no-ops without a PUT; replace retry only while its original tag still exists; report a second conflict; initial upload accepts several valid tags; surrounding comma whitespace is trimmed while internal whitespace is rejected; reject leading, trailing, and consecutive dashes; duplicate filter terms collapse before limit enforcement; undecryptable tags remain visible without a filter but are excluded with a warning while filtering; `list-files --json` distinguishes tag arrays, `[]`, and `null`; batch upload clearly applies the same tags to every selected file.
- Frontend filter/autocomplete tests: vocabulary comes only from decrypted entries and remains in memory; prefix ordering, frequency ordering, case-fold deduplication, selected-tag omission, suggestion limit, chip click, AND filtering, result count, `Show all files`, locked/config-failure disabled state, keyboard operation, and no network request during query/autocomplete.
- Model/sqlmock column list updates wherever `encrypted_password_hint` appears today.
- E2E (`e2e-test.sh`): upload with tags, list filter, add/remove/replace one tag, stale revision rejection, raw API privacy, share create/download proves tags absent from recipient path, export + `decrypt-blob` prints restored tags.
- Playwright: upload with tags, chips visible after decrypt, filter narrows list, add/remove/replace one tag in UI, confirm shared-file UI has no tags and no clear-all control.

## Out of Scope for v1

- Server-side tag search or blind indexes.
- Per-tag colors or a stored color index.
- OR / advanced query language.
- Encrypted per-account tag dictionary, server-side autocomplete service, or persistence of plaintext autocomplete vocabulary in browser storage.
- Folders, hierarchies, or path retention.
- Filename substring search (may share UI chrome later; not required for tags).
- Changing share envelope contents.
- Clear-all / delete-all-tags control, command, or dedicated API.
- Multi-file batch retag (multi-select apply/add/remove across many files).
- Separate on-disk tags sidecar next to decrypted output.

## Files / Tests Expected to Add or Modify

Paths are the primary touch list; some test helpers and sqlmock strings will expand wherever password-hint columns are currently projected.

### Schema, server, models

- `database/unified_schema.sql` -- add `encrypted_tags`, `tags_nonce` on `file_metadata` and `upload_sessions`; add `tags_revision` on `file_metadata`
- `main.go` -- additive `ALTER TABLE` migrations for tag fields and revision
- `models/file.go` -- struct fields, SELECTs, `FileMetadataForClient`, `ToClientMetadata`, conditional update helper for tags/revision
- `handlers/uploads.go` -- init request fields, validation (pair presence + size caps), session insert, complete insert into `file_metadata`
- `handlers/files.go` -- list/meta responses include opaque tag fields; new update-tags handler (or dedicated `handlers/file_tags.go`)
- `handlers/route_config.go` -- register tags PUT and `GET /api/config/file-tags`
- `handlers/config.go` -- serve `file-tags-params.json`
- `handlers/export.go` -- optional `encrypted_tags` / `tags_nonce` on version-2 `bundleMetadata`
- `handlers/payments_test_helpers.go` and other in-test schema stubs that define `file_metadata` / `upload_sessions`
- `handlers/files_test.go`, `handlers/uploads_test.go` -- sqlmock columns, init/update/list coverage
- New or extended handler tests for tags update ownership, pair rules, size caps, half-present pairs, revision increment, and stale-update conflict

### Crypto / shared constants

- New `crypto/file-tags-params.json` -- shared limits
- `crypto/aad.go` -- `AADFieldTags = "encrypted_tags"`
- `crypto/aad_test.go` -- constant + fixture coverage
- New `crypto/file_tags.go` (+ `crypto/file_tags_test.go`) -- parse, validate, canonicalize, single-tag mutators, AND filter; load limits from shared JSON
- Shared fixture corpus used by AAD conformance (wherever `encrypted_password_hint` is pinned today)
- `client/static/js/src/crypto/aad.ts` -- `AAD_FIELD_TAGS`
- `client/static/js/src/crypto/metadata-helpers.ts` -- decrypt path usage as needed
- New `client/static/js/src/crypto/file-tags.ts` (+ `__tests__/file-tags.test.ts`)
- `client/static/js/src/__tests__/aad.test.ts` -- new label / fixture assertions

### TypeScript frontend

- `client/static/js/src/files/upload.ts` -- encrypt tags at init; optional same initial tags on batch upload
- `client/static/js/src/files/list.ts` -- decrypt, display chips, client-side filter
- `client/static/js/src/files/share.ts` -- ensure tags never enter share create
- `client/static/js/src/files/streaming-download.ts` -- types only if meta includes new fields; do not require tags for download
- `client/static/js/src/app/upload-listeners.ts` -- wire tags input if present in UI
- `client/static/js/src/types/api.d.ts` -- API types for tags fields / update body / config
- New small UI module as needed (for example `files/tags.ts`) for single-tag add/remove/replace on one file
- New small filter/autocomplete module as needed (for example `files/tag-filter.ts`) operating only on decrypted in-memory entries
- `client/static/index.html` -- tags input, filter control, chip markup hooks
- `client/static/css/styles.css` -- fixed-accent tag chip / filter styles
- `client/static/js/src/__tests__/upload-batch.test.ts` -- tags on init payload when provided
- Additional frontend unit tests for list filter and single-tag mutation if not covered solely by `file-tags.test.ts`

### Go CLI

- `cmd/arkfile-client/main.go` -- types for opaque/decrypted tags; help text; new command dispatch
- `cmd/arkfile-client/commands.go` -- upload `--tags`, `list-files --tags`, and grouped `tags add` / `tags remove` / `tags replace` commands
- `cmd/arkfile-client/offline_decrypt.go` -- optional bundle meta fields; print `Tags: ...` on success
- CLI-focused unit tests where parse/upload helpers are tested today (or via `crypto/file_tags_test.go` + command-level tests if present)

### Docs

- `docs/api.md`
- `docs/security.md`
- `docs/user-faq.md`
- This plan: `docs/wip/file-tags.md` (update status when implementation starts / completes)

### E2E and Playwright

- `scripts/testing/e2e-test.sh` -- upload with tags; list filter; add/remove/replace one tag; stale revision rejection; `--raw` privacy (opaque fields only); share path proves no tag leakage; export + `decrypt-blob` shows tags
- `scripts/testing/e2e-playwright.ts` -- UI chips, filter, single-tag add/remove/replace; shared page has no tags; no clear-all control
- `scripts/testing/online-integrity-test.sh` / offline integrity scripts only if they assert full metadata field sets or AAD fixture lists
- Deploy/copy paths that install `crypto/*.json` must include `file-tags-params.json`

### Explicit non-touch (verify unchanged)

- `crypto/share_kdf.go` / share envelope create-parse paths -- no tag fields
- Public share handlers and `client/static/shared.html` / share-access UI -- no tag UI or API fields
- Recipient download path -- filename/sha256 continue to come from share envelope only