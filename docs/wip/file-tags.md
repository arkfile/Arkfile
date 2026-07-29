# Owner File Tags (Client-Encrypted Organization Metadata)

## Status

Draft planning document with design decisions locked. No implementation code has been written yet. This captures the agreed tag model, privacy boundaries, client-side filter approach, and the files and tests expected to change when the feature is built.

## Overview

Arkfile stores owner files under basename-only uploads so paths stay simple across devices and operating systems. That choice leaves owners without folders or other structural organization. Owner file tags are the intended way to label, browse, and filter files after upload without giving the server any plaintext taxonomy. Tags are owner-only metadata: they are encrypted client-side under the Account Key, never appear in share envelopes, and are never inherited by anonymous share recipients. Go CLI (`arkfile-client`) and TypeScript frontend must keep feature parity for validate, encrypt, decrypt, set, clear, list display, and filter.

The locked wire shape is a single optional encrypted string field, not a structured tag object and not a relational tags table. Plaintext before encryption is a comma-separated list such as `tag-1,Food,activity,FUN,234`. Each tag may use only ASCII `A-Z`, `a-z`, `0-9`, and `-` (dash); spaces are not allowed inside tags. Limits are at most five tags per file, at most 32 characters per tag, and at most ten tags per filter query. Optional whitespace around commas may be accepted on input, but clients canonicalize to comma-only joining with no spaces before encryption. Display preserves the typed casing; uniqueness within a file and filter matching use case-folded comparison so `fun` matches `FUN` and `food` / `Food` cannot both occupy a slot on the same file. No per-tag color is stored; the UI may use one or two fixed CSS accents (for example from the existing `biolum` / `phosphor` palette) so chips read as tags without encoding theme in ciphertext.

All tag parsing, validation, encryption, decryption, searching, and filtering happen on the client. The server stores only opaque `encrypted_tags` and `tags_nonce` (both present or both omitted, mirroring custom password hints). There are no blind indexes, no plaintext tag columns, and no server-side tag query parameters. Filter logic runs against already-decrypted in-memory metadata after the owner list is loaded. At large vault sizes (for example 10,000 files each with five max-length tags), matching itself is expected to be milliseconds; the dominant costs remain full-list fetch, Account Key metadata decrypt, and (on the web) DOM rendering -- the same costs owners already pay for encrypted filenames. Tag reuse rates do not reduce decrypt work because each file still carries its own ciphertext blob.

Post-upload editing requires a new authenticated owner metadata update path, because today owner metadata is written at upload init and is not otherwise mutable. Tags may also be supplied at upload time. Shares, public share metadata, and share envelopes stay unchanged. Owner `.arkbackup` export metadata must carry the encrypted tags fields so offline decrypt restores organization; admin export continues to be undecryptable without the owner's password.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Storage shape | Single optional encrypted string + nonce (`encrypted_tags`, `tags_nonce`) |
| Plaintext format | Comma-separated tags, canonical form with no spaces around commas |
| Allowed characters | `A-Z`, `a-z`, `0-9`, `-` only; no spaces inside tags |
| Per-file limit | Max 5 tags |
| Per-tag length | Max 32 characters |
| Per-query limit | Max 10 tags |
| Case | Preserve on display; case-fold for uniqueness and filter match |
| Multi-tag filter | AND (file must contain every queried tag); OR deferred |
| Colors | Not in ciphertext; fixed UI accents only |
| Search location | Client-side only after decrypt; no blind indexes |
| Share / recipient visibility | Never; tags excluded from share create and envelopes |
| Encryption | Account Key, AES-256-GCM, AAD label `encrypted_tags` bound to `(file_id, field_label, owner_username)` |
| Empty tags | Omit both ciphertext and nonce (same contract as empty password hint) |
| Clients | TypeScript frontend and `arkfile-client` parity |
| `.arkbackup` | Include encrypted tags fields in owner bundle metadata |

## Detailed Implementation Outline

### 1. Shared tag string helpers (Go + TypeScript)

Add mirrored parse / validate / canonicalize helpers used by both clients (and unit-tested in both languages):

- Split on `,`, trim surrounding whitespace per segment, reject empty segments after trim.
- Validate each tag against `^[A-Za-z0-9-]{1,32}$`.
- Enforce max 5 tags after parse.
- Case-fold for duplicate detection within a file (`Food` and `food` are the same tag).
- Canonical serialize as `strings.Join(tags, ",")` with original casing of the first-seen spelling for each case-folded key (or last-wins -- pick one rule and document it in helpers; prefer first-seen).
- Filter helper: parse query (max 10 tags), case-fold query set, return whether a file's tag set contains all query tags (AND).
- Reject oversized or invalid input before any encrypt or network call.

Prefer a small dedicated module on each side (for example `crypto/file_tags.go` and `client/static/js/src/crypto/file-tags.ts`) rather than burying rules inside upload UI code.

### 2. Cryptographic metadata field

- Add permanent AAD field-label constant `encrypted_tags` in `crypto/aad.go` and `client/static/js/src/crypto/aad.ts`.
- Encrypt/decrypt via existing metadata-field helpers (`Encrypt` / `Decrypt` with `buildMetadataFieldAAD`), same as filename, SHA-256, and password hint.
- Extend shared AAD conformance fixtures and tests so Go and TypeScript agree on the new label encoding.
- Update `docs/security.md` server-visible vs opaque metadata table to list `encrypted_tags` / `tags_nonce` as opaque owner metadata.

### 3. Schema and models

- Add nullable columns to `file_metadata` and `upload_sessions` in `database/unified_schema.sql`:
  - `encrypted_tags TEXT`
  - `tags_nonce TEXT`
- Add matching idempotent `ALTER TABLE ... ADD COLUMN` migrations in `main.go` `runSchemaMigrations` for existing deployments.
- Extend `models.File`, `FileMetadataForClient`, `ToClientMetadata`, and all SELECT/INSERT paths that currently project password-hint fields (`GetFileByFileID`, `GetFilesByOwner`, batch metadata, upload-complete insert, etc.).
- Update test schema helpers that recreate `file_metadata` / `upload_sessions` (for example `handlers/payments_test_helpers.go` and any sqlmock column lists).

### 4. Upload init and completion

- `POST /api/uploads/init`: accept optional `encrypted_tags` + `tags_nonce`; both present or both omitted; treat as opaque; do not parse plaintext tags server-side.
- Persist through `upload_sessions` and copy into `file_metadata` on upload complete (same pattern as encrypted password hint).
- TypeScript `upload.ts` and CLI upload path: optional tags input, validate/canonicalize, encrypt under candidate `file_id` AAD, include in init body; retry on `file_id_conflict` must re-encrypt tags under the new candidate id (same as other metadata fields).

### 5. Post-upload tag update API

There is no owner metadata mutation API today. Add an authenticated MFA-protected endpoint, for example:

- `PUT /api/files/:fileId/tags` with body `{ "encrypted_tags"?: string, "tags_nonce"?: string }`
- Clearing tags: omit both fields or send an explicit clear convention documented in `docs/api.md` (prefer omit-both or null-both meaning clear; reject half-present pairs).
- Ownership check required; server only replaces opaque columns.
- Register route in `handlers/route_config.go`.
- Frontend and CLI both use this for edit-after-upload and for batch retag (N sequential or lightly concurrent updates after multi-select).

### 6. List, meta, batch, and export surfaces

- Include `encrypted_tags` / `tags_nonce` on `GET /api/files`, `GET /api/files/:fileId/meta`, metadata batch/recent endpoints, and client list types.
- Decrypt tags during owner list decrypt (frontend `list.ts`, CLI `list-files`) and keep plaintext tags on the in-memory decrypted entry for filtering and display.
- Interactive filter must not re-decrypt; operate on the decrypted array.
- `.arkbackup` `bundleMetadata` / offline decrypt structs: add optional encrypted tags fields; offline decrypt may surface tags when Account Key decrypt succeeds.
- Do **not** add tags to share envelope JSON, share create requests, public share endpoints, or share UI.

### 7. TypeScript frontend UX

- Upload: optional tags field (single file and batch/folder flows share one tags string applied per file, or per-file override later -- v1 can apply the same validated tag string to each file in a batch).
- File list: small chips/badges using fixed CSS accents; no per-tag color mapping.
- Filter control: enter up to 10 tags (comma-separated or chip input), AND filter the decrypted list client-side.
- File detail / actions: edit tags for one file via the update API.
- Multi-select: batch apply/add/remove tags by reading current ciphertext is impossible server-side; client decrypts current tags per selected file, merges in memory, re-encrypts, PUTs each file (document merge rules: replace-all vs add-to-set; prefer explicit "set tags" and "add tags" / "remove tags" actions to avoid surprising replaces).
- Ensure share and anonymous recipient pages never show or request tags.

### 8. Go CLI UX

- `upload --tags 'tag-1,Food,activity'` (and multi-file / `--dir` parity: same tags applied to each uploaded file in v1).
- `list-files --tags 'Food,FUN'` client-side AND filter after decrypt; `--json` includes decrypted tags when metadata is decrypted; `--raw` must not invent plaintext `tags` from the server (only opaque fields from API).
- `set-tags` / `clear-tags` (names flexible) calling the update API.
- Help text and usage strings updated; reject invalid tags locally before network.

### 9. Privacy and logging

- Never log plaintext tags, tag strings, or decrypted metadata in server logs.
- Client debug/trace logging must follow existing filename privacy rules (no dumping full tag lists in production paths).
- E2E privacy canaries: raw list JSON may contain `encrypted_tags` / `tags_nonce` but must not contain plaintext `tags` from the server; share envelope responses must not contain tag fields.

### 10. Performance notes (non-blocking for v1)

- Filter after decrypt is expected to be negligible even at ~10k files.
- Full-vault decrypt cost already exists for filenames; tags add one small AES-GCM field per file (~164 bytes max plaintext).
- List payload grows by roughly a few MiB at 10k fully tagged files.
- Frontend sequential `await` decrypt loops may dominate large-list UX; optional follow-on is bounded concurrency for metadata decrypt and/or list virtualization. Not required to ship tags, but call out if large-vault testing on mobile is painful.
- Do not add server-side search to "fix" large vaults; that would break the privacy model.

### 11. Documentation

- `docs/api.md`: upload init fields, new tags update route, list/meta field additions, clear semantics.
- `docs/security.md`: opaque metadata row for tags; explicit note that tags are owner-only and absent from shares.
- `docs/user-faq.md`: Q&A prose only (no lists inside answers) covering what tags are, limits, that recipients never see them, and that search is on-device after unlock.
- CLI help / man-style usage in `cmd/arkfile-client`.

### 12. Testing strategy

- Unit tests for parse/validate/canonicalize/filter (Go + TypeScript), including case-fold duplicates, max counts, illegal characters, spaces, empty segments.
- AAD constant and fixture updates for `encrypted_tags`.
- Handler tests: init accepts/rejects half-present pairs; update ownership and clear; list/meta include opaque fields; share paths unchanged.
- Model/sqlmock column list updates wherever `encrypted_password_hint` appears today.
- E2E (`e2e-test.sh`): upload with tags, list filter, set/clear tags, raw API privacy, share create/download proves tags absent from recipient path, export/decrypt-blob restores tags when in scope.
- Playwright: upload with tags, chips visible after decrypt, filter narrows list, edit tags, confirm shared-file UI has no tags.

## Out of Scope for v1

- Server-side tag search or blind indexes.
- Per-tag colors or a stored color index.
- OR / advanced query language.
- Encrypted per-account tag dictionary or autocomplete service (clients may later derive a local vocabulary from the decrypted list without new server state).
- Folders, hierarchies, or path retention.
- Filename substring search (may share UI chrome later; not required for tags).
- Changing share envelope contents.

## Files / Tests Expected to Add or Modify

Paths are the primary touch list; some test helpers and sqlmock strings will expand wherever password-hint columns are currently projected.

### Schema, server, models

- `database/unified_schema.sql` -- add `encrypted_tags`, `tags_nonce` on `file_metadata` and `upload_sessions`
- `main.go` -- additive `ALTER TABLE` migrations for both tables
- `models/file.go` -- struct fields, SELECTs, `FileMetadataForClient`, `ToClientMetadata`, update helper for tags
- `handlers/uploads.go` -- init request fields, validation (pair presence), session insert, complete insert into `file_metadata`
- `handlers/files.go` -- list/meta responses include opaque tag fields; new update-tags handler (or dedicated `handlers/file_tags.go`)
- `handlers/route_config.go` -- register `PUT /api/files/:fileId/tags` (or final route name)
- `handlers/export.go` -- `bundleMetadata` fields for encrypted tags
- `handlers/payments_test_helpers.go` and other in-test schema stubs that define `file_metadata` / `upload_sessions`
- `handlers/files_test.go`, `handlers/uploads_test.go` -- sqlmock columns, init/update/list coverage
- New or extended handler tests for tags update ownership, clear, and reject half-present pairs

### Crypto / shared constants

- `crypto/aad.go` -- `AADFieldTags = "encrypted_tags"`
- `crypto/aad_test.go` -- constant + fixture coverage
- New `crypto/file_tags.go` (+ `crypto/file_tags_test.go`) -- parse, validate, canonicalize, AND filter
- Shared fixture corpus used by AAD conformance (wherever `encrypted_password_hint` is pinned today)
- `client/static/js/src/crypto/aad.ts` -- `AAD_FIELD_TAGS`
- `client/static/js/src/crypto/metadata-helpers.ts` -- decrypt path usage as needed
- New `client/static/js/src/crypto/file-tags.ts` (+ `__tests__/file-tags.test.ts`)
- `client/static/js/src/__tests__/aad.test.ts` -- new label / fixture assertions

### TypeScript frontend

- `client/static/js/src/files/upload.ts` -- encrypt tags at init; batch apply
- `client/static/js/src/files/list.ts` -- decrypt, display chips, client-side filter
- `client/static/js/src/files/share.ts` -- ensure tags never enter share create
- `client/static/js/src/files/streaming-download.ts` -- types only if meta includes new fields; do not require tags for download
- `client/static/js/src/app/upload-listeners.ts` -- wire tags input if present in UI
- `client/static/js/src/types/api.d.ts` -- API types for tags fields / update body
- New small UI module as needed (for example `files/tags.ts`) for edit/batch retag
- `client/static/index.html` -- tags input, filter control, chip markup hooks
- `client/static/css/styles.css` -- fixed-accent tag chip / filter styles
- `client/static/js/src/__tests__/upload-batch.test.ts` -- tags on init payload when provided
- Additional frontend unit tests for list filter behavior if not covered solely by `file-tags.test.ts`

### Go CLI

- `cmd/arkfile-client/main.go` -- types for opaque/decrypted tags; help text; new command dispatch
- `cmd/arkfile-client/commands.go` -- upload `--tags`, `list-files --tags`, set/clear tags commands
- `cmd/arkfile-client/offline_decrypt.go` -- bundle meta fields if offline surface includes tags
- CLI-focused unit tests where parse/upload helpers are tested today (or via `crypto/file_tags_test.go` + command-level tests if present)

### Docs

- `docs/api.md`
- `docs/security.md`
- `docs/user-faq.md`
- This plan: `docs/wip/file-tags.md` (update status when implementation starts / completes)

### E2E and Playwright

- `scripts/testing/e2e-test.sh` -- upload with tags; list filter; set/clear; `--raw` privacy (opaque fields only); share path proves no tag leakage; optional export/offline decrypt check
- `scripts/testing/e2e-playwright.ts` -- UI chips, filter, edit tags; shared page has no tags
- `scripts/testing/online-integrity-test.sh` / offline integrity scripts only if they assert full metadata field sets or AAD fixture lists

### Explicit non-touch (verify unchanged)

- `crypto/share_kdf.go` / share envelope create-parse paths -- no tag fields
- Public share handlers and `client/static/shared.html` / share-access UI -- no tag UI or API fields
- Recipient download path -- filename/sha256 continue to come from share envelope only
