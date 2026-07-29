# Owner File Tags (Client-Encrypted Organization Metadata)

## Status

Draft planning document with design decisions locked. No implementation code has been written yet. This captures the agreed tag model, privacy boundaries, client-side filter approach, and the files and tests expected to change when the feature is built.

## Overview

Arkfile stores owner files under basename-only uploads so paths stay simple across devices and operating systems. That choice leaves owners without folders or other structural organization. Owner file tags are the intended way to label, browse, and filter files after upload without giving the server any plaintext taxonomy. Tags are owner-only metadata: they are encrypted client-side under the Account Key, never appear in share envelopes, and are never inherited by anonymous share recipients. Go CLI (`arkfile-client`) and TypeScript frontend must keep feature parity for validate, encrypt, decrypt, add/remove one tag at a time, list display, and filter.

The locked wire shape is a single optional encrypted string field, not a structured tag object and not a relational tags table. Plaintext before encryption is a comma-separated list such as `tag-1,Food,activity,FUN,234`. Each tag may use only ASCII `A-Z`, `a-z`, `0-9`, and `-` (dash); spaces are not allowed inside tags. Limits (max tags per file, max characters per tag, max tags per filter query) live in a shared JSON config read by both clients, matching the pattern used for Argon2id and password requirements. Optional whitespace around commas may be accepted on input, but clients canonicalize to comma-only joining with no spaces before encryption. Display preserves the typed casing; uniqueness within a file and filter matching use ASCII case-folded comparison so `fun` matches `FUN` and `food` / `Food` cannot both occupy a slot on the same file. When canonicalizing duplicates, keep the first-seen spelling. No per-tag color is stored; the UI may use one or two fixed CSS accents (for example from the existing `biolum` / `phosphor` palette) so chips read as tags without encoding theme in ciphertext.

All tag parsing, validation, encryption, decryption, searching, and filtering happen on the client. The server stores only opaque `encrypted_tags` and `tags_nonce` (both present or both omitted, mirroring custom password hints). There are no blind indexes, no plaintext tag columns, and no server-side tag query parameters. Filter logic runs against already-decrypted in-memory metadata after the owner list is loaded. At large vault sizes (for example 10,000 files each with five max-length tags), matching itself is expected to be milliseconds; the dominant costs remain full-list fetch, Account Key metadata decrypt, and (on the web) DOM rendering -- the same costs owners already pay for encrypted filenames. Tag reuse rates do not reduce decrypt work because each file still carries its own ciphertext blob.

Post-upload editing requires a new authenticated owner metadata update path, because today owner metadata is written at upload init and is not otherwise mutable. Tags may also be supplied at upload time. After upload, owners add, remove, or replace one tag at a time on one file at a time; there is no "delete all tags" / clear-all action and no multi-file batch retag in v1. The wire still carries one ciphertext for the full tag list: the client decrypts, mutates a single tag in memory, re-encrypts, and PUTs. Shares, public share metadata, and share envelopes stay unchanged. Owner `.arkbackup` export must carry the encrypted tags fields in the version-2 JSON header so offline decrypt can restore organization (for example tags that encode former folder paths or topics); admin export continues to be undecryptable without the owner's password.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Storage shape | Single optional encrypted string + nonce (`encrypted_tags`, `tags_nonce`) |
| Plaintext format | Comma-separated tags, canonical form with no spaces around commas |
| Allowed characters | `A-Z`, `a-z`, `0-9`, `-` only; no spaces inside tags |
| Limits source | Shared `crypto/file-tags-params.json` served via public `/api/config/file-tags` (same pattern as Argon2 / password-requirements / chunking) |
| Default limits (in that JSON) | Max 5 tags per file; max 32 characters per tag; max 10 tags per filter query |
| Case | Preserve on display; ASCII `ToLower` / `toLowerCase` for uniqueness and filter match |
| Duplicate spelling | First-seen casing wins when canonicalizing |
| Multi-tag filter | AND (file must contain every queried tag); OR deferred |
| Colors | Not in ciphertext; fixed UI accents only |
| Search location | Client-side only after decrypt; no blind indexes |
| Share / recipient visibility | Never; tags excluded from share create and envelopes |
| Encryption | Account Key, AES-256-GCM, AAD label `encrypted_tags` bound to `(file_id, field_label, owner_username)` |
| Compartmentalization | Tags always under Account Key (same as filename/hint), including for custom-password files; not isolated by custom file password |
| Empty / absent tags | Omit both ciphertext and nonce (same pair contract as empty password hint) |
| Post-upload edit model | One file at a time; add, remove, or replace one tag per user action; no clear-all / delete-all-tags |
| Multi-file batch retag | Out of scope for v1 |
| Clients | TypeScript frontend and `arkfile-client` parity |
| Primary list surface | `GET /api/files` / `FileMetadataForClient` must include opaque tag fields (this is what the owner list UX decrypts and filters) |
| Lightweight metadata endpoints | Include opaque tag fields on recent/batch metadata only if those paths are used for owner list/filter; otherwise keep them lightweight and document that filter requires the full list path |
| `.arkbackup` packaging | Optional `encrypted_tags` + `tags_nonce` in existing version-2 JSON header next to filename fields; omit when untagged; greenfield additive fields, no sidecar |
| Offline decrypt presentation | After successful Account Key decrypt, print a `Tags: ...` line alongside the decrypted filename (same spirit as today's `Decrypted: <filename>`); if tag decrypt fails while other metadata succeeds, warn and continue (defensive edge case) |
| Server-visible residue | Server may observe tagged vs untagged and opaque blob size; documented as operational metadata, not a search surface |

## Detailed Implementation Outline

### 1. Shared limits config

- Add `crypto/file-tags-params.json` with the numeric limits (per-file max, per-tag max length, per-filter max).
- Serve it from a public `GET /api/config/file-tags` handler alongside existing config routes in `handlers/route_config.go` / `handlers/config.go`.
- Go and TypeScript tag helpers load limits from that shared source (Go embed or read from the crypto path used at build/deploy; TS via the config endpoint or the same JSON copied into static assets the way other crypto params are handled today).
- Unit tests pin the JSON values so clients cannot silently drift.

### 2. Shared tag string helpers (Go + TypeScript)

Add mirrored parse / validate / canonicalize helpers used by both clients (and unit-tested in both languages):

- Split on `,`, trim surrounding whitespace per segment, reject empty segments after trim.
- Validate each tag against `^[A-Za-z0-9-]{1,32}$` (length upper bound from shared config).
- Enforce max tags per file after parse (from shared config).
- ASCII case-fold for duplicate detection within a file (`Food` and `food` are the same tag).
- Canonical serialize as `strings.Join(tags, ",")` with first-seen spelling for each case-folded key.
- Single-tag mutators used by edit UX: add one tag, remove one tag (by case-folded match), or replace one tag with another; each produces a new canonical list for re-encryption. Removing the last remaining tag results in omitting both ciphertext and nonce on the next PUT (empty list), which is allowed as the outcome of removing tags one by one -- there is still no dedicated "clear all" control or command.
- Filter helper: parse query (max from shared config), case-fold query set, return whether a file's tag set contains all query tags (AND).
- Reject oversized or invalid input before any encrypt or network call.

Prefer a small dedicated module on each side (for example `crypto/file_tags.go` and `client/static/js/src/crypto/file-tags.ts`) rather than burying rules inside upload UI code.

### 3. Cryptographic metadata field

- Add permanent AAD field-label constant `encrypted_tags` in `crypto/aad.go` and `client/static/js/src/crypto/aad.ts`.
- Encrypt/decrypt via existing metadata-field helpers (`Encrypt` / `Decrypt` with `buildMetadataFieldAAD`), same as filename, SHA-256, and password hint.
- Extend shared AAD conformance fixtures and tests so Go and TypeScript agree on the new label encoding.
- Update `docs/security.md` server-visible vs opaque metadata table to list `encrypted_tags` / `tags_nonce` as opaque owner metadata; note owner-only / absent from shares; note Account Key binding even for custom-password files; note that presence and opaque size are server-visible.

### 4. Schema and models

- Add nullable columns to `file_metadata` and `upload_sessions` in `database/unified_schema.sql`:
  - `encrypted_tags TEXT`
  - `tags_nonce TEXT`
- Add matching idempotent `ALTER TABLE ... ADD COLUMN` migrations in `main.go` `runSchemaMigrations` for existing deployments.
- Extend `models.File`, `FileMetadataForClient`, `ToClientMetadata`, and all SELECT/INSERT paths that currently project password-hint fields (`GetFileByFileID`, `GetFilesByOwner`, upload-complete insert, etc.).
- Ensure `GET /api/files` list responses include the opaque tag fields (required for list chips and client-side filter).
- Update test schema helpers that recreate `file_metadata` / `upload_sessions` (for example `handlers/payments_test_helpers.go` and any sqlmock column lists).
- Cap opaque ciphertext and nonce string lengths on upload init and the tags PUT (reject absurd sizes even though contents stay opaque).

### 5. Upload init and completion

- `POST /api/uploads/init`: accept optional `encrypted_tags` + `tags_nonce`; both present or both omitted; treat as opaque; do not parse plaintext tags server-side; reject half-present pairs.
- Persist through `upload_sessions` and copy into `file_metadata` on upload complete (same pattern as encrypted password hint).
- TypeScript `upload.ts` and CLI upload path: optional tags input, validate/canonicalize, encrypt under candidate `file_id` AAD, include in init body; retry on `file_id_conflict` must re-encrypt tags under the new candidate id (same as other metadata fields).

### 6. Post-upload tag update API

There is no owner metadata mutation API today. Add an authenticated MFA-protected endpoint, for example:

- `PUT /api/files/:fileId/tags` with body requiring both `encrypted_tags` and `tags_nonce` when setting a non-empty tag list, or both omitted/empty according to the same pair contract as password hint when the client has removed the last tag one-by-one.
- No dedicated clear-all API, request flag, or CLI/UI control that wipes every tag in one user gesture. Clients only expose add / remove / replace one tag.
- Ownership check required; server only replaces opaque columns (last-write-wins if two sessions edit the same file).
- Register route in `handlers/route_config.go`.
- Frontend and CLI call this after a single-tag in-memory mutation on one file.

### 7. List, meta, and export surfaces

- Include `encrypted_tags` / `tags_nonce` on `GET /api/files` and `GET /api/files/:fileId/meta` (and client list types).
- Decrypt tags during owner list decrypt (frontend `list.ts`, CLI `list-files`) and keep plaintext tags on the in-memory decrypted entry for filtering and display.
- Interactive filter must not re-decrypt; operate on the decrypted array.
- If tag ciphertext fails to decrypt while filename (or other fields) succeed, show the file without chips and emit a quiet warning (same defensive class as a bad password-hint blob); do not fail the whole list row.
- `.arkbackup`: add optional `encrypted_tags` and `tags_nonce` to `bundleMetadata` in `handlers/export.go` and matching `bundleMeta` in `cmd/arkfile-client/offline_decrypt.go`. Keep bundle version 2; omit fields when untagged. Offline `decrypt-blob` decrypts tags with the Account Key after FEK unwrap setup and prints `Tags: ...` next to the decrypted filename when present; no separate on-disk tags sidecar.
- Do **not** add tags to share envelope JSON, share create requests, public share endpoints, or share UI.

### 8. TypeScript frontend UX

- Upload: optional tags field (single file and batch/folder flows may apply the same validated initial tag string to each file in a batch at upload time only).
- File list: small chips/badges using fixed CSS accents; no per-tag color mapping.
- Filter control: enter up to the configured max filter tags (comma-separated or chip input), AND filter the decrypted list client-side.
- File detail / actions: add, remove, or replace one tag on the selected file; decrypt current tags, mutate one, re-encrypt, PUT. No "clear all tags" button. No multi-select batch retag in v1.
- Ensure share and anonymous recipient pages never show or request tags.

### 9. Go CLI UX

- `upload --tags 'tag-1,Food,activity'` (and multi-file / `--dir` parity: same tags applied to each uploaded file in v1 at upload time only).
- `list-files --tags 'Food,FUN'` client-side AND filter after decrypt; `--json` includes decrypted tags when metadata is decrypted; `--raw` must not invent plaintext `tags` from the server (only opaque fields from API).
- Commands for single-tag mutation on one file (names flexible), for example `add-tag`, `remove-tag` (and optionally `replace-tag`); each decrypts current tags when needed, mutates one tag, re-encrypts, calls the update API. No `clear-tags` command.
- `decrypt-blob`: when bundle metadata includes tag ciphertext and Account Key decrypt succeeds, print `Tags: ...`; on tag decrypt failure, warn and continue with file output.
- Help text and usage strings updated; reject invalid tags locally before network.

### 10. Privacy and logging

- Never log plaintext tags, tag strings, or decrypted metadata in server logs.
- Client debug/trace logging must follow existing filename privacy rules (no dumping full tag lists in production paths).
- E2E privacy canaries: raw list JSON may contain `encrypted_tags` / `tags_nonce` but must not contain plaintext `tags` from the server; share envelope responses must not contain tag fields.

### 11. Performance notes (non-blocking for v1)

- Filter after decrypt is expected to be negligible even at ~10k files.
- Full-vault decrypt cost already exists for filenames; tags add one small AES-GCM field per file (~164 bytes max plaintext at default limits).
- List payload grows by roughly a few MiB at 10k fully tagged files.
- Frontend sequential `await` decrypt loops may dominate large-list UX; optional follow-on is bounded concurrency for metadata decrypt and/or list virtualization. Not required to ship tags, but call out if large-vault testing on mobile is painful.
- Do not add server-side search to "fix" large vaults; that would break the privacy model.

### 12. Documentation

- `docs/api.md`: upload init fields, tags update route (single opaque replace after client-side one-tag mutation), list/meta field additions, pair-presence rules, no clear-all endpoint, config endpoint for limits.
- `docs/security.md`: opaque metadata row for tags; owner-only and absent from shares; Account Key even for custom-password files; server may see presence/size only.
- `docs/user-faq.md`: Q&A prose only (no lists inside answers) covering what tags are, limits, that recipients never see them, that search is on-device after unlock, and that tags travel with owner `.arkbackup` exports for offline organization restore.
- CLI help / man-style usage in `cmd/arkfile-client`.

### 13. Testing strategy

- Unit tests for parse/validate/canonicalize/filter and single-tag add/remove/replace (Go + TypeScript), including case-fold duplicates, first-seen casing, max counts from shared JSON, illegal characters, spaces, empty segments.
- Config endpoint / JSON load tests for `file-tags-params.json`.
- AAD constant and fixture updates for `encrypted_tags`.
- Handler tests: init accepts/rejects half-present pairs; update ownership and opaque replace; reject absurd ciphertext sizes; list/meta include opaque fields; share paths unchanged; no clear-all-specific API beyond empty list after last one-by-one remove.
- Model/sqlmock column list updates wherever `encrypted_password_hint` appears today.
- E2E (`e2e-test.sh`): upload with tags, list filter, add/remove one tag, raw API privacy, share create/download proves tags absent from recipient path, export + `decrypt-blob` prints restored tags.
- Playwright: upload with tags, chips visible after decrypt, filter narrows list, add/remove one tag in UI, confirm shared-file UI has no tags and no clear-all control.

## Out of Scope for v1

- Server-side tag search or blind indexes.
- Per-tag colors or a stored color index.
- OR / advanced query language.
- Encrypted per-account tag dictionary or autocomplete service (clients may later derive a local vocabulary from the decrypted list without new server state).
- Folders, hierarchies, or path retention.
- Filename substring search (may share UI chrome later; not required for tags).
- Changing share envelope contents.
- Clear-all / delete-all-tags control, command, or dedicated API.
- Multi-file batch retag (multi-select apply/add/remove across many files).
- Separate on-disk tags sidecar next to decrypted output.

## Files / Tests Expected to Add or Modify

Paths are the primary touch list; some test helpers and sqlmock strings will expand wherever password-hint columns are currently projected.

### Schema, server, models

- `database/unified_schema.sql` -- add `encrypted_tags`, `tags_nonce` on `file_metadata` and `upload_sessions`
- `main.go` -- additive `ALTER TABLE` migrations for both tables
- `models/file.go` -- struct fields, SELECTs, `FileMetadataForClient`, `ToClientMetadata`, update helper for tags
- `handlers/uploads.go` -- init request fields, validation (pair presence + size caps), session insert, complete insert into `file_metadata`
- `handlers/files.go` -- list/meta responses include opaque tag fields; new update-tags handler (or dedicated `handlers/file_tags.go`)
- `handlers/route_config.go` -- register tags PUT and `GET /api/config/file-tags`
- `handlers/config.go` -- serve `file-tags-params.json`
- `handlers/export.go` -- optional `encrypted_tags` / `tags_nonce` on version-2 `bundleMetadata`
- `handlers/payments_test_helpers.go` and other in-test schema stubs that define `file_metadata` / `upload_sessions`
- `handlers/files_test.go`, `handlers/uploads_test.go` -- sqlmock columns, init/update/list coverage
- New or extended handler tests for tags update ownership, pair rules, size caps, and reject half-present pairs

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
- `client/static/index.html` -- tags input, filter control, chip markup hooks
- `client/static/css/styles.css` -- fixed-accent tag chip / filter styles
- `client/static/js/src/__tests__/upload-batch.test.ts` -- tags on init payload when provided
- Additional frontend unit tests for list filter and single-tag mutation if not covered solely by `file-tags.test.ts`

### Go CLI

- `cmd/arkfile-client/main.go` -- types for opaque/decrypted tags; help text; new command dispatch
- `cmd/arkfile-client/commands.go` -- upload `--tags`, `list-files --tags`, single-tag add/remove (and optional replace) commands
- `cmd/arkfile-client/offline_decrypt.go` -- optional bundle meta fields; print `Tags: ...` on success
- CLI-focused unit tests where parse/upload helpers are tested today (or via `crypto/file_tags_test.go` + command-level tests if present)

### Docs

- `docs/api.md`
- `docs/security.md`
- `docs/user-faq.md`
- This plan: `docs/wip/file-tags.md` (update status when implementation starts / completes)

### E2E and Playwright

- `scripts/testing/e2e-test.sh` -- upload with tags; list filter; add/remove one tag; `--raw` privacy (opaque fields only); share path proves no tag leakage; export + `decrypt-blob` shows tags
- `scripts/testing/e2e-playwright.ts` -- UI chips, filter, single-tag edit; shared page has no tags; no clear-all control
- `scripts/testing/online-integrity-test.sh` / offline integrity scripts only if they assert full metadata field sets or AAD fixture lists
- Deploy/copy paths that install `crypto/*.json` must include `file-tags-params.json`

### Explicit non-touch (verify unchanged)

- `crypto/share_kdf.go` / share envelope create-parse paths -- no tag fields
- Public share handlers and `client/static/shared.html` / share-access UI -- no tag UI or API fields
- Recipient download path -- filename/sha256 continue to come from share envelope only

---

## REMAINING QUESTIONS

Should the lightweight recent/batch metadata endpoints (`/api/files/metadata` and `/api/files/metadata/batch`) carry `encrypted_tags` / `tags_nonce`, or stay filename-focused while only `GET /api/files` includes tags? The plan still leaves that open. Including them keeps every owner metadata shape consistent and future-proofs any UI that later filters from batch fetches, at a small payload cost; leaving them out matches today’s “lightweight = no password hint” pattern and avoids growing share-list / batch callers that do not need tags.

How should clients load `file-tags-params.json`: always from `GET /api/config/file-tags` (like Argon2 / password requirements), or also embed/ship the same file next to the CLI and frontend assets? A single config fetch keeps one source of truth and matches AGENTS.md, but the CLI then needs the server (or a local copy) before it can validate `--tags` offline; embedding the JSON in both clients avoids that and is simpler for `arkfile-client`, at the cost of deploy discipline so the embedded file never drifts from what the server serves.

Is v1’s edit surface only add-tag and remove-tag, or is replace-tag a first-class CLI command and UI action too? Add and remove already cover “rename” as remove-then-add (two PUTs, brief intermediate state); a dedicated replace is nicer UX and one round-trip, but more UI/CLI surface for a greenfield v1 that is already trying to stay narrow.