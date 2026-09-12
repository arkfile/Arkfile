# Multi-File Backup Export, Bundle Hints, and Chained Offline Decrypt

## Reasoning

Owners can select many vault files and stream-decrypt them in one pass (see `docs/wip/multi-dl.md`), but `.arkbackup` export is still strictly one file at a time in both clients, and a bundle cannot remind its owner which custom password protects it. That combination makes disaster-recovery export unusable at scale: exporting 40 files means 40 clicks, and a folder of custom-password bundles is an archive with no way to recall which password opens which file. This work closes three gaps together because they are only useful as a set: put the already-encrypted custom-password hint into the bundle, let both clients export a selected set of bundles, and let `decrypt-blob` process a list or folder of bundles in one run with one account-password entry.

Nothing here weakens the sharing boundary. Anonymous share recipients must never receive an owner's custom-password hint, and that stays true: hints live only in owner metadata and owner bundles, never in share envelopes.

## Status

Planning. No implementation yet.

## Overview

Three coordinated changes.

**Bundle hints.** `.arkbackup` version 2 gains two optional fields, `encrypted_password_hint` and `password_hint_nonce`, copied verbatim from the owner's file metadata. They are Account Key ciphertext under the existing AAD label `encrypted_password_hint`, so the server still stores and forwards opaque bytes and learns nothing new. Bundles without the fields remain fully valid; already-downloaded bundles are untouched and keep working. `decrypt-blob` decrypts and shows the hint using only the account password, before it asks for the custom password, so the hint arrives when it is actually useful.

**Mass export.** The vault selection set already built for multi-download gains an Export selected action, and `arkfile-client export` gains repeatable `--file-id`, `--tags`, and `--output-dir`. No new endpoint: both clients loop the existing per-file export token and streaming GET. No zip, no server-side archive job, no password prompt.

**Chained offline decrypt.** `decrypt-blob` accepts repeatable `--bundle` or a `--bundle-dir`, discovers valid bundles by validating the header rather than trusting filenames, derives the Account Key once per distinct account salt, decrypts account-password bundles first, prompts for custom passwords last with the hint displayed, and prints one clear summary of successes, failures, and skips.

## Locked Decisions

| Decision | Choice |
|----------|--------|
| Bundle version | Stays 2. The two hint fields are additive and optional, exactly like `encrypted_tags` / `tags_nonce` |
| Old bundles | Bundles without hint fields stay valid forever. No migration, no re-export requirement, no compatibility shim |
| Hint field names | `encrypted_password_hint` and `password_hint_nonce`, matching the existing API and database field names |
| Hint crypto | Unchanged. Account Key, AES-256-GCM, AAD `BuildMetadataFieldAAD(file_id, "encrypted_password_hint", owner_username)`. The exporter copies ciphertext; it never decrypts or re-encrypts |
| Empty hint | Omit both fields. Single canonical representation, same rule as tags |
| Inclusion rule | Include when both stored fields are non-empty. Do not additionally condition on `password_type`, which would be a second rule to keep in sync |
| Share envelopes | No change. Hints are never placed in a share envelope or any public share response. Enforced by a negative assertion in share tests and an e2e privacy canary |
| Admin export | `AdminExportFile` shares `streamExportBundle`, so admin bundles carry the opaque hint too. The admin cannot decrypt it. No separate admin path |
| Browser bundle parsing | There is no TypeScript `.arkbackup` parser today and this work does not add one. The browser only triggers downloads |
| Hint display order | `decrypt-blob` decrypts and prints filename, tags, and hint after the Account Key is available and before the custom-password prompt |
| Terminal safety | Decrypted filename, tags, and hint are attacker-influenced display strings. Strip C0 and C1 control characters and escape sequences before printing. One shared helper covers all three |
| Hint logging | Print to stdout only. Never pass a hint to `logVerbose`, never write it to a file, never include it in an error string |
| Export API surface | No new endpoint. Both clients reuse `POST /api/files/:fileId/export-token` and `GET /api/files/:fileId/export?token=` per file |
| Export token timing | Mint the 60 second token immediately before each file's GET. Never pre-mint a batch of tokens; a large stream can outlive the token's validity window |
| Export archive format | No zip, no tar, no server-side archive job. One `.arkbackup` per file, mirroring the multi-download decision |
| Export passwords | Export never prompts for any password. Only offline decrypt does |
| Export parallelism | Sequential only, mirroring the upload and download batches |
| Export selection model | Reuse the existing `file_id` selection set in `client/static/js/src/files/selection.ts`. No second selection store, no separate export mode |
| Export destination (Chromium) | One `showDirectoryPicker({ mode: 'readwrite' })` under the click gesture, then one writable stream per bundle |
| Export destination (fallback) | Sequential native downloads to the browser's default folder, with the same multiple-download permission warning used by multi-download |
| Export bundle names | Reserve the original filename with the existing basename helper, then append `.arkbackup`: `photo.png.arkbackup`, `photo-1.png.arkbackup`. Falls back to `<file_id>.arkbackup` when metadata did not decrypt |
| Export memory | Stream the response body into the writable sink. Never buffer a bundle in a Blob or an ArrayBuffer |
| Export failure policy | Continue past per-file failures. Session loss aborts the rest and marks them skipped. One optional retry of failures, then a final summary |
| Decrypt input flags | Repeatable `--bundle`, or `--bundle-dir DIR`. `--output` for exactly one bundle, `--output-dir` required for more than one |
| Bundle discovery | Validate the header, not the extension: ARKB magic, version 2, header length within bounds, JSON parses, required fields present. Non-recursive |
| Discovery reporting | Report non-bundle files as an aggregate count by default and list them individually only under `--dry-run` or verbose output, so pointing at a large Downloads folder does not produce hundreds of skip lines |
| Decrypt ordering | Account-password bundles first, custom-password bundles last, matching the download batch |
| Account Key derivation | Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)` and derive one key per group. One prompt in the normal single-owner case. Never reuse a key derived from one bundle's salt against a different salt |
| Multiple salt groups | State plainly before prompting that the set spans more than one account key salt (different owners, or an account that re-registered) and that one password entry is needed per group |
| Account Key validation | Validate each group's key against its first bundle before processing the group, using a cheap FEK unwrap for account-type bundles or a metadata field decrypt for custom-type bundles. Allow up to 3 re-entries rather than failing every bundle with a wrong key |
| Custom password attempts | 3 attempts per bundle, 2 minute wait per entry, reusing `MaxBatchCustomPasswordAttempts` and `PasswordTimeoutBatchCustom` |
| Custom retry rounds | Single pass. Offline decrypt has no network flakiness, so a failure is nearly always a wrong password and per-bundle attempts already cover it. Do not reuse `MaxBatchDownloadRounds` |
| Custom password reuse | None. Prompt per custom bundle and retain nothing, matching the Secure Secret Handling rule in `docs/wip/multi-dl.md`. Reuse would only save typing, because every custom-password file has its own random salt and still needs a fresh Argon2id derivation |
| Decrypt output names | Decrypted filename reserved with the existing basename helper; falls back to the bundle basename minus `.arkbackup`, then to `file_id` |
| Decrypt output safety | Existing `writeAtomicOutput` behavior stands: temporary file in the destination directory, SHA-256 verified, atomic rename, temporary file removed on any failure |
| Decrypt interrupt | Abort the current bundle, clean its temporary output, dispose secrets, mark remaining bundles skipped, print the normal summary |
| Secret handling | Follows the Secure Secret Handling section of `docs/wip/multi-dl.md` verbatim. Fresh buffers per attempt, `clearBytes` at the narrowest scope, no password or derived key in state, logs, error text, or summaries |
| Bulk delete, share, retag | Still out of scope |
| Naming in code | No planning labels in identifiers, comments, or tests. Descriptive names only |

## Validation Workflow

All product code and all corresponding unit, integration, and e2e or Playwright script updates land as one body of work. An agent then runs the relevant Go and Bun unit suites and fixes what those runs reveal. Only after unit tests are green does the developer run `dev-reset.sh` followed by `e2e-test.sh` and `e2e-playwright.sh`. Agents must not invoke `dev-reset.sh`, `local-deploy.sh`, `prod-deploy.sh`, `prod-update.sh`, `test-update.sh`, `fdre2e.sh`, or the e2e shell scripts.

## Password Hint in the Bundle

### Server

In `handlers/export.go`, add `EncryptedPasswordHint` with JSON tag `encrypted_password_hint,omitempty` and `PasswordHintNonce` with JSON tag `password_hint_nonce,omitempty` to `bundleMetadata`, placed immediately after the existing `EncryptedTags` and `TagsNonce` fields so the struct continues to mirror the CLI schema field for field. In `buildBundleMetadata`, populate both only when `file.EncryptedPasswordHint` and `file.PasswordHintNonce` are both non-empty, using the same guard shape already used for the tag fields.

The model already loads these columns with `COALESCE(..., '')` in `ownerFileSelectColumns`, so no model or schema change is needed. `streamExportBundle` needs no change beyond the slightly larger JSON header, whose length is already length-prefixed by the writer and bounds-checked by the parser.

### CLI

In `cmd/arkfile-client/offline_decrypt.go`, add the matching fields to `bundleMeta` in the same position, and keep the comment documenting that the two schemas stay aligned.

Restructure `handleDecryptBlobCommand` so metadata decryption happens after the Account Key is obtained and before the FEK is unwrapped:

1. Parse and validate the bundle.
2. Obtain the Account Key (prompt, `--account-key-file`, or `--use-agent`).
3. Decrypt filename, tags, and hint with the Account Key. Warn and continue on any individual failure, as the filename path already does.
4. Print filename, tags, and, for custom-password bundles, the hint. Print an explicit line stating that no hint was saved when the fields are absent, so the user knows the hint is missing rather than blank.
5. Unwrap the FEK, prompting for the custom password when `password_type` is `custom`.
6. Decrypt the blob, verify SHA-256, publish the output atomically.

This does not change `--password-stdin` line ordering. `obtainAccountKey` already reads the account password before the custom password is read, so scripts that pipe the account password followed by the custom password keep working unchanged. `scripts/testing/e2e-test.sh` and `scripts/testing/online-integrity-test.sh` both rely on that ordering.

Add a small display sanitizer applied to filename, tags, and hint before printing. All three are decrypted user-authored content going to a terminal, and neither a filename nor a hint containing escape sequences should be able to manipulate the terminal.

### Parity fix in the CLI download batch

The browser passes `file.password_hint` into the batch custom-password modal, but the CLI prompt in `downloadOwnerFilesBatch` shows only the filename. Decrypt the hint alongside the filename when building each `batchPendingFile` and include it in the prompt text so both clients behave the same. This is a small change and belongs here because it is the same hint UX.

### Files touched

- `handlers/export.go`: two struct fields, two populated fields.
- `cmd/arkfile-client/offline_decrypt.go`: two struct fields, reordered flow, hint display, display sanitizer.
- `cmd/arkfile-client/commands.go`: hint in the batch download custom-password prompt.

## Mass Export

### Frontend

Extract a helper in `client/static/js/src/files/export.ts` that mints an export token and returns the export URL, keeping the existing per-row button behavior intact. The batch path must not use `window.location.href`, which cannot be looped.

Add `client/static/js/src/files/export-batch.ts` mirroring the shape of `download-batch.ts` minus the password machinery: resolve targets, open the directory picker under the click gesture when available, list existing directory entries, reserve basenames, refresh the JWT between files, honor an `AbortController`, and produce a summary. On the File System Access path, fetch the export URL and pipe the response body into a `FileSystemWritableFileStream` written to a temporary entry and published by move or rename, removing the temporary entry on failure, exactly as `downloadFileToDirectory` does today. On the fallback path, trigger sequential native downloads.

In `client/static/js/src/files/list.ts`, add an Export selected button to the existing `.file-list-toolbar` beside Download selected, disabled at zero selected, labeled with the count, resolving targets the same way Download selected does. Broaden the header comment in `files/selection.ts` from multi-download to vault multi-action. Confirm before starting when the set is large, noting that export downloads full stored objects, which are larger than the original files because they include padding.

Progress chrome matches multi-download: file i of N, a cancel control, continue past per-file failures, abort the remainder on session loss, and a final succeeded, failed, and skipped summary with one optional retry of failures.

### Bundle naming detail

Reserve the original filename first and append the suffix afterwards, rather than reserving the full `name.arkbackup` string. The basename helpers split on the final extension, so reserving `photo.png.arkbackup` directly would produce `photo.png-1.arkbackup` on a collision. Reserving `photo.png` first yields `photo.png` and `photo-1.png`, which become `photo.png.arkbackup` and `photo-1.png.arkbackup`. This keeps the original extension visible, prevents `photo.png` and `photo.jpg` from collapsing into the same reserved name, and lets `decrypt-blob` restore the true filename.

The native fallback path cannot choose its own filename and receives the server's `Content-Disposition` name, `<file_id>.arkbackup`. That is acceptable because bundle discovery validates the ARKB header rather than the filename, so those bundles still decrypt correctly and land under their true filenames.

### CLI

Extend `cmd/arkfile-client/export.go` to accept the same selection surface as `download`:

```text
arkfile-client export --file-id ID [--output PATH]
arkfile-client export --file-id ID [--file-id ID ...] --output-dir DIR
arkfile-client export --tags TAGS --output-dir DIR [--dry-run]
```

Reuse `multiStringFlag`, the cursor-paging owner scan in `fetchAllOwnerFiles`, the client-side tag AND filter after decrypt, and `reserveBasenames`. Preserve the current single-file default output of `<file-id>.arkbackup` so existing scripts keep working. Under `--output-dir`, use the decrypted filename plus `.arkbackup` when the name is available. Stream each response body to a temporary file in the destination directory and rename on completion. Summary lines mirror the download batch.

`arkfile-admin export-file` stays single-file unless bulk admin disaster recovery is requested separately.

### Files touched

- `client/static/js/src/files/export.ts`
- `client/static/js/src/files/export-batch.ts` (new)
- `client/static/js/src/files/list.ts`
- `client/static/js/src/files/selection.ts` (comment only)
- `cmd/arkfile-client/export.go`
- `cmd/arkfile-client/main.go` (usage text)

## Chained Offline Decrypt

### Command surface

```text
arkfile-client decrypt-blob --bundle FILE --output PATH
arkfile-client decrypt-blob --bundle F1 --bundle F2 [...] --output-dir DIR
arkfile-client decrypt-blob --bundle-dir DIR --output-dir DIR [--dry-run]
```

`--username`, `--account-key-file`, `--use-agent`, and `--password-stdin` keep working and apply to the whole run. In multi-bundle mode, `--username` must match every bundle's `owner_username`.

### Discovery

For `--bundle-dir`, read directory entries non-recursively, skip subdirectories, and call the existing `parseBundle` on each regular file. `parseBundle` reads only the header, so this is cheap. Accept a file when the magic is ARKB, the version is 2, the header length is within the existing 1 MiB bound, the JSON parses, and `file_id` and `owner_username` are present. Anything else is a non-bundle: counted in the summary, and listed individually only under `--dry-run` or verbose output.

`--dry-run` prints each discovered bundle's path, `file_id`, owner, `password_type`, and size straight from the plaintext JSON header, and never prompts for a password.

### Batch flow

Put the orchestration in a new `cmd/arkfile-client/offline_decrypt_batch.go` so `offline_decrypt.go` stays focused on the single-bundle path and the parser. Single-bundle behavior routes through the same per-bundle function, so there is one code path for one file and for many.

1. Build the target list from `--bundle` values and `--bundle-dir` discovery, deduplicating by absolute path.
2. Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)`. When more than one group exists, say so before prompting.
3. For each group, obtain the Account Key once, then validate it against the group's first bundle with a cheap FEK unwrap or metadata field decrypt, allowing up to 3 re-entries.
4. Reserve output basenames across the whole run from decrypted filenames, considering names already present in the destination directory.
5. Decrypt every account-password bundle in order.
6. Decrypt custom-password bundles last. For each, print filename, tags, and hint first, then prompt with up to 3 attempts and a 2 minute wait per entry.
7. Print the summary.

Per-bundle failure never stops the run. A wrong account password for an entire group, after re-entries are exhausted, marks that group's remaining bundles skipped and continues to the next group. Interrupt aborts the current bundle, cleans its temporary output, and marks the rest skipped.

The salt grouping is the subtle correctness requirement here. Deriving one key from the first bundle's `account_kdf_salt` and reusing it for the rest silently fails on any set spanning two owners or an account that re-registered with a new salt. With `--use-agent`, `GetOfflineAccountKey` is already keyed by salt and profile, so the same grouping applies.

### Summary and failure reasons

The summary reports counts for decrypted, failed, and skipped with an account versus custom breakdown, then one line per non-success carrying the filename when known, the bundle path, and a reason from a fixed set: `not_a_bundle`, `unsupported_version`, `unsupported_kdf_profile`, `owner_mismatch`, `wrong_account_password`, `wrong_custom_password`, `prompt_timeout`, `prompt_cancelled`, `integrity_mismatch`, `write_failed`, `cancelled`, `skipped`. Reason strings never contain password material.

### Files touched

- `cmd/arkfile-client/offline_decrypt.go`
- `cmd/arkfile-client/offline_decrypt_batch.go` (new)
- `cmd/arkfile-client/main.go` (usage text)

## Tests

### Go unit

Bundle metadata assertions belong in `handlers/export_rotation_test.go` beside the existing `TestBuildBundleMetadataIncludesAccountKDFMetadata`, which already calls `buildBundleMetadata` directly with no database. Cover: hint fields present and byte-identical to the stored ciphertext for a custom-password file with a hint; both fields omitted when either stored field is empty; no plaintext hint anywhere in the serialized header. The existing account salt and KDF profile assertions must still pass.

`cmd/arkfile-client/offline_decrypt_test.go`: hint round trip through a bundle; absent hint handled without error; hint decrypt failure warns and does not abort; hint tampering fails AEAD because `file_id` and owner are bound in AAD; hint decrypted and displayed before the custom-password prompt; control characters sanitized before display. Extend `FuzzParseBundle` seeds with a hint-bearing bundle and one carrying an oversized hint field.

New batch coverage: discovery accepts valid bundles and rejects a decoy file, a truncated bundle, and a wrong-magic file; salt grouping derives one key per distinct salt and never reuses a key across salts; account key validation retries rather than failing every bundle; ordering places account bundles before custom; per-bundle failure continues the run; interrupt marks the remainder skipped; output basename reservation and temporary file cleanup; secret disposal runs on success, wrong password, timeout, integrity failure, and cancellation.

### TypeScript unit

Export batch coverage: one token minted per file immediately before its GET; no navigation in the batch path; abort stops the run; session loss skips the remainder; a per-file failure does not stop the run; basename reservation produces `photo.png.arkbackup` and `photo-1.png.arkbackup`; no Blob buffering of a bundle body. The existing single-file assertions in `client/static/js/src/__tests__/export.test.ts` stay unchanged.

### e2e-test.sh

Assert a hint line in `decrypt-blob` output for a custom-password file that has a hint, and the explicit no-hint line for a file without one. Assert the hint is printed before the custom-password prompt. Add a raw API privacy canary confirming no plaintext hint in the export response header and no hint field of any kind in share metadata responses. Add a CLI multi-export into `--output-dir` covering account and custom files with no password entry, plus `--tags --dry-run`. Add a chained `decrypt-blob --bundle-dir` run over that export directory with one decoy non-bundle file present, asserting the summary counts and that decrypted outputs match their original digests. The existing single-file export and decrypt tests stay as they are.

### e2e-playwright.ts

Reuse the existing multi-select corpus. Select two files, click Export selected, abort the directory picker with the existing stub, wait for two downloads, and check the ARKB magic on each. Full offline decrypt stays in `e2e-test.sh`.

### online-integrity-test.sh

Confirm the existing export and `decrypt-blob` steps still pass unchanged.

## Documentation

`docs/api.md` Backup Export section: note the two optional hint fields in bundle metadata, that they are opaque Account Key ciphertext, that they are omitted when no hint was saved, and that the browser and CLI batch export paths use the existing per-file token and GET with no new endpoint.

`docs/security.md`: extend the `.arkbackup` version 2 paragraph to list the encrypted hint alongside the other owner metadata fields, and restate that share envelopes never carry hints.

`docs/user-faq.md`: one or two prose-only entries covering exporting several or all files as individual encrypted backup bundles, and the fact that a custom-password bundle shows its hint after the account password is entered but still needs the file's own password to decrypt. Paragraphs only, no lists and no code spans, per that file's rules.

`docs/wip/multi-dl.md`: note that bulk export, previously listed as out of scope, is now covered here and reuses the selection model.

## Out of Scope

- Server-side zip, tar, or any bulk archive job
- Parallel export or parallel offline decrypt
- A TypeScript `.arkbackup` parser
- Any change to bundle version, chunk layout, AAD composition, or padding
- Hints in share envelopes or any public share response
- Recursive `--bundle-dir` discovery
- Bulk delete, bulk share, or bulk retag
- Bulk admin export

## Implementation Checklist

- [ ] Hint fields in `handlers/export.go` bundle metadata, populated when both stored fields are present
- [ ] Matching fields in CLI `bundleMeta`, with the schema alignment comment updated
- [ ] `decrypt-blob` decrypts and displays filename, tags, and hint before the custom-password prompt
- [ ] Display sanitizer for decrypted filename, tags, and hint
- [ ] Hint shown in the CLI batch download custom-password prompt (parity with the browser)
- [ ] Frontend Export selected button reusing the existing selection set
- [ ] `export-batch.ts` with directory-picker and native fallback paths, streaming only
- [ ] CLI `export` accepts repeatable `--file-id`, `--tags`, `--output-dir`, and `--dry-run`
- [ ] `decrypt-blob` accepts repeatable `--bundle` and `--bundle-dir` with header-validated discovery
- [ ] Account Key grouping by salt, with per-group validation and re-entries
- [ ] Account-first then custom ordering, single pass, 3 attempts per bundle
- [ ] Summary with the fixed failure reason set, including the aggregate non-bundle count
- [ ] Go and TypeScript unit tests green
- [ ] `docs/api.md`, `docs/security.md`, `docs/user-faq.md`, and `docs/wip/multi-dl.md` updated
- [ ] Developer runs `dev-reset.sh`, then `e2e-test.sh` and `e2e-playwright.sh`
