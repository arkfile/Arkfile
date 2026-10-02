# Multi-File Backup Export, Bundle Hints, and Chained Offline Decrypt

## Reasoning

Owners can select many vault files and stream-decrypt them in one pass (see `docs/wip/multi-dl.md`), but `.arkbackup` export is still strictly one file at a time in both clients, and a bundle cannot remind its owner which custom password protects it. That combination makes disaster-recovery export unusable at scale: exporting 40 files means 40 clicks, and a folder of custom-password bundles is an archive with no way to recall which password opens which file. This work closes three gaps together because they are only useful as a set: put the already-encrypted custom-password hint into the bundle, let both clients export a selected set of bundles, and let `decrypt-blob` process a list or folder of bundles in one run with one account-password entry.

Nothing here weakens the sharing boundary. Anonymous share recipients must never receive an owner's custom-password hint, and that stays true: hints live only in owner metadata and owner bundles, never in share envelopes.

## Status

Planning. The shared helpers this plan reuses already landed with the CLI share download filename fix: `sanitizeDisplayText` in `cmd/arkfile-client/display_text.go`, `safeDownloadBasename` and `resolveDefaultDownloadPath` in `cmd/arkfile-client/output_basename.go`, and `isLowerHexSHA256` in `cmd/arkfile-client/crypto_utils.go`. Nothing else in this plan is implemented.

## Overview

Three coordinated changes, plus a few safety fixes in shared code they depend on.

**Bundle hints.** `.arkbackup` version 2 gains two optional fields, `encrypted_password_hint` and `password_hint_nonce`, copied verbatim from the owner's file metadata. They are Account Key ciphertext under the existing AAD label `encrypted_password_hint`, so the server still stores and forwards opaque bytes and learns nothing new. Bundles without the fields remain fully valid; already-downloaded bundles are untouched and keep working. `decrypt-blob` decrypts and shows the hint using only the account password, before it asks for the custom password, so the hint arrives when it is actually useful.

**Mass export.** The vault selection set already built for multi-download gains an Export selected action, and `arkfile-client export` gains repeatable `--file-id`, `--tags`, `--all`, and `--output-dir`. No new endpoint: both clients loop the existing per-file streaming GET, the CLI with its Bearer session and the browser with its session cookie. No zip, no server-side archive job, no password prompt. Bundles keep readable names (`photo.png.arkbackup`) so an owner can find a file in a backup folder without decrypting anything, and re-exporting into a folder that already holds bundles never replaces or deletes them.

**Chained offline decrypt.** `decrypt-blob` accepts repeatable `--bundle` or a `--bundle-dir`, discovers valid bundles by validating content and length rather than trusting filenames, skips duplicate copies of the same file, and processes one Account Key salt group at a time with one account-password entry per group. Within each group it decrypts account-password bundles first and custom-password bundles last, prompting for custom passwords on the terminal with the hint displayed, and it prints one clear summary of successes, failures, and skips.

**Related safety fixes.** Case-insensitive name reservation in both clients, terminal-safe printing of decrypted strings across the CLI, a safe default name for owner single-file downloads, a working single-file guard for `download --password-stdin`, and atomic publishing for single-file `export`. Each is small and sits in code this work touches.

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
| Browser bundle parsing | There is no TypeScript `.arkbackup` parser today and this work does not add one. The browser only triggers and writes downloads |
| Hint display order | `decrypt-blob` decrypts and prints filename, tags, and hint after the Account Key is obtained and validated, and before the custom-password prompt |
| Hint display wording | Print the explicit no-hint line only when both hint fields are absent. When the fields are present but do not decrypt, print a warning that the hint could not be decrypted and continue to the prompt. A hint failure never fails the bundle: the hint is display-only, and content stays protected by per-chunk AES-GCM and the SHA-256 check |
| Wrong account password | Caught before any custom-password prompt by validating the Account Key against the bundle (see Account Key validation). Interactive entry allows re-entry; non-interactive sources fail the bundle or group. No more silent downgrade to "encrypted SHA-256 unavailable" |
| Terminal safety | Decrypted filenames, tags, and hints are user-authored display strings. Every CLI print site routes them through `sanitizeDisplayText`, which replaces C0 and C1 control characters, DEL, and Unicode bidirectional controls with `?` |
| Hint logging | Print to stdout only. Never pass a hint to `logVerbose`, never write it to a file, never include it in an error string |
| Export API surface | No new endpoint. Both clients call `GET /api/files/:fileId/export` once per file |
| Export auth | CLI: `Authorization: Bearer` session token, refreshed with `ensureFreshSessionToken` between files. Browser: the `__Host-arkfile-token` session cookie, which the global `CookieTokenMiddleware` injects as a Bearer header on every route including this public GET, refreshed between files. Neither client mints export tokens |
| Export token endpoint | Unused once the per-row Export button moves to the cookie path in this work. Deleting `POST /api/files/:fileId/export-token`, `ExportTokenClaims`, the `?token=` branch of `resolveExportAuth`, and their tests is a separate follow-up after this work passes e2e |
| Export archive format | No zip, no tar, no server-side archive job. One `.arkbackup` per file, mirroring the multi-download decision |
| Export passwords | Export never prompts for any password. Only offline decrypt does |
| Export parallelism | Sequential only, mirroring the upload and download batches |
| Export selection model | Reuse the existing `file_id` selection set in `client/static/js/src/files/selection.ts` and its existing Select all shown and Select all matching filter controls (with no filter active, the latter selects the whole vault). No second selection store, no separate export mode, no new select-all control |
| Export destination (Chromium) | One `showDirectoryPicker({ mode: 'readwrite' })` under the click gesture, then one cookie-authenticated `fetch` and one writable stream per bundle |
| Export destination (fallback) | Sequential native downloads to the browser's default folder through one hidden same-origin iframe per file (never `window.location.href`), paced by a short fixed delay, with the same multiple-download permission warning used by multi-download. The page cannot observe completion or HTTP errors on this path, so files are reported as started, not succeeded |
| Export bundle names | Readable names. Reserve the original filename with the existing basename helper, then append `.arkbackup`: `photo.png.arkbackup`, `photo-1.png.arkbackup`. Falls back to `<file_id>.arkbackup` when metadata did not decrypt. The fallback path receives the server's `<file_id>.arkbackup` name and the browser resolves its own collisions |
| Export name visibility | Readable names show original filenames to anyone who can see the backup folder; bundle contents and header metadata stay encrypted. Documented plainly in `docs/security.md` and the user FAQ. No opaque-name mode in this work |
| Re-export safety | Re-exporting into a folder that already holds bundles never replaces or deletes them. Existing entries ending in `.arkbackup` count as taken under their name minus the suffix, comparisons are case-insensitive, publishing never targets an existing entry, and failure cleanup removes only entries the attempt itself created |
| Export memory | Stream the response body into the writable sink. Never buffer a bundle in a Blob or an ArrayBuffer |
| Export failure policy | Continue past per-file failures. Session loss aborts the rest and marks them skipped. The folder-picker path offers one optional retry of failures, the CLI retries each failed file once at the end of the run, and the fallback path has no failure signal to retry on. Final summary in every case |
| Single-file CLI export | Keeps the `<file-id>.arkbackup` default and explicit `--output`, but publishes through `writeAtomicOutput` so a failed re-export to the same path no longer truncates and then deletes the earlier bundle |
| Decrypt input flags | Repeatable `--bundle`, or `--bundle-dir DIR`. `--output` for exactly one bundle, `--output-dir` required for more than one |
| Bundle discovery | Validate content, not the extension: ARKB magic, version 2, header length within bounds, JSON parses, required fields present, and file length exactly `10 + header length + padded_size` (at least `10 + header length + size_bytes` when an old bundle has no `padded_size`). Non-recursive |
| Duplicate bundles | Deduplicate by absolute path, then by `file_id`: keep the first copy in processing order and skip the rest as `duplicate_file_id`. Safe because no feature re-wraps an owner FEK and file contents never change under a `file_id`, so copies differ at most in tags |
| Discovery reporting | Report non-bundle files as an aggregate count by default and list them individually only under `--dry-run` or verbose output, so pointing at a large Downloads folder does not produce hundreds of skip lines |
| Account Key derivation | Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)` and process one group at a time, holding one Account Key at a time and clearing it before the next group. Never reuse a key derived from one bundle's salt against a different salt |
| Multiple salt groups | State plainly before prompting that the set spans more than one Account Key salt and that one password entry is needed per group. This is rare: OPAQUE re-registration keeps the salt, so only bundles from different owners or from a deleted and recreated username produce more than one group |
| Decrypt ordering | Groups in first-appearance order. Within each group, account-password bundles first and custom-password bundles last, matching the download batch |
| Account Key sources | Interactive prompt, `--password-stdin`, `--account-key-file`, or `--use-agent`, applying to the whole run. Each non-interactive source supplies exactly one Account Key: the agent caches one key and rejects other salts, and a key file carries no salt. Groups a non-interactive source cannot unlock are skipped as `account_key_unavailable` |
| Password stdin | Single-bundle mode keeps today's two-line order (account password, then custom password), which `e2e-test.sh` and `online-integrity-test.sh` rely on. In multi-bundle mode, stdin carries only the account password for the first group, and custom passwords are never read from stdin |
| Account Key validation | Validate each group's key against its first bundle before processing it: for an account-type bundle the FEK unwrap itself, otherwise a decrypt of the first Account Key metadata field present (filename, then digest). Interactive prompts allow up to 3 re-entries; a stdin password that fails marks its group `wrong_account_password` |
| Custom password prompts | Interactive terminal only, after the filename, tags, and hint are printed, even when `--password-stdin` supplied the account password. Without a controlling terminal, custom bundles are skipped as `terminal_required`, mirroring the multi-download rule in `docs/wip/multi-dl.md` |
| Custom password attempts | 3 attempts per bundle, 2 minute wait per entry, reusing `MaxBatchCustomPasswordAttempts` and `PasswordTimeoutBatchCustom` |
| Custom retry rounds | Single pass. Offline decrypt has no network flakiness, so a failure is nearly always a wrong password and per-bundle attempts already cover it. Do not reuse `MaxBatchDownloadRounds` |
| Custom password reuse | None. Prompt per custom bundle and retain nothing, matching the Secure Secret Handling rule in `docs/wip/multi-dl.md`. Reuse would only save typing, because every custom-password file has its own random salt and still needs a fresh Argon2id derivation |
| Decrypt output names | Decrypted filename reserved with the basename helper; falls back to the bundle basename minus `.arkbackup`, then to `file_id`. Reservation starts from the entries already in the destination and grows group by group, case-insensitively |
| Decrypt output safety | Existing `writeAtomicOutput` behavior stands: temporary file in the destination directory, SHA-256 verified, atomic rename, temporary file removed on any failure. Reservation guarantees the rename never targets an existing entry |
| Decrypt interrupt | Abort the current bundle, clean its temporary output, dispose secrets, mark remaining bundles skipped, print the normal summary |
| Secret handling | Follows the Secure Secret Handling section of `docs/wip/multi-dl.md` verbatim. Fresh buffers per attempt, `clearBytes` at the narrowest scope, one Account Key alive at a time, no password or derived key in state, logs, error text, or summaries |
| Name reservation case | Both `reserveBasenames` helpers (Go and TypeScript) and `resolveDefaultDownloadPath` compare names case-insensitively, because backup and restore targets are often case-insensitive (exFAT or FAT drives on Linux, and macOS or Windows folders reached through the browser picker). Returned names keep their original case |
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

Restructure the single-bundle path, which becomes the per-bundle function the batch also uses, so the Account Key is validated and metadata is shown before the custom password is requested:

1. Parse and validate the bundle, including the length check.
2. Obtain the Account Key (prompt, `--password-stdin`, `--account-key-file`, or `--use-agent`).
3. Validate the key. For an account-type bundle this is the FEK unwrap itself; for a custom-type bundle, decrypt the first Account Key metadata field present (filename, then digest). On failure, offer re-entry when the key came from an interactive prompt, up to 3 entries; otherwise stop with a wrong-account-password error.
4. Decrypt filename, tags, and hint with the Account Key. Warn and continue on an individual tags or hint failure.
5. Print filename and tags, and for custom-password bundles the hint, all through `sanitizeDisplayText`. Print the explicit no-hint line only when both hint fields are absent; when they are present but do not decrypt, print a warning that the hint could not be decrypted.
6. For a custom-type bundle, prompt for the custom password and unwrap the FEK with the derived Custom Key.
7. Decrypt the blob, verify SHA-256, publish the output atomically.

Single-bundle `--password-stdin` ordering does not change. `obtainAccountKey` already reads the account password before the custom password is read, so scripts that pipe the account password followed by the custom password keep working; `scripts/testing/e2e-test.sh` and `scripts/testing/online-integrity-test.sh` both rely on that ordering. The one intended behavior change is that a wrong account password on a custom-password bundle now fails clearly instead of decrypting with verification quietly downgraded to "encrypted SHA-256 unavailable".

### Parity fix in the CLI download batch

The browser passes `file.password_hint` into the batch custom-password modal, but the CLI prompt in `downloadOwnerFilesBatch` shows only the filename. Decrypt the hint alongside the filename when building each `batchPendingFile` and include it, through `sanitizeDisplayText`, in the prompt text so both clients behave the same. This is a small change and belongs here because it is the same hint UX.

### Files touched

- `handlers/export.go`: two struct fields, two populated fields.
- `cmd/arkfile-client/offline_decrypt.go`: two struct fields, reordered flow with Account Key validation, hint display.
- `cmd/arkfile-client/commands.go`: hint in the batch download custom-password prompt.

## Mass Export

### Export auth

Both clients call `GET /api/files/:fileId/export` once per file with their normal session credential and mint no export tokens. The CLI already sends `Authorization: Bearer`, which `resolveExportAuthFromHeader` validates; the batch adds `ensureFreshSessionToken`, or the existing refresh-on-401 helper, between files.

The browser's session lives in the `__Host-arkfile-token` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`). The global `CookieTokenMiddleware` copies it into the Authorization header on every route, including this public GET, and `CSRFMiddleware` exempts GET as a safe method. A folder-picker `fetch` and a hidden same-origin iframe therefore authenticate exactly as the CLI does, after the same per-file refresh that `download-batch.ts` performs with `ensureFreshBatchAuth`. This keeps credentials out of URLs and removes a round trip per file.

Verify this before building on it: the Playwright check below asserts that the logged-in context can GET the export URL with no token and receive ARKB bytes. If that check fails, keep export tokens for the browser and mint each one immediately before its own GET. A token minted early can expire before its GET starts, while a long stream cannot outlive one, because validity is checked once when the request starts.

### Frontend

Rework `client/static/js/src/files/export.ts` around two small helpers: one that refreshes the session and triggers a native download of `/api/files/:fileId/export` through a hidden same-origin iframe, the same pattern `sw-streaming-download.ts` already relies on across browsers, and one that fetches the same URL and returns the response for streaming. The per-row Export button switches to the iframe trigger, so the browser has one export mechanism and the token request disappears. Neither path uses `window.location.href`, which cannot be looped.

Add `client/static/js/src/files/export-batch.ts` mirroring the shape of `download-batch.ts` minus the password machinery: resolve targets, open the directory picker under the click gesture when available (a cancelled picker falls back to native downloads, as in multi-download), list existing directory entries, reserve basenames, refresh the session between files, honor an `AbortController`, and produce a summary.

On the folder-picker path, fetch the export URL, treat a non-OK status or a body shorter than `Content-Length` as a failure, and pipe the body into a `FileSystemWritableFileStream` on a temporary entry that `move()` publishes under the reserved name. Unlike today's `downloadFileToDirectory`, the failure path removes only entries this attempt created and never touches a name that existed before the attempt. Where `move()` is unsupported, write to the reserved name directly; reservation guarantees that entry is new, so removing it on failure is safe.

On the fallback path, trigger one hidden iframe per file with a short fixed delay between triggers, keep each iframe attached long enough for the download manager to take over, and report each file as started. Expect inconsistent behavior across Firefox and Safari when many downloads start in sequence; the multiple-download permission warning covers the common case.

In `client/static/js/src/files/list.ts`, add an Export selected button to the existing `.file-list-toolbar` beside Download selected, disabled at zero selected, labeled with the count, resolving targets the same way Download selected does. Broaden the header comment in `files/selection.ts` from multi-download to vault multi-action. Confirm before starting when the set is large, noting that export downloads full stored objects, which are larger than the original files because they include padding.

Progress chrome matches multi-download on the folder-picker path: file i of N, a cancel control, continue past per-file failures, abort the remainder on session loss, and a final succeeded, failed, and skipped summary with one optional retry of failures. The fallback path reports started and skipped counts only.

### Bundle naming detail

Reserve the original filename first and append the suffix afterwards, rather than reserving the full `name.arkbackup` string. The basename helpers split on the final extension, so reserving `photo.png.arkbackup` directly would produce `photo.png-1.arkbackup` on a collision. Reserving `photo.png` first yields `photo.png` and `photo-1.png`, which become `photo.png.arkbackup` and `photo-1.png.arkbackup`. This keeps the original extension visible, prevents `photo.png` and `photo.jpg` from collapsing into the same reserved name, and lets an owner find a file in the folder by name.

Because reservation works on names without the suffix, the taken set must be built the same way. Every existing directory entry whose name ends in `.arkbackup`, compared case-insensitively, contributes its name minus the suffix, and other entries are ignored because they can never collide with a name ending in `.arkbackup`. Without this, a folder from an earlier export that holds `photo.png.arkbackup` would not register as a collision for `photo.png`, and the new bundle would target the old one. Both clients apply the same rule.

The native fallback path cannot choose its own filename and receives the server's `Content-Disposition` name, `<file_id>.arkbackup`; the browser resolves collisions there itself, for example as `<file_id> (1).arkbackup`. That is acceptable because bundle discovery validates content rather than names and deduplicates by `file_id`, so those bundles still decrypt correctly and land under their true filenames.

### CLI

Extend `cmd/arkfile-client/export.go` to accept the same selection surface as `download`, plus a whole-vault selector:

```text
arkfile-client export --file-id ID [--output PATH]
arkfile-client export --file-id ID [--file-id ID ...] --output-dir DIR
arkfile-client export --tags TAGS --output-dir DIR [--dry-run]
arkfile-client export --all --output-dir DIR [--dry-run]
```

Reuse `multiStringFlag`, the cursor-paging owner scan in `fetchAllOwnerFiles`, the client-side tag AND filter after decrypt, and `reserveBasenames`. `--all` selects every owner file and cannot be combined with `--file-id` or `--tags`. Preserve the current single-file default output of `<file-id>.arkbackup` so existing scripts keep working, but publish it through `writeAtomicOutput`: today's `export` opens its output with `O_TRUNC` and deletes it on failure, so a failed re-export to the same path destroys the earlier bundle.

Under `--output-dir`, names come from filenames decrypted with the agent's Account Key through `getOptionalAccountKey`. When no key is available, names fall back to `<file_id>.arkbackup` with a one-line notice, and `--tags` fails clearly because it cannot filter without the key. Build the taken set from existing `.arkbackup` entries as described above, stream each response body to a temporary file in the destination directory, and rename on completion. Keep Bearer auth and refresh the session between files. Retry each failed file once at the end of the run. Summary lines mirror the download batch.

`arkfile-admin export-file` stays single-file unless bulk admin disaster recovery is requested separately.

### Files touched

- `client/static/js/src/files/export.ts`
- `client/static/js/src/files/export-batch.ts` (new)
- `client/static/js/src/files/list.ts`
- `client/static/js/src/files/selection.ts` (comment only)
- `client/static/js/src/__tests__/export.test.ts` (token assertions replaced)
- `cmd/arkfile-client/export.go`
- `cmd/arkfile-client/main.go` (usage text)

## Chained Offline Decrypt

### Command surface

```text
arkfile-client decrypt-blob --bundle FILE --output PATH
arkfile-client decrypt-blob --bundle F1 --bundle F2 [...] --output-dir DIR
arkfile-client decrypt-blob --bundle-dir DIR --output-dir DIR [--dry-run]
```

`--username`, `--account-key-file`, `--use-agent`, and `--password-stdin` keep working and apply to the whole run, within the per-source limits described below. In multi-bundle mode, `--username` must match every bundle's `owner_username`.

### Discovery

For `--bundle-dir`, read directory entries non-recursively in sorted name order, skip subdirectories, and call the existing `parseBundle` on each regular file. `parseBundle` reads only the header, so this is cheap. Accept a file when the magic is ARKB, the version is 2, the header length is within the existing 1 MiB bound, the JSON parses, `file_id` and `owner_username` are present, and the file length is exactly `10 + header length + padded_size`, which is precisely what `streamExportBundle` writes. A bundle whose header lacks `padded_size` must be at least `10 + header length + size_bytes`, so old bundles stay valid. A file without ARKB magic is a non-bundle: counted in the summary, and listed individually only under `--dry-run` or verbose output. A file with ARKB magic that fails a later check is listed individually with its reason.

Switch `parseBundle` and `decryptBundleBlob` from `f.Read` to `io.ReadFull`. A short read is legal for any reader and common on FUSE and network mounts, where today it would misalign chunk boundaries and fail decryption with a misleading error.

After deduplicating by absolute path, deduplicate by `file_id`: keep the first copy in processing order and skip the others as `duplicate_file_id`. A folder that mixes browser fallback exports (`<file_id>.arkbackup`) with folder-picker exports (`photo.png.arkbackup`), or holds a re-exported `photo-1.png.arkbackup`, would otherwise decrypt the same file twice.

`--dry-run` prints each discovered bundle's path, `file_id`, owner, `password_type`, and size straight from the plaintext JSON header, marks duplicates, and never prompts for a password.

### Key sources and password input

The interactive prompt, `--password-stdin`, `--account-key-file`, and `--use-agent` apply to the whole run, but the three non-interactive sources each supply exactly one Account Key. `handleGetOfflineAccountKey` caches one key entry and rejects any other salt or profile, so the agent can serve only its own group. A key file carries no salt, so it is validated against each group. A group that a non-interactive source cannot unlock is skipped as `account_key_unavailable`, and re-entry applies only to interactive prompts.

With `--password-stdin`, single-bundle mode reads two lines exactly as today. Multi-bundle mode reads one line, the account password for the first group, and never reads custom passwords from stdin; a stdin password that fails validation marks that group `wrong_account_password`. Custom-password bundles always prompt on the controlling terminal, even when stdin supplied the account password, and are skipped as `terminal_required` when there is no terminal, after their filename, tags, and hint have been printed. Scripted custom decrypts use single-bundle mode. This mirrors the multi-download rule in `docs/wip/multi-dl.md` that batch custom passwords are interactive only, and it avoids a multi-line stdin contract whose order a script would have to predict.

### Batch flow

Put the orchestration in a new `cmd/arkfile-client/offline_decrypt_batch.go` so `offline_decrypt.go` stays focused on the single-bundle path and the parser. Single-bundle behavior routes through the same per-bundle function, so there is one code path for one file and for many.

1. Build the target list from `--bundle` values in argument order, then `--bundle-dir` discovery in sorted name order, deduplicating by absolute path and then by `file_id`.
2. Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)` in first-appearance order. When more than one group exists, say so before prompting.
3. For each group in turn, obtain the Account Key, validate it against the group's first bundle (re-entry only for interactive prompts), decrypt the group's filenames, and extend the output name reservation, which starts from the destination's existing entries and carries forward across groups.
4. Decrypt the group's account-password bundles in order.
5. Decrypt the group's custom-password bundles. For each, print filename, tags, and hint first, then prompt on the terminal with up to 3 attempts and a 2 minute wait per entry, or skip as `terminal_required` when there is no terminal.
6. Clear the group's Account Key before moving to the next group.
7. Print the summary.

Per-bundle failure never stops the run. A group whose Account Key cannot be obtained or validated marks its bundles skipped with the matching reason, and the run continues with the next group. Interrupt aborts the current bundle, cleans its temporary output, and marks the rest skipped.

The salt grouping is the subtle correctness requirement here. Deriving one key from the first bundle's `account_kdf_salt` and reusing it for the rest silently fails on any set spanning two owners. Processing groups one at a time also keeps a single Account Key in memory, which reserving every output name up front across the whole run would not allow.

### Summary and failure reasons

The summary reports counts for decrypted, failed, and skipped with an account versus custom breakdown, plus the aggregate non-bundle count, then one line per non-success carrying the filename when known (through `sanitizeDisplayText`), the bundle path, and a reason from a fixed set: `not_a_bundle`, `unsupported_version`, `unsupported_kdf_profile`, `bundle_length_mismatch`, `duplicate_file_id`, `owner_mismatch`, `account_key_unavailable`, `wrong_account_password`, `wrong_custom_password`, `terminal_required`, `prompt_timeout`, `prompt_cancelled`, `integrity_mismatch`, `write_failed`, `cancelled`, `skipped`. Reason strings never contain password material.

### Files touched

- `cmd/arkfile-client/offline_decrypt.go` (full reads, length check, per-bundle function)
- `cmd/arkfile-client/offline_decrypt_batch.go` (new)
- `cmd/arkfile-client/main.go` (usage text)

## Related Safety Fixes

These are small, sit in code this work touches, and close gaps found while reviewing the plan.

**Case-insensitive reservation.** Both `reserveBasenames` helpers (`cmd/arkfile-client/output_basename.go` and `client/static/js/src/files/output-basename.ts`) and `resolveDefaultDownloadPath` compare names case-insensitively while keeping each returned name's case. On a case-insensitive target, an existing `Photo.png` and a newly reserved `photo.png` are the same entry, so today a publish can replace it and the browser's failure cleanup can delete it. The change protects multi-download, export, `decrypt-blob --output-dir`, and the `share download` default name.

**Directory publish cleanup.** On failure, `downloadFileToDirectory` in `client/static/js/src/files/download.ts` removes the reserved name as well as its temporary entry. Apply the export rule there too: remove only entries the attempt created.

**Terminal-safe printing.** Route every CLI print of a decrypted filename, tag list, or hint through `sanitizeDisplayText`: the single-file download hint lines in `commands.go`, the batch download prompt, `list-files` output, the `share list` filename column, and `decrypt-blob`. `share download` already uses it.

**Owner single-file download name.** `download --file-id` without `--output` uses the decrypted filename directly as a path (the default-output block in `downloadOneOwnerFile`). Reduce it to a single path element, reject `.` and `..`, remove control and bidirectional characters, keep other leading dots because dotfile backups are legitimate for an owner, and reserve against existing entries so a default download never replaces a file. Only the owner's own clients can produce that ciphertext, so this is hardening rather than an exploitable bug.

**Download stdin guard.** The multi-file `--password-stdin` guard in `handleDownloadCommand` is unreachable because the batch branch returns first, so batch downloads currently read custom passwords, and their retries, from stdin lines. Move the guard above the batch branch so the documented single-file rule holds. No test script passes `--password-stdin` to a multi-file download.

Files touched: `cmd/arkfile-client/output_basename.go`, `cmd/arkfile-client/commands.go`, `client/static/js/src/files/output-basename.ts`, `client/static/js/src/files/download.ts`.

## Tests

### Go unit

Bundle metadata assertions belong in `handlers/export_rotation_test.go` beside the existing `TestBuildBundleMetadataIncludesAccountKDFMetadata`, which already calls `buildBundleMetadata` directly with no database. Cover: hint fields present and byte-identical to the stored ciphertext for a custom-password file with a hint; both fields omitted when either stored field is empty; no plaintext hint anywhere in the serialized header. The existing account salt and KDF profile assertions must still pass.

`cmd/arkfile-client/offline_decrypt_test.go`: hint round trip through a bundle; absent hint prints the no-hint line; a present but undecryptable hint prints the could-not-decrypt warning and continues; hint tampering fails AEAD because `file_id` and owner are bound in AAD; the hint prints before the custom-password prompt; control characters are neutralized before display; a wrong Account Key on a custom-password bundle is caught before the custom prompt, with re-entry for interactive input and a clear failure for stdin; the length check rejects truncated and padded-out bundles and accepts an old bundle without `padded_size`. Factor the header parse to accept an `io.Reader` so a test can feed it short reads, and cover the blob reader the same way. Extend `FuzzParseBundle` seeds with a hint-bearing bundle and one carrying an oversized hint field.

New batch coverage: discovery accepts valid bundles and rejects a decoy file, a truncated bundle, and a wrong-magic file; duplicates by `file_id` are skipped as `duplicate_file_id`; salt grouping derives one key per distinct salt, never reuses a key across salts, and holds one key at a time; the agent and key-file sources serve only a group they can unlock and mark others `account_key_unavailable`; multi-bundle stdin consumes exactly one line; custom bundles without a terminal are skipped as `terminal_required` after their hint prints; ordering places account bundles before custom bundles within each group; per-bundle failure continues the run; interrupt marks the remainder skipped; output basename reservation carries across groups and temporary files are cleaned up; secret disposal runs on success, wrong password, timeout, integrity failure, and cancellation.

Export and shared helpers: CLI multi-export into a populated directory reserves `photo-1.png.arkbackup` beside an existing `photo.png.arkbackup` and leaves the old bytes unchanged; a failed single-file re-export to an existing path leaves the earlier bundle intact; `--all` rejects `--file-id` and `--tags`; `reserveBasenames` and `resolveDefaultDownloadPath` treat `Photo.png` and `photo.png` as a collision; a multi-file download rejects `--password-stdin`; the owner single-file default name stays inside the current directory, keeps a leading dot, and never replaces an existing file.

### TypeScript unit

Export batch coverage: no export token is requested on any path; the folder-picker path fetches `/api/files/:fileId/export` with session credentials and streams into the writable without Blob buffering; a non-OK status or short body fails that file and cleans up only its own temporary entry; the top-level window never navigates; the fallback path triggers one hidden iframe per file with pacing and reports files as started; abort stops the run; session loss skips the remainder; a per-file failure does not stop the folder-picker run; reservation produces `photo.png.arkbackup` and `photo-1.png.arkbackup`, treats an existing `photo.png.arkbackup` as taken, and is case-insensitive. Rewrite the token assertions in `client/static/js/src/__tests__/export.test.ts` for the per-row button, which now triggers the hidden iframe with no token request. Extend `output-basename.test.ts` with the case-insensitive collision case and cover the narrowed cleanup in `downloadFileToDirectory`.

### e2e-test.sh

Assert a hint line in `decrypt-blob` output for a custom-password file that has a hint, and the explicit no-hint line for a file without one. Assert the hint is printed before the custom password is read. Add a raw API privacy canary confirming no plaintext hint in the export response header and no hint field of any kind in share metadata responses.

Add a CLI multi-export into `--output-dir` covering account and custom files with no password entry, plus `--tags --dry-run` and `--all --dry-run`. Export one of those files again into the same directory and assert it lands under a `-1` name while the first bundle stays byte-identical; that second copy also serves as the duplicate case below.

Add a chained `decrypt-blob --bundle-dir` run over that export directory with a decoy non-bundle file and a truncated copy of one bundle present, passing the account password on stdin. Assert that account bundles decrypt and match their original digests, custom bundles are skipped as `terminal_required` with their hints printed, and the summary reports the non-bundle count, `bundle_length_mismatch`, and `duplicate_file_id`. Then decrypt one custom bundle with single-bundle two-line stdin. The existing single-file export and decrypt tests stay as they are.

### e2e-playwright.ts

Reuse the existing multi-select corpus. First assert that the logged-in context can GET `/api/files/:fileId/export` with no token and receives the ARKB magic, which proves the cookie path that browser export relies on. Then select two files, click Export selected, abort the directory picker with the existing stub, wait for two downloads, check the ARKB magic on each, and assert no `/export-token` request was made. Exercise the per-row Export button once the same way. Full offline decrypt stays in `e2e-test.sh`.

### online-integrity-test.sh

Confirm the existing export and `decrypt-blob` steps still pass unchanged.

## Documentation

`docs/api.md` Backup Export section: note the two optional hint fields in bundle metadata, that they are opaque Account Key ciphertext, and that they are omitted when no hint was saved. Replace the browser export flow paragraph: the browser authenticates the GET with its session cookie, and the export-token endpoint remains only until the follow-up removes it. State that the browser and CLI batch export paths use the same per-file GET with no new endpoint.

`docs/security.md`: extend the `.arkbackup` version 2 paragraph to list the encrypted hint alongside the other owner metadata fields, restate that share envelopes never carry hints, and say plainly that exported bundle filenames show the original names to anyone who can see the backup folder while bundle contents and header metadata stay encrypted.

`docs/user-faq.md`: prose-only entries covering exporting selected, tagged, or all files as individual encrypted backup bundles; that bundle filenames are readable on disk, so an owner who needs names hidden should keep the folder somewhere private or rename the files, since decryption restores the true names; and that a custom-password bundle shows its hint after the account password is entered but still needs the file's own password to decrypt. Paragraphs only, no lists and no code spans, per that file's rules.

`docs/wip/multi-dl.md`: note that bulk export, previously listed as out of scope, is now covered here and reuses the selection model, and that the multi-file `--password-stdin` guard was fixed here.

## Out of Scope

- Server-side zip, tar, or any bulk archive job
- Parallel export or parallel offline decrypt
- A TypeScript `.arkbackup` parser
- Any change to bundle version, chunk layout, AAD composition, or padding
- Hints in share envelopes or any public share response
- Recursive `--bundle-dir` discovery
- Bulk delete, bulk share, or bulk retag
- Bulk admin export
- Deleting the export-token endpoint, `ExportTokenClaims`, and their tests, which is a follow-up once this work passes e2e
- Incremental re-export that skips files already present in the destination; the CLI could add it later by reading `file_id` from existing bundle headers
- An opaque-name export mode for owners who want filenames hidden on the backup medium
- Unattended custom-password input for batch decrypt; custom passwords stay interactive, as in multi-download

## Implementation Checklist

- [ ] Hint fields in `handlers/export.go` bundle metadata, populated when both stored fields are present
- [ ] Matching fields in CLI `bundleMeta`, with the schema alignment comment updated
- [ ] `decrypt-blob` validates the Account Key, then decrypts and displays filename, tags, and hint before the custom-password prompt, with the absent and undecryptable hint wording
- [ ] Hint shown in the CLI batch download custom-password prompt (parity with the browser)
- [ ] `sanitizeDisplayText` applied at every CLI print site for decrypted filenames, tags, and hints
- [ ] Browser export authenticates with the session cookie on the per-row button and the batch, with no token requests and a Playwright proof of the cookie path
- [ ] Frontend Export selected button reusing the existing selection set
- [ ] `export-batch.ts` with folder-picker and hidden-iframe fallback paths, streaming only, cleanup limited to entries the attempt created
- [ ] Re-export safety in both clients: existing `.arkbackup` entries count as taken minus the suffix
- [ ] CLI `export` accepts repeatable `--file-id`, `--tags`, `--all`, `--output-dir`, and `--dry-run`; single-file export publishes atomically
- [ ] `decrypt-blob` accepts repeatable `--bundle` and `--bundle-dir` with content-validated discovery, the length check, full reads, and `file_id` deduplication
- [ ] Per-group processing with one Account Key at a time, validation with interactive re-entry, and `account_key_unavailable` for sources that cannot serve a group
- [ ] Multi-bundle stdin carries only the account password; custom prompts are terminal-only with `terminal_required`
- [ ] Account-first then custom ordering within each group, single pass, 3 attempts per bundle
- [ ] Summary with the fixed failure reason set, including the aggregate non-bundle count
- [ ] Case-insensitive reservation in both `reserveBasenames` helpers and `resolveDefaultDownloadPath`
- [ ] `downloadFileToDirectory` cleanup limited to entries the attempt created
- [ ] Owner single-file download default name reduced to a safe single path element and reserved
- [ ] Multi-file `download --password-stdin` guard moved above the batch branch
- [ ] Go and TypeScript unit tests green
- [ ] `docs/api.md`, `docs/security.md`, `docs/user-faq.md`, and `docs/wip/multi-dl.md` updated
- [ ] Developer runs `dev-reset.sh`, then `e2e-test.sh` and `e2e-playwright.sh`
