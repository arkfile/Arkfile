# Multi-File Backup Export, Bundle Hints, Chained Offline Decrypt, and Integrity Manifests

## Reasoning

Owners can select many vault files and stream-decrypt them in one pass (see `docs/wip/multi-dl.md`), but `.arkbackup` export is still strictly one file at a time in both clients, and a bundle cannot remind its owner which custom password protects it. That combination makes disaster-recovery export unusable at scale: exporting 40 files means 40 clicks, and a folder of custom-password bundles is an archive with no way to recall which password opens which file. A large collection on removable media also has no simple inventory that can detect accidental corruption or incomplete copies without decrypting every payload. This work closes four gaps together: put the already-encrypted custom-password hint into the bundle, let both clients export a selected set of bundles, let `decrypt-blob` process or inspect a list or folder of bundles with one account-password entry per Account Key group, and let the CLI create and verify a minimal rebuildable integrity manifest for any bundle folder.

Nothing here weakens the sharing boundary. Anonymous share recipients must never receive an owner's custom-password hint, and that stays true: hints live only in owner metadata and owner bundles, never in share envelopes.

## Status

Planning. The shared helpers this plan reuses already landed with the CLI share download filename fix: `sanitizeDisplayText` in `cmd/arkfile-client/display_text.go`, `safeDownloadBasename` and `resolveDefaultDownloadPath` in `cmd/arkfile-client/output_basename.go`, and `isLowerHexSHA256` in `cmd/arkfile-client/crypto_utils.go`. Nothing else in this plan is implemented.

## Overview

Four coordinated changes, plus a few safety fixes in shared code they depend on.

**Bundle hints.** `.arkbackup` version 2 gains two optional fields, `encrypted_password_hint` and `password_hint_nonce`, copied verbatim from the owner's file metadata. They are Account Key ciphertext under the existing AAD label `encrypted_password_hint`, so the server still stores and forwards opaque bytes and learns nothing new. Bundles without the fields remain fully valid; already-downloaded bundles are untouched and keep working. `decrypt-blob` decrypts and shows the hint using only the account password, before it asks for the custom password, so the hint arrives when it is actually useful.

**Mass export.** The vault selection set already built for multi-download gains an Export selected action, and `arkfile-client export` gains repeatable `--file-id`, `--tags`, `--all`, and `--output-dir`. No new endpoint: both clients loop the existing per-file streaming GET, the CLI with its Bearer session and the browser with its session cookie. No zip, no server-side archive job, no password prompt. Bundles keep readable names (`photo.png.arkbackup`) so an owner can find a file in a backup folder without decrypting anything, and re-exporting into a folder that already holds bundles never replaces or deletes them.

**Chained offline decrypt and inspection.** `decrypt-blob` accepts repeatable `--bundle` or a `--bundle-dir`, discovers valid bundles through one strict parser rather than trusting filenames, retains duplicate copies as fallback candidates until one copy restores successfully, and processes one Account Key salt group at a time with one account-password entry per group. Within each group it decrypts account-password bundles first and custom-password bundles last, prompting for custom passwords on the terminal with the hint displayed, and it prints one clear summary of successes, failures, and skips. An inspection mode decrypts and displays owner metadata without reading payloads or asking for custom passwords.

**Minimal integrity manifest.** A local CLI command scans any folder of old or new bundles and writes a deterministic, versioned JSON manifest containing only each stored bundle name, `file_id`, bundle version, byte length, and SHA-256 digest of the complete `.arkbackup` file. A matching verification mode detects missing, changed, malformed, and unlisted bundles with no password. The manifest is optional, atomically replaceable, and always rebuildable from the bundles; it is never needed for decryption and does not change bundle version 2.

**Download parity.** `arkfile-client download` gains `--all`, matching what the web app already does with Select all matching filter and Download selected, so the CLI can restore a whole vault as plaintext in one run just as `export --all` saves it as bundles. Both commands resolve their targets through one shared selection helper, and one shared Output flag rules row governs `--output` and `--output-dir` across `download`, `export`, and `decrypt-blob`.

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
| Browser bundle parsing | There is no TypeScript `.arkbackup` parser today and this work does not add one. The browser only triggers and writes downloads. Integrity-manifest creation and verification are local CLI operations that also work on folders populated by browser export |
| Hint display order | `decrypt-blob` decrypts and prints filename, tags, and hint after the Account Key is obtained and validated, and before the custom-password prompt |
| Hint display wording | Print the explicit no-hint line only when both hint fields are absent. When the fields are present but do not decrypt, print a warning that the hint could not be decrypted and continue to the prompt. A hint failure never fails the bundle: the hint is display-only, and content stays protected by per-chunk AES-GCM and the SHA-256 check |
| Wrong account password | Caught before any custom-password prompt by validating the Account Key against authenticated material from the group's usable candidates (see Account Key validation). Interactive entry allows re-entry; non-interactive sources fail the bundle or group. No more silent downgrade to "encrypted SHA-256 unavailable" |
| Terminal safety | Decrypted filenames, tags, and hints are user-authored display strings. Every CLI print site routes them through `sanitizeDisplayText`, which replaces C0 and C1 control characters, DEL, and Unicode bidirectional controls with `?` |
| Hint logging | Print to stdout only. Never pass a hint to `logVerbose`, never write it to a file, never include it in an error string |
| Export API surface | No new endpoint. Both clients call `GET /api/files/:fileId/export` once per file |
| Export auth | Move `GET /api/files/:fileId/export` under `mfaProtectedGroup`, so CLI Bearer sessions and browser cookies pass through the standard JWT, revocation, approval, full-token, and current-MFA middleware stack. Refresh the session between files. Neither client mints export tokens |
| Export token endpoint | Delete `POST /api/files/:fileId/export-token`, `ExportTokenClaims`, the `?token=` branch and manual JWT parsing in `resolveExportAuth`, and their tests in this work after the cookie-path test proves direct authenticated GET works. Do not leave export on the public router or preserve an unused alternate authentication path |
| Export archive format | No zip, no tar, no server-side archive job. One `.arkbackup` per file, mirroring the multi-download decision |
| Export passwords | Export never prompts for any password. Only offline decrypt does |
| Export parallelism | Sequential only, mirroring the upload and download batches |
| Export selection model | Reuse the existing `file_id` selection set in `client/static/js/src/files/selection.ts` and its existing Select all shown and Select all matching filter controls (with no filter active, the latter selects the whole vault). No second selection store, no separate export mode, no new select-all control |
| Whole-vault selection | `export --all` and `download --all` mirror the web app's Select all matching filter with no filter active. Both resolve targets through one shared selection helper, require `--output-dir`, cannot be combined with `--file-id` or `--tags`, and print a clear message and exit zero when the vault is empty. An explicit `--tags` selection that matches nothing keeps today's error |
| Export destination (Chromium) | One `showDirectoryPicker({ mode: 'readwrite' })` under the click gesture, then one cookie-authenticated `fetch` and one writable stream per bundle. Explicit chooser cancellation cancels export; it never starts native fallback downloads |
| Export destination (fallback) | Sequential native downloads to the browser's default folder through one hidden same-origin iframe per file (never `window.location.href`), paced by a short fixed delay between triggers (one named constant, for example 250 ms; unlike the multi-download fallback there is no per-file decrypt work to pace the sequence naturally), with the same multiple-download permission warning used by multi-download. The page cannot observe completion or HTTP errors on this path, so files are reported as started, not succeeded |
| Export bundle names | Readable names. Reserve the original filename with the existing basename helper, then append `.arkbackup`: `photo.png.arkbackup`, `photo-1.png.arkbackup`. Falls back to `<file_id>.arkbackup` when metadata did not decrypt. The fallback path receives the server's `<file_id>.arkbackup` name and the browser resolves its own collisions |
| Export name visibility | Readable names show original filenames to anyone who can see the backup folder. The encrypted payload and owner metadata ciphertext remain protected, while operational header fields such as file ID, owner username, password type, sizes, chunk parameters, public salts, and versions remain plaintext as they already are in bundle version 2. Documented plainly in `docs/security.md` and the user FAQ. No opaque-name mode in this work |
| Re-export safety | Re-exporting through `--output-dir` or a browser directory handle never replaces or deletes an existing entry. Existing entries ending in `.arkbackup` count as taken under their name minus the suffix, comparisons are case-insensitive, and failure cleanup removes only entries the attempt itself created. Final publish must use no-clobber semantics or fail and reserve another name if a destination appeared after the initial scan; a prior name snapshot alone is not a no-replacement guarantee. An explicit single-file `--output PATH` intentionally replaces that exact path only after a complete successful write |
| Export memory | Stream the response body into the writable sink. Never buffer a bundle in a Blob or an ArrayBuffer |
| Export failure policy | Continue past per-file failures. Session loss aborts the rest and marks them skipped. The folder-picker path offers one optional retry of failures, the CLI retries each failed file once at the end of the run, and retries reuse the target's original reserved name unless a late collision forces a new reservation. The fallback path has no failure signal to retry on. Final summary in every case |
| Single-file CLI export | Keeps the `<file-id>.arkbackup` default and explicit `--output`, but publishes through `writeAtomicOutput` so a failed re-export to the same path no longer truncates and then deletes the earlier bundle. Successful exact-path replacement remains intentional and is distinct from the no-clobber `--output-dir` contract |
| Output flag rules | `--output` and `--output-dir` are mutually exclusive in `download`, `export`, and `decrypt-blob`. `--output` publishes one explicitly listed target to an exact path. `--output-dir` publishes any selection under reserved names inside the directory and is required for scanned (`--tags`, `--all`, `--bundle-dir`) and plural selections. Mode follows the selection, not the destination: one explicitly listed target keeps single-target behavior wherever it writes (including the `--password-stdin` contracts of `download` and `decrypt-blob`), while scanned or plural selections run the batch or chained machinery |
| Decrypt input flags | Repeatable `--bundle`, or `--bundle-dir DIR`. `--output` publishes one explicitly listed bundle to an exact path; `--output-dir` publishes under reserved names and is required for `--bundle-dir` and for more than one bundle |
| Bundle discovery | Validate content, not the extension, through one validator shared by explicit inputs, directory discovery, and manifest tooling. Require a regular non-symlink file; ARKB magic; matching outer and metadata version 2; bounded non-empty JSON header; required identifiers and fields; supported password type, envelope, key type, KDF profile, and exact salt/nonce encodings; non-negative bounded sizes and chunk counts with internally consistent chunk math and padding; and file length exactly `10 + header length + padded_size` (at least `10 + header length + size_bytes` when an old bundle has no `padded_size`). Non-recursive |
| Duplicate bundles | Deduplicate identical absolute paths immediately. Group remaining copies by `file_id`, but retain them as ordered fallback candidates until one copy decrypts and verifies successfully. After one succeeds, mark later copies `duplicate_file_id`; if a copy is damaged, continue to the next copy rather than allowing a corrupt first entry to suppress a valid backup |
| Discovery reporting | Report non-bundle files as an aggregate count by default and list them individually only under `--dry-run` or verbose output, so pointing at a large Downloads folder does not produce hundreds of skip lines |
| Account Key derivation | Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)` and process one group at a time, holding one Account Key at a time and clearing it before the next group. Never reuse a key derived from one bundle's salt against a different salt |
| Multiple salt groups | State plainly before prompting that the set spans more than one Account Key salt and that one password entry is needed per group. This is rare: OPAQUE re-registration keeps the salt, so only bundles from different owners or from a deleted and recreated username produce more than one group |
| Decrypt ordering | Groups in first-appearance order. Within each group, account-password bundles first and custom-password bundles last, matching the download batch |
| Account Key sources | Interactive prompt, `--password-stdin`, `--account-key-file`, or `--use-agent`, applying to the whole run. Each non-interactive source supplies exactly one Account Key: the agent caches one key and rejects other salts, and a key file carries no salt. Groups a non-interactive source cannot unlock are skipped as `account_key_unavailable` |
| Password stdin | Single-bundle mode keeps today's two-line order (account password, then custom password), which `e2e-test.sh` and `online-integrity-test.sh` rely on. In multi-bundle mode, stdin carries only the account password for the first group, and custom passwords are never read from stdin |
| Account Key validation | Validate each group's key against authenticated material from its ordered candidates: for an account-type bundle use the FEK unwrap, otherwise decrypt the first Account Key metadata field present (filename, then digest). If one candidate fails but another validates, classify the failed candidate as damaged and continue the group; a corrupt first bundle must not make the correct key look wrong or suppress the whole group. Only when no candidate validates is the source treated as the wrong or unavailable Account Key. Interactive prompts allow up to 3 re-entries; a stdin password that fails every usable candidate marks its group `wrong_account_password` |
| Custom password prompts | Interactive terminal only, after the filename, tags, and hint are printed, even when `--password-stdin` supplied the account password. Without a controlling terminal, custom bundles are skipped as `terminal_required`, mirroring the multi-download rule in `docs/wip/multi-dl.md` |
| Custom password attempts | 3 attempts per logical file, 2 minute wait per entry, reusing `MaxBatchCustomPasswordAttempts` and `PasswordTimeoutBatchCustom` |
| Custom retry rounds | Single pass. Offline decrypt has no network flakiness, so a failure is nearly always a wrong password and per-bundle attempts already cover it. Do not reuse `MaxBatchDownloadRounds` |
| Custom password reuse | None across logical files or retry rounds. Prompt per custom file and retain nothing after that file, matching the Secure Secret Handling rule in `docs/wip/multi-dl.md`. Ordered physical copies with the same `file_id` are fallback candidates for one logical file, so one in-scope password attempt and FEK may try those copies before being cleared; this is not cross-file reuse |
| Decrypt output names | Decrypted filename reserved with the basename helper; falls back to the bundle basename minus `.arkbackup`, then to `file_id`. Reservation starts from the entries already in the destination and grows group by group, case-insensitively |
| Decrypt output safety | Write to a temporary file in the destination directory, verify SHA-256, remove the temporary file on any failure, and publish with the same no-clobber boundary as `--output-dir` export. Reservation chooses the intended name, but final publication must still refuse or re-reserve after a late collision rather than relying on plain replacing `os.Rename` behavior |
| Decrypt interrupt | Abort the current bundle, clean its temporary output, dispose secrets, mark remaining bundles skipped, print the normal summary |
| Decrypt exit status | Non-zero when any bundle failed or was skipped for a reason other than `duplicate_file_id`; non-bundle files never affect it; zero otherwise. Mirrors the download batch, which exits non-zero on any unresolved failure or skip |
| Secret handling | Follows the Secure Secret Handling section of `docs/wip/multi-dl.md` verbatim. Fresh buffers per attempt, `clearBytes` at the narrowest scope, one Account Key alive at a time, no password or derived key in state, logs, error text, or summaries |
| Name reservation case | Both `reserveBasenames` helpers (Go and TypeScript) and `resolveDefaultDownloadPath` compare names case-insensitively, because backup and restore targets are often case-insensitive (exFAT or FAT drives on Linux, and macOS or Windows folders reached through the browser picker). Returned names keep their original case |
| Metadata-only inspection | `decrypt-blob --bundle-dir DIR --inspect` performs the same discovery, grouping, Account Key validation, and safe metadata display without reading payload bytes, creating outputs, or requesting custom passwords. It shows filename, tags, hint, file ID, password type, bundle path, and bundle size. `--dry-run` remains the no-password plaintext-header view; `--inspect` is human output only in this work |
| Manifest format | `arkbackup-manifest.json`, top-level format `arkbackup-integrity-manifest`, version 1, with entries containing only `bundle_name`, `file_id`, `bundle_version`, `bundle_size_bytes`, and lowercase whole-bundle `sha256`. Entries are sorted deterministically by stored bundle name. No original filename field, plaintext-file digest, tags, hint, password type, owner username, or decrypted metadata |
| Manifest lifecycle | `arkfile-client backup-manifest create --bundle-dir DIR` atomically creates or replaces the derivative manifest after a complete successful scan. `backup-manifest verify` streams and checks every listed file and reports missing, changed, malformed, and unlisted valid bundles. The manifest is optional, passwordless, rebuildable, never trusted as bundle metadata, and never required for decrypt |
| Manifest security claim | The manifest detects accidental media corruption, incomplete copies, and directory drift while an unchanged manifest is available. It is not signed or keyed and does not authenticate the collection against an attacker who can replace both bundles and manifest. Whole-bundle hashes fingerprint exact encrypted bundle copies but do not expose plaintext content hashes |
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

Both clients call `GET /api/files/:fileId/export` once per file with their normal session credential and mint no export tokens. Move the GET from the public router to `mfaProtectedGroup`, where the standard JWT, token-revocation, approval, full-token, and current-MFA middleware stack validates both clients. The CLI continues to send `Authorization: Bearer` and adds `ensureFreshSessionToken`, or the existing refresh-on-401 helper, between files.

The browser's session lives in the `__Host-arkfile-token` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`). The global `CookieTokenMiddleware` copies it into the Authorization header before the protected route middleware runs, and `CSRFMiddleware` exempts GET as a safe method. A folder-picker `fetch` and a hidden same-origin iframe therefore authenticate through the same route stack as the CLI, after the same per-file refresh that `download-batch.ts` performs with `ensureFreshBatchAuth`. This keeps credentials out of URLs and removes a round trip per file.

Verify the cookie path first: the Playwright check below asserts that the logged-in context can GET the protected export URL with no query token and receive ARKB bytes. Once that proof passes, delete `POST /api/files/:fileId/export-token`, `ExportTokenClaims`, query-token parsing, the manual full-JWT parser in `resolveExportAuth`, and their tests as part of this work. If the cookie-path proof initially fails, fix the protected cookie-authenticated route rather than retaining the special public export authentication path.

### Frontend

Rework `client/static/js/src/files/export.ts` around two small helpers: one that refreshes the session and triggers a native download of `/api/files/:fileId/export` through a hidden same-origin iframe, the same pattern `sw-streaming-download.ts` already relies on across browsers, and one that fetches the same URL and returns the response for streaming. The per-row Export button switches to the iframe trigger, so the browser has one export mechanism and the token request disappears. Neither path uses `window.location.href`, which cannot be looped.

Add `client/static/js/src/files/export-batch.ts` mirroring the shape of `download-batch.ts` minus the password machinery: resolve targets, open the directory picker under the click gesture when available, list existing directory entries, reserve basenames, refresh the session between files, honor an `AbortController`, and produce a summary. If the picker API is unavailable, use native downloads; if the user explicitly cancels the picker, cancel the export without triggering any downloads.

On the folder-picker path, fetch the export URL, treat a non-OK status or a body shorter than `Content-Length` as a failure, and pipe the body into a `FileSystemWritableFileStream` on a temporary entry that `move()` publishes under the reserved name. Unlike today's `downloadFileToDirectory`, the failure path removes only entries this attempt created and never touches a name that existed before the attempt. Recheck the destination immediately before publish and use no-clobber behavior where the API supports it; if a late collision appears, reserve a new name or fail that file rather than replacing the entry. Where `move()` is unsupported, create the reserved destination only after a fresh absence check and document the browser API's residual race honestly; never knowingly open and truncate an entry that already exists.

On the fallback path, trigger one hidden iframe per file with a short fixed delay between triggers (the named constant from the Export destination (fallback) row), keep each iframe attached long enough for the download manager to take over, and report each file as started. Expect inconsistent behavior across Firefox and Safari when many downloads start in sequence; the multiple-download permission warning covers the common case.

In `client/static/js/src/files/list.ts`, add an Export selected button to the existing `.file-list-toolbar` beside Download selected, disabled at zero selected, labeled with the count, resolving targets the same way Download selected does. Broaden the header comment in `files/selection.ts` from multi-download to vault multi-action. Confirm before starting when the set is large, noting that export downloads full stored objects, which are larger than the original files because they include padding.

Progress chrome matches multi-download on the folder-picker path: file i of N, a cancel control, continue past per-file failures, abort the remainder on session loss, and a final succeeded, failed, and skipped summary with one optional retry of failures. A retry reuses its reserved basename unless a late collision requires a new one. The fallback path reports started and skipped counts only.

### Bundle naming detail

Reserve the original filename first and append the suffix afterwards, rather than reserving the full `name.arkbackup` string. The basename helpers split on the final extension, so reserving `photo.png.arkbackup` directly would produce `photo.png-1.arkbackup` on a collision. Reserving `photo.png` first yields `photo.png` and `photo-1.png`, which become `photo.png.arkbackup` and `photo-1.png.arkbackup`. This keeps the original extension visible, prevents `photo.png` and `photo.jpg` from collapsing into the same reserved name, and lets an owner find a file in the folder by name.

Because reservation works on names without the suffix, the taken set must be built the same way. Every existing directory entry whose name ends in `.arkbackup`, compared case-insensitively, contributes its name minus the suffix, and other entries are ignored because they can never collide with a name ending in `.arkbackup`. Without this, a folder from an earlier export that holds `photo.png.arkbackup` would not register as a collision for `photo.png`, and the new bundle would target the old one. Both clients apply the same rule, then still enforce no-clobber publication because the directory snapshot can become stale.

The native fallback path cannot choose its own filename and receives the server's `Content-Disposition` name, `<file_id>.arkbackup`; the browser resolves collisions there itself, for example as `<file_id> (1).arkbackup`. That is acceptable because bundle discovery validates content rather than names and deduplicates by `file_id`, so those bundles still decrypt correctly and land under their true filenames.

### CLI

Extend `cmd/arkfile-client/export.go` to accept the same selection surface as `download`, plus a whole-vault selector:

```text
arkfile-client export --file-id ID [--output PATH]
arkfile-client export --file-id ID --output-dir DIR
arkfile-client export --file-id ID [--file-id ID ...] --output-dir DIR
arkfile-client export --tags TAGS --output-dir DIR [--dry-run]
arkfile-client export --all --output-dir DIR [--dry-run]
```

Resolve targets with the shared selection helper described under Download Parity, which wraps `multiStringFlag`, the cursor-paging owner scan in `fetchAllOwnerFiles`, and the client-side tag AND filter after decrypt, and name outputs with `reserveBasenames`. `--all` selects every owner file and cannot be combined with `--file-id` or `--tags`. Destination flags follow the Output flag rules row: a single `--file-id` with `--output-dir` is a batch of one that takes its name through the `--output-dir` naming path below and runs through the batch machinery, which is safe because export never prompts; a single `--file-id` with `--output`, or with neither destination flag, keeps today's exact-path and default behavior; and `--output` together with `--output-dir`, or with a plural or scanned selection, is rejected. Preserve the current single-file default output of `<file-id>.arkbackup` so existing scripts keep working, but publish it through `writeAtomicOutput`: today's `export` opens its output with `O_TRUNC` and deletes it on failure, so a failed re-export to the same path destroys the earlier bundle.

Under `--output-dir`, names come from filenames decrypted with the agent's Account Key through `getOptionalAccountKey`. When no key is available, names fall back to `<file_id>.arkbackup` with a one-line notice, and `--tags` fails clearly because it cannot filter without the key. Build the taken set from existing `.arkbackup` entries as described above, stream each response body to a temporary file in the destination directory, and publish with a no-clobber primitive or reserve again if the destination appeared after the scan. Do not use a plain `os.Rename` as the no-replacement boundary because it replaces an existing destination on supported Unix filesystems. Keep Bearer auth and refresh the session between files. Retry each failed file once at the end of the run, reusing its reservation unless a late collision requires a new one. Summary lines mirror the download batch.

`arkfile-admin export-file` stays single-file unless bulk admin disaster recovery is requested separately.

### Files touched

- `client/static/js/src/files/export.ts`
- `client/static/js/src/files/export-batch.ts` (new)
- `client/static/js/src/files/list.ts`
- `client/static/js/src/files/selection.ts` (comment only)
- `client/static/js/src/__tests__/export.test.ts` (token assertions replaced)
- `handlers/route_config.go` and `handlers/export.go` (protected GET route; export-token path removed)
- `cmd/arkfile-client/export.go`
- `cmd/arkfile-client/main.go` (usage text)

## Chained Offline Decrypt

### Command surface

```text
arkfile-client decrypt-blob --bundle FILE --output PATH
arkfile-client decrypt-blob --bundle FILE --output-dir DIR
arkfile-client decrypt-blob --bundle F1 --bundle F2 [...] --output-dir DIR
arkfile-client decrypt-blob --bundle-dir DIR --output-dir DIR [--dry-run]
arkfile-client decrypt-blob --bundle-dir DIR --inspect
```

`--username`, `--account-key-file`, `--use-agent`, and `--password-stdin` keep working and apply to the whole run, within the per-source limits described below. In multi-bundle mode, `--username` must match every bundle's `owner_username`.

Mode follows the selection, per the Output flag rules row: one explicitly listed `--bundle` is single-bundle mode wherever it writes, so `--bundle FILE --output-dir DIR` keeps the two-line stdin order and publishes under a reserved name in the directory. `--bundle-dir` always enters chained mode and requires `--output-dir` even when it discovers exactly one bundle, except that `--inspect` creates no output and therefore forbids both destination flags. `--inspect` and `--dry-run` are mutually exclusive: dry-run reports only plaintext header fields and never prompts, while inspection obtains and validates each Account Key and decrypts owner metadata without reading payload bytes or asking for custom passwords. `--output` together with `--output-dir`, or with a plural or `--bundle-dir` selection, is rejected.

### Discovery

For `--bundle-dir`, read directory entries non-recursively in sorted name order, skip directories, symlinks, devices, and other non-regular entries, and call the shared bundle validator on each regular file. The validator reads only the bounded header and file metadata, so discovery is cheap. It validates the ARKB magic; matching outer and metadata version 2; a non-empty header within the existing 1 MiB bound; JSON decoding; required identifiers and fields; supported password type, FEK-envelope version, envelope key type, KDF profile, and exact salt/nonce encodings; non-negative bounded sizes and chunk counts whose arithmetic and padding relationships are internally consistent; and file length exactly `10 + header length + padded_size`. A bundle whose header lacks `padded_size` must be at least `10 + header length + size_bytes`, so old bundles stay valid. The same validator is used for explicit `--bundle` inputs and integrity-manifest tooling so acceptance cannot drift. A file without ARKB magic is a non-bundle: counted in the summary, and listed individually only under `--dry-run` or verbose output. A file with ARKB magic that fails a later check is listed individually with its stable reason.

Switch `parseBundle` and `decryptBundleBlob` from `f.Read` to `io.ReadFull`. A short read is legal for any reader and common on FUSE and network mounts, where today it would misalign chunk boundaries and fail decryption with a misleading error.

After deduplicating identical absolute paths, group remaining candidates by `file_id` in processing order. Try copies in that order until one decrypts and verifies successfully, then skip the remaining copies as `duplicate_file_id`. If a copy is malformed, damaged, or fails payload integrity, continue to the next copy instead of allowing the first copy to suppress a valid backup. A folder that mixes browser fallback exports (`<file_id>.arkbackup`) with folder-picker exports (`photo.png.arkbackup`), or holds a re-exported `photo-1.png.arkbackup`, therefore restores the file once while preserving redundancy when one copy is damaged.

`--dry-run` prints each discovered bundle's path, `file_id`, owner, `password_type`, and size straight from the plaintext JSON header, marks duplicate candidate groups, and never prompts for a password. `--inspect` obtains one Account Key per group, validates it against usable authenticated candidates, and prints the safely sanitized decrypted filename, tags, and hint plus the file ID, password type, bundle path, and bundle size. It does not read payload bytes, create output files, or request custom passwords.

### Key sources and password input

The interactive prompt, `--password-stdin`, `--account-key-file`, and `--use-agent` apply to the whole run, but the three non-interactive sources each supply exactly one Account Key. `handleGetOfflineAccountKey` caches one key entry and rejects any other salt or profile, so the agent can serve only its own group. A key file carries no salt, so it is validated against each group. A group that a non-interactive source cannot unlock is skipped as `account_key_unavailable`, and re-entry applies only to interactive prompts.

With `--password-stdin`, single-bundle mode (one explicitly listed `--bundle`, with either destination flag) reads two lines exactly as today. Multi-bundle mode reads one line, the account password for the first group, and never reads custom passwords from stdin; a stdin password that fails validation marks that group `wrong_account_password`. Custom-password bundles always prompt on the controlling terminal, even when stdin supplied the account password, and are skipped as `terminal_required` when there is no terminal, after their filename, tags, and hint have been printed. Scripted custom decrypts use single-bundle mode. This mirrors the multi-download rule in `docs/wip/multi-dl.md` that batch custom passwords are interactive only, and it avoids a multi-line stdin contract whose order a script would have to predict.

### Batch flow

Put the orchestration in a new `cmd/arkfile-client/offline_decrypt_batch.go` so `offline_decrypt.go` stays focused on the single-bundle path and the parser. Single-bundle behavior routes through the same per-bundle function, so there is one code path for one file and for many.

1. Build the target list from `--bundle` values in argument order, then `--bundle-dir` discovery in sorted name order, deduplicating identical absolute paths and grouping remaining candidates by `file_id`.
2. Group targets by `(owner_username, account_kdf_salt, account_kdf_profile)` in first-appearance order. When more than one group exists, say so before prompting.
3. For each group in turn, obtain the Account Key and validate it against authenticated material from ordered candidates. If one candidate is corrupt but another validates, fail the corrupt candidate rather than rejecting the key; only treat the key as wrong or unavailable when no usable candidate validates. Decrypt the group's filenames and extend the output name reservation, which starts from the destination's existing entries and carries forward across groups.
4. In inspection mode, print the group's decrypted metadata without reading payloads or prompting for custom passwords, clear the Account Key, and continue to the next group.
5. Otherwise, decrypt the group's account-password files in order, trying duplicate copies until one verifies.
6. Decrypt the group's custom-password files. For each logical file, print filename, tags, and hint first, then prompt on the terminal with up to 3 attempts and a 2 minute wait per entry, or skip as `terminal_required` when there is no terminal. Once the FEK is available, try duplicate payload copies in order without requesting the same custom password again.
7. Clear the group's Account Key before moving to the next group.
8. Print the summary.

Per-bundle failure never stops the run. A group whose Account Key cannot be obtained or validated marks its bundles skipped with the matching reason, and the run continues with the next group. Interrupt aborts the current bundle, cleans its temporary output, and marks the rest skipped.

The salt grouping is the subtle correctness requirement here. Deriving one key from the first bundle's `account_kdf_salt` and reusing it for the rest silently fails on any set spanning two owners. Processing groups one at a time also keeps a single Account Key in memory, which reserving every output name up front across the whole run would not allow.

### Summary and failure reasons

The summary reports counts for decrypted, failed, and skipped with an account versus custom breakdown, plus the aggregate non-bundle count, then one line per non-success carrying the filename when known (through `sanitizeDisplayText`), the bundle path, and a reason from a fixed set: `not_a_bundle`, `unsafe_bundle_file`, `unsupported_version`, `unsupported_kdf_profile`, `invalid_bundle_metadata`, `bundle_length_mismatch`, `duplicate_file_id`, `owner_mismatch`, `account_key_unavailable`, `wrong_account_password`, `wrong_custom_password`, `terminal_required`, `prompt_timeout`, `prompt_cancelled`, `integrity_mismatch`, `write_failed`, `cancelled`, `skipped`. Reason strings never contain password material. The exit status follows the decrypt exit status rule: non-zero whenever any bundle failed or was skipped for a reason other than `duplicate_file_id`.

### Files touched

- `cmd/arkfile-client/offline_decrypt.go` (full reads, strict shared validator, per-bundle function)
- `cmd/arkfile-client/offline_decrypt_batch.go` (new; chained restore, duplicate fallback, and inspection)
- `cmd/arkfile-client/main.go` (usage text)

## Download Parity

### The gap

The web app can already download and decrypt a whole vault in one pass. With no tag filter active, Select all matching filter pages through every file into the selection set, and Download selected runs the multi-download batch over it: account-password files first, then a prompt showing the hint for each custom-password file. The CLI cannot do the same. `download` accepts only repeatable `--file-id` and `--tags`, so restoring a whole vault as plaintext means listing every file ID by hand, and once `export --all` lands, `download` would be the only owner batch command without a whole-vault selector.

### Command surface

```text
arkfile-client download --all --output-dir DIR [--dry-run]
```

`--all` selects every owner file from the cursor-paged scan in `fetchAllOwnerFiles`, in list order, which is the same set the web app collects with Select all matching filter and no filter. It requires `--output-dir` and cannot be combined with `--file-id` or `--tags`. Selecting targets needs no Account Key; the batch still obtains it for decryption exactly as it does today. `--dry-run` prints every target and the existing `Dry run: N file(s)` line without downloading anything. An empty vault prints a clear message and exits zero.

### Behavior

After selection, `--all` hands the targets to the existing `downloadOwnerFilesBatch`, so the batch itself does not change: account-password files first, custom-password files last with terminal prompts that now show the hint, 3 attempts per file, retry rounds as defined in `docs/wip/multi-dl.md`, basename reservation in the output directory, atomic publish per file, and the existing final summary line. `--password-stdin` is rejected for `--all` and for every scanned or plural selection, once the stdin guard fix in Related Safety Fixes lands; it stays valid for one explicitly listed `--file-id`, with `--output`, with the default output, or with the single-target `--output-dir` publish. Without a terminal, custom-password files fail as `prompt_cancelled` and the batch exits non-zero, which is today's rule.

The Output flag rules row also repairs the single-target `--output-dir` case for `download`: `download --file-id X --output-dir D` publishes under a reserved name in `D` through the single-file execution path, not the batch loop, so the single-file custom-password prompt and `--password-stdin` behavior are unchanged and the batch's retry prompt and summary are not used for one file. Today the flag is silently ignored and the default name lands in the current directory, which is the behavior the repair removes.

### Shared selection helper

Move target resolution for `--file-id`, `--tags`, and `--all` out of `handleDownloadCommand` into one helper in `cmd/arkfile-client/owner_file_list.go`, beside `fetchAllOwnerFiles`, and call it from both `download` and `export`. It owns the flag rules (the Output flag rules row: mutual exclusion of `--output` and `--output-dir`, `--output` only for one explicitly listed target, and the `--output-dir` requirement for scanned or plural selections), the client-side tag AND filter after decrypt, deduplication, and the empty-selection rules, so the two commands always select the same files the same way. Have it accept the fetched file list, or the listing function, as input so unit tests can exercise it without a server.

### Files touched

- `cmd/arkfile-client/owner_file_list.go`: shared selection helper.
- `cmd/arkfile-client/commands.go`: `--all` flag, usage text, `handleDownloadCommand` calls the helper.
- `cmd/arkfile-client/export.go`: calls the same helper.
- `cmd/arkfile-client/main.go`: usage examples.

### How the tests prove it

Go unit tests cover the helper: `--all` combined with `--file-id` or `--tags` is rejected; `--all` without `--output-dir` is rejected; `--output` together with `--output-dir` is rejected; `--output` with a plural or scanned selection is rejected; every file across several listing pages is returned once, in list order; an empty vault is reported as an empty selection rather than an error; and `download --all --password-stdin` is rejected.

In `e2e-test.sh`, steps 1 and 2 of the backup and restore sequence under Tests are the CLI proof. Step 1 shows that `--all` selects the whole vault, because the dry-run count must equal the count from `list-files --json`. Step 2 shows it works end to end: a real `download --all` must decrypt all 14 account-password files with digests matching the corpus manifest, while the 5 custom-password files fail as `prompt_cancelled` with the exact summary line and a non-zero exit, which proves the batch rules carried over unchanged.

In `e2e-playwright.ts`, the existing select-all-matching-filter test gains the no-filter case: with no filter active, the selection count must equal the total from paging `/api/files` with the logged-in context. That is the web app half of the same check, so together the two scripts show both clients select the same whole-vault set.

## Related Safety Fixes

These are small, sit in code this work touches, and close gaps found while reviewing the plan.

**Case-insensitive reservation.** Both `reserveBasenames` helpers (`cmd/arkfile-client/output_basename.go` and `client/static/js/src/files/output-basename.ts`) and `resolveDefaultDownloadPath` compare names case-insensitively while keeping each returned name's case. On a case-insensitive target, an existing `Photo.png` and a newly reserved `photo.png` are the same entry, so today a publish can replace it and the browser's failure cleanup can delete it. The change protects multi-download, export, `decrypt-blob --output-dir`, and the `share download` default name.

**Directory publish cleanup.** On failure, `downloadFileToDirectory` in `client/static/js/src/files/download.ts` removes the reserved name as well as its temporary entry. Apply the export rule there too: remove only entries the attempt created.

**Terminal-safe printing.** Route every CLI print of a decrypted filename, tag list, or hint through `sanitizeDisplayText`: the single-file download hint lines in `commands.go`, the batch download prompt, `list-files` output, the `share list` filename column, and `decrypt-blob`. `share download` already uses it.

**Owner single-file download name.** `download --file-id` without `--output` uses the decrypted filename directly as a path (the default-output block in `downloadOneOwnerFile`). Reduce it to a single path element, reject `.` and `..`, remove control and bidirectional characters, keep other leading dots because dotfile backups are legitimate for an owner, and reserve against existing entries so a default download never replaces a file. The default destination then follows the Output flag rules row: the reserved name publishes inside `--output-dir` when it is given, and in the current directory only when neither destination flag is given; today `--output-dir` is silently ignored on this path and the output lands in the current directory. Only the owner's own clients can produce that ciphertext, so this is hardening rather than an exploitable bug.

**Download stdin guard.** The multi-file `--password-stdin` guard in `handleDownloadCommand` is unreachable because the batch branch returns first, so batch downloads currently read custom passwords, and their retries, from stdin lines. Move the guard above every batch entry point and key it to the Output flag rules row: `--password-stdin` is accepted only when the selection is one explicitly listed `--file-id` (no `--tags`, no `--all`), which keeps it working with `--output`, with the default output, and with the single-target `--output-dir` publish, and rejects it for every scanned or plural selection regardless of match count. No test script passes `--password-stdin` to a multi-file download.

Files touched: `cmd/arkfile-client/output_basename.go`, `cmd/arkfile-client/commands.go`, `client/static/js/src/files/output-basename.ts`, `client/static/js/src/files/download.ts`.

## Tests

### Go unit

Bundle metadata assertions belong in `handlers/export_rotation_test.go` beside the existing `TestBuildBundleMetadataIncludesAccountKDFMetadata`, which already calls `buildBundleMetadata` directly with no database. Cover: hint fields present and byte-identical to the stored ciphertext for a custom-password file with a hint; both fields omitted when either stored field is empty; no plaintext hint anywhere in the serialized header. The existing account salt and KDF profile assertions must still pass.

`cmd/arkfile-client/offline_decrypt_test.go`: hint round trip through a bundle; absent hint prints the no-hint line; a present but undecryptable hint prints the could-not-decrypt warning and continues; hint tampering fails AEAD because `file_id` and owner are bound in AAD; the hint prints before the custom-password prompt; control characters are neutralized before display; a wrong Account Key on a custom-password bundle is caught before the custom prompt, with re-entry for interactive input and a clear failure for stdin; strict validation rejects mismatched inner and outer versions, unsupported envelope/key/KDF combinations, malformed salts and nonces, negative or inconsistent sizes and chunk counts, symlinks, truncated and padded-out bundles, and accepts an old bundle without `padded_size`; a single `--bundle` with `--output-dir` keeps the two-line stdin order and publishes under a reserved name in the directory. Factor the header parse to accept an `io.Reader` so a test can feed it short reads, and cover the blob reader the same way. Extend `FuzzParseBundle` seeds with a hint-bearing bundle and one carrying an oversized hint field.

New batch coverage: discovery accepts valid bundles and rejects a decoy file, a truncated bundle, and a wrong-magic file; a damaged first copy falls through to a valid later copy with the same `file_id`, while copies after a successful restore are skipped as `duplicate_file_id`; a damaged first validation candidate cannot make the correct Account Key fail the whole group; salt grouping derives one key per distinct salt, never reuses a key across salts, and holds one key at a time; the agent and key-file sources serve only a group they can unlock and mark others `account_key_unavailable`; multi-bundle stdin consumes exactly one line; custom bundles without a terminal are skipped as `terminal_required` after their hint prints; ordering places account bundles before custom bundles within each group; inspection prints safely sanitized owner metadata without reading payloads, creating output, or prompting for a custom password; per-bundle failure continues the run; interrupt marks the remainder skipped; output basename reservation carries across groups and temporary files are cleaned up; secret disposal runs on success, wrong password, timeout, integrity failure, and cancellation; the exit status is non-zero for any failure or non-duplicate skip, and zero when only duplicates and non-bundle files were skipped.

Export and shared helpers: CLI multi-export into a populated directory reserves `photo-1.png.arkbackup` beside an existing `photo.png.arkbackup` and leaves the old bytes unchanged; a destination created after reservation but before commit is not replaced; a failed single-file re-export to an existing exact path leaves the earlier bundle intact while a successful exact-path export replaces it atomically; `--all` rejects `--file-id` and `--tags`; `reserveBasenames` and `resolveDefaultDownloadPath` treat `Photo.png` and `photo.png` as a collision; a multi-file download rejects `--password-stdin`; the owner single-file default name stays inside the current directory, keeps a leading dot, and never replaces an existing file. Output flag rule boundaries: `--output` together with `--output-dir` is rejected in all three commands; `--output` with a plural or scanned selection is rejected; a single explicitly listed target with `--output-dir` publishes under a reserved name in that directory; a scanned selection requires `--output-dir` even when it matches exactly one file; and `download --file-id X --output-dir D` no longer writes into the current directory. The `download --all` selection tests are listed under Download Parity.

Manifest unit coverage creates a deterministic manifest from several valid bundles, includes exactly the five specified entry fields, streams whole-bundle hashes, and atomically replaces only the prior manifest after a complete successful scan. Creation leaves an earlier manifest unchanged when an ARKB candidate is malformed, a `.arkbackup` file has damaged magic, or the run is interrupted. Verification accepts an unchanged directory and reports non-zero for a missing bundle, changed bytes, changed length, malformed candidate, unlisted valid bundle, manifest entry with a path separator, duplicate bundle name, unsupported manifest version, or symlink in place of a listed file. A valid ARKB bundle without the conventional suffix is included, non-bundle regular files are ignored and counted, duplicate `file_id` values remain separate physical entries, no password is requested, and no plaintext filename, plaintext digest, tags, hint, password type, owner username, or decrypted metadata appears in the manifest.

### TypeScript unit

Export batch coverage: no export token is requested on any path; the folder-picker path fetches `/api/files/:fileId/export` with session credentials and streams into the writable without Blob buffering; explicit picker cancellation starts no fallback downloads; an unavailable picker uses fallback; a non-OK status or short body fails that file and cleans up only its own temporary entry; a late destination collision never replaces that entry; the top-level window never navigates; the fallback path triggers one hidden iframe per file with pacing and reports files as started; abort stops the run; session loss skips the remainder; a per-file failure does not stop the folder-picker run; retries reuse their reservation unless a late collision requires another; reservation produces `photo.png.arkbackup` and `photo-1.png.arkbackup`, treats an existing `photo.png.arkbackup` as taken, and is case-insensitive. Rewrite the token assertions in `client/static/js/src/__tests__/export.test.ts` for the per-row button, which now triggers the hidden iframe with no token request. Extend `output-basename.test.ts` with the case-insensitive collision case and cover the narrowed cleanup in `downloadFileToDirectory`.

### e2e-test.sh

All new backup and download coverage lives in one new function, `verify_backup_export_and_restore`, called from `run_files_custom_password()` right after `seed_and_verify_multi_dl_corpus`. At that point the vault holds exactly 19 files: the custom-password file uploaded with `--hint "$CUSTOM_HINT_SENTINEL"`, plus the 18-file corpus of 14 account-password files and 4 custom-password files without hints. The function reads `CUSTOM_FILE_ID`, `CUSTOM_FILE_SHA256`, and `CUSTOM_HINT_SENTINEL` from its caller, takes every other digest from the corpus manifest, and changes nothing on the server, so the corpus Playwright depends on is untouched. `export --all` runs exactly once, and every later step reuses that export directory.

Terminal handling matters here. `secureinput.ReadPassword` opens `/dev/tty` before anything else, and an e2e run launched from a shell has a controlling terminal, so a custom-password prompt inside a batch command would appear on the developer's terminal and wait 2 minutes per attempt. The existing corpus tests avoid this only by keeping custom files out of batch runs. Every batch command in this function that can reach a custom prompt runs as `: | setsid -w "$CLIENT" ...`, or with the account password piped in place of `:`. `setsid` drops the controlling terminal and the pipe keeps stdin from being a terminal, so the CLI takes its no-terminal path deterministically.

1. `download --all --output-dir "$all_dl_dir" --dry-run` prints `Dry run: 19 file(s)`, matching the count from `list-files --json`.
2. A real `download --all --output-dir "$all_dl_dir"` under `setsid` ends with `Batch download finished. Account succeeded: 14. Custom succeeded: 0. Unresolved failures: 5. Skipped: 0.` and a non-zero exit, because batch custom passwords are interactive only; the exact line also pins the current classification of no-terminal custom prompts as unresolved failures rather than skips, so a future reason-classification change must update this assertion deliberately. The 14 account outputs match their manifest digests. The two `photo.png` digests are compared as a set, since which copy becomes `photo-1.png` depends on processing order.
3. The single `export --all --output-dir "$export_dir"`, run under `setsid` with an empty stdin to prove export never prompts. Readable names require the Account Key from the running agent (`getOptionalAccountKey` never prompts and silently falls back to `<file_id>.arkbackup` names when no key is available), so call the existing `assert_agent_running` helper before this step; the readable-name assertions then prove the key path was taken rather than the fallback. Expect exit 0, exactly 19 `.arkbackup` files, and readable names including `custom_test_file.bin.arkbackup`, `photo.png.arkbackup`, and `photo-1.png.arkbackup`. The export privacy canary runs on these files: `custom_test_file.bin.arkbackup` contains `encrypted_password_hint` but never the plaintext sentinel, and a corpus custom-password bundle carries no hint field at all.
4. Create the default integrity manifest in the export directory and verify it. Assert exactly 19 deterministically ordered entries, each with only `bundle_name`, `file_id`, `bundle_version`, `bundle_size_bytes`, and `sha256`; recompute one bundle's digest independently; and confirm no plaintext-file digest, tag, hint, password type, owner username, or account KDF field appears. Run `decrypt-blob --bundle-dir "$export_dir" --inspect --password-stdin` with the account password under `setsid`; assert that filenames, tags, and the sentinel hint print without a custom-password prompt or output file.
5. `export --tags multi-decoy --output-dir "$export_dir" --dry-run` lists 4 files and leaves the directory at 19 bundles. This covers tag selection and the dry-run path without a second `--all` run.
6. Re-export safety: record the SHA-256 of `e2e-multi-01.bin.arkbackup`, export that file again with `--file-id` and `--output-dir "$export_dir"` (the single-target `--output-dir` publish), and assert that the new copy is `e2e-multi-01-1.bin.arkbackup` and the original's digest is unchanged. Manifest verification must now fail on the unlisted valid bundle; recreate it, verify successfully, and assert that both physical copies appear with the same `file_id`.
7. Add a decoy `notes.txt` and a truncated copy of `e2e-multi-02.bin.arkbackup`. Manifest verification must ignore `notes.txt` but fail on the malformed ARKB copy without changing the manifest. Then run the chained decrypt: `printf '%s\n' "$TEST_PASSWORD" | setsid -w "$CLIENT" decrypt-blob --bundle-dir "$export_dir" --output-dir "$restore_dir" --password-stdin`. Assert a non-zero exit under the decrypt exit status rule; 14 account-password files decrypted with matching digests, with the photo pair compared as a set; 5 custom-password bundles skipped as `terminal_required`; exactly one `duplicate_file_id` after one valid `e2e-multi-01` copy succeeds; one `bundle_length_mismatch`; a non-bundle count of 2 (`notes.txt` and the JSON manifest); the sentinel hint line printed for `custom_test_file.bin` and the no-hint line for the four corpus custom-password bundles; and no output or temporary file left for any skipped bundle.
8. Decrypt each of the 5 custom-password bundles on its own with two-line stdin (account password, then custom password) using `--bundle FILE --output-dir "$restore_dir"`, which stays single-bundle mode and publishes under reserved names, and check every digest. For `custom_test_file.bin.arkbackup`, the sentinel hint line must appear before the `Decrypted:` line. After this step every file in the vault has been restored from the one `export --all`.
9. Decrypt one custom-password bundle with a wrong account password followed by the correct custom password. It must fail with the wrong-account-password error before the custom password is used, and write no output.

Elsewhere in `e2e-test.sh`, the share privacy canary goes in `run_shares()`, next to "Visitor downloads custom-password share". Share D is created from the hinted custom-password file, so fetching its public envelope and metadata responses raw and finding no hint field and no sentinel proves hints never reach the sharing path. The existing single-file export and decrypt scenarios in `run_files_standard()` stay unchanged.

### e2e-playwright.ts

Reuse the existing multi-select corpus, and put the new tests right after "Multi-download: cancel aborts remaining files", using the existing `stubDirectoryPickerAbort` helper. First assert that the logged-in context can GET `/api/files/:fileId/export` with no token and receives the ARKB magic, which proves the protected cookie path that browser export relies on. Select two files, click Export selected, abort the directory picker, and assert that no downloads or `/export-token` requests occur. Then make the picker API unavailable, repeat the selection, wait for two fallback downloads, check the ARKB magic on each, and again assert no token request. Exercise the per-row Export button once through its iframe path. Full offline decrypt and manifest handling stay in `e2e-test.sh`.

Extend "Multi-select: select all matching filter (multi-a)" with the no-filter case for download parity: with no filter active, Select all matching filter must report a selection count equal to the total from paging `/api/files` with the logged-in context. This is the web app half of the whole-vault check; steps 1 and 2 of the `e2e-test.sh` sequence are the CLI half.

### online-integrity-test.sh

Confirm the existing export and `decrypt-blob` steps still pass unchanged.

## Minimal Integrity Manifest

The manifest is a local, derivative inventory for a directory of `.arkbackup` files. It gives an owner a quick way to detect accidental media corruption, incomplete copies, missing bundles, and directory drift without supplying any password or decrypting payloads. It does not change `.arkbackup` version 2, does not become an input required by `decrypt-blob`, and can always be deleted and regenerated from the bundles.

### Command surface

```text
arkfile-client backup-manifest create --bundle-dir DIR [--output FILE]
arkfile-client backup-manifest verify --bundle-dir DIR [--manifest FILE]
```

Create defaults to `DIR/arkbackup-manifest.json`; verify reads that path by default. Both commands are offline and non-recursive, accept only a real directory, and process only regular non-symlink files. They use the same strict bundle validator as `decrypt-blob`. A regular file is a manifest candidate when it has ARKB magic or its name ends in `.arkbackup`, case-insensitively: this still discovers valid renamed bundles by content, while ensuring that a bundle whose magic was corrupted is not silently reclassified as an ordinary file during manifest regeneration. Ordinary files matching neither condition are ignored and aggregated; every candidate must validate or creation fails. An explicit output path inside the bundle directory must not end in `.arkbackup` or alias a bundle candidate. Neither command obtains an Account Key or prompts for any password.

Creation scans the complete directory before publishing anything. It computes each whole-bundle SHA-256 incrementally with bounded memory, sorts entries deterministically by the stored bundle name, serializes one versioned JSON document, writes it to a protected temporary file in the destination directory, syncs it, and atomically replaces only the prior manifest path after every candidate has validated and hashed successfully. Failure or interruption leaves an earlier manifest unchanged. Duplicate `file_id` values remain separate entries because the manifest describes physical files, not logical restore targets.

The version 1 document has top-level fields `format`, `version`, and `entries`. `format` is exactly `arkbackup-integrity-manifest`, `version` is `1`, and each entry has exactly `bundle_name`, `file_id`, `bundle_version`, `bundle_size_bytes`, and `sha256`. `bundle_name` is one basename with no path separators, `bundle_version` is the outer ARKB version, `bundle_size_bytes` is the complete file length, and `sha256` is lowercase hexadecimal over every byte of the complete `.arkbackup` file. The manifest does not repeat the original filename separately and never includes the original plaintext SHA-256, tags, hint, password type, owner username, Account Key metadata, or any decrypted metadata. A readable export name is already visible as `bundle_name`; an opaque browser-fallback name remains opaque.

Verification treats the manifest as an untrusted claim, validates its format and bounded structure, rejects duplicate bundle names and unsafe paths, and opens listed files without following symlinks. It checks the current file length and streams its complete SHA-256, confirms its strict bundle parse still yields the recorded `file_id` and bundle version, and scans the directory for additional valid bundles not listed in the manifest. Missing, changed, malformed, or unlisted bundles produce a non-zero exit and per-file reasons; an unchanged collection exits zero. Ordinary non-bundle files such as a recovery note do not fail verification.

The manifest is deliberately not signed, encrypted, or keyed. It detects accidental corruption and copy mistakes while an unchanged manifest is available, but an attacker who can replace both bundles and manifest can rewrite it. The whole-bundle digest fingerprints an exact encrypted bundle copy and may correlate copies of that same bundle, but it is not the plaintext-file digest and does not provide known-plaintext content matching. Authenticated collection manifests, encrypted metadata catalogs, recursive inventories, and HTML rendering of this JSON manifest are possible later extensions, not part of this minimum.

### Files touched

- `cmd/arkfile-client/backup_manifest.go` (new): manifest schema, create, verify, streaming hash, and atomic publication.
- `cmd/arkfile-client/offline_decrypt.go`: exposes the strict shared bundle validator used by decrypt and manifest operations.
- `cmd/arkfile-client/main.go`: command dispatch and usage text.
- `cmd/arkfile-client/backup_manifest_test.go` (new): deterministic schema, privacy, validation, integrity, and failure-safety coverage.

## Documentation

`docs/api.md` Backup Export section: note the two optional hint fields in bundle metadata, that they are opaque Account Key ciphertext, and that they are omitted when no hint was saved. Replace the browser export flow paragraph: the protected GET accepts the normal browser session cookie or CLI Bearer session, and the export-token endpoint and public-route authentication path have been removed. State that the browser and CLI batch export paths use the same per-file GET with no new endpoint.

`docs/security.md`: extend the `.arkbackup` version 2 paragraph to list the encrypted hint alongside the other encrypted owner metadata fields, restate that share envelopes never carry hints, and say plainly that exported bundle filenames show the original names to anyone who can see the backup folder. Distinguish the encrypted payload and owner metadata ciphertext from the operational header fields that bundle version 2 already stores in plaintext. Also state the hint's guessing exposure in the same honest terms the existing offline-guessing note for captured FEK envelopes uses: capturing a bundle allows offline guessing of the account password against the wrapped owner metadata, exactly as a server-side database capture does, and a successful guess reveals the owner metadata including the custom-password hint; hints are often correlated with the custom password itself, so the hint is a memory aid for the owner, not added protection against an attacker who has already recovered the account password. Document the integrity manifest's exact plaintext fields, whole-bundle fingerprinting exposure, and accidental-corruption rather than adversarial-authentication guarantee.

`docs/user-faq.md`: prose-only entries covering exporting selected, tagged, or all files as individual encrypted backup bundles; downloading and decrypting every file in one run from either the web app or the CLI; inspecting or restoring a whole backup folder later with one command; creating and checking the optional integrity manifest; that bundle filenames are readable on disk, so an owner who needs names hidden should keep the folder somewhere private or rename the files, since decryption restores the true names; and that a custom-password bundle shows its hint after the account password is entered but still needs the file's own password to decrypt. Paragraphs only, no lists and no code spans, per that file's rules.

`docs/wip/multi-dl.md`: note that bulk export, previously listed as out of scope, is now covered here and reuses the selection model, that `download --all` was added here for parity with the web app, and that the multi-file `--password-stdin` guard was fixed here.

## Out of Scope

- Server-side zip, tar, or any bulk archive job
- Parallel export or parallel offline decrypt
- A TypeScript `.arkbackup` parser
- Any change to bundle version, chunk layout, AAD composition, or padding
- Hints in share envelopes or any public share response
- Recursive `--bundle-dir` discovery
- Bulk delete, bulk share, or bulk retag
- Bulk admin export
- Incremental re-export that skips files already present in the destination; the CLI could add it later by reading `file_id` from existing bundle headers
- An opaque-name export mode for owners who want filenames hidden on the backup medium
- Unattended custom-password input for batch decrypt; custom passwords stay interactive, as in multi-download
- A `--skip-custom` option for batch download, which `docs/wip/multi-dl.md` lists as optional later
- A signed, keyed, or encrypted collection manifest
- A persisted decrypted-metadata catalog, JSON inspection output, or HTML rendering of the minimal JSON integrity manifest

## Implementation Checklist

- [ ] Hint fields in `handlers/export.go` bundle metadata, populated when both stored fields are present
- [ ] Matching fields in CLI `bundleMeta`, with the schema alignment comment updated
- [ ] `decrypt-blob` validates the Account Key, then decrypts and displays filename, tags, and hint before the custom-password prompt, with the absent and undecryptable hint wording
- [ ] Hint shown in the CLI batch download custom-password prompt (parity with the browser)
- [ ] `sanitizeDisplayText` applied at every CLI print site for decrypted filenames, tags, and hints
- [ ] Browser export authenticates with the session cookie on the per-row button and the batch, with a Playwright proof of the protected cookie path
- [ ] Export GET moved under `mfaProtectedGroup`; export-token endpoint, claims, query branch, manual JWT parser, and tests removed
- [ ] Frontend Export selected button reusing the existing selection set
- [ ] `export-batch.ts` with folder-picker and hidden-iframe fallback paths, streaming only, explicit picker cancellation stopping the run, and cleanup limited to entries the attempt created
- [ ] Re-export safety in both clients: existing `.arkbackup` entries count as taken minus the suffix, retries reuse reservations, and late collisions cannot replace entries
- [ ] CLI `export` accepts repeatable `--file-id`, `--tags`, `--all`, `--output-dir`, and `--dry-run`; single-file export publishes atomically
- [ ] One strict shared bundle validator covers explicit decrypt, discovery, inspection, and manifest operations, including file type, format, crypto-field, size, chunk, padding, and length invariants
- [ ] `decrypt-blob` accepts repeatable `--bundle` and `--bundle-dir` with full reads and ordered fallback copies grouped by `file_id`
- [ ] Per-group processing with one Account Key at a time, validation across usable candidates so a corrupt first copy cannot poison the group, interactive re-entry, and `account_key_unavailable` for sources that cannot serve a group
- [ ] `decrypt-blob --bundle-dir --inspect` displays sanitized decrypted owner metadata without reading payloads, creating outputs, or prompting for custom passwords
- [ ] Multi-bundle stdin carries only the account password; custom prompts are terminal-only with `terminal_required`
- [ ] Account-first then custom ordering within each group, single pass, 3 attempts per bundle
- [ ] Summary with the fixed failure reason set, including the aggregate non-bundle count, and the decrypt exit status rule
- [ ] `backup-manifest create` writes the deterministic five-field-entry version 1 JSON manifest atomically after a complete passwordless scan
- [ ] `backup-manifest verify` detects missing, changed, malformed, unsafe, and unlisted bundles with streaming whole-bundle SHA-256
- [ ] `download --all` with `--dry-run` and the empty-vault rule, resolving targets through the shared selection helper that `export` also uses
- [ ] Output flag rules in `download`, `export`, and `decrypt-blob`: mutual exclusion of `--output` and `--output-dir`, `--output` only for one explicitly listed target, reserved-name publish for a single target with `--output-dir`, and `--output-dir` required for scanned selections even when they match one file
- [ ] Case-insensitive reservation in both `reserveBasenames` helpers and `resolveDefaultDownloadPath`
- [ ] `downloadFileToDirectory` cleanup limited to entries the attempt created
- [ ] Owner single-file download default name reduced to a safe single path element, reserved, and published inside `--output-dir` when given
- [ ] Download `--password-stdin` guard moved above every batch entry point and keyed to the Output flag rules row
- [ ] `verify_backup_export_and_restore` in `e2e-test.sh`: the nine-step sequence with exactly one `export --all`, inspect and manifest coverage, batch commands under `setsid`, plus the Share D hint canary in `run_shares()`
- [ ] Playwright: protected cookie-path export check, chooser-cancel and unavailable-picker behavior, Export selected and per-row Export downloads, and the no-filter whole-vault selection count
- [ ] Go and TypeScript unit tests green
- [ ] `docs/api.md`, `docs/security.md`, `docs/user-faq.md`, and `docs/wip/multi-dl.md` updated
- [ ] Developer runs `dev-reset.sh`, then `e2e-test.sh` and `e2e-playwright.sh`
