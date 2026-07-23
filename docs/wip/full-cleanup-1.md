# Full Cleanup Pass

Status: draft (revised after cross-check against the tree)
Created: 2026-07-21
Revised: 2026-07-23 (deploy/update shared library expansion complete; syntax/help verified)
Scope: Cross-stack hygiene after the archived server, CLI, and frontend cleanup audits. Greenfield: delete unused paths; no compatibility shims. Prefer honest naming and one canonical path per operation. This document uses descriptive headings only — do not introduce numbered, lettered, phase, tranche, or tier labels from this plan into source, tests, scripts, or comments.

Prior audits (reference only; do not edit): `docs/wip/archive/server-cleanup.md`, `docs/wip/archive/cli-cleanup.md`, `docs/wip/archive/frontend-cleanup.md`.

## Principles

One canonical way per client operation. Fail closed. Delete dead code rather than deprecate. Comments describe behavior in situ — no references to WIP planning paths, item indexes, or ephemeral planning labels in production source or e2e names. After each workstream: `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh`, optionally `sudo bash scripts/testing/e2e-playwright.sh`, plus `go test ./...` (AGENTS.md CGO flags) and `cd client/static/js && bun test` when frontend changes.

## Recommended focus order

1. Digest and size semantics clarity (correctness and threat-model honesty) — done; e2e green
2. Dead code, WIP certificate scripts, and other misleading operator/code surfaces — done; e2e green
3. Deploy/update shared library expansion (ops safety; behavior-preserving extract) — done; bash -n + help smoke verified

Defer frontend `app.ts` decomposition and broad planning-label renames; next recommended focus is planning-label hygiene or `app.ts` decomposition.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Digest and size semantics clarity | [x] | Renamed stream digest column/API; omitted from metadata; security.md updated; dead `upload_sessions.encrypted_hash` removed; e2e green |
| Dead code and legacy wrappers | [x] | Removed GetEntityID; e2e aliases; TS formatFileSize alias; share-access duplicate formatBytes; credits adjustment; billing overdrawn canonical name; billing_projection silence import; compat comments reworded; e2e output redaction removed earlier; e2e green |
| WIP certificate scripts removal | [x] | Deleted renew/validate scripts; updated setup.md, scripts-guide.md, 04-setup-tls-certs.sh; e2e green |
| Dual surfaces review | [x] | Dropped duplicate `GET /api/public/shares/:id` HTML page; keep `/shared/:id` + API subpaths; billing JSON uses `users_currently_overdrawn` only; e2e green |
| Deploy/update shared library expansion | [x] | Thin prod/test wrappers; shared `vps-first-deploy.sh` / `vps-update.sh`; deploy-common build/backup/static helpers; local wired onto same helpers; invocation paths unchanged |
| Frontend helper consolidation leftovers | [x] | Folded into dead-code pass (formatBytes) |
| Frontend app.ts decomposition | [ ] | Logical modules; thin entrypoint; after contracts stabilize |
| Planning-label comment hygiene | [ ] | Production source + e2e + Playwright |
| End-to-end verification (through completed workstreams) | [x] | Developer confirmed full e2e suite green after digest + dead-surfaces (including share page / billing / cert doc changes). Re-run after each remaining workstream. |

---

## Review corrections (2026-07-23)

Findings from re-checking this draft against the codebase. Treat these as part of the plan, not footnotes.

### Digests and sizes

- `models/file.go` already documents the three digests reasonably well. The real leftovers there are: the anti-equivocation claim, the “see the plan doc” reference, and the wrong `SizeBytes` comment (`// Original file size`). Do not rewrite the whole comment block for its own sake.
- Anti-equivocation is weaker than “clients do not implement it.” Upload-complete returns the hex; file metadata returns only a boolean presence flag under the same JSON name `encrypted_file_sha256`. Clients cannot later re-download and compare against a server-held hex via the metadata API even if they wanted to. TS upload returns the hex on `UploadResult` but nothing verifies it; CLI parses it into a struct field and does not use it afterward. Prefer deleting the claim unless deliberately designing a verify path with an honestly named hex field.
- `docs/security.md` classifies opaque owner metadata and size fields, but does **not** yet classify the plaintext encrypted-stream digest or the padded blob digest. “Match security.md” means update security.md as part of this workstream, not only code comments.
- Schema comment on `file_metadata.encrypted_file_sha256sum` (“final encrypted file in storage (pre-padding)”) is itself misleading; fix in the same pass as any rename.
- Do **not** rename the AAD label string `"encrypted_sha256sum"` — that binds the plaintext content digest metadata field.

### Dead code and dual surfaces

- Billing duplicate is not only “alias for CLI”: sweep summary emits both `users_currently_negative` and `users_currently_overdrawn`; overdrawn list emits only the latter; CLI reads the latter. Collapse to one canonical name across all admin billing payloads and update the CLI together.
- Share dual entry is real: both `/shared/:id` and `/api/public/shares/:id` call `GetSharedFile` (HTML page). Route comments already call `/shared/:id` a “legacy path”; reword to intentional pretty-URL dual entry, consistent with keeping both.
- `TransactionTypeAdjustment` / `"adjustment"` is constant-plus-constant-test only; safe to remove if unused in schema constraints.
- `GetEntityID` is production-API surface used only from tests; production request path uses `GetCompositeEntityIDForRequest`.

### WIP certificate scripts

- Deletion must update live operator docs, not only incidental greps: `docs/setup.md`, `docs/scripts-guide.md`, and the echo text in `scripts/setup/04-setup-tls-certs.sh` still advertise renew/validate. Do not leave broken operator instructions.

### Deploy common

- Deploy/update shared library expansion is done: thin prod/test wrappers, shared `vps-first-deploy.sh` / `vps-update.sh`, and expanded `deploy-common.sh` (build wipe/run/verify, backup/rollback, static/schema sync) with local wired onto the same helpers.

### Test impact gap (important)

The original draft said “coordinate … tests and e2e” for the column/API rename but did **not** inventory concrete unit, bun, or e2e touch points. That inventory is now under Digests (test and client impact). Most stream-hash JSON assertions are absent from e2e today; Go sqlmock strings and TS fixture types are the primary break points for a rename/API split.

---

## File digests and size semantics

There are three distinct file digests. Do not conflate them in names, comments, or APIs.

### Plaintext content digest (owner metadata)

- Columns: `encrypted_sha256sum` + `sha256sum_nonce`
- Meaning: SHA-256 of the original plaintext file
- Client computes and encrypts under the Account Key; AAD binds `(file_id, "encrypted_sha256sum", owner_username)`
- Server stores opaque ciphertext only
- Used for owner list/download verification, share envelope `sha256`, and client-side digest-cache dedup
- AAD label `"encrypted_sha256sum"` is a wire-format constant — do not rename it when renaming DB/API fields for the stream digest

### Encrypted-stream digest

- Column: `encrypted_stream_sha256sum` / Go `EncryptedStreamSha256sum` (renamed from `encrypted_file_sha256sum`)
- Meaning: plaintext hex SHA-256 of the concatenated client-encrypted chunk bytes **before** server padding
- Server computes during upload; this is **not** Account-Key ciphertext of a digest
- Upload-complete API returns hex as `encrypted_stream_sha256`
- Owner file-metadata JSON **omits** the stream digest (no boolean overload)
- Anti-equivocation verify is not implemented; do not claim it in comments until a real path exists

### Padded blob digest

- Column: `stored_blob_sha256sum`
- Meaning: SHA-256 of all bytes written to S3 (encrypted stream plus padding)
- Server-only; used for replication and at-rest integrity checks
- Not currently surfaced on the `File` JSON struct; keep server-only unless a deliberate admin/ops API is added

### Related digests and dead schema

- Per-chunk transport: `X-Chunk-Hash` / `upload_chunks.chunk_hash` (hash of one encrypted chunk body)
- Share envelope `sha256`: copy of the plaintext content digest after the owner decrypts owner metadata
- `download_token_hash`: hash of the share download token, not file content
- Dead column removed: `upload_sessions.encrypted_hash`

### Size fields

- `size_bytes` / upload `total_size`: pre-padding encrypted stream length (billing and chunk math)
- `padded_size`: full S3 object length
- Inferable plaintext length for non-empty files: `size_bytes - (28 × chunk_count)` where 28 is per-chunk AES-GCM overhead; empty files use one chunk by convention (see `docs/security.md`)

### Decisions locked (implemented)

- DB/Go: `encrypted_file_sha256sum` → `encrypted_stream_sha256sum` (`EncryptedStreamSha256sum`); startup RENAME COLUMN migration added
- Complete JSON: `encrypted_file_sha256` → `encrypted_stream_sha256` (hex)
- Metadata JSON: omit stream digest entirely
- AAD label `"encrypted_sha256sum"` unchanged
- `upload_sessions.encrypted_hash` removed from schema and payment test helpers
- `docs/security.md` classifies the three digests; anti-equivocation claims removed from live comments

### Digests: what breaks where (blast radius)

Runtime crypto and download/decrypt of file bytes do **not** depend on the stream-hash JSON name. Owner verify and share envelope integrity use the **plaintext content digest** (`encrypted_sha256sum` ciphertext), not the stream hash.

| Layer | Touch points (done) |
|-------|---------------------|
| Schema / DB | `unified_schema.sql` column + comment; `main.go` RENAME migration; INSERT/SELECT in uploads and models |
| Server JSON | Complete-upload `encrypted_stream_sha256`; metadata omits stream hash |
| Go models | `EncryptedStreamSha256sum` |
| CLI | `cmd/arkfile-client` complete-response parse |
| Browser | `upload.ts` complete field; metadata type no longer includes stream hash |
| Docs | `docs/security.md` |
| Dead schema | `upload_sessions.encrypted_hash` removed |

### Digests: test and client impact

| Suite | Required update |
|-------|-----------------|
| Go unit (`handlers/files_test.go`) | sqlmock column names → `encrypted_stream_sha256sum` |
| Go unit (`handlers/payments_test_helpers.go`) | Dropped `encrypted_hash` |
| bun (`upload-batch.test.ts`) | Complete fixture → `encrypted_stream_sha256` |
| bun (`streaming-download.test.ts`) | Removed metadata stream-hash field |
| e2e / Playwright | No prior stream-hash assertions; run full suite after `dev-reset.sh` |

---

## Dead code and small leftovers

| Item | Location | Action |
|------|----------|--------|
| `GetEntityID` IP-only wrapper | `logging/entity_id.go` | Delete from production API, or keep a test-only helper with no “legacy” production surface; update `logging/entity_id_test.go` |
| Unused e2e aliases | `scripts/testing/e2e-test.sh` (`TOTP_SECRET_FILE`, `BACKUP_CODE_FILE`) | Delete |
| `formatFileSize` alias | `client/static/js/src/utils/format.ts` | Use `formatBytes` at the call site; delete the alias |
| Private duplicate `formatBytes` | `client/static/js/src/shares/share-access.ts` | Import shared `formatBytes` |
| "for compatibility" export comments | `auth/login.ts`, `auth/register.ts` | Keep wrappers if used; reword comments to describe actual role |
| Credits `adjustment` type | `models/credits.go` | Remove constant + credits_test assertion if still unused in schema/API |
| Billing JSON duplicate keys | `users_currently_negative` vs `users_currently_overdrawn` | Pick one canonical name across sweep summary, overdrawn list, credits payloads; update `arkfile-admin` |
| Unused-import silence | `handlers/billing_projection.go` (`var _ = database.DB`) | Remove if the import is truly unused |

---

## Frontend: decompose app.ts

Goal: thin entrypoint; one concern per module. Behavior unchanged; Playwright and bun tests must stay green. Prefer after digest/size and dead-surface work so contracts are stable.

### Suggested layout

| Module | Responsibility |
|--------|----------------|
| `app.ts` | Trusted Types policy, construct app, DOMContentLoaded, shared.html ShareAccessUI bridge |
| Bootstrap module | `initialize`, `/readyz`, Service Worker register, billing checkout param capture, home versus app routing |
| Home listeners | Home CTA wiring into auth forms |
| Auth listeners | Login, register, logout, pending-approval wiring; password toggles |
| Shell listeners | Billing, security, contact, verify-file, lock key, revoke-all toggles |
| Upload listeners | Upload button and file input label |
| TOTP listeners | TOTP setup UI listeners and verify handler |
| Navigation helpers | Show home/app, navigate helpers, initial auth, load files/shares |

Keep the single `appListenersAttached` guard semantics when splitting listener setup. Prefer moving listeners next to existing domain modules (`auth/`, `ui/`, `files/`) when a group already has a home; use an `app/` (or equivalent) package only for orchestration that does not belong elsewhere.

Do not name new files or symbols after planning labels from this or any other WIP document.

---

## Delete WIP certificate scripts

Delete:

- `scripts/maintenance/renew-certificates.sh`
- `scripts/maintenance/validate-certificates.sh`

Both are marked WIP and are not part of the supported deploy/update path (Caddy and Let's Encrypt via deploy scripts; local TLS via `scripts/setup/04-setup-tls-certs.sh`).

Actions:

- Remove live operator references (not optional): `docs/setup.md`, `docs/scripts-guide.md`, and echo/help text in `scripts/setup/04-setup-tls-certs.sh`.
- Grep for any remaining references; remove from docs or help text.
- Do not replace with stubs. If operator TLS renewal documentation is needed later, write a finished doc against the real Caddy/deSEC flow — out of scope unless required for production preparation.

---

## Expand shared deploy and update library

Completed 2026-07-23.

### Layout

- `scripts/setup/deploy-common.sh` — shared print/run/stop/ownership/validation helpers, plus build wipe/run/verify, backup-before-overwrite with rollback trap, binary/static/schema sync.
- `scripts/setup/vps-first-deploy.sh` — parameterized VPS first-time deploy body (sourced by prod/test wrappers).
- `scripts/setup/vps-update.sh` — parameterized VPS update body (sourced by prod/test wrappers).
- Thin wrappers keep only profile differences: `prod-deploy.sh` / `test-deploy.sh` (~48 lines), `prod-update.sh` / `test-update.sh` (~39 lines).
- `local-deploy.sh` / `local-update.sh` reuse the common build and update helpers; local retains LAN IP, self-signed TLS, and no-Caddy paths. Fixed `validate_username` being called before `deploy-common.sh` was sourced.

### Profile differences preserved

- VERSION prefix (`prod` / `test`), rqlite username, Seaweed access key / bucket / provider ID, Caddyfile template, banners and help text.
- `ARKFILE_ENV=production` for both VPS profiles (unchanged from prior scripts).
- Seaweed identity `name` remains `arkfile` for both profiles.
- Test existing-deployment hint now points at `scripts/test-update.sh` (was a stale “future test-update.sh” string).
- Local builds still omit `--production`; VPS builds still pass it.

### Rules (still apply)

- Callers still set `ARKFILE_DIR`, user, and group before sourcing (existing contract).
- No silent behavior change between prod and test beyond today's intentional differences.
- Diff between prod and test wrappers is small and reviewable.
- AGENTS.md invocation paths unchanged (`scripts/prod-deploy.sh`, etc.).

---

## Planning-label comment hygiene

Strip or rewrite references in live code and tests that point at ephemeral planning documents or use planning-era scenario names:

- Path references such as `docs/wip/general-enhancements.md` (and similar) in uploads, upload client, and CLI — replace with in-situ behavior descriptions
- `docs/wip/storage-credits-v2.md` in `billing/types.go` — describe the billing package role or point at `docs/security.md`
- Comments citing archived export or unit-test WIP paths
- e2e scenario names that still say "Phase …" — rename to descriptive scenario titles
- Playwright comments that say "tranche …" or frame checks as "Legacy localStorage" migration story — keep useful regression guards; reword without planning or migration labels

Archived WIP documents under `docs/wip/archive/` remain untouched.

---

## Dual surfaces review

| Surface | Decision |
|---------|----------|
| Share HTML page | Single path: `GET /shared/:id` via `GetSharedFile`. Removed duplicate `GET /api/public/shares/:id` page registration. |
| Share API | Keep `/api/public/shares/:id/{envelope,ticket,metadata,chunks}` only |
| Admin billing overdrawn count | Canonical JSON key `users_currently_overdrawn` (sweep summary, overdrawn list, credits summary, CLI) |
---

## Verification

- `source scripts/setup/build-config.sh && export CGO_ENABLED=1 CGO_CFLAGS="$(cli_fido_cgo_cflags)" CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$PWD")" && go test ./...`
- `cd client/static/js && bun test`
- Developer: `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh`, then `sudo bash scripts/testing/e2e-playwright.sh`
- Spot-check: upload → list → download verify uses the plaintext content digest; complete-response and metadata stream-hash field names are consistent and honestly typed; `docs/security.md` lists all three digests; deploy wrappers still call through common helpers; WIP cert scripts and doc refs are gone

### Verification log

- 2026-07-23: After digest/size rename and dead-surfaces (share page singleton, WIP cert deletion, billing key collapse, related dead code), developer confirmed e2e suite green. Re-run the full verification block after deploy-common expansion and again after any `app.ts` / planning-label work.
- 2026-07-23: Deploy/update shared library expansion complete (`bash -n` on all wrappers and shared bodies; `--help` smoke for prod/test deploy and update). Operator deploy/update on a real host not exercised in this pass; re-run e2e after any follow-on code changes as usual.

## Out of scope

- New product features (subscriptions UI, post-quantum crypto, and similar)
- Editing archived cleanup docs
- Rewriting Caddy/deSEC certificate automation beyond deleting the WIP maintenance scripts and fixing docs that pointed at them
- Full e2e coverage of every admin command (track separately if needed)
- Implementing encrypted-stream anti-equivocation verify unless product explicitly chooses it in this pass
