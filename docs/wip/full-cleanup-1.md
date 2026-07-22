# Full Cleanup Pass

Status: draft
Created: 2026-07-21
Scope: Cross-stack hygiene after the archived server, CLI, and frontend cleanup audits. Greenfield: delete unused paths; no compatibility shims. Prefer honest naming and one canonical path per operation. This document uses descriptive headings only — do not introduce numbered, lettered, phase, tranche, or tier labels from this plan into source, tests, scripts, or comments.

Prior audits (reference only; do not edit): `docs/wip/archive/server-cleanup.md`, `docs/wip/archive/cli-cleanup.md`, `docs/wip/archive/frontend-cleanup.md`.

## Principles

One canonical way per client operation. Fail closed. Delete dead code rather than deprecate. Comments describe behavior in situ — no references to WIP planning paths, item indexes, or ephemeral planning labels in production source or e2e names. After each workstream: `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh`, optionally `sudo bash scripts/testing/e2e-playwright.sh`, plus `go test ./...` (AGENTS.md CGO flags) and `cd client/static/js && bun test` when frontend changes.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Digest and size semantics clarity | [ ] | Docs/comments/API naming; optional greenfield column rename |
| Dead code and legacy wrappers | [ ] | GetEntityID, e2e aliases, unused schema, format aliases |
| Frontend app.ts decomposition | [ ] | Logical modules; thin entrypoint |
| Frontend helper consolidation leftovers | [ ] | share-access formatBytes; formatFileSize alias; compat comments |
| WIP certificate scripts removal | [ ] | Delete renew/validate WIP scripts; update any refs |
| Deploy/update shared library expansion | [ ] | Grow deploy-common; thin prod/test/local wrappers |
| Planning-label comment hygiene | [ ] | Production source + e2e + Playwright |
| Dual surfaces review | [ ] | Pretty share URL vs public API; credits adjustment type; billing aliases |
| End-to-end verification | [ ] | Full suite after changes |

---

## File digests and size semantics

There are three distinct file digests. Do not conflate them in names, comments, or APIs.

### Plaintext content digest (owner metadata)

- Columns: `encrypted_sha256sum` + `sha256sum_nonce`
- Meaning: SHA-256 of the original plaintext file
- Client computes and encrypts under the Account Key; AAD binds `(file_id, "encrypted_sha256sum", owner_username)`
- Server stores opaque ciphertext only
- Used for owner list/download verification, share envelope `sha256`, and client-side digest-cache dedup

### Encrypted-stream digest (misnamed today)

- Column: `encrypted_file_sha256sum` / Go `EncryptedFileSha256sum`
- Meaning: plaintext hex SHA-256 of the concatenated client-encrypted chunk bytes **before** server padding
- Server computes during upload; this is **not** Account-Key ciphertext of a digest
- Upload-complete API returns hex as `encrypted_file_sha256`; file-metadata API currently returns a boolean under the same JSON name (overload to fix)
- Comments describe an anti-equivocation use that clients do not implement today — either wire a clear verify path or stop claiming it in comments

### Padded blob digest

- Column: `stored_blob_sha256sum`
- Meaning: SHA-256 of all bytes written to S3 (encrypted stream plus padding)
- Server-only; used for replication and at-rest integrity checks

### Related digests and dead schema

- Per-chunk transport: `X-Chunk-Hash` / `upload_chunks.chunk_hash` (hash of one encrypted chunk body)
- Share envelope `sha256`: copy of the plaintext content digest after the owner decrypts owner metadata
- `download_token_hash`: hash of the share download token, not file content
- Dead column: `upload_sessions.encrypted_hash` — present in schema, never written or read by application code; remove

### Size fields

- `size_bytes` / upload `total_size`: pre-padding encrypted stream length (billing and chunk math)
- `padded_size`: full S3 object length
- Inferable plaintext length for non-empty files: `size_bytes - (28 × chunk_count)` where 28 is per-chunk AES-GCM overhead
- Fix the stale comment on `File.SizeBytes` that says original file size — that is wrong

### Actions for digests and sizes

- Rewrite in-situ comments in `models/file.go`, `handlers/uploads.go`, and client types so the three digests and size semantics match `docs/security.md` and AGENTS.md. Remove "see the plan doc" and historical hand-waving.
- Resolve the API overload for `encrypted_file_sha256` (hex versus boolean) with distinct, honest field names.
- Decide a greenfield rename for `encrypted_file_sha256sum` to a name that cannot be read as "ciphertext of a digest" (for example `ciphertext_stream_sha256` or `encrypted_stream_sha256sum`). Coordinate schema, Go, complete response, tests, and e2e. Do **not** rename the AAD label `"encrypted_sha256sum"` — that binds the plaintext content digest metadata field.
- Drop dead `upload_sessions.encrypted_hash` from `unified_schema.sql` and test helpers.
- Either wire client anti-equivocation against the encrypted-stream digest or delete the unused claim from comments.

---

## Dead code and small leftovers

| Item | Location | Action |
|------|----------|--------|
| `GetEntityID` IP-only wrapper | `logging/entity_id.go` | Delete from production API, or keep a test-only helper with no "legacy" production surface |
| Unused e2e aliases | `scripts/testing/e2e-test.sh` (`TOTP_SECRET_FILE`, `BACKUP_CODE_FILE`) | Delete |
| `formatFileSize` alias | `client/static/js/src/utils/format.ts` | Use `formatBytes` at the call site; delete the alias |
| Private duplicate `formatBytes` | `client/static/js/src/shares/share-access.ts` | Import shared `formatBytes` |
| "for compatibility" export comments | `auth/login.ts`, `auth/register.ts` | Keep wrappers if used; reword comments to describe actual role |
| Credits `adjustment` type | `models/credits.go` | Remove if unused in schema/API; otherwise document as live |
| Billing JSON duplicate alias | `users_currently_overdrawn` | Keep one name; update CLI |
| Unused-import silence | `handlers/billing_projection.go` (`var _ = database.DB`) | Remove if the import is truly unused |

---

## Frontend: decompose app.ts

Goal: thin entrypoint; one concern per module. Behavior unchanged; Playwright and bun tests must stay green.

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

- Grep for references; remove from docs or help text if any.
- Do not replace with stubs. If operator TLS renewal documentation is needed later, write a finished doc against the real Caddy/deSEC flow — out of scope unless required for production preparation.

---

## Expand shared deploy and update library

`scripts/setup/deploy-common.sh` already holds `print_status`, `run_as_user`, stop helpers, ownership checks, and username/storage validation. Prod and test deploy scripts (near-duplicates) and update scripts still duplicate large bodies of logic.

### Target

Grow `deploy-common.sh` (or split into `deploy-common.sh` plus a VPS-specific common file if size warrants) so that:

- Shared: firewall, Caddy user and directories, application build, artifact deploy and verify, backup-before-overwrite, static sync, version stamp, and secrets.env domain/storage detection used by updates.
- Thin wrappers keep only profile differences:
  - **prod-deploy / test-deploy**: domain defaults, VERSION prefix, DB username, storage ID suffix, secrets.env labels, help text.
  - **local-deploy**: LAN IP, self-signed TLS, interactive storage prompts, no Caddy.
  - **update scripts**: same profile reads from existing `secrets.env` / caddy-env; no data wipe.

### Rules

- Callers still set `ARKFILE_DIR`, user, and group before sourcing (existing contract).
- No silent behavior change between prod and test beyond today's intentional differences.
- After refactor, the diff between prod and test wrappers should be small and reviewable.
- Update AGENTS.md only if script invocation paths change (prefer they do not).

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

| Surface | Options |
|---------|---------|
| `/shared/:id` versus `/api/public/shares/:id` both serving share page access | Keep both if HTML UX needs pretty URLs; document as intentional dual entry, not "legacy" |
| Share chunk credentials | Already ticket-only; confirm no leftover comments claiming static `X-Download-Token` chunk auth |
| Admin billing duplicate JSON keys | Collapse to one canonical name |

---

## Verification

- `source scripts/setup/build-config.sh && export CGO_ENABLED=1 CGO_CFLAGS="$(cli_fido_cgo_cflags)" CGO_LDFLAGS="$(cli_fido_cgo_ldflags "$PWD")" && go test ./...`
- `cd client/static/js && bun test`
- Developer: `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh`, then `sudo bash scripts/testing/e2e-playwright.sh`
- Spot-check: upload → list → download verify uses the plaintext content digest; complete-response stream-hash field names are consistent; deploy wrappers still call through common helpers

## Out of scope

- New product features (subscriptions UI, post-quantum crypto, and similar)
- Editing archived cleanup docs
- Rewriting Caddy/deSEC certificate automation beyond deleting the WIP maintenance scripts
- Full e2e coverage of every admin command (track separately if needed)
