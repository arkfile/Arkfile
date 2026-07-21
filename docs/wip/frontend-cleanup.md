# Frontend Cleanup & Cohesion Plan

This plan applies the same audit methodology as `docs/wip/archive/server-cleanup.md` and `docs/wip/archive/cli-cleanup.md` to the TypeScript browser client under `client/static/js/src/`. Every exported function, class method, and UI flow handler is reviewed against the Function Review Sanity Checks in `AGENTS.md`: required, correctly implemented, well placed, reachable, privacy-preserving, and free of stubs, deprecated paths, duplicated logic, and leftover placeholder code. Arkfile is greenfield; delete unused or misleading frontend paths rather than maintain compatibility shims. The audit is cross-checked against `scripts/testing/e2e-playwright.sh` (primary frontend proof), `scripts/testing/e2e-test.sh` (CLI/API baseline the browser should mirror), and `bun test` in `client/static/js/`. Where Playwright hedges (`includes(...)` with many alternatives, idempotent SKIP, pass-without-assertion), tighten tests and fix frontend behavior so there is one canonical expected result. Cross-client parity with `arkfile-client` is explicit: AGENTS.md requires one way to encrypt/upload, download/decrypt, and share per client type, with matching structure where practical.

Status: implementation complete (2026-07-21) — unit tests passing; run dev-reset + e2e locally to verify
Created: 2026-07-18
Audited: 2026-07-20
Priorities updated: 2026-07-21
Tranches and Playwright scope locked: 2026-07-21
Findings rechecked against implementation: 2026-07-21
Implementation: 2026-07-21
Scope: `client/static/js/src/**` (47 source modules excl. tests/`.d.ts`, ~18,043 LOC), `client/static/js/sw-download.js` (built from `sw-download.ts`), HTML entrypoints that load the bundle (`index.html`, `shared.html`). Server, schema, and CLI changes are in scope when required to remove a privacy-breaking shared contract, including plaintext `password_hint`, or to correct the shared chunk-accounting defect. Cross-stack documentation updates for intentionally server-visible operational metadata (billable storage size) are in scope; do not change size visibility or billing behavior merely to conceal size. Other server or CLI changes remain out of scope unless a contract or chunk fix requires matching implementation and E2E assertions. Archived WIP documents are reference material only and are not changed by this project.

## Principles

One canonical way per browser operation (upload, owner download, share create/list/revoke, anonymous share download, export backup, billing panel load, verify local file digest). Fail closed where technically possible: no fake admin contacts, no silent decode-success on malformed API responses, and no console logging of sensitive metadata in production bundles unless gated. Target state: no sensitive plaintext file metadata is sent to or stored by the server except explicitly documented operational fields whose necessity has been reviewed. That target is not met today for custom password hints (plaintext end-to-end). Custom password hints must be encrypted client-side with the Account Key. Remove the plaintext contract completely from clients, handlers, models, schema, tests, and comments; do not retain compatibility branches, deprecated names, or explanatory remnants of the removed path. The server knowing or computing pre-padded file size (encrypted length and inferable plaintext size) is intentional for storage accounting and billing; document this clearly across the codebase and do not change the wire contract merely to conceal size. Large-file downloads must remain possible on all client types: CLI streams decrypt-to-disk; browser uses the Service Worker path with chunk-bounded memory. Retain the working Blob fallback for environments where Service Worker streaming is unavailable or cannot initialize, without an Arkfile-imposed file-size cap; clearly explain that Blob fallback buffers the plaintext and may exhaust browser resources for large files. Download integrity UX must be honest about browser limits: always surface the expected SHA-256 at completion; when inline verification ran, show its result; when a streamed download may already be on disk before the whole-file digest is known, explain why and point users to the Verify File tool or an offline hasher. Do not claim clean success when inline verification reports a mismatch. Delete dead exports and legacy no-op APIs rather than keep them for compatibility. Shared pure helpers belong in one module (`utils/format.ts` or similar), not four copies of `formatBytes`. CLI and frontend critical crypto flows should mirror protocol behavior and test vectors (envelope bytes, AAD, salts, ticket refresh, chunk accounting, digest display and verification semantics); matching function names is secondary. The Go CLI is the current reference implementation after its cleanup, but parity does not prove correctness: shared frontend/CLI protocol deficiencies must be recorded and fixed in both. After each workstream: `sudo bash scripts/dev-reset.sh`, `bash scripts/testing/e2e-test.sh`, `sudo bash scripts/testing/e2e-playwright.sh`, and `cd client/static/js && bun test`.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Audit inventory and reachability map | [x] done | 2026-07-20: ~271 runtime exports by source scan; zero-importer count provisional; actionable inventory below |
| One canonical path audit (upload/download/share) | [x] done | Single upload/owner-download/share-ticket paths confirmed; download integrity UX open |
| CLI parity matrix and drift fixes | [x] audited | Matrix filled; crypto mostly matches; shared hint defect and frontend-only Blob defects recorded |
| Encrypt custom password hints (tranche 1) | [x] done | Account-Key encrypted hint + nonce; greenfield removal of plaintext contract across FE/CLI/server/schema |
| Canonical chunk accounting (tranche 1) | [x] done | `models.CalculateChunkCount` uses encrypted span; completion/meta use session/DB counts; boundary unit tests |
| Download integrity UX + Verify File tool (tranche 1) | [x] done | Integrity panel helpers; Blob mismatch blocks trigger; Verify File panel + streaming hasher; uncapped Blob retained |
| Server-visible metadata documentation (tranche 1) | [x] done | AGENTS.md + docs/security.md + uploads handler comments |
| Account key cache lifecycle (tranche 2) | [x] done | Unified teardown via cleanupAccountKeyCache; orphan ciphertext clear; docs/claims corrected |
| Share auth ticket-only cleanup (tranche 2) | [x] done | Dead static wrapper removed; ticket failure fails closed; server static fallback removed |
| Dead code and legacy API removal (tranche 2) | [x] done | Confirmed dead exports/globals removed; window surface narrowed |
| Admin contacts contract (frontend, tranche 2) | [x] done | Failed refresh clears state; unit tests added |
| Duplicate helper consolidation (tranche 3) | [x] done | Shared `utils/format.ts` |
| Privacy-sensitive logging review (tranche 2) | [x] done | Hot-path `debugLog` + `ARKFILE_DEBUG_LOG` define on build:prod |
| Hygiene and comment cleanup (tranche 3) | [x] done | Decorative dividers/WIP refs removed from production src; opaque "for now" clarified |
| Error message consistency (tranche 2) | [x] done | Stable `data-testid` for wrong-password and share access errors |
| `app.ts` decomposition (tranche 3) | [ ] deferred | Behavior stabilized; mechanical split left for a follow-up (low risk, low urgency) |
| Playwright hedging removal (tranche 2) | [x] done | Upload SKIP and share OR-hedges tightened; billing top-up fails closed |
| Playwright registration flow (tranche 3) | [x] done | Isolated register → TOTP → 25 MB custom upload → verify → revoke-all |
| Frontend billing display parity (tranche 3) | [x] done | PAYG upload cap, `rate_human`, run-out timestamp |
| Structural consolidation + hygiene (tranche 3) | [x] done | Formatters + hygiene + prod debug gate; `app.ts` split deferred |
| Unit test gap fill | [x] done | Hint round-trip, chunk counts, admin contacts, ticket fail-closed, integrity helpers |
| Production build hygiene | [x] done | `--define ARKFILE_DEBUG_LOG=false` on build:prod |

---

## Primary implementation priorities (agreed 2026-07-21)

These priorities take precedence over the rest of this plan. They reflect audit findings plus product decisions from the 2026-07-21 review.

### Encrypt custom password hints (shared frontend / CLI / server)

**Implemented.** Both clients encrypt custom-password hints with the Account Key under AAD label `encrypted_password_hint`, send `encrypted_password_hint` + `password_hint_nonce` (omit both when empty), and decrypt only for owner custom-password prompts. The plaintext contract is removed from schema, handlers, models, CLI, and browser. See **Custom password hint privacy** below for the design that was applied.

### Canonical chunk accounting, download integrity UX, large-file streaming, and Verify File tool (frontend)

**Implemented** (chunk accounting, integrity UX, Verify File, uncapped Blob fallback retained). Large downloads must work on constrained devices (e.g. 3 GB RAM, 6 GB file) without holding the whole plaintext in page memory. The Service Worker streaming path is the canonical browser mechanism; Blob fallback remains for SW-unavailable environments without an Arkfile size cap. Chunk accounting uses `ceil(size_bytes / (chunk_size_bytes + 28))` via `models.CalculateChunkCount`, with completion/meta preferring the validated session/DB count.

Integrity semantics must be honest about browser limits. Whole-file SHA-256 can be computed inline during SW streaming with bounded memory, but a mismatch is often detected only after bytes may already be saved by the OS download manager — the app cannot "un-download" without buffering the entire file first, which defeats streaming. Per-chunk AES-GCM still authenticates each chunk during decrypt. The UX model is: always show the expected SHA-256 at download completion (from decrypted metadata or share envelope); when inline verification ran, show match/mismatch alongside it; never show a clean success message when inline verification reports mismatch; on SW and other post-write paths, show tips explaining that users who need certainty should compare the expected digest using Verify File or an offline tool and delete the file if it differs.

Add a new **Verify this file** tool to the frontend, reachable at any time (not only immediately after download). The user picks a local file via the file picker; the app hashes it in chunks using the same streaming pattern as upload (`file.slice()` + incremental SHA-256, peak memory ~one chunk). The user supplies or pastes an expected hex digest (or the tool pre-fills it when launched from a download completion panel). Show match/mismatch without loading the whole file into JS heap. Works fully offline once the expected digest is known. Surface contextual hints, tips, and popups at appropriate moments — e.g. before or during a large SW download (explain streaming limits), and on the download completion panel (expected digest, optional inline result, link/button to Verify File).

Blob fallback remains available without an application-level file-size cap because it is needed when Service Worker streaming is unavailable or cannot initialize. Prefer SW streaming whenever available; warn that Blob fallback buffers the complete plaintext and may fail under browser resource limits for large files. Check `hashVerification` before `triggerBrowserDownloadFromUrl`, revoke the Blob URL on mismatch, and do not claim success. Document SW vs Blob vs CLI post-write verification limits in `sw-streaming-download.ts`, `streaming-download.ts`, `download.ts`, and `share-access.ts`.

### Document server-visible operational metadata (docs only; no behavior change)

The server knowing or computing pre-padded file size — encrypted declared length, inferable plaintext size from chunk count and fixed per-chunk overhead, `size_bytes`, and `padded_size` — is **intentional**. Arkfile must account for storage and bill users accurately; hiding exact size from the server would break billing, quotas, chunk download, padding removal, export, and replication. Padding obscures size from the storage backend and outside observers, not from the Arkfile server that receives the pre-padding length at upload init.

Do **not** change upload/download wire behavior for size. Instead, document accepted visibility consistently in `AGENTS.md`, `docs/security.md`, handler comments (e.g. `handlers/uploads.go`), and this plan. Classify server-visible fields as required operational data vs encrypted owner metadata (filename, content digest, encrypted password hint). Optionally document `password_type` and FEK envelope key-type visibility in the same pass; that is a separate disclosure from billable size and needs no protocol change unless product decides otherwise later.

---

## Implementation tranches (agreed 2026-07-21)

Work proceeds in three tranches. Do not expand Playwright beyond the single approved flow in tranche 3 unless product explicitly reopens scope.

### Tranche 1 — privacy, download integrity, documentation

| Workstream | Scope |
|------------|-------|
| Encrypt custom password hints | Atomic frontend + CLI + server + schema + E2E sentinel proof |
| Canonical chunk accounting | One encrypted-stream/chunk formula across init, completion, owner/share metadata and clients; exact-boundary and multi-GB tests |
| Download integrity UX + Verify File tool | SW canonical large-file path; unrestricted but clearly described Blob fallback; completion digest UX; standalone verify tool |
| Server-visible operational metadata | Docs only (`AGENTS.md`, `docs/security.md`, handler comments); no wire change |

### Tranche 2 — session lifecycle, share cleanup, existing E2E hardening

| Workstream | Scope |
|------------|-------|
| Account key cache lifecycle | Unified teardown; correct JWT binding claims; optional server session epoch decision |
| Share auth ticket-only cleanup | Delete dead static-token paths; coordinate server fallback removal |
| Error message consistency | Stable `data-testid` / error codes for Playwright tightening |
| Admin contacts stale cache | Clear state on every failed refresh |
| Playwright hedging removal | Fix existing shared-page suite only (upload SKIP, share OR-hedges, billing top-up SKIP-pass) |
| Privacy logging gate | Gate debug/info; verify `build:prod` artifact |

### Tranche 3 — consolidation, billing parity, one Playwright flow

| Workstream | Scope |
|------------|-------|
| Duplicate helper consolidation | `formatBytes` / `formatFileSize` → shared module |
| `app.ts` decomposition | Mechanical split after behavior stable |
| Hygiene pass | Remove `===` dividers, WIP refs in comments, emoji in logs |
| Frontend billing display parity | Render `rate_human`, friendly runway, and `estimated_runs_out_at_approx` to match `arkfile-client billing show` |
| **Playwright: one registration flow** | **Only new browser E2E addition for this project** — see **Playwright scope** below |

---

## Audit summary

| Metric | Value |
|--------|-------|
| Source `.ts` files (excl. tests / `.d.ts`) | 47 |
| Source LOC | ~18,043 |
| Test files | 22 |
| Test LOC | ~5,521 |
| Runtime exports surveyed | ~271 (source scan; approximate) |
| Exports with zero external importers | Provisional count; individually listed candidates reverified |
| Largest modules | `upload.ts` (~1,288), `billing.ts` (~880), `totp.ts` (~871), `streaming-download.ts` (~807), `account-key-cache.ts` (~756), `app.ts` (~748) |
| Playwright E2E coverage | Existing: login-through-logout shared-page suite + billing + contact-info embedded in share-revocation test. Planned (tranche 3): one isolated registration → TOTP → 25 MB custom-password round trip → revoke-all flow |
| `bun test` focus | Crypto, streaming download, upload batch helpers, auth cookie model; minimal UI/integration |

**Highest-impact findings (post-audit, prioritized)**

- **Shared frontend/CLI privacy defect: custom password hints are plaintext end-to-end** — Both clients send `password_hint`; the server stores and returns it. Encrypt with Account Key in both clients and remove the plaintext contract. Primary priority: encrypted password hints.
- **Chunk counts are calculated inconsistently** — Upload init correctly divides encrypted stream length by `plaintext chunk size + 28`, while upload completion and owner metadata divide encrypted length by plaintext chunk size. Exact-boundary files can gain an invalid extra chunk, and empty owner files can report zero chunks. The representative 6 GB file is an exact 16 MiB multiple and must be a boundary test.
- **Frontend download integrity UX is misleading** — Blob callers ignore `hashVerification`; SW path can show success before warning on mismatch. SW streaming is required for a chunk-bounded memory guarantee on large files; users need expected digest at completion, honest inline results, contextual tips, and a standalone Verify File tool.
- **Frontend Blob fallback fully buffers plaintext and is not the preferred large-file path** — Retain it without an Arkfile file-size cap for SW-unavailable environments, clearly warn about proportional browser resource use, and handle browser allocation failures honestly. SW remains canonical for reliable multi-GB downloads on constrained devices.
- **Server-visible file size is intentional operational metadata** — Pre-padded encrypted length and inferable plaintext size support billing and storage accounting. Document across codebase; do not change wire behavior.
- **Frontend account-key cache claims a production session binding that does not exist** — HttpOnly-cookie callers pass no token, so `token_hash` is empty and checks are skipped. Clearing session data removes ciphertext and makes the cache unusable, but does not consistently wipe the in-heap wrapping key. Rate Medium–High, not equivalent to the hint/Blob defects.
- **Share auth cleanup is needed, but the live UI does not downgrade** — `applyShareAuthHeader` contains static-token fallback code, yet `share-access.ts` → `downloadSharedFileWithTicket` passes only `shareTicket`; ticket failure sends no auth header. Static-token support is reachable through the dead wrapper/generic manager and remains accepted by the server.
- **Stale window globals and over-exposed globals** — `registrationData` and `totpLoginData` are never set; `window.arkfile` exposes whole modules though `shared-init.js` only needs `ShareAccessUI`; `window.arkfileApp` is also set with no repository reader.
- **`fetchAdminContacts` returns stale state after any failed refresh** — Non-OK responses and exceptions preserve previous usernames/contact/configured values.
- **Playwright hedges on existing suite** — Idempotent upload SKIP in account-password and custom-password upload tests; OR-hedges in share-control and revoke tests; billing top-up SKIP-pass. **Approved Playwright expansion (tranche 3 only):** one isolated flow — register new user, TOTP setup/confirm, custom-password upload of a **25 MB** file, download/decrypt/verify SHA-256, revoke-all via `#revoke-sessions-btn`. All other browser E2E gaps (export click, WebAuthn, MFA settings, subscription, admin-contacts footer, reregistration, dedicated Verify File E2E, custom-password share recipient) remain deferred to `e2e-test.sh`, unit tests, or manual proof for now.
- **Dead exports, hygiene, and logging remain** — Confirmed candidates are listed below. Production minification does not remove console calls; debug/info logs should be gated or dropped while security warnings/errors remain.

---

## Prioritized fix list (implementation order)

| Finding | Severity | Action |
|---------|----------|--------|
| Plaintext `password_hint` (frontend + CLI + server contract) | High | Account-Key encryption; schema/API/both clients together; sentinel privacy E2E |
| Inconsistent chunk-count and encrypted-size accounting | High | Canonical `ceil(size_bytes / (chunk_size_bytes + 28))` rule; empty-file semantics; boundary tests |
| Download integrity UX + Verify File tool (frontend) | High | Expected digest at completion; inline result when available; tips/popups; standalone verify tool; honest success/mismatch messaging |
| Blob path + large-file policy (frontend) | High | Retain fallback with no app cap; prefer SW; warn about full buffering; Blob mismatch blocks trigger; document resource and verification limits |
| Server-visible size documentation (cross-stack docs) | Medium | Document intentional billable size visibility in AGENTS.md, security.md, handlers; no wire change |
| Account key cache lifecycle (frontend) | Medium–High | Fix claims and teardown; decide whether server session epoch is warranted |
| Dead static share auth paths | Medium | Delete wrapper/fallback; server ticket-only coordination; actionable ticket errors |
| Stale globals + dead exports | Medium | Remove/unexport; narrow browser global surface |
| Admin contacts stale cache | Medium | Clear on every failed refresh; unit test; optional footer assert deferred from Playwright |
| Playwright hedges (existing suite) | Medium | Tranche 2: stable error identity; remove SKIP/OR hedges on shared-page tests |
| Playwright registration flow | Medium | Tranche 3: one isolated test only — register, TOTP, 25 MB custom upload, verify, revoke-all |
| Frontend billing display parity | Medium | Tranche 3: show `rate_human` and run-out fields matching CLI human output |
| Hygiene + production logging | Low | Tranche 3: dividers/WIP refs/emoji; tranche 2–3: gate debug/info while preserving warnings/errors |

---

## Audit inventory and reachability map

### Outcome (2026-07-20)

Reachability pass completed via export/import graph, dynamic imports from `app.ts`, and `shared.html` / `shared-init.js` bootstrap. A selected actionable inventory is in **Function inventory (frontend)** below; it is not a row-for-row table of every export.

### Entry points

| Surface | Bootstrap | Notes |
|---------|-----------|-------|
| `index.html` | `/js/libopaque.js` + `/js/dist/app.js` | Full `ArkFileApp`; dynamic imports for billing, contact, MFA, upload, shares list |
| `shared.html` | `/js/dist/app.js` + `/js/shared-init.js` | App still initializes; `shared-init.js` needs only `window.arkfile.shares.ShareAccessUI` |
| Service Worker | `/sw-download.js` from `sw-download.ts` | Separate ESM bundle; registered from app |

### Privacy check (inventory)

Does the module send sensitive plaintext metadata to the network, server storage, or logs? **Yes for password hints** (plaintext end-to-end; fix via encrypted password hints workstream). Filenames and content SHA-256 are encrypted in owner metadata. Declared upload size and inferable plaintext size are intentionally server-visible for billing and storage accounting (document in security docs). `password_type` and the FEK envelope key-type byte are also server-visible; document in the same pass if helpful. Hot-path logs use `password_type`, sizes, and timings; no plaintext password/FEK was found, but production gating is still required.

---

## One canonical path audit

### Upload — CONFIRMED single path

| Layer | File | Role |
|-------|------|------|
| UI entry | `upload.ts` `handleFileUpload()` | Sole UI entry from `app.ts` / `#upload-file-btn` |
| Core | `upload.ts` `uploadFiles()` / `uploadFile()` | Init/chunk/complete streaming |
| Dedup | `digest-cache.ts` | Client-side SHA-256 dedup before upload |

**Answers:** `handleFileUpload` is the only UI entry. Retry paths in `retry-handler.ts` are reachable via upload/download chunk helpers. Duplicate user string includes `Duplicate file detected` (duplicate-upload E2E in `e2e-playwright.ts`). Client-side digest cache is intentional divergence from CLI agent.

**Compare CLI:** MATCH on chunk size, AAD, FEK wrap, metadata encryption. BOTH send plaintext `password_hint`.

### Custom password hint privacy

#### Problem (was verified; now fixed)

Previously `upload.ts` and CLI `commands.go` sent plaintext `password_hint` in `/api/uploads/init`, the server persisted and returned it, and the browser showed it in custom-password prompts. Share envelopes and `.arkbackup` never included hints. That contract is removed.

#### Target design (applied)

Hints use Account-Key-encrypted ciphertext and nonce fields. Add matching permanent Go and TypeScript metadata AAD field constants using the label `encrypted_password_hint` alongside the filename and SHA-256 labels, using the existing `buildMetadataFieldAAD(fileID, fieldName, ownerUsername)` encoding. Existing metadata AAD is not separately versioned; future incompatible formats should use a new permanent field label rather than silently reusing one. Empty hints have one cross-client canonical representation: omit both encrypted fields. The server treats encrypted hint fields as opaque and rejects ambiguous ciphertext/nonce combinations.

Encryption must occur inside the upload `file_id` conflict retry loop. Each candidate file ID requires fresh hint ciphertext and nonce because the file ID is bound into AAD. Upload uses the authenticated canonical username; decryption uses `owner_username` returned with the metadata row, matching filename/SHA-256 handling.

Because Arkfile is greenfield, remove the plaintext contract completely rather than retaining dual decoding, compatibility fallback, deprecated symbols, named tombstones, or comments about the removed path. Coordinate these changes atomically:

| Layer | Required change |
|-------|-----------------|
| Browser upload/download/share | Re-encrypt per candidate file ID; decrypt only for custom-password owner prompts; update `list.ts`; never place plaintext hints in request bodies or logs |
| CLI upload/download/share | Use the same encrypted field format, nonce rules, AAD, and empty representation as the browser; add hint display only if desired |
| Server handlers/models/schema | Store and return only opaque ciphertext+nonce on both upload sessions and final file metadata; remove every plaintext field, column, model member, and handler binding |
| Share envelope | No change: anonymous recipients use the share password and must never receive the owner's custom-file hint |
| Export/backup | Optional follow-up: today `.arkbackup` omits hints; if offline UX needs them, update `handlers/export.go` and CLI `offline_decrypt.go` together |
| Tests | Go/TypeScript cross-client AAD and encryption vectors, raw API/DB assertions including abandoned upload sessions, wrong-key/tamper failures, omitted-empty-hint behavior, sentinel privacy |

#### Acceptance criteria

- Browser and CLI produce and consume the same encrypted hint format and AAD.
- Raw upload, list, metadata, share, and export API responses contain no plaintext hint.
- Database upload-session and file-metadata records use only opaque ciphertext and nonce fields; abandoned in-progress upload sessions are included in proof.
- Clients, handlers, models, schema, tests, and active documentation contain only the intended encrypted-hint contract, with no compatibility code or references to a removed plaintext path.
- For `password_type === 'custom'` only, owner download and share-creation decrypt and display the hint after the Account Key is available and before the custom-password prompt. Account-password files never show a hint.
- Hint ciphertext or AAD tampering fails closed and does not display corrupted text.
- Tests use a unique sentinel hint and prove that it does not appear in network payloads, server responses, database contents, server logs, or production browser logs.

### Server-visible operational metadata (document only; no behavior change)

#### Current behavior (verified; intentional)

Both clients send `total_size` as the exact encrypted-data length before the server adds padding and `chunk_size` as the plaintext chunk size. Upload initialization computes the intended chunk count from `chunk_size + 28`, then the server stores the unpadded encrypted length as `file_metadata.size_bytes` and the padded storage-object length as `padded_size`. For a non-empty file, the canonical chunk count is `ceil(size_bytes / (chunk_size_bytes + 28))`, and plaintext length is `size_bytes - (28 × chunk_count)`. Empty-file semantics must be defined once and shared by init, completion, metadata, owner download, and share download. This is **required operational metadata**: the server must account for storage consumption and bill users accurately. Server-generated padding obscures size from the storage backend or an outside observer of S3 objects, but not from the Arkfile server that received the pre-padding length at upload init.

Both clients also send plaintext `password_type`, and the FEK envelope includes a visible key-type header byte. These reveal account-vs-custom compartmentalization to the server. The server also knows `owner_username` and plaintext chunk size because they are required for ownership, metadata AAD reconstruction, and encrypted byte-range handling. User quota and projected billing use pre-padding encrypted `size_bytes`; storage-provider accounting and replication also know `padded_size`. These fields are separate from billable size but belong in the same consolidated server-visible metadata section in `docs/security.md`.

The implementation currently violates its own intended chunk formula: upload completion and owner metadata divide encrypted `size_bytes` by plaintext `chunk_size_bytes`. This can produce an invalid extra chunk for exact-boundary files and zero owner chunks for an empty file. Fixing that defect is a Tranche 1 correctness change, not a privacy-motivated wire-format change.

#### Target (documentation only)

Do not change upload init, chunk download, padding, billing, or quota wire behavior for size. Update documentation and code comments so developers and security reviewers understand the split:

| Category | Examples | Server visibility |
|----------|----------|-------------------|
| Encrypted owner metadata | filename, content SHA-256, password hint (once encrypted hints land) | Opaque ciphertext + nonce only |
| Intentional operational metadata | `total_size`, `size_bytes`, `padded_size`, chunk count, billable bytes | Known or computable by server; required for billing/accounting |
| Protocol and ownership fields | `owner_username`, plaintext chunk size, `password_type`, FEK envelope key-type byte | Visible; required for ownership/AAD/range handling and documents compartmentalization choice |

#### Files to update

| Location | Change |
|----------|--------|
| `AGENTS.md` | Nuance "server must know nothing about the nature of the data" — no passwords, no plaintext filenames, no file contents; billable storage size is known by design |
| `docs/security.md` | New or expanded section: server-visible operational metadata vs encrypted owner metadata |
| `handlers/uploads.go` (and related) | Align comments with billing/accounting intent (partially present today) |
| This plan | Record decision in **Document server-visible operational metadata** above |

#### Acceptance criteria

- Security documentation states exactly which metadata the server observes, stores, or infers, and why (especially billable size).
- No code or schema change alters size declaration, padding, or billing math solely for privacy of size from the server.
- Chunk-count correctness is fixed separately using the canonical encrypted-span formula; this is a correctness change, not a size-concealment change.
- Frontend and CLI cross-client size vectors pass existing E2E plus exact-boundary cases.
- The same documentation pass covers `owner_username`, plaintext chunk size, `password_type`, and FEK key-type visibility without implying pending concealment work.

### Canonical chunk accounting

Upload initialization correctly treats each stored encrypted chunk as `plaintext chunk size + 28-byte AES-GCM overhead`, with the final chunk possibly shorter. Upload completion currently recalculates `chunk_count` by dividing encrypted `declaredSize` by plaintext `chunkSizeBytes`, and owner metadata repeats that mismatch. Exact full-chunk files can therefore report one extra chunk, while an empty owner file can report zero even though upload initialization records one. The frontend trusts these values when generating chunk requests. The representative 6 GB file is an exact multiple of the configured 16 MiB plaintext chunk size, so the existing 25 MB fixture cannot prove this boundary.

Define one shared formula and empty-file rule across upload init, completion, file metadata, share metadata, owner download, share download, CLI, and browser. Persist the validated init chunk count or recompute only through one canonical helper. Correct frontend progress accounting as part of the same work: `size_bytes` is already encrypted-stream length and must not have per-chunk GCM overhead added again. Add Go and TypeScript unit vectors for 0, 1, `chunk size - 1`, exact chunk size, `chunk size + 1`, multiple exact chunks, and 6 GB; add E2E owner and anonymous-share proof at practical exact boundaries.

Acceptance: every layer reports and requests the same number of chunks; no request reaches padding bytes; exact-boundary and empty files upload, owner-download, share-download, decrypt, and verify successfully; size and progress displays do not double-count encryption overhead.

### Owner download — CONFIRMED single path; integrity UX OPEN

| Layer | File | Role |
|-------|------|------|
| Orchestration | `download.ts` `downloadFile()` | Sole list-item path from `list.ts` |
| Streaming | `streaming-download.ts` `downloadFileChunked` → manager | Chunk fetch, AES-GCM decrypt, SW vs Blob |
| SW integration | `sw-streaming-download.ts`, `sw-download.ts` | Canonical large-file path |
| Verify File (new) | TBD module + UI entry | Anytime local file vs expected digest; chunk-bounded hashing |

**Answers:** One owner UI path exists, but `download.ts` and `StreamingDownloadManager` currently fetch metadata separately; remove the duplicate request when touching orchestration. SW path streams with roughly chunk-bounded page-side memory and can compute whole-file SHA-256 inline during the stream, but a mismatch may be detected only after the OS download manager has already saved bytes — document this limit and surface expected digest + tips at completion. Blob fallback builds `new Blob([blob, chunk])` for the entire file with no size bound; retain it without adding an Arkfile cap, explain its proportional resource use, and handle browser allocation failure honestly. `download.ts` warns on SW mismatch but still calls `showSuccess` first; Blob path triggers download and success without checking `hashVerification`. Add completion UI: expected SHA-256 (copyable), inline verification result when available, link to Verify File tool. Existing Playwright fixtures remain 50–100 KB on the shared dev user; the tranche-3 registration flow uses a **25 MB** custom-password file as the only larger browser fixture and does not prove the 6 GB boundary.

### Share (owner + recipient) — CONFIRMED; delete dead wrapper

| Flow | Files | Verdict |
|------|-------|---------|
| Create | `files/share.ts` → `ShareCreator` → `share-crypto.ts` | Sole create path |
| List/revoke | `share-list.ts` | Live; share list and revoke/contact E2E in `e2e-playwright.ts` |
| Anonymous access | `share-access.ts` → `share-ticket.ts` → `downloadSharedFileWithTicket` | Sole live export |

**Answers:** Anonymous download always goes through `downloadSharedFileWithTicket`. **Delete `downloadSharedFileChunked`.** The live wrapper passes only `shareTicket`, so ticket-provider failure does not actually downgrade to a static token; it produces a request without an auth header and fails. `share-access.ts` needs the same download integrity UX as owner `download.ts` (expected digest from share envelope at completion, inline result, tips, Verify File launch). Generic manager/static-token support and server acceptance remain cleanup debt.

---

## Download integrity UX, Verify File tool, and Blob fallback

### Problem (was verified; now fixed)

When Service Worker streaming is unavailable or cannot initialize, `streamDecryptedChunks` retains the complete plaintext in a Blob regardless of size. This is full-file buffering in browser-managed Blob storage, not a resource-bounded path. The fallback is retained without an Arkfile-imposed size cap. Previously both `download.ts` and `share-access.ts` triggered the Blob download and reported success without checking `hashVerification`.

The Service Worker path streams with chunk-bounded memory and can hash plaintext incrementally during the stream (same memory profile as upload-side `computeStreamingSHA256`). However, the whole-file digest is often known only after bytes have been handed to the browser download manager. Preventing a bad file from landing on disk would require buffering the entire plaintext first, which defeats streaming and the 6 GB / 3 GB RAM requirement. Per-chunk AES-GCM authentication still fails during the stream on chunk tampering; whole-file SHA-256 is an additional consistency check whose result may arrive post-write. The CLI has the same timing on disk: it verifies after `computeStreamingSHA256` on the output path and returns an error on mismatch, but the file may already exist.

Current UI is misleading: SW path can show success then warn; Blob path ignores mismatch entirely. Users are not shown the expected digest prominently or guided to offline verification when inline blocking is impossible.

Service Worker registration is asynchronous, so an early download can take the Blob path even in a capable browser. The current fallback classifier also groups acknowledgement timeout with pre-transfer clone failure. If the SW has already consumed any generator output, reusing that generator for Blob fallback can produce a truncated or corrupt result. Mid-stream decryption or transport failure can likewise leave a partial browser download. Readiness, fallback eligibility, and partial-download messaging must therefore be explicit.

### Target design

#### Streaming download policy

| Path | Large files | Memory | Inline whole-file SHA-256 | On mismatch |
|------|-------------|--------|---------------------------|-------------|
| SW (canonical) | Yes | Chunk-bounded | Computed during stream | Do not claim clean success; show expected + computed digests; tip to delete file and use Verify File |
| Blob (fallback) | Best effort with no app cap; browser resources may be insufficient | Full file in Blob store before trigger | Computed before trigger | Revoke Blob URL; do not trigger download; show failure |
| CLI | Yes | Chunk-bounded decrypt-to-disk | After write via streaming hash | Error after write; file may remain (document parity) |

Prefer SW streaming whenever available and surface its readiness state instead of silently selecting Blob during the registration race. Retain Blob fallback without an application-level size limit and give owner and anonymous-share users the same warning that it buffers the complete plaintext and may fail under browser resource limits. If the browser cannot allocate or retain the Blob, report that failure directly and recommend retrying with SW streaming or the CLI.

Only fall back from SW to Blob when no generator output has been consumed. Treat a synchronous transfer/clone rejection separately from acknowledgement timeout or any uncertain post-transfer state; never reuse a possibly drained generator. On mid-stream transport or decryption failure, explain that a partial file may already exist and should be deleted.

#### Download completion UX (owner + share)

At download finalization, always display the expected SHA-256 hex (owner: decrypted metadata; share: envelope). Copy-to-clipboard. When inline verification ran, show match or mismatch beside it. Never show an unqualified success message when inline verification is `mismatch`. Contextual hints and popups:

- **Before / during large SW download:** brief note that the file streams to the download folder with chunk-bounded memory; whole-file digest is checked as data flows but a problem may be detected only after the file is saved.
- **After SW completion with match:** success plus expected digest for the user's records.
- **After SW completion with mismatch:** integrity failure panel — expected digest, computed digest if available, instruction to delete the downloaded file, button to open Verify File with expected digest pre-filled.
- **After Blob completion:** success only if inline verification passed or was skipped with explicit reason; retain the expected digest in the completion panel.

#### Verify this file tool (new; anytime)

Add a standalone frontend feature reachable from the main app (and optionally `shared.html` for share recipients who saved an expected digest):

| Aspect | Requirement |
|--------|-------------|
| Entry | Persistent nav/menu item or tools section; also deep-link from download completion |
| Input | User picks local file via `<input type="file">` (browser cannot read Downloads silently) |
| Expected digest | User paste, or pre-fill from download/share completion |
| Hashing | Reuse upload streaming pattern: `file.slice()` + incremental `@noble/hashes` SHA-256; peak memory ~one chunk |
| Offline | Works with no network once expected digest is known |
| Output | Match / mismatch / invalid hex; copy buttons; no logging of digest values in production info logs |

Extract shared `computeStreamingSHA256(file, chunkSize)` from `upload.ts` into a crypto or utils module for upload, verify tool, and tests.

#### Code comments and developer docs

Document in source why post-write verification is unavoidable on SW streams and how that differs from Blob pre-trigger verification. Reference CLI `computeStreamingSHA256` in `crypto_utils.go` and offline `decrypt-blob` post-write check as the same class of limitation.

### Acceptance criteria

- Multi-GB owner and share downloads use SW path on supported browsers without whole-file page buffering.
- Blob fallback remains available without an Arkfile-imposed file-size cap; owner and share UX accurately describe full buffering and possible browser resource failure.
- SW readiness is surfaced, and fallback occurs only when generator consumption is known not to have started.
- Owner and share Blob callers check `hashVerification` before trigger; mismatch revokes URL and does not claim success.
- SW mismatch never shows unqualified success; completion UI shows expected digest and guidance.
- Mid-stream failure warns that a partial downloaded file may need deletion.
- Verify File tool available anytime; hashes large local files without loading entire file into JS heap.
- Contextual tips/popups appear on large SW downloads and at completion as specified.
- Unit tests: Blob mismatch blocking, completion messaging, verify tool streaming hash.
- Playwright: **not** in scope for Verify File tool or a dedicated large-file SW test. The tranche-3 registration flow's **25 MB** custom-password upload/download is the only approved larger browser fixture; it provides moderate-size integration coverage but does not prove the 6 GB constrained-device requirement, a dedicated SW-only path, or the Verify File tool.

---

## Account key cache lifecycle

### Problem (verified; Medium–High)

`account-key-cache.ts` documents JWT session binding via `token_hash`, but all production cookie-auth reads/writes omit an access token, so the stored hash is empty and the binding check is skipped. Ephemeral wrapping key in JS heap remains the real protection. `clearAllSessionData()` removes sessionStorage ciphertext, making the persisted cached Account Key unusable, but it does not consistently wipe the wrapping key or other derived key bytes held by active operations; logout has additional cleanup while revoke-all/session-expiry paths do not. A page reload loses the heap-only wrapping key while leaving unusable ciphertext in `sessionStorage`. This is a misleading threat-model and teardown problem, not evidence that cleared persisted ciphertext remains decryptable.

### Target

- Implement one teardown primitive used by logout, revoke-all, session expiry, inactivity, and explicit lock so each clears ciphertext and wipes the wrapping key.
- Explicit decision: add a server-provided session epoch/version to `/api/auth/me` and bind the cache to it, or accept heap-only wrapping with accurate documentation. The epoch approach requires coordinated server/session work.
- Detect orphaned ciphertext after reload when no wrapping key exists and clear it rather than retaining unusable state.
- Document per-tab semantics correctly: module state and `sessionStorage` are tab-scoped (a newly opened tab may receive an initial copy depending on browser/opener behavior, but updates are not shared).
- Tests: logout, re-login as another user, session revoke, inactivity lock, page reload, and multi-tab.
- Remove emoji from integrity failure log (`AGENTS.md` no-emoji).

---

## Share auth ticket-only alignment

### Problem

`applyShareAuthHeader` contains a static `X-Download-Token` fallback when a manager has `downloadToken`. The live anonymous chunk-download path (`share-access.ts` → `downloadSharedFileWithTicket`) supplies only `shareTicket`, so ticket-provider failure sends no static token and fails in practice, matching the CLI's ticket-only chunk-auth posture. The encrypted share envelope still contains the download token needed to request the ticket; ticket-only cleanup does not remove that protocol input. The fallback remains reachable through the dead `downloadSharedFileChunked` wrapper or any generic-manager caller that supplies a token; the server still accepts both credentials. The current warning is also false on the live path because it claims fallback even when no token exists.

### Target design

When server ticket-only pass lands:

| File | Change |
|------|--------|
| `streaming-download.ts` | Delete dead static-token wrapper/support; propagate ticket-provider failure before issuing an unauthenticated request |
| `share-access.ts` | Envelope decrypt → ticket request → download is the only path |
| `share-ticket.ts` | Preserve already-verified CLI parity for refresh lead/minimum timing |

Until server changes: delete dead `downloadSharedFileChunked`; remove or accurately constrain manager fallback; align comments. The server-side static credential branch still needs coordinated removal, but the live frontend is not currently performing a silent downgrade.

### Tests

Extend `streaming-download.test.ts`: ticket-provider failure must stop before fetch or produce an actionable error and must never send `X-Download-Token`. Anonymous share download E2E in `e2e-playwright.ts` already exercises ticket download.

---

## Dead code and legacy API removal

### Confirmed dead (delete)

| Item | Location | Evidence | Action |
|------|----------|----------|--------|
| `downloadSharedFileChunked` | `streaming-download.ts` | Zero callers | Delete |
| `showTOTPSetupModal` | `totp.ts` | Never called; live path is `generateAndDisplayTOTPSetup` | Delete |
| `getTOTPStatus` | `totp.ts` | Never called | Delete |
| `hideTOTPSetupSection` / `hidePendingApprovalSection` | `sections.ts` | Never called | Delete |
| `handleBillingCheckoutReturn` / `handleSubscriptionCheckoutReturn` | `billing.ts` | Unused aliases; underlying `resumePending*` functions are live | Delete aliases only |
| `getCsrfTokenExport` | `auth.ts` | Unused rename | Delete |
| `getTokenExpiry` / `isTokenExpired` | `auth.ts` | Stub / test-only under HttpOnly JWT | Delete exports; update tests |
| `addPasswordTogglesGlobal` | `password-toggle.ts` | Unused | Delete |
| `showInfo` / `showConfirmModal` | messages/modals | Never called | Delete |
| Unused barrels (`accountKeyCache`, `fileEncryption`, `upload`, `passwordModal`, `primitives`) | various | Never imported as namespace objects | Delete objects only; preserve live named exports |
| `window.registrationData` | types + clearAllSessionData | Never set | Remove typing and cleanup |
| `window.totpLoginData` path | `app.ts` read | Never set; login uses `_pendingTOTPFlowData` | Remove window read |
| `window.arkfileApp` | `app.ts` / DOM types | Set but no repository reader | Remove exposure unless a documented external consumer exists |
| `showToast` / `clearAllMessages` / unused modal closers | messages/modals | Zero external call sites | Reverify and delete or unexport |

### Live (keep; fix comments)

| Item | Location | Notes |
|------|----------|-------|
| `showProgressMessage` | `progress.ts` | Used by auth flows; rename "Legacy compatibility" comment |
| `revokeAllSessions` | `auth.ts` + `#revoke-sessions-btn` | Live UI; covered by tranche-3 registration flow Playwright test |
| `window.totpSetupData` | `totp-setup.ts` | Live until migrated to module-private |
| `downloadFileChunked` | `streaming-download.ts` | Used by `download.ts` |
| `shareCrypto` namespace object | `share-crypto.ts` | Live in share creation/access; delete only unused member `validateSharePasswordStrength` |

### Narrow surface

| Item | Action |
|------|--------|
| `window.arkfile.shares` | Expose only `ShareAccessUI` for `shared-init.js` |
| `window.arkfile.encryption` / `window.arkfile.auth` | No readers; stop spreading full modules |
| Same-file-only class exports | Unexport in hygiene pass (`RegistrationManager`, `ShareListUI`, managers, etc.) |

### Decision criteria

If Playwright + `bun test` + grep show no importers, delete. If E2E does not cover but product requires it (registration UI, WebAuthn), keep the code; browser E2E for those flows is deferred except the single tranche-3 registration flow described under **Playwright scope**.

---

## CLI parity matrix (audited 2026-07-20)

AGENTS.md requires mirrored critical protocol behavior. Status after audit:

| Operation | CLI reference | Frontend reference | Status | Notes |
|-----------|---------------|-------------------|--------|-------|
| Argon2id params / salts | `crypto/key_derivation.go` | `constants.ts`, `floors.ts`, `file-encryption.ts` | MATCH wire values; LOW loading drift | FE fetches API + applies compiled floors; Go embeds JSON. FE lowercases defensively; valid/CLI usernames are already normalized lowercase |
| Chunk encrypt/upload | `commands.go` upload | `upload.ts` | MATCH | Same chunk size, AAD, FEK wrap |
| Custom password hint | upload init + meta | `upload.ts`, `download.ts`, `list.ts`, `share.ts` | SHARED DEFECT | Both clients send plaintext; FE displays hint, CLI does not |
| Declared size / key type | upload init + FEK envelope | `upload.ts` | DOCUMENTED INTENTIONAL | Server-visible for billing/accounting and routing; document only |
| Chunk download/decrypt | `commands.go` download | `download.ts` + `streaming-download.ts` | MATCH crypto; FE UX GAP | Metadata always Account Key; FE needs download completion UX + Verify File. CLI verifies after write via streaming hash |
| Share create | `CreateShareEnvelope` | `share-crypto.ts` | MATCH | Same JSON + AAD + token hash |
| Share recipient download | ticket-only | `share-access.ts`, `share-ticket.ts` | LIVE PATH MATCH | FE live UI is ticket-only; dead generic/static-token support remains cleanup |
| Export backup | `export.go` | `export.ts` | MATCH artifact | Intentional auth difference (Bearer vs short-lived token) |
| Billing display | `billing_commands.go` | `billing.ts` | GAP (tranche 3) | CLI human output shows `rate_human`, projected cost, runway hours, `estimated_runs_out_at_approx`; FE types include fields but `renderUsageSection` omits rate and run-out timestamp |
| Contact info | `handleContactInfo*` | `contact-info.ts` | MATCH | FE adds pending-approval UI |
| Digest dedup | agent digests | `digest-cache.ts` | INTENTIONAL | No agent in browser |
| Password validation | Go + JSON | `password-validation.ts` | MATCH | account / custom / share |
| Revoke all sessions | `revoke-all` | `auth.ts` + `#revoke-sessions-btn` | MATCH API+UI | Tranche-3 Playwright registration flow |

---

## Admin contacts contract (frontend)

Server cleanup established honest `GET /api/admin-contacts` with `configured: false`. Frontend call sites mostly correct.

### Verify / fix

| File | Check | Audit note |
|------|-------|------------|
| `auth.ts` `fetchAdminContacts` | No hardcoded defaults; clear state on any failed refresh | **Bug:** non-OK and exceptions return previous `adminContactsConfigured` / contact |
| `footer.ts` | Uses configured flag; shows "not configured" | OK when fetch succeeds |
| `list.ts` | Storage contact note uses same contract | OK pattern |
| `sections.ts` | Pending approval hints | OK pattern |

### E2E additions

Unit test: failed refresh clears `fetchAdminContacts` state. Playwright footer assert against `/api/admin-contacts` is **deferred** (not in approved Playwright scope). When implementing the stale-cache fix, assert via `bun test` and optionally manual check; do not assume dev-reset supplies a contact string.

---

## Duplicate helper consolidation

| Duplicates | Target |
|------------|--------|
| `formatBytes` x3, `formatFileSize` x1 | `client/static/js/src/utils/format.ts` (or `ui/format.ts`) |
| Error user strings | Prefer typed error → `data-testid` / error code; thin `ui/errors.ts` for copy |
| Base64/hex helpers | Already centralized; verify no ad hoc duplicates in share modules |

---

## Privacy-sensitive logging review

### Problem

Hot paths use ungated `console.log` with operation timing and field names. Integrity path in `account-key-cache.ts` uses an emoji. Production minify must not be assumed to strip console.

### Files to audit (approx. console call counts)

| File | Approx. console calls |
|------|----------------------|
| `streaming-download.ts` | 21 |
| `download.ts` | 16 |
| `upload.ts` | 8 |
| `account-key-cache.ts` | 10 |
| `login.ts` | 5 |

### Target

Gate verbose logs behind a single debug flag. Production `build:prod` should explicitly drop or no-op debug/info logs and verify the artifact; do not blindly remove security-relevant warnings/errors such as integrity failures. Never log passwords, FEK bytes, share passwords, decrypted filenames, plaintext SHA-256, or plaintext password hints. Chunk progress logs should use chunk index only. Remove emoji from logs.

Cross-reference: `docs/wip/archive/review/06-frontend-supply-ops.md` (source maps, service worker logs).

---

## Hygiene and comment cleanup

### Violations confirmed

| Pattern | Locations | Action |
|---------|-----------|--------|
| `// ===...===` section blocks | `list.ts`, `password-modal.ts`, `share-crypto.ts`, `share-list.ts`, `digest-cache.ts`, `upload.ts`, `auth-manager.test.ts`, others | Remove per AGENTS.md |
| "Legacy compatibility" | `progress.ts` | Describe actual role (simple progress toast) |
| "for now" | `opaque.ts` | Accurate crypto description |
| WIP doc paths in comments | `upload.ts`, `file-encryption.ts` (`docs/wip/...`) | Remove or point to stable docs |
| Emoji in log | `account-key-cache.ts` integrity failure | Plain ASCII |

---

## Error message consistency

### Problem

Playwright custom-password download test asserts `check your password` via `includes`. Duplicate upload E2E uses one string. Share error tests accept many alternatives.

### Target

| UX event | Canonical identity | Consumers |
|----------|-------------------|-----------|
| Wrong custom password decrypt | Stable error code or `data-testid` + unit-tested copy | `download.ts`, Playwright |
| Duplicate upload | Single string already present | Duplicate upload rejection E2E |
| Share expired / max downloads / revoked / not found | One `data-testid` (or code) each | Share control E2E tests, `shared.html` |

Prefer stable selectors over brittle exact-copy-only asserts. Fix frontend first, then tighten Playwright.

---

## `app.ts` decomposition

### Problem

`app.ts` (~748 LOC) mixes Trusted Types setup, readiness probe, SW registration, and dozens of DOM event listeners.

### Recommended extractions (after privacy/integrity stable)

| New file | Contents |
|----------|----------|
| `app/trusted-types.ts` | CSP Trusted Types policy |
| `app/ready-check.ts` | `/readyz` gate |
| `app/event-bindings.ts` | Upload, auth toggle, billing toggle, contact-info, security settings |
| `app.ts` | `ArkFileApp` orchestration only |

Template: CLI admin decomposition in `docs/wip/archive/cli-cleanup.md`. Defer to tranche 3 after tranche-1 privacy/integrity work lands.

---

## Playwright scope (locked 2026-07-21)

Do **not** add further browser E2E tests beyond what is listed here until product explicitly reopens Playwright scope.

### Existing suite (keep; harden in tranche 2)

The shared-page arc in `e2e-playwright.ts` (login through logout on `arkfile-dev-test-user`, shares, billing, contact-info embedded in share-revocation) stays as-is. Tranche 2 removes hedges (upload SKIP, share OR alternatives, billing top-up SKIP-pass) and adds stable error identity first.

Fixtures today: account-password file **100 KB** (`102400` bytes); custom-password file on shared user **50 KB** (`51200` bytes). These remain for the fast shared-page tests.

### One approved additive flow (tranche 3 only)

Add **one** new test (isolated browser context / page — not the shared Account Key cache page):

| Step | Requirement |
|------|-------------|
| 1. Register | Create a **new** user via browser UI (`register.ts` / `#register-form`). Use a unique username per run (e.g. timestamp suffix) to avoid collisions on re-runs. |
| 2. TOTP MFA setup + confirm | Complete mandatory TOTP enrollment in the registration modal. Read manual-entry secret from `#totp-reg-secret`; generate codes via `arkfile-client generate-totp` with `waitForMfaWindow` replay protection (same pattern as existing suite). Confirm setup with a valid code. Dismiss backup-codes step as needed. |
| 3. Login | Skip if registration + TOTP completion already yields an authenticated session; otherwise log in with the new credentials + TOTP. |
| 4. Custom-password upload | Upload a **25 MB** test file (`26214400` bytes via `arkfile-client generate-test-file` in `e2e-playwright.sh`). Use custom password (not account key). Increase upload wait timeout vs the 50 KB shared test (e.g. 300s+). |
| 5. Download / decrypt / verify | Download via file list; enter custom password; hash downloaded artifact with Node `crypto`; `expect(actualHash).toBe(expectedSha256)` from shell precompute. |
| 6. Revoke session | Click `#revoke-sessions-btn` (`revokeAllSessions` / `POST /api/auth/revoke-all`). Assert protected UI requires re-login (not merely `#logout-link`). |

**Shell / env:** dedicated fixture vars (e.g. `REG_FLOW_FILE_PATH`, `REG_FLOW_FILE_SHA256`, `REG_FLOW_USERNAME`, `REG_FLOW_PASSWORD`, `REG_FLOW_CUSTOM_PASSWORD`) separate from the existing `CUSTOM_FILE_*` shared-user vars.

**Prerequisites:** `e2e-test.sh` must finish by successfully running `run_enable_auto_approval`, which sets `require_approval=false` before teardown so subsequent Playwright registration auto-approves. This setup is mandatory: failure must fail the E2E run, and Playwright must not compensate with an approval fallback. Keep the final setup step and align its comment with its actual role preparing subsequent Playwright and manual testing.

**Out of scope for Playwright (deferred):** export backup click, WebAuthn setup, MFA settings panel, subscription checkout/portal, admin-contacts footer assert, reregistration, dedicated large-file SW-only test, Verify File tool E2E, custom-password share recipient, pending-approval UI as a standalone test. Cover these via `e2e-test.sh`, `bun test`, or manual proof unless scope is reopened.

---

## Playwright hedging removal (tranche 2)

| Location | Current hedge (verified) | Target |
|----------|--------------------------|--------|
| Account-password upload E2E | SKIP if file already in list (pass without upload) | Fail unexpected state; prefer deterministic post-dev-reset |
| Custom-password upload E2E | SKIP if file already in list (pass without upload) | Same as account-password upload |
| Custom-password wrong-password E2E | `includes('check your password')` | Stable identity from frontend |
| Share expiry control E2E | `expired` \| `forbidden` \| `error` \| `403` | One `data-testid` or string; avoid 65s wall clock via pre-expired fixture |
| Share max-downloads control E2E | 7 OR alternatives | One identity |
| Share non-existent ID E2E | 4 OR alternatives | One identity |
| Share revoke E2E | 5 OR alternatives; revoke UI OR-hedge | One identity |
| Logout E2E | Legacy localStorage checks comment | Assert only cookie/sessionStorage contract |
| Raw API privacy E2E | No `password_hint` check | Add sentinel after encryption |
| Billing top-up | `[SKIP]` if button missing → pass | Explicit precondition; fail if billing enabled in dev-reset |

---

## Deferred browser E2E (not in this project)

These gaps were audited but are **explicitly out of Playwright scope** for now. Track in CLI/unit/manual verification instead.

| Gap | Deferred proof |
|-----|----------------|
| Export backup download click | `e2e-test.sh` export/decrypt; file deletion Playwright only checks dialog text |
| MFA settings / WebAuthn setup | CLI + manual; WebAuthn needs hardware/virtual authenticator |
| Subscription checkout/portal | CLI billing/subscription commands; partial Playwright top-up already exists |
| Admin contacts footer | Unit test + manual; stale-cache fix in tranche 2 |
| Dedicated large-file SW download | Tranche-3 25 MB registration flow partially exercises streaming; 6 GB remains manual |
| Verify File tool | Unit tests in tranche 1; no Playwright E2E |
| Custom-password share recipient | `e2e-test.sh` share paths |
| Reregistration | `e2e-test.sh` OPAQUE reregistration group |
| Pending approval UI (standalone) | Not a separate test; the registration flow requires successful final `require_approval=false` setup |

---

## Unit test gap fill

### Current coverage (good)

Crypto primitives, AAD, Argon2 conformance, file encryption, share-crypto, streaming-download manager (mocked fetch), upload batch helpers, digest-cache, account-key-cache, export format, SW handler.

### Priority additions

| Target | Rationale |
|--------|-----------|
| Encrypted password hint contract | Cross-client vectors, tamper rejection, empty hint, no plaintext fields |
| Canonical chunk accounting | Empty/exact-boundary/multi-chunk vectors; owner/share consistency; no encrypted-overhead double count |
| Verify File tool + shared streaming hasher | Chunk-bounded hash of user-picked file; match/mismatch; extract from upload.ts |
| Download completion UX + Blob/SW integrity | Expected digest display, tips, Blob mismatch blocking, SW honest messaging |
| Account key cache lifecycle | Logout / binding / inactivity |
| `fetchAdminContacts` failed refresh clears state | Stale cache bug |
| `getUserFriendlyMessage` / wrong-password path | Stabilizes Playwright |
| `billing.ts` render helpers | Pure formatting; tranche-3 parity with CLI human fields (`rate_human`, run-out) |
| Production log stripping flag | If debug gate added |

Keep full upload/share integration in the **existing** Playwright shared-page suite unless flakiness forces slimmer unit tests with mocked `fetch`. The tranche-3 registration flow is the only new browser integration test.

---

## Frontend billing display parity (tranche 3)

### Problem

`arkfile-client billing show` human output includes upload cap, storage rate, projected monthly cost, estimated runway hours, and approximate run-out timestamp from the same `GET /api/credits` payload. `billing.ts` already types `rate_human` and `estimated_runs_out_at_approx` but `renderUsageSection` does not render the rate line or run-out timestamp when billable usage is above baseline. The frontend renders upload cap in subscribed mode but omits the corresponding PAYG field.

### Target

Match CLI placement and wording where practical:

| Field | CLI (`billing_commands.go`) | Frontend (`billing.ts`) |
|-------|----------------------------|-------------------------|
| `effective_storage_limit_bytes` | Upload cap when greater than zero | Show in PAYG usage grid as well as subscribed mode |
| `rate_human` | Under current storage block | Show in usage grid when present |
| `current_cost_per_month_usd_approx` | Projected cost/month | Already shown as "Your projected cost" |
| `estimated_hours_remaining` | Estimated runway: N hours | Already shown via `formatHoursFriendly` when billable > 0 |
| `estimated_runs_out_at_approx` | Indented run-out line | Add when hours > 0 and field present |

No new API calls. JSON shape unchanged. Add unit tests for render helpers.

---

## Production build hygiene

| Item | Action |
|------|--------|
| `build:prod` | Do not assume `--minify` strips console; explicitly gate/drop debug and info while retaining security warnings/errors; inspect artifact |
| `app.js.map` | Already external; operational decision from supply-chain review |
| `libopaque.js` | Pin/rebuild process out of scope unless hash mismatch found |

---

## Suggested implementation order

Work silent correctness and privacy before cosmetic cleanup. Tranche numbers match **Implementation tranches** above.

### Tranche 1

- **Encrypt custom password hints** — remove the plaintext frontend/CLI/server/schema contract; re-encrypt per file-ID attempt; add cross-client and sentinel privacy proof.
- **Canonical chunk accounting** — one encrypted-span formula and empty-file rule across init, completion, metadata and clients; exact-boundary and 6 GB vectors.
- **Download integrity UX + Verify File tool** — expected digest at completion; inline result when available; tips/popups for SW post-write limits; standalone verify tool; Blob mismatch blocking; retain uncapped Blob fallback with honest resource warnings; SW canonical for constrained-device large files.
- **Document server-visible operational metadata** — AGENTS.md, security.md, handler comments; billable size intentional; no wire change.

### Tranche 2

- **Account key cache lifecycle** — unify key teardown, correct security claims, decide whether a server session epoch is warranted.
- **Delete confirmed dead exports and static share paths** — `downloadSharedFileChunked`, token stubs, stale globals; coordinate server removal of static credential acceptance.
- **Admin contacts failed-refresh clear** — unit test; no Playwright footer assert in scope.
- **Error identity standardization** — unlock Playwright tightening without brittle copy-only asserts.
- **Playwright hedging removal** — existing shared-page suite only; deterministic fixtures post-dev-reset.
- **Privacy logging gate** — preserve security warnings/errors; verify `build:prod` artifact.

### Tranche 3

- **Frontend billing display parity** — PAYG upload cap, `rate_human`, runway, and `estimated_runs_out_at_approx` in billing panel matching CLI human output.
- **Playwright: one registration flow** — isolated context; register → TOTP → 25 MB custom upload → download/verify → revoke-all; dedicated shell fixture vars.
- **Duplicate formatters** — low-risk consolidation.
- **`app.ts` decomposition** — mechanical, after behavior stable.
- **Hygiene pass** — dividers, WIP refs, legacy comments, emoji in logs.

### Throughout all tranches

- **Unit tests** — alongside each fix (not a final batch).

---

## Verification checklist (final)

- [ ] `sudo bash scripts/dev-reset.sh`
- [ ] `bash scripts/testing/e2e-test.sh` — all PASS (includes custom-hint sentinel privacy assert)
- [ ] `sudo bash scripts/testing/e2e-playwright.sh` — all PASS, zero undocumented SKIP (includes tranche-3 registration flow)
- [x] `cd client/static/js && bun test` — all PASS (395 tests, 2026-07-21)
- [x] `cd client/static/js && bun run lint` — type-check clean (2026-07-21)
- [x] Exact-boundary chunk vectors pass for 0, 1, chunk size ±1, exact multi-chunk sizes, and 6 GB; owner and share paths agree (`models/file_chunk_count_test.go`)
- [ ] Manual: 6 GB file upload/download on constrained tab uses SW streaming; Blob fallback remains available without an app cap and clearly warns about full buffering
- [ ] Manual: shared file anonymous download with ticket refresh after forced 403
- [ ] Manual: Verify File tool hashes a multi-GB local file without excessive memory; match/mismatch against known digest
- [ ] Manual: large SW download shows streaming-limit tip; completion panel shows expected SHA-256 and Verify File entry point
- [ ] Manual: billing panel shows `rate_human`, projected cost, runway, and run-out timestamp matching CLI `billing show` human output (tranche 3)
- [ ] Tranche-3 Playwright registration flow passes: new user, TOTP setup, 25 MB custom-password upload/download SHA-256 verify, revoke-all
- [x] Browser and CLI encrypted password-hint conformance vectors pass (`crypto_utils_test.go`, `aad.test.ts`)
- [ ] Raw API, database, server-log, and production-browser-log checks prove a unique plaintext hint sentinel appears nowhere outside client plaintext memory/UI
- [x] Only the encrypted-hint contract remains across clients, handlers, models, schema, tests, and active documentation; no compatibility path or removed-field commentary remains
- [x] Owner and share Blob mismatches do not trigger browser download and revoke the Blob URL (wired via `download-integrity.ts`)
- [x] SW mismatch never shows unqualified success; completion UI shows expected digest, inline result when available, and Verify File guidance
- [x] `AGENTS.md` and `docs/security.md` document intentional server-visible billable size; no doc claims size is hidden from the server
- [x] Account key ciphertext and wrapping key are cleared after logout / revoke-all / inactivity as designed
- [x] Grep production `client/static/js/src` for decorative `===`/`---` dividers and WIP comment refs — cleaned; test files may still use section dividers
- [x] Hot-path download/upload/streaming logs gated via `debugLog` + `ARKFILE_DEBUG_LOG=false` on `build:prod`
- [ ] Production bundle inspection confirms debug/info logs stripped or gated while security warnings/errors remain
- [ ] `app.ts` mechanical decomposition deferred to a follow-up

---

## E2E-confirmed hot paths (do not delete without replacement)

| Flow | Frontend modules / DOM |
|------|------------------------|
| Auth | `login.ts`, `totp.ts`, `password-modal.ts` cache opt-in; `#login-btn`, `#verify-totp-login` |
| Upload | `upload.ts`, `app.ts` file input; account + custom password |
| Download | `download.ts`, `list.ts` Download action; completion digest UI; Verify File entry |
| Delete | `list.ts` delete + export backup button **text** presence (not click) |
| Shares | `share.ts`, `share-list.ts`, `share-access.ts`; create A/B/C, list, revoke |
| Anonymous share | `shared.html` + `share-access.ts`; anonymous share and share-control E2E; completion digest + optional Verify File on share page |
| Contact info | `contact-info.ts`; revoke/contact-info E2E embedded tests |
| Billing | `billing.ts`; balance, usage grid, transactions, top-up modal (may SKIP) |
| Logout | `login.ts` logout; logout E2E sessionStorage/CSRF checks |
| API privacy | Raw API privacy E2E checks encrypted filename/hash only; it does not assert hint absence or re-check intentional server-visible size/key type |

---

## Not exercised by Playwright (keep; deferred or tranche-3 only)

| Flow | Modules | Recommendation |
|------|---------|----------------|
| Registration + TOTP (full UI) | `register.ts`, `mfa-setup.ts`, `totp-setup.ts` | **Tranche 3:** one isolated Playwright flow only |
| WebAuthn | `webauthn.ts`, `clictap` integration | Keep; manual / CLI; no Playwright |
| MFA settings | `mfa-settings.ts`, `mfa-method.ts` | Keep; no Playwright |
| Export download | `export.ts` | Keep; `e2e-test.sh`; deletion test checks dialog text only |
| Subscription portal | `billing.ts` subscribe/portal handlers | Keep; CLI; no new Playwright |
| Revoke all | `auth.ts` + `#revoke-sessions-btn` | **Tranche 3** registration flow |
| Pending approval | `sections.ts` `showPendingApprovalSection` | Keep; no standalone Playwright |
| SW large download (6 GB) | `sw-streaming-download.ts` | Manual; 25 MB in tranche-3 registration flow |
| Reregistration | `login.ts` re-register path | Keep; `e2e-test.sh` |
| `downloadSharedFileChunked` | `streaming-download.ts` | **Confirmed dead — delete** |
| Admin contacts footer | `footer.ts` | Unit test; no Playwright |
| Custom-password share recipient | share of custom-password file | `e2e-test.sh` |
| Verify File tool | new verify module | Unit tests tranche 1; no Playwright |

---

## Out of scope (this document)

Vendored `libopaque.js` rebuild pipeline (see supply-chain review). Caddy/CSP/systemd changes. Server and CLI changes unrelated to required privacy-contract remediation; encrypted password-hint API/schema/model/CLI changes are explicitly in scope. Full rewrite of `06-frontend-supply-ops.md` findings. Windows or non-browser clients.

---

## Relationship to server and CLI cleanup

| Prior cleanup item | Frontend follow-up |
|--------------------|-------------------|
| Admin contacts honest API | Clear stale cache on every failed refresh; unit test; Playwright footer deferred |
| Plaintext custom password hint | Replace with Account-Key-encrypted metadata across browser, CLI, server, schema, export, and E2E |
| Server-visible billable size | Document intentional operational visibility; no wire change |
| Chunk accounting | Canonical encrypted-span formula, empty-file rule, and exact-boundary vectors across server and clients |
| Download integrity + Verify File | Expected digest UX, tips/popups, standalone verify tool, retained uncapped Blob fallback, safe fallback state; unit tests only (no Verify File Playwright) |
| Share ticket-only (deferred) | Live UI already fails ticket-only; remove dead static-token wrapper/generic support and server fallback |
| E2E hedging removal pattern | Tranche 2: `e2e-playwright.ts` upload SKIP, share-control OR hedges, billing SKIP |
| Frontend billing display parity | Tranche 3: match CLI human `billing show` fields (`rate_human`, run-out timestamp) |
| Playwright registration flow | Tranche 3: one test — register, TOTP, 25 MB custom upload, verify, revoke-all |
| CLI error message consistency | Align via stable error identities |
| Duplicate formatters | Same consolidation discipline as `handlers/format.go` / `cli/format` |
| Agent digest privacy | Browser uses `digest-cache.ts`; intentional divergence documented |

---

## Selected actionable function inventory (frontend)

Audit date: 2026-07-20. Method: named/dynamic import graph across `client/static/js/src`, `shared-init.js`, and HTML entrypoints. This is the reviewed keep/delete subset, not a complete row for every runtime export. Playwright column: Y = exercised, N = not exercised, P = partial.

### Canonical / hot-path symbols (keep)

| Symbol | File | Playwright | Action |
|--------|------|------------|--------|
| `handleFileUpload` | `upload.ts` | Y | Keep — sole upload UI entry |
| `uploadFiles` / `uploadFile` | `upload.ts` | Y / tests | Keep; consider unexporting `uploadFile` |
| `downloadFile` | `download.ts` | Y | Keep — sole owner download entry; download completion digest UX |
| `verifyLocalFileDigest` (or similar) | new verify module | N | **Add** — anytime Verify File tool; chunk-bounded |
| `computeStreamingSHA256` (shared) | extract from `upload.ts` | P (upload) | **Extract** for upload + verify tool + tests |
| `downloadFileChunked` | `streaming-download.ts` | Y | Keep |
| `downloadSharedFileWithTicket` | `streaming-download.ts` | Y | Keep — sole anonymous share download |
| `StreamingDownloadManager` | `streaming-download.ts` | P (unit) | Keep; tests construct directly |
| `shareFile` / `ShareCreator` | `share.ts` / `share-creation.ts` | Y | Keep |
| `shareCrypto.*` | `share-crypto.ts` | Y / unit | Keep |
| `ShareAccessUI` | `share-access.ts` | Y | Keep; required by `shared-init.js` |
| `ShareTicketHolder` | `share-ticket.ts` | Y | Keep |
| `initializeShareList` | `share-list.ts` | Y | Keep |
| `exportBackup` | `export.ts` | N (dialog text only) | Keep; `e2e-test.sh` export path |
| `revokeAllSessions` | `auth.ts` | N → tranche 3 | Keep; tranche-3 registration flow |
| `fetchAdminContacts` | `auth.ts` | N | Clear state after any failed refresh; unit test |
| `showProgressMessage` | `progress.ts` | Y (auth) | Keep; fix comment |
| `register` / `setupRegisterForm` | `register.ts` | N → tranche 3 | Keep; tranche-3 registration flow |
| WebAuthn / MFA settings helpers | `webauthn.ts`, `mfa-*.ts` | N | Keep; no Playwright |
| `swStreamDownload` / SW handler | `sw-streaming-download.ts`, `sw-download.ts` | P (unit only) | Keep; 25 MB in tranche-3 registration flow; 6 GB manual |
| Account key cache API | `account-key-cache.ts` | P (login opt-in) | Fix lifecycle; expand tests |
| `toggleBillingPanel` / checkout resume | `billing.ts` | P | Keep; tranche-3 billing parity + tighten SKIP |

### Confirmed delete / unexport candidates

| Symbol | File | Playwright | Action |
|--------|------|------------|--------|
| `downloadSharedFileChunked` | `streaming-download.ts` | N | **Delete** |
| `getTokenExpiry` / `isTokenExpired` | `auth.ts` | tests only | **Delete** exports; update tests |
| `getCsrfTokenExport` | `auth.ts` | N | **Delete** |
| `showTOTPSetupModal` / `getTOTPStatus` | `totp.ts` | N | **Delete** |
| `hideTOTPSetupSection` / `hidePendingApprovalSection` | `sections.ts` | N | **Delete** |
| `handleBillingCheckoutReturn` / `handleSubscriptionCheckoutReturn` | `billing.ts` | N | **Delete** aliases |
| `addPasswordTogglesGlobal` | `password-toggle.ts` | N | **Delete** |
| `showInfo` / `showConfirmModal` | messages/modals | N | **Delete** |
| `promptForAccountKeyCaching` | `password-modal.ts` | N | **Delete** (login uses `promptForCacheOptIn`) |
| `validateSharePasswordStrength` | `share-crypto.ts` | N | **Delete** wrapper if unused |
| Namespace barrels (`accountKeyCache`, `fileEncryption`, `upload`, `passwordModal`, `primitives`) | various | N | **Delete objects only; named exports remain** |
| `window.registrationData` | types/auth clear | N | **Remove** |
| `window.totpLoginData` | `app.ts` / types | N | **Remove** window path |
| `window.arkfile.encryption` / `.auth` | `app.ts` | N | **Stop exposing** |
| `window.arkfileApp` | `app.ts` / types | N | **Remove exposure unless external consumer documented** |
| `showToast` / `clearAllMessages` / unused modal closers | messages/modals | N | **Reverify and delete/unexport** |
| Same-file-only class exports | register/share-list/UI managers | — | **Unexport** in hygiene pass |

### Window globals lifecycle

| Global | Set | Read | Cleared | Verdict |
|--------|-----|------|---------|---------|
| `window.totpSetupData` | `totp-setup.ts` | Setup completion | Success/error; `clearAllSessionData` | Live |
| `window.totpLoginData` | Never | `app.ts` `handleTOTPVerify` | Deletes in totp/auth | Stale — remove |
| `window.registrationData` | Never | None | `clearAllSessionData` | Dead — remove |
| `window.arkfile.shares` | `app.ts` spread | `shared-init.js` needs `ShareAccessUI` | — | Over-exposed |
| `window.arkfile.encryption` / `.auth` | `app.ts` | No readers | — | Dead exposure |
| `window.arkfileApp` | `app.ts` | No repository reader | — | Dead exposure unless externally required |

### Playwright E2E map (summary)

Use test titles in `scripts/testing/e2e-playwright.ts` when referring to coverage in code or reviews — not ordinal labels.

| Test (as named in `e2e-playwright.ts`) | Exercises | Hedge? |
|----------------------------------------|-----------|--------|
| Login (OPAQUE + MFA + cache opt-in) | OPAQUE + TOTP + cache opt-in | No |
| Upload file with account password | `upload.ts` | SKIP if file exists |
| Download file and verify SHA-256 integrity | `download.ts` | No |
| Duplicate upload rejection | upload duplicate string | No |
| File deletion via Delete button | delete dialog; Export Backup **text only** | No export click |
| Upload file with custom password | custom password | SKIP if file exists |
| Custom-password download (correct + wrong password) | correct + wrong password | Mild `includes` |
| Raw API privacy verification | filename/hash encrypted | **No hint check** |
| Create shares A (no limits), B (max_downloads=2), C (expires=1m) | share UI | Soft overlay catch |
| Share list verification (decrypted metadata) | share list UI | Soft overlay catch |
| Anonymous share download (Share A) | ticket download | Soft toast catch |
| Share access controls (max downloads, expiry, non-existent) | share control paths | **OR hedges**; 65s wait |
| Share revocation (revoke Share A, verify access denied) | revoke + user contact CRUD | OR hedges on revoke/deny |
| Billing panel renders balance, usage grid, and transaction history | billing UI | No |
| Billing top-up modal creates invoice and embeds checkout iframe | billing top-up modal | Top-up **SKIP-pass** |
| External-tab checkout return opens billing panel and confirms paid invoice | billing checkout return | No |
| Logout and post-logout security checks | cookies/sessionStorage | Soft re-login skip |
| *(planned tranche 3)* Registration, TOTP, 25 MB custom upload, verify, revoke-all | `register.ts`, `totp-setup.ts`, `upload.ts`, `download.ts`, `auth.ts` | **Not yet in spec** — add as single isolated test |

---

## Audit session record

Completed 2026-07-20 (read-only; documentation update only):

- Reachability inventory of runtime exports and entry points.
- End-to-end read of upload/download/streaming-download/share-access against Function Review Sanity Checks.
- Playwright E2E map and hedging inventory.
- Full `password_hint` trace across browser, CLI, handlers, schema, export, shares, tests, and docs.
- CLI parity matrix for upload, download, share, export, billing, contact, digest, revoke-all, hints, size, and key type.
- Hygiene and privacy greps (`===` dividers, WIP refs, console/sensitive patterns, emoji).
- Independent correction pass for live share-ticket reachability, Blob/SW integrity semantics, cache teardown, AAD design, and selected inventory accuracy.
- Priority refinement (2026-07-21): encrypted hints, download integrity UX + Verify File tool, server-visible size documentation only.
- Tranche and Playwright scope lock (2026-07-21): three tranches; one approved Playwright registration flow (25 MB custom password, revoke-all); frontend billing parity with CLI; deferred browser E2E list.
- Label cleanup (2026-07-21): removed ordinal area/phase/section numbering from this plan so implementation does not inherit accidental identifiers.
- Independent implementation recheck (2026-07-21): verified the principal findings; corrected test inventory; found inconsistent completion/metadata chunk arithmetic, SW readiness and generator-reuse risks, cache reload/teardown gaps, PAYG upload-cap display drift, and the strict final auto-approval setup.
- Product decisions incorporated (2026-07-21): retain Blob fallback without an Arkfile file-size cap; prefer SW streaming and describe Blob resource costs honestly; remove the plaintext hint contract without compatibility remnants; leave archived WIP documents unchanged.

Deliverables: this filled inventory, prioritized fix list, primary implementation priorities section, and updated progress tracker. Application code was not modified in this pass.
