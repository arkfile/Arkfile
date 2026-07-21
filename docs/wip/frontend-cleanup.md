# Frontend Cleanup & Cohesion Plan

This plan applies the same audit methodology as `docs/wip/archive/server-cleanup.md` and `docs/wip/archive/cli-cleanup.md` to the TypeScript browser client under `client/static/js/src/`. Every exported function, class method, and UI flow handler is reviewed against the Function Review Sanity Checks in `AGENTS.md`: required, correctly implemented, well placed, reachable, privacy-preserving, and free of stubs, deprecated paths, duplicated logic, and leftover placeholder code. Arkfile is greenfield; delete unused or misleading frontend paths rather than maintain compatibility shims. The audit is cross-checked against `scripts/testing/e2e-playwright.sh` (primary frontend proof), `scripts/testing/e2e-test.sh` (CLI/API baseline the browser should mirror), and `bun test` in `client/static/js/`. Where Playwright hedges (`includes(...)` with many alternatives, idempotent SKIP, pass-without-assertion), tighten tests and fix frontend behavior so there is one canonical expected result. Cross-client parity with `arkfile-client` is explicit: AGENTS.md requires one way to encrypt/upload, download/decrypt, and share per client type, with matching structure where practical.

Status: audit complete (2026-07-20); priorities refined (2026-07-21) — ready for implementation
Created: 2026-07-18
Audited: 2026-07-20
Priorities updated: 2026-07-21
Scope: `client/static/js/src/**` (47 source modules excl. tests/`.d.ts`, ~18,043 LOC), `client/static/js/sw-download.js` (built from `sw-download.ts`), HTML entrypoints that load the bundle (`index.html`, `shared.html`). Server, schema, and CLI changes are in scope when required to remove a privacy-breaking shared contract, including plaintext `password_hint`. Cross-stack documentation updates for intentionally server-visible operational metadata (billable storage size) are in scope; wire-format or behavior changes for size accounting are not. Other server or CLI changes remain out of scope unless a contract fix requires a matching E2E assertion. Prior security review findings in `docs/wip/archive/review/06-frontend-supply-ops.md` (CSP, innerHTML, supply chain) are referenced but not re-litigated here unless they intersect with dead code or misleading behavior.

## Principles

One canonical way per browser operation (upload, owner download, share create/list/revoke, anonymous share download, export backup, billing panel load, verify local file digest). Fail closed where technically possible: no fake admin contacts, no silent decode-success on malformed API responses, and no console logging of sensitive metadata in production bundles unless gated. Target state: no sensitive plaintext file metadata is sent to or stored by the server except explicitly documented operational fields whose necessity has been reviewed. That target is not met today for custom password hints (plaintext end-to-end). Custom password hints must be encrypted client-side with the Account Key. The server knowing or computing pre-padded file size (encrypted length and inferable plaintext size) is intentional for storage accounting and billing; document this clearly across the codebase and do not change the wire contract. Large-file downloads must remain possible on all client types: CLI streams decrypt-to-disk; browser uses the Service Worker path with chunk-bounded memory. Blob fallback is a small-file / SW-unavailable escape hatch only and must not fully buffer files beyond a documented safe bound. Download integrity UX must be honest about browser limits: always surface the expected SHA-256 at completion; when inline verification ran, show its result; when a streamed download may already be on disk before the whole-file digest is known, explain why and point users to the Verify File tool or an offline hasher. Do not claim clean success when inline verification reports a mismatch. Delete dead exports and legacy no-op APIs rather than keep them for compatibility. Shared pure helpers belong in one module (`utils/format.ts` or similar), not four copies of `formatBytes`. CLI and frontend critical crypto flows should mirror protocol behavior and test vectors (envelope bytes, AAD, salts, ticket refresh, digest display and verification semantics); matching function names is secondary. The Go CLI is the current reference implementation after its cleanup, but parity does not prove correctness: shared frontend/CLI protocol deficiencies must be recorded and fixed in both. After each workstream: `sudo bash scripts/dev-reset.sh`, `bash scripts/testing/e2e-test.sh`, `sudo bash scripts/testing/e2e-playwright.sh`, and `cd client/static/js && bun test`.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Audit inventory and reachability map | [x] done | 2026-07-20: ~271 runtime exports by source scan; zero-importer count provisional; actionable inventory below |
| One canonical path audit (upload/download/share) | [x] done | Single upload/owner-download/share-ticket paths confirmed; Area 2 integrity UX open |
| CLI parity matrix and drift fixes | [x] audited | Matrix filled; crypto mostly matches; shared hint defect and frontend-only Blob defects recorded |
| Encrypt custom password hints | [ ] pending | **Area 1 — highest priority**; coordinate frontend, CLI, server, schema, E2E |
| Download integrity UX + Verify File tool | [ ] pending | **Area 2**; SW large-file path, expected-digest display, tips/popups, Blob bounds, new verify tool |
| Server-visible metadata documentation | [ ] pending | **Area 3 — docs only**; billable size is intentional; no wire/behavior change |
| Account key cache lifecycle | [ ] pending | Production session binding absent; teardown does not wipe wrapping key consistently |
| Share auth ticket-only cleanup | [ ] pending | Live UI is ticket-only in practice; dead generic/static-token paths and server fallback remain |
| Dead code and legacy API removal | [ ] pending | `downloadSharedFileChunked` confirmed dead; stubs and stale window globals listed |
| Admin contacts contract (frontend) | [ ] partial | Call sites use `configured`; any failed refresh keeps stale cache |
| Duplicate helper consolidation | [ ] pending | `formatBytes` / `formatFileSize` |
| Privacy-sensitive logging review | [ ] pending | Hot-path `console.log`; emoji in `account-key-cache.ts` integrity error |
| Hygiene and comment cleanup | [ ] pending | `===` dividers, WIP refs, "Legacy compatibility", "for now" |
| Error message consistency | [ ] pending | Prefer stable `data-testid` / error codes over brittle exact copy alone |
| `app.ts` decomposition | [ ] pending | After behavior stable; lower priority than privacy/integrity |
| Playwright hedging removal | [ ] pending | Phase 2/5 SKIP, Phase 11/12 OR hedges, billing top-up SKIP |
| Playwright coverage gaps | [ ] pending | register, export click, MFA, WebAuthn, revoke-all, SW large-file, etc. |
| Unit test gap fill | [ ] pending | Alongside each fix; hint contract, admin contacts, wrong-password |
| Production build hygiene | [ ] pending | Do not assume minify strips console; add explicit drop/gate |

---

## Top three implementation areas (agreed 2026-07-21)

These three areas take precedence over the rest of this plan. They reflect audit findings plus product decisions from the 2026-07-21 review.

### Area 1 — Encrypt custom password hints (shared frontend / CLI / server)

Both clients still send `password_hint` in plaintext; the server stores and returns it. This is the clearest cross-client privacy break and the first implementation tranche. Replace with Account-Key-encrypted `encrypted_password_hint` + nonce using metadata AAD bound to file ID and owner username; remove the plaintext contract atomically across browser, CLI, server, schema, and tests. See **Custom password hint privacy** below for the full target design and acceptance criteria.

### Area 2 — Download integrity UX, large-file streaming, and Verify File tool (frontend)

Large downloads must work on constrained devices (e.g. 3 GB RAM, 6 GB file) without holding the whole plaintext in page memory. The Service Worker streaming path is the canonical browser mechanism: decrypt and hash incrementally with chunk-bounded memory while the browser download manager writes to disk. The Blob fallback accumulates the full file before trigger and must be capped or refused above a documented safe bound; it is not the large-file path.

Integrity semantics must be honest about browser limits. Whole-file SHA-256 can be computed inline during SW streaming with bounded memory, but a mismatch is often detected only after bytes may already be saved by the OS download manager — the app cannot "un-download" without buffering the entire file first, which defeats streaming. Per-chunk AES-GCM still authenticates each chunk during decrypt. The UX model is: always show the expected SHA-256 at download completion (from decrypted metadata or share envelope); when inline verification ran, show match/mismatch alongside it; never show a clean success message when inline verification reports mismatch; on SW and other post-write paths, show tips explaining that users who need certainty should compare the expected digest using Verify File or an offline tool and delete the file if it differs.

Add a new **Verify this file** tool to the frontend, reachable at any time (not only immediately after download). The user picks a local file via the file picker; the app hashes it in chunks using the same streaming pattern as upload (`file.slice()` + incremental SHA-256, peak memory ~one chunk). The user supplies or pastes an expected hex digest (or the tool pre-fills it when launched from a download completion panel). Show match/mismatch without loading the whole file into JS heap. Works fully offline once the expected digest is known. Surface contextual hints, tips, and popups at appropriate moments — e.g. before or during a large SW download (explain streaming limits), and on the download completion panel (expected digest, optional inline result, link/button to Verify File).

Blob-path fixes remain for small files only: check `hashVerification` before `triggerBrowserDownloadFromUrl`, revoke the Blob URL on mismatch, and do not claim success. Document SW vs Blob vs CLI post-write verification limits in `sw-streaming-download.ts`, `streaming-download.ts`, `download.ts`, and `share-access.ts`.

### Area 3 — Document server-visible operational metadata (docs only; no behavior change)

The server knowing or computing pre-padded file size — encrypted declared length, inferable plaintext size from chunk count and fixed per-chunk overhead, `size_bytes`, and `padded_size` — is **intentional**. Arkfile must account for storage and bill users accurately; hiding exact size from the server would break billing, quotas, chunk download, padding removal, export, and replication. Padding obscures size from the storage backend and outside observers, not from the Arkfile server that receives the pre-padding length at upload init.

Do **not** change upload/download wire behavior for size. Instead, document accepted visibility consistently in `AGENTS.md`, `docs/security.md`, handler comments (e.g. `handlers/uploads.go`), and this plan. Classify server-visible fields as required operational data vs encrypted owner metadata (filename, content digest, password hint once fixed). Optionally document `password_type` and FEK envelope key-type visibility in the same pass; that is a separate disclosure from billable size and needs no protocol change unless product decides otherwise later.

---

## Audit summary

| Metric | Value |
|--------|-------|
| Source `.ts` files (excl. tests / `.d.ts`) | 47 |
| Source LOC | ~18,043 |
| Test files | 21 |
| Test LOC | ~5,443 |
| Runtime exports surveyed | ~271 (source scan; approximate) |
| Exports with zero external importers | Provisional count; individually listed candidates reverified |
| Largest modules | `upload.ts` (~1,288), `billing.ts` (~880), `totp.ts` (~871), `streaming-download.ts` (~807), `account-key-cache.ts` (~756), `app.ts` (~748) |
| Playwright phases | 1-13 + billing (3 tests) + contact-info (embedded in Phase 12) |
| `bun test` focus | Crypto, streaming download, upload batch helpers, auth cookie model; minimal UI/integration |

**Highest-impact findings (post-audit, prioritized)**

1. **Shared frontend/CLI privacy defect: custom password hints are plaintext end-to-end** — Both clients send `password_hint`; the server stores and returns it. Encrypt with Account Key in both clients and remove the plaintext contract. **Area 1.**
2. **Frontend download integrity UX is misleading** — Blob callers ignore `hashVerification`; SW path can show success before warning on mismatch. Large files must use SW streaming (chunk-bounded memory); users need expected digest at completion, honest inline results, contextual tips, and a standalone Verify File tool. **Area 2.**
3. **Frontend Blob fallback is unbounded and not a large-file path** — Full-file Blob retention before trigger; enforce safe bound and refuse above it; SW remains canonical for multi-GB downloads. **Area 2.**
4. **Server-visible file size is intentional operational metadata** — Pre-padded encrypted length and inferable plaintext size support billing and storage accounting. Document across codebase; do not change wire behavior. **Area 3.**
5. **Frontend account-key cache claims a production session binding that does not exist** — HttpOnly-cookie callers pass no token, so `token_hash` is empty and checks are skipped. Clearing session data removes ciphertext and makes the cache unusable, but does not consistently wipe the in-heap wrapping key. Rate Medium–High, not equivalent to the hint/Blob defects.
6. **Share auth cleanup is needed, but the live UI does not downgrade** — `applyShareAuthHeader` contains static-token fallback code, yet `share-access.ts` → `downloadSharedFileWithTicket` passes only `shareTicket`; ticket failure sends no auth header. Static-token support is reachable through the dead wrapper/generic manager and remains accepted by the server.
7. **Stale window globals and over-exposed globals** — `registrationData` and `totpLoginData` are never set; `window.arkfile` exposes whole modules though `shared-init.js` only needs `ShareAccessUI`; `window.arkfileApp` is also set with no repository reader.
8. **`fetchAdminContacts` returns stale state after any failed refresh** — Non-OK responses and exceptions preserve previous usernames/contact/configured values.
9. **Playwright hedges and coverage gaps** — Phase 2/5 idempotent SKIP; Phase 11/12 OR-hedges; billing top-up SKIP-pass; no browser E2E for registration, export click, MFA settings, WebAuthn, revoke-all, large-file SW, custom-password share recipient, admin-contact footer, or reregistration.
10. **Dead exports, hygiene, and logging remain** — Confirmed candidates are listed below. Production minification does not remove console calls; debug/info logs should be gated or dropped while security warnings/errors remain.

---

## Prioritized top-10 fix list (implementation order)

| # | Finding | Severity | Action |
|---|---------|----------|--------|
| 1 | Plaintext `password_hint` (frontend + CLI + server contract) | High | **Area 1:** Account-Key encryption; schema/API/both clients together; sentinel privacy E2E |
| 2 | Download integrity UX + Verify File tool (frontend) | High | **Area 2:** Expected digest at completion; inline result when available; tips/popups; standalone verify tool; honest success/mismatch messaging |
| 3 | Blob path + large-file policy (frontend) | High | **Area 2:** Enforce tested safe Blob bound; SW canonical for large files; Blob mismatch blocks trigger; document streaming limits |
| 4 | Server-visible size documentation (cross-stack docs) | Medium | **Area 3:** Document intentional billable size visibility in AGENTS.md, security.md, handlers; no wire change |
| 5 | Account key cache lifecycle (frontend) | Medium–High | Fix claims and teardown; decide whether server session epoch is warranted |
| 6 | Dead static share auth paths | Medium | Delete wrapper/fallback; server ticket-only coordination; actionable ticket errors |
| 7 | Stale globals + dead exports | Medium | Remove/unexport; narrow browser global surface |
| 8 | Admin contacts stale cache | Medium | Clear on every failed refresh; unit + fixture-aware Playwright assert |
| 9 | Playwright hedges / missing coverage | Medium | Stable error identity; deterministic fixtures; verify tool + large-file SW when fixture budget allows |
| 10 | Hygiene + production logging | Low | Remove dividers/WIP refs/emoji; gate debug/info while preserving warnings/errors |

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

Does the module send sensitive plaintext metadata to the network, server storage, or logs? **Yes for password hints** (plaintext end-to-end; Area 1 fix). Filenames and content SHA-256 are encrypted in owner metadata. Declared upload size and inferable plaintext size are intentionally server-visible for billing and storage accounting (Area 3 documentation). `password_type` and the FEK envelope key-type byte are also server-visible; document in the same pass if helpful. Hot-path logs use `password_type`, sizes, and timings; no plaintext password/FEK was found, but production gating is still required.

---

## One canonical path audit

### Upload — CONFIRMED single path

| Layer | File | Role |
|-------|------|------|
| UI entry | `upload.ts` `handleFileUpload()` | Sole UI entry from `app.ts` / `#upload-file-btn` |
| Core | `upload.ts` `uploadFiles()` / `uploadFile()` | Init/chunk/complete streaming |
| Dedup | `digest-cache.ts` | Client-side SHA-256 dedup before upload |

**Answers:** `handleFileUpload` is the only UI entry. Retry paths in `retry-handler.ts` are reachable via upload/download chunk helpers. Duplicate user string includes `Duplicate file detected` (Phase 4). Client-side digest cache is intentional divergence from CLI agent.

**Compare CLI:** MATCH on chunk size, AAD, FEK wrap, metadata encryption. BOTH send plaintext `password_hint`.

### Custom password hint privacy

#### Problem (verified)

`upload.ts` and CLI `commands.go` send plaintext `password_hint` in `/api/uploads/init`. Server persists in `upload_sessions.password_hint` and `file_metadata.password_hint` (`database/unified_schema.sql`) and returns it on `GET /api/files` and `GET /api/files/:fileId/meta`. Browser shows the hint in custom-password prompts (`download.ts`, `share.ts`). CLI does not display the hint on download. Share envelopes (`ShareEnvelope`) and `.arkbackup` `bundleMetadata` do **not** include hints. Older review docs called this "plaintext by design"; this plan treats it as a privacy break. E2E custom-password uploads typically omit `--hint`; Phase 7 does not assert hint absence.

#### Target design

Replace plaintext `password_hint` with `encrypted_password_hint` and `password_hint_nonce`, encrypted with the Account Key. Add a new permanent metadata AAD field label `AAD_FIELD_PASSWORD_HINT = 'encrypted_password_hint'` alongside `AAD_FIELD_FILENAME` and `AAD_FIELD_SHA256`, using the existing `buildMetadataFieldAAD(fileID, fieldName, ownerUsername)` encoding. Existing metadata AAD is not separately versioned; future incompatible formats should use a new permanent field label rather than silently reusing one. Empty hints must have one cross-client canonical representation (omit both fields, or encrypt an empty string; do not accept ambiguous ciphertext/nonce combinations). The server treats encrypted hint fields as opaque.

Encryption must occur inside the upload `file_id` conflict retry loop. Each candidate file ID requires fresh hint ciphertext and nonce because the file ID is bound into AAD. Upload uses the authenticated canonical username; decryption uses `owner_username` returned with the metadata row, matching filename/SHA-256 handling.

Because Arkfile is greenfield, remove the plaintext field and compatibility fallback rather than retaining dual plaintext/encrypted decoding. Coordinate these changes atomically:

| Layer | Required change |
|-------|-----------------|
| Browser upload/download/share | Re-encrypt per candidate file ID; decrypt only for custom-password owner prompts; never place plaintext hints in request bodies or logs |
| CLI upload/download/share | Use the same encrypted field format, nonce rules, AAD, and empty representation as the browser; add hint display only if desired |
| Server handlers/models/schema | Replace plaintext storage/API fields with opaque ciphertext+nonce; obsolete plaintext input must never persist (reject explicitly if strict API behavior is adopted) |
| Share envelope | No change: anonymous recipients use the share password and must never receive the owner's custom-file hint |
| Export/backup | Optional follow-up: today `.arkbackup` omits hints; if offline UX needs them, update `handlers/export.go` and CLI `offline_decrypt.go` together |
| Tests | Cross-client vectors, raw API/DB assertions, wrong-key/tamper failures, empty-hint behavior, sentinel privacy |

#### Acceptance criteria

- Browser and CLI produce and consume the same encrypted hint format and AAD.
- Raw upload, list, metadata, share, and export API responses contain no plaintext hint.
- Database upload-session and file-metadata records contain no plaintext hint column or value.
- The obsolete plaintext field is absent from the supported contract and cannot be persisted or returned; if sent, behavior is explicitly tested (reject or safely ignore).
- For `password_type === 'custom'` only, owner download and share-creation decrypt and display the hint after the Account Key is available and before the custom-password prompt. Account-password files never show a hint.
- Hint ciphertext or AAD tampering fails closed and does not display corrupted text.
- Tests use a unique sentinel hint and prove that it does not appear in network payloads, server responses, database contents, server logs, or production browser logs.

### Server-visible operational metadata (Area 3 — document only; no behavior change)

#### Current behavior (verified; intentional)

Both clients send `total_size` as the exact encrypted-data length before the server adds padding. The server computes `total_chunks` from that value using the known `chunk_size + 28` encrypted chunk size, then stores the unpadded length as `file_metadata.size_bytes` and padded totals for storage objects. For a non-empty file, plaintext size is directly recoverable as `total_size - (28 * total_chunks)`. This is **required operational metadata**: the server must account for storage consumption and bill users accurately. Server-generated padding obscures size from the storage backend or an outside observer of S3 objects, but not from the Arkfile server that received the pre-padding length at upload init.

Both clients also send plaintext `password_type`, and the FEK envelope includes a visible key-type header byte. These reveal account-vs-custom compartmentalization to the server. They are separate from billable size; document alongside size visibility if product wants one consolidated "server-visible metadata" section in `docs/security.md`.

#### Target (documentation only)

Do not change upload init, chunk download, padding, billing, or quota wire behavior for size. Update documentation and code comments so developers and security reviewers understand the split:

| Category | Examples | Server visibility |
|----------|----------|-------------------|
| Encrypted owner metadata | filename, content SHA-256, password hint (once Area 1 lands) | Opaque ciphertext + nonce only |
| Intentional operational metadata | `total_size`, `size_bytes`, `padded_size`, chunk count, billable bytes | Known or computable by server; required for billing/accounting |
| Protocol routing fields | `password_type`, FEK envelope key-type byte | Visible; documents compartmentalization choice |

#### Files to update

| Location | Change |
|----------|--------|
| `AGENTS.md` | Nuance "server must know nothing about the nature of the data" — no passwords, no plaintext filenames, no file contents; billable storage size is known by design |
| `docs/security.md` | New or expanded section: server-visible operational metadata vs encrypted owner metadata |
| `handlers/uploads.go` (and related) | Align comments with billing/accounting intent (partially present today) |
| This plan | Record decision (done in Area 3 above) |

#### Acceptance criteria

- Security documentation states exactly which metadata the server observes, stores, or infers, and why (especially billable size).
- No code or schema change alters size declaration, padding, or billing math solely for privacy of size from the server.
- Frontend and CLI upload/download behavior unchanged; cross-client size vectors still pass existing E2E.
- Optional: same documentation pass covers `password_type` / FEK key-type visibility without implying a pending protocol fix.

### Owner download — CONFIRMED single path; integrity UX OPEN (Area 2)

| Layer | File | Role |
|-------|------|------|
| Orchestration | `download.ts` `downloadFile()` | Sole list-item path from `list.ts` |
| Streaming | `streaming-download.ts` `downloadFileChunked` → manager | Chunk fetch, AES-GCM decrypt, SW vs Blob |
| SW integration | `sw-streaming-download.ts`, `sw-download.ts` | Canonical large-file path |
| Verify File (new) | TBD module + UI entry | Anytime local file vs expected digest; chunk-bounded hashing |

**Answers:** Single owner download API. SW path streams with roughly chunk-bounded page-side memory and can compute whole-file SHA-256 inline during the stream, but a mismatch may be detected only after the OS download manager has already saved bytes — document this limit and surface expected digest + tips at completion. Blob fallback builds `new Blob([blob, chunk])` for the entire file with no size bound today; cap or refuse above safe limit. `download.ts` warns on SW mismatch but still calls `showSuccess` first; Blob path triggers download and success without checking `hashVerification`. Add completion UI: expected SHA-256 (copyable), inline verification result when available, link to Verify File tool. No Playwright coverage of large-file SW path (fixtures are 50–100 KB).

### Share (owner + recipient) — CONFIRMED; delete dead wrapper

| Flow | Files | Verdict |
|------|-------|---------|
| Create | `files/share.ts` → `ShareCreator` → `share-crypto.ts` | Sole create path |
| List/revoke | `share-list.ts` | Live; Playwright Phase 9/12 |
| Anonymous access | `share-access.ts` → `share-ticket.ts` → `downloadSharedFileWithTicket` | Sole live export |

**Answers:** Anonymous download always goes through `downloadSharedFileWithTicket`. **Delete `downloadSharedFileChunked`.** The live wrapper passes only `shareTicket`, so ticket-provider failure does not actually downgrade to a static token; it produces a request without an auth header and fails. `share-access.ts` needs the same Area 2 integrity UX as owner `download.ts` (expected digest from share envelope at completion, inline result, tips, Verify File launch). Generic manager/static-token support and server acceptance remain cleanup debt.

---

## Download integrity UX, Verify File tool, and Blob bounds (Area 2)

### Problem (verified)

When Service Worker streaming is unavailable or transfer fails, `streamDecryptedChunks` retains the complete plaintext in a Blob regardless of size. This is full-file buffering in browser-managed Blob storage, not a large-file path. Blob completion returns `hashVerification`, yet both `download.ts` and `share-access.ts` trigger the Blob download and report success without checking it.

The Service Worker path streams with chunk-bounded memory and can hash plaintext incrementally during the stream (same memory profile as upload-side `computeStreamingSHA256`). However, the whole-file digest is often known only after bytes have been handed to the browser download manager. Preventing a bad file from landing on disk would require buffering the entire plaintext first, which defeats streaming and the 6 GB / 3 GB RAM requirement. Per-chunk AES-GCM authentication still fails during the stream on chunk tampering; whole-file SHA-256 is an additional consistency check whose result may arrive post-write. The CLI has the same timing on disk: it verifies after `computeStreamingSHA256` on the output path and returns an error on mismatch, but the file may already exist.

Current UI is misleading: SW path can show success then warn; Blob path ignores mismatch entirely. Users are not shown the expected digest prominently or guided to offline verification when inline blocking is impossible.

### Target design

#### Streaming download policy

| Path | Large files | Memory | Inline whole-file SHA-256 | On mismatch |
|------|-------------|--------|---------------------------|-------------|
| SW (canonical) | Yes | Chunk-bounded | Computed during stream | Do not claim clean success; show expected + computed digests; tip to delete file and use Verify File |
| Blob (fallback) | No above safe bound | Full file in Blob store before trigger | Computed before trigger | Revoke Blob URL; do not trigger download; show failure |
| CLI | Yes | Chunk-bounded decrypt-to-disk | After write via streaming hash | Error after write; file may remain (document parity) |

Enforce a tested safe maximum for Blob fallback; refuse with clear message directing users to a browser/environment that supports SW streaming (proven multi-GB on `test.arkfile.net`). Harden SW registration and fallback rules: only fall back before generator consumption when possible.

#### Download completion UX (owner + share)

At download finalization, always display the expected SHA-256 hex (owner: decrypted metadata; share: envelope). Copy-to-clipboard. When inline verification ran, show match or mismatch beside it. Never show an unqualified success message when inline verification is `mismatch`. Contextual hints and popups:

- **Before / during large SW download:** brief note that the file streams to the download folder with chunk-bounded memory; whole-file digest is checked as data flows but a problem may be detected only after the file is saved.
- **After SW completion with match:** success plus expected digest for the user's records.
- **After SW completion with mismatch:** integrity failure panel — expected digest, computed digest if available, instruction to delete the downloaded file, button to open Verify File with expected digest pre-filled.
- **After Blob completion (small files):** success only if inline verification passed or was skipped with explicit reason.

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
- Blob fallback refuses files above documented safe bound with actionable message.
- Owner and share Blob callers check `hashVerification` before trigger; mismatch revokes URL and does not claim success.
- SW mismatch never shows unqualified success; completion UI shows expected digest and guidance.
- Verify File tool available anytime; hashes large local files without loading entire file into JS heap.
- Contextual tips/popups appear on large SW downloads and at completion as specified.
- Unit tests: Blob mismatch blocking, completion messaging, verify tool streaming hash; Playwright: verify tool smoke + large-file SW when fixture budget allows.

---

## Account key cache lifecycle

### Problem (verified; Medium–High)

`account-key-cache.ts` documents JWT session binding via `token_hash`, but all production cookie-auth reads/writes omit an access token, so the stored hash is empty and the binding check is skipped. Ephemeral wrapping key in JS heap remains the real protection. `clearAllSessionData()` removes sessionStorage ciphertext, making the cached Account Key unusable, but it does not consistently wipe the wrapping key; logout has additional cleanup while revoke-all/session-expiry paths do not. This is a misleading threat-model and teardown problem, not evidence that revoked users can currently decrypt absent ciphertext.

### Target

- First unify teardown so logout, revoke-all, session expiry, inactivity, and explicit lock clear ciphertext and wipe the wrapping key.
- Explicit decision: add a server-provided session epoch/version to `/api/auth/me` and bind the cache to it, or accept heap-only wrapping with accurate documentation. The epoch approach requires coordinated server/session work.
- Document per-tab semantics correctly: module state and `sessionStorage` are tab-scoped (a newly opened tab may receive an initial copy depending on browser/opener behavior, but updates are not shared).
- Tests: logout, re-login as another user, session revoke, inactivity lock, page reload, and multi-tab.
- Remove emoji from integrity failure log (`AGENTS.md` no-emoji).

---

## Share auth ticket-only alignment

### Problem

`applyShareAuthHeader` contains a static `X-Download-Token` fallback when a manager has `downloadToken`. The live anonymous path (`share-access.ts` → `downloadSharedFileWithTicket`) supplies only `shareTicket`, so ticket-provider failure sends no static token and fails in practice, matching the CLI's ticket-only security posture. The fallback remains reachable through the dead `downloadSharedFileChunked` wrapper or any generic-manager caller that supplies a token; the server still accepts both credentials. The current warning is also false on the live path because it claims fallback even when no token exists.

### Target design

When server ticket-only pass lands:

| File | Change |
|------|--------|
| `streaming-download.ts` | Delete dead static-token wrapper/support; propagate ticket-provider failure before issuing an unauthenticated request |
| `share-access.ts` | Envelope decrypt → ticket request → download is the only path |
| `share-ticket.ts` | Preserve already-verified CLI parity for refresh lead/minimum timing |

Until server changes: delete dead `downloadSharedFileChunked`; remove or accurately constrain manager fallback; align comments. The server-side static credential branch still needs coordinated removal, but the live frontend is not currently performing a silent downgrade.

### Tests

Extend `streaming-download.test.ts`: ticket-provider failure must stop before fetch or produce an actionable error and must never send `X-Download-Token`. Playwright Phase 10 already exercises anonymous ticket download.

---

## Dead code and legacy API removal

### Confirmed dead (delete)

| Item | Location | Evidence | Action |
|------|----------|----------|--------|
| `downloadSharedFileChunked` | `streaming-download.ts` | Zero callers | Delete |
| `showTOTPSetupModal` | `totp.ts` | Never called; live path is `generateAndDisplayTOTPSetup` | Delete |
| `getTOTPStatus` | `totp.ts` | Never called | Delete |
| `hideTOTPSetupSection` / `hidePendingApprovalSection` | `sections.ts` | Never called | Delete |
| `handleBillingCheckoutReturn` / `handleSubscriptionCheckoutReturn` | `billing.ts` | Unused aliases | Delete |
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
| `revokeAllSessions` | `auth.ts` + `#revoke-sessions-btn` | Live UI; add Playwright |
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

If Playwright + `bun test` + grep show no importers, delete. If E2E does not cover but product requires it (registration, WebAuthn), keep and add E2E rather than delete.

---

## CLI parity matrix (audited 2026-07-20)

AGENTS.md requires mirrored critical protocol behavior. Status after audit:

| Operation | CLI reference | Frontend reference | Status | Notes |
|-----------|---------------|-------------------|--------|-------|
| Argon2id params / salts | `crypto/key_derivation.go` | `constants.ts`, `floors.ts`, `file-encryption.ts` | MATCH wire values; LOW loading drift | FE fetches API + applies compiled floors; Go embeds JSON. FE lowercases defensively; valid/CLI usernames are already normalized lowercase |
| Chunk encrypt/upload | `commands.go` upload | `upload.ts` | MATCH | Same chunk size, AAD, FEK wrap |
| Custom password hint | upload init + meta | `upload.ts`, `download.ts`, `list.ts`, `share.ts` | SHARED DEFECT | Both clients send plaintext; FE displays hint, CLI does not |
| Declared size / key type | upload init + FEK envelope | `upload.ts` | DOCUMENTED INTENTIONAL | Server-visible for billing/accounting and routing; Area 3 docs only |
| Chunk download/decrypt | `commands.go` download | `download.ts` + `streaming-download.ts` | MATCH crypto; FE UX GAP | Metadata always Account Key; FE needs Area 2 completion UX + Verify File. CLI verifies after write via streaming hash |
| Share create | `CreateShareEnvelope` | `share-crypto.ts` | MATCH | Same JSON + AAD + token hash |
| Share recipient download | ticket-only | `share-access.ts`, `share-ticket.ts` | LIVE PATH MATCH | FE live UI is ticket-only; dead generic/static-token support remains cleanup |
| Export backup | `export.go` | `export.ts` | MATCH artifact | Intentional auth difference (Bearer vs short-lived token) |
| Billing display | `billing_commands.go` | `billing.ts` | MOSTLY MATCH | FE omits some fields (`rate_human`, approx runway) |
| Contact info | `handleContactInfo*` | `contact-info.ts` | MATCH | FE adds pending-approval UI |
| Digest dedup | agent digests | `digest-cache.ts` | INTENTIONAL | No agent in browser |
| Password validation | Go + JSON | `password-validation.ts` | MATCH | account / custom / share |
| Revoke all sessions | `revoke-all` | `auth.ts` + `#revoke-sessions-btn` | MATCH API+UI | Playwright gap |

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

Playwright: fetch `/api/admin-contacts` via `page.evaluate` and assert the footer matches the returned contract. Do not assume dev-reset supplies a contact string: it may configure an admin username while `admin_contact` remains empty, in which case the footer correctly shows `not configured`. Assert no fake fallback such as `admin@example.com`.

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

Playwright Phase 6 asserts `check your password` via `includes`. Phase 4 duplicate upload uses one string. Share errors (Phase 11/12) accept many alternatives.

### Target

| UX event | Canonical identity | Consumers |
|----------|-------------------|-----------|
| Wrong custom password decrypt | Stable error code or `data-testid` + unit-tested copy | `download.ts`, Playwright |
| Duplicate upload | Single string already present | Phase 4 |
| Share expired / max downloads / revoked / not found | One `data-testid` (or code) each | Phase 11/12, `shared.html` |

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

Template: CLI admin decomposition in `docs/wip/archive/cli-cleanup.md`. Defer until Areas 1–3 and related integrity UX land.

---

## Playwright hedging removal

| Location | Current hedge (verified) | Target |
|----------|--------------------------|--------|
| Phase 2/5 upload | SKIP if file already in list (pass without upload) | Fail unexpected state; prefer deterministic post-dev-reset |
| Phase 6 wrong password | `includes('check your password')` | Stable identity from frontend |
| Phase 11a expiry | `expired` \| `forbidden` \| `error` \| `403` | One `data-testid` or string; avoid 65s wall clock via pre-expired fixture |
| Phase 11b max downloads | 7 OR alternatives | One identity |
| Phase 11c non-existent | 4 OR alternatives | One identity |
| Phase 12 revoked share | 5 OR alternatives; revoke UI OR-hedge | One identity |
| Billing top-up | `[SKIP]` if button missing → pass | Explicit precondition; fail if billing enabled in dev-reset |
| Phase 13 | Legacy localStorage checks comment | Assert only cookie/sessionStorage contract |
| Phase 7 | No `password_hint` check | Add sentinel after encryption |

---

## Playwright coverage gaps

| Gap | Status | Recommendation |
|-----|--------|----------------|
| Registration + pending approval UI | Untested | Add Playwright phase |
| Export backup download | Phase 4b only checks dialog text "Export Backup" | Click export; verify download |
| MFA settings / WebAuthn setup | Untested | Add or document manual-only for WebAuthn |
| Subscription checkout/portal | Partial (top-up mocked) | Add after billing top-up stable |
| `revoke-all` | UI exists (`#revoke-sessions-btn`); untested | Add phase |
| Admin contacts footer | Untested (user contact-info is covered) | Assert footer + API |
| Large file SW download | 50–100 KB only | Dedicated fixture + timeout; completion digest UI |
| Verify File tool | Untested | Add unit tests + Playwright smoke |
| Custom-password share recipient | Shares only from account-password file | Add share of custom-password file |
| Reregistration | Untested | Align with CLI reregistration E2E |

---

## Unit test gap fill

### Current coverage (good)

Crypto primitives, AAD, Argon2 conformance, file encryption, share-crypto, streaming-download manager (mocked fetch), upload batch helpers, digest-cache, account-key-cache, export format, SW handler.

### Priority additions

| Target | Rationale |
|--------|-----------|
| Encrypted password hint contract | Cross-client vectors, tamper rejection, empty hint, no plaintext fields |
| Verify File tool + shared streaming hasher | Chunk-bounded hash of user-picked file; match/mismatch; extract from upload.ts |
| Download completion UX + Blob/SW integrity | Expected digest display, tips, Blob mismatch blocking, SW honest messaging |
| Account key cache lifecycle | Logout / binding / inactivity |
| `fetchAdminContacts` failed refresh clears state | Stale cache bug |
| `getUserFriendlyMessage` / wrong-password path | Stabilizes Playwright |
| `billing.ts` render helpers | Pure formatting |
| Production log stripping flag | If debug gate added |

Keep full upload/share integration in Playwright unless flakiness forces slimmer unit tests with mocked `fetch`.

---

## Production build hygiene

| Item | Action |
|------|--------|
| `build:prod` | Do not assume `--minify` strips console; explicitly gate/drop debug and info while retaining security warnings/errors; inspect artifact |
| `app.js.map` | Already external; operational decision from supply-chain review |
| `libopaque.js` | Pin/rebuild process out of scope unless hash mismatch found |

---

## Suggested implementation order

Work silent correctness and privacy before cosmetic cleanup:

1. **Encrypt custom password hints (Area 1)** — remove the plaintext frontend/CLI/server/schema contract; re-encrypt per file-ID attempt; add cross-client and sentinel privacy proof.
2. **Download integrity UX + Verify File tool (Area 2)** — expected digest at completion; inline result when available; tips/popups for SW post-write limits; standalone verify tool; Blob mismatch blocking; Blob size bound; SW canonical for large files.
3. **Document server-visible operational metadata (Area 3)** — AGENTS.md, security.md, handler comments; billable size intentional; no wire change.
4. **Account key cache lifecycle** — unify key teardown, correct security claims, decide whether a server session epoch is warranted.
5. **Delete confirmed dead exports and static share paths** — `downloadSharedFileChunked`, token stubs, stale globals; coordinate server removal of static credential acceptance.
6. **Admin contacts failed-refresh clear + fixture-aware Playwright footer** — small, high confidence.
7. **Error identity standardization** — unlock Playwright tightening without brittle copy-only asserts.
8. **Privacy logging gate** — preserve security warnings/errors; verify `build:prod` artifact.
9. **Playwright hedging removal and gap fill** — deterministic fixtures; verify tool, revoke-all, export click, registration, subscription, large-file SW.
10. **Duplicate formatters** — low-risk consolidation.
11. **`app.ts` decomposition** — mechanical, after behavior stable.
12. **Hygiene pass** — dividers, WIP refs, legacy comments.
13. **Unit tests** — alongside each fix (not a final batch).

---

## Verification checklist (final)

- [ ] `sudo bash scripts/dev-reset.sh`
- [ ] `bash scripts/testing/e2e-test.sh` — all PASS
- [ ] `sudo bash scripts/testing/e2e-playwright.sh` — all PASS, zero undocumented SKIP
- [ ] `cd client/static/js && bun test` — all PASS
- [ ] `cd client/static/js && bun run lint` — type-check clean
- [ ] Manual: 6 GB file upload/download on constrained tab (SW path; Blob refused above bound)
- [ ] Manual: shared file anonymous download with ticket refresh after forced 403
- [ ] Manual: Verify File tool hashes a multi-GB local file without excessive memory; match/mismatch against known digest
- [ ] Manual: large SW download shows streaming-limit tip; completion panel shows expected SHA-256 and Verify File entry point
- [ ] Manual: billing panel shows transactions + runway matching CLI `billing show --json` fields
- [ ] Browser and CLI encrypted password-hint conformance vectors pass; custom hint remains usable in owner download and share creation
- [ ] Raw API, database, server-log, and production-browser-log checks prove a unique plaintext hint sentinel appears nowhere outside client plaintext memory/UI
- [ ] Obsolete plaintext `password_hint` cannot persist or return; schema and models contain no plaintext hint storage path
- [ ] Owner and share Blob mismatches do not trigger browser download and revoke the Blob URL
- [ ] SW mismatch never shows unqualified success; completion UI shows expected digest, inline result when available, and Verify File guidance
- [ ] `AGENTS.md` and `docs/security.md` document intentional server-visible billable size; no doc claims size is hidden from the server
- [ ] Account key ciphertext and wrapping key are cleared after logout / revoke-all / inactivity as designed
- [ ] Grep `client/static/js/src` for `default-admin`, `admin@example.com`, `docs/wip/`, decorative `===`/`---` in comments, `for now`, `backward compatibility`, emoji — zero inappropriate hits
- [ ] Grep frontend for `console.log` of filename, sha256, password, password hint, fek — zero in production path or gated
- [ ] Production bundle inspection confirms debug/info logs stripped or gated while security warnings/errors remain

---

## E2E-confirmed hot paths (do not delete without replacement)

| Area | Frontend modules / DOM |
|------|------------------------|
| Auth | `login.ts`, `totp.ts`, `password-modal.ts` cache opt-in; `#login-btn`, `#verify-totp-login` |
| Upload | `upload.ts`, `app.ts` file input; account + custom password |
| Download | `download.ts`, `list.ts` Download action; completion digest UI; Verify File entry (Area 2) |
| Delete | `list.ts` delete + export backup button **text** presence (not click) |
| Shares | `share.ts`, `share-list.ts`, `share-access.ts`; create A/B/C, list, revoke |
| Anonymous share | `shared.html` + `share-access.ts`; Phase 10-11; Area 2 completion digest + optional Verify File on share page |
| Contact info | `contact-info.ts`; Phase 12 embedded tests |
| Billing | `billing.ts`; balance, usage grid, transactions, top-up modal (may SKIP) |
| Logout | `login.ts` logout; Phase 13 sessionStorage/CSRF checks |
| API privacy | Phase 7 checks encrypted filename/hash only; it does not assert hint absence (Area 1) or re-check intentional server-visible size/key type (Area 3) |

---

## Not exercised by Playwright (keep, delete, or add coverage)

| Area | Modules | Recommendation |
|------|---------|----------------|
| Registration | `register.ts`, `mfa-setup.ts` | Add Playwright phase |
| WebAuthn | `webauthn.ts`, `clictap` integration | Add or document manual-only |
| MFA settings | `mfa-settings.ts`, `mfa-method.ts` | Add coverage |
| Export download | `export.ts` | Add phase; Phase 4b only checks dialog text |
| Subscription portal | `billing.ts` subscribe/portal handlers | Add after billing top-up stable |
| Revoke all | `auth.ts` + `#revoke-sessions-btn` | **UI exists** — add Playwright (do not delete) |
| Pending approval | `sections.ts` `showPendingApprovalSection` | Add with registration phase |
| SW large download | `sw-streaming-download.ts` | Dedicated test with large fixture |
| Reregistration | `login.ts` re-register path | Align with CLI reregistration E2E |
| `downloadSharedFileChunked` | `streaming-download.ts` | **Confirmed dead — delete** |
| Admin contacts footer | `footer.ts` | Add assert (distinct from user contact-info) |
| Custom-password share recipient | share of custom-password file | Add coverage |

---

## Out of scope (this document)

Vendored `libopaque.js` rebuild pipeline (see supply-chain review). Caddy/CSP/systemd changes. Server and CLI changes unrelated to required privacy-contract remediation; encrypted password-hint API/schema/model/CLI changes are explicitly in scope. Full rewrite of `06-frontend-supply-ops.md` findings. Windows or non-browser clients.

---

## Relationship to server and CLI cleanup

| Prior cleanup item | Frontend follow-up |
|--------------------|-------------------|
| Admin contacts honest API | Clear stale cache on every failed refresh; verify footer/list/sections; fixture-aware Playwright assert |
| Plaintext custom password hint | Replace with Account-Key-encrypted metadata across browser, CLI, server, schema, export, and E2E (Area 1) |
| Server-visible billable size | Document intentional operational visibility; no wire change (Area 3) |
| Download integrity + Verify File | Expected digest UX, tips/popups, standalone verify tool, Blob bounds (Area 2) |
| Share ticket-only (deferred) | Live UI already fails ticket-only; remove dead static-token wrapper/generic support and server fallback |
| E2E hedging removal pattern | Apply to `e2e-playwright.ts` Phase 2/5/11/12 and billing SKIP |
| CLI billing human parity | Match remaining display fields (`rate_human`, approx runway) if product wants parity |
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
| `downloadFile` | `download.ts` | Y | Keep — sole owner download entry; Area 2 completion UX |
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
| `exportBackup` | `export.ts` | N (dialog text only) | Keep; add E2E |
| `revokeAllSessions` | `auth.ts` | N | Keep; UI wired; add E2E |
| `fetchAdminContacts` | `auth.ts` | N | Clear state after any failed refresh; add E2E |
| `showProgressMessage` | `progress.ts` | Y (auth) | Keep; fix comment |
| `register` / `setupRegisterForm` | `register.ts` | N | Keep; add E2E |
| WebAuthn / MFA settings helpers | `webauthn.ts`, `mfa-*.ts` | N | Keep; add E2E or document manual |
| `swStreamDownload` / SW handler | `sw-streaming-download.ts`, `sw-download.ts` | P (unit only) | Keep; add large-file E2E |
| Account key cache API | `account-key-cache.ts` | P (login opt-in) | Fix lifecycle; expand tests |
| `toggleBillingPanel` / checkout resume | `billing.ts` | P | Keep; tighten SKIP |

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

### Playwright phase map (summary)

| Phase | Exercises | Hedge? |
|-------|-----------|--------|
| 1 Login | OPAQUE + TOTP + cache opt-in | No |
| 2 Account upload | `upload.ts` | SKIP if file exists |
| 3 Download + SHA-256 | `download.ts` | No |
| 4 Duplicate | upload duplicate string | No |
| 4b Delete | delete dialog; Export Backup **text only** | No export click |
| 5 Custom upload | custom password | SKIP if file exists |
| 6 Custom download | correct + wrong password | Mild `includes` |
| 7 Raw API privacy | filename/hash encrypted | **No hint check** |
| 8–9 Share create/list | share UI | Soft overlay catch |
| 10 Anonymous Share A | ticket download | Soft toast catch |
| 11 Share controls | expiry / max / missing | **OR hedges**; 65s wait |
| 12 Revoke + contact-info | revoke + user contact CRUD | OR hedges on revoke/deny |
| Billing x3 | panel, top-up, return | Top-up **SKIP-pass** |
| 13 Logout | cookies/sessionStorage | Soft re-login skip |

---

## Audit session record

Completed 2026-07-20 (read-only; documentation update only):

1. Reachability inventory of runtime exports and entry points.
2. End-to-end read of upload/download/streaming-download/share-access against Function Review Sanity Checks.
3. Playwright phase map and hedging inventory.
4. Full `password_hint` trace across browser, CLI, handlers, schema, export, shares, tests, and docs.
5. CLI parity matrix for upload, download, share, export, billing, contact, digest, revoke-all, hints, size, and key type.
6. Hygiene and privacy greps (`===` dividers, WIP refs, console/sensitive patterns, emoji).
7. Independent correction pass for live share-ticket reachability, Blob/SW integrity semantics, cache teardown, AAD design, and selected inventory accuracy.
8. Priority refinement (2026-07-21): three implementation areas — encrypted hints, download integrity UX + Verify File tool, server-visible size documentation only.

Deliverables: this filled inventory, prioritized top-10 fix list, top-three areas section, and updated progress tracker. Application code was not modified in this pass.
