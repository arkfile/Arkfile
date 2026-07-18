# Frontend Cleanup & Cohesion Plan

This plan applies the same audit methodology as `docs/wip/archive/server-cleanup.md` and `docs/wip/archive/cli-cleanup.md` to the TypeScript browser client under `client/static/js/src/`. Every exported function, class method, and UI flow handler is reviewed against the Function Review Sanity Checks in `AGENTS.md`: required, correctly implemented, well placed, reachable, privacy-preserving, and free of stubs, deprecated paths, duplicated logic, and leftover placeholder code. Arkfile is greenfield; delete unused or misleading frontend paths rather than maintain compatibility shims. The audit is cross-checked against `scripts/testing/e2e-playwright.sh` (primary frontend proof), `scripts/testing/e2e-test.sh` (CLI/API baseline the browser should mirror), and `bun test` in `client/static/js/`. Where Playwright hedges (`includes(...)` with many alternatives, idempotent SKIP, pass-without-assertion), tighten tests and fix frontend behavior so there is one canonical expected result. Cross-client parity with `arkfile-client` is explicit: AGENTS.md requires one way to encrypt/upload, download/decrypt, and share per client type, with matching structure where practical.

Status: planning (audit document)
Created: 2026-07-18
Scope: `client/static/js/src/**` (~50 source modules, ~18,400 LOC), `client/static/js/sw-download.js` (built from `sw-download.ts`), HTML entrypoints that load the bundle (`index.html`, `shared.html`). Server, schema, and CLI changes are in scope when required to remove a privacy-breaking contract, including the plaintext `password_hint` field. Other server or CLI changes remain out of scope unless a contract fix requires a matching E2E assertion. Prior security review findings in `docs/wip/archive/review/06-frontend-supply-ops.md` (CSP, innerHTML, supply chain) are referenced but not re-litigated here unless they intersect with dead code or misleading behavior.

## Principles

One canonical way per browser operation (upload, owner download, share create/list/revoke, anonymous share download, export backup, billing panel load). Fail closed: no fake admin contacts, no silent decode-success on malformed API responses, no plaintext file metadata or password-derived information sent to the server, and no console logging of sensitive metadata in production bundles unless gated. Custom password hints are file metadata and must be encrypted client-side with the Account Key; the server must never receive or store them in plaintext. Delete dead exports and legacy no-op APIs rather than keep them for compatibility. Shared pure helpers belong in one module (`utils/format.ts` or similar), not four copies of `formatBytes`. CLI and frontend critical crypto flows should mirror naming and logic (compare against `cmd/arkfile-client/commands.go`, `cli/*`, and Go crypto packages). After each workstream: `sudo bash scripts/dev-reset.sh`, `bash scripts/testing/e2e-test.sh`, `sudo bash scripts/testing/e2e-playwright.sh`, and `cd client/static/js && bun test`.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Audit inventory and reachability map | [ ] pending | grep + import graph + Playwright phase map |
| One canonical path audit (upload/download/share) | [ ] pending | `upload.ts`, `download.ts`, `streaming-download.ts`, `share-*.ts` |
| Encrypt custom password hints | [ ] pending | remove plaintext API/database field; coordinate frontend, CLI, server, schema, and E2E |
| Share auth ticket-only alignment | [ ] pending | coordinate with deferred server ticket-only pass |
| Dead code and legacy API removal | [ ] pending | unused exports, no-op token helpers, duplicate wrappers |
| CLI parity matrix and drift fixes | [ ] pending | crypto, billing, share, export, contact-info |
| Admin contacts contract (frontend) | [ ] partial | server cleanup landed; verify all UI call sites |
| Duplicate helper consolidation | [ ] pending | `formatBytes` / `formatFileSize` |
| Privacy-sensitive logging review | [ ] pending | `console.log` in download/upload/streaming paths |
| Hygiene and comment cleanup | [ ] pending | `===`/`---` dividers, legacy compatibility comments, WIP refs |
| Error message consistency | [ ] pending | password errors, duplicate upload, share failures |
| `app.ts` decomposition | [ ] pending | event wiring vs domain modules |
| Playwright hedging removal | [ ] pending | Phase 6b, 11, billing SKIP, idempotent skips |
| Playwright coverage gaps | [ ] pending | register, export, MFA manage, subscription, large-file SW |
| Unit test gap fill | [ ] pending | auth UI, billing, share-access, contact-info |
| Production build hygiene | [ ] pending | strip or gate debug logs in `build:prod` |

---

## Audit summary

| Metric | Value |
|--------|-------|
| Source `.ts` files (excl. tests) | ~50 |
| Source LOC | ~18,400 |
| Test files | 21 |
| Test LOC | ~5,500 |
| Largest modules | `upload.ts` (~1,288), `billing.ts` (~880), `totp.ts` (~871), `streaming-download.ts` (~807), `account-key-cache.ts` (~756), `app.ts` (~748) |
| Playwright phases | 1-13 + billing (3 tests) + contact-info (embedded in Phase 12) |
| `bun test` focus | Crypto, streaming download, upload batch helpers, auth cookie model; minimal UI/integration |

**Highest-impact findings (initial grep/read pass)**

1. **Custom password hints are sent to and stored by the server in plaintext** — `upload.ts` sends `password_hint` in `/api/uploads/init`; the server persists and returns it. Hints can reveal sensitive context or partial password material. Encrypt hints client-side with the Account Key, migrate the frontend/CLI/server/schema contract together, and prove through raw API/database assertions that plaintext hints never leave the client.
2. **`upload.ts` is 7% of the frontend** — batch queue, retry, quota, and UI handler coexist; prime candidate for decomposition after correctness audit, similar to admin `main.go` split in CLI cleanup.
3. **Four independent byte formatters** — `formatBytes` in `billing.ts`, `share-access.ts`, `progress.ts`; `formatFileSize` in `share-list.ts`. Server and CLI already consolidated formatters.
4. **Share download has two exported entry points but one is dead** — `downloadSharedFileWithTicket` is used from `share-access.ts`; `downloadSharedFileChunked` is exported from `streaming-download.ts` with no callers (candidate delete).
5. **Static `X-Download-Token` fallback remains in browser** — `streaming-download.ts` `applyShareAuthHeader` falls back when ticket provider fails; server cleanup deferred ticket-only auth. Browser, CLI, server, and E2E should move together.
6. **Playwright still hedges on share error copy** — Phase 11 accepts many `includes(...)` alternatives for expiry, max downloads, revoked, and not-found states; server cleanup tightened the same class of assertions on the shell E2E side.
7. **Strong crypto unit tests, weak UI flow tests** — 21 test files cover primitives well; no tests for `login.ts`, `register.ts`, `billing.ts`, `share-access.ts`, `contact-info.ts`, or `app.ts` event wiring.
8. **Large functional gaps vs Playwright** — no browser E2E for registration, WebAuthn MFA, MFA settings, `.arkbackup` export/download, subscription checkout (only partial billing), `revoke-all`, pending-approval UX, or Service Worker large-file path.
9. **Hygiene violations** — decorative `// ===...===` section blocks in `list.ts`, `password-modal.ts`, `share-crypto.ts`, tests; `showProgressMessage` labeled "Legacy compatibility" in `progress.ts`; comment "for now" in `opaque.ts`.
10. **Console logging in hot paths** — `download.ts` and `streaming-download.ts` log timing and metadata fields (`password_type`, chunk counts); audit for production bundle and privacy (filename/hash must never appear).
11. **CLI parity not yet systematically mapped** — billing human panel vs `arkfile-client billing show`, share ticket flow, digest-cache behavior (browser `digest-cache.ts` vs CLI agent), export format.

---

## Audit inventory and reachability map

### Problem

Without a reachability map, dead exports and duplicate paths hide behind dynamic imports in `app.ts` and `login.ts`.

### Target process

For each module under `client/static/js/src/`:

| Check | Method |
|-------|--------|
| Required? | Trace from `app.ts`, `shared.html` bootstrap, or Playwright DOM ids |
| Reachable? | grep exports + import graph; flag exports with zero importers |
| E2E exercised? | Map to Playwright phase or mark "not exercised" |
| CLI mirror? | Name/logic compare to `arkfile-client` for crypto/upload/download/share/export |
| Privacy? | Does it send plaintext filename/hash/password/password hint to the network, server storage, or logs? |

Produce a table (like CLI command inventory) listing each exported symbol, file, Playwright coverage (Y/N/partial), and recommended action (keep / fix / delete / add E2E).

### Deliverable

`Function inventory (frontend)` section appended to this doc after the first audit pass.

---

## One canonical path audit

### Upload

| Layer | File | Role |
|-------|------|------|
| UI entry | `upload.ts` `handleFileUpload()` | File input, batch selection |
| Core | `upload.ts` `uploadFile()` / `uploadFiles()` | Init/chunk/complete streaming |
| Dedup | `digest-cache.ts` | Client-side SHA-256 dedup before upload |

**Review questions:** Is `handleFileUpload` the only UI entry? Are retry paths (`retry-handler.ts`) all reachable? Does batch upload mirror CLI multi-file behavior? On 409 duplicate, is there exactly one user-facing error string (Playwright Phase 4 expects `duplicate file detected`)?

**Compare CLI:** `cmd/arkfile-client/commands.go` upload init/chunk/complete and duplicate detection messaging.

### Custom password hint privacy

#### Problem

`upload.ts` sends the user-provided custom password hint as the plaintext `password_hint` field in `/api/uploads/init`. The server persists that value in upload sessions and file metadata and returns it to clients. A hint may contain personal information, describe the protected file, or expose part of the password. This violates Arkfile's requirement that file metadata remain encrypted from the server.

The server does not need the plaintext hint. File metadata is always encrypted and decrypted with the Account Key, including when the FEK is wrapped with a custom-password-derived key. The frontend and CLI can therefore decrypt the hint before prompting for the custom password.

#### Target design

Replace plaintext `password_hint` with Account-Key-encrypted hint ciphertext and nonce fields using a dedicated, versioned metadata AAD context bound to the canonical file ID and owner. Use the existing metadata encryption primitives where appropriate, but do not reuse the filename or SHA-256 AAD context. Empty hints must have one canonical representation. The server treats encrypted hint fields as opaque and never receives, logs, indexes, or returns a plaintext hint.

Because Arkfile is greenfield, remove the plaintext field and compatibility fallback rather than retaining dual plaintext/encrypted decoding. Coordinate these changes atomically:

| Layer | Required change |
|-------|-----------------|
| Browser upload/download/share | Encrypt hints with the Account Key before upload; decrypt before displaying or prompting; never place plaintext hints in request bodies or logs |
| CLI upload/download/share | Use the same encrypted field format, nonce rules, and AAD as the browser |
| Server handlers/models/schema | Replace plaintext storage and API fields with opaque encrypted hint fields; reject obsolete plaintext input |
| Export/backup | Carry only encrypted hint metadata and preserve the same cryptographic binding |
| Tests | Add cross-client vectors, raw API assertions, database assertions, wrong-key/tamper failures, empty-hint behavior, and owner/custom/share flows |

#### Acceptance criteria

- Browser and CLI produce and consume the same encrypted hint format and AAD.
- Raw upload, list, metadata, share, and export API responses contain no plaintext hint.
- Database upload-session and file-metadata records contain no plaintext hint column or value.
- The server rejects requests that attempt to submit the obsolete plaintext field.
- Account-encrypted and custom-encrypted files display the decrypted hint only after the Account Key is available and before any custom-password prompt that needs it.
- Hint ciphertext or AAD tampering fails closed and does not display corrupted text.
- Tests use a unique sentinel hint and prove that it does not appear in network payloads, server responses, database contents, server logs, or production browser logs.

### Owner download

| Layer | File | Role |
|-------|------|------|
| Orchestration | `download.ts` `downloadFile()` | Meta fetch, FEK decrypt, password prompts |
| Streaming | `streaming-download.ts` `StreamingDownloadManager` | Chunk fetch, AES-GCM decrypt, SW vs Blob |
| SW integration | `sw-streaming-download.ts`, `sw-download.ts` | Large-file path (>2 GB) |

**Review questions:** Is `downloadFile` the only list-item download path (`list.ts`)? Is Blob fallback clearly bounded for 3 GB RAM / 6 GB file persona? Does SW path get any automated coverage?

### Share (owner + recipient)

| Flow | Files |
|------|-------|
| Create | `files/share.ts` -> `ShareCreator` in `share-creation.ts` -> `share-crypto.ts` |
| List/revoke | `share-list.ts` |
| Anonymous access | `share-access.ts` -> `share-ticket.ts` -> `streaming-download.ts` |

**Review questions:** Is `shareFile()` the only create path? Does anonymous download always go through `downloadSharedFileWithTicket`? Should `downloadSharedFileChunked` be deleted?

---

## Share auth ticket-only alignment

### Problem

`streaming-download.ts` documents ticket preference but falls back to static `X-Download-Token` when ticket issuance fails. Server cleanup deferred removing the server-side static token branch; CLI is already ticket-first.

### Target design

When server ticket-only pass lands:

| File | Change |
|------|--------|
| `streaming-download.ts` | Remove static token branch from `applyShareAuthHeader`; fail with actionable error |
| `share-access.ts` | Ensure envelope decrypt -> ticket request -> download is the only path |
| `share-ticket.ts` | Verify AAD and refresh semantics match CLI |

Until server changes: align comments with actual behavior; flag fallback as technical debt tied to server workstream.

### Tests

Extend `streaming-download.test.ts`: ticket failure must not silently fall back once ticket-only is canonical. Playwright Phase 10 already exercises anonymous ticket download.

---

## Dead code and legacy API removal

### Confirmed or likely dead (verify in inventory pass)

| Item | Location | Issue | Action |
|------|----------|-------|--------|
| `downloadSharedFileChunked` | `streaming-download.ts` | Exported; zero callers | Delete or merge into `downloadSharedFileWithTicket` |
| `getTokenExpiry()` | `auth.ts` | Always returns `null`; HttpOnly cookie model | Keep only if callers exist; else remove export and update tests |
| `showProgressMessage` "legacy" | `progress.ts` | Still used by auth flows | Rename comment; not dead; do not delete without migrating callers |
| Window globals | `register.ts`, `totp.ts`, `webauthn.ts` | `window.registrationData`, `window.totpLoginData` | Audit lifecycle; ensure `clearAllSessionData` always clears |
| Duplicate share download wrappers | `streaming-download.ts` | `downloadSharedFileChunked` vs `downloadSharedFileWithTicket` | One export |

### Decision criteria

Same as server/CLI: if Playwright + `bun test` + grep show no importers, delete. If E2E does not cover but product requires it (registration, WebAuthn), keep and add E2E rather than delete.

---

## CLI parity matrix

AGENTS.md requires mirrored critical functions. Audit each row; file mismatches as work items.

| Operation | CLI reference | Frontend reference | Parity checks |
|-----------|---------------|-------------------|---------------|
| Argon2id params | `crypto/constants` via API | `crypto/constants.ts`, `floors.ts` | Same floor resolution; same salt contexts (`account`, `custom`, share random salt) |
| Chunk encrypt/upload | `commands.go` upload | `upload.ts` | Same chunk size source; same envelope/AAD layout |
| Custom password hint | upload/download metadata | `upload.ts`, `download.ts`, `list.ts`, `share.ts` | Account-Key encryption, dedicated AAD, no plaintext server field, same empty-hint representation |
| Chunk download/decrypt | `commands.go` download | `download.ts` + `streaming-download.ts` | Same metadata decrypt order (account key for metadata even on custom FEK) |
| Share create | `commands.go` share create | `share-crypto.ts`, `share-creation.ts` | Envelope JSON shape, download token hash upload |
| Share recipient download | ticket + chunks | `share-access.ts`, `share-ticket.ts` | Ticket refresh on 403; no password on wire |
| Export backup | `export.go` | `export.ts` | `.arkbackup` format; short-lived download token pattern |
| Billing display | `billing_commands.go` human + `--json` | `billing.ts` | transactions, runway, billable bytes/rate (CLI cleanup added human parity) |
| Contact info | `commands.go` contact-info | `contact-info.ts` | CRUD + pending registration contact |
| Digest dedup | CLI agent digest RPCs | `digest-cache.ts` sessionStorage | Document intentional divergence (no agent in browser) |
| Password validation | server JSON + Go | `password-validation.ts` | Same contexts: account, custom, share |
| Revoke all sessions | `revoke-all` command | `auth.ts` `revokeAllSessions` | Confirm UI exposes this if product requires; E2E gap |

---

## Admin contacts contract (frontend)

Server cleanup established honest `GET /api/admin-contacts` with `configured: false`. Frontend was partially updated.

### Verify

| File | Check |
|------|-------|
| `auth.ts` `fetchAdminContacts` | No hardcoded defaults; handle non-200 (503 should not show fake contact) |
| `footer.ts` | Uses `isAdminContactsConfigured()`; no string compare to placeholder emails |
| `list.ts` | Storage contact note uses same contract |
| `sections.ts` | Pending approval MFA recovery hints |

### E2E additions

Playwright: fetch `/api/admin-contacts` via `page.evaluate`; assert `configured: true` on dev-reset and footer shows real contact. Assert no `admin@example.com` unless configured.

---

## Duplicate helper consolidation

| Duplicates | Target |
|------------|--------|
| `formatBytes` x3, `formatFileSize` x1 | `client/static/js/src/utils/format.ts` (or `ui/format.ts`) |
| Error user strings | Consider thin `ui/errors.ts` mapping `CryptoError` -> canonical copy (align with Playwright exact asserts) |
| Base64/hex helpers | Already centralized in `primitives.ts` / `metadata-helpers.ts`; verify no ad hoc duplicates in share modules |

---

## Privacy-sensitive logging review

### Problem

Hot paths use `console.log` with operation timing and sometimes field names that aid debugging but may leak operational detail in production DevTools (and violate spirit of privacy-first ops).

### Files to audit

| File | Approx. console calls |
|------|----------------------|
| `streaming-download.ts` | 26 |
| `download.ts` | 26 |
| `upload.ts` | 8 |
| `account-key-cache.ts` | 11 |
| `login.ts` | 9 |

### Target

Gate verbose logs behind a single debug flag (e.g. only when server debug mode detectable, or a documented dev-only flag). Production `build:prod` should strip or no-op debug logs. Never log passwords, FEK bytes, share passwords, decrypted filenames, or plaintext SHA-256. Chunk progress logs should use chunk index only.

Cross-reference: `docs/wip/archive/review/06-frontend-supply-ops.md` (source maps, service worker logs).

---

## Hygiene and comment cleanup

### Violations to fix

| Pattern | Locations | Action |
|---------|-----------|--------|
| `// ===...===` section blocks | `list.ts`, `password-modal.ts`, `share-crypto.ts`, `share-list.ts`, `digest-cache.ts`, `auth-manager.test.ts` | Remove decorative dividers per AGENTS.md |
| `// ---` in block comments | `share-access.ts`, `streaming-download.ts` | Rewrite as plain prose |
| "Legacy compatibility" | `progress.ts` | Rename to describe actual role (simple progress toast) |
| "for now" | `opaque.ts` | Verify KDF/session-key derivation comment; replace with accurate crypto description |
| WIP doc paths in comments | grep `docs/wip` | Remove or point to stable docs |

---

## Error message consistency

### Problem

Playwright Phase 6b asserts `check your password` via broad `includes`. Phase 4 duplicate upload uses one string. Share errors (Phase 11) accept many alternatives.

### Target

| UX event | Canonical message source | Consumers |
|----------|-------------------------|-----------|
| Wrong custom password decrypt | `crypto/errors.ts` `getUserFriendlyMessage` or dedicated constant | `download.ts`, Playwright Phase 6b |
| Duplicate upload | Single string from upload path | Phase 4 |
| Share expired / max downloads / revoked / not found | Stable copy on error pages or `data-testid` + one string each | Phase 11, `shared.html` error states |

Fix frontend first, then tighten Playwright to exact match or stable selectors (server cleanup pattern).

---

## `app.ts` decomposition

### Problem

`app.ts` (~748 LOC) mixes Trusted Types setup, readiness probe, SW registration, and dozens of DOM event listeners.

### Recommended extractions (after behavior stable)

| New file | Contents |
|----------|----------|
| `app/trusted-types.ts` | CSP Trusted Types policy |
| `app/ready-check.ts` | `/readyz` gate |
| `app/event-bindings.ts` | Upload, auth toggle, billing toggle, contact-info, security settings |
| `app.ts` | `ArkFileApp` orchestration only |

Template: CLI admin decomposition in `docs/wip/archive/cli-cleanup.md`.

---

## Playwright hedging removal

| Location | Current hedge | Target |
|----------|---------------|--------|
| Phase 2/5 upload | SKIP if file already in list | Document idempotent SKIP or fail if unexpected state; prefer deterministic dev-reset state |
| Phase 6b wrong password | `includes('check your password')` | Exact canonical error from frontend |
| Phase 11a expiry | many `includes('expired'|'forbidden'|'error'|'403')` | One error page copy or `data-testid` |
| Phase 11b max downloads | many alternatives | One string |
| Phase 11c non-existent | many alternatives | One string |
| Phase 12 revoked share | multiple `includes` | One string |
| Billing top-up | `[SKIP] payments may be disabled` | Explicit precondition: fail if billing enabled in dev-reset but button missing |
| Phase 13 | "Legacy localStorage checks" comment | Remove obsolete checks; assert only cookie/sessionStorage contract documented in auth model |

---

## Playwright coverage gaps

Add after hedging removal (priority order):

| Gap | Rationale |
|-----|-----------|
| Registration + pending approval UI | Greenfield onboarding path untested in browser |
| Export backup download | CLI E2E covers export; browser only sees "Export Backup" button in delete flow |
| MFA settings / WebAuthn setup | High security surface; CLI partially covered |
| Subscription checkout return | Billing partial; mirror CLI subscription tests |
| `revoke-all` if exposed in UI | Privacy/session hygiene |
| Admin contacts footer | Post server-cleanup contract |
| Large file SW download | 3 GB RAM / 6 GB file persona; may need dedicated test asset + timeout budget |
| Custom-password share recipient | Distinct from owner custom-password file |

---

## Unit test gap fill

### Current coverage (good)

Crypto primitives, AAD, Argon2 conformance, file encryption, share-crypto, streaming-download manager (mocked fetch), upload batch helpers, digest-cache, account-key-cache, export format, SW handler.

### Priority additions

| Target | Rationale |
|--------|-----------|
| `getUserFriendlyMessage` / wrong-password path | Stabilizes Playwright Phase 6b |
| `auth.ts` admin contacts parsing | 503 vs empty vs configured |
| `billing.ts` render helpers | Pure functions for balance/runway formatting |
| `share-access.ts` envelope error mapping | Anonymous share edge cases |
| `contact-info.ts` row builders | DOM-safe HTML escaping |
| Encrypted password hint contract | Cross-client vectors, tamper rejection, empty hint, and no plaintext request/response fields |
| Flag: production log stripping | If debug gate added |

Keep full upload/share integration in Playwright unless flakiness forces slimmer unit tests with mocked `fetch`.

---

## Production build hygiene

| Item | Action |
|------|--------|
| `build:prod` | Confirm `--minify` strips console or add explicit drop |
| `app.js.map` | Already external; operational decision from supply-chain review |
| `libopaque.js` | Pin/rebuild process out of scope unless hash mismatch found |

---

## Suggested implementation order

Work silent correctness and privacy before cosmetic cleanup:

1. **Audit inventory** — reachability map and CLI parity matrix (read-only pass produces the function table).
2. **Encrypt custom password hints** — remove the plaintext frontend/CLI/server/schema contract and add cross-client/privacy proof before lower-risk cleanup.
3. **Canonical path verification** — confirm single upload/download/share paths; delete `downloadSharedFileChunked` if confirmed dead.
4. **Error message standardization** — unlock Playwright tightening.
5. **Admin contacts frontend verification** — small, server already fixed.
6. **Privacy logging gate** — before production deploy hardening.
7. **Share ticket-only** — coordinate with server deferred workstream.
8. **Duplicate formatters** — low-risk consolidation.
9. **Dead legacy API cleanup** — `getTokenExpiry` export policy, window global audit.
10. **Playwright hedging removal** — depends on steps 4-5.
11. **Playwright gap fill** — registration, export, subscription.
12. **`app.ts` decomposition** — mechanical, after behavior stable.
13. **Hygiene pass** — dividers, comments.
14. **Unit tests** — alongside each fix.

---

## Verification checklist (final)

- [ ] `sudo bash scripts/dev-reset.sh`
- [ ] `bash scripts/testing/e2e-test.sh` — all PASS
- [ ] `sudo bash scripts/testing/e2e-playwright.sh` — all PASS, zero undocumented SKIP
- [ ] `cd client/static/js && bun test` — all PASS
- [ ] `cd client/static/js && bun run lint` — type-check clean
- [ ] Manual: 6 GB file upload/download on constrained tab (or documented SW test)
- [ ] Manual: shared file anonymous download with ticket refresh after forced 403
- [ ] Manual: billing panel shows transactions + runway matching CLI `billing show --json` fields
- [ ] Browser and CLI encrypted password-hint conformance vectors pass; custom hint remains usable in owner download and share creation
- [ ] Raw API, database, server-log, and production-browser-log checks prove a unique plaintext hint sentinel appears nowhere outside client plaintext memory/UI
- [ ] Server rejects obsolete plaintext `password_hint` input; schema and models contain no plaintext hint storage path
- [ ] Grep `client/static/js/src` for `default-admin`, `admin@example.com`, `docs/wip/`, decorative `===`/`---` in comments, `for now`, `backward compatibility` — zero inappropriate hits
- [ ] Grep frontend for `console.log` of filename, sha256, password, password hint, fek — zero in production path or gated

---

## E2E-confirmed hot paths (do not delete without replacement)

| Area | Frontend modules / DOM |
|------|------------------------|
| Auth | `login.ts`, `totp.ts`, `password-modal.ts` cache opt-in; `#login-btn`, `#verify-totp-login` |
| Upload | `upload.ts`, `app.ts` file input; account + custom password |
| Download | `download.ts`, `list.ts` `.btn-download` |
| Delete | `list.ts` delete + export backup button presence |
| Shares | `share.ts`, `share-list.ts`, `share-access.ts`; create A/B/C, list, revoke |
| Anonymous share | `shared.html` + `share-access.ts`; Phase 10-11 |
| Contact info | `contact-info.ts`; Phase 12 embedded tests |
| Billing | `billing.ts`; balance, usage grid, transactions, top-up modal |
| Logout | `login.ts` logout; Phase 13 sessionStorage/CSRF checks |
| API privacy | Phase 7 raw list — encrypted fields only |

---

## Not exercised by Playwright (keep, delete, or add coverage)

| Area | Modules | Recommendation |
|------|---------|----------------|
| Registration | `register.ts`, `mfa-setup.ts` | Add Playwright phase |
| WebAuthn | `webauthn.ts`, `clictap` integration | Add or document manual-only |
| MFA settings | `mfa-settings.ts`, `mfa-method.ts` | Add coverage |
| Export download | `export.ts` | Add phase mirroring CLI export E2E |
| Subscription portal | `billing.ts` subscribe/portal handlers | Add after billing top-up stable |
| Revoke all | `auth.ts` if UI exists | Wire UI or delete dead button |
| Pending approval | `sections.ts` `showPendingApprovalSection` | Add with registration phase |
| SW large download | `sw-streaming-download.ts` | Dedicated test with large fixture |
| Reregistration | `login.ts` re-register path | Align with CLI reregistration E2E |
| `downloadSharedFileChunked` | `streaming-download.ts` | Delete if inventory confirms |

---

## Out of scope (this document)

Vendored `libopaque.js` rebuild pipeline (see supply-chain review). Caddy/CSP/systemd changes. Server and CLI changes unrelated to required privacy-contract remediation; encrypted password-hint API/schema/model/CLI changes are explicitly in scope. Full rewrite of `06-frontend-supply-ops.md` findings. Windows or non-browser clients.

---

## Relationship to server and CLI cleanup

| Prior cleanup item | Frontend follow-up |
|--------------------|-------------------|
| Admin contacts honest API | Verify `auth.ts`, `footer.ts`, `list.ts`; add Playwright assert |
| Plaintext custom password hint | Replace with Account-Key-encrypted metadata across browser, CLI, server, schema, export, and E2E |
| Share ticket-only (deferred) | Remove `X-Download-Token` fallback in `streaming-download.ts` |
| E2E hedging removal pattern | Apply to `e2e-playwright.ts` Phase 6b, 11, 12 |
| CLI billing human parity | Match `billing.ts` display fields to CLI output |
| CLI error message consistency | Align browser toast/modal strings |
| Duplicate formatters | Same consolidation discipline as `handlers/format.go` / `cli/format` |
| Agent digest privacy | Browser uses `digest-cache.ts`; document different threat model |

---

## Suggested first audit session

Bounded first pass before writing fixes:

1. Run the reachability inventory (exports with zero importers).
2. Read `upload.ts`, `download.ts`, `streaming-download.ts`, and `share-access.ts` end-to-end with the Function Review Sanity Check list literally in hand.
3. Map Playwright phases to functions (tables above are the starter).
4. Trace `password_hint` across browser, CLI, API handlers, database schema, exports, shares, tests, and logs; define the encrypted replacement contract and sentinel privacy test.
5. Build the CLI parity matrix for upload, download, share create, share receive, export.
6. Grep for hygiene and privacy violations; triage into workstream rows.

That first session should produce the filled-in **Function inventory (frontend)** table and a prioritized top-10 fix list, the same outcome the server and CLI audits produced before implementation began.
