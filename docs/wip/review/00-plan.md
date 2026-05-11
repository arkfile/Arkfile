# Arkfile In-Depth Security Review — Plan & Tracker

This document is the master tracker for the multi-session security review of the Arkfile codebase. It defines scope, ground rules, slice decomposition, output format, status, and a preliminary list of items considered N/A for this codebase.

The driving prompt for this review is `docs/wip/idsrp.md` (the "In-Depth Security Review Prompt"). Project context and rules-of-engagement come from `docs/AGENTS.md`.

This plan was created at commit `8f4f9834078977b2be5ee9cc3ae533d12ad5bd21`.

---

## 1. Purpose

Perform an adversarial, evidence-backed security review of the Arkfile codebase covering:

- OPAQUE authentication (Go server, CGO wrapper, vendored C libopaque/liboprf/libsodium, browser WASM client)
- Go CLI clients (`arkfile-client`, `arkfile-admin`) including OPAQUE registration/login flows, password lifecycle, session-file hygiene, the local key-agent daemon, CLI flag-based leakage surfaces (e.g. `--totp-secret` argv exposure), and CLI binary supply chain
- TOTP as **mandatory 2FA** for all authenticated access and user actions across browser and both CLIs — enrollment, verify, backup codes, lockout, recovery, per-endpoint TOTP gating, and the two-tier JWT model (post-OPAQUE temp token vs. post-TOTP full JWT) enforced by a dedicated TOTP middleware
- Argon2id key derivation and the account / custom / share password key hierarchy
- Client-side file encryption, chunked streaming upload/download, envelope format
- File sharing flow (share envelope, share password, anonymous recipient access)
- Backend authorization, IDOR, API surface, rate limiting
- Admin surface (`handlers/admin*.go`, `cmd/arkfile-admin/`) and billing math (`billing/`, credits/balances) in preparation for future payment-processor wiring
- Frontend (TypeScript), WASM loading and integrity, XSS / CSP, dependency supply chain
- Build, deployment, and operational security (`scripts/`, `Caddyfile*`, `systemd/`)
- Telemetry, logging, and PII hygiene per Arkfile's "no IP, no PII" privacy posture

The review must produce concrete, code-backed findings — not generic best-practice commentary.

---

## 2. Ground Rules

### Honesty and transparency
Per `docs/AGENTS.md`: full thinking including criticisms, no sweeping anything under the rug, especially privacy/security gaps. Flag stub / deprecated / "backwards-compatibility" code aggressively (Arkfile is greenfield with no production deployments; `test.arkfile.net` is the only beta).

### Severity policy (aggressive)
Apply severity per `idsrp.md` §18. Be aggressive on Critical/High where evidence supports it, because the goal is to protect users and potential users of the system.

- **Critical**: unauthenticated user-file compromise, auth bypass, server-wide plaintext access where E2EE is claimed, OPAQUE failure enabling offline cracking, RCE, key exfiltration at scale, AEAD/MAC/signature bypass at scale.
- **High**: another user's files (encrypted or plain), persistent XSS in this crypto web app, share authz bypass, file key exposure, realistic account takeover, significant metadata leakage contrary to claims, replay/substitution on encrypted files, CGO memory-safety bugs reachable from attacker input.
- **Medium**: missing rate limits, weak-but-not-immediately-exploitable crypto choices, limited IDORs, token lifetime issues, incomplete logging hygiene, undocumented revocation limitations, defense-in-depth gaps.
- **Low / Informational**: hardening, minor leakage, doc gaps, non-exploitable inconsistencies, code-clarity items affecting future security maintenance.

### Evidence requirement
Every finding must cite file + line range (e.g. `auth/opaque.go:123-145`). Hand-wavy "could be vulnerable" claims get downgraded to Informational or moved to Open Questions. Quote the relevant lines briefly in each finding's Evidence section.

### Confidence rating
Per finding: High / Medium / Low. "I read the code and reproduced the path" is High. "Static reasoning only, plausible but not exercised" is Medium. "Suggestive but I lack visibility" is Low.

### Scope of trust for vendored C
`libopaque`, `liboprf`, and `libsodium` (~347k LOC of vendored C under git submodules) are treated as trusted, audited upstreams. We audit:

- The CGO surface in `auth/opaque_wrapper.{c,h}` (~200 LOC) line by line.
- Every Go call site that crosses the boundary.
- Build flags and link configuration.
- Update / pinning hygiene.

We do **not** re-audit libsodium internals.

### Privacy posture
Per AGENTS.md, IP addresses and PII must not be logged. EntityID HMAC is used for rate-limit keying. Any code path that logs or persists raw IPs, emails in unintended places, filenames in cleartext, share tokens, or session material is a finding.

### Greenfield expectations
"Backwards compatibility", "fallback", or "deprecated but kept" findings should be flagged for removal, not accommodation. There are no production deployments to migrate.

### No commits
Per AGENTS.md, the agent will not run `git add`, `git commit`, or `git push`. Developers commit.

### No reading of secrets
Per `.clinerules`, the agent will not read, cat, grep, or otherwise access `.env` files or any file under `/opt/arkfile/etc/`. If a finding depends on what's in a secrets file, the developer will be asked to check it.

---

## 3. Codebase Size at Time of Plan

| Area | LOC | Files |
|---|---:|---:|
| `handlers/` | 16,790 | many |
| `cmd/` (`arkfile-admin`, `arkfile-client`) | 11,948 | - |
| `crypto/` (Go) | 4,481 | - |
| `auth/` | 3,712 | - |
| `models/` | 3,705 | - |
| `logging/` | 2,041 | - |
| `storage/` | 1,859 | - |
| `billing/` | 1,422 | - |
| `config/` | 1,190 | - |
| `monitoring/` | 1,097 | - |
| `utils/` | 690 | - |
| `database/` | 154 | 1 |
| **Go total (project, ex-vendor)** | **~50,000** | **133** |
| TypeScript (`client/static/js/src/**`) | 20,077 | 58 |
| CGO wrapper (`auth/opaque_wrapper.{c,h}`) | 203 | 2 |
| Vendored C (libopaque + liboprf + libsodium) | ~347,000 | many |

In-house auditable code: **~70k LOC** (Go + TS + CGO wrapper).

---

## 4. Slice Decomposition

The audit is split into six analysis slices (A–F) plus a synthesis slice (G). Each slice fits in a single focused session (~250–500k tokens) and produces a standalone, reviewable deliverable. Order:

> A -> B -> C -> D -> E -> F -> G

### Slice A — Auth & OPAQUE (incl. CLI auth flows and TOTP enforcement)
**Output:** `docs/wip/review/01-auth-opaque.md`
**`idsrp.md` sections:** §4 (OPAQUE), §9 (session/cookie/token), §15 (password change / recovery), parts of §3 (WASM/opaque.js), parts of §14 (telemetry around auth), **§22 (CLIs + mandatory TOTP)**.
**Code in scope (Server + Browser):**
- `auth/opaque.go`, `auth/opaque_client.go`, `auth/opaque_multi_step.go`, `auth/opaque_wrapper.{c,h}`, `auth/keys.go`, `auth/bootstrap.go`, `auth/dev_admin.go`, `auth/jwt.go`, `auth/totp.go`, `auth/token_revocation.go`, `auth/constants.go`
- `handlers/auth.go`, `handlers/bootstrap.go`, `handlers/admin_auth.go`, `handlers/middleware.go` (auth + TOTP-gate middleware), `handlers/route_config.go` (verify every protected route is wired through the TOTP middleware chokepoint)
- `crypto/opaque_validation.go`, `crypto/totp_keys.go`, `crypto/password_validation.go` (login-password class only; file-encryption password classes belong to Slice B)
- `models/user.go`, `models/refresh_token.go`
- TypeScript: `client/static/js/src/auth/**`, WASM loading and `opaque.js` integration, browser TOTP enroll/verify UI
- Auth tests: `auth/jwt_test.go`, `auth/totp_test.go`, `auth/totp_backup_test.go`, `auth/token_revocation_test.go`, `handlers/auth_test.go`, `handlers/auth_test_helpers.go`

**Code in scope (Go CLI clients — per `idsrp.md` §22.1):**
- `cmd/arkfile-client/main.go` (register, login, TOTP entry, session save/load, password I/O)
- `cmd/arkfile-client/commands.go` (the OPAQUE-bearing command paths and the deliberate password-lifetime decisions)
- `cmd/arkfile-client/agent.go`, `cmd/arkfile-client/agent_test.go` (key-caching daemon, Unix-socket IPC, TTL, wipe logic, digest-cache integrity)
- `cmd/arkfile-client/crypto_utils.go` (`generateTOTPCode` from `--totp-secret`)
- `cmd/arkfile-admin/main.go` (admin bootstrap, admin OPAQUE login, admin TOTP, session save/load)

**Specifically must answer (Server-side OPAQUE / JWT / TOTP):**
- Offline password-cracking resistance if DB is stolen.
- Where the OPAQUE server setup key lives and whether DB+setup-key together suffice for impersonation or password recovery.
- Export-key usage and domain separation (or absence of export-key use).
- Identity binding, normalization (Unicode, casing) for usernames/emails.
- Replay and concurrent-session safety in the multi-step OPAQUE handshake.
- JWT validation, refresh-token rotation, revocation on password change.
- CGO boundary: input validation, length handling, return-code checks, memory zeroing.
- WASM pinning / SRI / build provenance.

**Specifically must answer (Mandatory TOTP / two-tier JWT — per `idsrp.md` §22.2):**
- Two-tier JWT model: confirm post-OPAQUE temp token vs. post-TOTP full JWT are cryptographically distinct (separate audience claim, separate signing key, in-DB allowlist, or `totp_verified=true` claim). The temp token MUST be rejected by every route except TOTP-verify / TOTP-enrollment-completion.
- TOTP middleware chokepoint: single function, applied to every protected route; verify against `handlers/route_config.go`. No per-handler ad-hoc checks.
- TOTP enrollment: secret entropy (CSPRNG, ≥160 bits), server-side at-rest encryption of the secret (which key encrypts it? rotated how?), QR/URI not logged, finalize requires a valid first code, no race between two concurrent enrollments.
- TOTP verify: 30 s step, narrow skew window (±1 step), constant-time comparison, one-time use per step per user, rate limit, lockout after N failures (and the lockout state must not enable account enumeration).
- Backup codes: generation entropy and count, server-side hashed (Argon2id or comparable) and/or at-rest encrypted (never plaintext), atomic mark-as-used (no double-spend race), regeneration invalidates old codes, rate limited.
- Loss-of-device recovery: document the supported path (backup codes? admin reset?); audit any admin-reset for authz, audit trail, and TOTP-guarantee impact.
- Admin TOTP: admin login forces TOTP; admin bootstrap either requires immediate TOTP enrollment or clearly constrains the deferral window.
- Dev/test bypass: `ADMIN_DEV_TEST_API_ENABLED=true`, `dev-reset.sh`, and debug-mode toggles must not silently disable the TOTP middleware in non-dev builds. `config/security_config.go` must fail closed on conflicting flags.

**Specifically must answer (Go CLI clients — per `idsrp.md` §22.1):**
- OPAQUE protocol-state correctness parity between `arkfile-client` / `arkfile-admin` and the browser. Any divergence in `ClientCreateRegistrationRequest` / `ClientCreateCredentialRequest` / `ClientRecoverCredentials` / finalize calls.
- Password lifecycle in CLIs: when is the password byte buffer zeroed? Justify the explicit `// NOTE: Do NOT zero password here` in `commands.go` — is it strictly necessary, and is the residual lifetime minimized?
- Session file location, permissions (expect 0600), serialized contents — confirm no KEK / OPAQUE export / TOTP material is persisted.
- `--totp-secret` argv exposure (`/proc/<pid>/cmdline`, shell history, process accounting). Treat as Medium+ unless mitigated.
- `--password-stdin` pipe handling: timeout (`PasswordTimeoutPipe`), leftover bytes, EOF correctness.
- `--account-key-file`: required file mode, TOCTOU between stat and read.
- Agent daemon (`cmd/arkfile-client/agent.go`):
  - Unix-socket path predictability, parent directory mode, socket file mode (0600).
  - Peer-credential check or shared-cookie auth for clients connecting to the agent.
  - Account-KEK cache TTL behavior; behavior under SIGTERM / SIGKILL / OOM / core dump (`madvise(MADV_DONTDUMP)` / `mlock`).
  - `wipeAllSensitiveDataLocked` and "session mismatch" trigger correctness — can a malicious local process induce the wipe (DoS) or evade it?
  - Digest-cache integrity: can a poisoned dedup digest coerce upload/download of wrong content?
- Admin bootstrap (`cmd/arkfile-admin/main.go` + `handlers/bootstrap.go`): single-use token enforcement, idempotency, replay resistance, TOTP enrollment expectations for the first admin.

### Slice B — Crypto & Key Hierarchy
**Output:** `docs/wip/review/02-crypto-keys.md`
**`idsrp.md` sections:** §5 (Argon2id), §6 (file encryption), §16 (cryptographic design / key hierarchy), parts of §11 (metadata encryption).
**Code in scope:**
- `crypto/key_derivation.go`, `crypto/key_manager.go`, `crypto/gcm.go`, `crypto/envelope.go`, `crypto/file_operations.go`, `crypto/chunking_constants.go`, `crypto/session.go`, `crypto/share_kdf.go`, `crypto/password_validation.go`, `crypto/utils.go`
- `crypto/argon2id-params.json`, `crypto/chunking-params.json`, `crypto/password-requirements.json`
- TypeScript: `client/static/js/src/crypto/**`
- `utils/padding.go`
- Crypto tests: `crypto/*_test.go`, `client/static/js/src/__tests__/**` (crypto subset)

**Specifically must answer:**
- Argon2id parameters per password class (account, custom, share) and whether parameters can be downgraded by attacker-controlled responses.
- Salt construction (`SHA-256("arkfile-account-key-salt:{username}")` etc.) and whether deterministic salts are safe in context.
- Domain separation between OPAQUE auth, account-KEK, custom-KEK, share-KEK, metadata key.
- FEK generation entropy (per file random 256-bit) and verification.
- AES-GCM nonce strategy across chunks, nonce reuse risk under single key.
- Envelope format, key-type byte (0x01 account / 0x02 custom), tamper resistance, AAD bindings.
- Metadata encryption coverage (filename, size, SHA-256), and authentication of metadata vs blob.
- Padding policy and length-leak analysis.
- Zeroization of key material in Go and TS where practical.
- Documented vs. implemented hierarchy match.

### Slice C — File Upload / Download / Chunking
**Output:** `docs/wip/review/03-files-upload-download.md`
**`idsrp.md` sections:** §6 (continued), §8 (backend authz & object storage, file-path), §10 (API), parts of §17 (file-handling tests).
**Code in scope:**
- `handlers/uploads.go`, `handlers/downloads.go`, `handlers/files.go`, `handlers/streaming_hash.go`, `handlers/chunked_upload_*` tests/integration
- `storage/registry.go`, `storage/s3.go`, `storage/storage.go`, `storage/types.go`, `storage/verify.go`, `storage/mock_storage.go`
- `models/file.go`, `models/file_storage_location.go`, `models/storage_provider.go`
- TypeScript: `client/static/js/src/files/**` (streaming-download, download, list, upload)
- `client/static/js/src/__tests__/streaming-download.test.ts`
- Erasure-coding doc: `docs/erasure-coding.md` (compare claims to code)
- `handlers/files_test.go`, `handlers/uploads_test.go`, `handlers/chunked_upload_100mb_test.go`, `handlers/chunked_upload_integration_test.go`

**Specifically must answer:**
- Streaming decryption: is unauthenticated plaintext released before tag verification?
- Chunk reorder / truncate / replay protection; AAD binding to chunk index and file ID.
- IDOR on file IDs, object keys; predictability of object keys in S3.
- Authorization parity between metadata API and blob fetch path; signed URL hygiene if used.
- Resumable upload state safety; race in finalize vs delete.
- Server's ability to swap or replay older ciphertexts undetected.
- 6 GB-on-3 GB-RAM mobile constraint (per AGENTS.md): memory bounds in chunk reader, hashing, padding.
- Multi-provider storage routing safety (`storage_provider`, location records) and trust boundary.

### Slice D — Sharing
**Output:** `docs/wip/review/04-sharing.md`
**`idsrp.md` sections:** §7 (sharing), §11 (metadata leakage via shares), parts of §8 (authz on share endpoints).
**Code in scope:**
- `handlers/file_shares.go`, `handlers/file_shares_test.go`, `handlers/share_enumeration.go`
- `crypto/share_kdf.go`, `crypto/share_kdf_test.go`
- TypeScript: `client/static/js/src/shares/**`, `client/static/shared.html`
- Anonymous-recipient flow end to end
- Rate limiting for enumeration: `handlers/flood_guard.go`, `handlers/rate_limiting.go`, `logging/entity_id.go`

**Specifically must answer:**
- Share password Argon2id params, random 32-byte salt, AAD = `share_id || file_id` binding correctness.
- Share envelope tamper resistance; can server swap envelopes between shares?
- Share ID entropy and enumeration resistance; per-IP/per-share rate limits and EntityID HMAC correctness.
- Revocation semantics — clearly distinguish future-access revocation from "already-downloaded key" revocation in disclosure.
- Anonymous recipient privacy: no IP logging, no recipient identifiers persisted.
- Cross-share confusion: can a share password / envelope from share A unlock share B?

### Slice E — API / Authz / Admin / Billing
**Output:** `docs/wip/review/05-api-authz-admin-billing.md`
**`idsrp.md` sections:** §8 (backend authz), §10 (API security), parts of §14 (logging hygiene for admin/billing paths).
**Code in scope:**
- `handlers/handlers.go`, `handlers/middleware.go`, `handlers/response.go`, `handlers/route_config.go`, `handlers/error_pages.go`, `handlers/config.go`, `handlers/rate_limiting.go`, `handlers/flood_guard.go`, `handlers/contact_info.go`, `handlers/export.go`
- Admin surface: `handlers/admin.go`, `handlers/admin_auth.go`, `handlers/admin_billing.go`, `handlers/admin_storage.go`, `handlers/admin_task_runner.go`, `cmd/arkfile-admin/`
- Billing math: `billing/types.go`, `billing/rates.go`, `billing/meter.go`, `billing/sweep.go`, `billing/scheduler.go`, `billing/gift.go`, `handlers/credits.go`, `handlers/billing_projection.go`, `models/credits.go`, `models/admin_task.go`
- `database/database.go`, `database/unified_schema.sql` (constraints, FKs, schema-level authz)
- `logging/logging.go`, `logging/security_events.go`, `logging/entity_id.go`
- `monitoring/health_endpoints.go`, `monitoring/key_health.go`
- All `_test.go` for the above

**Specifically must answer:**
- Per-endpoint: auth required? authz rule? sensitive inputs/outputs? rate limited? logged? **TOTP-gated?**
- Produce an Endpoint Review Table per `idsrp.md` §20 with an explicit **"TOTP-gated?"** column. Every protected route must be marked Yes/No/N-A; any route marked No that should be Yes (per `idsrp.md` §22.2) is at minimum a High finding. This is the API-surface verification of the TOTP middleware chokepoint audited in Slice A.
- Admin privilege boundary; cross-tenant N/A but cross-user is in scope.
- Mass assignment, IDOR, JSON parser differentials, content-type confusion.
- Billing math correctness: rate application, credit gift idempotency, meter overflow / negative-value / off-by-one, sweep window vs. clock skew, scheduler concurrency. Goal: be ready for payment-processor wiring (card, crypto, ACH, SEPA) — flag anything that would be unsafe once real money is involved (transaction atomicity, idempotency keys, audit trails, refund/charge-back semantics, currency rounding).
- Logging hygiene across admin/billing/credits paths (no PII, no IPs, no card-likely identifiers in future).
- `export.go` (encrypted backup) — confirm no plaintext or KEK material is exported in cleartext.

### Slice F — Frontend / WASM / Supply Chain / Ops
**Output:** `docs/wip/review/06-frontend-supply-ops.md`
**`idsrp.md` sections:** §3 (frontend / WASM / TS), §12 (XSS), §13 (supply chain & build), §15 (deployment & operational), residual §14 (frontend telemetry).
**Code in scope:**
- `client/static/index.html`, `client/static/shared.html`, `client/static/theme-preview.html`, `client/static/errors/**`, `client/static/css/**`, `client/static/js/**`
- TypeScript: all of `client/static/js/src/**` (ui, utils, types not already covered)
- `package.json`, `tsconfig.json`, `tsconfig.sw.json`, `playwright.config.ts`
- `go.mod`, `.gitmodules`, `config/dependency-hashes.json`
- `Caddyfile`, `Caddyfile.local`, `Caddyfile.prod`, `Caddyfile.test` — CSP, security headers, TLS posture, deSEC DNS-01 integration
- `systemd/arkfile.service`, `systemd/caddy.service`, `systemd/rqlite.service`, `systemd/seaweedfs.service` — sandboxing, capabilities, user isolation
- `scripts/dev-reset.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/prod-update.sh`, `scripts/test-*.sh`, `scripts/maintenance/**`, `scripts/setup/**`, `scripts/testing/**`
- CLI binary build/supply chain (per `idsrp.md` §22.1): the portions of the above scripts and any `Makefile`/`go build` invocations that compile `arkfile-client` and `arkfile-admin`; `CGO_LDFLAGS` and static-linking of libsodium/libopaque/liboprf; `.gitmodules` for vendored crypto submodule pinning.
- `monitoring/` (frontend-visible health endpoints)

**Specifically must answer:**
- WASM artifact integrity (SRI? hash pinning? bundled? fetched at runtime?).
- CLI binary integrity: static vs dynamic linking of libsodium/libopaque/liboprf in `arkfile-client` and `arkfile-admin`; RPATH/RUNPATH presence; stripped symbols; reproducible-build flags (`-trimpath`, `-buildid=`); release-artifact signing and provenance.
- CSP strictness; whether inline script/style is permitted; Trusted Types usage.
- XSS sinks for filenames, usernames, contact-info, share messages, admin views.
- localStorage / sessionStorage / IndexedDB / cookie inventory of anything secret-adjacent.
- Service-worker (if any) scope and cache poisoning risk.
- npm + Go module pinning, lockfile presence, `config/dependency-hashes.json` enforcement.
- Postinstall scripts, build-time codegen risks.
- systemd hardening: `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, capability sets.
- TLS / Caddy config: cipher suites, HSTS, OCSP, secret cert handling, deSEC token exposure surface.
- Deployment scripts: privilege escalation surface, secret material on disk, file modes under `/opt/arkfile/etc/`.

### Slice G — Synthesis
**Output:** `docs/wip/review/00-executive-summary.md`
**Sources:** Only the six finding docs above. No fresh code reads (target ~100–200k tokens).
**Contents (per `idsrp.md` §20):**
- Executive summary (overall posture, top risks, claims-vs-implementation gap).
- Architecture & data-flow summary (registration, login, upload, download, share, password change, key hierarchy).
- Threat-model assessment vs. `idsrp.md` §2.
- Consolidated severity-ranked finding index (links into the six slice docs).
- Endpoint review table (merged from Slice E, with C/D additions).
- Cryptographic review table (from Slice B).
- Key hierarchy (text + optional Mermaid).
- Metadata exposure matrix.
- Testing gaps, prioritized.
- Hardening recommendations.
- Explicit answers to all 20 questions in `idsrp.md` §19.
- Open questions for the team.

---

## 5. Output Format Spec (used by every slice doc)

Each slice doc follows this structure:

```
# Slice <N> — <Title>

## 0. Scope
- idsrp.md sections covered (and which are deferred / N/A here)
- Files actually read (with brief why-each)
- Out-of-scope notes

## 1. Architecture & Data-Flow Summary (for this slice)
- Narrative + ASCII diagrams as needed
- Cross-references to other slices for boundary clarity

## 2. Findings
For each finding:
### Finding <Slice>-<NN>: <Title>
- Severity: Critical | High | Medium | Low | Informational
- Confidence: High | Medium | Low
- Category: cryptographic | authorization | memory-safety | frontend | operational | design | privacy
- Component: <module/dir>
- Affected files / functions: file:line ranges
- Description
- Evidence: brief code quote with file:line
- Attack scenario
- Impact
- Recommendation: concrete, implementation-oriented
- Suggested tests
- Cross-refs (other slice findings if related)

## 3. Tables (where they fit)
- Endpoint review table (C, D, E)
- Crypto operations table (B)
- Metadata exposure matrix (B, D)
- Key hierarchy entries (A, B)

## 4. N/A items
- idsrp.md items this slice was supposed to cover but that do not exist
  in Arkfile, each with a one-line justification

## 5. Open questions / blocked-on-developer items

## 6. Testing gaps identified (feed into Slice G)

## 7. Hardening / non-vulnerability recommendations
```

Caps to enforce focus:
- ~20–30 findings per slice (force prioritization).
- Evidence required: every finding must cite file:line.
- N/A list at the bottom of each slice instead of speculative "no evidence" findings.

---

## 6. Preliminary N/A List (to be confirmed per slice)

Items the `idsrp.md` prompt asks about that, based on initial inspection, appear not to exist in Arkfile. Each will be re-verified in its respective slice and either confirmed N/A or upgraded to a finding.

| Item from `idsrp.md` | Preliminary status | Where it would have been |
|---|---|---|
| Folder hierarchy / nested folder ACLs | N/A — Arkfile is a flat per-user file space, sharing is per-file | §7, §8 |
| Recipient public-key directory / PKI sharing | N/A — sharing is password-derived share envelope | §7 |
| Multi-tenant separation | N/A — single tenant | §8 |
| Email verification / password reset flow | TBD — verify in Slice A; account recovery may simply not exist by design (forgotten password = lost files, accept and document) | §15 |
| Thumbnails / previews / server-side search index | N/A — files are encrypted blobs, no preview | §6, §11, §12 |
| Archive extraction (zip-slip etc.) | N/A — server does not extract archives | §10 |
| SSRF on user-supplied URLs | TBD — confirm no URL-fetch endpoints exist | §10 |
| MFA enrollment / verify / backup codes / lockout / loss-of-device recovery | **In scope** — full coverage in Slice A per `idsrp.md` §22.2 (TOTP is mandatory 2FA) | §15, §22 |
| Device enrollment / device management | TBD — refresh tokens exist; full device mgmt likely N/A | §15 |
| Recovery codes (other than TOTP backup) | TBD | §15 |
| CDN cache-poisoning for private content | TBD — check Caddy config in Slice F | §10, §8 |
| Payment-processor specific issues | N/A right now — no card/crypto/ACH/SEPA integrations wired in. Billing math reviewed in Slice E to be ready for that wiring. | §10 |

---

## 7. Status Tracker

| Slice | Output file | Status | Started | Completed | Notes |
|---|---|---|---|---|---|
| Plan / tracker | `00-plan.md` | Done | 2026-05-11 | 2026-05-11 | This document. |
| A — Auth & OPAQUE | `01-auth-opaque.md` | **Done** | 2026-05-11 | 2026-05-11 | Consolidated final deliverable: 45 findings (1 Critical, 12 High, 21 Medium, 9 Low, 2 Informational) covering server OPAQUE/JWT/TOTP, both CLIs + agent daemon, browser auth flow. Single `A-NN` numbering. |
| B — Crypto & key hierarchy | `02-crypto-keys.md` | Not started | | | |
| C — Upload/Download/Chunking | `03-files-upload-download.md` | Not started | | | |
| D — Sharing | `04-sharing.md` | Not started | | | |
| E — API/Authz/Admin/Billing | `05-api-authz-admin-billing.md` | Not started | | | |
| F — Frontend/WASM/Supply/Ops | `06-frontend-supply-ops.md` | Not started | | | |
| G — Synthesis | `00-executive-summary.md` | Not started | | | Depends on A–F. |

Update the Status column at the start and end of each slice session.

---

## 8. How to Use This Tracker in Future Sessions

At the start of each new session:
1. Open this file first.
2. Re-read `docs/AGENTS.md` and `docs/wip/idsrp.md`.
3. Open the slice doc you are working on. If starting fresh, copy the Output Format Spec from §5 here as the skeleton.
4. Update the Status Tracker (§7) to "In progress" with today's date.
5. Read only the files in that slice's "Code in scope" list. Resist scope creep — cross-cutting issues get a one-liner cross-ref and live in their proper slice.
6. Enforce the finding cap and evidence rule.
7. At end of session, update Status Tracker, add any newly discovered N/A items to §6, and append any newly raised Open Questions there too.

When all of A–F are complete, run Slice G. Slice G must not read new code — only the six slice docs.

---

## 9. Out-of-Scope (Whole Review)

- Re-auditing libsodium / liboprf / libopaque internals (we trust upstream and audit the CGO boundary).
- Performance benchmarking.
- Penetration testing of a live deployment (`test.arkfile.net` or otherwise). Findings may suggest live tests but executing them is the developer's call.
- Reading or attempting to read `.env` files or `/opt/arkfile/etc/**`.
- Committing or pushing any change. Developer commits.

---

## 10. Open Questions for Developer (to revisit before Slice G)

- Confirm whether forgotten-password recovery is intentionally absent (i.e., lost password = lost files by design).
- Confirm whether device-management / per-device session listing is planned or out of scope.
- Confirm intended CSP strictness target for production (`Caddyfile.prod`).
- Confirm whether WASM is bundled into the TS build or fetched separately (affects Slice F supply-chain analysis).
- ~~Confirm whether `arkfile-client` (CLI) is in scope for end-user threat modeling.~~ **Answered (2026-05-11):** `arkfile-client` and `arkfile-admin` are first-class audited end-user / privileged-user surfaces. See `idsrp.md` §22.1 and Slice A scope.
- ~~Confirm TOTP enforcement model (every-login vs step-up).~~ **Answered (2026-05-11):** Two-tier JWT — post-OPAQUE temp token gates only TOTP-verify endpoints; full JWT (post-TOTP) required for every protected route via a dedicated TOTP middleware. See `idsrp.md` §22.2 and Slice A / Slice E scope.
