# Arkfile High-Priority Issues — Phased Remediation Plan

Companion doc to `docs/wip/review/00-executive-summary.md`. This document is the working plan for resolving the High-severity findings now that both Criticals (F-01 and A-01) are closed.

---

## Part 1: Assessment of the Two Critical Resolutions

Both Criticals are convincingly resolved based on the documentation. Quick rundown.

### F-01 (XFF localhost-gate bypass) — RESOLVED

The fix is structurally correct and goes beyond the minimal patch:

- `main.go` pins `e.IPExtractor = echo.ExtractIPDirect()` (kills the Echo default that walked XFF).
- New `peerAddrIsLoopback` helper reads `c.Request().RemoteAddr` directly for **authorization** decisions only, and a separate `publicClientIP` helper reads a Caddy-set `X-Arkfile-Peer` header for **rate-limit / EntityID** binning only. Clean separation of trust zones.
- All four Caddyfiles (`Caddyfile`, `.local`, `.test`, `.prod`) now strip `X-Forwarded-For` / `X-Real-IP` / `Forwarded` and set `X-Arkfile-Peer`.
- 11 regression tests added in `handlers/middleware_test.go` and `handlers/bootstrap_test.go`.
- Cross-slice downgrades to A-02 / A-13 / A-14 / A-26 / E-14 are explicitly tracked back to their per-slice baselines (not silently rolled into F-01's close-out).

### A-01 (Two-tier JWT model not enforced) — RESOLVED, with three ride-alongs

The fix is also structurally clean:

- Two separate Ed25519 keys (`jwt_signing_key_temp_v1`, `jwt_signing_key_full_v1`). A regression where someone forgets the audience check would still fail on signature mismatch.
- Validator enforces audience at `echojwt.ParseTokenFunc` per route group.
- New `RequireFullJWT` middleware as defense in depth on `totpProtectedGroup`, `pendingAllowedGroup`, `adminGroup`, `devTestAdminGroup`.
- `adminGroup` and `devTestAdminGroup` finally include `RequireTOTP`. This closes **E-01** (Medium) as a ride-along.
- **E-19** (High, export-any-file) and **A-39** (Low, panic on missing claims) are also closed by the same change set.
- 15 new Go tests + 7 new TS tests; full suites green.

### Net effect on the High bucket

- E-19 closed (was High; now Resolved).
- A-39 closed (was Low; now Resolved).
- E-01 closed via the `RequireTOTP` addition to admin groups (was Medium; now Resolved).
- A-02 (admin reach via temp token) is functionally closed because the same code path is what got fixed; the executive summary correctly notes it "requires no further action".
- A-13, A-14, A-26, E-14 revert to per-slice baselines and still need their own fixes (none are higher than High; the F-01 escalation that made them Critical-adjacent is gone).

Realistic open High count: **~26 Highs** (27 originally minus E-19), with several structurally connected.

---

## Part 2: Operating Principles

These are the cross-cutting rules that govern every phase. They derive from `docs/AGENTS.md` and the developer's workflow.

### 2.1 Workflow

- **Direct-to-main**, no PRs. The developer commits directly.
- Local validation gate: `sudo bash scripts/dev-reset.sh` → `bash scripts/testing/e2e-test.sh` → `sudo bash scripts/testing/e2e-playwright.sh`. All three must be green before any commit cluster lands.
- Beta-site updates via `sudo bash scripts/test-update.sh` against `test.arkfile.net` (~5 beta users, 1–3 files each). Updates to the beta are gated on the developer's discretion; not every commit cluster ships to beta.
- No commits or pushes are performed by AI assistants. The assistant writes code, runs local tests, and asks the developer to commit.

### 2.2 Greenfield posture: "redefine, don't increment"

There are no production deployments. When a phase changes a binary format (envelope, AAD, schema, etc.) the correct greenfield move is:

- **Keep the existing version byte / column name / format identifier the same.**
- **Change what it means.** The code that wrote `0x01` yesterday and the code that writes `0x01` tomorrow are different specs, and that's fine because there is no production data to preserve.
- **Reject any byte sequence that does not conform to the new definition.** No "try old format, fall back" logic.
- **Existing beta data may become unreadable.** That is the explicit, communicated trade.
- **Old code paths get deleted, not deprecated.** No `// kept for backwards compat with v1` comments per AGENTS.md §"Comment/Log/Print Formatting".

Applied to specific upcoming work:

- Phase 3: the `0x01` envelope marker stays `0x01` but its meaning is **redefined** to mean AAD-bound, file_id-binding chunks/FEK/metadata. The old `0x01` semantics is deleted; the new `0x01` is the only `0x01` the codebase knows.
- Phase 4: share envelope binds KDF params into the JSON structure without bumping a version field. Old envelopes simply fail to parse.
- Phase 1 refresh-token table: greenfield rewrite of the column rather than adding a `v2` table.
- Phase 5 backup-code storage: the schema gets the new column directly; the old `backup_codes_encrypted` column is dropped from the schema. No dual-column transition.

### 2.3 Beta-impact awareness

For every commit cluster that could break login or file access for the ~5 beta users on `test.arkfile.net`, the assistant must:

1. Flag the format-changing event in the phase doc when the phase starts.
2. Re-flag it the moment local validation passes and before recommending `test-update.sh`.
3. Draft the user-facing heads-up message for the beta users (copy-paste ready).

A summary of beta-impact events is maintained in §5 below.

### 2.4 Validation strategy

Each phase has a primary validation surface. The assistant should call out which of the three test scripts is most likely to surface regressions:

- `dev-reset.sh` rebuilds and reseeds; catches build-time, schema, and startup regressions.
- `e2e-test.sh` exercises curl + `arkfile-client` flows; catches API-level regressions in OPAQUE, JWT, upload, download, share, export, billing, admin.
- `e2e-playwright.sh` exercises the browser frontend; catches TS-side regressions in auth, file ops, share, export.

If a phase is likely to regress only one of these, that is noted in the phase's "Validation focus" subsection.

---

## Part 3: Phase-by-Phase Plan

Seven phases total. The ordering interleaves Phase 7 (supply-chain) between Phase 3 and Phase 4; rationale is in §4.

### Phase 1 — "Finish the auth-pathway lockdown"

**Goal:** close the remaining Highs in the auth surface while the code is fresh from the A-01 / F-01 work.

**Findings:**
- **A-13** Bootstrap token not consumed on first redemption → atomic single-use.
- **A-26** Bootstrap token logged in cleartext to stdout → stop logging it.
- **F-03** Bootstrap token harvested from systemd journal → companion to A-26.
- **A-14** Dev/test admin API has no production-environment check → fail-closed at startup if `ENVIRONMENT=production` AND `ADMIN_DEV_TEST_API_ENABLED=true`.
- **A-08** Per-user TOTP failure lockout (DB-backed counter on `user_totp`).
- **A-09** Per-request enforcement of user-wide JWT revocation in `TokenRevocationMiddleware`; shorten full-JWT TTL.
- **A-10** Refresh token: 256-bit instead of 122-bit UUID; reuse-detection that revokes the whole family; replace sliding-window logic.

**Files most likely touched:** `auth/`, `handlers/bootstrap.go`, `handlers/middleware.go`, `models/refresh_token.go`, `auth/token_revocation.go`, `database/unified_schema.sql`.

**Sub-clusters (commit groups within the phase):**
- **1A** Bootstrap-token hardening: A-13 + A-26 + F-03 + A-14. Tight, server-only, no schema change (A-13 may need a `consumed_at` column on the bootstrap token row).
- **1B** Per-user TOTP lockout: A-08. Adds `consecutive_totp_failures` + `last_failed_attempt_at` columns to `user_totp`. Backend-only.
- **1C** JWT and refresh-token hardening: A-09 + A-10. Per-request `IsUserJWTRevoked` lookup; refresh-token entropy bump; family-revoke on reuse detection.

**Validation focus:** `e2e-test.sh` primarily. `e2e-playwright.sh` will catch any TS-side refresh-token regression. `dev-reset.sh` catches the bootstrap-token consumed-on-first-redemption behaviour cleanly.

**Beta impact:** Yellow.
- 1A: invisible to existing users.
- 1B: invisible to existing users.
- 1C: **invalidates all existing sessions.** All 5 beta users have to log in again. Files survive.

**Heads-up message draft (post-1C):**
> "Hi all — pushed an update that strengthens session security. You'll need to log in again on next visit. Your files and account are unchanged."

---

### Phase 2 — "Frontend credential exfiltration class"

**Goal:** stop the largest blast-radius gap (XSS / dep-compromise → password + JWT + refresh token).

**Findings:**
- **A-04 / F-08** Stop stashing plaintext password on `window.totpLoginData`. Keep it as a module-private constant zeroed on TOTP-verify success.
- **A-05 / F-07** Move full JWT + refresh token out of `localStorage` into `__Host-` cookies (Secure, HttpOnly, SameSite=Strict, Path=/) with CSRF double-submit.

**Cookie posture decision:** `__Host-` prefix.
- `Secure` requirement: satisfied by HTTPS in all four deploy modes (including `dev-reset.sh`, which serves on `https://localhost:8443` with a self-signed cert).
- `Path=/` requirement: fine for our usage.
- `Domain` attribute forbidden: cookie is locked to the exact host, immune to subdomain takeover.
- Same code path works in `dev-reset` / `local-deploy` / `test-deploy` / `prod-deploy` with no conditional relaxation.

**Files most likely touched:** `client/static/js/src/utils/auth.ts` (the auth-fetch wrapper, login flow, TOTP flow), `client/static/js/src/__tests__/auth-manager.test.ts`, `handlers/auth.go`, `handlers/middleware.go` (cookie reader + CSRF middleware), `auth/jwt.go` (no change to JWT itself; the transport is what changes).

**Cutover strategy:** **non-overlapping**. Server stops accepting the `Authorization: Bearer` header for browser-origin requests once cookies land. No transitional dual-mode. CLI clients (`arkfile-client`, `arkfile-admin`) continue using `Authorization: Bearer` because they are not browser-origin and cookies do not apply.

**Validation focus:** `e2e-playwright.sh` is the primary surface here. `e2e-test.sh` exercises the CLI clients, which keep using bearer auth, so it should remain green. `dev-reset.sh` will confirm cookie-issuing endpoints work end-to-end.

**Beta impact:** Yellow.
- All 5 beta users: forced re-login + may need to hard-refresh any open tabs.
- No file impact.

**Heads-up message draft:**
> "Hi all — pushed a frontend update that moves session tokens into more secure browser cookies. Please hard-refresh the page (Ctrl-Shift-R / Cmd-Shift-R) and log in again. Files unaffected."

---

### Phase 3 — "Bind AAD everywhere on the file path"

**Goal:** close the cross-slice file-identity authenticity gap. An active server should no longer be able to swap, reorder, or substitute encrypted chunks/FEK/metadata between or within a user's files without detection at the AEAD layer.

**Findings:**
- **B-02** AAD on file chunks: `file_id || chunk_index || chunk_count || ciphertext_sha256`.
- **C-02** Same as B-02 from the upload-handler perspective (server-side).
- **C-03** Bind `chunk_size` + `chunk_count` into AAD so the byte-range math is crypto-anchored, not DB-trust.
- **C-19** Metadata AAD: `file_id || field_name || owner_username`. Fixes the docs-vs-code drift in `models/file.go`.
- **B-08** FEK envelope AAD: `file_id || key_type`.
- **B-05** (Medium, rides along) Chunk reorder/truncation detection — solved structurally by the AAD binding.

**Greenfield approach:** the envelope `0x01` byte stays `0x01` but its semantics is redefined to require AAD-bound chunks / FEK / metadata. The old `0x01` (no-AAD) code paths are deleted, not preserved as fallback. Existing beta files become unreadable.

**Files most likely touched:** `crypto/file_operations.go`, `crypto/envelope.go`, `crypto/gcm.go`, `client/static/js/src/crypto/upload.ts`, `client/static/js/src/crypto/streaming-download.ts`, `client/static/js/src/crypto/types.ts`, `cmd/arkfile-client/` upload + download paths, `handlers/uploads.go`, `handlers/files.go`, `handlers/downloads.go`, `models/file.go`.

**Validation focus:** **All three.** This is the largest cross-language change in the campaign.
- `dev-reset.sh` catches build-time and CGO mismatches.
- `e2e-test.sh` exercises the CLI upload/download/share paths; will catch any Go-side AAD mismatch.
- `e2e-playwright.sh` exercises the browser upload/download paths; will catch any TS-side AAD mismatch.
- Cross-client conformance test (CLI uploads → browser downloads, and vice versa) is essential because the AAD construction must byte-equal across Go and TS.

**Beta impact:** **RED.** This is the single biggest disruption in the campaign.
- All 5 beta users: existing files become unreadable on next visit. Account survives, TOTP survives, login works, but every file shows "unreadable" or fails to decrypt.
- Given 5 users × 1-3 files = ~15 files total, simplest is "re-upload your files".
- Alternative if there is sensitive content: a one-shot migration script that downloads each file with the old AAD-free decrypt path, re-encrypts with the new AAD-bound path, re-uploads. The greenfield principle argues against keeping the old decrypt path in the production code, but a one-shot offline migration tool that uses the old path is fine because it is not part of the shipped binary.

**Heads-up message draft (pre-update):**
> "Heads up — pushing a security update tomorrow that strengthens how files are bound to their identity. Existing uploaded files will no longer be readable after the update; you'll need to re-upload them. Account and login unchanged. If you have files you can't easily re-create, let me know before [date] and I'll arrange a manual re-encryption."

**This phase needs explicit developer go-ahead before `test-update.sh` runs.** The local validation pass can land at any time; the beta push is the gated event.

---

### Phase 7 — "Supply-chain integrity gap" (interleaved here)

**Why here:** right after Phase 3 the codebase is in a known-good state and a context-switch to ops work doesn't lose momentum on a half-finished crypto refactor. Phase 4 will embed JSON params into the shipped binaries and the TS bundle, so the reproducibility / signing posture (F-05) and SRI plumbing (F-04) are most valuable once those frozen params are actually in the artifact. Doing F-13 (frozen lockfile) and F-05 (Go build flags) before Phases 4/5/6 means supply-chain regressions get caught during the remaining app-code work, not after.

**Findings (Highs):**
- **F-04** Subresource Integrity on `libopaque.js` and every shipped asset; build-time hash emission embedded in `index.html`.
- **F-05** Go build flags (`-trimpath`, `-buildid=`, `-ldflags='-s -w'`, `-buildvcs=false`); reproducibility verification in CI; cosign-signed release artifacts.
- **F-06** Vendor libsodium as a pinned git submodule and statically link, instead of host apt/dnf.
- **F-13** `bun install --frozen-lockfile`; drop `^` ranges in `package.json` where they matter.

**Ride-along Mediums to consider:** F-11 (SeaweedFS MD5 → SHA-256), F-12 (rqlite pinning), F-25 (govulncheck + bun audit + SBOM). Pull them in only if they are cheap to grab in the same pass.

**Files most likely touched:** `scripts/setup/build-libopaque-wasm.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/test-deploy.sh`, `scripts/dev-reset.sh`, `client/static/index.html`, `client/static/shared.html`, `client/static/js/package.json`, `client/static/js/bun.lock`, `.gitmodules`, vendored `libsodium/` path, `Makefile` or equivalent build invocation.

**Validation focus:** `dev-reset.sh` is the primary surface. The other two scripts depend on a successful build, so build-flag changes show up there first.

**Beta impact:** **GREEN.** Pure build-time / artifact-integrity changes. Users see nothing different.

---

### Phase 4 — "Parameter floors + share envelope binding"

**Goal:** close the server-controlled crypto parameters downgrade pathway.

**Findings:**
- **B-01** Embed `crypto/argon2id-params.json` as compile-time floors in Go binaries and the TS bundle.
- **B-03** Same treatment for `crypto/chunking-params.json`.
- **B-19** Same for `crypto/password-requirements.json` (Medium, rides along).
- **D-10** Share envelope: bind KDF parameters into the encrypted envelope so a downgrade is detectable on decrypt.
- **D-12** Same root cause (Medium, rides along).
- **C-01** Padding-DoS — bound the server-side `append` allocation. (Medium, but landable here since the chunking-params change is adjacent.)

Treat `/api/config/*` as informational-only after this lands; the security path uses the embedded floors.

**Greenfield approach:** the share-envelope JSON structure gains the KDF-params fields directly. Old envelopes simply fail to parse. No version bump.

**Files most likely touched:** `crypto/argon2id-params.json`, `crypto/chunking-params.json`, `crypto/password-requirements.json`, `crypto/key_derivation.go`, `crypto/share_kdf.go`, `client/static/js/src/crypto/argon2.ts`, `client/static/js/src/crypto/chunking.ts`, `handlers/file_shares.go`, `client/static/js/src/share/` decrypt paths, build scripts that embed the JSON.

**Validation focus:** `e2e-test.sh` and `e2e-playwright.sh` both. The Argon2id parameter conformance test (Go ↔ TS) should be added in CI here.

**Beta impact:** Yellow.
- Existing files unaffected (the Argon2id floors are the same params currently served by `/api/config/argon2`; client encryption keeps producing identical KDF output).
- **Existing shares stop working.** Shares are ephemeral by design, so this is low-coordination cost. Owners can re-share.

**Heads-up message draft:**
> "Pushed a security update that hardens how shared file links are protected. Any active share links will stop working; please re-share files if needed. Your own files and account unaffected."

---

### Phase 5 — "Server-secret single-point-of-compromise" (TOTP material)

**Goal:** make a `system_keys` + DB compromise no longer yield plaintext TOTP backup codes.

**Findings:**
- **A-07** TOTP backup codes hashed per-code via Argon2id, not AES-GCM encrypted under a master key.
- **A-17** `mlock` + `MADV_DONTDUMP` + `PR_SET_DUMPABLE=0` on the TOTP master key page (Medium, rides along).
- **A-18** Move TOTP master key out of `system_keys` into a separately-stored on-disk file with a rotation script (Medium, rides along).
- **A-15** Make TOTP loss-of-device recovery actually reachable — `/api/totp/reset` currently requires a full JWT which requires TOTP. Recovery must be backup-code-based per AGENTS.md "no PII" posture.
- **A-16** UNIQUE on `(username, code_hash)` for backup-code race (Medium, rides along).

**Greenfield approach:** the schema gets the new backup-code-hash columns directly. The old `backup_codes_encrypted` column is dropped. No dual-column transition. Existing backup codes cannot be migrated (we cannot hash a code we never see in cleartext), so existing TOTP enrollments are dropped and users re-enroll.

**Files most likely touched:** `auth/totp.go`, `auth/totp_test.go`, `auth/totp_backup_test.go`, `crypto/totp_keys.go`, `database/unified_schema.sql`, `handlers/auth.go` (reset flow), new `scripts/maintenance/rotate-totp-keys.sh`.

**Validation focus:** `e2e-test.sh` for TOTP setup / verify / auth / reset flows. `e2e-playwright.sh` for the browser TOTP enrollment screen.

**Beta impact:** Yellow.
- All 5 beta users: forced TOTP re-enrollment on next login (existing TOTP secrets and backup codes dropped).
- Account and files survive.

**Heads-up message draft:**
> "Pushed a security update that hardens TOTP storage. On next login you'll be prompted to re-enroll your TOTP authenticator and save new backup codes. Your account and files are unchanged."

---

### Phase 6 — "Pre-payment financial-audit integrity"

**Goal:** make the billing surface ready for real-money integration. The exec summary flags these as Critical-the-moment-Stripe-lands. Cheaper to do now while there is no real money in the system. Developer has confirmed payment integration starts only after all Highs are resolved, so Phase 6 stays last in the High campaign.

**Findings:**
- **E-21** Soft-delete users (`deleted_at TIMESTAMP`) instead of `DELETE FROM users` with `ON DELETE CASCADE` wiping `credit_transactions` and `admin_logs`.
- **E-03** `settleOneUser` reads `user_credits.balance` inside the transaction.
- **E-04** `UNIQUE(transaction_id)` on `credit_transactions` (Medium, rides along — idempotency key).
- **E-05** Persist `lastSweepDate` across restarts (Medium, rides along).
- **E-02** SQL injection in `AdminSyncStatus` — parameterized SQL + `golangci-lint` rule banning `fmt.Sprintf` adjacent to SQL keywords.
- **A-12** Fix `models.User.Delete()` to actually clean up referencing rows (or, post-soft-delete, scrub correctly).

**Greenfield approach:** schema migration is performed in-place against `database/unified_schema.sql` (no migration framework in this codebase). The soft-delete change adds `deleted_at TIMESTAMP` columns and requires every `JOIN users` and every `WHERE username = ?` in the codebase to be audited and updated with `AND deleted_at IS NULL` filters — that is approximately 50 call sites. **Budget a half-day for that audit alone.**

**Files most likely touched:** `database/unified_schema.sql`, `models/user.go`, `models/credits.go`, `models/refresh_token.go`, `billing/scheduler.go`, `billing/sweep.go`, `billing/meter.go`, `handlers/admin_billing.go`, `handlers/admin_storage.go`, every handler doing a user lookup. Plus a one-shot grep for `fmt.Sprintf` near SQL keywords to fix E-02.

**Validation focus:** `e2e-test.sh` exercises the billing scenarios most directly. `dev-reset.sh` catches the schema regression. The user-deletion audit is a manual code-review activity, not a test pass.

**Beta impact:** **GREEN** (assuming `credit_transactions` is empty/small on beta).
- No user-visible change.
- A duplicate-`transaction_id` row in the existing beta DB would block the `UNIQUE(transaction_id)` migration; check first.

---

## Part 4: Phase Ordering and Rationale

```
Phase 1  →  Phase 2  →  Phase 3  →  Phase 7  →  Phase 4  →  Phase 5  →  Phase 6
(auth)      (frontend)   (AAD)      (supply)    (params)    (TOTP)      (billing)
```

**Why this order:**

1. **Phase 1 first** because the code is fresh from the A-01 / F-01 work and several of these (A-08 / A-09 / A-10) share files and concepts with what was just touched. Marginal cost is lowest now.
2. **Phase 2 second** because XSS + token-in-localStorage is the single largest blast-radius gap and it requires a frontend refactor that should land before any other frontend changes. Phase 3's TS crypto changes would have to be re-reviewed against the new auth flow if Phase 2 came after.
3. **Phase 3 third** because the AAD binding is the largest crypto-correctness fix and a coordinated Go + TS + CLI change. It benefits from Phase 2 having stabilized the frontend.
4. **Phase 7 fourth** because it interleaves cleanly after Phase 3 (codebase in known-good state; natural context-switch point) and the SRI / build-flag / frozen-lockfile guarantees catch supply-chain regressions during the remaining Phases 4/5/6 work.
5. **Phase 4 fifth** because the parameter-floor work touches the shipped binaries / TS bundle that Phase 7 just hardened; the SRI + build-flag work is most valuable once the embedded floors are actually in the artifact.
6. **Phase 5 sixth** because it is an internal-only change (no frontend impact post-Phase-2) and includes a schema migration that should not coincide with another schema migration.
7. **Phase 6 last** because it is the largest schema change (soft-delete users) and the user-deletion model is touched by every other system; doing it last lets us migrate once with full knowledge of what references `users`.

### Alternative bucketings considered and rejected

- **Strict "by severity" ordering**: lumps everything into one giant pile and ignores that several Highs share root causes. Bad for reviewability.
- **"By file area" ordering** (all `auth/` Highs first, then `crypto/`, etc.): forces E-21 (high-priority billing) to wait behind a lot of lower-priority `auth/` Mediums, since the file area is dominated by Mediums.
- **"Phase 7 last"** (after Phase 6): defensible. Trade-off is that supply-chain regressions during Phases 4/5/6 work go undetected longer. Mild preference for the interleave at 7→4 position; not a strong objection to moving 7 to the end if developer prefers.
- **"Phase 7 in parallel"**: rejected — single developer, so this is misleading framing.

---

## Part 5: Beta-Impact Summary (format-changing events)

For every event in this table, the assistant will re-flag explicitly when the phase starts and again immediately before `test-update.sh` is recommended, with a copy-paste-ready user message.

| Phase | Format-changing event | Severity | Beta user impact |
|---|---|---|---|
| 1A | None (server-internal) | GREEN | No user-visible change |
| 1B | None (server-internal) | GREEN | No user-visible change |
| 1C | JWT and refresh-token shape changes | YELLOW | Forced re-login. Files survive. |
| 2 | Auth transport changes (Bearer → `__Host-` cookie) | YELLOW | Forced re-login + page refresh. Files survive. |
| 3 | File chunk + FEK envelope + metadata AAD binding | **RED** | **All existing files become unreadable.** Re-upload required. Account + TOTP survive. |
| 7 | None (build-time only) | GREEN | No user-visible change |
| 4 | Share envelope KDF-params binding | YELLOW | Existing shares stop working. Files unaffected. |
| 5 | TOTP backup-code storage redefined | YELLOW | Forced TOTP re-enrollment. Files survive. |
| 6 | Schema additions (soft-delete, UNIQUE) | GREEN | No user-visible change |

Notable: Phase 3 is the only RED. The developer should give beta users explicit advance notice before pushing Phase 3 to `test-update.sh`.

---

## Part 6: Phase 1 Kickoff Plan

Phase 1 is split into three commit clusters. We will land them in order locally and let the developer commit each one before moving on.

### 6.1 Commit cluster 1A: Bootstrap-token hardening (A-13 + A-26 + F-03 + A-14)

**Pre-work (read-only):**
1. Read `handlers/bootstrap.go` end-to-end to map the current bootstrap-token lifecycle.
2. Read `auth/bootstrap.go` (token generation, storage in `system_keys`).
3. Read `scripts/dev-reset.sh` and `scripts/prod-deploy.sh` to find every place the token is currently written to stdout / journal.
4. Identify the existing schema / `system_keys` row layout for the bootstrap token (is there a `consumed_at` column? If not, we'll need to add one).
5. Identify how `ENVIRONMENT=production` and `ADMIN_DEV_TEST_API_ENABLED=true` are read; design the startup fail-closed check for A-14.

**Design decisions to make before coding:**
- Atomic single-use enforcement for the bootstrap token: use a `consumed_at` column (set inside the transaction that creates the first admin) vs. delete-the-row-on-redemption. Probably `consumed_at` is better for forensics.
- Where the dev-admin token / bootstrap token still needs to be communicated to the operator (it does — they have to use it to register the first admin). Options:
  - Write to a 0600 file at a known path (preferred — operator reads it and deletes it).
  - Print only the first N characters and require operator to read the rest from the file.
  - Continue printing but with a clear "this will appear in journald — invalidate after first use" warning.
- A-14 fail-closed timing: probably in `config/config.go` `ValidateProductionConfig`, refusing to start the server if both flags are set.

**Implementation order:**
1. Add `consumed_at` column to bootstrap-token row in `system_keys` (or wherever it lives). Update `database/unified_schema.sql`.
2. Modify the bootstrap-redeem handler in `handlers/bootstrap.go` to perform the consume + first-admin-creation in a single transaction; reject if `consumed_at IS NOT NULL`.
3. Update `auth/bootstrap.go` to write the token to a 0600 file at a configurable path (default: `/opt/arkfile/etc/bootstrap-admin-token`) and remove the stdout / journal print.
4. Update `scripts/dev-reset.sh` to read the token from the file rather than from logs.
5. Add the A-14 fail-closed check to `config/config.go` or `config/security_config.go`.
6. Tests: extend `handlers/bootstrap_test.go` with `TestBootstrapToken_SingleUse`, `TestBootstrapToken_NotInLogs`, `TestProduction_RejectsDevTestAPI`.

**Validation pass:**
- `sudo bash scripts/dev-reset.sh` should succeed and admin-bootstrap should still work (reading the token from the file).
- `bash scripts/testing/e2e-test.sh` should be green.
- `sudo bash scripts/testing/e2e-playwright.sh` should be green.
- New tests must all pass.

**Beta impact:** GREEN. Server-internal change.

### 6.2 Commit cluster 1B: Per-user TOTP lockout (A-08)

(Detailed plan to be drafted after 1A lands.)

### 6.3 Commit cluster 1C: JWT and refresh-token hardening (A-09 + A-10)

(Detailed plan to be drafted after 1B lands. This is the cluster that forces all beta users to re-login.)

---

## Part 7: Status Tracker

Updated as work lands.

| Phase | Cluster | Findings | Status | Notes |
|---|---|---|---|---|
| 1 | 1A | A-13, A-26, F-03, A-14 | Not started | Bootstrap-token hardening |
| 1 | 1B | A-08 | Not started | Per-user TOTP lockout |
| 1 | 1C | A-09, A-10 | Not started | JWT + refresh-token; forces beta re-login |
| 2 | — | A-04, F-08, A-05, F-07 | Not started | Frontend cookies + CSRF; forces beta re-login |
| 3 | — | B-02, C-02, C-03, C-19, B-08, B-05 | Not started | AAD binding; **RED beta impact** |
| 7 | — | F-04, F-05, F-06, F-13 | Not started | Supply-chain hardening; no beta impact |
| 4 | — | B-01, B-03, B-19, D-10, D-12, C-01 | Not started | Parameter floors; breaks existing shares |
| 5 | — | A-07, A-17, A-18, A-15, A-16 | Not started | TOTP material; forces re-enrollment |
| 6 | — | E-21, E-03, E-04, E-05, E-02, A-12 | Not started | Financial-audit schema; no beta impact |

End of plan.
