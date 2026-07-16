# Server Cleanup & E2E Hardening Plan

This plan follows a server-side audit against the Function Review Sanity Checks in docs/AGENTS.md: every handler and helper should be required, correctly implemented, well placed, reachable, privacy-preserving, and free of stubs, deprecated paths, duplicated logic, and leftover "AI slop" (placeholder implementations, fake fallbacks, WIP-planning comments, and redundant branches that exist only because something was never finished). Arkfile is greenfield; test.arkfile.net will be fully redeployed, so we do not keep backwards compatibility for code that is unused, unreachable, or actively misleading (fabricated health metrics, fake admin contacts, revocation that leaves sessions alive, legacy env overrides, and similar). The audit was cross-checked against scripts/testing/e2e-test.sh and scripts/testing/e2e-playwright.sh so we keep what E2E actually exercises and delete or fix what it does not. Where E2E currently hedges (accepting one of several HTTP codes, error strings, or pass-with-warning outcomes), we tighten tests and fix server or client behavior so there is one canonical expected result. We also add coverage for gaps E2E missed: isolated revoke endpoints, refresh after unapproval, real health output, admin contacts contract, and correct preflight probes. The goal is a coherent server surface that matches the privacy-first design, honest operator tooling, and tests that prove it before first production deployment.

Status: complete (implementation) — run dev-reset + e2e locally to verify  
Created: 2026-07-16  
Scope: Greenfield server refactor, CLI alignment, frontend contract cleanup, E2E tightening. No backwards compatibility for unused or stubbed paths.

## Principles

One canonical way per operation (revoke user, health probes, share chunk auth, admin contacts). Fail closed: no fake data, no silent fallbacks that hide misconfiguration. Delete dead code rather than deprecate it (greenfield redeploy at test.arkfile.net). E2E assertions must be exact: one expected HTTP status, one expected message shape, no "A or B also acceptable" unless the product genuinely has two valid outcomes (document why in the test comment). After each workstream: `sudo bash scripts/dev-reset.sh` then `bash scripts/testing/e2e-test.sh`; optionally `sudo bash scripts/testing/e2e-playwright.sh`.

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| User revocation unification | [x] complete | `handlers/admin_user_access.go`, `AdminRevokeUser`, CLI single `/revoke` call |
| Refresh token approval gate | [x] complete | `RefreshToken` returns 403 for unapproved non-admins |
| Admin health: drop disk usage | [x] complete | disk removed; `DefaultHealthMonitor` singleton in `main.go` |
| Admin contacts contract | [x] complete | server + `auth.ts`, `footer.ts`, `list.ts`, `sections.ts` |
| Dead code removal | [x] complete | middleware/helpers, decrypt-check route, tee reader, etc. |
| Legacy compatibility removal | [x] complete | PAYG auto-enable, PROD_PORT/TEST_PORT, chunk defaults, billing fallback, GCM debug |
| Duplicate utility consolidation | [x] complete | `handlers/format.go`, `utils/debug.go` |
| Share auth ticket-only (optional) | [ ] deferred | static `X-Download-Token` fallback kept this pass |
| E2E preflight & health fixes | [x] complete | `/readyz` preflight, health-check in admin ops |
| E2E hedging removal | [x] complete | rate limit, session file, flood guard, set-price, playwright strings |
| New E2E coverage (honest gaps) | [x] complete | admin-contacts, health-check, tightened privacy jq checks |
| Unit and handler tests | [x] complete | contacts, refresh gate, rate limit penalty, UpdateUser reject |

---

## User revocation unification

### Problem

`AdminRevokeUser` and `UpdateUser(is_approved=false)` only flip the database flag; tokens stay valid until a separate `force-logout` call. The `arkfile-admin unapprove-user` and `revoke-user` commands compensate with two HTTP calls. E2E expects one CLI command to do both (`sessions terminated` plus blocked `list-files`).

### Target design

Single internal helper, e.g. in `handlers/admin_user_access.go`:

```
revokeUserAccess(db, username, adminUsername, reason string) error
```

Always atomically (same transaction where practical):

- `UPDATE users SET is_approved = 0 WHERE username = ?`
- `models.RevokeAllUserTokens`
- `auth.RevokeAllUserJWTTokens`
- Security event plus `LogAdminAction`

### Handler changes

| Handler | Change |
|---------|--------|
| `AdminRevokeUser` | Call `revokeUserAccess`; remove standalone flag-only logic |
| `UpdateUser` | When `is_approved` set false, delegate to `revokeUserAccess` (remove "for now, just log" stub) |
| `ApproveUser` | Unchanged (approval only) |

### API surface (greenfield)

Keep `POST /api/admin/users/:username/revoke` as the canonical unapprove/revoke endpoint. Keep `POST /api/admin/users/:username/force-logout` for explicit session kill without unapprove (MFA reset and similar flows already use it). For `PUT /api/admin/users/:username`: either reject `is_approved: false` with 400 directing callers to `/revoke`, or delegate to the same helper. Prefer reject plus documentation to avoid dual paths.

### CLI changes (`cmd/arkfile-admin/main.go`)

| Command | Change |
|---------|--------|
| `unapprove-user` | Single `POST .../revoke`; remove second `force-logout` call |
| `revoke-user` | Same single call |
| Help text | Update to reflect one server round-trip |

### Tests

Extend `handlers/admin_test.go`: revoke via API alone blocks subsequent JWT access (401) without a separate force-logout call. E2E `unapprove-user` section unchanged in intent; should still pass with simpler CLI.

---

## Refresh token approval gate

### Problem

Revoked or unapproved users can rotate refresh tokens via `POST /api/refresh` even when `RequireApproved` blocks other API routes.

### Change

In `handlers/auth.go` `RefreshToken`, after successful `ValidateRefreshToken`:

- Load user via `models.GetUserByUsername`
- If `!user.IsApproved && !user.HasAdminPrivileges()` return 403 with the same wording as `RequireApproved` (`Account pending approval`)

### Tests

New handler test: unapproved user with valid refresh token gets 403. Optional E2E: after `unapprove-user`, `POST /api/refresh` with saved refresh cookie returns 403.

---

## Admin health: drop disk usage

### Problem

`getDiskUsage()` returns hardcoded placeholder values surfaced through `AdminSystemHealth`.

### Changes

| File | Action |
|------|--------|
| `monitoring/health_endpoints.go` | Delete `getDiskUsage` and disk path collection in `getSystemInfo` |
| `monitoring/health_endpoints.go` | Remove `DiskUsage` from `SystemInfo` struct and JSON output |
| `handlers/admin.go` `AdminSystemHealth` | Use shared `HealthMonitor` singleton; drop per-request `NewHealthMonitor` and WIP-planning comment |

### E2E

Add assertion in admin operations: `health-check --json` does not contain placeholder disk values. Wire `arkfile-admin health-check` into e2e if not already present (currently only `system-status` is exercised).

---

## Admin contacts contract

### Problem

Server and client both fabricate `default-admin` and `admin@example.com`. Frontend display layers filter the placeholder in footer and storage UI, and MFA recovery hints return null for the default, but the API still lies on error or empty config, and `auth.ts` seeds the same hardcoded values before fetch.

### Target API (`GET /api/admin-contacts`)

When configured:

```json
{
  "admin_usernames": ["alice"],
  "admin_contact": "ops@example.com",
  "configured": true
}
```

When unset:

```json
{
  "admin_usernames": [],
  "admin_contact": "",
  "configured": false
}
```

On config load failure: 503 with error body, not 200 with fake data.

### Server (`handlers/files.go` `AdminContactsHandler`)

Remove all `default-admin` and `admin@example.com` fallbacks. Read from `config.LoadConfig()`; if `AdminContact` is empty and `AdminUsernames` is empty, return `configured: false`. Config error returns 503.

### Frontend

| File | Change |
|------|--------|
| `client/static/js/src/utils/auth.ts` | Remove hardcoded defaults; store empty until fetch succeeds |
| `client/static/js/src/ui/footer.ts` | Use `configured` flag or empty contact; remove default-string compare hack |
| `client/static/js/src/files/list.ts` | Same pattern for storage contact note |
| `client/static/js/src/__tests__/auth-manager.test.ts` | Update test that expects non-empty default |

### E2E additions

New scenario in admin operations or a dedicated group: `curl /api/admin-contacts` returns 200 with `configured: true` on dev-reset (admin contact set in secrets). Response must not contain `admin@example.com` or `default-admin` unless explicitly configured in test env.

---

## Dead code removal

Delete outright (no callers or superseded):

| Item | Location |
|------|----------|
| `isLocalhostIP` | `handlers/middleware.go` |
| `GetEntityIDForIP`, `GetEntityID` legacy wrappers | `logging/entity_id.go` (update tests to composite-only) |
| `formatFileSize` | `handlers/handlers.go` |
| `RequireAdmin` middleware | `handlers/middleware.go` |
| `StreamingHashTeeReader` and helpers | `handlers/streaming_hash.go` (keep `StreamingHashState`) |
| `HealthHandler`, `ReadinessHandler`, `LivenessHandler`, `MetricsHandler` | `monitoring/health_endpoints.go` |
| Redundant `requireAdmin` / `requireAdminWithUsername` | `handlers/admin_billing.go` |
| Redundant `!adminUser.IsAdmin` checks | `handlers/admin.go` (routes already behind `AdminMiddleware`) |
| Identical if/else branches in `AdminCleanupTestUser` | `handlers/admin.go` |

### Optional dev-only endpoints (not E2E-tested)

| Endpoint | Recommendation |
|----------|----------------|
| `POST /api/admin/dev-test/users/cleanup` | Keep if useful for manual dev; fix incomplete table list or delete |
| `GET /api/admin/dev-test/mfa/decrypt-check/:username` | Delete unless actively used |

### Health monitor singleton

Create `monitoring.DefaultHealthMonitor` at startup in `main.go`. `AdminSystemHealth` uses the singleton instead of per-request allocation.

---

## Legacy compatibility removal

| Item | Action |
|------|--------|
| `config/config.go` PAYG auto-enable when billing enabled | Remove; require explicit `ARKFILE_BILLING_PAYG_ENABLED` |
| `main.go` `PROD_PORT` / `TEST_PORT` / `TEST_DOMAIN` overrides | Remove; use config only |
| `handlers/file_shares.go` legacy chunk zero-defaults | Remove; require non-zero `chunk_count` / `chunk_size_bytes` in DB |
| `billing/rates.go` hardcoded `$10.00` safety fallback | Fail startup or first tick with clear error (E2E always sets price first) |
| WIP-planning comments in handlers | Remove or replace with in-situ descriptions |
| `crypto/gcm.go` DEBUG_MODE byte dumps | Remove debug prints of nonce and ciphertext material |

---

## Duplicate consolidation

| Duplicates | Target |
|------------|--------|
| `formatBytes` in `admin.go` and `files.go` | `handlers/format.go` |
| `isDebugMode` in `auth/mfa_internal.go` and `crypto/gcm.go` | Single shared helper (e.g. `utils/debug.go`) |
| `emptyOrValue` / `defaultString` in CLI packages | Shared helper under `cmd/internal/` if worth it; else separate pass |

---

## Share chunk auth ticket-only (optional / deferrable)

### Rationale

Ticket is the primary path (CLI, browser, e2e ticket tests). Static `X-Download-Token` fallback is legacy.

### If done in this pass

- Remove static token branch from `validateShareDownloadCredential` in `handlers/file_shares.go`
- Remove CLI fallback in `setShareAuthHeader` (`cmd/arkfile-client/commands.go`)
- Update e2e invalid-credential test to use bad `X-Share-Ticket` instead of `X-Download-Token`
- Standardize rate limiter to return 429 after threshold (see E2E hedging removal)

Defer if scope is too large; track as follow-up.

---

## E2E preflight and health fixes

### Problem

`e2e-test.sh` and `e2e-playwright.sh` curl `$SERVER_URL/health` without `-f`. Server exposes `/healthz` and `/readyz`.

### Changes

| Script | Change |
|--------|--------|
| `e2e-test.sh` preflight | `curl -sf "$SERVER_URL/readyz"` expect 200 and ready status |
| `e2e-playwright.sh` | Same |
| `scripts/maintenance/renew-certificates.sh` | Align to `/healthz` or `/readyz` |

---

## E2E hedging removal

Tighten assertions. Fix handlers if product behavior is ambiguous.

| Location | Current hedge | Target |
|----------|---------------|--------|
| `e2e-test.sh` invalid download token rate limit | PASS on 429 or any other code on fifth attempt | Require 429; fix rate limiter if needed |
| `e2e-test.sh` invalid token attempts 1-4 | Accept 403 or 429 | Require 403 for invalid credential; 429 only after threshold |
| `e2e-test.sh` raw list/shares API privacy | grep-based OR logic | Use `jq` on structured JSON; assert encrypted fields present, plaintext absent |
| `e2e-test.sh` session file after revoke-all | PASS even if file still exists (with warning) | FAIL if session file remains |
| `e2e-test.sh` flood guard security event | Try `suspicious_pattern` then `endpoint_abuse` | Standardize one event type in `handlers/flood_guard.go` |
| `e2e-playwright.ts` duplicate upload rejection | `duplicate` OR `already uploaded` OR `already exists` | Standardize server/CLI error string; assert exact substring |
| `e2e-playwright.ts` wrong custom password | four alternative strings | One canonical client error message |
| `e2e-playwright.ts` share error states (expiry, max downloads, revoked, non-existent) | many `includes(...)` alternatives | Prefer stable DOM ids or `data-testid` plus exact copy from error pages |
| `e2e-test.sh` set-price assertion | `grep -qE "2711\|microcents"` | Assert exact JSON field via `--json` and `jq` |

### Handler changes implied

Share invalid-token rate limit: deterministic 429 after N failures. Flood guard: one security event type for unauthorized flood. Duplicate upload: consistent HTTP status and message from `handlers/uploads.go`. Wrong password decrypt: consistent error from client after failed decrypt.

---

## New E2E coverage (honest gaps)

Add to `e2e-test.sh` (new scenarios or extend admin operations):

| Gap | Test |
|-----|------|
| `POST /api/admin/users/:user/revoke` alone | `revoke-user --confirm` without separate force-logout; verify `list-files` blocked |
| Refresh after revoke | Save refresh token before revoke; `POST /api/refresh` returns 403 |
| `health-check --detailed` | No fake disk; components reflect real DB and storage |
| `/api/admin-contacts` | Contract per admin contacts section |
| Preflight `/readyz` | See E2E preflight section |
| `UpdateUser is_approved:false` via API | If API rejects, assert 400; if delegates, assert tokens revoked without second call |

### Playwright additions (lower priority)

Footer shows `not configured` only when contact empty. Dev-reset with real contact shows real email. Optional: assert `/api/admin-contacts` `configured` via `page.evaluate` fetch.

---

## Unit and handler tests

| Area | Tests |
|------|-------|
| `revokeUserAccess` | Token and refresh invalidation, approved flag |
| `RefreshToken` | Unapproved user rejected |
| `AdminContactsHandler` | Empty config, configured config, config error 503 |
| Rate limiter | Fifth bad share chunk credential returns 429 |
| Removed legacy chunk defaults | Share metadata missing chunks returns error, not silent default |

---

## Suggested implementation order

User revocation unification and refresh token approval gate first (security correctness). Admin contacts contract next. Drop disk from admin health. E2E preflight, hedging removal, and new gap coverage in the same wave as the behavior fixes they depend on. Dead code removal, legacy compatibility removal, and duplicate consolidation after core behavior is stable. Share ticket-only auth optional last. Unit tests throughout.

---

## Verification checklist (final)

- [ ] `sudo bash scripts/dev-reset.sh`
- [ ] `bash scripts/testing/e2e-test.sh` — all PASS, zero SKIP unless documented
- [ ] `sudo bash scripts/testing/e2e-playwright.sh` — all PASS
- [ ] `go test ./handlers/... ./monitoring/... ./logging/...` — pass
- [ ] Manual: `arkfile-admin health-check --detailed` — no disk section
- [ ] Manual: `curl -s /api/admin-contacts | jq` — no fake defaults on dev instance
- [ ] Grep server handlers for `default-admin`, `admin@example.com`, WIP-planning comment patterns, `for now`, `Backward compatibility` — zero inappropriate hits

---

## Out of scope (this document)

CLI `formatFileSize` and section divider cleanup in `cmd/arkfile-client`. Full ticket-only share auth if deferred. Production deploy script changes beyond health URL alignment.

## E2E-confirmed hot paths (do not delete without replacement)

| Area | Endpoints / handlers |
|------|----------------------|
| Auth | OPAQUE register/login, reregister, bootstrap, MFA setup/verify/auth, refresh, logout, revoke-all |
| Files | uploads init/chunks/complete, file list/meta/delete, chunked download |
| Shares | `/api/shares`, `/api/public/shares/:id/{envelope,ticket,metadata,chunks}`, `/shared/:id` via `GetSharedFile` |
| Admin | list/approve/update users, force-logout, MFA reset, security-events, storage ops, billing, payments, subscriptions |
| Dev/test only | `/api/admin/dev-test/billing/tick-now`, `/api/admin/dev-test/registration-throttle/reset` |
| Billing/payments | credits, invoice create, BTCPay and subscription-bridge webhooks |
| Probes | `main.go` inline `/healthz` and `/readyz` |

## Not exercised by E2E (safe to remove or must add coverage)

- `arkfile-admin health-check` to `GET /api/admin/system/health` (e2e uses `system-status` only today)
- `POST /api/admin/users/:username/revoke` in isolation (e2e uses `unapprove-user` which hits `UpdateUser` plus `force-logout`)
- `POST /api/admin/dev-test/users/cleanup`
- `GET /api/admin/dev-test/mfa/decrypt-check/:username`
- `monitoring` package HTTP handlers (`HealthHandler`, etc.) — superseded by `main.go` probes
