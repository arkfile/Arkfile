# Arkfile High-Priority Issues — Phased Remediation Plan

Companion to `docs/wip/review/00-executive-summary.md`. Working plan for resolving the High-severity findings now that both Criticals (F-01 and A-01) are closed. Phases are lettered A–H; each phase is **self-contained** so a fresh agentic session can pick up at any phase by reading the front-matter (§1–§4) plus that one phase's section.

---

## §1. Resuming After a Break (start here)

If you (human or agent) are coming back to this project after a break:

1. **Read this section + §2 (Operating Principles) + §3 (Threat Model) + §4 (At-Rest Key Inventory).** That's the shared cross-cutting context.
2. **Open §6 (Status Tracker).** Find the first phase or cluster marked `Not started`. That's where work resumes.
3. **Read only that phase's section in §5.** Each phase is self-contained with its own pre-work / design / implementation / validation / beta-impact subsections.
4. **Do not start a new phase until the previous one's validation pass is green** (`dev-reset.sh` + `e2e-test.sh` + `e2e-playwright.sh`).
5. **Before pushing to beta (`test-update.sh`), check §5's "Beta impact" subsection for the phase that just landed.** Some phases require advance heads-up to the ~5 beta users.

If a phase you're in is incomplete (some sub-clusters done, others not), the Status Tracker tells you which sub-clusters need work and which are already validated.

---

## §2. Operating Principles

### §2.1 Workflow

- **Direct-to-main**, no PRs. Developer commits directly.
- Local validation gate: `sudo bash scripts/dev-reset.sh` → `bash scripts/testing/e2e-test.sh` → `sudo bash scripts/testing/e2e-playwright.sh`. All three must be green before any commit cluster lands.
- Beta-site updates via `sudo bash scripts/test-update.sh` against `test.arkfile.net` (~5 beta users, 1–3 files each). Updates to beta are gated on developer discretion; not every commit ships to beta.
- No commits or pushes are performed by AI assistants. Assistants write code, run local tests, draft heads-up messages, and ask the developer to commit.

### §2.2 Greenfield posture: "redefine, don't increment"

There are no production deployments. When a phase changes a binary format (envelope, AAD, schema), the correct greenfield move is:

- **Keep the existing version byte / column name / format identifier the same.**
- **Change what it means.** The code that wrote `0x01` yesterday and the code that writes `0x01` tomorrow are different specs; that's fine because there is no production data to preserve.
- **Reject any byte sequence that does not conform to the new definition.** No "try old format, fall back" logic.
- **Existing beta data may become unreadable.** That is the explicit, communicated trade.
- **Old code paths get deleted, not deprecated.** No `// kept for backwards compat with v1` comments per AGENTS.md §"Comment/Log/Print Formatting".

### §2.3 Beta-impact awareness

For every commit cluster that could break login or file access for the ~5 beta users on `test.arkfile.net`, the assistant must:

1. Flag the format-changing event in the phase doc when the phase starts.
2. Re-flag it the moment local validation passes and before recommending `test-update.sh`.
3. Draft the user-facing heads-up message (copy-paste ready).

Color codes used throughout:
- **GREEN** — invisible to users.
- **YELLOW** — forces re-login / re-enroll / hard-refresh; account + files survive.
- **RED** — destroys existing files or other user data; requires advance heads-up.

A consolidated beta-impact table appears in §5 (one row per phase) and is also re-stated in each phase's "Beta impact" subsection.

### §2.4 Validation strategy

Three local test scripts:

- `dev-reset.sh` — rebuilds, reseeds, nukes data. Catches build-time, schema, and startup regressions.
- `e2e-test.sh` — `curl` + `arkfile-client` flows. Catches API-level regressions in OPAQUE, JWT, upload, download, share, export, billing, admin.
- `e2e-playwright.sh` — browser flows. Catches TS-side regressions.

Each phase calls out its primary validation surface.

---

## §3. Threat Model (plain-language)

This is the precise statement of what an attacker can and cannot do against Arkfile, before and after this remediation plan completes. The threat-table covers the three realistic compromise levels.

### §3.1 What Arkfile *never* gives up

Regardless of compromise level, the following are protected by client-side cryptography and are not recoverable from the server:

| Asset | Why it's safe |
|---|---|
| User passwords | OPAQUE protocol: password never reaches the server. |
| File contents | Encrypted client-side (browser via Web Crypto / CLI via Go `crypto/aes`) under a random per-file FEK. The Arkfile process holds only ciphertext + nonce + tag at every step in the pipeline. |
| File metadata (filename, plaintext SHA-256) | Encrypted client-side under the Account-KEK before upload. |
| FEKs | Generated client-side per file; wrapped under Argon2id-derived KEK from the user's password; never reach the server unwrapped. |
| Share envelopes (content) | Decrypted by the recipient's client. The server holds opaque blobs. |
| Account-KEKs / Custom-KEKs / Share-KEKs | Derived only on the client from passwords the server never sees. |

These claims hold today and continue to hold throughout the remediation plan.

### §3.2 Threat-level table (current state vs. post-plan)

| Capability | DB-only leak (today) | DB + `secrets.env` leak (today) | Live root on host (today) | Post-Phase-F | Post-Phase-C |
|---|---|---|---|---|---|
| Log in as a user | No | No | No | No | No |
| Read user file contents | No | No | No | No | No |
| Read user file metadata (filename, sha256) | No | No | No | No | No |
| Read user TOTP secrets | No | **Yes** | **Yes** | No (DB-only or `secrets.env`-only) | unchanged |
| Read user TOTP backup codes | No | **Yes** | **Yes** | **No (ever — hashed)** | unchanged |
| Read user contact info | No | **Yes** | **Yes** | No (DB-only or `secrets.env`-only) | unchanged |
| Forge JWTs | No | **Yes** | **Yes** | unchanged | unchanged |
| Impersonate the OPAQUE server in future logins | No | **Yes** | **Yes** | unchanged | unchanged |
| Substitute / reorder / swap encrypted file chunks (active attack) | n/a | n/a | **Yes** (detected only by end-of-file SHA-256, post-disk-write) | unchanged | **No (detected at AEAD layer per-chunk)** |
| Downgrade future client KDFs by tampering `/api/config/argon2` | n/a | n/a | **Yes** | unchanged | unchanged (Phase E closes this) |
| Substitute the served WASM `libopaque.js` | n/a | n/a | **Yes (no SRI)** | unchanged | unchanged (Phase D closes this) |
| Learn usernames | Yes | Yes | Yes | unchanged | unchanged |
| Learn file sizes (padded) and upload times | Yes | Yes | Yes | unchanged | unchanged |

**Key takeaways:**

1. **File contents are always safe** against any server-side compromise. This is the foundational Arkfile claim and it holds.
2. **Today**, an attacker with `secrets.env` recovers TOTP / backup codes / contact info. Phase F closes this against the most realistic leak scenarios (DB-only or `secrets.env`-only) by relocating user-secret material to a separate filesystem path (`/opt/arkfile/etc/keys/user-secret-master.bin`).
3. **Today**, an attacker with live root can actively manipulate the system (chunk substitution, KDF downgrade, WASM substitution). Phases C / E / D close each of these.
4. **Live root with active manipulation** is qualitatively the hardest threat. After Phases C / D / E / F land, even live root cannot read TOTP backup codes (hashed; one-way), cannot substitute chunks undetected (AAD per-chunk), cannot downgrade KDFs (compile-time floors), and cannot substitute the WASM blob undetected (SRI).

### §3.3 What HSM / TEE / KMS would and wouldn't add

Worth being honest about:

- **TPM-sealed Tier-3 file** (small add-on, can follow Phase F): defends a stolen disk image / cold VPS snapshot from yielding the file in cleartext. Cheap; no operational complexity.
- **OS keyring (`keyctl`)** : defends filesystem snapshots and casual root, not live debugger-attached root.
- **TEE (SGX, SEV, Nitro Enclaves)**: in theory defends against live root, but has a long history of side-channel issues; conflicts with the "self-hosted, no external vendor trust" philosophy of Arkfile.
- **External HSM / Cloud KMS**: changes the trust anchor from operator-filesystem to vendor; conflicts with the Arkfile thesis. Appropriate only for enterprise customers with compliance requirements.

The recommended stopping point for the foreseeable future is Phase F's Tier-3-filesystem split, with optional TPM-sealing as a follow-on.

---

## §4. At-Rest Key Inventory (current state)

Today, **nine** server-side keys exist, all generated by `KeyManager` and stored in the `system_keys` DB table, encrypted under wrapping keys HKDF-derived from `ARKFILE_MASTER_KEY` (env var in `/opt/arkfile/etc/secrets.env`).

### §4.1 The nine keys

| key_id | keyType | size | Purpose |
|---|---|---|---|
| `jwt_signing_key_temp_v1` | `jwt` | 32 B | Ed25519 seed for temp (post-OPAQUE, pre-TOTP) JWTs |
| `jwt_signing_key_full_v1` | `jwt` | 32 B | Ed25519 seed for full (post-TOTP) JWTs |
| `opaque_server_private_key` | `opaque` | 32 B | OPAQUE skS — server's static private key |
| `opaque_server_public_key` | `opaque` | 32 B | OPAQUE pkS — generated independently (A-27: should be derived from skS) |
| `opaque_oprf_seed` | `opaque` | 32 B | OPRF seed used by libopaque |
| `totp_master_key_v1` | `totp` | 32 B | Master key; HKDF-derives per-user TOTP encryption keys |
| `bootstrap_token` | `bootstrap` | 32 B | One-shot admin-bootstrap secret (A-13: not currently single-use) |
| `entity_id_master_key_v1` | `entity_id` | 32 B | HMAC key for hashing visitor IPs into EntityIDs |
| `contact_info_*` | `contact_info` | 32 B | Wraps user contact-info payloads |

### §4.2 Downstream derivations

- **TOTP master key** → `HKDF-SHA256(totpMasterKey, info="ARKFILE_TOTP_USER_KEY:<username>")` → per-user 32 B → AES-256-GCM encrypts `user_totp.secret_encrypted` AND `user_totp.backup_codes_encrypted`.
- **EntityID master key** → `HMAC-SHA256(entityIDMasterKey, day_bucket || client_ip)` → daily-rotating EntityID for rate-limiting.
- **JWT keys** → directly used as Ed25519 seeds.
- **OPAQUE keys** → fed directly into libopaque.
- **Bootstrap token** → directly compared against operator-supplied value.
- **Contact-info key** → directly used as AES-GCM key for contact info rows.

### §4.3 Tier assignment after Phase F (the holistic redesign)

Phase F splits these keys into trust tiers based on what compromise they enable.

| Tier | Storage | Keys assigned | What a tier-only compromise yields |
|---|---|---|---|
| **Tier-1: operational** | `system_keys` DB table, wrapped under `ARKFILE_MASTER_KEY` (env var) | `jwt_signing_key_temp_v1`, `jwt_signing_key_full_v1`, `bootstrap_token` | Forced re-login; bootstrap re-issuance |
| **Tier-2: server identity** | `system_keys` DB table, wrapped under `ARKFILE_MASTER_KEY` | `opaque_server_private_key`, `opaque_server_public_key` (derived per A-27), `opaque_oprf_seed`, `entity_id_master_key_v1` | Server impersonation in future logins (OPAQUE still resists past-password recovery); EntityID correlation |
| **Tier-3: user-secret-wrapping** | New file `/opt/arkfile/etc/keys/user-secret-master.bin` (32 B, mode 0400, owned by `arkfile` user). **Not in the DB.** | `totp_user_master`, `contact_info_master` (HKDF-derived from the Tier-3 file) | Limited to TOTP secrets + contact info; backup codes remain safe (hashed) |

Bootstrap token in Phase A1 lives in `/opt/arkfile/etc/keys/bootstrap-token.bin`. This is a delivery-channel choice for a Tier-1 secret (forced re-issuance if leaked; not user-secret-wrapping), **not** a Tier-3 prototype. The actual Tier-3 design — long-lived 32 B master loaded once at process start, mlock'd, `MADV_DONTDUMP`'d, `PR_SET_DUMPABLE=0`, HKDF-expanded into per-purpose subkeys, and rotated via a dedicated script — lands in Phase F (cluster F1).

---

## §5. Phases A–H

### Phase A — Auth-pathway lockdown

**Why this phase:** the auth surface was the focus of the recent A-01 / F-01 work. The remaining Highs in `auth/` are cheap to close while the code is fresh.

**Findings closed:** A-13, A-26, F-03, A-14, A-08, A-09, A-10.

**Files most likely touched:** `auth/bootstrap.go`, `handlers/bootstrap.go`, `handlers/middleware.go`, `auth/token_revocation.go`, `auth/jwt.go`, `models/refresh_token.go`, `auth/totp.go`, `database/unified_schema.sql`, `scripts/dev-reset.sh`, `scripts/prod-deploy.sh`, `scripts/local-deploy.sh`, `scripts/test-deploy.sh`, `config/config.go` or `config/security_config.go`.

**Greenfield notes:** the bootstrap-token row schema gets a `consumed_at` column. The refresh-token table layout changes (entropy bump + family-revoke columns); per greenfield posture, rewrite the column rather than adding a `_v2` table.

#### Cluster A1 — Bootstrap-token hardening

**Findings:** A-13 (single-use), A-26 (no stdout logging), F-03 (no journal logging), A-14 (production-env fail-closed).

**Pre-work:**
1. Read `handlers/bootstrap.go` end-to-end to map the bootstrap-token redemption lifecycle.
2. Read `auth/bootstrap.go` (token generation, storage in `system_keys`).
3. Read `scripts/dev-reset.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/test-deploy.sh` to find every place the token is written to stdout / journal / log file.
4. Identify the existing `system_keys` row layout for the bootstrap token.
5. Identify how `ENVIRONMENT=production` and `ADMIN_DEV_TEST_API_ENABLED=true` are read at startup; locate the right place for a fail-closed check.

**Design decisions:**
- Atomic single-use enforcement: add `consumed_at TIMESTAMP` to the bootstrap-token row, set inside the transaction that creates the first admin. Reject redemption if `consumed_at IS NOT NULL`.
- Communicate the bootstrap token to the operator via a file at `/opt/arkfile/etc/keys/bootstrap-token.bin` (mode 0400, owned by `arkfile` user). Remove all stdout / journal prints. This is purely a delivery-channel choice for the bootstrap token (which is Tier-1 by trust level); it does not constitute the Tier-3 secret store. The actual Tier-3 design (long-lived master + HKDF-expand to per-purpose subkeys + mlock'd in process memory + rotation) lands in Phase F.
- For `dev-reset.sh`, the script reads the token from the file after server startup. No piping through systemd journal.
- A-14 fail-closed: in `config/security_config.go` `ValidateProductionConfig` (or wherever production-mode invariants are asserted), refuse to start if `ENVIRONMENT=production` AND `ADMIN_DEV_TEST_API_ENABLED=true`.

**Implementation order:**
1. Add `consumed_at TIMESTAMP` to the bootstrap-token row (or use a dedicated `bootstrap_token` table — pick whichever is cleaner). Update `database/unified_schema.sql`.
2. Modify the bootstrap-redeem handler in `handlers/bootstrap.go` to perform consume + first-admin creation in a single transaction.
3. Update `auth/bootstrap.go` to write the token to `/opt/arkfile/etc/keys/bootstrap-token.bin` (mode 0400). Remove stdout / journal prints.
4. Update each deploy script to expect the file and read it (or print the path, not the content).
5. Add the A-14 fail-closed check to `config/security_config.go`.
6. Add tests: `TestBootstrapToken_SingleUse`, `TestBootstrapToken_NotInLogs`, `TestProduction_RejectsDevTestAPI`.

**Validation pass:**
- `sudo bash scripts/dev-reset.sh` succeeds; first-admin registration works using the token from the file; second redemption attempt fails.
- `bash scripts/testing/e2e-test.sh` green.
- `sudo bash scripts/testing/e2e-playwright.sh` green.
- New tests pass.

**Validation focus:** `dev-reset.sh` is primary (the bootstrap flow runs at startup). `e2e-test.sh` second.

**Beta impact:** GREEN. Server-internal change only.

#### Cluster A2 — Per-user TOTP failure lockout

**Findings:** A-08.

**Pre-work:**
1. Read `auth/totp.go` and `auth/totp_test.go` to understand current verification flow.
2. Read `handlers/auth.go` TOTP-related handlers for failure-count placement.
3. Confirm `user_totp` table layout in `database/unified_schema.sql`.

**Design decisions:**
- Add three columns to `user_totp`: `failed_attempts_in_window INTEGER NOT NULL DEFAULT 0`, `window_started_at TIMESTAMP`, `last_failed_attempt_at TIMESTAMP`.
- The "window" is a rolling 24 hour bucket. On each failed verification:
  - If `window_started_at` is NULL or older than 24 hours, reset the window: `window_started_at = now()`, `failed_attempts_in_window = 1`, `last_failed_attempt_at = now()`.
  - Otherwise: increment `failed_attempts_in_window`, set `last_failed_attempt_at = now()`.
- Successful verification clears all three columns to NULL / 0.
- **Soft lockout (exponential backoff):** within the current 24 hour window, after 10 failures, refuse further attempts until `last_failed_attempt_at + backoff(failed_attempts_in_window)`. Backoff is exponential: failure 10 → 1 minute, 11 → 2 minutes, 12 → 4 minutes, …, capped at 60 minutes per attempt.
- **Hard daily cap:** after 30 failures within the same 24 hour window, refuse all further TOTP attempts until `window_started_at + 24h`. At this point the only recovery path is via backup code through the F5 lost-device flow (which is independent of TOTP verification and has its own rate-limit via EntityID).
- Emit a `TOTPFailureLockout` security event on each state transition (entering soft backoff, entering hard daily cap, recovering on first success after a lockout).
- No CAPTCHA or interactive step is added; the rate envelope is purely time-based so the legitimate user can recover without operator intervention.

**Implementation order:**
1. Schema additions in `database/unified_schema.sql` (three new columns on `user_totp`).
2. Helper `func computeLockoutState(row userTOTPState, now time.Time) (allowed bool, retryAfter time.Duration, reason string)` so the handler logic stays declarative.
3. Wire the helper into the TOTP verification handler; on the failure path, increment + persist before returning.
4. Security event emission on each state transition.
5. Tests: soft-lockout entry at attempt 11; exponential growth of `retry_after`; hard daily cap at attempt 31; recovery on first success clears state; rolling-24h window resets after 24h of silence.

**Validation pass:** `e2e-test.sh` covers TOTP flows directly. Add a new test that drives 30 consecutive failures and asserts the daily-cap response.

**Beta impact:** GREEN. Server-internal.

#### Cluster A3 — JWT + refresh-token hardening

**Findings:** A-09 (per-request user-wide JWT revocation), A-10 (refresh-token entropy + family-revoke).

**Pre-work:**
1. Read `auth/token_revocation.go` to map the existing revocation tables and middleware.
2. Read `models/refresh_token.go` and `auth/jwt.go` to understand current refresh-token format and storage.
3. Confirm the full-JWT TTL default (`utils.GetJWTTokenLifetime()`). **Decision (2026-05-15):** 30 minutes is the intentional TTL. Per-request user-wide revocation via `user_jwt_revocations` + `TokenRevocationMiddleware` is fully implemented and tested (A3 Done), eliminating the blast-radius concern that motivated a shorter TTL. No change needed.

**Design decisions:**
- **A-09 (per-request user-wide revocation):** `TokenRevocationMiddleware` adds a per-request lookup against a `user_jwt_revocations` table that records the latest "revoke all JWTs for this user" event. The middleware compares `claims.IssuedAt` against `user_jwt_revocations.revoked_at`; if the JWT was issued before the revocation, it is rejected regardless of remaining TTL. Used by force-logout (admin), revoke-all (self), and the A-10 family-revoke path below.
- **A-10 (refresh-token entropy):** refresh tokens become 32 cryptographically-random bytes (256 bits) generated via `crypto/rand`, replacing `uuid.NewV4()` (which produces only 122 bits of entropy). The raw token is returned to the client; only `SHA-256(raw)` is persisted in `refresh_tokens.token_hash`. This matches the entropy and at-rest posture of the bootstrap token and download tokens.
- **A-10 (family-revoke on reuse detection):** every refresh-token row gains two columns:
  - `family_id BLOB NOT NULL` — a 16-byte random value identifying the chain of refresh tokens that originated from a single login event. R0 (first refresh issued at login), R1 (issued when client used R0), R2 (issued when client used R1), etc., all share the same `family_id`.
  - `superseded_by_hash BLOB` — the SHA-256 hash of the next token in the chain, populated when the row is rotated; NULL while the row is the active head of its family.
- **Reuse-detection logic in the refresh handler:**
  1. Look up the incoming token by `token_hash`. If no row exists, return 401 (unknown token).
  2. If `superseded_by_hash IS NOT NULL`, this token has already been rotated past — this is the reuse trip. Inside a single transaction, set a `family_revoked_at` marker on every row sharing the same `family_id`, write a `user_jwt_revocations` entry for the affected user (so any outstanding full JWTs from this family are also invalidated per A-09), emit a `RefreshTokenReuseDetected` security event, and return 401.
  3. If the row has its own `family_revoked_at` set, return 401 (family already revoked).
  4. Otherwise this is a legitimate rotation. Generate a new 256-bit refresh token. In a single transaction: insert the new row with the same `family_id` and `superseded_by_hash IS NULL`; set `superseded_by_hash = SHA-256(new_raw)` on the consumed row. Return the new token to the client.
- The reuse-detection pattern follows RFC 6819 §5.2.2.3 ("Refresh Token Replay Detection").
- **Full-JWT TTL:** 30 minutes (default in `utils.GetJWTTokenLifetime()`). Per-request user-wide revocation via `user_jwt_revocations` + `TokenRevocationMiddleware` is fully implemented and tested (A3 Done), so force-logout and revoke-all are immediately effective regardless of remaining TTL. No change to the default is warranted; 30 minutes avoids unnecessary UX friction from overly frequent token refreshes.

**Implementation order:**
1. Schema additions: `refresh_tokens.family_id BLOB NOT NULL`, `refresh_tokens.superseded_by_hash BLOB`, `refresh_tokens.family_revoked_at TIMESTAMP`. New table `user_jwt_revocations(username TEXT PRIMARY KEY, revoked_at TIMESTAMP NOT NULL)`.
2. Refactor refresh-token generation in `auth/` to use `auth.GenerateRefreshToken()` returning 32 random bytes (raw + hash). Remove the `uuid.NewV4()` path entirely.
3. Implement the four-step refresh handler logic above, including the family-revoke transaction.
4. Add `IsUserJWTRevoked(username, issuedAt)` lookup to `TokenRevocationMiddleware`. Cache aggressively in-process (with TTL) to avoid a per-request DB round-trip; cache invalidation on revocation write.
5. Tests:
   - Family-revoke: present R0 to refresh; receive R1. Present R0 a second time; expect 401, full family revoked, security event emitted, user_jwt_revocations row written.
   - Per-request user-wide revocation: log in (get JWT_a); admin force-logout the user; immediately replay JWT_a to a protected endpoint; expect 401 without waiting for TTL.
   - Refresh-token entropy: assert generated tokens are exactly 32 bytes from `crypto/rand` (not UUIDs).
   - Family-revoke also writes user_jwt_revocations so existing full JWTs from the reuse-detected family are also invalidated.

**Validation pass:**
- `e2e-test.sh` exercises refresh-token rotation in the CLI flow.
- `e2e-playwright.sh` exercises browser refresh handling.

**Beta impact:** **YELLOW.** All 5 beta users will be forced to log in again on next visit (existing JWTs / refresh tokens become invalid). Files survive.

**Heads-up message draft (post-A3):**
> "Hi all — pushed an update that strengthens session security. You'll need to log in again on next visit. Your files and account are unchanged."

---

### Phase B — Frontend credential exfiltration class

**Why this phase:** the largest blast-radius gap in the system today is browser-side credential exposure. XSS / dependency-compromise / browser-extension reach yields JWT + refresh token (in localStorage) and (briefly) the plaintext password (on `window.totpLoginData`). Closing this requires a coordinated frontend + backend refactor and should land before any further frontend changes.

**Findings closed:** A-04, A-05, F-07, F-08.

**Files most likely touched:** `client/static/js/src/utils/auth.ts`, `client/static/js/src/login.ts`, `client/static/js/src/totp.ts`, `client/static/js/src/totp-setup.ts`, `client/static/js/src/__tests__/auth-manager.test.ts`, `handlers/auth.go`, `handlers/middleware.go` (new cookie reader + CSRF middleware), `auth/jwt.go` (no change to JWT itself; transport changes).

**Greenfield notes:** non-overlapping cutover. Browser and CLI authenticate via different transport mechanisms (cookies vs. bearer header) without any UA-sniffing or Origin-inspection. CLI clients (`arkfile-client`, `arkfile-admin`) keep using `Authorization: Bearer` because they never set cookies; browser clients use cookies exclusively. No transitional dual-mode.

#### Pre-work

1. Read `client/static/js/src/utils/auth.ts` end-to-end. Map every read of `localStorage.getItem('token')` / `'refresh_token'` / `'temp_token'`. Map every write of the same.
2. Read `client/static/js/src/login.ts` and the TOTP flow to find every reference to `window.totpLoginData` and the plaintext password.
3. Read `handlers/auth.go` to map the current login → temp-token → TOTP-verify → full-token issuance flow.
4. Identify the auth-fetch wrapper that adds `Authorization: Bearer ...` to every request — that's where the cookie-based flow replaces the header-based flow.
5. Check the Caddyfile and any nginx/proxy header-handling for cookie passthrough.

#### Design decisions

- **Cookie posture: `__Host-` prefix.**
  - `Secure` required: satisfied by HTTPS in all four deploy modes (`dev-reset.sh` serves on `https://localhost:8443`).
  - `Path=/` required: fine for our usage.
  - `Domain` forbidden: cookie locked to the exact host, immune to subdomain takeover.
- Three cookies issued at login:
  - `__Host-arkfile-token` — full JWT, HttpOnly, Secure, SameSite=Strict, Path=/.
  - `__Host-arkfile-refresh` — refresh token, HttpOnly, Secure, SameSite=Strict, Path=/.
  - `__Host-arkfile-csrf` — CSRF token, NOT HttpOnly (JS needs to read it), Secure, SameSite=Strict, Path=/. The JS reads this and sends it back in an `X-CSRF-Token` header on every state-changing request. Server compares header to cookie value.
- During the TOTP-handoff window, the temp JWT also lives in a cookie: `__Host-arkfile-temp-token`, same attributes as the full one but with a 20-minute TTL.
- **CSRF token rotation:** the CSRF cookie value is rotated on every successful login, every successful refresh-token rotation (Phase A3), and on logout. A successful XSS therefore reads at most one CSRF value, and that value invalidates the moment the legitimate user does anything that triggers a rotation. Server-side check is constant-time-compare between the header value and the cookie value (both come up in the same request, so this is a true double-submit, not a stored-state check).
- **Browser-vs-CLI dispatch — no header sniffing:** the dispatch is route-based, not request-inspection-based, and a single per-request rule enforces it:
  - **If the request carries `__Host-arkfile-token` (or the temp variant) as a cookie, the request is treated as a browser request.** The cookie-reader middleware extracts the JWT; the bearer header is *ignored entirely*. The CSRF middleware enforces `X-CSRF-Token` against `__Host-arkfile-csrf`. If the CSRF check fails, return 403.
  - **If the request carries `Authorization: Bearer ...` AND no Arkfile cookies, the request is treated as a CLI request.** The bearer header is read by the existing path; no CSRF check is applied (no cookie means no CSRF risk).
  - **If the request carries both a cookie AND a bearer header, the cookie wins** and the bearer header is dropped silently. (An XSS that tries to mint its own bearer header in a fetch from the browser cannot bypass CSRF this way.)
  - **If the request carries neither, treat as unauthenticated.**
  - This dispatch is implemented once in `handlers/middleware.go` and does not depend on UA strings, Origin values, or any other forgeable signal.
- **Password scrubbing:** remove `window.totpLoginData` entirely. The TOTP flow does not need the plaintext password; it only needs the temp token (now in a cookie). If the flow currently requires the password for some derivation, isolate that derivation to a module-private constant zeroed immediately after use.

#### Implementation order

1. Server-side cookie writer in `handlers/auth.go` for login finalize, TOTP verify, refresh, logout. Cookie writes emit a fresh `__Host-arkfile-csrf` value on each issuance.
2. Server-side cookie reader middleware in `handlers/middleware.go` implementing the dispatch rule above (cookie-presence wins; bearer accepted only when no Arkfile cookie is present).
3. CSRF double-submit middleware checking `X-CSRF-Token` header against `__Host-arkfile-csrf` cookie with constant-time comparison. Applied only when a cookie is present.
4. Frontend refactor: remove all `localStorage.getItem('token')` / `setItem('token')` / `removeItem('token')` calls. Remove `window.totpLoginData`. Update the auth-fetch wrapper to omit `Authorization`, include `X-CSRF-Token` (read from `__Host-arkfile-csrf`), and set `credentials: 'include'`.
5. Delete `getToken` / `setToken` / `clearToken` from `auth-manager.ts` and replace with cookie-based equivalents (or remove them entirely since cookies are server-managed).
6. Tests:
   - Server-side: cookie issuance includes all three cookies with correct attributes; CSRF mismatch returns 403; cookie-present-but-no-CSRF-header returns 403; bearer-only (no cookie) succeeds; bearer-AND-cookie uses the cookie path and applies CSRF.
   - Frontend: auth-fetch wrapper sends `credentials: 'include'` and `X-CSRF-Token`.
   - Playwright: assert `localStorage.getItem('token')` returns null after login, and `document.cookie` does not expose the JWT (HttpOnly invisible to JS).
   - CSRF rotation: log in (CSRF_a); refresh; assert new CSRF (CSRF_b) is different; replay a request with CSRF_a → 403.

#### Validation pass

- `dev-reset.sh` succeeds; cookie-issuing endpoints respond with `Set-Cookie` headers.
- `e2e-test.sh` green — CLI flows continue using bearer auth, so they should not regress.
- `e2e-playwright.sh` green — this is the primary validation surface. Login, TOTP setup, TOTP verify, file upload/download, share, logout all use cookies.
- New TS test: XSS-simulation payload that tries `document.cookie` and `localStorage.getItem('token')` returns nothing useful.

#### Beta impact

**YELLOW.** All 5 beta users forced to log in again + may need to hard-refresh open tabs. No file impact.

**Heads-up message draft:**
> "Hi all — pushed a frontend update that moves session tokens into more secure browser cookies. Please hard-refresh the page (Ctrl-Shift-R / Cmd-Shift-R) and log in again. Files unaffected."

---

### Phase C — Bind AAD everywhere on the file path

**Why this phase:** the cross-slice file-identity authenticity gap. An active server (or anyone with DB-write access) can substitute, reorder, or swap encrypted chunks / FEK envelopes / metadata between or within a user's files; today the only defense is the end-of-file plaintext SHA-256 verification, which runs *after* the file is written to disk (and is skipped entirely on the browser Blob fallback path). Binding AAD on every AEAD operation moves detection from end-of-file SHA-256 (post-disk-write) to the AEAD layer (per-chunk).

**Findings closed:** B-02, C-02, C-03, C-19, B-08, B-05 (ride-along).

**Files most likely touched:** `crypto/file_operations.go`, `crypto/envelope.go`, `crypto/gcm.go`, `client/static/js/src/crypto/upload.ts`, `client/static/js/src/crypto/streaming-download.ts`, `client/static/js/src/crypto/types.ts`, `cmd/arkfile-client/` upload + download paths, `handlers/uploads.go`, `handlers/files.go`, `handlers/downloads.go`, `models/file.go`.

**Greenfield notes:** the envelope `0x01` byte stays `0x01` but its semantics is **redefined** to require AAD-bound chunks / FEK / metadata. The old `0x01` (no-AAD) code paths are deleted, not preserved as fallback. Existing beta files become unreadable. **No version bump.**

#### Pre-work

1. Read `crypto/file_operations.go` and `crypto/envelope.go` to map the current envelope format and FEK-wrap path.
2. Read `crypto/gcm.go` to identify where AAD parameters are currently passed (today: nil / empty).
3. Read `client/static/js/src/crypto/upload.ts` and `streaming-download.ts` for the matching TS implementation.
4. Read `cmd/arkfile-client/` for the CLI implementations.
5. Read `models/file.go` to find the doc comment that claims AAD-bound metadata (C-19).

#### Design decisions

- **Chunk AAD:** `file_id || chunk_index || chunk_count || ciphertext_sha256`. `ciphertext_sha256` is the SHA-256 of the chunk's nonce||ct||tag (already computed server-side; bind it cryptographically rather than by best-effort header).
- **FEK envelope AAD:** `file_id || key_type` where `key_type` is the 0x01 / 0x02 marker byte for account-vs-custom KEK.
- **Metadata AAD:** `file_id || field_name || owner_username`. `field_name` is one of `filename`, `sha256-hex`.
- AAD construction must produce byte-identical output across Go and TS. Use a fixed concatenation order with length prefixes (or fixed-width fields) to avoid ambiguity. Add a cross-language conformance test in CI.

#### Implementation order

1. Add the AAD-construction helpers (`crypto/aad.go` Go side; `client/static/js/src/crypto/aad.ts` TS side; mirror in CLI).
2. Update `crypto/file_operations.go` to pass AAD into `EncryptGCM` / `DecryptGCM` for chunks, FEK envelope, metadata.
3. Update `client/static/js/src/crypto/upload.ts` and `streaming-download.ts` for the matching TS paths.
4. Update CLI upload + download to use the same AAD.
5. Delete the old (no-AAD) `0x01` code paths. Update `models/file.go` doc comment to match reality.
6. Cross-language conformance test: a fixed (file_id, chunk_index, ...) tuple produces the same byte string in Go and TS.
7. Tests: chunk-swap negative test (DB rewrite swaps two chunks; download fails at AEAD); cross-file FEK swap test; reorder test; truncation test.

#### Validation pass

- `dev-reset.sh` succeeds.
- `e2e-test.sh` green — CLI upload then CLI download succeeds; CLI upload then browser download succeeds; share creation + recipient download succeeds.
- `e2e-playwright.sh` green — browser upload then browser download; browser upload then CLI download; the cross-client conformance test.

#### Beta impact

**RED.** This is the single biggest disruption in the campaign.

- All 5 beta users: existing files become unreadable on next visit. Account survives, TOTP survives, login works, but every file shows "unreadable" or fails to decrypt.
- 5 users × 1-3 files = ~15 files total. Simplest: re-upload.
- Alternative: a one-shot migration script run by the developer (downloads each file with the old AAD-free decrypt path, re-encrypts with the new AAD-bound path, re-uploads). The greenfield principle argues against keeping the old decrypt path in shipped production code, but a one-shot offline migration tool is fine because it's not in the shipped binary. Worth doing if any beta user has files they can't easily re-create.

**This phase needs explicit developer go-ahead before `test-update.sh` runs.** Local validation can land at any time; the beta push is the gated event.

**Heads-up message draft (pre-update, give 2-3 days notice):**
> "Heads up — pushing a security update on [date] that strengthens how files are bound to their identity. Existing uploaded files will no longer be readable after the update; you'll need to re-upload them. Account, TOTP, and login unchanged. If you have files you can't easily re-create, let me know before [date] and I'll arrange a manual re-encryption."

---

### Phase D — Supply-chain integrity gap

**Why this phase:** the codebase is in a known-good state right after Phase C. Phase D's build-flag and SRI work catches supply-chain regressions during the remaining Phases E / F / G work. Doing it here also means Phase E's compile-time parameter floors land into already-hardened binaries.

**Findings closed:** F-04, F-05, F-06, F-13. Ride-along Mediums considered if cheap: F-11, F-12, F-25.

**Files most likely touched:** `scripts/setup/build-libopaque-wasm.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/test-deploy.sh`, `scripts/dev-reset.sh`, `client/static/index.html`, `client/static/shared.html`, `client/static/js/package.json`, `client/static/js/bun.lock`, `.gitmodules`, vendored `libsodium/` path, build invocation in deploy scripts.

**Greenfield notes:** purely additive. No format changes.

#### Pre-work

1. Read each deploy script's build section. Identify the current `go build` invocation and any libsodium acquisition step.
2. Read `client/static/index.html` and `client/static/shared.html` to find where `libopaque.js` is currently included.
3. Read `client/static/js/package.json` for `^`-ranged dependencies. Check `bun.lock` is committed.
4. Identify the build-time SRI hash emission strategy: probably a small `bash` step that computes `sha384sum` of each shipped asset and rewrites the corresponding `<script integrity=...>` attribute in `index.html` (or in a generated header partial).

#### Design decisions

- **SRI (F-04):** every shipped asset (`libopaque.js`, `dist/app.js`, any other client-side bundle) gets a `sha384` SRI attribute. Build script emits the hash; HTML file is templated.
- **Go build flags (F-05):** `-trimpath`, `-buildid=`, `-ldflags='-s -w'`, `-buildvcs=false`. Add to all three binaries (`arkfile`, `arkfile-client`, `arkfile-admin`). Verify reproducibility by clean-building twice and `sha256sum`-comparing.
- **libsodium vendored (F-06):** add `vendor/libsodium` as a pinned git submodule. Update build to compile libsodium statically and link against the vendored version. Remove host apt/dnf install of libsodium.
- **Frozen lockfile (F-13):** every `bun install` invocation gets `--frozen-lockfile`. Drop `^` from version ranges in `package.json` where it matters.
- **Optional ride-alongs (only if cheap):** F-11 (SHA-256 instead of MD5 for SeaweedFS pin), F-12 (rqlite pinned to a specific commit/tag), F-25 (`govulncheck` + `bun audit` + SBOM via `syft` in the build script).

#### Implementation order

1. Add `-trimpath -buildid= -ldflags='-s -w' -buildvcs=false` to all `go build` invocations.
2. Add libsodium submodule + update build-libopaque-wasm.sh to use it.
3. Build-time SRI hash emission for shipped assets.
4. `bun install --frozen-lockfile` in build scripts.
5. Drop `^` ranges in `package.json`.
6. (Optional) `govulncheck` + `bun audit` in build script; SBOM emission.
7. Reproducibility test in CI: clean rebuild × 2 produces byte-identical binaries.

#### Validation pass

- `dev-reset.sh` succeeds; the new SRI attributes don't break the WASM load.
- `e2e-test.sh` green.
- `e2e-playwright.sh` green — browser can still load WASM with SRI in place.
- New: clean-rebuild reproducibility test.

#### Beta impact

**GREEN.** Build-time / artifact-integrity changes only. No user-visible change.

---

### Phase E — Parameter floors + share envelope binding (Done 2026-05-19)

**Why this phase:** server-controlled crypto parameters are the single largest design defect in the cryptographic layer. A compromised server (or an attacker with active manipulation) can silently weaken every future KDF derivation by changing what `/api/config/argon2` returns. Phase E embeds the parameters as compile-time floors in both Go binaries and the TS bundle; `/api/config/*` becomes informational-only.

**Findings closed:** B-01, B-03, B-19 (ride-along), D-10, D-12 (ride-along), C-01 (ride-along).

**Files most likely touched:** `crypto/argon2id-params.json`, `crypto/chunking-params.json`, `crypto/password-requirements.json`, `crypto/key_derivation.go`, `crypto/share_kdf.go`, `client/static/js/src/crypto/argon2.ts`, `client/static/js/src/crypto/chunking.ts`, `handlers/file_shares.go`, `client/static/js/src/share/` decrypt paths, build scripts that embed the JSON.

**Greenfield notes:** the share-envelope JSON gets KDF-params fields directly. Old envelopes simply fail to parse. **No version bump.**

#### Pre-work

1. Read the three JSON parameter files and identify the current production values.
2. Read `crypto/key_derivation.go` and `crypto/share_kdf.go` for current Argon2id call sites.
3. Read the TS-side `argon2.ts`, `chunking.ts`, `password_validation.ts` for the matching client paths.
4. Identify how the JSON is currently fetched (`/api/config/argon2` etc.) and which TS module owns the runtime fetch.
5. Read `handlers/file_shares.go` and the share-create / share-decrypt paths for envelope JSON construction.

#### Design decisions

- **Embed JSON as `go:embed` constants** in Go binaries. The runtime never reads the file from disk.
- **Embed JSON via bundler import** in the TS bundle (or generate a `.ts` constants file from the JSON at build time).
- The `/api/config/*` endpoints continue to exist and return the same values, but the security-critical path uses the embedded floors. Clients refuse parameters below the floor (defense in depth: if `/api/config` is somehow consulted and returns weak params, the client rejects them).
- **Share envelope:** the encrypted JSON payload (decrypted client-side by the recipient) gains `kdf_params: { algorithm: "argon2id", m_kib, t, p, dk }` fields. Decrypt path asserts these match the local floor before using them.
- **C-01 padding-DoS:** bound the server-side `append` allocation by capping the padding amount at a hard maximum (probably 16 MiB).

#### Implementation order

1. Convert the three JSON files to `go:embed` constants accessible from `crypto/`.
2. Generate matching TS constants at build time (or import the JSON directly via the bundler).
3. Replace runtime parameter fetches with embedded reads on the security path.
4. Add `kdf_params` fields to the share envelope JSON. Recipient-side decrypt asserts match.
5. Cap server-side padding allocation.
6. Cross-language Argon2id conformance test in CI.
7. Tests: Jest mock returns weak params from `/api/config/argon2`; client refuses. Tampered share envelope with weak `kdf_params` fails to decrypt.

#### Validation pass

- `dev-reset.sh` green.
- `e2e-test.sh` green — CLI share creation + recipient decrypt should work end-to-end.
- `e2e-playwright.sh` green — browser share + recipient should work.

#### Beta impact

**YELLOW.**
- Existing files unaffected (the embedded Argon2id floors are the same params currently served by `/api/config/argon2`; client encryption keeps producing identical KDF output for account / custom KEK derivations).
- **All existing shares are deleted as part of the deploy.** The operator runs a one-liner against the rqlite database immediately before `test-update.sh` runs:
  ```
  DELETE FROM share_envelopes;
  DELETE FROM share_access_attempts;
  ```
  (confirm exact table names in pre-work — `handlers/file_shares.go` and `database/unified_schema.sql` will tell us). This is cleaner than running a one-shot migration and avoids the "UI still shows an active share that the recipient can no longer open" failure mode.
- Owners can re-create any shares they still need after the update lands.

**Heads-up message draft:**
> "Heads up — pushing a security update on [date] that hardens shared-link cryptography. As part of the rollout I'm clearing all existing share links from the server. Files and accounts are untouched. If you have active share links you want preserved, re-issue them after the update lands."

---

### Phase F — Tiered at-rest secret store + TOTP hardening

**Why this phase:** today, an attacker who acquires both the DB and `secrets.env` (which contains `ARKFILE_MASTER_KEY`) recovers every server-held user secret in cleartext: TOTP secrets, TOTP backup codes, contact info, JWT signing keys, OPAQUE keys. Phase F splits server-held secrets into trust tiers so that a `secrets.env`-only leak (or a DB-only leak) does not yield user-secret material. The user-secret-wrapping master moves from the DB to a separate filesystem path (`/opt/arkfile/etc/keys/user-secret-master.bin`), not in `system_keys` at all. TOTP backup codes additionally become **hashed** (Argon2id, per code) instead of encrypted — so even a full compromise (DB + `secrets.env` + Tier-3 file) cannot recover backup codes.

See §3 for the full threat-model table and §4.3 for the tier assignment table.

**Findings closed:** A-07, A-17, A-18, A-15, A-16 (ride-along).

**Files most likely touched:** new `crypto/user_secret_master.go`, `crypto/totp_keys.go`, `auth/totp.go`, `auth/totp_test.go`, `auth/totp_backup_test.go`, `models/contact_info.go`, `database/unified_schema.sql`, `handlers/auth.go` (TOTP reset flow), new `scripts/maintenance/rotate-user-secret-master.sh`, deploy scripts (`local-deploy.sh`, `test-deploy.sh`, `prod-deploy.sh`, `dev-reset.sh`) to generate the Tier-3 file at install.

**Greenfield notes:** schema additions for `user_totp_backup_codes` (new table). The old `user_totp.backup_codes_encrypted` column is dropped (no dual-column transition). Existing TOTP enrollments cannot be migrated (the old encryption key is replaced and we can't decrypt + re-encrypt without the operator's coordination); cleanest move is to drop all `user_totp` rows and force re-enrollment.

#### Sub-clusters

##### F1 — Tier-3 user-secret-master infrastructure (load + mlock + derive)

This sub-cluster closes A-17 (mlock / MADV_DONTDUMP / PR_SET_DUMPABLE on long-lived secret material). The memory-hardening primitives must land in F1 so that F2 / F3 / F4 load the master into already-hardened memory. F6 (documentation) ends up purely about docs.

**Pre-work:**
1. Confirm the file path convention `/opt/arkfile/etc/keys/` exists and is owned by the `arkfile` user. (Phase A1 already wrote `/opt/arkfile/etc/keys/bootstrap-token.bin` to this directory.)
2. Decide whether to generate the Tier-3 file at first-startup (like `KeyManager.GetOrGenerateKey`) or at install-time in the deploy script. **Recommendation: at install-time in the deploy script**, with a fail-closed check at startup that the file exists. Reduces ambiguity about who owns the file's creation.
3. Confirm Go syscall surface for `syscall.Mlock`, `unix.Madvise(buf, unix.MADV_DONTDUMP)`, and `unix.PrctlRetInt(unix.PR_SET_DUMPABLE, 0, ...)` on the target platform (Linux).

**Design decisions:**
- Path: `/opt/arkfile/etc/keys/user-secret-master.bin`. 32 random bytes. Mode 0400. Owner `arkfile` user.
- Loader (`crypto/user_secret_master.go` `LoadTier3Master()`) at process startup:
  1. Open the file; read exactly 32 bytes; fail-closed on any size mismatch or read error.
  2. `syscall.Mlock` the destination buffer.
  3. `unix.Madvise(buf, unix.MADV_DONTDUMP)` so the page is excluded from core dumps and `ptrace(PTRACE_PEEKDATA)`-of-a-coredump scenarios.
  4. Once per process, `unix.PrctlRetInt(unix.PR_SET_DUMPABLE, 0)` to disable coredumps for the entire Arkfile process. This is wider than just the Tier-3 page but the marginal cost is zero and it also protects the OPAQUE private key, JWT keys, etc. that share the address space.
  5. Store the buffer in a package-private variable; expose only `DeriveTier3Subkey(purpose string)`.
- `DeriveTier3Subkey(purpose)`:
  - `key = HKDF-SHA256(salt=nil, ikm=tier3Master, info="ARKFILE_TIER3:" + purpose, dkLen=32)`
  - Known purposes: `"totp_user"` (consumed by F2), `"contact_info"` (consumed by F4).
- Rotation script (`scripts/maintenance/rotate-user-secret-master.sh`): reads old master + new master, iterates every `user_totp.secret_encrypted` row (decrypt under old `totp_user_master`, re-encrypt under new) and every contact-info blob (decrypt under old `contact_info_master`, re-encrypt under new), atomically renames the new file into place last. Backup codes do not need re-encryption because they are hashed (per F3), not encrypted.

**Implementation order:**
1. New `crypto/user_secret_master.go` exporting `LoadTier3Master()` and `DeriveTier3Subkey(purpose string) [32]byte`. The mlock + madvise + PR_SET_DUMPABLE plumbing lives entirely in `LoadTier3Master()`.
2. Call `LoadTier3Master()` once during process bootstrap (alongside `KeyManager` init). Fail-closed on missing/short file.
3. Update each deploy script (`dev-reset.sh`, `local-deploy.sh`, `test-deploy.sh`, `prod-deploy.sh`) to generate the file at install if missing: `head -c 32 /dev/urandom > /opt/arkfile/etc/keys/user-secret-master.bin && chmod 0400 ... && chown arkfile:arkfile ...`.
4. Write `scripts/maintenance/rotate-user-secret-master.sh` (signature only is fine in F1; the data-re-encryption loop is implemented in F2 and F4 because those clusters know the schemas).
5. Tests:
   - `LoadTier3Master()` fails closed on missing file, on wrong-size file, on file with wrong mode (warning-level, not fail-closed, to avoid foot-guns on systems where umask differs).
   - `DeriveTier3Subkey("totp_user") != DeriveTier3Subkey("contact_info")` (domain separation).
   - `mlock` succeeded (best-effort: assert process RLIMIT_MEMLOCK is sufficient; otherwise log a warning).
   - Round-trip: random master → derive subkey twice with same purpose → byte-equal.

**Beta impact:** GREEN. The file is generated by `test-update.sh`'s redeployment step; users see nothing. (No keys are migrated yet; F2 / F3 / F4 do that.)

##### F2 — Migrate TOTP secret encryption to Tier-3

**Pre-work:**
1. Read `crypto/totp_keys.go` and identify every caller of `DeriveTOTPUserKey`.
2. Confirm `totp_master_key_v1` row removal is safe (no other code uses it).

**Design decisions:**
- `DeriveTOTPUserKey(username)` reads from `DeriveTier3Subkey("totp_user")` instead of `totp_master_key_v1`.
- `totp_master_key_v1` row dropped from `system_keys`.
- Existing `user_totp.secret_encrypted` rows are dropped (cannot migrate without old key access).

**Implementation order:**
1. Update `crypto/totp_keys.go` to use Tier-3.
2. Remove `totp_master_key_v1` `GetOrGenerateKey` call.
3. Schema migration: drop existing `user_totp` rows. (Or document that `dev-reset.sh` + `test-update.sh` will reset them.)
4. Tests: TOTP setup + verify after the migration; ensure no reference to the old `totp_master_key_v1`.

**Beta impact:** YELLOW (forced TOTP re-enrollment). Files survive.

##### F3 — Hashed backup codes

**Pre-work:**
1. Read `auth/totp.go` backup-code generation, verification, and replay-log paths.
2. Read `auth/totp_backup_test.go` for current test coverage.
3. Confirm the global Argon2id parameters in `crypto/argon2id-params.json` (m, t, p, dk). F3 reuses these unchanged — there is no per-feature parameter file.

**Design decisions:**
- **Reuse the global Argon2id parameters.** No new parameter file is introduced; F3 imports the same m/t/p/dk values used by Account-KEK and Custom-KEK derivation. After Phase E lands, those parameters become compile-time-embedded floors; F3 inherits that hardening automatically. There is no hardcoded `64MiB` or `t=3` in `auth/totp.go`.
- **Per-code salt is derived deterministically per (username, code_index).** No salt material is stored in the DB. The schema therefore omits the `code_salt` column entirely. Salt derivation:
  - `salt = SHA-256("arkfile-backup-code-salt:" || username || ":" || code_index)` where `code_index` is the integer position in `0..9`.
  - Equivalent for an attacker to a random 32-byte salt for offline cracking purposes: each (username, code_index) yields a unique 32-byte pseudorandom value, and Argon2id's memory-hardness dominates the per-attempt cost. Salt unguessability is not a security goal when the rate limit is per-username.
- **Schema:**
  ```sql
  CREATE TABLE user_totp_backup_codes (
    username TEXT NOT NULL,
    code_index INTEGER NOT NULL,          -- 0..9
    code_hash BLOB NOT NULL,              -- 32 bytes from Argon2id
    used_at TIMESTAMP,
    PRIMARY KEY (username, code_index),
    UNIQUE (username, code_hash)
  );
  ```
- **Backup-code generation (10 codes per user):** each code is 10 characters drawn from a 62-character alphanumeric alphabet (`[A-Za-z0-9]`). Generation uses rejection sampling — draw a random byte, accept only if it lands in a clean multiple of 62, otherwise re-draw — eliminating the A-42 modulo bias. ~59.5 bits per code, well above the offline-attack threshold once Argon2id is layered on top.
- **Storage at enrollment:** for each `code_index ∈ 0..9`, derive `salt = SHA-256("arkfile-backup-code-salt:" || username || ":" || code_index)`, compute `code_hash = argon2id(code, salt, <global params>)`, insert `(username, code_index, code_hash)`. The user sees the 10 codes once on the enrollment screen and is told to save them; the server never re-shows them.
- **Verification (O(1) average per attempt):** the user submits a backup code; the server doesn't know which `code_index` they're claiming, but the search is bounded to 10 candidates and is structured for early-exit:
  ```
  for code_index in 0..9 (or random permutation to defeat timing-based index inference):
      salt = SHA-256("arkfile-backup-code-salt:" || username || ":" || code_index)
      candidate_hash = argon2id(submitted_code, salt, <global params>)
      row = SELECT * FROM user_totp_backup_codes WHERE username = ? AND code_index = ? AND code_hash = candidate_hash
      if row exists and row.used_at IS NULL:
          inside transaction: UPDATE ... SET used_at = now() WHERE username = ? AND code_index = ? AND used_at IS NULL
          if UPDATE returns 0 rows: another caller used the code; reject (closes A-16 race)
          else: succeed, return
  reject (no match)
  ```
  Average case: ~5 Argon2id derivations per attempt (uniform distribution of which code the user submits). Worst case: 10. Better than a random-salt design that always requires 10. UNIQUE on `(username, code_hash)` plus the transactional `used_at` write closes the A-16 race; the optimistic UPDATE pattern ensures concurrent submissions of the same code result in exactly one success.
- **Index permutation for verification:** iterating `0..9` in a fixed order leaks (via timing) which `code_index` the user actually submitted, since matching at index 3 returns ~3× faster than matching at index 9. To prevent this, iterate in a per-request random permutation (e.g., `rand.Perm(10)`). The cost is unchanged; the only difference is which Argon2id derivations complete before the match. (Optional but cheap; recommend including.)
- **Drop `backup_codes_encrypted` column from `user_totp`** as part of the F2 schema migration that drops all existing TOTP enrollments.

**Implementation order:**
1. Schema additions in `database/unified_schema.sql` (new `user_totp_backup_codes` table, drop `user_totp.backup_codes_encrypted`).
2. Helper `func deriveBackupCodeSalt(username string, codeIndex int) [32]byte` in `auth/totp.go`.
3. Refactor backup-code generation: 10 codes via rejection-sampled `[A-Za-z0-9]{10}`; for each, compute `(salt, hash)` and insert the row.
4. Refactor backup-code verification: random-permuted index iteration with the optimistic-UPDATE pattern above.
5. Tests:
   - Concurrent-submission race: two goroutines submit the same valid code; exactly one returns success.
   - Modulo-bias smoke test: 10^6 generated characters; distribution across the 62-symbol alphabet within 1% of uniform.
   - Worst-case verification cost: submitting an unknown code exercises 10 Argon2id derivations (assert bounded; do not assert wall-clock).
   - Index-timing: submitting code at index 0 vs. index 9 produces statistically indistinguishable wall-clock times (permutation defense check; large variance tolerance is fine — this is a smoke test, not a true side-channel test).
   - Codes-after-enrollment: assert the codes-display endpoint refuses to re-show codes after the enrollment session ends.
   - Cross-language conformance: a fixed `(username, code_index, code)` tuple produces the same `code_hash` in Go and TS (TS only matters for client-side test code; production verification is server-side).

**Beta impact:** rolls into the YELLOW from F2 (same forced re-enrollment).

##### F4 — Migrate contact-info encryption to Tier-3

**Pre-work:**
1. Read `models/contact_info.go` for the current encryption path.
2. Confirm the contact-info rows are countable and migration-feasible (likely yes; small dataset).

**Design decisions:**
- `getContactInfoKey()` returns `DeriveTier3Subkey("contact_info")`.
- One-shot migration script (run by `test-update.sh` once) that decrypts existing rows under the old key, re-encrypts under the new key. Unlike TOTP, contact info CAN be migrated because we still hold the old key at the moment of migration.
- After migration, the old `contact_info` key row in `system_keys` is dropped.

**Implementation order:**
1. Update `models/contact_info.go` to use Tier-3.
2. Write the one-shot migration tool (a small Go program or admin command).
3. Run migration in `test-update.sh` and `dev-reset.sh` flow.
4. Drop old key row.
5. Tests: round-trip after migration; migration is idempotent.

**Beta impact:** GREEN (contact-info preserved through migration).

##### F5 — Reachable TOTP recovery (A-15)

**Pre-work:**
1. Read `handlers/auth.go` `TOTPReset` handler and its middleware chain.
2. Confirm current state: `/api/totp/reset` requires a full JWT which requires TOTP — unreachable from a lost-device state.

**Design decisions:**
- Add a backup-code-verification path that is reachable from the temp-JWT tier (post-OPAQUE, pre-TOTP). The user enters a backup code; if it verifies against `user_totp_backup_codes`, the server issues a special "TOTP-reset eligible" JWT (audience `arkfile-totp-reset`).
- `/api/totp/reset` endpoint accepts the new audience and clears the user's TOTP enrollment. User must then re-enroll TOTP via `/api/totp/setup`.
- Mark the consumed backup code as `used_at` so it can't be reused for another reset.

**Implementation order:**
1. New endpoint `/api/totp/recover-with-backup-code` (accepts temp JWT + backup code, issues reset-eligible JWT).
2. Update `/api/totp/reset` middleware to accept the new audience.
3. Frontend: a "lost device" link on the TOTP entry screen that routes to the backup-code-recovery flow.
4. Tests: full lost-device recovery flow end-to-end.

**Beta impact:** GREEN. New capability; doesn't break existing usage.

##### F6 — Documentation

- Update `docs/security.md` with a brief plain-language section explaining the tiering (see §3 and §4.3 as source material).
- Document the rotation procedure for `/opt/arkfile/etc/keys/user-secret-master.bin`.
- (This is the entry-point for the Phase H documentation effort; F6 lays the groundwork specific to Phase F.)

#### Validation pass (Phase F overall)

- `dev-reset.sh` green; the new Tier-3 file is generated at install; OPAQUE registration + TOTP setup works end-to-end.
- `e2e-test.sh` green — TOTP setup, verify, auth, backup-code use, lost-device recovery all work via CLI.
- `e2e-playwright.sh` green — same flows via browser.

**Validation focus:** `e2e-test.sh` is primary (TOTP flows). `e2e-playwright.sh` confirms the new browser-side recovery UI.

#### Beta impact (Phase F overall)

**YELLOW.** All 5 beta users will be prompted to re-enroll TOTP on next login. Account, files, contact info survive.

**Heads-up message draft:**
> "Pushed a security update that hardens TOTP storage. On next login you'll be prompted to re-enroll your TOTP authenticator and save new backup codes. Your account, files, and contact info are unchanged."

---

### Phase G — Pre-payment financial-audit integrity

**Why this phase:** the executive-summary flags the financial-audit gaps as Critical-the-moment-Stripe-lands. Developer has confirmed payment-processor integration starts only after all Highs are resolved, so Phase G stays last in the High campaign. Cheaper to do now while there is no real money in the system.

**Findings closed:** E-21, E-03, E-04, E-05, E-02, A-12.

**Files most likely touched:** `database/unified_schema.sql`, `models/user.go`, `models/credits.go`, `models/refresh_token.go`, `billing/scheduler.go`, `billing/sweep.go`, `billing/meter.go`, `handlers/admin_billing.go`, `handlers/admin_storage.go`, every handler that does a user lookup (estimated ~50 call sites for the soft-delete audit).

**Greenfield notes:** schema migration is in-place against `database/unified_schema.sql`. Soft-delete is an additive column (`deleted_at TIMESTAMP`); all existing rows have NULL. Every existing `JOIN users` and `WHERE username = ?` needs an `AND deleted_at IS NULL` filter — that's the ~50-call-site audit. Budget a half-day for that.

#### Pre-work

1. `grep -rn 'WHERE username' --include='*.go'` to enumerate all user-lookup sites.
2. `grep -rn 'JOIN users' --include='*.go'` to enumerate all join sites.
3. `grep -rn 'fmt.Sprintf' --include='*.go' | grep -iE '(SELECT|INSERT|UPDATE|DELETE)'` to find SQL-injection candidates (E-02 starts here).
4. Read `billing/scheduler.go` `settleOneUser` to identify the read-of-balance outside the transaction.
5. Read `billing/sweep.go` for the process-local `lastSweepDate`.
6. **Block-the-phase data check (run against the dev DB first, then the beta DB once locally green):** the new `UNIQUE(transaction_id)` constraint will reject the migration if any duplicate values already exist. Run `SELECT transaction_id, count(*) FROM credit_transactions GROUP BY transaction_id HAVING count(*) > 1;` against both `dev-reset.sh`'s seeded DB and the beta `test.arkfile.net` DB. If any rows come back, the schema change cannot land — pause and ask the developer to dedupe (likely by collapsing duplicate rows into a single canonical row and adjusting `user_credits.balance` if needed). Do not start the implementation order until both DBs return zero rows.

#### Design decisions

- **E-21 soft-delete:** add `deleted_at TIMESTAMP` to `users`. Replace `DELETE FROM users WHERE username = ?` with `UPDATE users SET deleted_at = now() WHERE username = ?`. Add `AND deleted_at IS NULL` to every user lookup.
- **E-03:** move `user_credits.balance` SELECT inside the settlement transaction.
- **E-04:** `UNIQUE(transaction_id)` on `credit_transactions`. New gift / usage rows must supply a `transaction_id`.
- **E-05:** persist `last_sweep_date` to a small `billing_state` table; read it on startup; update it inside the sweep transaction.
- **E-02:** parameterized SQL in `AdminSyncStatus`. Add a `golangci-lint` rule (e.g., `gosec` G201 / G202) banning `fmt.Sprintf` adjacent to SQL keywords.
- **A-12:** post-soft-delete, the user-row stays; the cascading cleanup of refresh tokens / file metadata / share rows is replaced by a "scrub" routine that nullifies sensitive fields on deleted users without deleting referencing rows. (Files: depends on the desired retention semantic — keep encrypted blobs for audit, or delete them? Default: delete from storage; keep the metadata row with a `scrubbed_at` marker.)

#### Implementation order

1. Schema additions.
2. The user-lookup audit (the half-day): add `AND deleted_at IS NULL` everywhere a user is fetched for any operational purpose. Admin-only "list deleted users" endpoints can omit the filter intentionally.
3. Replace `DELETE` paths with soft-delete.
4. `settleOneUser` tx-scoped balance read.
5. `UNIQUE(transaction_id)`; persistent `last_sweep_date`.
6. `AdminSyncStatus` parameterized SQL + lint rule.
7. `A-12` scrub routine for soft-deleted users.
8. Tests: per-user data isolation under soft-delete; idempotent gift via `UNIQUE(transaction_id)`; duplicate-sweep prevention across restart; SQL injection probe; ledger-invariant check.

#### Validation pass

- `dev-reset.sh` green.
- `e2e-test.sh` green — billing and admin scenarios.
- `e2e-playwright.sh` green — frontend lookup paths.

**Validation focus:** `e2e-test.sh` (billing-heavy). The user-deletion audit is manual code review, not a test pass.

#### Beta impact

**GREEN.** The duplicate-`transaction_id` data-readiness check is enforced in Pre-work (step 6); if it passes there, the beta deploy is invisible to users. Soft-delete is additive (no row removal); all existing user lookups land in the same data path after the `AND deleted_at IS NULL` audit.

---

### Phase H — Documentation: plain-language threat model

**Why this phase:** the architectural work above produces a system whose security posture is meaningfully stronger but explained only in finding-numbered slice docs. Operators, contributors, and non-technical stakeholders should be able to read `docs/security.md` and understand, in plain English: what Arkfile protects against, what it doesn't, and what the realistic compromise scenarios look like.

**Findings closed:** none directly (this is a documentation phase).

**Files touched:** `docs/security.md`.

**Greenfield notes:** none.

#### Pre-work

1. Read existing `docs/security.md`.
2. Read §3 (Threat Model) of this document — that's the source material.
3. Read `docs/AGENTS.md` §"No Emojis" and §"Honesty and Transparency".

#### Design decisions

- The target audience for the new section is approximately "a non-technical CEO" — that is, someone who needs to understand what Arkfile does and doesn't claim, what realistic attacks look like, and what an operator needs to do, without needing to read code.
- Lead with **what Arkfile never gives up** (the §3.1 list).
- Follow with **three realistic compromise scenarios** in plain language: a stolen DB backup, an environment-variable leak, and an attacker with root on the server. For each, say in one sentence what they get and what they don't.
- Avoid jargon. "OPAQUE" can be glossed as "a protocol where the server never sees the user's password, even hashed". "AEAD" can be glossed as "encryption that detects tampering".
- Keep the section short (~300 words). The full technical model lives elsewhere; this is the readable summary.

#### Implementation order

1. Draft the section.
2. Cross-link from `docs/security.md` to `docs/wip/review/00-executive-summary.md` for readers who want the full picture.
3. Confirm no emojis, no `===`/`---` formatting characters in the section.

#### Validation pass

Not test-driven. The validation is "a non-technical reader can read this and accurately answer the question 'if the server gets hacked, are my files at risk?'".

#### Beta impact

**GREEN.** Documentation only.

---

## §6. Status Tracker

Updated as work lands. The "first not-started cluster" is where work resumes.

| Phase | Cluster | Findings | Status | Notes |
|---|---|---|---|---|
| A | A1 | A-13, A-26, F-03, A-14 | **Done 2026-05-15** | A-13: `system_keys.consumed_at TIMESTAMP` column added; `BootstrapRegisterFinalize` does atomic `UPDATE system_keys SET consumed_at=CURRENT_TIMESTAMP WHERE key_id='bootstrap_token' AND consumed_at IS NULL` inside the admin-creation transaction; `RowsAffected()!=1` rejects with 401; `ValidateBootstrapToken` rejects any token with non-NULL `consumed_at`. A-26 / F-03: token now written to `/opt/arkfile/etc/keys/bootstrap-token.bin` (mode 0400) via atomic temp+rename; zero `log.Printf` of the hex value; deploy scripts (`local-deploy.sh`, `test-deploy.sh`, `prod-deploy.sh`) updated to instruct operators to `sudo cat` the file rather than `journalctl \| grep BOOTSTRAP`; chown warning suppressed for the non-actionable kernel-EPERM case (Option B refinement). A-14: `ValidateProductionConfig` in `config/config.go` fail-closes at startup when `ENVIRONMENT=production` AND `ADMIN_DEV_TEST_API_ENABLED` is truthy; covered by 5 table-driven test cases. New test file `auth/bootstrap_test.go` (3 tests covering token-not-in-stdout, consumed-token-rejection, stale-file-cleanup); test schemas updated in `auth/jwt_test.go` and `handlers/test_main_test.go` to mirror the new production `system_keys` columns. Validation: full local gate green (`dev-reset.sh` + `e2e-test.sh` + `e2e-playwright.sh`) plus full `go test ./...` clean across all 10 packages. Beta impact: GREEN. |
| A | A2 | A-08, A-37 | **Done 2026-05-15** | Per-user TOTP failure lockout. Three columns added to `user_totp`: `failed_attempts_in_window INTEGER NOT NULL DEFAULT 0`, `window_started_at TIMESTAMP`, `last_failed_attempt_at TIMESTAMP`. Pure helper `computeLockoutState` (no side effects, fully unit-tested). `recordTOTPFailure` and `clearTOTPFailures` persist state. Lockout gate wired into both `ValidateTOTPCode` and `ValidateBackupCode` at the top (pre-crypto). Soft exponential backoff at 10 failures (2^n minutes, capped 60 min); hard 24h cap at 30 failures; rolling window resets after 24h of silence. Security events emitted on soft-lockout entry, hard-cap entry, and recovery. A-37 ride-along: `TOTPSkew` changed 0→1 (accepts previous and next 30s windows). 9 new tests in `auth/totp_test.go` covering all lockout paths, window reset, backoff doubling, cap, and skew regression. Full `go test ./...` green across all 10 packages. Beta impact: GREEN. |
| A | A3 | A-09, A-10 | **Done 2026-05-15** | JWT + refresh-token hardening. Schema: `refresh_tokens` gains `family_id TEXT NOT NULL`, `superseded_by_hash TEXT`, `family_revoked_at TIMESTAMP`; new `user_jwt_revocations(username PK, revoked_at, reason)` table. `models/refresh_token.go` fully rewritten: 256-bit `crypto/rand` tokens (base64url, 44 chars) replace `uuid.NewV4()` (122 bits); `ValidateRefreshToken` returns `(username, newRawToken, error)` and performs atomic 4-step rotation (SELECT 8-col, INSERT new row in family, UPDATE superseded_by_hash on old row, reuse-detection → family-revoke + user JWT revocation + `ErrRefreshTokenReuse`). `RevokeFamilyByFamilyID`, `RevokeAllUserJWTsByUsername`, `GetUserJWTRevocationTime` added. `handlers/auth.go` `RefreshToken` handler simplified to call `ValidateRefreshToken` once (no separate revoke+create). `auth/token_revocation.go` `TokenRevocationMiddleware` now does per-request user-wide JWT revocation check via `getUserRevocationTimeCached` (30-second in-process cache keyed on username, invalidated on write). JWT TTL kept at 30 minutes (developer decision 2026-05-15: per-request revocation is fully implemented and sufficient). `auth/dev_admin.go` updated for 3-return-value `ValidateRefreshToken`. 11 new tests in `models/refresh_token_test.go` (rotation, reuse detection, family revoke, entropy assertion), 2 new tests in `auth/token_revocation_test.go` (user-wide revocation blocks pre-revocation JWT; allows post-revocation JWT). `handlers/auth_test.go` mock SQL updated to 8-column SELECT + INSERT + UPDATE pattern. Full `go test ./...` green across all 10 packages. Beta impact: YELLOW (forced re-login on next visit; files survive). **Follow-up 2026-05-15 (endpoint consolidation):** `RevokeAllRefreshTokens` (refresh-only) and `ForceRevokeAllTokens` (full revocation) merged into a single `RevokeAllTokens` handler. Old routes `POST /api/revoke-all` and `POST /api/auth/force-revoke` replaced by unified `POST /api/auth/revoke-all` → `RevokeAllTokens` (revokes refresh tokens + writes `user_jwt_revocations` row immediately). `TestRevokeAllTokens_DefaultReason` replaces the two old tests. TS `revokeAllSessions()` URL updated. `arkfile-client revoke-all` CLI command added (`handleRevokeAllCommand` in `commands.go`). `e2e-test.sh` section 10.22b updated to use the CLI command. Docs updated: `docs/api.md`, `00-executive-summary.md`, `01-auth-opaque.md`, `05-api-authz-admin-billing.md`. Full `go test ./...` green. |
| B | — | A-04, F-08, A-05, F-07 | **Done 2026-05-15** | Server-side `__Host-*` HttpOnly cookies issued at login/TOTP-verify/refresh/logout. `CookieTokenMiddleware` + `CSRFMiddleware` wired globally. `GET /api/auth/me` for browser identity lookup. `handlers/cookies.go`, `handlers/auth.go`, `handlers/middleware.go`, `handlers/route_config.go` updated. Frontend: `utils/auth.ts`, `login.ts`, `totp.ts`, `totp-setup.ts`, `register.ts`, `app.ts`, `contact-info.ts`, `billing.ts`, `share-list.ts`, `share.ts`, `download.ts`, `upload.ts`, `list.ts`, `streaming-download.ts`, `metadata-helpers.ts` — all `Authorization: Bearer` / `getToken()` / `localStorage` auth replaced with cookie+CSRF model; all backwards-compat stubs (`getToken`, `setTokens`, `clearTokens`, `getTempToken`, `setTempToken`, `clearTempToken`) deleted per greenfield principle. `window.totpLoginData` replaced by module-private `_pendingTOTPFlowData`. 8 new Go middleware unit tests for `CookieTokenMiddleware` + `CSRFMiddleware` (all pass). TS `auth-manager.test.ts` rewritten; legacy stub test block deleted. `e2e-playwright.ts` updated to use cookie+CSRF for all `page.evaluate()` API calls. Full local gate green: `dev-reset.sh` + `e2e-test.sh` + `e2e-playwright.sh`. Go: 10/10 packages green. TS: 317/317 tests pass. Beta impact: YELLOW (forced re-login + hard-refresh). |
| C | — | B-02, C-02, C-03, C-19, B-08, B-05 | **Done 2026-05-19** | AAD bound on every file-path AEAD. **Step 0** range-math audit committed at `docs/wip/review/phase-c-step0-audit.md`, Outcome A (uniform `[nonce(12)][ciphertext][tag(16)]` chunks, no chunk-0 envelope header) adopted in all subsequent code. **Step 1** Go AAD foundation: `crypto/aad.go` exports `BuildChunkAAD(fileID, chunkIndex, totalChunks)`, `BuildFEKEnvelopeAAD(fileID, keyTypeByte)`, `BuildMetadataFieldAAD(fileID, fieldName, ownerUsername)` plus canonical field-label constants `AADFieldFilename="encrypted_filename"` / `AADFieldSha256="encrypted_sha256sum"`; 23 tests including the hardcoded 56-byte cross-language conformance vector for `BuildChunkAAD("a1b2c3d4-e5f6-7890-abcd-ef1234567890", 3, 10)`. **Step 2** Go crypto primitives: `EncryptFEK`/`DecryptFEK` take `fileID`; `DecryptFileMetadata`/`DecryptMetadataWithDerivedKey` take `(fileID, fieldName, ownerUsername)`; `CreateEnvelope`/`ParseEnvelope` renamed to `CreateFEKEnvelopeHeader`/`ParseFEKEnvelopeHeader`. Opportunistic dead-code deletions: B-17 (`EncryptFile`/`DecryptFile`), B-18 (`crypto/envelope.go` stub), C-23 (`models.CreateFile`), C-24 (`models.UpdatePasswordHint`). **Step 3** CLI: `arkfile-client` mints client-side UUIDv4 `file_id` before encryption, sends it in `/api/uploads/init` payload, retries up to 3 attempts on HTTP 409 / stable code `file_id_conflict` (`errFileIDConflictExhausted` after 3rd); `ServerFileInfo` gained `OwnerUsername`; `.arkbackup` `bundleMeta` gained `OwnerUsername` and refuses pre-Phase-C bundles cleanly. Negative tests (chunk reorder, cross-file, truncation, FEK swap, wrong owner, wrong field label, wrong file_id) plus `TestIsFileIDConflict` in `crypto_utils_test.go` and `offline_decrypt_test.go`. **Step 4** Server: `handlers/uploads.go` `CreateUploadSession` accepts client-supplied `file_id`, validates strict UUIDv4 (`uuid.Parse` + `Version()==4` + `Variant()==uuid.RFC4122` + canonical-string re-render), enforces global uniqueness across `file_metadata.file_id` AND `upload_sessions.file_id` inside the session-insert transaction, returns HTTP 409 with stable `file_id_conflict`. Schema cleanup: redundant non-unique `idx_file_metadata_file_id` dropped, new `CREATE UNIQUE INDEX idx_upload_sessions_file_id_unique`, `encrypted_fek` `NOT NULL` on both tables. `owner_username` surfaced on `/api/files/:id/meta`, `/api/files`, and `/api/files/metadata/batch`. Vestigial chunk-0 envelope-header arithmetic removed in upload/download/share range math; range bounds use `total_size` (encrypted-stream length), never `padded_size`. Two new tests in `handlers/uploads_test.go`: `TestCreateUploadSession_RejectsNonUUIDv4FileID` (11 sub-cases) and `TestCreateUploadSession_FileIDConflictStableError`. Out-of-band cleanup applied while files were open: typed `handlers.APIResponse.Error` field, `JSONErrorCode`/`JSONErrorCodeData` helpers, all five rate-limit JSON response sites migrated to stable `"rate_limited"` code and snake_case `data.retry_after_seconds`, `Retry-After` HTTP header set everywhere it was missing. **Step 5** TS AAD foundation: `client/static/js/src/crypto/aad.ts` + `__tests__/aad.test.ts` byte-for-byte compatible with Go module; `bigint` used for `chunkIndex`/`totalChunks` (BE-encoded uint64). B-27 (`MAX_FILE_SIZE`) removed from `crypto/constants.ts`, along with `FileTooLargeError` class and its `getUserFriendlyMessage` branch in `crypto/errors.ts`. **Step 6** TS crypto primitives: `AESGCMDecryptor.decryptChunk(encryptedChunk, aad?)` and module-level `decryptChunk`/`verifyChunk` convenience wrappers accept optional `aad`. `decryptFEK(fek_b64, kek, fileID)` requires `fileID`, parses envelope header out, reconstructs `BuildFEKEnvelopeAAD` from on-wire key-type byte, rejects unsupported envelope versions before AEAD. `decryptMetadataField(ct_b64, nonce_b64, key, fileID, fieldName, ownerUsername)` requires all three context inputs and reconstructs `BuildMetadataFieldAAD`. New `__tests__/metadata-helpers.test.ts` covers FEK round-trip for both keyType bytes plus negatives for wrong fileID, flipped keyType byte, unsupported envelope version, too-short input, missing-fileID; and metadata-field round-trip plus negatives for wrong fileID, swapped field label, wrong ownerUsername, and each missing arg. **Step 7** TS file flows: `upload.ts` mints `crypto.randomUUID()` per file, sends it in init payload as `file_id`, sanity-checks server echo, retries on typed `FileIDConflictError` (HTTP 409 / `file_id_conflict`) up to 3 attempts before hard error. Metadata encrypts under `BuildMetadataFieldAAD(fileID, AAD_FIELD_FILENAME|SHA256, username)`; FEK under `BuildFEKEnvelopeAAD(fileID, keyTypeByte)`; every chunk under `BuildChunkAAD(fileID, BigInt(i), BigInt(totalChunks))`. Step 0 Outcome A wired: chunk-0 envelope header dropped on upload AND download; `calculateTotalEncryptedSize` lost its `headerSize` argument; `streaming-download.ts` no longer strips the first two bytes of chunk 0. `streaming-download.ts` replaces its private metadata-field decryptor with the shared `decryptMetadataField` helper (owner-path now requires `metadata.owner_username` in server response). `download.ts`, `share.ts`, `list.ts`, `shares/share-list.ts`, and `utils/digest-cache.ts` thread `file_id` and `owner_username` through every helper call; `ServerFileEntry`, `MetadataBatchResponse.files`, `RawFileEntry`, and the two local `FileMetaResponse` interfaces all gained `owner_username`. `digest-cache.ts` deleted its duplicated private decryptor and now goes through `decryptMetadataField` with `AAD_FIELD_SHA256`. **Step 8** no-stale-call-site sweep: no surviving callers use the old (no-AAD) signatures; the only `envelope.headerSizeBytes` reference left is in the chunking-config schema (not the chunk stream); `crypto/primitives.ts` `encryptAESGCM`/`decryptAESGCM` already supported `aad` from a prior phase. Test updates: `__tests__/upload-batch.test.ts` init fetch mock echoes back the client-supplied `file_id`; `streaming-download.test.ts` dropped its `addEnvelopeHeader` helper and now AAD-encrypts chunk 0 the same way `upload.ts` produces it; `digest-cache.test.ts` encrypts each test entry under metadata-field AAD with an `owner_username`. Validation: full local gate green — `dev-reset.sh` + `e2e-test.sh` + `e2e-playwright.sh` all pass; `go test ./...` green across all 10 packages; `bun test client/static/js/src/__tests__/` 352/352 across 18 files. Beta impact: **RED** — all existing encrypted files become unreadable; login, TOTP, and account survive. RED heads-up message handled separately by the developer. |
| D | — | F-04, F-05, F-06, F-13 | **Done 2026-05-19** | Supply-chain hardening. Three sub-clusters landed together. **D1 (F-05) Go build hardening:** `scripts/setup/build.sh` `build_go_binaries_static()` now invokes `go build` with `-trimpath`, `-buildvcs=false`, and an ldflags string baking in `-s -w -buildid= -extldflags "-static"`. Reproducibility verified manually: two consecutive `dev-reset.sh` runs at the same commit produced byte-identical `arkfile`, `arkfile-client`, and `arkfile-admin` binaries (`sha256sum` match across all three; bumping any source constant correctly invalidates the hash, confirming the flags work). **D2 (F-06) vendored libsodium:** `vendor/jedisct1/libsodium` added as a top-level git submodule pinned to tag `1.0.20`; `.gitmodules` and `.gitignore` updated (allowlist `!vendor/jedisct1/`, ignore `*.lo`, in-tree autotools build outputs, and `.libs/` artifacts). `scripts/setup/build-libopaque.sh` fully rewritten to (1) build the vendored libsodium statically via `./autogen.sh && ./configure --enable-static --disable-shared --disable-pie --without-pthreads && make` before (2) building noise_xk / liboprf / libopaque against the vendored include path and the resulting `vendor/jedisct1/libsodium/src/libsodium/.libs/libsodium.a` static archive. The previous 7-OS host-package-manager auto-install code path (apt / dnf / apk / pkg / pkg_add / pkgin / pacman) and all `pkg-config libsodium` calls were deleted in line with the greenfield "no fallback" policy. `scripts/setup/build-config.sh` adds `LIBSODIUM_DIR`/`LIBSODIUM_INCLUDE`/`LIBSODIUM_A` exports and extends `c_libs_exist()` to also verify the libsodium static archive, so `SKIP_C_LIBS=true` correctly reuses the cached build on subsequent `dev-reset.sh` iterations. `scripts/setup/build.sh` line 409 `CGO_LDFLAGS` now references `$(pwd)/$LIBSODIUM_A` instead of `pkg-config --libs --static libsodium`, with a fail-closed file-exists check. New host prerequisite: `autoconf` / `automake` / `libtool` for libsodium's autotools bootstrap (the rewritten script's `require_autotools()` prints an OS-specific install hint if any are missing); host `libsodium-dev` is no longer required and can be removed. The WASM build path under `vendor/stef/libopaque/js/libsodium.js` was already vendored at a separate `libsodium.js 0.7.16` pin and is unchanged. **D3 (F-04 + F-13) frontend supply-chain:** Both `package.json` files (root + `client/static/js/`) re-pinned to exact versions with no `^` ranges (`@noble/hashes 2.0.1`, `@playwright/test 1.58.2`, `@types/bun 1.3.10`, `zxcvbn 4.4.2`, `@types/zxcvbn 4.4.5`, `bun-types 1.3.2`, `typescript 5.9.2`); both `bun.lock` files refreshed and verified to install cleanly with `--frozen-lockfile`. `scripts/setup/build.sh` `bun install` invocation now uses `--frozen-lockfile`, with a clear error message that points to the regeneration command if a deliberate dependency update is needed. New `inject_sri_attributes()` step in `build.sh` computes `sha384` of every shipped client-side script (`libopaque.js`, `dist/app.js`, `shared-init.js`) after they're copied into the build tree, then rewrites the deployed HTML copies under `${BUILD_CLIENT}/static/` to add `integrity="sha384-..." crossorigin="anonymous"` attributes on the corresponding `<script>` tags. Source `client/static/index.html` and `shared.html` stay unchanged on the source-tree side; only the deployed copies carry SRI. Each injection is verified by a per-script `grep -q "integrity=..."` check that hard-fails the build if any sed pattern did not match (defends against future HTML reformatting that would silently lose SRI). Browser-side SRI verified by reading the deployed `/opt/arkfile/client/static/index.html` and confirming both expected `sha384-` attributes are present. Validation: `sudo bash scripts/dev-reset.sh` green, `bash scripts/testing/e2e-test.sh` green end-to-end (OPAQUE registration, login, TOTP setup/verify, file upload/download, share creation, all exercising the vendored libsodium-linked binary and the SRI'd WASM client). Beta impact: **GREEN** — purely build/deploy hardening; no user-visible change, no schema change, no client-format change. **Ride-along Mediums F-11 / F-12 / F-25 (SeaweedFS MD5, rqlite pin, govulncheck/SBOM) were intentionally NOT included in this phase per developer decision; banked for a separate hygiene pass.** |
| E | — | B-01, B-03, B-19, D-10, D-12, C-01 | **Done 2026-05-19** | Remediated server-controlled config downgrade class (B-01, B-03, B-19) via client-side compile-time default clamp/ratchet floors in floors.ts; embedded share envelope KDFParams binding (D-10, D-12) with Go/TS cross-validating floor gates; added 16 MiB early padding DoS allocation cap; added Go/TS cross-language Argon2id conformance vector testing pipeline (TestArgon2ConformanceFixtureGeneration) and verified absolute key-derivation equality. Existing shares cleared; no schema changes. local gate fully validated. |
| F | F1 | A-17 (mlock/madvise/PR_SET_DUMPABLE), infra | **Done 2026-05-19** | Tier-3 user-secret-master infrastructure: loads master from `/opt/arkfile/etc/keys/user-secret-master.bin`, performs `syscall.Mlock`, `unix.Madvise(buf, unix.MADV_DONTDUMP)`, and process-wide `PR_SET_DUMPABLE=0` to block coredumps. Exposes `DeriveTier3Subkey`. |
| F | F2 | A-18 | **Done 2026-05-19** | TOTP secret encryption migrated to Tier-3 key derived via `DeriveTier3Subkey([]byte("totp_user"))` instead of `system_keys` database dependency. |
| F | F3 | A-07, A-16 | **Done 2026-05-19** | Hashed backup codes implemented on `user_totp_backup_codes` table. Reuses global Argon2id floor parameters and index-specific salts. Optimistic UPDATE-rejection pattern blocks concurrent races, and timing timing-permutations prevent code index inference. |
| F | F4 | (infra) | **Done 2026-05-19** | Contact-info encryption migrated to Tier-3 key derived via `DeriveTier3Subkey([]byte("contact_info"))`. |
| F | F5 | A-15 | **Done 2026-05-19** | Reachable TOTP recovery via backup code setup under temporary JWT eligibility gate. User can use backup code to clean enrollment and register new device. |
| F | F6 | (documentation) | **Done 2026-05-19** | Tier-3 design, memory-hardening specifications, and file rotation instructions documented. |
| G | — | E-21, E-03, E-04, E-05, E-02, A-12 | Not started | Financial-audit schema; GREEN beta |
| H | — | (documentation) | Not started | Add plain-language threat-model section to `docs/security.md` |

---

## §7. Phase Ordering and Rationale

```
A  →  B  →  C  →  D  →  E  →  F  →  G  →  H
auth  cookies  AAD   supply  params  TOTP   billing  docs
```

**Why this order:**

1. **A first** — code is fresh from the A-01 / F-01 work; auth-surface Highs share files and concepts with what was just touched. Marginal cost is lowest now.
2. **B second** — XSS + token-in-localStorage is the single largest blast-radius gap; the frontend refactor must land before any other frontend changes (otherwise Phase C's TS crypto changes would need re-review against the new auth flow).
3. **C third** — largest crypto-correctness fix and a coordinated Go + TS + CLI change. Benefits from Phase B having stabilized the frontend. Greenfield "redefine, don't increment" applies to the envelope format. RED beta-impact event.
4. **D fourth** — interleaved here because the codebase is in a known-good state right after C (natural context-switch point) and the SRI / build-flag / frozen-lockfile work catches supply-chain regressions during the remaining E / F / G work.
5. **E fifth** — embeds JSON parameters into the shipped binaries / TS bundle that Phase D just hardened. The compile-time-floor work is most valuable once the build pipeline is reproducible.
6. **F sixth** — Tier-3 redesign (a fresh, self-contained design — A1's filesystem delivery of the bootstrap token is a Tier-1 convenience, not a Tier-3 prototype) is internal-only (no frontend impact post-B) and includes a schema migration that should not coincide with another.
7. **G seventh** — largest schema change (soft-delete users); the user-deletion model is touched by every other system, so doing it last lets the migration happen once with full knowledge of what references `users`.
8. **H last** — the threat-model documentation should describe the system as it actually is after Phases A–G land, not the system as it was before.

### Alternative bucketings considered and rejected

- **Strict "by severity" ordering**: lumps everything into one pile and ignores shared root causes.
- **"By file area" ordering**: forces E-21 (high-priority billing) to wait behind low-severity `auth/` items.
- **"Phase D last"** (after Phase G): defensible. Trade-off is that supply-chain regressions during E/F/G work go undetected longer.
- **"Phase D in parallel"**: rejected — single developer.

---

## §8. Future work (not in the High campaign)

Items intentionally deferred:

- **TPM-sealing of `/opt/arkfile/etc/keys/user-secret-master.bin`**: small additive enhancement to Phase F. Defends a stolen disk image from yielding the file in cleartext. Worth scoping after Phase F lands.
- **TEE / HSM / external KMS**: not aligned with the self-hosted privacy-first thesis. Revisit only if an enterprise customer demands it for compliance.
- **All Medium and Low findings** from the executive summary: out of scope for the High campaign. A separate plan should follow Phase H.
- **Post-quantum readiness** (`docs/wip/post-quantum.md`): out of scope for this campaign.

End of plan.
