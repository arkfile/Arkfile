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

Bootstrap token in Phase A1 lives in `/opt/arkfile/etc/keys/bootstrap-token.bin` as a small dry-run of the Tier-3 filesystem-secret pattern, even though the bootstrap token itself is Tier-1 by trust level. (The filesystem location is independent of the tier; what matters is that the *trust anchor* for Tier-3 keys is the file, not the DB.)

---

## §5. Phases A–H

### Phase A — Auth-pathway lockdown

**Why this phase:** the auth surface was the focus of the recent A-01 / F-01 work. The remaining Highs in `auth/` are cheap to close while the code is fresh. Phase A also prototypes the Tier-3 filesystem-secret pattern (cluster A1) so Phase F is a routine extension rather than a novel introduction.

**Findings closed:** A-13, A-26, F-03, A-14, A-08, A-09, A-10.

**Files most likely touched:** `auth/bootstrap.go`, `handlers/bootstrap.go`, `handlers/middleware.go`, `auth/token_revocation.go`, `auth/jwt.go`, `models/refresh_token.go`, `auth/totp.go`, `database/unified_schema.sql`, `scripts/dev-reset.sh`, `scripts/prod-deploy.sh`, `scripts/local-deploy.sh`, `scripts/test-deploy.sh`, `config/config.go` or `config/security_config.go`.

**Greenfield notes:** the bootstrap-token row schema gets a `consumed_at` column. The refresh-token table layout changes (entropy bump + family-revoke columns); per greenfield posture, rewrite the column rather than adding a `_v2` table.

#### Cluster A1 — Bootstrap-token hardening + Tier-3 prototype

**Findings:** A-13 (single-use), A-26 (no stdout logging), F-03 (no journal logging), A-14 (production-env fail-closed).

**Pre-work:**
1. Read `handlers/bootstrap.go` end-to-end to map the bootstrap-token redemption lifecycle.
2. Read `auth/bootstrap.go` (token generation, storage in `system_keys`).
3. Read `scripts/dev-reset.sh`, `scripts/local-deploy.sh`, `scripts/prod-deploy.sh`, `scripts/test-deploy.sh` to find every place the token is written to stdout / journal / log file.
4. Identify the existing `system_keys` row layout for the bootstrap token.
5. Identify how `ENVIRONMENT=production` and `ADMIN_DEV_TEST_API_ENABLED=true` are read at startup; locate the right place for a fail-closed check.

**Design decisions:**
- Atomic single-use enforcement: add `consumed_at TIMESTAMP` to the bootstrap-token row, set inside the transaction that creates the first admin. Reject redemption if `consumed_at IS NOT NULL`.
- Communicate the bootstrap token to the operator via a file at `/opt/arkfile/etc/keys/bootstrap-token.bin` (mode 0400, owned by `arkfile` user). Remove all stdout / journal prints.
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
- Add `consecutive_totp_failures INTEGER NOT NULL DEFAULT 0` and `last_failed_attempt_at TIMESTAMP` to `user_totp`.
- Lockout policy: after 10 consecutive failures, reject TOTP verification with a lockout response until `last_failed_attempt_at + 15 minutes`. Successful verification resets the counter.
- Emit a security event (via `logging/security_events.go`) on each failure and on lockout.

**Implementation order:**
1. Schema additions in `database/unified_schema.sql`.
2. Increment / reset / check in the TOTP verification handler.
3. Security event emission.
4. Tests for lockout, reset on success, expiry of lockout window.

**Validation pass:** `e2e-test.sh` covers TOTP flows directly.

**Beta impact:** GREEN. Server-internal.

#### Cluster A3 — JWT + refresh-token hardening

**Findings:** A-09 (per-request user-wide JWT revocation), A-10 (refresh-token entropy + family-revoke).

**Pre-work:**
1. Read `auth/token_revocation.go` to map the existing revocation tables and middleware.
2. Read `models/refresh_token.go` and `auth/jwt.go` to understand current refresh-token format and storage.
3. Identify the full-JWT TTL default (`utils.GetJWTTokenLifetime()`); plan to shorten if currently long.

**Design decisions:**
- A-09: `TokenRevocationMiddleware` adds a per-request lookup of any user-wide revocation marker (e.g., `IsUserJWTRevoked(username, jwt_iat)`). Truthy result rejects the JWT regardless of TTL.
- A-10: refresh tokens become 32 random bytes (256-bit) instead of `uuid.NewV4()` (122-bit). Storage remains hashed.
- A-10: family-revoke on reuse detection. A refresh-token row tracks a `family_id`; if a token from a family is presented after the family has been rotated past it, the entire family is revoked and a security event is emitted.
- Shorten full-JWT TTL to ~5 minutes; refresh handles the rotation.

**Implementation order:**
1. Schema additions to `refresh_tokens` (family_id, rotated_at).
2. Refactor refresh-token generation in `auth/` to use 32 random bytes via `auth.GenerateRefreshToken()`.
3. Implement reuse-detection logic in the refresh handler.
4. Add `IsUserJWTRevoked` lookup to `TokenRevocationMiddleware`.
5. Shorten full-JWT TTL default.
6. Tests for: family-revoke on reuse, per-request user-wide revocation enforcement, TTL shortening.

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

**Greenfield notes:** non-overlapping cutover. The server stops accepting the `Authorization: Bearer` header for browser-origin requests once cookies land. No transitional dual-mode. CLI clients (`arkfile-client`, `arkfile-admin`) keep using `Authorization: Bearer` because they're not browser-origin and cookies don't apply to them.

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
- **Password scrubbing:** remove `window.totpLoginData` entirely. The TOTP flow does not need the plaintext password; it only needs the temp token (now in a cookie). If the flow currently requires the password for some derivation, isolate that derivation to a module-private constant zeroed immediately after use.

#### Implementation order

1. Server-side cookie writer in `handlers/auth.go` for login finalize, TOTP verify, refresh, logout.
2. Server-side cookie reader middleware (replaces or augments `JWTMiddleware`'s header-based read).
3. CSRF double-submit middleware checking `X-CSRF-Token` header against `__Host-arkfile-csrf` cookie.
4. Reject `Authorization: Bearer` for browser-origin requests (UA-based or Origin-based detection). CLI clients keep working.
5. Frontend refactor: remove all `localStorage.getItem('token')` / `setItem('token')` / `removeItem('token')` calls. Remove `window.totpLoginData`. Update the auth-fetch wrapper to omit `Authorization` and include `X-CSRF-Token` + `credentials: 'include'`.
6. Delete `getToken` / `setToken` / `clearToken` from `auth-manager.ts` and replace with cookie-based equivalents (or remove them entirely since cookies are server-managed).
7. Tests: server-side cookie issuance + CSRF check; frontend tests for the new fetch wrapper; Playwright test asserting `localStorage.getItem('token')` returns null after login.

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

### Phase E — Parameter floors + share envelope binding

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
- Existing files unaffected (the embedded Argon2id floors are the same params currently served by `/api/config/argon2`; client encryption keeps producing identical KDF output).
- **Existing shares stop working** because the share-envelope format changes. Shares are ephemeral by design, so this is low-coordination. Owners can re-share.

**Heads-up message draft:**
> "Pushed a security update that hardens how shared file links are protected. Any active share links will stop working; please re-share files if needed. Your own files and account unaffected."

---

### Phase F — Tiered at-rest secret store + TOTP hardening

**Why this phase:** today, an attacker who acquires both the DB and `secrets.env` (which contains `ARKFILE_MASTER_KEY`) recovers every server-held user secret in cleartext: TOTP secrets, TOTP backup codes, contact info, JWT signing keys, OPAQUE keys. Phase F splits server-held secrets into trust tiers so that a `secrets.env`-only leak (or a DB-only leak) does not yield user-secret material. The user-secret-wrapping master moves from the DB to a separate filesystem path (`/opt/arkfile/etc/keys/user-secret-master.bin`), not in `system_keys` at all. TOTP backup codes additionally become **hashed** (Argon2id, per code) instead of encrypted — so even a full compromise (DB + `secrets.env` + Tier-3 file) cannot recover backup codes.

See §3 for the full threat-model table and §4.3 for the tier assignment table.

**Findings closed:** A-07, A-17, A-18, A-15, A-16 (ride-along).

**Files most likely touched:** new `crypto/user_secret_master.go`, `crypto/totp_keys.go`, `auth/totp.go`, `auth/totp_test.go`, `auth/totp_backup_test.go`, `models/contact_info.go`, `database/unified_schema.sql`, `handlers/auth.go` (TOTP reset flow), new `scripts/maintenance/rotate-user-secret-master.sh`, deploy scripts (`local-deploy.sh`, `test-deploy.sh`, `prod-deploy.sh`, `dev-reset.sh`) to generate the Tier-3 file at install.

**Greenfield notes:** schema additions for `user_totp_backup_codes` (new table). The old `user_totp.backup_codes_encrypted` column is dropped (no dual-column transition). Existing TOTP enrollments cannot be migrated (the old encryption key is replaced and we can't decrypt + re-encrypt without the operator's coordination); cleanest move is to drop all `user_totp` rows and force re-enrollment.

#### Sub-clusters

##### F1 — Tier-3 user-secret-master infrastructure

**Pre-work:**
1. Confirm the file path convention `/opt/arkfile/etc/keys/` exists and is owned by the `arkfile` user. (Phase A1 already creates `/opt/arkfile/etc/keys/bootstrap-token.bin` there.)
2. Decide whether to generate the Tier-3 file at first-startup (like `KeyManager.GetOrGenerateKey`) or at install-time in the deploy script. **Recommendation: at install-time in the deploy script**, with a fail-closed check at startup that the file exists. Reduces ambiguity about who owns the file's creation.

**Design decisions:**
- Path: `/opt/arkfile/etc/keys/user-secret-master.bin`. 32 random bytes. Mode 0400. Owner `arkfile` user.
- Loader: `crypto/user_secret_master.go` reads the file at process startup, mlocks the buffer, applies `MADV_DONTDUMP` and `PR_SET_DUMPABLE=0`. Fail-closed if the file is missing or wrong size.
- HKDF-derive per-purpose subkeys: `totp_user_master` (for TOTP secret encryption) and `contact_info_master` (for contact-info encryption). Domain-separated info strings.
- Rotation: a new `scripts/maintenance/rotate-user-secret-master.sh` that reads old + new keys, re-encrypts every `user_totp.secret_encrypted` and every contact-info blob, swaps the file atomically.

**Implementation order:**
1. New `crypto/user_secret_master.go` with `LoadTier3Master()`, `DeriveTier3Subkey(purpose string)`.
2. Update each deploy script (`dev-reset.sh`, `local-deploy.sh`, `test-deploy.sh`, `prod-deploy.sh`) to generate the file at install if missing.
3. Tests: file-missing path fails closed; file-wrong-size fails closed; subkey derivation domain separation.

**Beta impact:** GREEN. (The file is generated by `test-update.sh`'s redeployment step; users see nothing.)

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

**Design decisions:**
- New table `user_totp_backup_codes`:
  ```
  CREATE TABLE user_totp_backup_codes (
    username TEXT NOT NULL,
    code_hash BLOB NOT NULL,
    code_salt BLOB NOT NULL,
    used_at TIMESTAMP,
    UNIQUE(username, code_hash)
  );
  ```
- Backup-code generation: 10 codes of ~10 alphanumeric chars each. Use rejection sampling (not modulo) to fix A-42 bias. Each code gets its own random 16-byte salt; stored as `argon2id(code, salt, m=64MiB, t=3, p=1)`.
- Verification: iterate user's rows, compute `argon2id(submitted_code, row.salt)`, constant-time compare with `row.code_hash`. On match, set `used_at = now()` in a transaction; reject if already set. (UNIQUE on `(username, code_hash)` plus tx-scoped used-at check closes the A-16 race.)
- The user only sees the codes once, at enrollment. The UI displays them and asks the user to save them; server never re-shows.
- Drop `backup_codes_encrypted` column from `user_totp`.

**Implementation order:**
1. Schema additions in `database/unified_schema.sql`.
2. Refactor backup-code generation in `auth/totp.go`.
3. Refactor backup-code verification.
4. Drop old column.
5. Tests: race test on concurrent submission of the same code; rejection-sampling statistical test; "can't show codes after enrollment" assertion.

**Beta impact:** rolls into the YELLOW from F2 (same re-enrollment).

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

**GREEN** assuming `credit_transactions` is empty/small on beta. A duplicate-`transaction_id` row in the existing beta DB would block the `UNIQUE(transaction_id)` migration; check first with `SELECT transaction_id, count(*) FROM credit_transactions GROUP BY transaction_id HAVING count(*) > 1;` and dedupe if necessary.

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
| A | A1 | A-13, A-26, F-03, A-14 | Not started | Bootstrap-token hardening + Tier-3 filesystem prototype |
| A | A2 | A-08 | Not started | Per-user TOTP failure lockout |
| A | A3 | A-09, A-10 | Not started | JWT + refresh-token hardening; YELLOW beta (forced re-login) |
| B | — | A-04, F-08, A-05, F-07 | Not started | `__Host-` cookies + CSRF; YELLOW beta (forced re-login) |
| C | — | B-02, C-02, C-03, C-19, B-08, B-05 | Not started | AAD on every file-related AEAD; **RED beta** (re-upload required) |
| D | — | F-04, F-05, F-06, F-13 | Not started | Supply-chain hardening; GREEN beta |
| E | — | B-01, B-03, B-19, D-10, D-12, C-01 | Not started | Parameter floors; YELLOW beta (existing shares broken) |
| F | F1 | (infra) | Not started | Tier-3 user-secret-master infrastructure |
| F | F2 | A-18 | Not started | TOTP secret encryption migrates to Tier-3 |
| F | F3 | A-07, A-16 | Not started | Hashed backup codes |
| F | F4 | (infra) | Not started | Contact-info encryption migrates to Tier-3 |
| F | F5 | A-15 | Not started | Reachable TOTP recovery via backup code |
| F | F6 | A-17 (mlock/madvise) + docs entry | Not started | Tier-3 file is mlocked at process start |
| G | — | E-21, E-03, E-04, E-05, E-02, A-12 | Not started | Financial-audit schema; GREEN beta |
| H | — | (documentation) | Not started | Add plain-language threat-model section to `docs/security.md` |

---

## §7. Phase Ordering and Rationale

```
A  →  B  →  C  →  D  →  E  →  F  →  G  →  H
auth  cookies  AAD   supply  params  TOTP   billing  docs
```

**Why this order:**

1. **A first** — code is fresh from the A-01 / F-01 work; auth-surface Highs share files and concepts with what was just touched. Marginal cost is lowest now. A1 also prototypes the Tier-3 filesystem-secret pattern that Phase F will use.
2. **B second** — XSS + token-in-localStorage is the single largest blast-radius gap; the frontend refactor must land before any other frontend changes (otherwise Phase C's TS crypto changes would need re-review against the new auth flow).
3. **C third** — largest crypto-correctness fix and a coordinated Go + TS + CLI change. Benefits from Phase B having stabilized the frontend. Greenfield "redefine, don't increment" applies to the envelope format. RED beta-impact event.
4. **D fourth** — interleaved here because the codebase is in a known-good state right after C (natural context-switch point) and the SRI / build-flag / frozen-lockfile work catches supply-chain regressions during the remaining E / F / G work.
5. **E fifth** — embeds JSON parameters into the shipped binaries / TS bundle that Phase D just hardened. The compile-time-floor work is most valuable once the build pipeline is reproducible.
6. **F sixth** — Tier-3 redesign is internal-only (no frontend impact post-B) and includes a schema migration that should not coincide with another. F also depends on the Tier-3 filesystem-secret pattern that Phase A1 prototyped.
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
