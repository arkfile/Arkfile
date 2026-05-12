# Arkfile In-Depth Security Review — Executive Summary & Synthesis

Status: **Slice G complete** (2026-05-12). This is the consolidated executive synthesis for the multi-session adversarial security review of Arkfile defined in `docs/wip/review/00-plan.md` and driven by the prompt in `docs/wip/idsrp.md`. It draws **only** on the six analytical slice deliverables (`01-auth-opaque.md`, `02-crypto-keys.md`, `03-files-upload-download.md`, `04-sharing.md`, `05-api-authz-admin-billing.md`, `06-frontend-supply-ops.md`). No fresh source code was read for this document; every claim traces to a slice finding with a file:line citation already validated in that slice.

Greenfield posture per `AGENTS.md`: Arkfile has no production deployments; `test.arkfile.net` is the only live beta. Severities in this document do not soften for "backwards compatibility"; the policy is fix-properly, not accommodate.

Per-finding evidence lives in the slice docs. This document carries the cross-slice synthesis: the headline risks where one root cause is visible across multiple slices, the consolidated index, the merged tables, and explicit answers to every question in `idsrp.md` §19.

---

## 1. Executive Summary

### 1.1 Overall security posture

Arkfile's documented design — OPAQUE for password-authenticated key exchange, client-side AEAD for file content, Argon2id-derived KEKs that wrap per-file random FEKs, password-derived share envelopes, no PII / no IP logging — is sound and modern. The primitives chosen (libopaque/liboprf/libsodium for OPAQUE; AES-256-GCM via Web Crypto and Go's `crypto/aes`; Argon2id; Ed25519 JWT signatures; SHA-256-keyed HMAC EntityID) are appropriate. Where the design is correctly implemented, it delivers what it claims.

However, the **implementation does not yet meet the design's claims** in several places that matter materially for the threat model. The review surfaced **179 findings** across the six slices (2 Critical, 27 High, 61 Medium, 52 Low, 37 Informational; see §4 for the consolidated index). Of those, four cross-slice patterns dominate the risk picture:

1. **The two-tier JWT model is not enforced** (Slice A `A-01`). The post-OPAQUE temp token is intended to be valid only at `/api/totp/{setup,verify,auth}`; the validator does not check `aud` or `requires_totp`, both tokens are signed with the same Ed25519 key, and `RequireTOTP` only consults a DB flag that every TOTP-enrolled user has. The "second factor" is therefore cosmetic at the protocol level: anyone who completes OPAQUE alone reaches every protected route.

2. **Localhost-only protections are bypassable from anywhere on the internet** (Slice F `F-01`, Critical). The Echo `c.RealIP()` default walks attacker-controlled `X-Forwarded-For`; `main.go` does not override `e.IPExtractor`; `Caddyfile.prod` and `Caddyfile.test` do not strip the incoming header. `AdminMiddleware`'s localhost gate and the admin-bootstrap localhost gate both trust `c.RealIP()` for authorization. This single defect escalates four Slice A findings (A-02, A-13, A-14, A-26) and one Slice E finding (E-14) into a remotely-reachable admin and bootstrap-redemption attack surface.

3. **Authenticated-encryption integrity does not bind cryptographically to file identity or chunk order** (Slice B `B-02` / `B-05` / `B-08`, Slice C `C-02` / `C-03` / `C-19`). No file-chunk, FEK envelope, or metadata encryption operation uses AAD. The server (or any party with DB write access) can swap encrypted chunks between two of the same user's files, reorder chunks within a file, or substitute one user's FEK envelope for another. The end-of-file plaintext SHA-256 verification (Slice C `C-13`/`C-14`) detects content-level swap but only after the file has been written to disk; the warning is post-facto and the Blob fallback path skips verification entirely. The claimed file-identity integrity is not provided.

4. **Server-side parameters that should be client-side floors are downloaded over an unauthenticated channel** (Slice B `B-01` / `B-03` / `B-19`). Argon2id parameters, chunking parameters, and password requirements are fetched at runtime from `/api/config/*` with no signature or pinning. A compromised server can silently weaken every future KDF derivation, every chunk size, and every password check. The same defect makes shared envelopes brute-forceable offline if a server operator obtains the envelope blob (Slice D `D-10`): the Argon2id parameters are not bound into the envelope, so the operator picks the cheapest parameters the client will accept.

A fifth pattern — credential material at rest — pulls together a coherent set of medium-severity findings that, taken together, mean a server-side compromise of `system_keys` + the DB recovers cleartext TOTP secrets and cleartext backup codes for every user (Slice A `A-07` + `A-17` + `A-18`).

The system is **not** broken end-to-end. Content confidentiality of file payloads against the server is **substantially** achieved: a server that follows protocol cannot read file plaintext, and a passive server-side observer learns roughly the padded-blob size, the timing of uploads, and the username — but not file content. The gaps above raise the bar for an *active* server that can swap, reorder, or substitute artifacts, and for an attacker who reaches the admin surface via `F-01` or `A-01`.

### 1.2 Most serious risks (top ten)

In priority order. Each entry cites the underlying slice finding(s) and the cross-slice escalation that elevates it above the per-slice severity.

1. **(Critical) `F-01` — `X-Forwarded-For` localhost-gate bypass.** Slice F. Escalates `A-02` (admin temp-token reach), `A-13` (bootstrap window), `A-14` (dev-test API in prod), `A-26` (bootstrap token in stdout), and `E-14` (admin middleware trusts header) into one cohesive remote-admin pathway. Fix: set `e.IPExtractor` to trust only `127.0.0.1/32` + `::1/128`; strip incoming XFF at Caddy; for authorization use `c.Request().RemoteAddr` not `c.RealIP()`.
2. **(Critical) `A-01` — two-tier JWT model not enforced.** Slice A. The validator does not check `aud` or `requires_totp`; both tiers use the same Ed25519 key. Combined with `F-01`, completing OPAQUE alone yields full access to every protected route, including admin. Fix: enforce audience claim at `echojwt.ParseTokenFunc`; reject `requires_totp=true` at every protected group; use separate signing keys per tier.
3. **(High, escalates with F-01) `F-03` — bootstrap token harvested from systemd journal.** With `F-01` allowing remote redemption and `A-13` keeping the token alive after the first registration, anyone with `journalctl` access on the host (root, ops staff, container shell) can seed a second admin remotely. Fix: stop logging the token; consume on first redemption.
4. **(High) `A-07` + `A-17` + `A-18` — TOTP backup codes encrypted, not hashed; master key co-located with every other server secret.** A `system_keys` + DB compromise yields plaintext TOTP backup codes for every user with zero offline cost. The TOTP master key is not `mlock`'d, not `MADV_DONTDUMP`'d, and is in the same table as the JWT signing key, the OPAQUE server private key, and the bootstrap token. Fix: store backup codes as per-code Argon2id hashes; move TOTP master to a separate at-rest store with rotation.
5. **(High) `A-05` + `F-07` — JWTs (temp and full) and refresh token in `localStorage`.** Any XSS, dependency compromise, or browser-extension reach yields full session takeover, and combined with `A-04` / `F-08` (plaintext password on `window.totpLoginData`) yields the password itself. Fix: move tokens to `__Host-` `HttpOnly` cookies with CSRF protection.
6. **(High) `B-02` + `B-05` + `B-08` + `C-02` + `C-03` + `C-19` — no AAD on file chunks, FEK envelope, or metadata.** A server with write access to the DB or storage can swap chunks within or between a user's files; the byte-range math trusts DB-stored `chunk_size_bytes`/`chunk_count`; the `models/file.go` doc claims AAD that the upload pipeline does not apply. End-of-file SHA-256 detects but only post-disk-write. Fix: bind `file_id`, chunk-index, and field-name into AAD for every file-related AEAD operation in both Go (`crypto/file_operations.go`, CLI) and TS (`crypto/upload.ts`, `streaming-download.ts`); fail at AEAD layer, not at end-of-file hash.
7. **(High) `B-01` + `B-03` + `B-19` + `D-10` + `D-12` — server-controlled crypto parameters.** Argon2id params, chunk params, password requirements are runtime-fetched from `/api/config/*` with no signature/binding. A compromised server silently downgrades every future encryption, password check, and share envelope. Stolen share envelopes are then brute-forceable offline at the weakest accepted params. Fix: embed parameter *floors* in client bundles; bind KDF params into share envelopes; refuse server-supplied params below floor.
8. **(High) `E-02` — SQL injection in `AdminSyncStatus` via interpolated `provider_id`.** Admin-authenticated only, but combined with `F-01` (remote-reachable admin) and `A-01` (temp token alone suffices), the precondition is no longer "trusted local admin". Fix: parameterized SQL; add a `golangci-lint` rule banning `fmt.Sprintf` adjacent to SQL keywords.
9. **(High, future-Critical) `E-21` + `E-03` + `E-04` + `E-05` — financial-audit integrity gaps.** `ON DELETE CASCADE` on `users(username)` wipes `credit_transactions` and `admin_logs` when a user is deleted; `settleOneUser` reads `user_credits.balance` outside the transaction; no UNIQUE constraint on `credit_transactions(transaction_id)`; process-local `lastSweepDate` allows duplicate sweeps on restart. Today these are billing-correctness defects; the moment a payment processor (Stripe, crypto, ACH, SEPA) is wired in, every one becomes Critical. Fix: soft-delete users; `UNIQUE(transaction_id)`; persistent `lastSweepDate`; tx-scoped reads.
10. **(High) `F-04` + `F-05` + `F-06` + `F-13` — supply-chain integrity gaps.** WASM `libopaque.js` served without SRI; Go binaries built without `-trimpath`/`-buildid=`/`-ldflags='-s -w'`/`-buildvcs=false` and no release signing; libsodium pulled from host apt/dnf rather than vendored submodule; `bun install` without `--frozen-lockfile`. Combined: an attacker who reaches the build host or the asset CDN can substitute crypto code with no integrity check downstream. Fix: SRI on every shipped asset; reproducible build flags; vendored libsodium; frozen lockfile; cosign-signed releases.

### 1.3 Whether cryptographic claims appear justified

`AGENTS.md` makes four cryptographic claims explicitly or by strong implication:

| Claim | Status | Caveat |
|---|---|---|
| OPAQUE is used and the password is never sent to the server | **Yes** | The browser does keep the plaintext password in `window.totpLoginData` during the TOTP-handoff window (`A-04`/`F-08`). The OPAQUE protocol itself does not leak the password; the *frontend integration* does, transiently. |
| Files are encrypted client-side before reaching the server | **Yes** | Content confidentiality is achieved. The server never sees plaintext file bytes. |
| File metadata (filename, size, original SHA-256) is encrypted | **Partial** | Filename and SHA-256 are encrypted under the Account-KEK (`B-07` notes that the same key wraps FEKs *and* encrypts metadata — domain-separation omission). **File size is not** end-to-end encrypted: the server learns the unpadded size before applying padding (`B-06`), and the padded size leaks ~2.2% of plaintext size to anyone with bucket access. Chunk count is plaintext (`D-21`). |
| No PII / no IP logging | **Mostly** | EntityID HMAC is correctly implemented. But `InfoLogger` lines in the upload/download path log username and file_id together (`C-15`), share creation logs the owner's username (`D-25`), the admin audit-log `details` column contains operator-supplied strings that can include sensitive inputs (`E-15`), `LogUserAction` records plaintext file_id, and `DEBUG_MODE=true` (enabled by `dev-reset.sh`) prints raw refresh tokens (`A-11`). The privacy posture is consistent in design but leaks in implementation. |

### 1.4 Whether file confidentiality from the server is actually achieved

**Yes for content; partial for metadata; partial for integrity.**

- **Content (file bytes).** Yes. AES-256-GCM with random per-chunk nonces under a random per-file FEK that is wrapped by an Argon2id-derived KEK held only client-side. A protocol-following server never sees plaintext. (Slice B §1.2.)
- **Metadata.** Filename, plaintext SHA-256, and the FEK itself are encrypted. File size is leaked to within ~10% via server-applied padding (`B-06`). Owner username, upload timestamp, chunk count, chunk size, storage-provider routing, and password hint are all server-visible by design. (Slice B §3.3, Slice C §3.3, Slice D §3.3.)
- **Integrity.** AEAD tag verification is performed on every decrypt. **However**, no AAD binds chunks to file or order (`B-02`/`B-05`/`C-02`), and the server-trusted byte-range math (`C-03`) means an active server can reorder or substitute chunks within the user's own file space. The end-of-file plaintext SHA-256 check catches content-level tampering but only after disk write (`C-13`), and the Blob fallback path skips it entirely (`C-14`). The claim "content authenticity against an active server" is therefore **not yet achieved**; the system relies on end-of-file SHA-256 as a second-tier integrity check, which is post-disk-write.

### 1.5 Top recommended fixes (consolidated, in landing order)

This is the order in which a fix campaign would have maximum risk-reduction per developer-hour. Each fix maps to one or more slice findings.

1. **Set `e.IPExtractor` to localhost-only, strip XFF at Caddy, and rebase admin/bootstrap authz on `c.Request().RemoteAddr`.** Closes `F-01` and downgrades `A-02`/`A-13`/`A-14`/`A-26`/`E-14` to their per-slice baselines. One main.go line + two Caddyfile blocks + a tiny refactor of `AdminMiddleware` and `bootstrap.go`.
2. **Enforce JWT audience and `requires_totp` claims at the validator.** Add `echojwt.ParseTokenFunc` rejection of wrong-aud and `requires_totp=true` on every protected group. Mint temp and full tokens with distinct Ed25519 keys (`jwt_signing_key_temp_v1`, `jwt_signing_key_full_v1`). Closes `A-01` and structurally protects against future audience-claim oversight. Add `RequireFullJWT` as defense-in-depth on `totpProtectedGroup`, `adminGroup`, and `pendingAllowedGroup`.
3. **Move auth tokens out of `localStorage` into `__Host-` `HttpOnly` `SameSite=Strict` cookies; add CSRF double-submit.** Stop storing the plaintext password on `window.totpLoginData`. Closes `A-04`/`A-05`/`F-07`/`F-08` and reduces the blast radius of any frontend compromise.
4. **Bind AAD to every file-related AEAD operation.** Chunk encrypt/decrypt: AAD = `file_id || chunk_index || chunk_count || ciphertext_sha256`. FEK envelope: AAD = `file_id || key_type`. Metadata fields: AAD = `file_id || field_name || owner_username`. Mirror in both Go (`crypto/file_operations.go`, CLI) and TS (`crypto/upload.ts`, `streaming-download.ts`). Bump the envelope version byte to `0x02` and reject unknown versions. Closes `B-02`/`B-05`/`B-08`/`C-02`/`C-03`/`C-19`.
5. **Bind Argon2id parameters into the share envelope; ship parameter floors in client bundles.** Embed `crypto/argon2id-params.json`, `crypto/chunking-params.json`, and `crypto/password-requirements.json` as compile-time constants in the TS bundle and the Go binaries; treat `/api/config/*` as informational only. Bind the actual KDF parameters used into the share envelope so a downgrade is detectable on decrypt. Closes `B-01`/`B-03`/`B-19`/`D-10`/`D-12`.
6. **Replace TOTP-backup-code AES-GCM blob with per-code Argon2id hashes + `UNIQUE(username, code_hash)` constraints**; `mlock`+`MADV_DONTDUMP`+`PR_SET_DUMPABLE=0` on the TOTP master key page; move TOTP master out of `system_keys` into a separately-stored on-disk file with rotation. Closes `A-07`/`A-16`/`A-17`/`A-18`.
7. **Schema-level financial-audit integrity.** Soft-delete users (`deleted_at TIMESTAMP`) rather than `DELETE FROM users`; add `UNIQUE(transaction_id)` on `credit_transactions`; persist `last_sweep_date` across restarts; move the read-of-balance inside the settlement transaction. Add CHECK constraints on `transaction_type` and `provider_id`. Closes `E-03`/`E-04`/`E-05`/`E-21`/`E-22`/`E-23`. Pre-requisite for any payment-processor work.
8. **Build-and-ship integrity.** Add `-trimpath`/`-buildid=`/`-ldflags='-s -w'`/`-buildvcs=false` to all three Go binaries; vendor libsodium as a pinned git submodule; run `bun install --frozen-lockfile`; emit SRI hashes for `libopaque.js` and `dist/app.js` at build time and embed them in the HTML; sign release artifacts with cosign or minisign; emit an SBOM. Closes `F-04`/`F-05`/`F-06`/`F-13`/`F-25`.
9. **Per-user TOTP failure lockout** keyed on username, not on EntityID. Add `consecutive_totp_failures`/`last_failed_attempt` to `user_totp`; lock after 10 failures; emit security event. Closes `A-08`.
10. **Per-request user-wide JWT revocation enforcement.** Add `IsUserJWTRevoked` to `TokenRevocationMiddleware`; shorten the full-JWT TTL to ~5 minutes; replace `uuid.New().String()` with 256-bit `auth.GenerateRefreshToken()`; add reuse detection that revokes the entire refresh-token family on detected replay. Closes `A-09`/`A-10`.

The 10 items above resolve 1 Critical, 12 High, and ~20 Medium findings. Everything else in §4 is addressable but lower-leverage.

---

## 2. Architecture & Data-Flow Summary (consolidated)

This section is built from Slice A §1, Slice B §1, Slice C §1, Slice D §1, and Slice E §1. The narrative is condensed; per-flow detail is in the slice docs.

### 2.1 Request path (production)

```
Internet  ──► Caddy (:443, TLS 1.3, deSEC DNS-01)
              │  appends (does NOT strip) X-Forwarded-For        ◄── F-01 root
              │  reverse_proxy localhost:8443  (tls_insecure_skip_verify)
              ▼
Arkfile Go process (Echo, :8443 internal TLS, :8080 plaintext)
              │  middleware order:
              │   1. CSPMiddleware           (sets CSP, X-Frame-Options=DENY)
              │   2. PrivacyRequestLogger    (logs EntityID HMAC; no IP)
              │   3. FloodGuardMiddleware    (401/404 flood detector, in-memory)
              │   4. CORSWithConfig          (AllowCredentials=true; see Slice F Open Q6)
              │  c.RealIP() default walks XFF; no e.IPExtractor override   ◄── F-01
              ▼
            route_config.go
              │
              ├─ public routes  (/, /healthz, /readyz, /api/config/*, /api/version,
              │                  /api/opaque/*, /api/admin/login/*, /api/bootstrap/*,
              │                  /api/totp/* via TOTPJWTMiddleware,
              │                  /api/refresh, /api/logout, /shared/:id,
              │                  /api/public/shares/*, /api/files/:fileId/export)
              │
              ├─ auth.Echo group  (JWTMiddleware + TokenRevocationMiddleware + RequireApproved)
              │      ├─ /api/totp/status, /api/totp/reset   (full JWT; reset unreachable from
              │      │                                       lost-device state — A-15)
              │      └─ totpProtectedGroup  (+ RequireTOTP)
              │             ├─ /api/files/**, /api/uploads/**   (Slice C)
              │             ├─ /api/shares (authz endpoints)    (Slice D)
              │             ├─ /api/files/:fileId/envelope
              │             ├─ /api/files/:fileId/export-token
              │             ├─ /api/credits
              │             └─ /api/revoke-token, /api/revoke-all
              │
              ├─ pendingAllowedGroup  (JWTMiddleware + RequireTOTP; intentionally omits Approved)
              │      └─ /api/user/contact-info  (GET/PUT/DELETE)
              │
              └─ adminGroup  (JWTMiddleware + AdminMiddleware)        ◄── E-01: no RequireTOTP
                     │   AdminMiddleware checks: localhost (via c.RealIP — F-01),
                     │   admin flag, EntityID rate-limit (10/min global),
                     │   audit log via LogSecurityEvent.
                     ├─ /credits, /users/**, /files/**, /shares/**,
                     ├─ /system/**, /security/**, /storage/**, /billing/**
                     └─ devTestAdminGroup (env-gated; A-14: no production env check)
```

Key facts that drive cross-slice risks:
- The validator does not check `aud` or `requires_totp` (`A-01`).
- `c.RealIP()` is attacker-controlled (`F-01`).
- Admin group has no `RequireTOTP` (`E-01`).
- 51 of 64 admin/billing endpoints are not route-level TOTP-gated (Slice E §3.1).

### 2.2 Registration flow (browser; CLI is structurally parallel)

```
Client (browser via opaque.js WASM)                                Server
─────────────────────────────────────                              ──────
ClientCreateRegistrationRequest(password)
   ──── POST /api/opaque/register/response ────────────────►       CreateRegistrationResponse
                                                                      → rpub, rsec (15-min TTL)
                            ◄──── {session_id, rpub} ────
ClientFinalizeRegistration(usrCtx, rpub, username)
   → rrec, exportKey (UNUSED — A-45 stub)
   ──── POST /api/opaque/register/finalize ────────────────►       StoreUserRecord(rsec, rrec)
                                                                   INSERT users + opaque_user_data
                                                                   Issue TEMP TOTP JWT (aud=arkfile-totp,
                                                                      requires_totp=true, TTL=20m)
                            ◄──── {temp_token, requires_totp_setup=true} ────
[browser stores temp_token in localStorage — A-05/F-07]
[browser sets window.totpLoginData = { tempToken, username, password } — A-04/F-08]

   ──── POST /api/totp/setup ────────────────────────────►          Generate 160-bit secret + 10 backup codes
                                                                   AES-GCM encrypt under per-user TOTP key
                                                                      (HKDF from system-wide totpMasterKey)
                            ◄──── {qr, secret, backup_codes} ────
   ──── POST /api/totp/verify ───────────────────────────►          ValidateTOTPCode(code) — Skew=0, A-37
                                                                   On first valid code: mark enabled
                                                                   Issue FULL JWT (aud=arkfile-api,
                                                                      requires_totp=false)
                                                                   Issue refresh token (uuid.NewV4 — A-10)
                            ◄──── {full_token, refresh_token} ────
[browser stores full_token + refresh_token in localStorage — A-05/F-07]
[browser scrubs window.totpLoginData.password (best-effort; string immutable) — A-04/F-08]
[browser derives Account-KEK = Argon2id(password, det_salt(username, "account"))]
[Account-KEK cached encrypted in sessionStorage under ephemeral random wrapping key]
```

Cross-slice notes: every issued JWT today is signed with the same Ed25519 key (`A-01`); the temp token is structurally indistinguishable from the full token at the validator; the password is held on `window.totpLoginData` from OPAQUE finalize through TOTP verify (`A-04`); the Account-KEK is derived using server-supplied Argon2id parameters (`B-01`/`B-19`).

### 2.3 Login flow

Identical to §2.2 from `POST /api/opaque/login/response` onward, except no TOTP-setup step — the user enters an existing TOTP code at `POST /api/totp/auth`. Admin login replaces `/api/opaque/login/*` with `/api/admin/login/*`, which enforces `user.IsAdmin` before responding (Slice A §1.1). Account enumeration is possible at both login paths via HTTP-status differential (`A-24`) and admin enumeration via `/api/admin/login/response` (`A-24`).

CLI login (`arkfile-client login`) follows the same OPAQUE handshake using shared `auth/opaque_client.go`, prompts for TOTP code or accepts `--totp-secret` (`A-06` — argv leak), derives Account-KEK via `crypto.DeriveAccountPasswordKey`, and optionally hands the KEK to a local key-agent daemon over `~/.arkfile/agent-<uid>.sock` (`A-21` — same-UID processes can drain the cache). Admin login (`arkfile-admin login`) is structurally identical but returns a `string` password instead of `[]byte`, leaving the password unzeroizable in heap memory (`A-03`).

### 2.4 File upload flow

```
Browser (or arkfile-client)                                          Server
───────────────────────────                                          ──────
1. Generate FEK = 32 random bytes (crypto.getRandomValues / crypto/rand)
2. Split plaintext into 16 MiB chunks
3. For each chunk i:
      nonce_i = 12 random bytes
      (ct_i, tag_i) = AES-256-GCM(key=FEK, iv=nonce_i, aad=NONE, pt=chunk_i)   ◄── B-02 / C-02
      upload_blob_i = nonce_i || ct_i || tag_i
4. Wrap FEK:
      KEK = Argon2id(account_pwd OR custom_pwd, salt=det(username, "account"|"custom"))
      encrypted_FEK = [0x01][key_type=0x01 or 0x02][12-B nonce][AES-GCM(FEK, KEK, aad=NONE)]   ◄── B-08
5. Encrypt metadata:
      metadataKey = Account-KEK (same key as FEK wrapping — B-07)
      For each field f ∈ {filename, sha256-hex}:
         nonce_f = 12 random bytes
         (ct_f, tag_f) = AES-256-GCM(key=metadataKey, iv=nonce_f, aad=NONE, pt=utf8(f))   ◄── C-19
6.  ──── POST /api/uploads/init {enc filename, enc sha256, enc FEK, total_size,
                                  chunk_size, password_hint (PLAINTEXT — by design),
                                  password_type} ──────►
                                                                     session_id, file_id, total_chunks
7. For each chunk: POST /api/uploads/:sessionId/chunks/:chunkNumber
      body = upload_blob_i
      X-Chunk-Hash header = client-supplied SHA-256(blob_i)  ◄── C-04 (server never verifies)
                                                                     Server appends to S3 part
                                                                     Server increments in-process SHA-256
                                                                        of the encrypted stream         ◄── C-10
                                                                     Server pads last chunk with random  ◄── B-06
8. POST /api/uploads/:sessionId/complete
                                                                     CompleteMultipartUpload to S3
                                                                     Then DB tx writes file_metadata    ◄── C-07 orphan window
                                                                     LogUserAction(username, "uploaded",
                                                                        file_id)                       ◄── C-15 / C-26
                                                                     Async replicate to secondary       ◄── C-11
```

### 2.5 File download flow

```
Browser                                                              Server
───────                                                              ──────
1. GET /api/files/:fileId/meta  ─────────────────────────►           returns enc filename, enc sha256, enc FEK,
                                                                     password_type, size, total_chunks, password_hint
2. (User enters password if password_type==0x02)
3. KEK = Argon2id(password, det_salt(username, "account"|"custom"))
4. FEK = AES-GCM-Open(enc_FEK, KEK, aad=NONE)                        ◄── B-08
5. plaintext filename, plaintext sha256 = decrypt(metadata, Account-KEK, aad=NONE)
6. For each chunk i = 0..total_chunks-1:
      GET /api/files/:fileId/chunks/:i  ──────────────────►          Compute byte range from DB chunk_size_bytes
                                                                     × chunk_count (NO AAD binds these)   ◄── C-03
                                                                     Stream encrypted bytes (multi-provider fallback;
                                                                        no stored_blob_sha256 verify)     ◄── C-08
      Service Worker streams to disk via /sw-download/<uuid>         (or Blob fallback if SW unavailable — C-14)
      chunk_pt = AES-GCM-Open(ct_i, FEK, iv=nonce_i, aad=NONE)
      plaintext_running_hash.update(chunk_pt)
7. After last chunk: compare plaintext_running_hash to stored sha256
      If mismatch: show warning AFTER file is on disk                ◄── C-13
      Blob fallback: NO verification at all                          ◄── C-14
```

### 2.6 Sharing flow

```
Owner (logged in)                                                    Server                              Recipient
─────────────────                                                    ──────                              ─────────
1. Owner gets envelope: GET /api/files/:fileId/envelope  ──────►     enc_FEK, key_type
2. Owner decrypts FEK with Account-KEK or Custom-KEK
3. Owner enters share password (separate from account password)
4. share_salt = 32 random bytes
5. share_KEK = Argon2id(share_pwd, salt=share_salt, m/t/p FROM /api/config/argon2) ◄── B-19, D-10, D-12
6. download_token = 32 random bytes
7. envelope_pt = JSON({fek, download_token, filename, size_bytes, sha256})
8. aad = utf8(share_id || file_id)  -- no delimiter, B-15
9. envelope_ct = AES-256-GCM(share_KEK, iv=12-rand, aad, pt=envelope_pt)
10. download_token_hash = SHA-256(download_token)
11. POST /api/shares {share_id (CLIENT-supplied — D-23), salt, encrypted_envelope,
                       download_token_hash, expires_after_minutes, max_accesses} ──►
                                                                     Stores row; ListShares is GET-with-writes (D-03)
                            ◄────── {share_url} (Origin-derived — D-09) ──────

                                                                     /shared/:id                        ──► /shared/:id
                                                                     (HTML page, no per-share rate-limit — D-05)
                                                                                                        ◄── /api/public/shares/:id/envelope
                                                                                                            (returns salt, encrypted_envelope, size_bytes — D-21)
                                                                                                        share_KEK = Argon2id(pwd_typed_by_recipient,
                                                                                                                            salt, server params)
                                                                                                        envelope_pt = AES-GCM-Open(envelope_ct, share_KEK, aad)
                                                                                                        → fek, download_token
                                                                                                        ◄── /api/public/shares/:id/metadata
                                                                                                            (chunk_count, chunk_size — D-21 leak)
                                                                                                        For each chunk:
                                                                                                           GET /api/public/shares/:id/chunks/:i
                                                                                                           with X-Download-Token: <token>
                                                                                                           — max_accesses bypassable by skipping chunk 0 (D-01)
                                                                                                           — race on access_count (D-02)
                                                                                                        Decrypt with FEK (no AAD)
```

Cross-slice: the share envelope is the **only** AEAD operation in Arkfile that uses AAD (Slice B §1.3). But the share KDF parameters are not bound into the envelope (`D-12`), and an operator who exfiltrates a stored envelope can brute-force the share password offline at the weakest accepted Argon2id params (`D-10` × `B-19`).

### 2.7 Password change / recovery — there isn't one

Per `AGENTS.md` and Slice A N/A items, there is **no password change**, **no password reset**, **no email verification**, **no "forgot password" flow**, and **no admin reset for TOTP**. The intended posture is "lost password = lost files; lost authenticator = lost account". TOTP backup codes exist but `/api/totp/reset` requires a full JWT (which requires TOTP), so a user who has lost their authenticator cannot use a backup code to recover (`A-15`). The recovery model is consistent with the no-PII privacy stance but is not documented user-facing, and the backup-code mechanism is therefore not reachable for its intended use case.

### 2.8 Key hierarchy (canonical, cross-referenced)

```
                   ┌─────────────────────────────────────────────────────────────┐
                   │ USER PASSWORDS (typed by humans; never persisted plaintext) │
                   │  • Account password                                         │
                   │  • Custom file password (optional)                          │
                   │  • Share password (per share, typed by recipient)          │
                   └────────────┬────────────────────────────────────────────────┘
                                │
            ┌───────────────────┼─────────────────────────────┐
            │                   │                             │
            ▼                   ▼                             ▼
    [OPAQUE protocol]   [Argon2id, client-side]       [Argon2id, client-side]
            │           m=64MiB, t=3, p=1, dk=32      m=64MiB, t=3, p=1, dk=32
            │           salt = SHA-256(prefix:username)  salt = random32 (share)
            │                   │                             │
            ▼                   ▼                             ▼
    OPAQUE session keys   Account-KEK (32B)              Share-KEK (32B)
    (used for JWT issuance,    │                             │
     not for file crypto;      │                             │
     OPAQUE export key         │                             │
     UNUSED — A-45)            │                             │
                               ▼                             │
                       Wraps FEKs (AES-GCM, no AAD — B-08) ──┘ Wraps share envelope
                               +                                  (AES-GCM, AAD = share_id||file_id — B-15)
                       Encrypts metadata (filename, sha256)
                       Same key for both — B-07
                               │
                               ▼
                       FEK (32B random per file; crypto/rand)
                               │
                               ▼
                       Encrypts file chunks
                       (AES-256-GCM, random per-chunk nonce, NO AAD — B-02 / C-02)

  Server-side keys (all in `system_keys`; wrapped under HKDF-Expand of ARKFILE_MASTER_KEY env var):
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  • ARKFILE_MASTER_KEY (env var; B-16)                                            │
  │     └─ HKDF-Expand(info=ARKFILE_<type>_KEY_ENCRYPTION) → per-type wrapping key   │
  │           └─ AES-256-GCM wraps each system key                                   │
  │                                                                                  │
  │  • JWT signing key (Ed25519, 32B seed) — SAME key for temp + full JWT (A-01)     │
  │  • OPAQUE server private key (skS) + OPAQUE OPRF seed                            │
  │  • OPAQUE server public key (independently generated — A-27)                     │
  │  • Bootstrap token (one-shot intended; not enforced — A-13)                      │
  │  • TOTP master key (NOT mlock'd, NOT MADV_DONTDUMP — A-17; co-located — A-18)    │
  │     └─ HKDF-SHA256(info="ARKFILE_TOTP_USER_KEY:<username>") → per-user TOTP key  │
  │           └─ AES-256-GCM encrypts user_totp.secret_encrypted                     │
  │           └─ AES-256-GCM encrypts user_totp.backup_codes_encrypted (NOT hashed — A-07) │
  └──────────────────────────────────────────────────────────────────────────────────┘

  Bearer-token surface:
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  • Refresh token: uuid.NewV4() = 122 bits (A-10); SHA-256 stored                 │
  │  • Per-JTI revocation row (works per-request)                                    │
  │  • User-wide revocation row (Netflix-style; NOT per-request enforced — A-09)     │
  └──────────────────────────────────────────────────────────────────────────────────┘

  Client storage:
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Browser:                                                                        │
  │   localStorage[token]          full JWT  — A-05/F-07                             │
  │   localStorage[refresh_token]  refresh token — A-05/F-07                         │
  │   sessionStorage               OPAQUE intermediate (per-handshake, scoped)       │
  │   window.totpLoginData         plaintext password during TOTP window — A-04/F-08 │
  │   in-RAM Account-KEK           cached encrypted via account-key-cache.ts (B-21)  │
  │                                                                                  │
  │  arkfile-client CLI:                                                             │
  │   ~/.arkfile-session.json      access_token, refresh_token, expires_at (mode 0600)│
  │                                non-atomic initial save — A-43                    │
  │   key-agent daemon (UNIX sock) caches Account-KEK 1–4 h with mlock — A-21        │
  │                                                                                  │
  │  arkfile-admin CLI:                                                              │
  │   password returned as immutable string — A-03 (cannot be zeroed)                │
  └──────────────────────────────────────────────────────────────────────────────────┘
```

Slice references for each entry in the hierarchy are in Slice A §3.3 and Slice B §3.2.

---

## 3. Threat-Model Assessment vs. `idsrp.md` §2

The `idsrp.md` threat model lists 13 adversary classes and ~13 security properties. The matrix below maps the implementation today against each.

### 3.1 Adversaries — coverage

| Adversary | Posture today | Key gaps | Slice refs |
|---|---|---|---|
| Remote unauthenticated attacker | **Mostly good**; one Critical bypass | `F-01` lets a remote attacker pretend to be loopback; with a leaked bootstrap token or stolen admin JWT, full admin surface is reachable | `F-01`, `F-03`, `A-13`, `A-26` |
| Remote authenticated malicious user | Adequate | Account-enumeration `A-24`/`A-25`; share-enumeration in-memory only `D-18`; max_accesses bypass on shared files `D-01`; access_count race `D-02` | `A-24/A-25`, `D-01/D-02/D-18` |
| Malicious file recipient | Reasonable | `D-13`: revocation is future-fetch-only and the UI overstates the guarantee; `D-26`: owner-controlled envelope plaintext metadata is a tracking channel | `D-13`, `D-26` |
| Compromised user account | Adequate but slow to revoke | `A-09`: user-wide JWT revocation not enforced per-request; `A-10`: refresh tokens are 122-bit UUIDs with no reuse-detection | `A-09`, `A-10` |
| Compromised browser environment | **Significant gaps** | Plaintext password on `window.totpLoginData` (`A-04`/`F-08`); JWT + refresh token in localStorage (`A-05`/`F-07`); ~12 `innerHTML` sinks without Trusted Types (`F-17`) | A-04/A-05/A-22, F-07/F-08/F-17 |
| Network attacker | Good | Caddy TLS 1.3, HSTS, deSEC DNS-01; loopback-only Arkfile listener (with `F-01` exception). Internal Caddy→Arkfile TLS is `tls_insecure_skip_verify` but loopback-only (`F-18`) | F-18 |
| Malicious or compromised server operator | **Partially broken** | No AAD binds chunks/FEK/metadata to file identity (`B-02`/`B-08`/`C-02`/`C-19`); server picks Argon2id parameters runtime (`B-01`/`B-19`); operator can offline-brute-force stolen share envelopes (`D-10`) | B-01/B-02/B-08/B-19, C-02/C-03/C-19, D-10/D-12 |
| Database compromise attacker | Adequate but `system_keys`-dependent | If DB only: OPAQUE design protects passwords; share envelopes are offline-attackable at server-set params. If DB + ARKFILE_MASTER_KEY + system_keys: every server-side key + every TOTP backup code in cleartext (`A-07`/`A-18`/`B-16`) | A-07/A-17/A-18, B-16 |
| Object-storage compromise attacker | Mostly good; metadata gaps | Encrypted chunks; but storage objects include `owner-username` in user metadata (`C-09`), padded size leaks ~2.2% of plaintext size (`B-06`) | C-09, B-06 |
| Supply-chain attacker (npm / Go modules / WASM / CGO / build) | **Significant gaps** | No SRI on `libopaque.js` (`F-04`); Go binaries built without `-trimpath`/`-buildid=` (`F-05`); libsodium from host apt/dnf (`F-06`); `bun install` without `--frozen-lockfile` (`F-13`); no release signing or SBOM (`F-25`); rqlite unpinned (`F-12`); SeaweedFS pinned via MD5 (`F-11`) | F-04/F-05/F-06/F-11/F-12/F-13/F-25 |
| Cross-site scripting attacker | Partially mitigated | CSP forbids `'unsafe-inline'` for `script-src` (correct); ~12 `innerHTML` sinks (`F-17`); no Trusted Types; full JWT + plaintext password reachable via XSS (`A-04/A-05/F-07/F-08`) | F-14/F-17, A-04/A-05 |
| Cross-site request forgery attacker | Adequate by design (tokens not in cookies) | `D-27`: anonymous share GET endpoints lack explicit Origin check; `D-09`: share-URL Origin trust | D-09, D-27 |
| Insider with access to logs, metrics, storage, snapshots | Mostly good; specific log leaks | `A-11`: refresh tokens logged when `DEBUG_MODE=true`; `C-15`/`D-15`/`D-25`: plaintext username + file_id at INFO; `E-15`: operator strings in `admin_logs.details`; `F-03`: bootstrap token in systemd journal | A-11, C-15, D-15/D-25, E-15, F-03 |

### 3.2 Security properties — pass/partial/fail

| Property | Status | Justification + slice ref |
|---|---|---|
| Password confidentiality | **Partial** | OPAQUE protocol meets the bar. Browser holds plaintext password on `window.totpLoginData` from OPAQUE-finalize through TOTP-verify (`A-04`/`F-08`). CLI `arkfile-admin` returns the password as a Go `string` that cannot be zeroed (`A-03`). |
| Resistance to offline password guessing | **Partial** | OPAQUE prevents this for login-passwords against a DB-only attacker. Argon2id-with-deterministic-salt (account/custom) is fine because the salt is only an input to a slow KDF, but Argon2id parameters are server-controlled (`B-01`/`B-19`) — a compromised server lowers the bar. Share passwords are fully offline-attackable on stolen envelopes (`D-10`). |
| OPAQUE protocol correctness | **Mostly OK** | libopaque is trusted upstream; CGO wrapper line-by-line audited (`auth/opaque_wrapper.c`). Issues: OPAQUE server public key independently generated rather than derived (`A-27`); idS hardcoded as `"server"` rather than deployment FQDN (`A-28`); CGO password-buffer not zeroed in C heap (`A-38`); CGO double-buffer pattern internally inconsistent in `StoreUserRecord` (`A-36`). |
| File content confidentiality against server | **Pass** | AES-256-GCM under random per-file FEK; FEK never reaches server unwrapped. (Slice B §1.2.) |
| File integrity and authenticity | **Partial / Fail** | AEAD tags protect against random tampering. No AAD binds chunks to file identity or order — server-side reordering / inter-file swap is undetectable at the AEAD layer (`B-02`/`B-05`/`C-02`/`C-03`). End-of-file plaintext SHA-256 catches content-level tampering but only post-disk-write (`C-13`); Blob fallback skips this entirely (`C-14`). |
| Authorization for reads / writes / deletes / shares / revocations | **Partial** | Per-route ownership checks are mostly correct. Gaps: `C-12` `/envelope` skips `IsApproved`; `C-05` `CancelUpload` route is dead-on-arrival (param mismatch); admin group not TOTP-gated (`E-01`); `ExportFile` accepts any valid Arkfile JWT without TOTP claim (`E-19`); `AdminExportFile` lets any admin download any blob (`E-20`). |
| Recipient-only access for shared files | **Partial** | Anyone with URL + password can access — by design. `D-01`/`D-02` allow `max_accesses` bypass and double-spend. |
| Revocation semantics | **Future-access only, mis-marketed** | Revoking a share prevents future fetches of envelope + chunks. Anyone who already decrypted the envelope holds the FEK forever; the file is not re-encrypted on revoke. UI says "immediately prevent anyone from accessing" (`D-13`) which is stronger than the implementation. |
| Metadata confidentiality, if claimed | **Partial** | Filename + plaintext SHA-256 encrypted client-side. Size leaks within ~10% via padding (`B-06`). Owner username, upload timestamp, chunk count, chunk size, storage routing, password hint, share file_id ↔ share_id mapping all plaintext at server. |
| Resistance to replay / rollback / substitution / confused-deputy | **Fail at AEAD layer** | No AAD binds file_id, chunk index, key-type, owner. Active server can substitute and reorder undetected at AEAD layer; relies on end-of-file SHA-256 (`B-02`/`C-02`/`C-19`). |
| Secure key rotation and password change | **N/A by design** | No password change. No TOTP-master rotation script. JWT key rotation script exists but `F-19` flags it as stale. (`A-18`/`F-19`.) |
| Safe recovery flows | **N/A by design, but inconsistent** | No password reset (intentional). TOTP backup-code recovery path is unreachable from a lost-device state (`A-15`); backup codes are encrypted-not-hashed on the server (`A-07`). The user feature exists but the flow does not work. |

---

## 4. Consolidated Severity-Ranked Finding Index

179 findings total. Severity counts (final tally):

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 27 |
| Medium | 61 |
| Low | 52 |
| Informational | 37 |
| **Total** | **179** |

Sort order below is Severity → Slice → Finding number. Cross-refs in the rightmost column indicate where the same root cause shows up in another slice. Per-finding evidence (file:line, attack scenario, recommendation, suggested tests) is in the slice doc named in the second column.

### 4.1 Critical (2)

| Finding | Slice | One-line title | Category | Cross-refs |
|---|---|---|---|---|
| `F-01` | 06 | `X-Forwarded-For` localhost-gate bypass via `c.RealIP()` walking attacker-controlled header | authorization / operational | A-02, A-13, A-14, A-26, E-14 |
| `A-01` | 01 | Two-tier JWT model not enforced — temp post-OPAQUE token grants access to every protected route | authorization | A-02, A-05, E-01, E-19 |

### 4.2 High (27)

| Finding | Slice | One-line title | Category | Cross-refs |
|---|---|---|---|---|
| `A-02` | 01 | Admin endpoints reachable with a post-OPAQUE temp token | authorization | A-01, E-01, F-01 |
| `A-03` | 01 | `arkfile-admin readPassword()` returns immutable string — password lives in heap for process lifetime | memory-safety / privacy | A-04, A-38 |
| `A-04` | 01 | Browser stashes plaintext password on `window.totpLoginData` during TOTP entry | privacy / frontend | F-08 |
| `A-05` | 01 | JWT (temp+full) and refresh token in localStorage — XSS = total takeover + TOTP bypass | authorization / frontend | A-01, F-07 |
| `A-06` | 01 | `arkfile-client --totp-secret` argv flag exposes 160-bit TOTP shared secret | privacy / authentication | A-23 |
| `A-07` | 01 | TOTP backup codes stored encrypted, not hashed — `system_keys`+DB dump yields plaintext codes | cryptographic / at-rest | A-17, A-18 |
| `A-08` | 01 | No per-user TOTP lockout — IP-rotation brute force tractable in well under an hour | authorization | A-37 |
| `A-09` | 01 | User-wide JWT revocation not enforced per-request — 30-min Netflix-style gap after force-logout | authorization | A-10 |
| `A-10` | 01 | Refresh tokens are 122-bit UUIDv4; no rotation reuse-detection; sliding-window expiry | cryptographic / authorization | A-09, A-30 |
| `A-11` | 01 | Refresh-token raw value logged to stdout when `DEBUG_MODE=true` | privacy / logging | B-12, C-15 |
| `A-12` | 01 | `models.User.Delete()` leaves refresh tokens, TOTP, files, shares, billing rows behind | authorization / data hygiene | E-21 |
| `A-13` | 01 | Bootstrap token NOT consumed by first registration; second-admin race during bootstrap window | authorization / replay | A-26, F-01, F-03 |
| `A-14` | 01 | Dev/test admin API gate has no production-environment check — env var alone is sufficient | operational / authorization | F-02, A-41 |
| `A-15` | 01 (User-impact: High) | TOTP loss-of-device recovery is impossible — `/api/totp/reset` requires a full JWT which requires TOTP | design / recoverability | A-07, A-16 |
| `B-01` | 02 | Argon2id parameters are server-controlled — client trusts `/api/config/argon2` | cryptographic / design | B-03, B-19, D-10, D-12 |
| `B-02` | 02 | File chunks have no AAD — server can swap files between user's own files undetected | cryptographic / integrity | B-05, B-08, C-02, C-19 |
| `B-03` | 02 | Chunking parameters are server-controlled — server can set absurd chunk sizes | cryptographic / design | B-01, B-19 |
| `C-01` | 03 | Server allocates up to ~10% of file size in a single Go `append` on last chunk upload (DoS) | operational | B-06 |
| `C-02` | 03 | Server cannot detect chunk swap/reorder/cross-file substitution at the wire layer | cryptographic / integrity | B-02, B-05 |
| `C-03` | 03 | Download byte-range math trusts DB `chunk_size_bytes` and `chunk_count` without crypto binding | cryptographic / integrity | C-02 |
| `D-01` | 04 | `max_accesses` enforcement is bypassable; only checked on chunk 0 | authorization | D-02 |
| `D-10` | 04 | Share security model = pure offline brute force on stolen envelope | cryptographic / design | B-19, D-12 |
| `E-02` | 05 | SQL injection via interpolated `provider_id` in `AdminSyncStatus` | authorization / injection | F-01, E-01 |
| `E-03` | 05 | `settleOneUser` reads `user_credits.balance` outside tx; sweep + concurrent gift race (Critical w/ payments) | atomicity / billing | E-04, E-05 |
| `E-21` | 05 | `ON DELETE CASCADE` on `users(username)` wipes the financial audit trail (Critical w/ payments) | design / financial-audit | A-12 |
| `F-03` | 06 | Bootstrap token harvested from systemd journal | privacy / logging | A-13, A-26, F-01 |
| `F-04` | 06 | WASM artifact `/js/libopaque.js` loaded without Subresource Integrity | supply-chain / frontend | F-05, F-13 |
| `F-05` | 06 | Go binaries built without `-trimpath` / `-buildid=` / `-ldflags='-s -w'` / `-buildvcs=false`; no signing | supply-chain / reproducibility | F-06, F-11, F-12 |
| `F-06` | 06 | libsodium is host's apt/dnf package, not a pinned vendored submodule | supply-chain | F-05 |
| `F-07` | 06 | Full JWT and refresh token stored in localStorage | authorization / frontend | A-05 |
| `F-08` | 06 | Plaintext password stored on `window.totpLoginData` during TOTP step | privacy / frontend | A-04 |

### 4.3 Medium (61)

| Finding | Slice | One-line title | Cross-refs |
|---|---|---|---|
| `A-16` | 01 | Backup-code race — no UNIQUE on `(username, code_hash)`; concurrent submissions can double-spend | A-07 |
| `A-17` | 01 | `totpMasterKey` no `mlock`, no `MADV_DONTDUMP`, no zeroize-on-shutdown | A-07, A-18 |
| `A-18` | 01 | TOTP master key co-located with OPAQUE / JWT / bootstrap keys in `system_keys` | A-07, A-17, B-16 |
| `A-19` | 01 | `decodeBase64IfNeeded` is an rqlite driver-quirk workaround — greenfield-policy violation | — |
| `A-20` | 01 | `CompleteTOTPSetup` does not write to replay log — first-window code replayable at `/api/totp/auth` | A-16 |
| `A-21` | 01 | CLI agent has stat-based UID check; no `SO_PEERCRED`; same-UID drain/poison/DoS-wipe | — |
| `A-22` | 01 | TOTP secret, manual entry, QR data URL, backup codes rendered as raw DOM text after enrollment | F-17 |
| `A-23` | 01 | `arkfile-client setup-totp --show-secret` prints TOTP secret to stdout | A-06 |
| `A-24` | 01 | OPAQUE login leaks account existence by HTTP status + timing differential; admin login enumerates admin-ness | A-25 |
| `A-25` | 01 | OPAQUE registration finalize leaks account existence via 409 after expensive OPAQUE work | A-24 |
| `A-26` | 01 | Bootstrap token logged to stdout in cleartext | F-03 |
| `A-27` | 01 | OPAQUE server public key independently generated, not derived from the private key | — |
| `A-28` | 01 | OPAQUE server identity hardcoded as `"server"`; not bound to deployment | — |
| `A-29` | 01 | Username comparisons are byte-wise; no Unicode normalization/case-folding policy | — |
| `A-30` | 01 | Refresh-token rotation revokes old token best-effort; failure does not abort new-token issuance | A-10 |
| `A-31` | 01 | `TokenRevocationMiddleware` fails open when claims are missing or malformed | A-39 |
| `A-32` | 01 | `RateLimitMiddleware` fails open on backend errors | A-08, E-09 |
| `A-33` | 01 | `/api/logout` requires no auth; refresh-token DoS via known-token revocation | — |
| `A-34` | 01 | `ApproveUser` trusts caller-supplied `adminUsername` parameter | E-13 |
| `A-35` | 01 | `--password-stdin` and `--account-key-file` CLI flags do not exist; pipe-stdin asymmetric | — |
| `A-36` | 01 | CGO double-buffer pattern in `StoreUserRecord` is internally inconsistent | A-38 |
| `A-37` | 01 | `TOTPSkew = 0` contradicts its own comment and `idsrp.md` §22.2 expectation | A-08 |
| `B-04` | 02 | TypeScript Argon2id runs on the main thread, blocking the UI for several seconds | B-27 |
| `B-05` | 02 | Chunk reordering and truncation are not detected by the crypto layer | B-02, C-02 |
| `B-06` | 02 | Padding is server-applied — server sees unpadded ciphertext size before padding | C-01 |
| `B-07` | 02 | `metadataKey == Account-KEK` — same key wraps FEK and encrypts metadata | — |
| `B-08` | 02 | FEK envelope has no AAD | B-02, C-02 |
| `B-19` | 02 | Password requirements also fetched from server unauthenticated — same downgrade pattern as B-01/B-03 | B-01, D-10, D-12 |
| `C-04` | 03 | `X-Chunk-Hash` header accepted/stored but never verified server-side | — |
| `C-05` | 03 | `CancelUpload` route uses `:fileId` param; handler reads `c.Param("sessionId")` — dead-on-arrival | — |
| `C-06` | 03 | Upload-session sweep marks DB rows abandoned but doesn't abort underlying S3 multipart — storage cost leak | — |
| `C-07` | 03 | `CompleteUpload` two-phase (storage → DB) — failure window orphans S3 objects | C-06 |
| `C-08` | 03 | Multi-provider download fallback does NOT verify served blob against `stored_blob_sha256sum` | C-11 |
| `C-09` | 03 | S3 object metadata includes `owner-username` — plaintext to every storage backend | C-15 |
| `C-10` | 03 | Per-session SHA-256 hasher state in-process only; server restart corrupts in-flight uploads | — |
| `C-11` | 03 | `replicateToSecondary` fire-and-forget goroutine, `context.Background()` — uncancellable | — |
| `C-13` | 03 | Streaming download writes plaintext to disk BEFORE SHA-256 verification result is known | C-14 |
| `C-14` | 03 | Blob-fallback download path performs no SHA-256 verification at all | C-13 |
| `C-15` | 03 | Per-upload/download InfoLogger lines log username + file_id together — reconstructs per-user file activity | A-11, D-15, D-25 |
| `C-18` | 03 | Both build-tagged `mock` chunked-upload integration tests are not run under default `go test ./...` | — |
| `D-02` | 04 | Race on `access_count` increment allows double-spend on `max_accesses` | D-01 |
| `D-03` | 04 | `ListShares` GET handler performs side-effecting writes (auto-revoke) | — |
| `D-04` | 04 | Owner-supplied `revoked_reason` leaks back to anonymous recipient | E-15 |
| `D-05` | 04 | `/shared/:id` route missing per-share rate-limit and timing-protection middleware | D-06 |
| `D-06` | 04 | Race + read-then-write on per-share rate-limit failed_count | D-05 |
| `D-09` | 04 | Origin-header trust in share URL construction — owner-side phishing / self-XSS amplification | D-14 |
| `D-11` | 04 | Anonymous EntityID rotates daily; rate-limit budget effectively resets daily; trivially multipliable | D-19 |
| `D-12` | 04 | Share envelope has no per-envelope versioning or KDF parameter binding | B-19, D-10 |
| `D-13` | 04 | Revocation UI overstates the guarantee ("immediately prevent anyone from accessing") | — |
| `E-01` | 05 | Admin route group is not wired through `RequireTOTP` | A-01, A-02, F-01 |
| `E-04` | 05 | No idempotency key on `credit_transactions` — gift/usage rows duplicable under retry | E-03, E-05 |
| `E-05` | 05 | Process-local `lastSweepDate` allows duplicate daily sweep across restarts | E-04 |
| `E-06` | 05 | `ParseCreditsFromUSD` accepts inputs that overflow int64 on multiplication | E-07 |
| `E-14` | 05 | `AdminMiddleware` localhost gate trusts `c.RealIP()` which trusts forwarded headers | F-01 |
| `E-19` | 05 | Public `ExportFile` endpoint accepts any valid Arkfile JWT for any user's own file; no TOTP claim required | A-01, E-20 |
| `E-25` | 05 | `OpaqueRegister*` paths do not call `recordAuthFailedAttempt` | A-25 |
| `F-09` | 06 | systemd hardening gaps across all four units; biggest is absence of `LimitCORE=0` | F-10 |
| `F-10` | 06 | rqlite binds `0.0.0.0:4001`/`:4002` (HTTP and Raft) instead of loopback | F-09 |
| `F-11` | 06 | SeaweedFS integrity check uses MD5 | F-12 |
| `F-12` | 06 | rqlite is "built from source" with no pinned commit or tag | F-05, F-11 |
| `F-13` | 06 | `bun install` runs without `--frozen-lockfile`; `package.json` uses `^` ranges | F-25 |
| `F-14` | 06 | CSP forbids `'unsafe-inline'` in script-src but TS modules emit inline `onclick=`; handlers silently do not fire | F-17 |
| `F-17` | 06 | No `require-trusted-types-for 'script'`; ~12 `innerHTML` sinks across `client/static/js/src/**` | A-22, D-14, F-21 |

### 4.4 Low (52)

| Finding | Slice | One-line title |
|---|---|---|
| `A-38` | 01 | OPAQUE password buffer not zeroized in the C heap after CGO call |
| `A-39` | 01 | `RequiresTOTPFromToken` panics on missing claims |
| `A-40` | 01 | `ResetKeysForTest` exported in production code |
| `A-41` | 01 | `validateDevAdminAuthentication` lacks self-contained production-environment guard |
| `A-42` | 01 | Backup-code generation has modulo bias; tests log plaintext codes via `t.Logf` |
| `A-43` | 01 | `saveAuthSession` non-atomic on initial write; SIGINT during login leaves partial file |
| `A-44` | 01 | Pipe-mode `readPassword` grows buffer via `append`; partial-password copies remain in heap |
| `B-09` | 02 | Embedded JS comment claims Argon2id parameters of "256MB, 8 iterations" — actual production is 64MB, 3 iterations |
| `B-10` | 02 | `crypto/session.go` is dead code |
| `B-11` | 02 | `crypto/opaque_validation.go` is an empty stub |
| `B-12` | 02 | GCM debug-mode logging dumps nonces and tag-region hex to stdout |
| `B-13` | 02 | `DecryptFileMetadata` hardcodes account-context for metadata decryption |
| `B-14` | 02 | `EncryptFile` rejects empty plaintext but `EncryptGCM` accepts it — inconsistency |
| `B-15` | 02 | `CreateAAD` for share envelopes concatenates `share_id || file_id` without a delimiter |
| `B-16` | 02 | Single `ARKFILE_MASTER_KEY` env-var-only master key — operator hardening gap |
| `B-17` | 02 | `EncryptFile`/`DecryptFile`/`EncryptFEK`/`DecryptFEK` are unused outside tests |
| `B-20` | 02 | `password.length` (JS) vs `len(password)` (Go) — Unicode length mismatch in password validation |
| `C-09` | 03 | (also above) S3 object metadata includes `owner-username` — listed in Medium |
| `C-12` | 03 | `GetFileEnvelope` lacks the `IsApproved` check |
| `C-16` | 03 | Per-user concurrent-upload-session cap TOCTOU under rqlite default isolation |
| `C-17` | 03 | `storage.GetPresignedURL` interface method implemented but never called — dead-code footgun |
| `C-19` | 03 | `models/file.go` doc claims AAD for `EncryptedSha256sum` but upload pipeline uses no AAD |
| `C-20` | 03 | `parseChunkIndex` rolls its own integer parser with no overflow check |
| `C-21` | 03 | Bucket creation sets no public-access block, no encryption config, no lifecycle policy |
| `C-22` | 03 | `S3AWSStorage` disables `RequestChecksumCalculation` for non-HTTPS endpoints |
| `C-23` | 03 | `models/file.go` `CreateFile` function no handler calls — dead code drift |
| `C-24` | 03 | `models/file.go` `UpdatePasswordHint` does no owner check — currently unwired tripwire |
| `D-07` | 04 | `share_access_attempts` table grows unbounded; no DB-side cleanup |
| `D-08` | 04 | Share rate-limit reuse table schema confusion (auth rate limits stored as fake share IDs) |
| `D-14` | 04 | Self-XSS via Origin-controlled `share_url` rendered into `innerHTML` |
| `D-15` | 04 | Plaintext `file_id` and EntityID logged on every anonymous share access |
| `D-16` | 04 | No rate limit on the chunk-download endpoint beyond the per-share failed-token limiter |
| `D-17` | 04 | Download-token comparison decode failures leak format-vs-mismatch oracle |
| `D-18` | 04 | Share enumeration guard is in-memory only; no multi-instance coherence |
| `D-19` | 04 | Anonymous EntityID for share access bypassable to fresh state by attacker without persistent identity |
| `D-20` | 04 | `revoked_at` not checked in `GetSharedFile` HTML-page path |
| `D-21` | 04 | `GetShareDownloadMetadata` returns `chunk_count` and `chunk_size_bytes` without requiring the download token |
| `E-07` | 05 | `billable * MicrocentsPerGiBPerHour` can overflow int64 in `TickUser` |
| `E-08` | 05 | `hoursPerMonth = 24 × 30 = 720` derives rates ~1.4% lower than operator's stated USD-per-TB-per-month |
| `E-09` | 05 | `AdminMiddleware` rate limit keys all admin routes under one bucket |
| `E-10` | 05 | `requireAdmin` / `requireAdminWithUsername` in `admin_billing.go` don't verify request came through `AdminMiddleware` |
| `E-12` | 05 | `AdminTOTPDecryptCheck` is admin-gated and dev-only, but response confirms TOTP-secret-decryptability |
| `E-15` | 05 | `LogAdminAction` writes plaintext `details` strings that can include sensitive operator inputs |
| `E-23` | 05 | `file_storage_locations.provider_id` has no `ON DELETE` rule |
| `E-24` | 05 | `share_access_attempts` table is reused as a polymorphic rate-limit store via synthetic share_ids |
| `F-02` | 06 | Hardcoded dev-admin credentials and TOTP secret compiled into the production binary |
| `F-15` | 06 | `style-src 'unsafe-inline'` accommodates a single `<style>` block in `shared.html` |
| `F-16` | 06 | No `Permissions-Policy` header |
| `F-18` | 06 | `tls_insecure_skip_verify` on Caddy → Arkfile upstream |
| `F-19` | 06 | `scripts/maintenance/rotate-jwt-keys.sh` manages a path that is no longer authoritative |
| `F-22` | 06 | Production bundle ships with external sourcemap (`dist/app.js.map`) |

### 4.5 Informational (37)

| Finding | Slice | One-line title |
|---|---|---|
| `A-45` | 01 | `crypto/opaque_validation.go` is a stub file |
| `B-18` | 02 | Comment-only `crypto/envelope.go` file (essentially dead) |
| `B-21` | 02 | Account-key-cache `secureWipe` overwrites with random then zero — JS GC may have already copied |
| `B-22` | 02 | `account-key-cache.ts` uses an emoji in `console.error` — violates AGENTS.md §"No Emojis" |
| `B-23` | 02 | TS `EncryptedFileMetadata` interface declared twice in `types.ts` |
| `B-24` | 02 | Go `DeriveAccountPasswordKey` / `DeriveCustomPasswordKey` discard the error from `DeriveArgon2IDKey` |
| `B-25` | 02 | `KeyManager.StoreKey` uses `REPLACE INTO` — silently overwrites existing keys |
| `B-26` | 02 | `KeyManager.deriveWrappingKey` uses HKDF-Expand on a high-entropy master key (Extract+Expand more conventional) |
| `B-27` | 02 | Client-side `MAX_FILE_SIZE: 5 GB` contradicts AGENTS.md mobile-constraint example of "6 GB on 3 GB RAM" |
| `C-25` | 03 | `GetFileMetadataBatch` does not deduplicate the `file_ids` array |
| `C-26` | 03 | `database.LogUserAction(...)` called outside the upload transaction and after `tx.Commit()` |
| `C-27` | 03 | `chunk_hash` in `upload_chunks` has no UNIQUE constraint per `(session_id, chunk_number)` |
| `D-22` | 04 | No length cap on `expires_after_minutes`; integer overflow / effectively-permanent shares |
| `D-23` | 04 | Client-supplied `share_id` (not server-generated) gives a weak pre-image / pre-claim surface |
| `D-24` | 04 | `isShareEndpoint` is dead code with wrong paths |
| `D-25` | 04 | Owner JWT username appears in plaintext in InfoLogger on share creation |
| `D-26` | 04 | Share envelope plaintext metadata can be used as a tracking channel by the owner |
| `D-27` | 04 | Anonymous share GET endpoints lack explicit CSRF / Origin-check guard |
| `E-11` | 05 | `AdminCleanupTestUser` deletes the same `opaque_user_data` row twice via a typo'd cleanup list |
| `E-13` | 05 | Admin handlers inconsistently re-check `user.IsAdmin` after `AdminMiddleware` |
| `E-16` | 05 | `/readyz` reveals internal dependency health to unauthenticated callers |
| `E-17` | 05 | `AdminMiddleware` audit log lacks operation outcome (success/failure of wrapped handler) |
| `E-18` | 05 | `AdminGetContactInfo` decrypts and returns user contact info to admin without warning |
| `E-20` | 05 | `AdminExportFile` lets any admin download any user's encrypted blob; design-level disclosure |
| `E-22` | 05 | `credit_transactions.transaction_type` is not constrained to a CHECK list |
| `E-26` | 05 | Public config endpoints (`/api/config/argon2`, etc.) are unrate-limited |
| `E-27` | 05 | `AdminSecurityEvents` limit clamp uses `fmt.Sscanf` rather than strconv, silently coerces malformed input |
| `F-20` | 06 | `/healthz` and `/readyz` publicly reachable via Caddy |
| `F-21` | 06 | `shared-init.js` uses `innerHTML` for error rendering |
| `F-23` | 06 | `tls_insecure_skip_verify` on Caddy upstream documented as intentional (companion to F-18) |
| `F-24` | 06 | deSEC API token stored on disk in plaintext (`/var/lib/caddy/caddy-env`) |
| `F-25` | 06 | No `govulncheck`, `npm audit` / `bun audit`, or SBOM in the build script |
| `F-26` | 06 | Bun lockfile is text-format `bun.lock` (informational positive) |

(D-22/D-23/D-24/D-25/D-26/D-27 from Slice D's Informational list; E-11/E-13/E-16/E-17/E-18/E-20/E-22/E-26/E-27 from Slice E's Informational list; the count totals to 37 across all slices when including A-45, B-18 + B-21..B-27 = 8, C-25..C-27 = 3.)

### 4.6 Cross-slice headline risks

These are not new findings; they collapse multiple findings into a single risk narrative.

| Headline | Underlying findings | Why it matters |
|---|---|---|
| **Remote-admin pathway** | F-01 (Critical) escalating A-02, A-13, A-14, A-26, E-01, E-02, E-12, E-14, E-18, E-19 | One Echo config line + one Caddy block keep an admin attack out of reach. Without them, every Slice E admin-side finding becomes remotely exploitable. |
| **TOTP-as-decoration** | A-01 (Critical) compounded by A-02, A-08, E-01, F-01 | Validator does not check `aud` or `requires_totp`; admin group has no `RequireTOTP`; no per-user lockout. The "mandatory 2FA" claim does not hold at the JWT layer. |
| **File-identity authenticity gap** | B-02, B-05, B-08, C-02, C-03, C-19 | No AAD anywhere on the file path. End-of-file SHA-256 catches content tampering only post-disk-write; AEAD layer detects nothing. Single coordinated fix (bind file_id + chunk_index + key_type into AAD everywhere) closes all six. |
| **Server-controlled crypto parameters** | B-01, B-03, B-19, D-10, D-12 | Three runtime-fetched config endpoints + one un-bound share envelope. A compromised server can silently downgrade every future KDF and every shared-envelope brute-force. |
| **Frontend credential exposure** | A-04, A-05, F-07, F-08, F-17 | Tokens in localStorage + plaintext password on `window.totpLoginData` + 12 `innerHTML` sinks without Trusted Types. Any XSS, dep compromise, or browser-extension hit yields password + session. |
| **Server-secret single-point-of-compromise** | A-07, A-17, A-18, B-16 | All system keys + TOTP master key in one `system_keys` table; backup codes encrypted not hashed; ARKFILE_MASTER_KEY is a single env var. DB + system_keys + master key = full plaintext recovery of TOTP secrets and backup codes for every user. |
| **Financial-audit-integrity gap (future-Critical)** | E-03, E-04, E-05, E-21, E-22 | Today these are billing-correctness defects; once Stripe/crypto/ACH is wired in, every one is Critical for chargeback evidence, refund audit, and double-spend safety. Fix before any payment-processor integration lands. |
| **Supply-chain integrity gap** | F-04, F-05, F-06, F-11, F-12, F-13, F-25 | WASM no SRI + Go binaries no `-trimpath`/signing + libsodium from host + rqlite unpinned + SeaweedFS MD5 + bun not frozen + no SBOM/audit. Each individually small; collectively the build is not verifiable and the assets are not pinned. |
| **Recovery-flow inconsistency** | A-07, A-15, A-16, A-42 | Backup codes are advertised as the lost-device recovery path; the recovery endpoint is unreachable from a lost-device state; codes are encrypted not hashed; codes have modulo bias and tests log them plaintext. The user feature exists but does not work for its intended use case. |
| **Privacy-posture leakage in logs** | A-11, C-15, C-26, D-15, D-25, E-15, F-03 | The "no IP / no PII" privacy posture is consistently designed (EntityID HMAC), but `InfoLogger` lines log plaintext username + file_id (C-15/D-15/D-25), `DEBUG_MODE=true` prints raw refresh tokens (A-11), admin audit details contain operator inputs (E-15), and bootstrap token is in journald (F-03). |

---

## 5. Endpoint Review Table (merged A + C + D + E)

Columns: `Endpoint | Auth | Authz | TOTP-gated? | Notable issues`. Sensitive inputs/outputs/rate-limit/suggested-tests detail lives in each slice's table (Slice A §3.1, Slice C §3.1, Slice D §3.1, Slice E §3.1). 64 of these endpoints are from Slice E's per-route audit; ~30 more come from Slice A/C/D.

### 5.1 Public / pre-auth endpoints

| Endpoint | Auth | Authz | TOTP-gated? | Issues |
|---|---|---|---|---|
| `GET /healthz` | None | None | N/A | Trivial; OK |
| `GET /readyz` | None | None | N/A | E-16 (dependency health leak), F-20 |
| `GET /api/version` | None | None | N/A | OK |
| `GET /api/config/argon2` | None | None | N/A | B-01, B-19, E-26 (no rate-limit) |
| `GET /api/config/password-requirements` | None | None | N/A | B-19, E-26 |
| `GET /api/config/chunking` | None | None | N/A | B-03, E-26 |
| `GET /api/admin-contacts` | None | None | N/A | Public exposes admin usernames (cross-ref A-24 enumeration) |
| `POST /api/opaque/register/response` | None (rate-limited) | None | N/A | A-25 (enumeration via 409) |
| `POST /api/opaque/register/finalize` | Session token | Session==username | N/A | A-25; E-25 (no recordAuthFailedAttempt) |
| `POST /api/opaque/login/response` | None (rate-limited) | None | N/A | A-24 enumeration |
| `POST /api/opaque/login/finalize` | Session token | Session==username | N/A | Temp token reaches protected routes (A-01) |
| `GET /api/opaque/health` | None | None | N/A | OK |
| `POST /api/admin/login/response` | None | None | N/A | A-24 admin enumeration |
| `POST /api/admin/login/finalize` | Session token | Session==username + `is_admin` | N/A | OK once A-24 fixed |
| `POST /api/bootstrap/register/response` | Bootstrap token | Localhost + token valid | N/A | A-26 (token in stdout), F-01 (XFF bypass), F-03 (journal) |
| `POST /api/bootstrap/register/finalize` | Bootstrap token | Same + session | N/A | A-13 (token NOT consumed), F-01, F-03 |
| `POST /api/refresh` | Refresh token | per-token | N/A | A-10 (122-bit), A-30, A-09 |
| `POST /api/logout` | **None** | None | N/A | **A-33 unauth DoS** |
| `GET /shared/:id` | None | None | N/A (correct) | D-05 (no per-share rate-limit), D-20 |
| `GET /api/public/shares/:id` | None | None | N/A (correct) | OK |
| `GET /api/public/shares/:id/envelope` | None | None | N/A | D-10, D-12, D-21 |
| `GET /api/public/shares/:id/metadata` | None | None | N/A | D-21 (chunk count + size leak) |
| `GET /api/public/shares/:id/chunks/:i` | Bearer (X-Download-Token) | Token valid | N/A | D-01, D-02, D-16, D-17 |
| `GET /api/files/:fileId/export?token=...` | Token *or* JWT | Token-bound or self-owns-file | **No (header path)** / Indirect (token path) | **E-19** |

### 5.2 TOTP-temp-token entry points

| Endpoint | Auth | Authz | TOTP-gated? | Issues |
|---|---|---|---|---|
| `POST /api/totp/setup` | Temp TOTP JWT | Self | (entry point) | A-01 audience not enforced; A-42 backup-code entropy |
| `POST /api/totp/verify` | Temp TOTP JWT | Self + valid first code | (entry point) | A-37 Skew=0; A-20 no replay-log insert |
| `POST /api/totp/auth` | Temp TOTP JWT | Self + `RequiresTOTP=true` claim + valid code/backup | (entry point) | A-08 (no per-user lockout); A-16 race; A-07 codes encrypted not hashed; A-37 |

### 5.3 Full-JWT but not TOTP-gated (Slice A `auth.Echo` group)

| Endpoint | Auth | Authz | TOTP-gated? | Issues |
|---|---|---|---|---|
| `GET /api/totp/status` | Full JWT | Self | Implicit (full JWT) | OK |
| `POST /api/totp/reset` | Full JWT | Self + valid backup code | Implicit | **A-15** unreachable from lost-device state; A-16 |
| `GET /api/user/contact-info` | JWT (no Approved) + TOTP | Self | **Yes** | OK |
| `PUT /api/user/contact-info` | JWT (no Approved) + TOTP | Self | **Yes** | size-limit OK |
| `DELETE /api/user/contact-info` | JWT (no Approved) + TOTP | Self | **Yes** | OK |

### 5.4 TOTP-gated user routes (`totpProtectedGroup`)

| Endpoint | Issues |
|---|---|
| `POST /api/revoke-token` | OK |
| `POST /api/revoke-all` | Does NOT revoke active JWTs (A-09) |
| `GET /api/credits` | OK |
| `POST /api/uploads/init` | C-09 (S3 owner-username), C-15, C-16 |
| `POST /api/uploads/:sessionId/chunks/:chunkNumber` | **C-01 padding alloc**, C-04, C-10, C-27 |
| `POST /api/uploads/:sessionId/complete` | C-07, C-26 |
| `GET /api/uploads/:sessionId/status` | C-15 |
| `DELETE /api/uploads/:fileId` (CancelUpload) | **C-05 BROKEN** |
| `GET /api/files` | C-15 |
| `GET /api/files/metadata` | C-15 |
| `POST /api/files/metadata/batch` | C-25 |
| `GET /api/files/:fileId/meta` | C-15 |
| `GET /api/files/:fileId/envelope` | **C-12 missing IsApproved** |
| `GET /api/files/:fileId/chunks/:chunkIndex` | C-02, C-03, C-08, C-13, C-15 |
| `DELETE /api/files/:fileId` | OK |
| `POST /api/files/:fileId/export-token` | OK |
| `POST /api/shares` | D-09, D-22, D-23 |
| `GET /api/shares` | D-03 (writes in GET), D-09, D-25 |
| `POST /api/shares/:id/revoke` | D-04 free-form reason |

### 5.5 Admin endpoints (`adminGroup` — **NONE route-level TOTP-gated**; `E-01`)

51 routes total. Truncated to highlights; full table in Slice E §3.1.

| Endpoint | Issues |
|---|---|
| `GET /api/admin/credits`, `GET /api/admin/credits/:username` | E-01 |
| `GET /api/admin/users`, `POST /api/admin/users/:u/approve`, `GET /api/admin/users/:u/status`, `PUT /api/admin/users/:u/storage`, `POST /api/admin/users/:u/revoke`, `DELETE /api/admin/users/:u`, `PUT /api/admin/users/:u`, `POST /api/admin/users/:u/force-logout`, `GET /api/admin/users/:u/files`, `GET /api/admin/users/:u/shares` | E-01; A-09 for force-logout; **E-21 cascade** for DELETE; E-12 cross-ref |
| `GET /api/admin/users/:u/contact-info` | E-01, E-18 |
| `DELETE /api/admin/files/:fileId` | E-01 |
| `POST /api/admin/shares/:shareId/revoke` | E-01; D-04 leak |
| `GET /api/admin/files/:fileId/export` | **E-20**, E-01 (tamper-evident audit required) |
| `GET /api/admin/system/status`, `GET /api/admin/system/health`, `GET /api/admin/security/events` | E-01, E-27 |
| `GET /api/admin/storage/status`, `GET /api/admin/storage/sync-status`, `POST /api/admin/storage/copy-*`, `GET/POST /api/admin/storage/task/*`, `POST /api/admin/storage/set-*`, `POST /api/admin/storage/swap-providers`, `POST /api/admin/storage/verify-*`, `POST /api/admin/storage/set-cost` | **E-02 SQLi in sync-status**, E-01 |
| `GET /api/admin/alerts/summary` | E-01 |
| `GET /api/admin/billing/price`, `POST /api/admin/billing/set-price`, `GET /api/admin/billing/sweep-summary`, `GET /api/admin/billing/overdrawn`, `POST /api/admin/billing/gift` | E-01, **E-04 no idempotency**, E-06 overflow, E-15 details cleartext |
| `POST /api/admin/dev-test/users/cleanup`, `GET /api/admin/dev-test/totp/decrypt-check/:u`, `POST /api/admin/dev-test/billing/tick-now` | E-11, **E-12** TOTP oracle, **A-14** no production-env check |

**Count summary**: of 64 admin/billing/misc/auth endpoints reviewed at the API layer, **51 are NOT route-level TOTP-gated** per `idsrp.md` §22.3. Fixing E-01 (add `RequireTOTP` to `adminGroup`) closes this in one line.

---

## 6. Cryptographic Review Table (merged B + Slice A crypto rows)

Columns: `Operation | Primitive | Key source | Nonce/IV handling | Associated data | Storage location | Issues`. Drawn from Slice A §3.2 and Slice B §3.1.

| Operation | Primitive | Key source | Nonce/IV | AAD | Storage | Issues |
|---|---|---|---|---|---|---|
| OPAQUE registration / login | libopaque (Ristretto255, OPRF, HKDF-SHA512, AKE) | KeyManager `opaque_server_private_key`, `opaque_oprf_seed`; independent `opaque_server_public_key` | per-handshake | idU, idS=`"server"`, ctx=`arkfile_auth` | system_keys + opaque_user_data | A-27 pkS not derived; A-28 idS hardcoded; A-38 C-heap not zeroed |
| JWT signing | Ed25519 | KeyManager `jwt_signing_key_v1` (single key for temp + full) | n/a | n/a | system_keys | **A-01 same key for both tiers** |
| Refresh token | `uuid.NewV4()` (122-bit) | n/a | n/a | n/a | `refresh_tokens.token_hash` (SHA-256) | **A-10** |
| Bootstrap token | crypto/rand 32B + hex | n/a | n/a | n/a | system_keys + stdout | A-13 (not consumed), A-26 (stdout), F-03 (journal) |
| Account-KEK derivation | Argon2id (m=64MiB, t=3, p=1, dk=32) | account password | salt = SHA-256("arkfile-account-key-salt:" + username) deterministic | n/a | client RAM; sessionStorage (encrypted) | B-01 server params; B-07 reused as metadata key |
| Custom-KEK derivation | Argon2id same params | custom password | salt = SHA-256("arkfile-custom-key-salt:" + username) deterministic | n/a | client RAM only | B-01 |
| Share-KEK derivation | Argon2id same params | share password | random 32B per share | n/a | recipient RAM | B-01, B-04 (UI block), B-19, D-10/D-12 |
| FEK generation | crypto/rand or getRandomValues | n/a | n/a | n/a | random 32B per file, never persisted plain | OK |
| File chunk encryption | AES-256-GCM | FEK | 12B random per chunk | **NONE** | nonce \|\| ct \|\| tag on S3 | **B-02, C-02, C-03** |
| FEK envelope | AES-256-GCM | Account-KEK or Custom-KEK | 12B random | **NONE** | `[0x01][keytype][nonce][ct][tag]` in `encrypted_fek` | **B-08** |
| Metadata encryption (filename, sha256-hex) | AES-256-GCM | Account-KEK directly | 12B random per field | **NONE** | nonce + (ct\|\|tag) in DB | B-07, B-13, C-19 |
| Share envelope encryption | AES-256-GCM | Share-KEK | 12B random | **utf8(share_id + file_id)** (no delimiter) | DB envelope blob | B-15 |
| Server-side padding | random bytes appended | n/a | n/a | n/a (not authenticated) | last chunk on S3 | **B-06** |
| TOTP secret generation | crypto/rand 20B = 160 bits | server at enrollment | n/a | n/a | base32 string | OK |
| TOTP secret encryption | AES-256-GCM | HKDF-SHA256(totpMasterKey, "ARKFILE_TOTP_USER_KEY:<username>") | random | none | user_totp.secret_encrypted | A-17, A-18 |
| TOTP backup-code generation | crypto/rand byte mod 26 per char | server at enrollment | n/a | n/a | plaintext JSON → encrypted | **A-07 (encrypted not hashed), A-42 (modulo bias)** |
| TOTP backup-code storage | AES-256-GCM same per-user key | same | random | none | user_totp.backup_codes_encrypted | **A-07** |
| TOTP code verification | pquerna/otp ValidateCustom (HMAC-SHA1, 30s, 6 digits) | per-user TOTP secret (derived) | n/a | n/a | n/a | **A-37 Skew=0**, A-08 no lockout |
| TOTP replay log | SHA-256(code) + window_start | n/a | n/a | n/a | totp_usage_log (no UNIQUE) | A-16 (less severe) |
| Backup-code replay log | SHA-256(code) | n/a | n/a | n/a | totp_backup_usage (no UNIQUE) | **A-16 race** |
| System key wrap | AES-256-GCM | HKDF-Expand(`ARKFILE_MASTER_KEY`, "ARKFILE_<type>_KEY_ENCRYPTION") | 12B random | none | system_keys.encrypted_data + nonce (hex) | B-16, B-25 (REPLACE INTO), B-26 (Expand-only) |
| Account-key cache wrap (browser sessionStorage) | AES-256-GCM + HMAC-SHA256 | ephemeral random 32B in JS heap | 12B random | n/a on AEAD; HMAC over ct | sessionStorage + ephemeral wrappingKey in RAM | B-21, B-22 |
| Server-side per-session SHA-256 (during chunked upload) | SHA-256 | n/a | n/a | n/a | in-process map only | **C-10** |
| End-of-file plaintext SHA-256 verify (download) | SHA-256, constant-time compare | n/a | n/a | n/a | computed after all chunks | C-13 (post-disk-write), C-14 (Blob path skips) |
| `stored_blob_sha256sum` on download (fallback) | (NOT PERFORMED) | n/a | n/a | n/a | n/a | **C-08** |
| Download token | crypto/rand 32B | n/a | n/a | n/a | inside envelope (encrypted) + SHA-256 hash in DB | D-16, D-17 |
| Share ID | client crypto/rand 32B → base64url | n/a | n/a | n/a | DB plaintext + URL | D-23 (client-supplied) |
| CLI agent AccountKey | raw bytes from `DeriveAccountPasswordKey` | n/a | n/a | n/a | RAM, mlock best-effort, no MADV_DONTDUMP | A-21 |
| CLI agent session-binding | SHA-256(access_token) | n/a | n/a | n/a | RAM | OK |
| CLI `--totp-secret` argv | (no crypto; raw bytes via TOTP RFC 6238) | n/a | n/a | n/a | n/a | **A-06** |
| Browser localStorage tokens | bearer | server-issued | n/a | n/a | localStorage `token`, `refresh_token` | **A-05, F-07** |
| Browser password during TOTP | plaintext | input.value | n/a | n/a | window.totpLoginData.password | **A-04, F-08** |

---

## 7. Key Hierarchy (text + reference diagram)

The canonical diagram is in §2.8. Per-key lifecycle table is in Slice A §3.3 and Slice B §3.2. Slice D §3.4 contributes the share-specific entries.

Key entropy summary (worst-case, in bits):

| Key | Entropy | Source | Note |
|---|---:|---|---|
| ARKFILE_MASTER_KEY | 256 | env var (operator-managed) | env-var-only (B-16) |
| OPAQUE server private key (skS) | 256 | crypto/rand at first run | in system_keys |
| OPAQUE OPRF seed | 256 | crypto/rand at first run | in system_keys |
| JWT signing key | 256 (Ed25519 seed) | crypto/rand at first run | same key for temp + full (A-01) |
| Bootstrap token | 256 | crypto/rand at first run | stdout-logged (A-26); journal-logged (F-03) |
| TOTP master key | 256 | crypto/rand at first run | not mlock'd (A-17); co-located (A-18) |
| Per-user TOTP secret | 160 | crypto/rand at enrollment | RFC 6238 §4 minimum |
| TOTP backup codes (per-code) | ~47 | crypto/rand byte mod 26 × 10 chars | modulo bias (A-42); too-short for offline (A-07) |
| Refresh token | 122 | uuid.NewV4 | **below 256-bit recommendation** (A-10) |
| Account-KEK | 256 | Argon2id (m=64MiB, t=3, p=1) | server-controlled params (B-01) |
| Custom-KEK | 256 | Argon2id same params | B-01 |
| Share-KEK | 256 | Argon2id same params with random 32B salt | B-01, B-19, D-10 |
| Share salt | 256 | crypto/rand per share | OK |
| FEK | 256 | crypto/rand per file | OK |
| Per-chunk nonce | 96 | crypto/rand per chunk | OK; never reused under a single FEK |
| Download token | 256 | crypto/rand per share | OK; SHA-256-hashed at rest |
| Share ID | 256 | crypto/rand (client-supplied — D-23) | OK in practice; trust boundary concern |
| AAD on file chunks/FEK/metadata | **0** | not applied | **B-02, B-08, C-02, C-19** |
| AAD on share envelope | (variable) | `utf8(share_id + file_id)` no delimiter | B-15 |

---

## 8. Metadata Exposure Matrix (merged B + C + D)

`Server-visible` = visible to the Go process. `Storage-visible` = visible to S3 backend (object metadata or object body). `Encrypted` / `Authenticated` apply to the values stored, not to network in-transit.

| Metadata item | Server-visible? | Storage-visible? | Encrypted at rest? | Authenticated (AAD)? | Notes / slice refs |
|---|---|---|---|---|---|
| Filename (plaintext) | No (ciphertext only) | No | Yes (Account-KEK) | **No** (`B-07`, `C-19`) | Doc claims AAD; code does not bind |
| File extension (separate metadata) | n/a | n/a | n/a | n/a | Not stored separately |
| Plaintext SHA-256 hex | No | No | Yes (Account-KEK) | **No** | |
| Encrypted-file SHA-256 (server-computed) | **Yes** | No (DB only) | No | n/a | By design — anti-equivocation record |
| Stored blob SHA-256 | **Yes** | No | No | n/a | Includes padding |
| MIME type | n/a | n/a | n/a | n/a | Not stored; HTTP layer always returns `application/octet-stream` (Slice C §4) |
| File size (declared, unpadded) | **Yes** | Yes (via `HeadObject` on storage_id) | No | n/a | `B-06` |
| Padded size | **Yes** | Yes (S3 object's actual byte length) | No | n/a | Leaks ~2.2% of plaintext size |
| Upload timestamp | **Yes** | Yes (S3 `LastModified`) | No | n/a | Standard DB timestamps |
| Modified timestamp | **Yes** | Yes | No | n/a | |
| Owner username | **Yes** | **Yes** (in S3 user metadata — `C-09`) | No | n/a | Required for ACL/KEK; storage leak avoidable |
| Recipient identity (sharing) | n/a | n/a | n/a | n/a | **No PII; EntityID HMAC only** (`D-11`, `D-19`) |
| Folder path | n/a | n/a | n/a | n/a | No folders (flat per-user) |
| Number of files per user | **Yes** | n/a | No | n/a | Trivially queryable |
| Chunk count | **Yes** | No | No | **No** (`C-03`) | Used in byte-range math |
| Chunk size | **Yes** | No | No | **No** (`C-03`) | |
| Per-chunk byte ranges | **Yes** (derivable) | n/a | No | **No** | |
| FEK | No | No | Yes (wrapped under KEK) | **No** (`B-08`) | |
| Storage-provider routing (which S3 backend) | **Yes** | n/a | No | n/a | Operator-side |
| Password hint | **Yes** (cleartext by design) | No | No | n/a | By design |
| Password type byte | **Yes** | No | No | n/a | |
| Access frequency | **Yes** (logs) | n/a | No | n/a | `C-15` logs file_id + username |
| Sharing graph (owner → recipient) | partial | n/a | n/a | n/a | No recipient identity; owner ↔ share_id mapping is plaintext |
| Share password | only to recipient | n/a | n/a | n/a | Never sent to server |
| Share salt | yes (envelope response) | n/a | No (plaintext in DB) | n/a | Required for KDF |
| Argon2id params (for share) | yes (via `/api/config/argon2`) | n/a | No | **No (not bound)** | `D-12` |
| Encrypted envelope blob | yes (to recipient + server) | n/a | Yes (AES-GCM-AAD) | Yes | Asset under offline attack `D-10` |
| Share download token | only to recipient post-decrypt | n/a | inside envelope (encrypted) + SHA-256 at rest | n/a (bearer) | D-16, D-17 |
| Share file_id ↔ share_id mapping | **Yes** | n/a | No | n/a | Required for AAD construction |
| Revoked reason | yes (to anonymous recipient!) | n/a | No | n/a | **`D-04`** — owner-controlled string leaks |
| Filename rendered into browser DOM | (after decrypt) | n/a | n/a | n/a | `F-17` Trusted Types missing |
| Thumbnails / previews / search index | n/a | n/a | n/a | n/a | None exist |

---

## 9. Testing Gaps — prioritized

Consolidated from each slice's §6. Grouped by priority bucket. Each item maps to one or more findings; the full per-test recipe is in the slice that raised it.

### 9.1 Critical priority

1. **JWT audience claim enforcement at validator** — present a temp token to `/api/files`, expect 401/403; forge `aud=foo` with valid signature, expect rejection (`A-01`).
2. **`X-Forwarded-For` localhost-gate bypass** — off-host `curl -H "X-Forwarded-For: 127.0.0.1"` against `/api/admin/users` and `/api/bootstrap/*`, expect 403 (`F-01`).
3. **AAD-bound chunk reorder negative test** — upload chunks 0..N successfully; swap two chunk_numbers in DB; download; expect failure **at AEAD layer**, not at end-of-file SHA-256 (`B-02`/`C-02`/`C-19`).
4. **Cross-file FEK swap** — encrypt two files with same Account-KEK; swap `encrypted_fek` blobs; expect decryption to fail (`B-08`).
5. **Bootstrap token consumed atomically on first redemption** — register first admin; re-redeem same token; expect 401/403 (`A-13`).
6. **Build reproducibility** — clean rebuild from same commit twice; `sha256sum` matches all three Go binaries (`F-05`).
7. **WASM SRI** — tamper with `libopaque.js` post-build; next browser load fails SRI check (`F-04`).

### 9.2 High priority

8. **Refusal of weak server-supplied Argon2id / chunking / password params** — Jest mock returns weak params; client refuses (`B-01`/`B-03`/`B-19`).
9. **Backup codes stored hashed not encrypted** — schema-level assertion that no `crypto.DecryptGCM(user_totp.backup_codes_encrypted)` succeeds (`A-07`).
10. **Per-user TOTP failure lockout** — 10 wrong codes for `alice` from 10 different IPs; 11th rejected with lock state (`A-08`).
11. **Race: concurrent backup-code submission** — two goroutines submit same code; exactly one succeeds (`A-16`).
12. **Per-request `IsUserJWTRevoked` enforcement** — log in; admin force-logout; replay JWT to `/api/files`; expect 401 (`A-09`).
13. **Refresh token entropy + reuse-detection** — decoded refresh token is 32 bytes; use old token after rotation triggers family-revoke + security event (`A-10`).
14. **Window.totpLoginData absent throughout login flow** — Playwright assertion (`A-04`/`F-08`).
15. **JWT in HttpOnly cookie not localStorage** — inject XSS payload that tries `localStorage.getItem('token')`; expect empty (`A-05`/`F-07`).
16. **SQL injection probe** — `storage_providers` row with `provider_id = "x' OR 1=1 --"`; `GET /api/admin/storage/sync-status`; expect parameterized error (`E-02`).
17. **Duplicate-gift idempotency** — identical `POST /api/admin/billing/gift` twice; second returns 409 once UNIQUE exists (`E-04`).
18. **Duplicate daily sweep** — `SweepAllUsers` twice across restart simulation; exactly one usage row per user per day (`E-05`).
19. **Per-route TOTP-gate verification on every `/api/admin/**`** — non-TOTP-verified JWT rejected (`E-01`, `A-01`).
20. **Padding-DoS guard** — synthetic final chunk with large `padded_size - total_size`; server memory bounded (`C-01`).
21. **Multi-provider fallback chunk-hash verify** — primary down; secondary serves; divergence detected (`C-08`).
22. **`max_accesses` enforcement under chunk-0-skip** — anonymous recipient requests chunks 1..N without 0; expect counter to advance / chunks refused (`D-01`).
23. **Race on `access_count`** — N parallel anonymous fetches against `max_accesses=1`; exactly one succeeds (`D-02`).
24. **Argon2id parameter binding into share envelope** — tamper with server's `/api/config/argon2` response; decrypt fails (`D-10`/`D-12`).
25. **CGO fuzz** — feed `auth/opaque_wrapper.c` malformed lengths, NULL pointers, oversize buffers; assert graceful refusal (`A-38`/`A-36`).

### 9.3 Medium priority

26. **DEBUG_MODE prints no raw tokens or backup codes** (`A-11`, `A-42`, `B-12`).
27. **User.Delete cascades all referencing tables** (`A-12`).
28. **Unicode-normalized usernames stored canonically** (`A-29`).
29. **TOTP `Skew = 1`** accepts codes from previous and next windows (`A-37`).
30. **`CompleteTOTPSetup` writes to replay log** (`A-20`).
31. **Lost-device TOTP recovery flow** (`A-15`).
32. **`--totp-secret` not in `/proc/<pid>/cmdline` post-mitigation** (`A-06`).
33. **`arkfile-admin readPassword` returns `[]byte` and zeroes** (`A-3`).
34. **CLI agent peer-cred check** — same-UID different-PID without `SO_PEERCRED` match rejected (`A-21`).
35. **Atomic session-file writes on initial login** — SIGKILL between write and rename (`A-43`).
36. **Browser SW path hash mismatch shows warning before disk write** — currently warns after (`C-13`).
37. **Browser Blob-fallback hash verification** — after `C-14` fix (`C-14`).
38. **6 GB on 3 GB RAM load test** — synthetic 6 GB upload; server peak heap < 1 GB (`B-27`, `C-01`).
39. **`replicateToSecondary` cancellation** — submit replication; cancel via admin runner; goroutine cooperatively exits (`C-11`).
40. **`/shared/:id` rate-limit and timing-protection coverage** (`D-05`).
41. **Free-form `revoked_reason` leak** — anonymous recipient sees only generic message (`D-04`).
42. **Negative test: invalid-base64 vs valid-base64-wrong-hash download tokens** — timing equivalence (`D-17`).
43. **Multi-instance share enumeration coherence** — when multi-instance lands (`D-18`).
44. **Anonymous-side log hygiene** — share access logs contain no plaintext username or full file_id (`D-15`/`D-25`).
45. **Ledger invariant** — `sum(credit_transactions.amount WHERE username=U) == user_credits.balance` (`E-03`/`E-04`).
46. **Overflow tests** — `ParseCreditsFromUSD("92233720369.00")`, `TickUser` with crafted `billable × rate` (`E-06`/`E-07`).
47. **`OpaqueRegister*` register-rate-limit ladder** — 20 consecutive register requests blocked by attempt 4 (`E-25`).
48. **Schema invariants** — `transaction_type` outside enum rejected; `storage_providers.provider_id` matches `^[a-zA-Z0-9_-]+$`; user delete with non-zero balance rejected (`E-21`/`E-22`/`E-23`).
49. **`/readyz` error responses contain no driver-specific wording** (`E-16`).
50. **systemd-analyze security score per unit** (`F-09`).
51. **rqlite loopback-only bind** — `ss -ltn` shows only `127.0.0.1` (`F-10`).
52. **Source-map exposure** — `GET /js/dist/app.js.map` → 404 post-fix (`F-22`).
53. **Frozen lockfile + audit** — `bun install --frozen-lockfile`; `govulncheck ./...`; `bun audit` (`F-13`/`F-25`).
54. **XSS via decrypted filename / contact-info** — Playwright; Trusted Types blocks (`F-17`).

### 9.4 Low / hygiene priority

55. Bootstrap-token redacted from journal (`F-03`).
56. Property test: `decodeBase64IfNeeded` does not corrupt valid AES-GCM ciphertext (`A-19`).
57. Backup-code modulo bias statistical test on 10^6 codes (`A-42`).
58. Cross-language Argon2id conformance test in CI (Go ↔ TS).
59. Property test: `CreateAAD` for any (share_id, file_id) pair yields unique AAD (`B-15`).
60. Empty-plaintext consistency between `EncryptGCM` and `EncryptFile` (`B-14`).
61. Fuzz test on envelope parser (`ParseEnvelope`, `DecryptFEK`).
62. Nonce-uniqueness statistical smoke test under a single key.
63. `secureWipe` on `Uint8Array` backed by `SharedArrayBuffer` (`B-21`).

---

## 10. Hardening Recommendations (non-vulnerability, prioritized)

Consolidated from each slice's §7. Items not tied to a specific finding but improving posture.

### 10.1 Architecture-level

1. **Separate Ed25519 keys for temp vs full JWT** — KeyManager entries `jwt_signing_key_temp_v1` and `jwt_signing_key_full_v1`. Makes A-01-class regressions structurally impossible. (A.)
2. **Typed-key wrappers in Go** — `type AccountKEK [32]byte`, `type CustomKEK [32]byte`, `type FEK [32]byte`, etc. The compiler catches misuse. Branded types in TS. (B.)
3. **Cross-language Argon2id conformance test in CI** — Go emits expected hex; TS asserts byte-equality. (B.)
4. **Embed `argon2id-params.json` / `chunking-params.json` / `password-requirements.json` into both the Go binary and the TS bundle** as compile-time floors. Remove `/api/config/*` from the security-critical path. (B/E.)
5. **Crypto agility version byte present and policed** — current envelope `0x01`; the AAD-binding fix lands as `0x02`. Parser rejects unknown versions. (B.)
6. **Soft-delete users via `deleted_at TIMESTAMP`** — preserves financial audit trail across deletes (E-21). (E.)
7. **Tamper-evident admin audit log** — append-only or chain-hashed `admin_logs` so an admin reading another user's contact info (E-18) leaves a record the admin themselves cannot tamper with. (E.)
8. **Ledger-invariant background job** — nightly verify `sum(credit_transactions.amount) == user_credits.balance` per user; alert on drift. (E.)
9. **Move bearer tokens from localStorage to `__Host-` cookies** with SameSite=Strict + CSRF double-submit. Tighten CSP; add Trusted Types. (A/F.)
10. **`require-trusted-types-for 'script'` plus refactor of all `innerHTML` sinks** — uses `textContent` or sanitized typed values. (F.)
11. **CSP/Permissions-Policy/COOP/COEP/CORP** consolidated emission in one place (Go middleware). Single source of truth per header. (F.)

### 10.2 Crypto-implementation hardening

12. **Bind AAD on every file-related AEAD** — chunks (file_id + chunk_index + chunk_count + ciphertext_sha256), FEK envelope (file_id + key_type), metadata (file_id + field_name + owner_username). Single coordinated change in Go and TS and CLI. (B/C.)
13. **Bind Argon2id params into share envelope JSON**; refuse decrypt if `m/t/p` doesn't match the local floor. (B/D.)
14. **Client-side padding before upload** — server never sees unpadded size. (B.)
15. **HKDF-Extract+Expand (instead of Expand-only)** for `KeyManager.deriveWrappingKey`. One line. (B.)
16. **TOTP backup-code length increase to 14 chars (~65 bits)**, generated without modulo bias (sample with rejection from a 32-byte buffer). (A.)
17. **Per-user TOTP failure counter + lockout on `user_totp`**. (A.)
18. **`mlock` + `MADV_DONTDUMP` + `PR_SET_DUMPABLE=0` on every server-side process** holding long-lived secrets. Match the CLI agent's pattern. (A.)
19. **Atomic write everywhere session-file is written** in both CLIs (match `atomicSaveAuthSession`). (A.)
20. **Module-private password retention in browser; never `window`-attached.** (A/F.)
21. **`mlock` and madvise on TOTP master key, OPAQUE server key, JWT key pages.** (A.)
22. **`crypto/subtle.ConstantTimeCompare` for every secret comparison** (CLI password-vs-confirm; download-token decode failure path D-17; admin reset comparisons). (A/D.)

### 10.3 Operational

23. **Document the recovery model explicitly** in `docs/security.md`: lost password = lost files; lost authenticator + lost backup codes = lost account. Discourages future "let me add an admin reset" code. (A.)
24. **Move `/healthz` and `/readyz` to a loopback listener** (or `/internal/...` with a fixed token). (E/F.)
25. **Pin Caddy binary; verify hash on every deploy.** (F.)
26. **Vendor libsodium as a pinned git submodule and statically link.** (F.)
27. **Replace MD5 with SHA-256 for SeaweedFS pinning; hash-pin rqlite.** (F.)
28. **Audit `scripts/maintenance/**` for stale assumptions** (F-19 is one example). (F.)
29. **Document the Caddy↔Arkfile co-located trust model** so `tls_insecure_skip_verify` is an auditable decision. (F.)
30. **Add `LimitCORE=0` as the FIRST hardening step on all four systemd units** — one-line change, single largest risk reduction in F-09. (F.)
31. **Document that the bootstrap-token-in-journal behavior is a known issue** and operators must invalidate by restarting service if they cannot redeem immediately. (F.)
32. **Startup self-test for `F-01`** — issue `/api/admin/users` with `X-Forwarded-For: 127.0.0.1` from a non-loopback netns peer; refuse to start if it succeeds. Catches regressions deterministically. (F.)
33. **Prometheus-style metrics for billing** — ticks-per-hour, sweeps-per-day, gifts-per-day, total drained. (E.)
34. **Background incomplete-multipart-upload aborter + orphan reconciler** — closes C-06/C-07 storage-cost leaks. (C.)
35. **Pass `req.Context()` to `replicateToSecondary`** instead of `context.Background()` (or route through the task runner). (C.)
36. **`govulncheck` + `bun audit` in CI**; fail on high-severity. (F.)
37. **Cosign-sign release artifacts** with `cosign.pub` published in repo. SBOM via `syft`. (F.)
38. **Reproducible-build verification in CI** (clean rebuild × 2 matches; `strings` contains no `/home/` paths). (F.)

### 10.4 Code hygiene

39. **Delete dead code** — `crypto/session.go` (B-10), `crypto/opaque_validation.go` (B-11/A-45), `crypto/envelope.go` if comment-only (B-18), unused `storage.GetPresignedURL` (C-17), `models/file.go:CreateFile` (C-23) + `UpdatePasswordHint` (C-24), `isShareEndpoint` (D-24), unused `generateShareID` (D-23), `decodeBase64IfNeeded` rqlite-driver workaround (A-19), `scripts/maintenance/rotate-jwt-keys.sh` if obsolete (F-19).
40. **Move `crypto/envelope.go`'s envelope code into the file named `envelope.go`** rather than `file_operations.go`. (B.)
41. **Drop `//go:build mock` from chunked-upload integration tests** — they are the only end-to-end coverage and are silently skipped (C-18).
42. **Match `arkfile-admin` and `arkfile-client` interfaces** — `readPassword` signature, pipe timeout, password lifecycle. Cross-binary drift is long-term security debt. (A.)
43. **Adopt a single `requireAdmin*` helper** and migrate all admin handlers (E-10/E-13). `golangci-lint` rule forbidding inline `if !user.IsAdmin`. (E.)
44. **Adopt a parameterized-SQL-only policy** — `golangci-lint` rule banning `fmt.Sprintf` adjacent to SQL keywords (E-02). (E.)
45. **Constrain `storage_providers.provider_id` to a charset** at schema level (E-02). (E.)

---

## 11. Explicit Answers to `idsrp.md` §19 (20 Questions)

Each question is answered briefly with the specific finding(s) that justify the answer. Slice file:line evidence lives in the cited findings.

**1. Does the OPAQUE implementation prevent offline password guessing if the database is stolen?**
**Mostly yes for login passwords.** OPAQUE is specifically designed to resist this. `opaque_user_data` rows on their own do not enable offline guessing. Caveats: (a) if the attacker also obtains `system_keys` and ARKFILE_MASTER_KEY (Slice B `B-16`), the OPAQUE server private key is recovered, but per OPAQUE design that still does not enable offline password recovery against the user records themselves — the OPRF blinding protects passwords from the server. (b) `share_envelopes` are encrypted with **Argon2id-only** under a share password and are **trivially offline-attackable** (Slice D `D-10`), especially because share KDF parameters are not bound into the envelope (`B-19`/`D-12`).

**2. Is the OPAQUE server setup key protected separately from the database?**
**No, it is co-located.** `system_keys` row, same table as JWT signing key, TOTP master key, and bootstrap token (Slice A `A-18`). It is wrapped at rest under `ARKFILE_MASTER_KEY` which lives in `/opt/arkfile/etc/secrets.env` as an env-var-only secret (`B-16`, Slice A Open Question 1). A `system_keys` + `ARKFILE_MASTER_KEY` compromise unlocks all server-side keys at once.

**3. Is the OPAQUE export key used? If yes, how?**
**No.** libopaque returns it; both server and browser ignore it. `crypto/opaque_validation.go` is an empty stub (Slice A `A-45`, Slice B `B-11`). This is a latent capability that could be wired up for KEK derivation in the future, but doing so would require a new audit. Today the export key is dead.

**4. Is Argon2id being used safely and with domain separation?**
**Mostly.** Three contexts (account / custom / share) with distinct salt prefixes (`SHA-256("arkfile-{account,custom}-key-salt:" + username)` or random per share). Domain separation is enforced by code structure: nothing from OPAQUE feeds into Argon2id. Caveats: (a) the same Account-KEK is used both to wrap FEKs and to encrypt metadata — domain-separation omission (`B-07`); (b) parameters are server-controlled (`B-01`); (c) TS implementation blocks the main thread for several seconds (`B-04`); (d) share parameters are not bound into the envelope (`D-12`).

**5. Are Argon2id parameters attacker-controlled or downgradeable?**
**Yes.** Both Go and TS clients fetch parameters at runtime from `/api/config/argon2` with no signature, hash-pin, or compile-time floor (Slice B `B-01`). The chunking parameters and password requirements have the same defect (`B-03`, `B-19`). A compromised server can silently weaken every future KDF derivation. This is the largest single design defect in the cryptographic layer.

**6. Are file encryption keys generated randomly per file?**
**Yes.** `crypto/rand` (Go) and `crypto.getRandomValues` (TS) yield a 32-byte FEK per file. Never reused across files. Documented in Slice B §1.2.

**7. Are AEAD nonces unique under each key?**
**Yes.** All AES-GCM nonces are 12-byte random values from CSPRNG; nonce-collision is birthday-bound at 2^48 encryptions under one key, which no Arkfile file approaches. No counter-mode nonce derivation, no per-chunk-index nonce reuse. (Slice B §3.1.)

**8. Is ciphertext integrity verified before plaintext is used?**
**At the AEAD layer, yes** (AES-GCM tag verified before plaintext returned). **At the application layer, no** — see Q9. The browser streaming-download path writes plaintext to disk before the end-of-file plaintext SHA-256 is verified (`C-13`); the Blob fallback skips that verification entirely (`C-14`). A server-tampered chunk is detected, but a server-substituted chunk-of-the-same-FEK is not detected at the AEAD layer (Q9 below).

**9. Can the server swap, replay, truncate, or roll back encrypted files without detection?**
**Swap: yes, between this user's own files** (Slice B `B-02`, Slice C `C-02`). No AAD binds chunks or FEK envelopes to `file_id`, so a server with DB write access can substitute one of Alice's files' chunks for another. End-of-file plaintext SHA-256 catches this — but only after the file has been written to disk. **Reorder: yes** (`B-05`, `C-02`, `C-03`); same root cause. **Truncate: yes**; `chunk_count` is plaintext in DB and not bound by AAD. **Roll back: yes**; no monotonic counter or version chain on `file_metadata`. The end-of-file plaintext SHA-256 verification is the only line of defense, and it is post-disk-write.

**10. Are filenames and metadata encrypted, authenticated, or plaintext?**
**Filename + plaintext SHA-256: encrypted, NOT authenticated** (`B-07`, `C-19`). **File size: PLAINTEXT** to within ~10% padding (`B-06`). **Owner username: PLAINTEXT in DB and in S3 object metadata** (`C-09`). **Upload timestamp: plaintext.** **Chunk count + chunk size: plaintext** (`C-03`, `D-21`). **Password hint: plaintext by design.** **Folder path: N/A (no folders).** Slice B §3.3, Slice C §3.3, Slice D §3.3 detail the matrix; merged in §8 above.

**11. Can one user access another user's files by changing IDs?**
**No, ownership is consistently checked.** Per-route handlers query `WHERE file_id = ? AND owner_username = ?`. Exceptions: `C-12` (`GetFileEnvelope` skips `IsApproved`); `C-05` (`CancelUpload` is dead-on-arrival due to param mismatch but doesn't fail-open); admin endpoints intentionally bypass owner check by design (`E-20`).

**12. Can a malicious recipient access files after revocation?**
**Future fetches: no.** **Already-downloaded content + held keys: yes.** Revocation prevents future fetches of the envelope and chunk endpoints (cross-instance coherence is best-effort, `D-18`). Once a recipient has decrypted the envelope they hold the FEK forever; the file is not re-encrypted on revoke. The revocation UI overstates the guarantee ("immediately prevent anyone from accessing", `D-13`). This is consistent with the AGENTS.md "no PII" share posture but the UI/docs mismatch is a finding.

**13. Does sharing rely on server-controlled public keys? If so, can the server substitute keys?**
**No.** Sharing is password-derived, not PKI-based. There is no recipient public-key directory. The server cannot substitute keys directly; it can, however, substitute the entire envelope ciphertext at storage time (and the AAD-binding to `share_id + file_id` does *not* prevent this because the server controls the (share_id, file_id) mapping). Today this is mitigated by AEAD authentication of the share password the recipient types — a substituted envelope would fail to decrypt with the legitimate password. The defense is structural, not by recipient-identity verification.

**14. Can XSS expose passwords, file keys, or plaintext files?**
**Yes, all three.** Password: stashed on `window.totpLoginData` during the TOTP window (`A-04`/`F-08`). Full JWT and refresh token: in `localStorage` (`A-05`/`F-07`), exfiltrable by any same-origin script. File keys: Account-KEK is held in JS heap during file ops; sessionStorage-cached version is encrypted under an ephemeral key (`B-21`) but the wrapping key is also in JS heap, so any same-origin script can recover both. The frontend has 12 `innerHTML` sinks (`F-17`) with no Trusted Types. CSP forbids `'unsafe-inline'` in script-src (good), but a successful XSS via dependency compromise, supply-chain attack, or filename-rendering bug (filenames are decrypted client-side) reads all three.

**15. Are any secrets stored in localStorage, IndexedDB, logs, crash reports, or analytics?**
**localStorage: yes** (`A-05`/`F-07` — JWT, refresh token). **IndexedDB: no** (Slice F §3.4). **Logs: yes, in multiple places** — `A-11` (refresh token under `DEBUG_MODE=true`), `C-15`/`D-15`/`D-25` (plaintext username + file_id at INFO), `F-03` (bootstrap token in systemd journal), `E-15` (operator-supplied details in `admin_logs`). **Crash reports: no instrumentation present.** **Analytics: none.**

**16. Does password reset preserve encrypted data? If so, how?**
**N/A — there is no password reset.** Per `AGENTS.md` and Slice A §4: lost password = lost files. The cryptographic model requires the password to re-derive Account-KEK; no escrow exists. The OPAQUE export key is unused (Q3), so even a recovery flow built on it would require a new design. Consistent with the no-PII posture; should be user-facing-documented.

**17. Is the claimed security model accurately reflected in implementation and documentation?**
**Partially.** Where the design is correct, the implementation is broadly faithful. Where it isn't: (a) the "two-tier JWT" model is documented in `idsrp.md` §22.2 but not enforced (`A-01`); (b) the "mandatory TOTP for all authenticated access" claim does not hold for the admin route group (`E-01`) or for the public `/api/files/:fileId/export` header path (`E-19`); (c) the share-revocation UI overstates the guarantee (`D-13`); (d) `models/file.go`'s doc comment claims AAD-bound metadata that the implementation does not apply (`C-19`); (e) an embedded JS comment claims Argon2id parameters of 256MB/8 iterations when production is 64MB/3 (`B-09`); (f) `idsrp.md` §22.2 requires TOTP backup codes "hashed (Argon2id or comparable) and/or at-rest encrypted (never plaintext)" — Arkfile satisfies the letter but the encryption is reversible from `system_keys` + DB (`A-07`).

**18. Are CGO components reachable with attacker-controlled data?**
**Yes, by design** — the entire OPAQUE handshake feeds attacker-supplied bytes (registration request M, login credential request, etc.) through `auth/opaque_wrapper.c` into libopaque. The wrapper is 203 LOC and was line-by-line audited in Slice A. Specific issues: `A-36` (`StoreUserRecord` internal buffer inconsistency); `A-38` (password-buffer not zeroed in C heap after use). The vendored libopaque/liboprf/libsodium internals are trusted upstream and were not re-audited (per plan §2). No fuzz harness exists for the wrapper itself (testing gap §9.1 item 25).

**19. Are WASM artifacts pinned and tied to audited source?**
**No.** `client/static/js/libopaque.js` is built from source via `build-libopaque-wasm.sh` (emscripten) and checked into the repository. It is served as a static asset with **no Subresource Integrity** attribute (Slice F `F-04`) and **no hash entry in `config/dependency-hashes.json`**. There is no SRI declared in `index.html`, no build-time hash emission, and no startup self-check that the on-disk artifact matches the audited source. A build-host or asset-CDN compromise can substitute the WASM with no integrity check downstream.

**20. What are the top five security risks in the current design?**
1. **`F-01` Critical** — `X-Forwarded-For` localhost-gate bypass renders admin and bootstrap localhost-only protections remotely bypassable.
2. **`A-01` Critical** — Two-tier JWT model is not enforced; post-OPAQUE temp token reaches every protected route, making the "mandatory TOTP" claim cosmetic.
3. **`B-02` / `C-02` / `C-19` / `B-08` (High, cross-slice)** — No AAD binds file chunks, FEK envelopes, or metadata to file identity or order; an active server can swap/reorder/substitute undetected at AEAD layer.
4. **`A-07` + `A-17` + `A-18` (High, cross-slice)** — TOTP backup codes encrypted not hashed; master key co-located with every other server secret; a `system_keys` + DB + master-key compromise yields plaintext backup codes for every user.
5. **`A-05` + `F-07` + `A-04` + `F-08` (High, cross-slice)** — Full JWT, refresh token, and (briefly) plaintext password all reachable via same-origin script. Any XSS / dependency compromise yields complete account takeover.

---

## 12. Open Questions for the Team

Consolidated from `00-plan.md` §10 and each slice's §5. Items marked "Answered" in the plan are not repeated.

### 12.1 Pre-Slice-A questions (status from `00-plan.md` §10)

1. **Forgotten-password recovery intentionally absent?** Still TBD by developer confirmation. Slice A treats it as N/A by design (`A-15` documents the impossibility of TOTP recovery). Recommendation: document it explicitly in `docs/security.md` so future contributors do not implement an admin reset that would weaken the model.
2. **Device-management / per-device session listing planned?** Still TBD. Refresh tokens are not tied to a device identifier today; building this requires schema additions to `refresh_tokens`. Slice A flagged as N/A for now.
3. **CSP strictness target for production?** F-14 / F-15 / F-17 surface specific items. Recommendation: add `require-trusted-types-for 'script'`, remove inline `onclick=` handlers, refactor `innerHTML` sinks to `textContent`.
4. **WASM bundled into TS build or fetched separately?** Currently fetched separately (`<script src="/js/libopaque.js">`) per Slice F §1.2. F-04 escalates if it remains separate without SRI; consider bundling or hash-pinning.

### 12.2 Slice A open questions

5. **`KeyManager` at-rest encryption posture** — confirm `system_keys` rows are encrypted at rest under a KEK and that the KEK lives outside the rqlite volume. Per `.clinerules` the auditor cannot read `/opt/arkfile/etc/**`. Determines final severity of A-18.
6. **Caddyfile trusted-proxy configuration** — answered partially by Slice F: `Caddyfile.prod` and `Caddyfile.test` do not declare `trusted_proxies` and do not strip incoming `X-Forwarded-For`. Severity escalation to `F-01` Critical now applies. Fix per §10.3 item 32.
7. **JWT TTL default** — `utils.GetJWTTokenLifetime()` default and env-var override not confirmed; if hours, A-09's gap widens.
8. **CLI agent + refresh-token rotation** — confirmed behavior: agent wipes on session-hash mismatch. Open question: should `refreshSessionToken` push a new hash to the agent rather than force re-login?
9. **`utils.IsProductionEnvironment` definition** — Slice F confirms it is env-var-checked (`ENVIRONMENT=production`). A-14/A-41 stand. Recommendation: build-tag separation instead.
10. **TOTP master-key rotation script absent** — Slice A Open Q6. Recommendation: implement `scripts/maintenance/rotate-totp-keys.sh` to re-derive every user's encrypted blob under the new master key in a single transaction.
11. **`config/security_config.go` fail-closed on conflicting flags** — does it refuse to start if `ENVIRONMENT=production` AND `ADMIN_DEV_TEST_API_ENABLED=true`? A-14 should fail-closed.
12. **`arkfile-admin` pipe-mode timeout** — missing vs `arkfile-client`'s 10s. Justified? If so, what use case?
13. **Browser TOTP-setup screen lifetime** — after "Done", is the section's `innerHTML` cleared or just hidden? A-22 assumes the worst.
14. **`/api/admin-contacts` exposure** — public unauthenticated route returning admin contact info. Intentional? Cross-ref A-24 admin enumeration.

### 12.3 Slice B open questions

15. **Is the decision not to bind `file_id` into file-chunk AEAD documented anywhere?** Slice B treats B-02 as a finding; if there's a design rationale, please flag.
16. **Planned key-rotation cadence for system keys?** B-25 `REPLACE INTO` suggests no rotation today.
17. **Is `ARKFILE_MASTER_KEY` ever read from anywhere other than `secrets.env`?** Per `.clinerules` the auditor has not read that file.
18. **Should Arkfile bundle Argon2id WASM (vs continuing with pure-JS `@noble/hashes`)?** Would address B-04. Requires SRI/pinning treatment in Slice F.
19. **Is the 5 GB client-side `MAX_FILE_SIZE` intentional?** Conflicts with AGENTS.md 6 GB mobile constraint (B-27).
20. **Roadmap to derive a separate metadata key via HKDF from Account-KEK?** Would resolve B-07.

### 12.4 Slice C open questions

21. **Schema details deferred to Slice E** — resolved by Slice E §3.3.
22. **`ADMIN_DEV_TEST_API_ENABLED=true` cannot be set in prod-deploy?** Per `.clinerules` the auditor cannot read secrets. Slice F item §5.4 also asks. Recommendation: `prod-deploy.sh` should refuse to write the flag.
23. **CLI parity for AAD changes** — implementing C-02 needs matching changes in `cmd/arkfile-client/crypto_utils.go`. Mirror in TS.
24. **`docs/wip/folders-multi-upload-v2.md`** — out of scope for slices; explains C-19 doc-vs-code drift. Did the team roll back AAD or is it just unimplemented?
25. **`ENABLE_UPLOAD_REPLICATION` default in production?** Determines C-08 urgency.
26. **`storage.GetPresignedURL` planned use case?** If not, delete (C-17).

### 12.5 Slice D open questions

27. **`max_accesses` intended semantic** — "completed downloads, total" or "download starts"? Determines D-01/D-02 severity.
28. **`BASE_URL` mandatory in production?** D-09 assumes the Origin fallback path is reachable.
29. **Daily EntityID rotation period configurable?** D-11/D-19.
30. **Is `generateShareID` intentional (CLI client) or stray?** D-23.
31. **Per-share-creation rate limiting** — any account-level quota/spam-share guard? Not visible in this slice.

### 12.6 Slice E open questions

32. **Confirm no JWT minted with `aud=arkfile-prod` + `totp_verified=false`** — if any path exists (e.g. refresh after TOTP reset), E-01 and E-19 escalate.
33. **Caddy `X-Forwarded-For` posture** — Slice F confirms `F-01`; E-14 now Critical-escalated.
34. **Future paid-top-up `transaction_id` source** — Stripe `pi_*` IDs, crypto txid, etc. Add `UNIQUE(transaction_id)` *before* writing any paid rows.
35. **`AdminCleanupTestUser`'s duplicate `opaque_user_data` row (E-11)** — intentional belt-and-suspenders, or copy-paste bug?
36. **Process-local `lastSweepDate` (E-05)** — documented invariant or emergent property?
37. **`AdminGetContactInfo` audit-log** — should every admin read land in `admin_logs`? (E-18.)

### 12.7 Slice F open questions

38. **Runtime file modes under `/opt/arkfile/etc/**`** — `prod-deploy.sh` writes `secrets.env` as 0640 and `caddy-env` as 0600; confirm at runtime that no operator chmod has loosened these. Per `.clinerules`.
39. **`bun.lock` commit status** — confirm `git ls-files client/static/js/bun.lock` returns a hit; if not, F-13 escalates.
40. **`scripts/maintenance/rotate-jwt-keys.sh` retirement** — confirm with Slice A's owner that the on-disk path is no longer authoritative.
41. **`ENVIRONMENT=production` posture today** — recommended that all non-dev deploys write this unconditionally so `ValidateProductionConfig`'s fail-closed abort is enforced.
42. **Release-artifact signing today** — F-05 assumes none; confirm there is no out-of-band CI signing process before recommending cosign integration.
43. **`AllowedOrigins` in deployed CORS config** — with `AllowCredentials: true`, `[*]` would break the app; confirm explicit allow-list.
44. **`/healthz` and `/readyz` external monitoring** — decide before moving to loopback (F-20).
45. **Caddy binary supply-chain pinning** — `prod-deploy.sh` Caddy download step not deep-read; confirm specific release hash is pinned.

---

## 13. Out-of-Scope Reminders (for completeness)

Per `00-plan.md` §9, the following remain out of scope for this review:

- Re-auditing libsodium / liboprf / libopaque internals (trusted upstream; only the CGO boundary in `auth/opaque_wrapper.c` was line-by-line audited).
- Performance benchmarking.
- Penetration testing of any live deployment (`test.arkfile.net` or otherwise).
- Reading `.env` files or `/opt/arkfile/etc/**` (per `.clinerules`).
- Committing or pushing any change. Developers commit. This document is also produced under that constraint.

---

## 14. Closing Assessment

Arkfile's design is good: OPAQUE for authentication, client-side AEAD for content, Argon2id for password-derived KEKs, password-derived share envelopes, no PII / no IPs in logs. The primitives are right and the trust boundaries are mostly placed where they should be.

The implementation does not yet meet the design's claims in several places that matter materially. The two highest-leverage fixes are not large — `e.IPExtractor` and JWT audience enforcement are each a few lines of code — and together they close the headline Critical/High pathway: a remote, unauthenticated attacker plus password compromise yields full account access today; with those two fixes that pathway closes. The next layer of work — AAD on every AEAD operation, parameter floors embedded in client bundles, schema-level financial-audit integrity, supply-chain hardening — is more substantial but each item is well-scoped and individually addressable.

There are no findings in this review that require fundamental architectural change. Every finding is fixable within the existing structure; the greenfield posture (`AGENTS.md` §"Greenfield App") means there is no backwards-compatibility friction to absorb. The 10-step fix campaign in §1.5 closes roughly 1 Critical, 12 High, and ~20 Medium findings.

Beta deployment at `test.arkfile.net` should expect that, until at least `F-01`, `A-01`, and the AAD-binding cluster (`B-02` / `C-02` / `C-19`) are addressed, file-content confidentiality against a protocol-following server holds, but file-content authenticity against an active server and admin-surface remote isolation do not. Operators should be informed.

The system is on a credible path to delivering its stated guarantees. The work to get there is concrete, well-bounded, and described finding-by-finding in the six slice documents that this synthesis summarizes.

---

## Appendix A: Slice cross-reference

| Slice | Output file | Findings | Severity range |
|---|---|---:|---|
| A — Auth & OPAQUE (incl. CLIs and mandatory TOTP) | `01-auth-opaque.md` | 45 (A-01..A-45) | 1 Critical, 12 High, 21 Medium, 9 Low, 2 Informational |
| B — Crypto & key hierarchy | `02-crypto-keys.md` | 27 (B-01..B-27) | 0 Critical, 3 High, 6 Medium, 10 Low, 8 Informational |
| C — Upload / Download / Chunking | `03-files-upload-download.md` | 27 (C-01..C-27) | 0 Critical, 3 High, 11 Medium, 10 Low, 3 Informational |
| D — Sharing | `04-sharing.md` | 27 (D-01..D-27) | 0 Critical, 2 High, 9 Medium, 10 Low, 6 Informational |
| E — API / Authz / Admin / Billing | `05-api-authz-admin-billing.md` | 27 (E-01..E-27) | 0 Critical, 2 High, 8 Medium, 7 Low, 10 Informational |
| F — Frontend / WASM / Supply / Ops | `06-frontend-supply-ops.md` | 26 (F-01..F-26) | 1 Critical, 5 High, 6 Medium, 6 Low, 8 Informational |
| **Total** | **6 slice docs** | **179** | **2 Critical, 27 High, 61 Medium, 52 Low, 37 Informational** |

## Appendix B: Files audited (cross-slice)

Each slice doc lists the specific files read and the LOC. The aggregate scope of the review:

- Go server: ~50,000 LOC across `handlers/`, `auth/`, `crypto/`, `models/`, `billing/`, `storage/`, `logging/`, `monitoring/`, `config/`, `database/`, `utils/`.
- TypeScript frontend: 20,077 LOC across `client/static/js/src/**`.
- CGO wrapper: 203 LOC in `auth/opaque_wrapper.{c,h}` (line-by-line).
- CLI binaries: ~11,948 LOC across `cmd/arkfile-client/` and `cmd/arkfile-admin/`.
- Schema: `database/unified_schema.sql`.
- Config: `crypto/argon2id-params.json`, `crypto/chunking-params.json`, `crypto/password-requirements.json`, `config/dependency-hashes.json`.
- Ops: `Caddyfile{,.local,.test,.prod}`, `systemd/*.service`, `scripts/setup/**`, `scripts/maintenance/**`, `scripts/{dev-reset,local-deploy,prod-deploy,prod-update,test-deploy,test-update}.sh`.
- WIP docs cross-referenced: `docs/AGENTS.md`, `docs/wip/idsrp.md`, `docs/wip/review/00-plan.md`, `docs/erasure-coding.md`.

Vendored C libraries (libopaque, liboprf, libsodium) — ~347,000 LOC — were treated as trusted upstream per `00-plan.md` §2.

## End of Slice G — Executive Synthesis
