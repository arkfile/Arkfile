# Better MFA: Hardware Security Keys, Unified Credentials, and Recovery

This document plans the Multi-Factor Authentication enhancement for Arkfile: hardware security key support (YubiKey, Nitrokey 3), a greenfield migration from the TOTP-specific tables to a unified MFA credential model, admin bootstrap MFA setup via `arkfile-admin` on the server host (including security keys on local deploy), admin-assisted recovery, end-user CLI/browser parity, Tor Browser considerations, Tier-3 key rotation hardening, and supporting user documentation.

## Goals

Arkfile currently requires TOTP as the sole second factor. This project adds FIDO2/WebAuthn hardware security keys as an alternative second factor (user picks one at enrollment in the first release), preserves backup codes as the primary self-service recovery path for all MFA types, adds an admin CLI command to reset a user's MFA, improves sitewide visibility of contact/admin-contact affordances, completes the Tier-3 user-secret-master rotation script so it re-encrypts all dependent database rows, and achieves functional equivalence between the TypeScript browser client and the `arkfile-client` Go CLI for MFA enrollment and login. Admin bootstrap is equally in scope: after `arkfile-admin bootstrap` on a new instance, the operator must be able to complete initial MFA setup with either TOTP or a hardware security key via `arkfile-admin` on the server host — not through the website. Administrators do not perform admin functions in the web app; all privileged operations, including bootstrap, MFA enrollment, and ongoing administration, run through `arkfile-admin` on the instance itself.

## Non-goals (first release)

Multi-method enrollment (more than one second factor per account) is deferred. The long-term cap of three total methods remains the target architecture, but the first release enforces exactly one method per user: either TOTP or a hardware security key. Passkey/platform authenticators (Touch ID, Windows Hello as primary factor) are out of scope. Email-based recovery remains out of scope. Password reset remains out of scope.

## Current codebase assessment (pre-implementation sanity check)

The core TOTP implementation in `auth/totp.go` (~1,100 lines) is sound and should be migrated rather than rewritten. It includes two-phase enrollment (`StoreTOTPSetup` / `CompleteTOTPSetup`), RFC 6238 validation with skew and replay protection, Argon2id-hashed single-use backup codes with race-safe consumption, per-user failure lockout, and Tier-3 encryption of TOTP secrets via `crypto.DeriveTOTPUserKey` (HKDF purpose `totp_user` today).

The two-tier JWT model in `auth/jwt.go` and route wiring in `handlers/route_config.go` are coherent: temp tier (`arkfile-totp`) for post-OPAQUE handoff, full tier (`arkfile-api`) for normal access, reset tier (`arkfile-totp-reset`) intended for re-enrollment after backup-code recovery. Browser cookie injection via `CookieTokenMiddleware` and CSRF rules are in place.

Gaps and issues identified before implementation begins:

**Reset-tier JWT routing bug.** `POST /api/totp/reset` is registered on `auth.Echo`, which applies `JWTMiddleware` expecting full-tier `arkfile-api` tokens. The lost-device recovery flow issues a reset-tier token (`AudienceReset` = `arkfile-totp-reset`, temp signing key) from `RecoverWithBackupCode`, and both the browser (`client/static/js/src/auth/totp.ts`) and `arkfile-client` then call `/api/totp/reset` with that token. The `TOTPReset` handler checks for `arkfile-totp-reset` audience, but `JWTMiddleware` rejects the token before the handler runs. Fix: add `ResetJWTMiddleware` (temp key + `arkfile-totp-reset` audience) and register reset on a route group that uses it, or extend temp-tier middleware to accept reset audience for that path only.

**Browser backup-code UI gap.** The server supports two backup-code paths (see next section). The browser lost-device UI today only exposes re-enrollment (path B). Emergency one-shot login (path A) must be added to the MFA login UI during implementation; do not defer this.

**Dead/stub crypto from Tier-3 migration.** `crypto.InitializeTOTPMasterKey` is a no-op; `GetTOTPMasterKeyStatus` always reports empty; `totpMasterKey` in `crypto/totp_keys.go` is never populated. Still called from `main.go`. Delete during cleanup per AGENTS.md greenfield rules.

**Admin MFA reset absent.** No `POST /api/admin/users/:username/reset-mfa` and no `arkfile-admin reset-user-mfa`. TOTP rows are deleted only via dev-test cleanup or full user deletion in `handlers/admin.go`. Admin reset must DELETE credential rows (not `UPDATE` like `ResetTOTP`) and force-logout. v1 ships full reset only; API/CLI shape should accept an optional credential selector later for multi-method accounts (see arkfile-admin section).

**Admin contacts API shape mismatch.** `AdminContactsHandler` in `handlers/files.go` returns flat `{ adminUsernames, adminContact }`. `client/static/js/src/files/list.ts` expects nested `data.admins[].contacts`, so the storage-section contact note always falls back to generic text.

**Schema view not in original plan.** `user_auth_status` SQL view in `unified_schema.sql` joins `user_totp` and must be updated when tables rename.

**Fourth usage table.** Plan must include `totp_backup_usage` (backup code replay log), actively used in `auth/totp.go`; rename to e.g. `mfa_backup_usage`.

**Tier-3 rotation script incomplete.** `scripts/maintenance/rotate-user-secret-master.sh` backs up and replaces `user-secret-master.bin` but does not re-encrypt database rows. After rotation, all MFA secrets and contact info encrypted under the old master become undecryptable. Replacement is a two-phase `arkfile-admin` flow (`prepare` while server is up with full admin + 2FA auth, `apply` offline with server stopped and a signed mandate). See dedicated section below.

**Admin bootstrap MFA is TOTP-only today.** `arkfile-admin setup-mfa` calls only `/api/mfa/setup` and `/api/mfa/verify` (TOTP). Deploy runbooks in `local-deploy.sh`, `test-deploy.sh`, and `prod-deploy.sh` echo that TOTP-only flow. There is no method picker, no WebAuthn/FIDO2 path, and no documented alternative for operators who want a security key at first boot. Admin MFA must remain `arkfile-admin`-only (not the website). This must change before WebAuthn ships; see the arkfile-admin bootstrap section below.

**Test gaps.** Unit tests for TOTP crypto/lockout are good (`auth/totp_test.go`). JWT audience tests are good. Missing: HTTP integration tests for both backup-code paths (path A and path B); e2e coverage for both paths in `e2e-test.sh`; e2e admin MFA reset (feature absent); admin bootstrap MFA with a security key (feature absent).

**Monolith file.** Split `auth/totp.go` during migration into focused files (e.g. `auth/mfa_totp.go`, `auth/mfa_backup_codes.go`, shared lockout helpers) rather than carrying a 1,100-line file forward.

**WebAuthn credential state in encrypted blobs.** The WebAuthn `credential_data` payload is not write-once: it holds the public key plus a signature counter used for clone detection. Every successful authentication finish must decrypt the row, verify the assertion (including monotonic signCount), bump the counter, re-encrypt, and UPDATE the row in the same per-user transaction as full-token issuance -- the same atomic pattern already used for backup-code consumption and TOTP window marking. Tier-3 rotation must round-trip WebAuthn blobs through the same decrypt/re-encrypt path as TOTP secrets; a failed mid-run must leave the old master in place. `mfa_usage_log` remains TOTP window replay only; WebAuthn counters live inside `credential_data`, not in a separate usage table.

## Backup code login paths (decided)

Arkfile supports two self-service backup-code flows. Both remain in the product after the MFA rename. Each consumes one single-use backup code. Both work regardless of whether the enrolled second factor is TOTP or a hardware security key. Document both in `docs/user-faq.md` and expose both clearly in the MFA login UI and in `arkfile-client`.

**Path A — Emergency one-shot login.** After OPAQUE password login, the user enters a backup code on the second-factor screen and chooses sign-in only (no re-enrollment). API: `POST /api/mfa/auth` with `is_backup: true` (today `TOTPAuth`). The server validates and consumes the backup code, then issues a full access token. The enrolled second factor is unchanged. The user can access their account once but will need their normal second factor (or another backup code, or path B) on the next login. Use when the user still has their authenticator or security key elsewhere and merely needs temporary access, or when they are not ready to re-enroll yet.

**Path B — Re-enroll with a backup code.** After OPAQUE password login, the user chooses to set up a new second factor using a backup code (lost authenticator or security key). API: `POST /api/mfa/recover-with-backup-code` (consumes the code, issues a short-lived reset-tier JWT), then `POST /api/mfa/reset` (issues new enrollment material and a fresh set of ten backup codes). The user completes enrollment before gaining full access. Use when the normal second factor is lost or must be replaced.

**UI requirements.** The MFA login modal (and equivalent CLI prompts) must present both options with distinct labels so users do not confuse them. Suggested framing: sign in once with a backup code versus set up a new second factor with a backup code. Do not merge into a single undifferentiated backup-code field.

**Implementation notes.** Keep `MFAAuth` `is_backup` handling through the rename. Keep `RecoverWithBackupCode` + reset flow. Add browser UI for path A (path B exists today). Ensure `arkfile-client login` can use path A via `--backup-code` or an interactive prompt, and path B via existing recover/reset commands. Each path needs unit, integration, and e2e coverage.

## Recovery model (ordered)

Users should attempt self-service recovery before involving an admin. Document this in `docs/user-faq.md` and surface it in the MFA login UI.

First, if the user still intends to keep their current second factor but needs access now, use path A (emergency one-shot login with a backup code). They sign in once; their enrolled MFA is unchanged; they will need their normal second factor on the next login.

Second, if the user has lost their second factor or wants to replace it, use path B (re-enroll with a backup code). After OPAQUE login, they consume a backup code through the recover-and-reset flow, set up a new second factor immediately, and receive fresh backup codes.

Third, if backup codes are also lost, contact the instance admin using the admin contact details shown on the site. The admin verifies the requester's identity out-of-band. The recommended verification method is matching the request against contact methods the user previously saved under Contact Info (encrypted, admin-readable). Contact Info remains optional for normal usage but is strongly recommended before anyone relies on admin-assisted MFA reset.

Fourth, the admin runs a **full** MFA reset: `arkfile-admin reset-user-mfa --username USER --confirm`. This clears all MFA credentials and backup codes, force-logouts all sessions, and leaves the account in `requires_mfa_setup` state. The user logs in with their password and completes MFA enrollment again. Admin reset is for **total lockout** (all factors and backup codes gone). It is not the normal path when the user still has another enrolled factor or usable backup codes — those cases are steps one and two above.

Lost password means lost files. Lost second factor and lost backup codes means the account cannot be recovered without admin intervention, and admin intervention is only appropriate when identity (that the person requesting reset actually owns the account) can be established out-of-band.

## Tor Browser

Tor Browser is a primary supported browser for Arkfile. TOTP authentication must continue to work fully in Tor Browser.

Tor Browser disables WebAuthn and FIDO2 by default as a documented known issue, to reduce fingerprinting. Hardware security key login via the web application will not work in stock Tor Browser. Users who rely on Tor Browser should choose TOTP at enrollment, or use `arkfile-client` with a USB-connected security key for hardware-based second factor (the CLI uses direct CTAP2/HID and does not depend on browser WebAuthn).

The enrollment UI and user FAQ must state this clearly. Do not enable or require `about:config` WebAuthn overrides for Tor users.

## Schema migration (greenfield)

Replace `user_totp`, `user_totp_backup_codes`, `totp_usage_log`, and `totp_backup_usage` with:

```
user_mfa_credentials: one row per user in v1 (username PRIMARY KEY). Columns include method_type (totp or webauthn), optional label, credential_data (method-specific encrypted payload), enabled, setup_completed, timestamps, and lockout counters migrated from user_totp.

user_mfa_backup_codes: unchanged semantics, hashed single-use codes (rename from user_totp_backup_codes).

mfa_usage_log: replay protection for TOTP windows (rename from totp_usage_log).

mfa_backup_usage: backup code usage / replay log (rename from totp_backup_usage).
```

Also update the `user_auth_status` view to join `user_mfa_credentials` instead of `user_totp` (columns e.g. `has_mfa`, `mfa_enabled`, `mfa_setup_completed`).

Drop old tables entirely. No compatibility views. Update all Go packages (`auth`, `handlers`, crypto key purposes), TypeScript frontend, `arkfile-client`, `arkfile-admin`, `unified_schema.sql`, dev-reset path, `e2e-test.sh`, `e2e-playwright`, `docs/api.md`, `docs/security.md`, `scripts/maintenance/rotate-user-secret-master.sh`, `monitoring/key_health.go` if it references TOTP key types. Phase 1 rename is a repo-wide sweep, not only tables and core handlers: route group names and comments (`totpProtectedGroup`, `pendingAllowedGroup`), middleware and security-event strings, JSON response fields (`requires_totp` → `requires_mfa`), CLI commands and help text (`setup-totp`, `generate-totp`), deploy-script echoes, e2e helpers (`wait_for_totp_window`, Playwright TOTP selectors), `monitoring/key_health.go` audience labels, and `handlers/export.go` claim checks. Live source should retain no TOTP-specific identifiers except the dev-only fixed secret in `auth/dev_admin.go` and prose in end-user docs where "TOTP" names the method type.

Rename JWT/API concepts: `requires_totp` becomes `requires_mfa`, `requires_totp_setup` becomes `requires_mfa_setup`, `RequireTOTP` middleware becomes `RequireMFA`, route group `/api/totp` becomes `/api/mfa`. JWT audiences may become `arkfile-mfa`, `arkfile-mfa-reset` (rename from `arkfile-totp` / `arkfile-totp-reset`) for consistency — update all validators, cookies flow, and clients together.

Rename Tier-3 HKDF purpose from `totp_user` to `mfa_user` in `crypto/totp_keys.go` (rename file to e.g. `crypto/mfa_keys.go`, function `DeriveMFAUserKey`). Greenfield redeploy of test.arkfile.net; no in-place ciphertext migration needed for purpose rename if DB is wiped on redeploy.

## File touch inventory (approximate)

| Area | Primary files |
|------|----------------|
| Schema | `database/unified_schema.sql` |
| Core MFA logic | `auth/totp.go` → split into `auth/mfa_*.go`, `auth/totp_test.go`, `auth/totp_backup_test.go` |
| JWT / middleware | `auth/jwt.go`, `auth/jwt_test.go`, `auth/keys.go`, `auth/token_revocation*.go`, `handlers/middleware.go`, `handlers/route_config.go` |
| HTTP handlers | `handlers/auth.go`, `handlers/auth_test.go`, `handlers/admin.go`, `handlers/bootstrap.go`, `handlers/admin_auth.go`, `handlers/export.go`, `handlers/rate_limiting.go`, `handlers/files.go` |
| Crypto | `crypto/totp_keys.go` → `crypto/mfa_keys.go`, `crypto/user_secret_master.go` |
| CLI | `cmd/arkfile-client/main.go`, `cmd/arkfile-client/commands.go`, `cmd/arkfile-admin/main.go` |
| Deploy runbooks | `scripts/local-deploy.sh`, `scripts/test-deploy.sh`, `scripts/prod-deploy.sh` (post-bootstrap MFA echoes) |
| Browser | `client/static/js/src/auth/{totp,totp-setup,login,register}.ts`, `app.ts`, `utils/auth.ts`, `ui/sections.ts`, `files/list.ts`, `types/api.d.ts`, `index.html` |
| Ops | `scripts/maintenance/rotate-user-secret-master.sh`, `scripts/testing/e2e-test.sh`, `scripts/testing/e2e-playwright.ts`, `scripts/testing/totp-generator.go` |
| Startup | `main.go`, `auth/dev_admin.go` |
| Docs | `docs/api.md`, `docs/security.md`, `docs/user-faq.md` |
| New (later) | `auth/mfa_webauthn.go`, browser WebAuthn module, shared FIDO2/CTAP2 code used by `arkfile-client` and `arkfile-admin` |

## Server implementation

Use `github.com/go-webauthn/webauthn` for server-side WebAuthn ceremony handling and credential verification. TOTP logic moves into `auth/mfa_totp.go` operating on `user_mfa_credentials` rows where `method_type` is `totp`.

WebAuthn registration and authentication use the standard two-step begin/finish pattern. Relying party ID is the site domain. Use non-discoverable credentials (no resident passkeys required). `authenticatorAttachment` `cross-platform` for USB/NFC keys. `userVerification` `preferred` (touch-first; PIN only when the key policy requires it).

Define the WebAuthn encrypted payload schema explicitly before Phase 6: at minimum credential ID, COSE public key, and signCount (plus any fields `go-webauthn` requires for verification). Registration finish writes the initial blob once; authentication finish is always read-modify-write. Document this schema in `docs/security.md` so rotation and future multi-credential work (Phase 9) do not guess at field layout.

Shared lockout and rate-limiting must sit above method-specific code from Phase 1 onward. Extract the existing per-user failure counters and lockout helpers from `auth/totp.go` into shared MFA modules (e.g. `auth/mfa_lockout.go`) and route all auth failure paths through them: TOTP verify, WebAuthn finish, backup-code validation (including path A `is_backup`), and wrong-code attempts during enrollment. Counters stay on `user_mfa_credentials`; a user locked out after TOTP failures must remain locked out if they switch clients or attempt WebAuthn or backup codes until the lockout expires. Wrong backup codes increment the same counter; successful path A or path B clearing behavior must match today's TOTP semantics.

Backup code generation, hashing (Argon2id per code), validation, and both backup-code login paths are method-agnostic. Rename endpoints: `POST /api/mfa/auth` (includes `is_backup: true` for path A), `POST /api/mfa/recover-with-backup-code`, and `POST /api/mfa/reset` (path B).

Admin reset (`POST /api/admin/users/:username/reset-mfa`) must call existing force-logout / token revocation and log a security event. Do not use `ResetTOTP` (which UPDATEs an existing row and re-issues TOTP secrets). See **Full vs credential-scoped reset** below — v1 implements full reset only; shape the handler and request body so an optional `credential_id` (or label) can be added in Phase 9 without a breaking API change.

## Browser client (TypeScript)

Use `@simplewebauthn/browser` (or equivalent) for WebAuthn ceremonies. Enrollment: after registration OPAQUE, end users choose TOTP or Security Key. Security key path calls begin/finish registration endpoints. Login: after OPAQUE, begin/finish authentication with the key. The browser MFA UI is for ordinary user accounts only; admin bootstrap and admin MFA setup are out of scope for the web client (see arkfile-admin bootstrap section).

MFA login UI must expose both backup-code paths (path A one-shot sign-in and path B re-enroll). Path B UI exists today; add path A during Phase 2. Update all labels from TOTP-specific wording to generic MFA wording.

Add persistent Contact / Contact Admin affordance on homepage and all logged-in pages (see UI section below).

Use only strictly typed TypeScript in new/modified code and dependencies as much as possible.

## arkfile-client (Go CLI) parity

Hardware key support in `arkfile-client` is equal priority to the browser. The CLI must support the same enrollment and login ceremonies via the same API endpoints. Implement a FIDO2 client using direct USB HID CTAP2. Candidate library: `github.com/mohammadv184/go-fido2` (CGO-free, aligns with static builds); evaluate in depth before landing on this library (is it secure, trusted, used in at least 3 other significant open source projects, etc.). Evaluate `keys-pub/go-libfido2` if system `libfido2` is acceptable on target platforms.

Commands: `setup-mfa` (interactive, choose `totp` or `security key`), `login` (existing flow extended with security key auth step and path A backup login via `is_backup: true`). Path B remains `recover-mfa` (rename from `recover-totp`). Add path A to `login` if not present today (interactive or `--backup-code` flag at MFA step). Share the evaluated FIDO2 library and ceremony helpers with `arkfile-admin` so both CLIs use the same CTAP2 stack.

## arkfile-admin: bootstrap MFA setup

The entire admin lifecycle is server-side CLI only. Account creation (`arkfile-admin bootstrap` with the bootstrap token), MFA enrollment (`setup-mfa` after bootstrap), authentication (`login`), and every privileged command thereafter run through `arkfile-admin` on the instance host. The website is not an admin console and must not be documented or implemented as a fallback for bootstrap MFA. This is a hard acceptance criterion for shipping WebAuthn, not an optional parity stretch goal.

`arkfile-admin setup-mfa` must grow an interactive method picker and a security-key branch that drives the same begin/finish registration API as the browser uses for end users. `arkfile-admin login` must complete the matching authentication ceremony when the enrolled method is `webauthn`, including path A backup login where applicable. Reuse the FIDO2 library chosen for `arkfile-client` (direct USB HID CTAP2; no browser WebAuthn dependency) in a small shared package or internal module so static builds and security review happen once. Emit backup codes from the setup response the same way as `arkfile-client` automation (`BACKUP_CODE_*` when `--show-secret` or equivalent is inappropriate for WebAuthn-only flows). Because CTAP2 runs on the machine where `arkfile-admin` executes, the security key must be reachable from that host — typically plugged into the server or forwarded to it, not into the operator's desktop browser.

Deploy runbooks must stop implying TOTP-only admin setup. Replace "Setup TOTP" echoes with generic MFA wording and document both methods. Fix stale identifiers while touching these files (`verify-login` in `local-deploy.sh` should be `login`; `etc/keys/totp` chmod lines are legacy path names). Hardware-key bootstrap is most practical on **`local-deploy.sh`**: the operator typically runs deploy and `arkfile-admin` on the same machine that has the USB port, so `setup-mfa` with a plugged-in key is the primary documented path for local instances.

**Remote VPS deploys (`test-deploy.sh`, `prod-deploy.sh`).** Operators usually SSH into a headless VPS. USB security keys are attached to the operator's workstation, not the remote host, so `arkfile-admin setup-mfa` on the VPS cannot see the key unless the operator deliberately forwards USB to the server (USB/IP, `usbip`, serial console with local KVM, etc.). Whether that works is environment-specific and should not be assumed in the default runbook. For test/prod, treat **TOTP via `arkfile-admin setup-mfa` on the VPS** as the default practical path. When a security-key-first admin is required on a remote instance, document only CLI-viable options: deploy on hardware the operator physically controls (`local-deploy.sh` or equivalent, key on that host), attach the key directly to the VPS if it has a USB port and the operator has physical or out-of-band console access, or use advanced USB forwarding to the VPS with an explicit warning that this is operator-managed and untested as a universal procedure. Do not document browser-based admin MFA setup as an alternative — it violates the admin model. Shipping WebAuthn does not require solving universal SSH USB passthrough; it does require that `arkfile-admin` supports both methods wherever the key is reachable from the server host.

## arkfile-admin: reset-user-mfa

New command: `arkfile-admin reset-user-mfa --username USER --confirm`.

Calls `POST /api/admin/users/:username/reset-mfa`. Before reset, display user contact info if present (reuse `user-contact-info` API). If no contact info on file, require `--acknowledge-no-contact-info` flag.

Operator runbook: verify requester identity against saved contact methods when possible; only then run reset; instruct user to log in and re-enroll.

Admin MFA reset must not clear user contact info.

### Full vs credential-scoped reset

Two distinct operations; v1 (one method per user) implements **full reset** only.

**Full reset (default, Phase 5).** For total lockout: user has lost all enrolled factors and all backup codes. DELETE all rows in `user_mfa_credentials`, `user_mfa_backup_codes`, and MFA usage logs for the user; force-logout all sessions; account enters `requires_mfa_setup`. In v1 this is the only credential row anyway.

**Credential-scoped reset (Phase 9, multi-method).** For removing one stale enrollment while others remain — e.g. retire a lost YubiKey when the user still has TOTP or another key, but cannot log in to remove it themselves. DELETE one credential row (and any usage data tied to that credential). **Keep** account-level backup codes if at least one completed credential remains. Still force-logout (MFA configuration changed). If the delete leaves zero credentials, escalate to full-reset semantics (clear backup codes, `requires_mfa_setup`).

**Identifying the credential.** Full reset needs no method detail. Credential-scoped reset requires agreement on **which enrollment** — not `method_type` alone (a user may have two security keys). Use `credential_id` (UUID once schema allows multiple rows per user) or the user's private **label** ("Travel Nitrokey"). Admin CLI should list non-secret metadata first (`method_type`, label, enrolled date); user and admin confirm the same label out-of-band.

**Self-service first.** Users with multiple factors who lose one should use another factor or backup codes (paths A/B); admin reset remains the last resort for total lockout or exceptional credential removal.

## Tier-3 user-secret-master rotation (full implementation)

Today `scripts/maintenance/rotate-user-secret-master.sh` only:

1. Backs up `/opt/arkfile/etc/keys/user-secret-master.bin`
2. Generates a new 32-byte master
3. Atomically replaces the file
4. Prints a reminder to restart the server

It does not touch the database. MFA credential blobs (`user_mfa_credentials.credential_data` for TOTP and WebAuthn) and contact info (`user_contact_info.encrypted_data`) are encrypted with keys derived from the master via HKDF purposes (`mfa_user`, `contact_info`). Rotating the master file without re-encrypting rows leaves all such data permanently undecryptable.

### Admin auth model (must not break)

Every privileged `arkfile-admin` operation today requires an authenticated admin session: OPAQUE login plus completed 2FA, then a full-tier JWT on each network API call. Tier-3 rotation follows that model.

The tension: re-encryption must run with the main Arkfile service **stopped** (no concurrent DB writes, no in-memory old master in the server), but with the service stopped the HTTP admin API is unavailable. Resolve this with a **two-phase command** on `arkfile-admin` only (no separate maintenance binary). Phase 1 authenticates while the server is up; phase 2 applies offline using a server-issued mandate that proves an admin with full MFA already authorized the run.

### Two-phase operator flow

**Step 1 — `prepare` (server running, normal admin auth)**

1. Admin runs `arkfile-admin login` (OPAQUE + 2FA) if session is missing or expired — same as any other admin command.
2. Admin runs `arkfile-admin rotate-user-secret-master prepare --confirm`.
3. This is a **network command** to a new admin API route (e.g. `POST /api/admin/system/prepare-user-secret-master-rotation`). Server validates full-tier admin JWT and completed MFA, same middleware stack as other admin routes.
4. Server returns a **single-use rotation mandate**: a signed blob bound to admin username, short TTL (e.g. 5–15 minutes), explicit purpose `user-secret-master-rotation`, and a nonce or server-side single-use flag so it cannot be replayed after `apply`. No DB or key-file changes in `prepare` — authorization only.
5. CLI writes the mandate to a path the operator chooses (stdout or `--mandate-file`).

**Step 2 — stop service**

6. Operator stops Arkfile (`systemctl stop arkfile` or equivalent). Confirm no concurrent writes.

**Step 3 — `apply` (server stopped, mandate-gated local work)**

7. Admin runs `arkfile-admin rotate-user-secret-master apply --mandate-file PATH --confirm`.
8. This command **does not use HTTP**. It verifies the mandate cryptographically offline (verify key from install layout — same trust boundary as `/opt/arkfile` today). Without a valid, unexpired, unused mandate, `apply` refuses to run.
9. `apply` performs pre-flight checks (DB path, master key file exist), backs up master key and DB, then:
   - Loads old master into memory for derivation only.
   - Generates new master (32 random bytes, `0400` permissions) to a temp path — do not install until re-encrypt succeeds.
   - Re-encrypts all Tier-3-wrapped rows (see below).
   - Atomically swaps `user-secret-master.bin`.
   - Runs verification pass.
10. Operator starts Arkfile.

`apply` is not an auth bypass: it is gated by a credential issued only after admin + 2FA on `prepare`. Re-prompting OPAQUE/TOTP at `apply` time is impractical while the server is down; the mandate is the correct proof-of-authorization for the offline phase.

Do **not** expose full rotation as a generic admin REST endpoint that mutates the DB while the server is running — that conflicts with both the stop-service requirement and clean locking.

`scripts/maintenance/rotate-user-secret-master.sh` may remain as an optional thin wrapper that prints the runbook steps (login → prepare → stop → apply → start) but the Go logic lives in `arkfile-admin` subcommands linked to the same `crypto` and DB packages as the server.

### Re-encryption scope

1. **MFA credentials:** For each row in `user_mfa_credentials` (TOTP and WebAuthn from day one): decrypt `credential_data` with `DeriveMFAUserKey(username)` under old master; re-encrypt with new master; UPDATE row in a per-user transaction.

2. **Contact info:** For each row in `user_contact_info`: decrypt `encrypted_data` with `contact_info` purpose subkey under old master; re-encrypt with new master; UPDATE row.

3. **Do not re-hash backup codes:** `user_mfa_backup_codes` stores Argon2id hashes of backup codes, not Tier-3-encrypted plaintext. Rotation does not affect them.

### Failure handling, verification, and tests

- If re-encryption fails mid-run, do not install the new master file; restore from backup and abort. Per-user transactions with clear rollback semantics.
- After rotation, spot-check decrypt of at least one MFA row and one contact row (or run existing decrypt diagnostic) before declaring success.
- Unit tests with two known master keys and fixture rows proving round-trip decrypt/re-encrypt. Test mandate issue/verify and reject expired, replayed, or tampered mandates. Optional integration test tagged `rotation` on dev instances.
- Update `docs/security.md` with operator steps, downtime expectation, prepare/apply auth model, and affected tables.

Note: Purpose rename (`totp_user` → `mfa_user`) is a separate one-time migration handled by greenfield redeploy; the rotation tool assumes current purpose strings and must work for all Tier-3-wrapped columns going forward.

## Contact UI (sitewide)

Homepage: add persistent footer link Contact Admin showing `ARKFILE_ADMIN_CONTACT` from `GET /api/admin-contacts`.

Logged-in pages: keep Contact Info nav entry for user's encrypted contact details; ensure admin contact is also reachable without hunting (footer or nav).

Fix `/api/admin-contacts` response shape inconsistency between `handlers/files.go` and `client/static/js/src/files/list.ts` — pick one canonical JSON shape (recommend keeping flat `adminUsernames` + `adminContact` and fixing `list.ts`, or document a nested format if multiple admins with multiple contacts is needed later).

Pending-approval page already shows admin contact; keep that behavior.

MFA login modal: distinct controls for path A (sign in once) and path B (set up new second factor); short hint that admin contact is available if backup codes are exhausted.

## User FAQ (sitewide)

Homepage: add a persistent footer link 'FAQ' that includes all the Q&A in the `docs/user-faq.md` document in a format that matches our existing theme/styling/conventions/colors.

Logged-in pages: keep FAQ link available (footer is fine).

## Contact info and admin reset policy

Contact Info is optional. It cannot be a hard server-side gate on normal MFA usage or backup-code recovery.

For admin-assisted MFA reset, treat saved contact info as a soft prerequisite: document that users should save contact methods before requesting reset; admins should verify requests against those methods when present. CLI enforces explicit acknowledgment when no contact info exists.

## Testing plan

Unit tests: MFA credential CRUD, WebAuthn verify (mock), TOTP unchanged behavior on new tables, backup code recovery, lockout policy, admin reset, Tier-3 re-encrypt round-trip. Where relevant add unit tests in Go and TypeScript.

Add a cross-method lockout integration matrix, not only per-method unit tests: consecutive TOTP failures then WebAuthn attempt (still locked); consecutive WebAuthn failures; wrong backup codes on path A and path B (counter increments, no token); lockout expiry then successful normal login; path A success leaves enrolled MFA unchanged; path B success issues new backup codes. Cover these in HTTP integration tests and at least one `e2e-test.sh` subsection after Phase 2 (backup paths) and again after Phase 6/7 when WebAuthn is live.

HTTP integration tests: path A (`/api/mfa/auth` with `is_backup: true` issues full token, MFA unchanged); path B (recover-with-backup-code → reset-tier JWT → `/api/mfa/reset` returns new setup material; covers middleware fix).

`e2e-test.sh`: MFA path on renamed endpoints; path A emergency backup login; path B full backup-code re-enrollment (recover + reset + login with new second factor); admin `reset-user-mfa` flow; `arkfile-client` path A and path B.

Hardware integration tests (manual or tagged integration): YubiKey 5, Nitrokey 3C, Firefox, Chromium, `arkfile-client` and `arkfile-admin` on Linux. Include at least one manual or tagged run of the post-bootstrap admin flow: `bootstrap` → `setup-mfa` with a security key → `login`, mirroring `local-deploy.sh` step 3. Tor Browser: TOTP login e2e; confirm WebAuthn unavailable message or graceful fallback when user enrolled with HW key.

Playwright: update MFA selectors and contact UI visibility on homepage and logged-in views; FAQ footer link.

Tier-3 rotation: unit test re-encrypt loop and mandate issue/verify/reject; manual runbook test (login → prepare → stop → apply → start) on dev instance before relying on procedure in production.

## Documentation deliverables

`docs/user-faq.md`: Q&A only; all answers plain paragraphs; no special formatting; no emojis. Cover recovery order, both backup-code paths (one-shot login and re-enrollment), admin reset, Tor + TOTP vs HW key, optional contact info, CLI vs browser.

`docs/security.md` and `docs/api.md`: update for unified MFA model, renamed endpoints, JWT audiences, Tier-3 rotation procedure, and admin bootstrap MFA via `arkfile-admin` only (local vs remote VPS, TOTP default on headless VPS).

Deploy runbook echoes in `scripts/local-deploy.sh`, `scripts/test-deploy.sh`, and `scripts/prod-deploy.sh`: MFA method choice at bootstrap, backup-code reminder, and remote-VPS notes per the arkfile-admin bootstrap section.

`client/static/index.html` feature card: update Mandatory 2FA copy to mention TOTP or security key.

## Phased implementation order

Use whole phase numbers only. Each phase should leave tests green before starting the next. Developer will run dev-reset.sh and e2e test suites at his discretion during or between phases.

**Phase 1: COMPLETE** Schema migration and mechanical rename. Introduce `user_mfa_credentials`, `user_mfa_backup_codes`, `mfa_usage_log`, `mfa_backup_usage`; drop old TOTP tables; update `user_auth_status` view. Rename routes `/api/totp` → `/api/mfa`, middleware `RequireTOTP` → `RequireMFA`, JWT claims `requires_mfa` / `requires_mfa_setup`, audiences as chosen. Update Go handlers, both CLIs, TypeScript clients, e2e scripts, and docs references, including exhaustive TOTP identifier sweep per Schema migration. TOTP-only behavior preserved; all existing unit tests adapted and passing.

**Phase 2: COMPLETE** Fix reset-tier JWT routing. Add `ResetJWTMiddleware` (or equivalent) so `/api/mfa/reset` accepts `arkfile-mfa-reset` tokens. Add browser UI for path A (emergency one-shot backup login) alongside existing path B re-enroll UI. HTTP integration tests and e2e for both path A and path B. Verify `arkfile-client` supports both paths end-to-end.

**Phase 3: COMPLETE** Codebase cleanup and crypto rename. Removed `InitializeTOTPMasterKey`, `GetTOTPMasterKeyStatus`, and unused `totpMasterKey` state. Renamed `totp_user` → `mfa_user`, `DeriveTOTPUserKey` → `DeriveMFAUserKey`, `crypto/totp_keys.go` → `crypto/mfa_keys.go`. Split `auth/totp.go` into `auth/mfa_*.go` with shared lockout helpers. `MFAAuth` `is_backup` retained for path A. Updated `docs/security.md` for `mfa_user` purpose and both backup-code paths. **Requires `dev-reset.sh` after deploy** — existing MFA ciphertext encrypted under `totp_user` will not decrypt under `mfa_user`.

**Phase 4: COMPLETE** Tier-3 master rotation with full DB re-encrypt. Added `arkfile-admin rotate-user-secret-master prepare|apply` and `POST /api/admin/system/prepare-user-secret-master-rotation`. Mandate-gated offline apply re-encrypts `user_mfa_credentials` and `user_contact_info`, atomically swaps `user-secret-master.bin`, and verifies sample decrypts. **Deleted** unsafe key-only `rotate-user-secret-master.sh` body, dead `arkfile-admin key-rotation` stub, and stale `rotate-jwt-keys.sh`. Removed legacy `etc/keys/jwt/` scaffolding from deploy scripts. JWT keys remain in KeyManager (`system_keys`); automated JWT rotation is future work.

**Phase 5: COMPLETE** Admin MFA reset — **full reset only** (v1 has one credential per user). `POST /api/admin/users/:username/reset-mfa` and `arkfile-admin reset-user-mfa --username USER --confirm`: delete all credentials, backup codes, usage logs; force-logout; audit log; contact-info display and `--acknowledge-no-contact-info` when empty. API/CLI accept optional future `credential_id` / `--credential-id` / `--label` (v1 returns 400 if set). Handler, auth, and integration tests; e2e fused into admin `reset-user-mfa` + payments re-enrollment (no extra user login/logout cycles).

**Phase 6:** WebAuthn server and browser client (end users only). `go-webauthn/webauthn` registration/auth begin/finish endpoints; implement WebAuthn `credential_data` read-modify-write and signCount verification; enrollment UI method picker (TOTP or security key, one method only); backup codes on both paths; Tor warning in UI; `@simplewebauthn/browser` integration.

**Phase 7:** CLI FIDO2 parity for `arkfile-client` and `arkfile-admin`. Library evaluation (`go-fido2` vs `go-libfido2`); shared CTAP2 helpers; `setup-mfa` method picker and security-key enrollment; extend `login` for security-key auth and path A backup login; same API endpoints as browser. Update deploy runbook echoes — primarily `local-deploy.sh` for hardware-key bootstrap on the deploy host; `test-deploy.sh` and `prod-deploy.sh` document TOTP-on-VPS as the default remote path and note USB-to-server constraints for security keys. Do not ship Phase 6 without Phase 7 admin `setup-mfa`/`login` parity, or operators on local deploys would still be forced to TOTP at bootstrap.

**Phase 8:** Sitewide Contact Admin + FAQ footer; fix admin-contacts API consumption in `list.ts`; MFA login recovery hint; publish FAQ page from `docs/user-faq.md`; update homepage feature card.

**Phase 9 (future):** Multi-method enrollment up to three credentials per account with private device labels. Schema: `credential_id` primary key, multiple rows per username. Add credential-scoped admin reset (`--credential-id` or `--label`), admin credential listing endpoint, and logged-in user self-service remove for own credentials. Backup codes remain account-level.

## Other notes

- Aim to support NFC as well as USB for HW keys where applicable.
- `auth/dev_admin.go` fixed dev TOTP secret remains dev-only; keep working through renames.
- Review `monitoring/key_health.go` for stale TOTP key type references during Phase 1.
- CSP in `handlers/middleware.go` — verify no change needed for WebAuthn (`navigator.credentials`); recheck if adding inline scripts for FAQ page.
- `pendingAllowedGroup` requires completed MFA before contact-info APIs; consistent with registration flow (MFA before approval).

## Greenfield and clean codebase concerns

Throughout this project please keep in mind the greenfield nature of this app. We will completely redeploy the one test/beta instance at test.arkfile.net after this project. Codebase should end up cleaner and more coherent than when we started. Respect these requirements around function review sanity checks and naming throughout the refactor:

- Do not name functions or variables or include in comments references to temporary or ephemeral WIP planning document "IDs" or "Phases" or "Sections" or "Tiers". Use concise but descriptive terminology that does not require a lookup in other planning documents or glossaries or archive or WIP markdown files of any kind. If you find any names for variables or functions that are inexplicable in-situ, such as "runC06Cleanup" or "phase-b" or the like, immediately flag to the dev, remediate and rename these. Same goes for code comments.
- Treat the MFA rename as complete only when a repo search for `totp`, `TOTP`, `requires_totp`, and `arkfile-totp` in non-WIP, non-vendor paths returns only intentional references (dev admin seed, user-facing "TOTP app" wording in FAQ, method_type value `totp` in schema/API).
- As you are implementing, updating or reviewing existing functions, go through the following mental checklist: Is this function required? Is it implemented in a standard and secure way? Is it merely a stub function or otherwise incomplete? Is it well placed, in the right file or area of the app? Is it reachable and currently in use, or could it be deleted? Does it require additional review, updates, moving or potentially deletion? Does it align with the vision and intended design of the app as being privacy-preserving for users end-to-end?
