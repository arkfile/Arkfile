# Better MFA: Hardware Security Keys, Unified Credentials, and Recovery

This document plans the Multi-Factor Authentication enhancement for Arkfile: hardware security key support (YubiKey, Nitrokey 3), a greenfield migration from the TOTP-specific tables to a unified MFA credential model, admin-assisted recovery, CLI parity with the browser, Tor Browser considerations, and supporting user documentation.

## Goals

Arkfile currently requires TOTP as the sole second factor. This project adds FIDO2/WebAuthn hardware security keys as an alternative second factor (user picks one at enrollment in the first release), preserves backup codes as the primary self-service recovery path for all MFA types, adds an admin CLI command to reset a user's MFA, improves sitewide visibility of contact/admin-contact affordances, and achieves functional equivalence between the TypeScript browser client and the `arkfile-client` Go CLI for MFA enrollment and login.

## Non-goals (first release)

Multi-method enrollment (more than one second factor per account) is deferred. The long-term cap of three total methods remains the target architecture, but the first release enforces exactly one method per user: either TOTP or a hardware security key. Passkey/platform authenticators (Touch ID, Windows Hello as primary factor) are out of scope. Email-based recovery remains out of scope. Password reset remains out of scope.

## Recovery model (ordered)

Users should attempt recovery in this order. Document this in `docs/user-faq.md` and surface it in the MFA login UI.

First, use a backup code. After OPAQUE password login, choose the backup-code path on the second-factor screen. A valid backup code issues a short-lived reset session and immediately re-enrolls MFA with a new secret or key and fresh backup codes. This works identically whether the user's normal second factor is TOTP or a hardware security key. Backup codes are account-level recovery credentials, not tied to TOTP.

Second, if backup codes are lost, contact the instance admin using the admin contact details shown on the site. The admin verifies the requester's identity out-of-band. The recommended verification method is matching the request against contact methods the user previously saved under Contact Info (encrypted, admin-readable). Contact Info remains optional for normal usage but is strongly recommended before anyone relies on admin-assisted MFA reset.

Third, the admin runs `arkfile-admin reset-user-mfa --username USER --confirm`. This clears MFA credentials and backup codes, force-logouts all sessions, and leaves the account in `requires_mfa_setup` state. The user logs in with their password and completes MFA enrollment again.

Lost password means lost files. Lost second factor and lost backup codes means the account cannot be recovered without admin intervention, and admin intervention is only appropriate when identity (that the person requesting reset actually owns the account) can be established out-of-band.

## Tor Browser

Tor Browser is a primary supported browser for Arkfile. TOTP authentication must continue to work fully in Tor Browser.

Tor Browser disables WebAuthn and FIDO2 by default as a documented known issue, to reduce fingerprinting. Hardware security key login via the web application will not work in stock Tor Browser. Users who rely on Tor Browser should choose TOTP at enrollment, or use `arkfile-client` with a USB-connected security key for hardware-based second factor (the CLI uses direct CTAP2/HID and does not depend on browser WebAuthn).

The enrollment UI and user FAQ must state this clearly. Do not enable or require `about:config` WebAuthn overrides for Tor users.

## Schema migration (greenfield)

Replace `user_totp`, `user_totp_backup_codes`, `totp_usage_log`, and `totp_backup_usage` with:

```
user_mfa_credentials: one row per user in v1 (username PRIMARY KEY). Columns include method_type (totp or webauthn), optional label, credential_data (method-specific encrypted payload), enabled, setup_completed, timestamps, and lockout counters migrated from user_totp.

user_mfa_backup_codes: unchanged semantics, hashed single-use codes.

mfa_usage_log: replay protection for TOTP windows (and any shared rate-limit state as needed).
```

Drop old tables entirely. No compatibility views. Update all Go packages (`auth`, `handlers`, crypto key purposes if renamed), TypeScript frontend, `arkfile-client`, `arkfile-admin`, `unified_schema.sql`, dev-reset path, `e2e-test.sh`, `e2e-playwright`, `docs/api.md`, `docs/security.md`.

Rename JWT/API concepts: `requires_totp` becomes `requires_mfa`, `requires_totp_setup` becomes `requires_mfa_setup`, `RequireTOTP` middleware becomes `RequireMFA`, route group `/api/totp` becomes `/api/mfa`.

## Server implementation

Use `github.com/go-webauthn/webauthn` for server-side WebAuthn ceremony handling and credential verification. TOTP logic moves into `auth/mfa_totp.go` (or similar) operating on `user_mfa_credentials` rows where `method_type` is `totp`.

WebAuthn registration and authentication use the standard two-step begin/finish pattern. Relying party ID is the site domain. Use non-discoverable credentials (no resident passkeys required). `authenticatorAttachment` `cross-platform` for USB/NFC keys. `userVerification` `preferred` (touch-first; PIN only when the key policy requires it).

Backup code generation, hashing (Argon2id per code), validation, and recover-with-backup-code flow are method-agnostic. Rename endpoints to `/api/mfa/recover-with-backup-code` and `/api/mfa/reset`.

## Browser client (TypeScript)

Use `@simplewebauthn/browser` (or equivalent) for WebAuthn ceremonies. Enrollment: after registration OPAQUE, user chooses TOTP or Security Key. Security key path calls begin/finish registration endpoints. Login: after OPAQUE, begin/finish authentication with the key.

Preserve existing backup-code recovery UI; update labels from TOTP-specific wording to generic MFA wording.

Add persistent Contact / Contact Admin affordance on homepage and all logged-in pages (see UI section below).

Use only stricly typed TypeScript in new/modified code and dependencies as much as possible.

## arkfile-client (Go CLI) parity

Hardware key support in `arkfile-client` is equal priority to the browser. The CLI must support the same enrollment and login ceremonies via the same API endpoints. Implement a FIDO2 client using direct USB HID CTAP2. Candidate library: `github.com/mohammadv184/go-fido2` (CGO-free, aligns with static builds); evaluate in depth before landing on this library (is it secure, trusted, used in at least 3 other significant open source projects, etc.). Evaluate `keys-pub/go-libfido2` if system `libfido2` is acceptable on target platforms.

Commands: `setup-mfa` (interactive, choose `totp` or `security key`), `login` (existing flow extended with security key auth step). Mirror `arkfile-admin setup-totp` patterns for MFA setup.

## arkfile-admin: reset-user-mfa

New command: `arkfile-admin reset-user-mfa --username USER --confirm`.

Calls `POST /api/admin/users/:username/reset-mfa`. Clears `user_mfa_credentials`, backup codes, usage logs; force-logouts user; logs security event.

Before reset, display user contact info if present (reuse `user-contact-info` API). If no contact info on file, require `--acknowledge-no-contact-info` flag.

Operator runbook: verify requester identity against saved contact methods when possible; only then run reset; instruct user to log in and re-enroll.

## Contact UI (sitewide)

Homepage: add persistent footer link Contact Admin showing `ARKFILE_ADMIN_CONTACT` from `GET /api/admin-contacts`.

Logged-in pages: keep Contact Info nav entry for user's encrypted contact details; ensure admin contact is also reachable without hunting (footer or nav).

Fix `/api/admin-contacts` response shape inconsistency between `handlers/files.go` and `client/static/js/src/files/list.ts`.

Pending-approval page already shows admin contact; keep that behavior.

MFA login modal: add short recovery hint (backup code first; then contact admin at ...).

## User FAQ (sitewide)

Homepage: add a persistent footer link 'FAQ' that includes all the Q&A in the user-faq.md document in a format that matches our existing theme/styling/conventions/colors.

Logged-in pages: keep FAQ link available (footer is fine)

## Contact info and admin reset policy

Contact Info is optional. It cannot be a hard server-side gate on normal MFA usage or backup-code recovery.

For admin-assisted MFA reset, treat saved contact info as a soft prerequisite: document that users should save contact methods before requesting reset; admins should verify requests against those methods when present. CLI enforces explicit acknowledgment when no contact info exists.

## Testing plan

Unit tests: MFA credential CRUD, WebAuthn verify (mock), TOTP unchanged behavior on new tables, backup code recovery, lockout policy, admin reset. Where relevant add unit tests in Go and TypeScript.

`e2e-test.sh`: TOTP path on renamed endpoints; backup code recovery; admin `reset-user-mfa` flow; `arkfile-client login` with TOTP.

Hardware integration tests (manual or tagged integration): YubiKey 5, Nitrokey 3C, Firefox, Chromium, `arkfile-client` on Linux. Tor Browser: TOTP login e2e; confirm WebAuthn unavailable message or graceful fallback when user enrolled with HW key.

Playwright: update MFA selectors and contact UI visibility on homepage and logged-in views.

## Documentation deliverables

`docs/user-faq.md`: Q&A only; all answers plain paragraphs; no special formatting; no emojis. Cover recovery order, backup codes, admin reset, Tor + TOTP vs HW key, optional contact info, CLI vs browser.

`docs/security.md` and `docs/api.md`: update for unified MFA model and renamed endpoints.

`client/static/index.html` feature card: update Mandatory 2FA copy to mention TOTP or security key.

## Phased implementation order

Phase 1: Schema + rename (`user_mfa_credentials`, endpoint renames, middleware renames, all tests green with TOTP-only behavior preserved).

Phase 2: WebAuthn server + browser enrollment/login (one method choice). Backup codes on both paths.

Phase 3: `arkfile-client` FIDO2 parity + `setup-mfa` command.

Phase 4: `arkfile-admin reset-user-mfa` + contact UI sitewide + `user-faq.md`.

Phase 5 (future): multi-method up to three credentials, private labels per device.

## Other Notes

- Admin MFA reset should not clear user contact info.
- Aim to support NFC as well as USB for HW Keys where applicable.
- Rename Tier-3 crypto purpose key from `totp_user` to `mfa_user` and update docs/security.md accordingly. Greenfield upgrade.

# IMPORTANT: GREENFIELD & CLEAN CODEBASE CONCERNS

Throughout this project please keep in mind the greenfield nature of this app. We will completely redeploy the 1 test/beta instance we have atm at test.arkfile.net after this project. Codebase should end up cleaner and more coherent than when we started. Remember the instructions from AGENTS.md about function review sanity checks and naming:

- Do not name functions or variables or include in comments references to temporary or ephemeral WIP planning document "IDs" or "Phases" or "Sections" or "Tiers". Use concise but descriptive terminology that does not require a lookup in other planning documents or glossaries or archive or WIP markdown files of any kind. If you find any names for variables or functions that are inexplicable in-situ, such as "runC06Cleanup" or "phase-b" or the like, immediately flag to the dev, remediate and rename these. Same goes for code comments. 
- As you are implementing, updating or reviewing existing functions, go through the following mental checklist: Is this function required? Is it implemented in a standard and secure way? Is it merely a stub function or otherwise incomplete? Is it well placed, in the right file or area of the app? - Is it reachable and currently in use, or could it be deleted? Does it require additional review, updates, moving or potentially deletion? Does it align with the vision and intended design of the app as being privacy-preserving for users end-to-end?
