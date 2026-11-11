# Admin Access Tightening

## Status

The behavior in this document is implemented, including the 60-minute admin cap from `docs/wip/auto-logout.md`. Local `e2e-test.sh` passed the Go checks: an unmarked login is refused on admin routes, a marked admin token is refused on `/api/files`, and an admin request that carries `X-Arkfile-Peer` is refused. The code is deployed to `test.arkfile.net` and `arkfile.net`. On 2026-11-11 a check from outside both servers returned 404 for `/api/admin/system/health` and `/api/bootstrap/register/response`, and 200 for `/api/admin-contacts`. Sign in again on that machine; saved admin sessions from before the update are unmarked and stop working on admin routes. Do not run `arkfile-admin rotate-opaque-keys rotate` until that on-box login, including a flagged admin re-registration if one is needed, has been tried.

A flagged admin who tries the website or `arkfile-client` gets the same generic failure as any other bad login. Admin access comes only from the account's `is_admin` flag. `ADMIN_USERNAMES` remains a deployment check, including blocking the dev admin name in production. Caddy answers 404 for `/api/admin`, `/api/admin/*`, and `/api/bootstrap/*`. The Go server answers 403 when a request is not a direct local connection. The two open questions below are decided and implemented: a 15-minute idle limit inside the 60 minutes, and no hard stop for an export already streaming past that mark. The admin re-registration ceremony now has handler unit tests and an `e2e-test.sh` case; writing those tests found that the ceremony's admin and marked-token guard wrote its refusal but let the handler continue, which is fixed. See `docs/wip/finish-logout-admin-sec.md`.

## Goal

Admin endpoints and admin functionality must be reachable only through `arkfile-admin`, run directly on the server it administers, talking to the Go server over a direct local connection (the default `--server-url https://localhost:8443`). A login made through the web app or `arkfile-client`, including a login of an admin account, must never be usable on admin routes, and an `arkfile-admin` login must never be usable as a web app session or from any other machine.

## Findings

Before this code was deployed, `/api/admin/*` was reachable from the public internet through Caddy. That was confirmed on `test.arkfile.net`: an unauthenticated `curl` from outside the box to `/api/admin/system/health` returned `401` from the Go JWT middleware, so the request reached the admin route group. `test-update.sh` and `prod-update.sh` replaced that Caddyfile from the templates in this tree, and the same request now returns 404 on both deployments.

The localhost gate in `AdminMiddleware` used to check only the kernel-reported peer address. On a VPS the Go server listens on `127.0.0.1:8443` and Caddy reverse-proxies every public request over loopback, so that check alone let public traffic through. The four Caddyfile templates now refuse `/api/admin`, `/api/admin/*`, and `/api/bootstrap/*` with 404, and the Go server also requires a direct local connection with no proxy headers. `dev-reset.sh` still has no Caddy, so its tests talk to the Go server directly.

Admin logins are a separate kind of session. Only a login that starts at `/api/admin/login/*`, bootstrap, or the on-box admin re-registration is marked. A website or `arkfile-client` login of an admin account is unmarked and is refused on admin routes. A marked login receives no browser cookies.

On the client side the intent already holds. All admin functionality lives under `/api/admin/*` (plus the public admin login endpoints, the bootstrap endpoints, and the public read-only `/api/admin-contacts`). The web frontend never calls `/api/admin/*`, and `arkfile-client` never calls it either; the shared `ListUserCredentialsAdmin` helper in `cli/mfa/manage.go` is only used by `arkfile-admin`. The gap is entirely server and proxy side.

Three further problems from review are handled in this tree. `arkfile-admin logout` calls `/api/logout` before deleting the local session file. Admin access is the `is_admin` flag only, so the login check and `HasAdminPrivileges()` agree. A flagged admin re-registers only through `arkfile-admin` on the server. The website and `arkfile-client` do not get a special message, and they cannot replace an admin password record.

## Layer one: Caddy refuses admin and bootstrap paths

All four Caddyfile templates refuse `/api/admin`, `/api/admin/*`, and `/api/bootstrap/*` with a `404` before reverse-proxying. This reaches existing deployments through the normal update path: `scripts/setup/vps-update.sh`, used by both `prod-update.sh` and `test-update.sh`, regenerates `/etc/caddy/Caddyfile` from the template and runs `caddy validate` before restarting Caddy. `Caddyfile.local` is a reference file not used by `local-deploy.sh`, but it gets the same block so it does not mislead anyone who copies it.

## Layer two: the Go server requires a direct local connection

One middleware defines a direct local connection as a loopback kernel peer with none of the proxy headers present: `X-Arkfile-Peer`, `X-Forwarded-For`, `X-Real-IP`, and `Forwarded`. Caddy always sets `X-Arkfile-Peer` on every request it relays (overwriting any client value), so a request from outside the box cannot arrive without it. A local process that adds the header only blocks itself. The check is attached by route group rather than by path string, so unusual path forms that might slip past a proxy path matcher do not matter. It applies to the admin group, the dev-test admin group, the two `/api/admin/login/*` routes, the two `/api/bootstrap/register/*` routes, and the new admin re-registration routes. It replaces the bare `peerAddrIsLoopback` checks in `AdminMiddleware` and in the bootstrap handlers. Refusals use the existing JSON error shape with a 403.

## Layer three: admin logins are marked and confined

A login is marked as an admin login only when it starts at `/api/admin/login/*`, at the bootstrap registration, or at the admin re-registration ceremony. The temporary MFA token issued there carries a signed `login_kind` claim with the value `admin`. Temporary tokens are signed with the temp-tier key, so a client cannot add the claim. The mark is carried through every token derived from that login: the full access token issued after TOTP verify, after WebAuthn authentication, and after first MFA setup; the reset-tier token from `/api/mfa/recover-with-backup-code`; the new temporary MFA token that `MFAReset` issues; and the login's `session_families` row, which `/api/refresh` reads before reissuing a marked access token. Any token derived from an unmarked token stays unmarked, so the mark can never be gained after login. `refresh_tokens` continues to carry the family id but does not duplicate `login_kind`; the family row is the source of truth.

`AdminMiddleware` requires the mark in addition to its existing checks, and still checks admin privileges in the database on every request, so demoting an admin takes effect immediately. An unmarked token, such as one from a web app or `arkfile-client` login of an admin account, gets a 403 on every admin route.

A marked login is confined to admin work. It may use the admin group; the `/api/mfa/*` routes `arkfile-admin` uses to manage the admin's own second factor (`setup`, `verify`, `auth`, the WebAuthn register and auth routes, `recover-with-backup-code`, `reset`, the `credentials` list and per-credential routes, `credentials/totp/add`, `credentials/webauthn/register/*`, and `backup-codes/regenerate`); `/api/refresh`; and `/api/logout`. Every other authenticated route refuses a marked token with a 403, including files, uploads, shares, billing, subscriptions, contact info, credits, and `/api/auth/me`. Public routes that need no token, such as `/api/config/opaque`, are unaffected. The admin account can still use the web app or `arkfile-client` for its own files through a separate, unmarked login. The scope check uses the matched route template (`c.Path()`), not the raw URL.

A marked token of any tier (temporary MFA, reset, re-registration handoff, or full) is accepted only over a direct local connection, on every route it can reach, and a marked refresh token is accepted at `/api/refresh` only over a direct local connection. On a VPS the web app always comes through Caddy, so this closes the frontend completely, and a copied `arkfile-admin` session file is useless from any other machine.

A marked token is accepted only from the `Authorization` header, never from a cookie. `CookieTokenMiddleware` records in the request context when it injected a token from a cookie, and a marked token that arrived that way is refused. Marked logins are never given cookies: `completeMFALogin`, the MFA setup completion, `/api/refresh`, the bootstrap flow, and the admin re-registration ceremony return tokens only in the JSON body and set no session, refresh, CSRF, or temporary cookies for a marked login.

`arkfile-admin logout` calls `/api/logout` with the current session before deleting the local session file, and deletes the file whether or not that call succeeds.

All admin checks go through one helper so the admin login, the admin re-registration ceremony, `AdminMiddleware`, `RequireApproved`, and the refresh handler cannot drift apart again (see open questions on what that helper counts).

## Admin re-registration ceremony

An admin password record can only be re-created through `arkfile-admin` on the server. When an admin account's record is missing and the account is flagged, `AdminOpaqueAuthResponse` returns the same `409 account_requires_reregistration` response the normal login uses, with a marked re-registration handoff token delivered only in the JSON body (no cookie), the file count, the Account Key salt and KDF profile, and, when the admin account owns files, one Account-Key-encrypted filename verifier sample. When the account is an admin but is not flagged and has no record, it keeps today's fake-record behavior.

The ceremony runs on two new routes, `/api/admin/reregister/response` and `/api/admin/reregister/finalize`. Being under `/api/admin/`, Caddy refuses them, and the direct-local-connection middleware wraps them. They accept only a marked handoff token and share their internals with the existing `ReregisterResponse` and `ReregisterFinalize`: replace the single `opaque_user_data` row in place, clear the flag, and touch nothing else. The admin finalize issues a marked temporary MFA token, so the second factor ends in a marked admin login with no cookies. The existing `/api/opaque/reregister/*` routes refuse admin accounts even when presented with a valid handoff token.

`arkfile-admin login` handles the 409 by running the same client steps `arkfile-client` runs in `performReregistration`, including the password check before finalizing: when the account owns files, the entered password must decrypt the verifier sample before the record is replaced, so a mistyped password cannot be bound to an account whose files it would no longer open. The ceremony and its helpers (`performReregistration`, `verifyReregistrationPassword`, and `decryptMetadataField`, which currently lives in `cmd/arkfile-client/crypto_utils.go`) move into a shared `cli/` package using the requester pattern `cli/mfa` already uses, so both CLIs call one implementation.

A consequence of this decision, accepted: an admin who loses SSH access to the server cannot recover admin access through the web app.

## Existing data and rollout

All changes are additive. `session_families.login_kind` already exists from the initial idle-lifetime work. A missing value means an unmarked login. Existing access tokens carry no mark, so at the upgrade every saved `arkfile-admin` session stops working on admin routes and each admin runs `arkfile-admin login` once on each box. Existing unmarked family rows stay unmarked. No account, MFA, file, share, credit, or billing row is rewritten, and web app and `arkfile-client` sessions keep working on their normal routes.

Rollout is `test-update.sh` on the test VPS, the outside `curl` check (expect `404`), an on-box `arkfile-admin login` and a few read-only admin commands, then the same on production with `prod-update.sh`. Both update scripts regenerate `/etc/caddy/Caddyfile` from the template, which now contains the 404, then validate it and start Caddy. Rolling back through an update from an older checkout regenerates the older Caddyfile and restores the old binary, which ignores `login_kind`. That reopens admin routes on the public proxy until this code is deployed again.

## Testing

Unit tests cover the direct-local-connection middleware with a non-loopback peer and with each proxy header present; the mark carried through every token hop listed above, and never gained from an unmarked token; an unmarked full token refused on admin routes; a marked token refused on a non-admin route such as `/api/files`, refused when it arrives by cookie, and refused when any proxy header is present; marked logins receiving no cookies from MFA completion, setup completion, and refresh; `login_kind` preserved on the family across refresh-token rotation; the admin re-registration handlers, including refusal of an unmarked handoff token and refusal of admin accounts on the normal re-registration routes; and existing unmarked families remaining unmarked.

`e2e-test.sh` runs against `dev-reset.sh`, which has no Caddy, so it covers the Go layers directly. New cases: the dev admin signs in through the normal login with `arkfile-client` and `/api/admin/users` with that token returns 403; an admin request carrying an `X-Arkfile-Peer` header is refused while normal `arkfile-admin` calls succeed; the marked admin access token is refused on `/api/files`; `arkfile-admin logout` revokes the server-side refresh token, so presenting it afterward fails; and, late in the run or followed by a fresh admin login because flagging force-logs-out the account, the dev admin is flagged for re-registration, `arkfile-admin login` completes the admin ceremony and the resulting login works on admin routes, and the same flagged account cannot re-register through the normal login. The Caddy layer is verified by the outside `curl` check after `test-update.sh`.

## Admin session lifetime (implemented with the auto-logout work)

These decisions are now folded into `docs/wip/auto-logout.md`, which carries the implementation detail; this summary is kept here for context. A marked admin login never lasts longer than 60 minutes from `arkfile-admin login`, with no extension and no grace period. The one exception is an admin request that the server accepted before the 60-minute mark: it runs to completion (in practice this is `export-file` streaming one `.arkbackup`), and any request that starts after the mark is refused. Server-side storage copy tasks started by a short admin request keep running after the login ends; checking their status requires a fresh login. The refresh token row expires 60 minutes after the login started, and every marked access token's expiry is the earlier of the configured JWT lifetime and that same moment, so the token itself never outlives the login even with a long `JWT_TOKEN_LIFETIME_MINUTES`. The admin notice becomes "admin session ended 60 minutes after login, please login again". `e2e-test.sh` signs the admin in once in `run_platform_bootstrap_admin_login` and reuses that login for the rest of the run, so `admin_login_with_totp` must sign in again when it sees the session-ended code, or before each admin-heavy group, if a full run exceeds 60 minutes.

The other amendments agreed for `docs/wip/auto-logout.md` during the same review, also now folded in there: a throttled `last_transfer_request_at` on the family row so that a refresh shortly after the 24-hour mark does not end a transfer before its first chunk claims grace; grace ending through the quiet timeout rather than immediately after the final chunk or complete, with the grace target staying locked and retries of the final request allowed; a named `session_logged_out` error code for families ended by logout; an optional `family_id` on the dev-test session-shift endpoint; flagging the missing-`family_id` acceptance rule as debt for removal in a later release; a note that only user-started requests may count as activity; and a note on the single-process assumption, with conditional updates for claiming the grace target and ending a family. The auto-logout e2e case that revoked the admin's access token through `/api/revoke-token` now uses `arkfile-admin force-logout` against the admin itself instead, since a marked token cannot use `/api/revoke-token` under the scope above.

## Files to add

- `cli/reregistration/` (shared OPAQUE re-registration ceremony, password verifier check, and metadata decryption helper used by both CLIs), with unit tests
- Unit tests for the direct-local-connection middleware and the marked-login scope check, next to the existing middleware tests

## Files to modify

- `Caddyfile`, `Caddyfile.prod`, `Caddyfile.test`, `Caddyfile.local` (refuse `/api/admin`, `/api/admin/*`, `/api/bootstrap/*`)
- `handlers/middleware.go` (direct-local-connection middleware; `CookieTokenMiddleware` records cookie-sourced tokens; `AdminMiddleware` requires the mark and uses the shared admin check; `RequireApproved` uses the shared admin check; marked-login scope check)
- `handlers/route_config.go` (attach the direct-local middleware to the admin group, dev-test admin group, admin login, and bootstrap routes; register `/api/admin/reregister/*`; attach the marked-login scope check to the full-session stacks and the MFA group)
- `handlers/admin_auth.go` (flagged admin accounts get the marked 409 re-registration response; marked temporary MFA token; shared admin check)
- `handlers/bootstrap.go` (replace the bare loopback check; marked temporary MFA token; no cookies)
- `handlers/reregistration.go` (admin ceremony handlers sharing internals; normal ceremony refuses admin accounts; marked handoff and temporary tokens without cookies)
- `handlers/auth.go` (normal login handling of flagged admin accounts; `MFAReset` and `RecoverWithBackupCode` carry the mark; `RefreshToken` reads `login_kind` from the session family, enforces direct local connection for marked refresh tokens, and sets no cookies for them)
- `handlers/mfa_login_complete.go` (carry the mark onto the full token and refresh token; no cookies for marked logins)
- `handlers/mfa_webauthn.go` (pass the mark through WebAuthn completion)
- `handlers/cookies.go` (helpers to skip cookie issuance for marked logins)
- `auth/jwt.go` (`login_kind` claim on temporary, reset, re-registration, and full tokens; generator signatures take the login kind; marked tokens accepted only over a direct local connection and not from a cookie)
- The session-family model (`login_kind` written when the marked login completes and returned with refresh validation)
- `models/user.go` (single admin-privilege helper)
- `database/unified_schema.sql` and `main.go` only if the session-family schema or backfill needs an admin-specific adjustment; no duplicate `refresh_tokens.login_kind` column is added
- `auth/dev_admin.go` (refresh token lifecycle validation follows the new signatures)
- `cmd/arkfile-admin/auth_commands.go` (handle the 409 and run the shared re-registration ceremony against the admin routes; `logout` calls `/api/logout` first)
- `cmd/arkfile-admin/client.go` (requester wiring for the shared ceremony)
- `cmd/arkfile-client/reregistration.go` and `cmd/arkfile-client/crypto_utils.go` (use the shared package)
- Tests: `handlers/middleware_test.go`, `handlers/admin_audience_test.go`, `handlers/bootstrap_test.go`, `handlers/reregistration_test.go`, `handlers/admin_rotation_test.go`, `handlers/cookies_test.go`, `handlers/auth_test.go`, `auth/jwt_test.go`, `models/refresh_token_test.go`, `cmd/arkfile-admin/session_test.go`
- `scripts/testing/e2e-test.sh` (cases listed under Testing)
- `docs/security.md` (correct the localhost-gate description; document the three layers, marked admin logins, admin re-registration, and the server-side admin logout)
- `docs/api.md` (admin login and re-registration routes, the 403 cases, and that admin routes are not reachable through the public proxy)
- `docs/testing.md` (new e2e cases and the post-update `curl` check)
- `docs/setup.md` (admin access only on the box through `arkfile-admin`; one re-login after this update)
- `docs/wip/auto-logout.md` (fold in the admin 60-minute cap and the other agreed amendments)

## Decisions

A flagged admin who uses the website or `arkfile-client` gets the generic invalid-credentials failure. Those endpoints are public, and a message that names `arkfile-admin` would identify admin usernames. An admin who forgets and tries the website after a key rotation gets that same generic failure, then has to sign in on the server.

Admin access comes only from `is_admin`. Bootstrap sets that flag when it creates the admin account. `ADMIN_USERNAMES` does not grant admin access. It stays a deployment check, including blocking the dev admin name in production.

Caddy answers 404. The Go server answers 403. The Go refusal is only reachable from something already on the box or already past Caddy.

## Remaining open questions

Both are decided in `docs/wip/finish-logout-admin-sec.md`: a marked admin login ends after 15 minutes without an admin request, and an accepted admin export keeps streaming with no write deadline. The questions are kept below for context.

Should a marked admin login also have an idle limit inside the 60-minute cap, for example 15 or 30 minutes without an admin request? With only the absolute cap, a forgotten SSH session keeps a usable admin login for up to an hour.

Should an admin request that is already streaming past the 60-minute mark have any hard bound? The current decision is that an accepted request runs to completion, which for a multi-gigabyte `export-file` over a slow link could be hours. A server-side write deadline would bound it but could cut off a legitimate export.
