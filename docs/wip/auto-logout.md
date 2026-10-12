# Auto Logout

## Reasoning

A browser login left open overnight stays signed in. The access token lasts 30 minutes, and the page renews it every 25 minutes and again whenever the tab becomes visible. Each renewal reissues the refresh cookie for 7 days and inserts a new database refresh token that expires 14 days later (30 days on the original login). Nothing ends the login at the Account Key lock, which only wipes the in-browser key after 15 idle minutes or after the 1 to 4 hour cache the user picked. Filenames lock again, but the session can still delete files, revoke shares, and change MFA or account settings. The same refresh-token family is what `arkfile-client` and `arkfile-admin` receive after OPAQUE and MFA, so a cap that lived only in the browser would leave the other two logins, and any copied refresh token, unbounded.

## Limits

Two clocks apply to every full session, meaning every refresh-token family created at the end of MFA. Idle time is 6 hours since the last user action on that login. Total time is 24 hours from the moment that login was created. Either limit ends that login. Both numbers are locked. The 30-minute access token, the 25-minute browser refresh, and the Account Key cache stay as they are. Temporary MFA and re-registration handoff tokens are unchanged and are not these sessions.

The clocks are per login, not per account. A browser, an `arkfile-client` session file, and an `arkfile-admin` session file are separate families when each one signed in on its own. Activity on one does not extend the others. Two tabs that share the browser refresh cookie are one login.

Refresh is not a user action. `POST /api/refresh`, the browser visibility refresh, and `ExtendAuthenticatedSession` may rotate the refresh token only when both clocks still have time left, and that rotation does not move the idle timestamp or the 24-hour start. Listing, uploading, downloading, sharing, billing calls the user started, contact-info updates, and admin API calls are user actions. Chunk requests during a transfer count, so a long upload or download keeps the idle clock satisfied.

The 6-hour idle cap has no grace period. A request that arrives after 6 hours without user actions ends the login, including a chunk request for an upload that was left open. The 24-hour cap is different when a browser or `arkfile-client` transfer is already in progress. The file already being uploaded, downloaded, or exported is allowed to finish. No other file in the queue starts. When that file completes, fails, or is cancelled, the login ends. `arkfile-admin` has no upload command and no file queue. Its only user-file byte stream is `export-file`, one GET of a single `.arkbackup`. A response that was already accepted keeps streaming. An export that starts after the cap is rejected before any bytes are written, and the admin sees the plain 24-hour notice.

## Enforcement

The server is the authority. Client clocks in `SessionCreated` are hints for a local message only.

Each refresh-token row gains `session_started_at`, set once at `CreateRefreshToken` and copied onto every rotated row, and `last_user_activity`, set at creation and updated by user actions. `expires_at` becomes `session_started_at` plus 24 hours on the original row and is copied, not extended, on rotation. The current 30-day create and 14-day rotate lifetimes go away. The existing expiry check then enforces the absolute cap on every refresh path, including the browser, `arkfile-client`'s `refreshSessionToken`, and any use of the refresh token stored in the admin session file. A nullable `grace_file_id` on the current head row records the one file exempted after the 24-hour mark. It is not copied forward as a new exemption. Rotation during grace keeps the same file id.

`ValidateRefreshToken` checks idle time before it rotates. If `last_user_activity` is 6 hours old or older, it revokes that family and returns `session_idle`. It does not write `user_jwt_revocations`, because that row logs out every device for the account. An idle login's access token has already expired (it only lasts 30 minutes), so revoking the family is enough for the idle case.

The absolute cap can arrive while an access token still has time left, up to 30 minutes after the last refresh. Full access JWTs gain a `family_id` claim. A session-lifetime middleware on every full-session route loads that family's `session_started_at` and `last_user_activity`. The check runs before this request is recorded as activity, so the request that arrives after the idle window does not reset the clock. If the idle cap has passed, the middleware rejects the request, revokes that family, and revokes the current token id. If the 24-hour cap has passed and no transfer of a single file is already underway, it does the same and returns `session_absolute`. If a chunk or complete request for one file is already in progress when the 24-hour mark hits, the middleware sets `grace_file_id` to that file id (once) and allows chunk and complete calls for that file only. Every other authenticated route is rejected. Refresh during grace is allowed only to renew the access token for those routes, and it does not clear `grace_file_id` or move `session_started_at`. A second file cannot be substituted. Grace ends when that file's last chunk or complete succeeds, when the client cancels or the transfer fails, or when 30 minutes pass with no chunk request in flight for that file and none succeeded in that window. An in-flight chunk is allowed to finish even if that single request runs longer than 30 minutes. Ending grace revokes the family. Activity writes outside grace are throttled to at most one update per family per minute, so a 16 MiB chunk stream does not write the database on every chunk.

The lifetime middleware and the existing `TokenRevocationMiddleware` both attach to every full-session stack: the authenticated group in `main.go` (`auth.Echo`), `pendingAllowedGroup`, `adminGroup`, and the dev-test admin group. Admin routes today validate the JWT and the admin flag without `TokenRevocationMiddleware`. This work adds that middleware there too, so a revoked access token fails the same way for the browser, `arkfile-client`, and `arkfile-admin`.

The refresh cookie `Max-Age` becomes the remaining time until `session_started_at` plus 24 hours, instead of a sliding 7 days. The access-token cookie stays at 30 minutes.

## Clients

The browser already calls `POST /api/refresh` on a timer and when the tab becomes visible. When that call fails, `startAutoRefresh` today only logs a warning, and a later page load shows "Your session has expired (30 minutes)." A failed refresh from either cap clears the session the same way logout does (`clearAllSessionData`, including the Account Key cache) and returns to the auth screen. The 30-minute wording goes away. If a batch download, upload, or export is on the current file when the 24-hour cap hits, that file is allowed to finish under the server grace rule, and files still queued are left unstarted. The batch runner knows the remaining count. The server does not. The notice is the reason and that count, never filenames.

The notice is shown on the auth screen immediately. The same text is written to a single `sessionStorage` key after `clearAllSessionData`. That cleanup removes Account Key entries and does not wipe the rest of `sessionStorage`. The next paint of this tab reads the key, shows it once, and deletes it. Closing the tab drops it. Manual logout and revoke-all keep their existing messages.

`arkfile-client` already refreshes from `ensureFreshSessionToken` and from `makeRequestWithSession` on HTTP 401, and it stores the new refresh token with `refreshSessionToken`. A server rejection takes the existing `errAuthExpired` path and stops the command or the batch after the one-file grace, if a file was in progress. The batch summary prints the reason and how many queued files were not started. Commands that never refresh already stop when the 30-minute access token expires, which is inside both caps. The server still rejects their refresh token if something presents it later. `SessionCreated` in the session file is not consulted for the decision.

`arkfile-admin` stores a refresh token and `SessionCreated`, but `requireAdminSession` never calls `/api/refresh`. It treats a locally expired access token as logged out, so an admin session dies after about 30 minutes even though the refresh token in `~/.arkfile-admin-session.json` remains usable at `POST /api/refresh` until the database row expires. The server cap closes that hole for every client. Admin refreshes the way `arkfile-client` does, before a command, when the access token is inside a few minutes of expiry, and once on HTTP 401. A rejected refresh removes the saved session and prints the idle notice or the 24-hour notice. After that, an operator can work until 6 idle hours or 24 hours from `arkfile-admin login`, and cannot work past either limit. There is no admin grace notice and no remaining-file count. Storage copy commands return after scheduling a server task, and `verify-storage` is a short server-side round trip, so neither is a client transfer that outlives the cap. Admin API calls count as activity only for the admin login's family.

The CLI agent does not hold a refresh token. Offline `.arkbackup` operations do not create one of these sessions.

## Notices

The server returns `session_idle` or `session_absolute`. Each client maps those codes to the text below. A generic 401 that carries neither code stays on the existing "Your session has expired. Please log in again." line. Counts use the real number. One file uses the singular sentence. Zero files still queued omits the queue sentence.

Browser, 6 hours idle: "Your session ended after 6 hours without activity. Please log in again."

Browser, 24 hours, nothing in progress: "Your session ended 24 hours after you signed in. Please log in again."

Browser, 24 hours, the file in progress finished, and other files were still queued. Download: "Your session ended 24 hours after you signed in. The download in progress finished. 3 other files in the queue were not downloaded. Please log in again." Upload uses "The upload in progress finished" and "were not uploaded." Export uses "The export in progress finished" and "were not exported." One remaining file uses "1 other file in the queue was not downloaded."

Browser, 24 hours, the file in progress did not finish: "Your session ended 24 hours after you signed in. The file in progress did not finish. 3 other files in the queue were not started. Please log in again."

`arkfile-client`, 6 hours idle: "session ended after 6 hours without activity. Please run: arkfile-client login --username <user>"

`arkfile-client`, 24 hours, nothing in progress: "session ended 24 hours after login. Please run: arkfile-client login --username <user>"

`arkfile-client` batch, after the current file finishes, printed with the existing batch summary: "session ended 24 hours after login. The file in progress finished. 3 other files in the queue were not downloaded." Upload and export batches use "were not uploaded" or "were not exported." If the file in progress failed: "The file in progress did not finish. 3 other files in the queue were not started."

`arkfile-admin`, 6 hours idle: "admin session ended after 6 hours without activity, please login again"

`arkfile-admin`, 24 hours, including an `export-file` that has not started yet: "admin session ended 24 hours after login, please login again"

## Existing sessions

Startup already runs additive migrations from `runSchemaMigrations`, and `unified_schema.sql` is updated so new installs create the columns directly. The migration adds `session_started_at`, `last_user_activity`, and nullable `grace_file_id`, backfills `session_started_at` from the earliest `created_at` in each family (the original login row remains until it expires), sets `last_user_activity` to the migration time, and shrinks `expires_at` to `session_started_at` plus 24 hours when that is sooner. Real idle time before the upgrade is not knowable, because `last_used` moves on every refresh. Existing sessions are not mass-revoked. A login already older than 24 hours fails on its next refresh. A newer one keeps going until that 24-hour mark, and its 6-hour idle clock starts at the upgrade. No file, account, MFA, or billing row is rewritten.

## Privacy and logging

`last_user_activity` is a timestamp on the session row, in the same class as `expires_at`. It does not record which route ran, and it does not record an address. `grace_file_id` is the file id the server already stores for that upload or download, not a filename. Ending a session writes one security log line with the username and the reason (idle or 24-hour cap), matching the existing logout line. The raw refresh token stays out of logs. The browser notice stored for one reload contains the reason and a count, not filenames or file ids.

## Tests

Unit tests set timestamps directly. They cover rotation copying `session_started_at` and not moving `last_user_activity`, refresh rejected at 6 hours idle and at 24 hours, a user action inside the window allowing refresh, one family's expiry leaving another family for the same username valid, the middleware rejecting a still-unexpired access token after the 24-hour mark, chunk calls for `grace_file_id` succeeding after that mark, any other file id failing, grace ending after the last chunk, grace ending after 30 quiet minutes, and the activity write throttle. Handler tests cover the browser cookie `Max-Age`, the distinct error codes, and the admin refresh helper. In-memory schemas that create `refresh_tokens` grow the new columns, and the SQL shapes asserted in `handlers/auth_test.go` follow the new statements. Browser and CLI tests cover the notice text, including a queued count and the one-shot `sessionStorage` key.

No end-to-end test waits 6 or 24 hours. Existing `e2e-test.sh` and `e2e-playwright.sh` sessions stay inside both windows, so they keep passing without a clock hook. A dev-test endpoint that rewrites these timestamps is not part of this work.

## Docs

`docs/security.md` Session Management describes the 6-hour idle cap, the 24-hour absolute cap, that refresh does not slide either one, and that a file already transferring at 24 hours may finish while the rest of the queue does not start. `docs/api.md` describes `POST /api/refresh` the same way, including `session_idle` and `session_absolute`.

`docs/user-faq.md` gains one question, kept in sync with `client/static/faq.html`. The question is "How long can I stay signed in?" The answer is prose only:

A sign-in lasts until you have gone 6 hours without using Arkfile, or until 24 hours after you signed in, whichever comes first. Signing in again starts a new session. Leaving a tab open does not keep you signed in past those limits. If a download, upload, or export is already underway when the 24 hours are up, that file can finish, and any other files you had selected wait until you sign in again. The page or the command-line tool tells you that the session ended and, when some files were still queued, how many did not start.

## Files to add

- `docs/wip/auto-logout.md`
- A small Go file for the 6-hour and 24-hour constants and the session-lifetime middleware, next to the JWT middleware (`auth/`) so both the user group and the admin group can mount it
- Unit tests for the idle check, the 24-hour check, the one-file grace, family copy-on-rotation, and the middleware, beside the refresh-token tests

## Files to modify

- `database/unified_schema.sql`
- `main.go` (`runSchemaMigrations`, and mount the middleware on `auth.Echo`)
- `models/refresh_token.go`
- `models/refresh_token_test.go`
- `auth/jwt.go` (`family_id` on full access tokens; `GenerateFullAccessToken` takes the family id)
- `auth/jwt_test.go`
- `auth/jwt_rotation_test.go`
- `handlers/auth.go`
- `handlers/auth_test.go`
- `handlers/cookies.go`
- `handlers/session_extend.go`
- `handlers/mfa_login_complete.go`
- `handlers/route_config.go` (lifetime middleware and `TokenRevocationMiddleware` on `pendingAllowedGroup`, `adminGroup`, and the dev-test admin group)
- `handlers/mfa_backup_integration_test.go`
- `handlers/admin_mfa_reset_test.go`
- `handlers/admin_rotation_test.go`
- `handlers/admin_user_status_test.go`
- `handlers/reregistration_test.go`
- `handlers/admin_audience_test.go`
- `client/static/js/src/utils/auth.ts`
- `client/static/js/src/app/bootstrap.ts`
- `client/static/js/src/__tests__/auth-manager.test.ts`
- `client/static/js/src/files/download-batch.ts`
- `client/static/js/src/files/export-batch.ts`
- `client/static/js/src/files/upload.ts`
- `cmd/arkfile-client/main.go` (surface the server rejection on the existing refresh failure path)
- `cmd/arkfile-client/commands.go` (batch summary lines for the cap and the queued count)
- `cmd/arkfile-admin/session.go`
- `cmd/arkfile-admin/client.go` or `cmd/arkfile-admin/auth_commands.go` (refresh-before-command, shared by command entry points that call `requireAdminSession`)
- `cmd/arkfile-admin/session_test.go`
- `docs/security.md`
- `docs/api.md`
- `docs/user-faq.md`
- `client/static/faq.html` (same FAQ answer as `docs/user-faq.md`)

## Locked decisions

- Idle cap is 6 hours. Absolute cap is 24 hours from sign-in. Both stay.
- A browser or `arkfile-client` transfer already running at 24 hours finishes that one file, then the login ends. No other queued file starts. The 6-hour idle cap does not get this grace. `arkfile-admin` does not upload and has no queue, so it has no one-file grace notice.
- The browser, `arkfile-client`, and `arkfile-admin` show a distinct notice for each cap. A browser or `arkfile-client` batch notice includes how many files were still queued and does not include filenames. The browser notice survives one reload of the same tab in `sessionStorage`, then is deleted. Admin notices are only the idle line and the 24-hour line.
- Admin routes get `TokenRevocationMiddleware` as well as the lifetime check, the same stack the other full sessions already use.
- The user FAQ and `client/static/faq.html` both gain the "How long can I stay signed in?" question, in prose.
