# Auto Logout

## Delivery sequence

The session-family foundation and six-hour idle enforcement ship first. This initial delivery creates the final `session_families` schema, adds `family_id` and `login_kind` to the JWT plumbing, backfills existing refresh-token families, enforces the idle clock on normal full sessions, ends one family on logout, adds the browser and basic `arkfile-client` idle-expiry behavior, and adds deterministic unit and end-to-end clock controls. Normal logins use an empty `login_kind`.

`docs/wip/admin-sec.md` builds on that foundation. It begins marking logins that start through `arkfile-admin`, stores the mark on the existing family row, confines marked logins to admin work over a direct local connection, and never gives them cookies. There is no transitional `refresh_tokens.login_kind` column.

The 24-hour absolute cap, one-file transfer grace, 36-hour hard ceiling, shrinking refresh-cookie lifetime, detailed queued-file notices, and 60-minute marked-admin cap land after admin confinement. Their schema fields and stable claim/function shapes are established by the initial delivery, but their behavior is not enabled early. Each delivery remains independently testable and deployable without weakening existing file, account, MFA, share, or billing data.

## Reasoning

A browser login left open overnight stays signed in. The access token lasts 30 minutes by default (`JWT_TOKEN_LIFETIME_MINUTES`; handler tests set 1440), and the page renews it every 25 minutes and again whenever the tab becomes visible. Each renewal reissues the refresh cookie for 7 days and inserts a new database refresh token that expires 14 days later (30 days on the original login). Nothing ends the login at the Account Key lock, which only wipes the in-browser key after 15 idle minutes or after the 1 to 4 hour cache the user picked. Filenames lock again, but the session can still delete files, revoke shares, and change MFA or account settings. The same refresh-token family is what `arkfile-client` and `arkfile-admin` receive after OPAQUE and MFA, so a cap that lived only in the browser would leave the other two logins, and any copied refresh token, unbounded.

The idle and absolute checks do not assume the access token has already expired. The lifetime is configurable. The middleware is the enforcement on every full-session route, including when a test or a deployment sets a long JWT lifetime.

## Limits

Two clocks apply to every full session, meaning every refresh-token family created at the end of MFA. Idle time is 6 hours since the last user action on that login. Total time is 24 hours from the moment that login was created. Either limit ends that login. Both numbers are locked. The access-token cookie stays at the configured JWT lifetime. The 25-minute browser refresh and the Account Key cache stay as they are. Temporary MFA and re-registration handoff tokens are unchanged and are not these sessions.

The initial delivery enforces the six-hour idle clock only. It records `session_started_at` from the beginning so the later absolute-cap delivery extends the same family rather than replacing or resetting it.

The clocks are per login, not per account. A browser, an `arkfile-client` session file, and an `arkfile-admin` session file are separate families when each one signed in on its own. Activity on one does not extend the others. Two tabs that share the browser refresh cookie are one login.

Marked admin logins are the exception to these numbers. A marked admin login lasts at most 60 minutes from `arkfile-admin login`, with no extension and no grace period. The one exception is an admin request the server accepted before the 60-minute mark: it runs to completion, and any request that starts after the mark is rejected. Whether a marked admin login also gets a shorter idle limit inside the 60 minutes is an open question at the end of this document. A browser or `arkfile-client` login of an admin account is unmarked and follows the normal 6-hour and 24-hour limits.

Refresh is not a user action. `POST /api/refresh` and the browser visibility refresh may rotate the refresh token only when the rules below allow it, and that rotation does not move the idle timestamp or the 24-hour start. Listing, uploading, downloading, sharing, billing calls the user started, contact-info updates, and admin API calls are user actions. Chunk requests during a transfer count, including during the one-file grace below, so a long upload or download keeps the idle clock satisfied while bytes are still moving. The idle check runs before this request is recorded, so a chunk that arrives after 6 hours of silence ends the login.

Only requests the user started count as activity. The browser has no background API polling today: its intervals are the refresh timer, the TOTP and modal countdowns, and the service worker's stream cleanup. A future timer or poller must not call a full-session route outside the refresh path, or it would silently disable the idle limit.

The 6-hour idle cap has no grace period. A request that arrives after 6 hours without user actions ends the login, including a chunk request for an upload that was left open. The 24-hour cap is different when a browser or `arkfile-client` transfer of one file is already in progress. That file is allowed to continue, and no other file in the queue starts. Grace ends when the client cancels the upload, when 30 minutes pass with no request for that grace target, or when the grace ceiling is hit. After the upload complete or the last download chunk, the grace target stays locked and repeated requests for that same target are still allowed, so a retry of a lost final response can succeed. The client learns the login ended from its next request outside the target, such as meta for the next file or the file-list reload. The server cannot see a client-side failure. A transfer that stops sending requests ends through the 30-minute quiet timeout. An in-flight request that was already accepted finishes on its own. There is no separate tracking of requests in flight.

Grace has a hard ceiling of 12 hours past the 24-hour mark (36 hours after sign-in). A client that keeps requesting a non-final chunk cannot hold the login open past that ceiling. The ceiling is locked. It is a fixed duration, long enough for a multi-gigabyte file on a slow link. It is not computed from file size.

`arkfile-admin` has no upload command and no file queue, so it has no one-file grace. Its only user-file byte stream is `export-file`, one GET of a single `.arkbackup`. A response that was already accepted before the 60-minute mark keeps streaming. An export that starts after the mark is rejected before any bytes are written, and the admin sees the plain 60-minute notice. The same accepted-response rule applies to the user export GET at the 24-hour mark. Activity for a streamed export is recorded when the response finishes, in both the user and admin export handlers, so a multi-hour stream does not look idle on the next request. Server-side storage copy tasks started by a short admin request keep running after the admin login ends; checking their status needs a fresh login.

Adding refresh to `arkfile-admin` is intentional. Today the admin client treats a locally expired access token as logged out after about 30 minutes, while the refresh token in the admin session file stays usable at `POST /api/refresh` until the database row expires. After this work a marked admin login is usable until 60 minutes from `arkfile-admin login`, and it cannot work past that. That shortens the stolen-refresh-token window from up to 30 days to at most 60 minutes, and lengthens the working admin session from about 30 minutes to 60 minutes. Under `docs/wip/admin-sec.md` a marked refresh token is also accepted only over a direct local connection.

## Enforcement

The server is the authority. Client clocks in `SessionCreated` are hints for a local message only. Login and refresh also return `session_expires_at`, the absolute cap (`session_started_at` plus 24 hours, or plus 60 minutes for a marked admin login). That value stays constant across rotations. Clients may use it to word a local message. The notice the user sees still comes from the server error code.

One API process serves these checks. The activity-write throttle is in memory in that process. Family state itself is read from the database on each check. Claiming the grace target and ending a family use conditional updates (`WHERE grace_target IS NULL` and `WHERE ended_at IS NULL`), checked by rows affected and a re-read, because concurrent requests can race even within one process. The first `ended_reason` written wins. Running more than one API process would need the throttle moved out of memory or accepted as per-process, and an upgrade that switches every process at once because of the missing-`family_id` startup rule below.

Session state lives in a new `session_families` table, one row per login, keyed by `family_id`. The row holds `username`, `login_kind`, `session_started_at`, `last_user_activity`, `last_transfer_request_at`, the grace target and its kind (`upload_session` or `file`), `grace_last_request_at`, `ended_at`, and `ended_reason`. Refresh-token rotation does not copy these fields. The middleware loads the family by primary key. The initial delivery writes an empty `login_kind` and leaves the transfer and grace fields null. Admin confinement later writes `admin`; the absolute-cap delivery begins using the transfer and grace fields. `ended_reason` is `idle`, `absolute`, or `logout`. Those map to the error codes `session_idle`, `session_absolute`, and `session_logged_out`.

`last_transfer_request_at` is set on any upload chunk, complete, status, or cancel request and on any download chunk request, before or after the 24-hour mark. It is a timestamp only. It records neither the route nor the target.

`refresh_tokens.expires_at` is the hard ceiling: `session_started_at` plus 36 hours, set on the original row and copied onto every rotated row. For a marked admin login the ceiling is `session_started_at` plus 60 minutes. The current 30-day create and 14-day rotate lifetimes go away. The refresh cookie `Max-Age` is the remaining time until that same ceiling. It shrinks as time passes and does not slide forward on refresh. This applies only to unmarked logins, since marked admin logins never receive cookies. The access-token cookie stays at the configured JWT lifetime. The cookie outliving the 24-hour mark is what lets a grace transfer renew its access token. The family row still rejects refresh once the login has ended, once the 24-hour mark has passed with no active grace, and once the ceiling is hit.

A marked admin access token's expiry is the earlier of the configured JWT lifetime and the 60-minute mark, so the token itself never outlives the login, even with a long `JWT_TOKEN_LIFETIME_MINUTES`. With the default 30-minute access token, a marked admin login refreshes at most once.

The initial `ValidateRefreshToken` implementation uses this order:

1. Token not found.
2. Reuse of an already-rotated token. This keeps today's all-device revocation through `user_jwt_revocations`.
3. Refresh-token family already revoked by reuse.
4. Family already ended. Return the code for the stored `ended_reason`. Do not rotate. This check precedes the row's `revoked` flag so a token revoked during logout continues returning `session_logged_out`.
5. Idle cap. End the family as `idle` and return `session_idle`.
6. This refresh-token row is revoked.
7. Apply the existing refresh-row expiry check.
8. Rotate. Do not move `session_started_at` or `last_user_activity`.

The later absolute-cap delivery inserts the marked-admin, hard-ceiling, 24-hour, and grace checks between the ended-family and idle checks. Its final order is: marked-admin cap, hard ceiling, 24-hour grace decision, idle cap, then rotation. This preserves the locked rule that the 24-hour grace path never exempts a login from the six-hour idle cap. The grace decision covers a refresh that reaches the server after the 24-hour mark but before the first chunk of a running transfer has claimed grace. `arkfile-client` refreshes before a chunk when the access token is within 5 minutes of expiry, and the browser timer runs independently of a 16 MiB chunk that can stay in flight for minutes on a slow link. Without the transfer timestamp, either refresh would end the login and drop the grace.

After admin confinement lands, the direct-local-connection requirement for marked refresh tokens from `docs/wip/admin-sec.md` is checked before this order runs.

Returning the stored reason on every later refresh is required. Revoking the family and then answering "Invalid or expired refresh token" drops the 24-hour and idle notices on the retry. An empty refresh cookie still means the browser did not send one. The `Max-Age` above is what keeps the cookie available through the ceiling so the server can return the code.

Full access JWTs gain `family_id` and `login_kind` claims in the initial delivery. `CreateRefreshToken` runs before `GenerateFullAccessToken` in both functions in `mfa_login_complete.go`, and in `auth/dev_admin.go`, so the family id can be set. Normal login paths pass an empty login kind until admin confinement begins marking the admin paths. Refresh creation and validation return structured session results rather than accumulating positional return values as later deliveries add family state.

A token that has no `family_id` is accepted only when its `iat` is before this process started. Tokens issued after the upgrade always carry the claim. This covers outstanding access tokens from before the migration for one JWT lifetime, and it is not a standing bypass. This branch matches nothing once one JWT lifetime has passed after the upgrade, and it is debt to remove in a later release.

The session-lifetime middleware lives in `handlers/`, next to `RequireMFA` and `AdminMiddleware`. In the initial delivery it performs the family and idle checks and records accepted activity. The later absolute-cap delivery extends the same middleware with route-aware reads of `:sessionId`, `:fileId`, and the chunk routes. The pure clock comparison lives in `auth/` and is what `MFAResetJWTMiddleware` calls. `auth/` does not import `handlers`. Every rejection uses the existing API error shape, written by the caller that has the Echo context: `{"success":false,"error":"session_idle","message":"..."}` or the same with `session_absolute`. `echo.NewHTTPError` is the wrong shape. It renders only `{"message":...}`.

The check runs before this request is recorded as activity. If the family is already ended, return the stored reason. For a marked admin login, if the 60-minute mark has passed, end the family as `absolute` and reject; no grace rules apply, and a request accepted before the mark runs to completion. If the idle cap has passed, end the family as `idle` and reject. There is no idle exemption for chunks. If the hard ceiling has passed, end the family as `absolute` and reject. If the 24-hour cap has passed, apply the grace rules below. Otherwise a user action may update `last_user_activity`, and a transfer request may update `last_transfer_request_at`. Refresh does neither.

Grace after the 24-hour mark:

- Uploads qualify only when the upload session was created before the cap. `POST /api/uploads/init` is rejected after the cap, so a new upload cannot be created. The grace target is the upload session id. Allowed routes for that session are chunk, complete, `GET /api/uploads/:sessionId/status`, and `DELETE /api/uploads/:sessionId`. The browser cancel path calls that DELETE. Status is allowed for the same session. Current clients do not poll it during an upload.
- Downloads qualify only on chunk routes. The grace target is the file id. Both clients start every download with `GET /api/files/:fileId/meta`, and that route is rejected after the cap, so a normal client cannot start another file. The first allowed chunk after the cap sets the file id once. A later chunk for a different file id is rejected. A client that skipped meta and called a chunk route directly could still claim one file. That does not need a download-session table.
- Export is one GET. It does not set a grace target. A response already accepted keeps streaming. A GET that starts after the cap is rejected before any bytes are written.
- The first qualifying upload or download request sets the grace target once, through the conditional update above. A second target cannot be substituted, and of two concurrent requests for different targets only one claims grace. Refresh during grace is allowed only to renew the access token. It does not clear the grace target or move `session_started_at`.
- `grace_last_request_at` is updated on an allowed grace request. If that timestamp is 30 minutes old or older at the start of the next request, grace ends. After `CompleteUpload` succeeds or the last download chunk is served, the target stays locked and repeated requests for that same target are still allowed until the quiet timeout or the ceiling. The handler marks the family ended when cancel succeeds, after that request has been accepted.
- Ending grace sets `ended_reason` to `absolute` and stops the family. The cancelling request itself is allowed to finish.

Every other authenticated route is rejected after the cap.

Activity writes are throttled to at most one `last_user_activity` update per family per minute, and the same for `last_transfer_request_at` and `grace_last_request_at`. A request still counts when the write is skipped because a write happened in the last minute. One-minute granularity is enough for a 30-minute quiet timeout. The middleware does not insert into `revoked_tokens`. The family row is what rejects the access token, and `token_id` is the primary key, so a repeated insert of the same token id would fail.

The initial delivery attaches the lifetime middleware to the normal full-session stacks: the authenticated group in `main.go` (`auth.Echo`) and `pendingAllowedGroup`. This enforces the same family clock for browser and `arkfile-client` logins; checking whether a JWT arrived through a cookie would create a Bearer-token bypass and is not used. Admin confinement later attaches the lifetime middleware and the existing `TokenRevocationMiddleware` to `adminGroup` and the dev-test admin group alongside the direct-local, marked-login, and confined-scope checks.

`POST /api/logout` is registered on `auth.Echo`. The lifetime and token-revocation middleware both let that path through after JWT validation, so logout stays idempotent when the presented token or all of the user's tokens were already revoked. Logout clears the session cookies and ends that login's family with `ended_reason` `logout`. It does not write `user_jwt_revocations`. Other logins for the same account keep working. A later refresh of the ended family returns `session_logged_out`, which clients map to the existing logged-out line, not the idle or 24-hour notice. The initial delivery makes `arkfile-client logout` call `/api/logout` before deleting its session file. `arkfile-admin logout` gains the same behavior with `docs/wip/admin-sec.md`, so it ends the marked admin family on the server. `POST /api/auth/revoke-all` and admin force-logout stay user-wide.

`POST /api/mfa/reset` is on `mfaGroup`, outside those four stacks. `MFAResetJWTMiddleware` accepts a full-tier token and a reset-tier token. The full-token branch runs the same lifetime check and `TokenRevocationMiddleware`. The reset-tier token is unchanged and is not one of these sessions. MFA reset is not a file transfer and gets no grace.

`ExtendAuthenticatedSession` and its call in `payments.go` go away. Its job was to reset the session window. Rotation no longer does that. The billing return path already refreshes.

## Clients

The initial delivery implements the shared result shape and `session_idle` behavior. The browser handles the code from refresh and authenticated fetches, clears local Account Key/session state, returns to the auth screen, and preserves the notice for one reload. `arkfile-client` recognizes the code on its session-aware request and refresh paths, removes its session file, clears the agent, and reports the six-hour reason. Raw transfer-path parsing, detailed batch queue summaries, `session_absolute`, and marked-admin refresh behavior are completed with the later limits that need them.

The browser, the CLI, and admin share one failure path. On HTTP 401, refresh once. If the refresh body carries `session_idle` or `session_absolute`, map that code to the notice text below. If the retried request is still 401, map its code the same way. `session_logged_out` maps to the existing logged-out line. A 401 that carries none of these codes stays on the existing "Your session has expired. Please log in again." line.

The browser already calls `POST /api/refresh` on a timer and when the tab becomes visible. `AuthManager.refreshToken()` today returns a boolean. It has to return the error code as well, and every caller has to use that result: the timer, the visibility handler, `app/bootstrap.ts`, `files/upload.ts`, `files/download-batch.ts`, `files/download.ts`, `files/streaming-download.ts`, `files/export.ts`, `files/export-batch.ts`, and `ui/billing.ts`. A failed refresh from either cap clears the session the same way logout does (`clearAllSessionData`, including the Account Key cache) and returns to the auth screen. The "Your session has expired (30 minutes)." wording goes away.

`isAuthenticated()` reads the CSRF cookie, whose `Max-Age` is the JWT lifetime, and the auto-refresh timer runs only when that returns true. After a sleep longer than that lifetime the timer stops, and bootstrap today shows the auth screen without trying a refresh. Bootstrap calls `POST /api/refresh` even when the CSRF cookie is missing. The refresh cookie is HttpOnly and may still be present. If that refresh succeeds, the session continues. If it returns a cap code, the notice is shown. If it fails with no code, the existing expired-session line is shown.

If a batch download, upload, or export is on the current file when the 24-hour cap hits, that file is allowed to finish under the server grace rule, and files still queued are left unstarted. The batch runner knows the remaining count. The server does not. The notice is the reason and that count, never filenames. After a successful upload complete, the follow-up file-list reload can 401. That 401 is the session notice. It is not an upload failure.

The notice is shown on the auth screen immediately. The same text is written to a single `sessionStorage` key after `clearAllSessionData`. That cleanup removes Account Key entries and does not wipe the rest of `sessionStorage`. The next paint of this tab reads the key, shows it once, and deletes it. Closing the tab drops it. A second reload does not show it. Manual logout and revoke-all keep their existing messages.

Native export, the path without a directory picker, fires one anchor download about every 250 ms and cannot see completion. Its notice only reports how many selected files were not started. It does not say the export in progress finished. Directory-picker export can say whether the file in progress finished.

`arkfile-client` already refreshes from `ensureFreshSessionToken` and from `makeRequestWithSession` on HTTP 401. The chunk download and upload paths in `commands.go` and the export path in `export.go` use raw `http.Client.Do`. On 401 they call `ensureFreshSessionToken(client, session, 0)`. A zero threshold is replaced with the 5-minute default, so a still-valid access token is not refreshed, the same token is retried once, and the path returns `errAuthExpired` without reading the body. That is the usual 24-hour case: the middleware rejects a token that has not expired yet. Those paths, and `main.go`, parse the JSON `error` field on every 401. `errSessionIdle` and `errSessionAbsolute` wrap `errAuthExpired`, so batch loops still treat them as fatal. The batch summary prints the reason and how many queued files were not started. On either cap the client removes the session file and calls `agentClient.Clear()`, the same local cleanup logout and revoke-all already do. Commands that never refresh already stop when the access token expires. The server still rejects their refresh token if something presents it later, and returns the stored reason. `SessionCreated` in the session file is not consulted for the decision.

Refresh writes the session file with the existing atomic rename. A file lock covers the read-refresh-write so two `arkfile-client` processes cannot present the same refresh token. Reuse detection revokes every device for the account.

`arkfile-admin` stores a refresh token and `SessionCreated`, but `requireAdminSession` never calls `/api/refresh`. It treats a locally expired access token as logged out. Admin refreshes the way `arkfile-client` does, before a command, when the access token is inside a few minutes of expiry, and once on HTTP 401. `saveAdminSession` today is a plain `os.WriteFile`. Admin session writes become an atomic rename plus a file lock around refresh, same as the client. A rejected refresh removes the saved session and prints the 60-minute notice (or the admin idle notice, if the open question on an admin idle limit is decided that way). With the default 30-minute access token and the expiry clamped to the 60-minute mark, a marked admin login refreshes at most once. There is no admin grace notice and no remaining-file count. Storage copy commands return after scheduling a server task, and `verify-storage` is a short server-side round trip, so neither is a client transfer that outlives the cap. Admin API calls count as activity only for the admin login's family.

The CLI agent does not hold a refresh token. Offline `.arkbackup` operations do not create one of these sessions.

## Notices

The server returns `session_idle` or `session_absolute` on the refresh response and on the middleware response, including every later try after the family has ended. Each client maps those codes to the text below. A generic 401 that carries neither code stays on the existing session-expired line, and `session_logged_out` (a family ended with `logout`) stays on the existing logged-out line. Counts use the real number. One file uses the singular sentence. Zero files still queued omits the queue sentence and still says whether the file in progress finished.

Browser, 6 hours idle: "Your session ended after 6 hours without activity. Please log in again."

Browser, 24 hours, nothing in progress: "Your session ended 24 hours after you signed in. Please log in again."

Browser, 24 hours, the file in progress finished, and nothing was still queued. Download: "Your session ended 24 hours after you signed in. The download in progress finished. Please log in again." Upload uses "The upload in progress finished." Export uses "The export in progress finished."

Browser, 24 hours, the file in progress finished, and other files were still queued. Download: "Your session ended 24 hours after you signed in. The download in progress finished. 3 other files in the queue were not downloaded. Please log in again." Upload uses "The upload in progress finished" and "were not uploaded." Directory-picker export uses "The export in progress finished" and "were not exported." One remaining file uses "1 other file in the queue was not downloaded."

Browser, 24 hours, the file in progress did not finish: "Your session ended 24 hours after you signed in. The file in progress did not finish. 3 other files in the queue were not started. Please log in again."

Browser, native export, 24 hours: "Your session ended 24 hours after you signed in. 3 selected files were not started. Please log in again." When every selected file was already handed to the browser, omit the count sentence and use the plain 24-hour line. Do not claim the export finished.

`arkfile-client`, 6 hours idle: "session ended after 6 hours without activity. Please run: arkfile-client login --username <user>"

`arkfile-client`, 24 hours, nothing in progress: "session ended 24 hours after login. Please run: arkfile-client login --username <user>"

`arkfile-client` batch, after the current file finishes, printed with the existing batch summary: "session ended 24 hours after login. The file in progress finished. 3 other files in the queue were not downloaded." Upload and export batches use "were not uploaded" or "were not exported." If nothing was still queued, omit the queue sentence. If the file in progress failed: "The file in progress did not finish. 3 other files in the queue were not started."

`arkfile-admin`, 60 minutes, including an `export-file` that has not started yet: "admin session ended 60 minutes after login, please login again"

`arkfile-admin` idle: only if an admin idle limit is adopted (open question below). The line would follow the same pattern, for example "admin session ended after 15 minutes without activity, please login again".

## Existing sessions

Startup already applies `unified_schema.sql` as one operation, then runs additive migrations from `runSchemaMigrations`. The initial delivery makes `unified_schema.sql` create the final `session_families` shape with `CREATE TABLE IF NOT EXISTS` and adds `CREATE INDEX IF NOT EXISTS` on `refresh_tokens(family_id)`. The family id column already exists, so that index is safe in the schema file that re-runs on every startup. The table's primary key is the middleware lookup.

`runSchemaMigrations` initially backfills one `session_families` row per existing `family_id` that does not yet have one. It reads the rows, computes in Go, and writes `time.Time` parameters. `session_started_at` is the earliest `created_at` in that family, `last_user_activity` is the migration time only on rows this backfill inserts, and `login_kind` is empty. Real idle time before the upgrade is not knowable because `last_used` moves on refresh, so existing sessions receive a fresh six-hour idle window. Date math stays in Go. SQLite `datetime()` text and the driver's timestamp text do not compare cleanly, and the refresh-token reader already accepts more than one timestamp shape.

The later absolute-cap delivery does not reset either clock. It shrinks `expires_at` on refresh-token rows to `session_started_at` plus 36 hours when that is sooner. A normal family whose recorded start is already 24 hours or more in the past is ended with `ended_reason` `absolute`, so the next refresh returns `session_absolute` instead of a generic expiry. After admin confinement has forced each admin to create a marked family, the same delivery shrinks marked-family refresh expiry to 60 minutes from its recorded start and ends marked families already beyond that point.

The backfill runs on every startup and only inserts missing family rows. An unconditional update of `last_user_activity` would reset the idle clock on every restart. Existing sessions are not mass-revoked by the initial delivery. No file, account, MFA, or billing row is rewritten.

Columns on this table are nullable where SQLite `ADD COLUMN` would otherwise need a constant default. The new table is created with `CREATE TABLE`, so the backfill is what fills the clocks. An unexpected failure of this migration aborts startup. "Already applied" stays non-fatal, matching the older migrations, which only log and continue. The new code cannot run without the family rows.

Unit tests that use go-sqlite3 do not reproduce the rqlite timestamp encoding. The initial migration unit test inserts legacy-shaped refresh families, runs the backfill twice, checks that the second run changes nothing, and checks that restart does not move `last_user_activity`. The absolute-cap delivery extends that test with old-family ending and refresh-expiry shrinking. A `test-update.sh` run on the test VPS, with live sessions of each relevant age, is the check that has to pass before `prod-update.sh`.

Rolling back to the old binary is safe. It ignores `session_families` and the new index. On the next upgrade the missing-row backfill creates family rows for families the old binary inserted after the rollback.

## Privacy and logging

`last_user_activity` and `last_transfer_request_at` are timestamps on the family row, in the same class as `expires_at`. They do not record which route ran or which target, and they do not record an address. `login_kind` records only whether the login came through `arkfile-admin`. The grace target is the upload session id or the file id the server already stores, not a filename. Ending a session writes one security log line with the username and the reason (idle, 24-hour cap, 60-minute admin cap, or logout), matching the existing logout line. The raw refresh token stays out of logs. The browser notice stored for one reload contains the reason and a count, not filenames or file ids.

## Cleanup

`models.CleanupExpiredTokens` and `auth.CleanupExpiredTokens` are only called from tests, so `refresh_tokens` and `revoked_tokens` grow without a bound. This work adds a periodic cleanup, on the same kind of timer as the existing session cleanup. It keeps a family row, and the refresh-token row a client might still present, until 7 days after `ended_at`. Until then, refresh returns the stored reason. After that, those rows can be deleted, and a late refresh gets the generic not-found line. Superseded refresh-token rows for an ended family go away in that same cleanup. The cleanup also deletes expired `revoked_tokens` rows past their expiry. `auth.DeleteAllRefreshTokensForUser` has no callers. Removing it is existing debt and is not part of this change.

## Tests

The initial delivery covers family state across refresh rotation, refresh rejected at six hours idle, a user action inside the window allowing a later refresh, refresh itself not moving activity, one family's idle expiry leaving another family for the same username valid, the middleware rejecting a still-unexpired access token after the idle mark, a token with no `family_id` accepted only when `iat` is before process start, the activity-write throttle, logout ending one family while another family for the same username still works, browser notice and one-reload behavior, basic `arkfile-client` idle cleanup, and the idempotent initial backfill. These tests ship with the idle enforcement rather than waiting for the absolute-cap work.

Unit tests set timestamps directly. They cover family state left in place across rotation, refresh rejected at 6 hours idle and at 24 hours, refresh allowed during active grace and rejected after the 12-hour ceiling, a user action inside the window allowing refresh, one family's expiry leaving another family for the same username valid, the middleware rejecting a still-unexpired access token after the 24-hour mark, a token with no `family_id` accepted only when `iat` is before process start, chunk calls for the grace target succeeding after that mark, any other file id or upload session failing, upload init and download meta failing after the cap, cancel and status allowed for the grace upload session, a retried final chunk or complete for the grace target still allowed after the last chunk or complete, grace ending after 30 quiet minutes, grace ending at the ceiling, a refresh after the 24-hour mark with no grace target but a recent `last_transfer_request_at` rotating, the same refresh with a stale `last_transfer_request_at` ending the family, two concurrent chunk requests for different targets where only one claims grace, two concurrent end-family writes where the first reason wins, the activity write throttle, and logout ending one family while another family for the same username still works. For marked admin logins they cover refresh rejected at 60 minutes, the access token's expiry clamped to the 60-minute mark, the middleware rejecting a still-unexpired marked token after the mark, no grace applied to a marked login, an admin export accepted before the mark finishing while one starting after it is rejected, and the backfill inserting a marked family older than 60 minutes as ended. Handler tests cover the browser cookie `Max-Age` shrinking toward the 36-hour ceiling and not sliding, `session_expires_at` staying constant, the JSON error shape and the distinct codes on refresh and on a later retry, logout succeeding after the cap, the full-token branch of MFA reset, and the admin refresh helper. In-memory schemas that create `refresh_tokens` grow the family table, and the SQL shapes asserted in `handlers/auth_test.go` follow the new statements.

The one-file grace is covered by a Go test that mounts the real route stack with `httptest`, calls the real upload and download handlers, and sets timestamps directly. The migration unit test is described above.

Browser and CLI tests cover the notice text, including a queued count, the finished-with-zero-queued sentence, the native-export wording, and the one-shot `sessionStorage` key.

End-to-end coverage does not wait 6 or 24 hours. These cases go in `e2e-test.sh` and need no clock control:

- Extend the existing refresh rotation scenario. The `Set-Cookie` `Max-Age` on `/api/refresh` is at most the time left until the 36-hour ceiling and does not increase. `session_expires_at` stays constant across refreshes.
- Set `expires_at` in the past in the admin session file, run a read-only `arkfile-admin` command, and expect success plus a rotated refresh token on disk. Do the same for `arkfile-client`.
- Copy the admin's current access token, run `arkfile-admin force-logout --username <dev-admin>` against the admin itself (a user-wide revocation through `user_jwt_revocations`), then call `/api/admin/users` with the copied token and expect 401. This proves `TokenRevocationMiddleware` on the admin group. A marked login cannot use `/api/revoke-token` under `docs/wip/admin-sec.md`, so that route is not used here.
- Copy the admin's access token and refresh token, run `arkfile-admin logout`, then expect 401 from `/api/admin/users` with the copied access token and `session_logged_out` from `/api/refresh` with the copied refresh token over the direct local connection.
- Use two `arkfile-client` logins for one user in separate `HOME` directories. Log one out. The other keeps working, and the logged-out access token is rejected.

A dev-test endpoint ships with the initial idle enforcement and is registered only on the dev-test admin group the way the billing and throttle-reset endpoints are: `POST /api/admin/dev-test/sessions/shift` takes a username, an optional `family_id`, and idle and age offsets. Without a `family_id` it shifts every family for that username; the two-login cases pass a `family_id` so only one login moves. A companion `POST /api/dev-test/sessions/shift-self`, registered only when the same dev-test API flag is enabled and protected by the normal full-session stack, shifts only the caller's signed family id so Playwright can exercise the browser response without receiving an admin token. Initially the scripts use these endpoints to prove that a still-unexpired access token and the corresponding refresh token both return `session_idle`, the other family keeps working, the CLI prints the idle notice, the session file is removed, the agent is cleared, and the browser returns to the auth screen with the one-shot notice. The endpoints accept the age offset from the beginning so the absolute-cap delivery can add its middleware, refresh, and admin 60-minute cases without changing the test API.

`e2e-test.sh` logs the admin in once in `run_platform_bootstrap_admin_login` and reuses that login for the rest of the run. With the 60-minute admin cap, `admin_login_with_totp` logs in again when an admin command reports the session-ended code, and the admin-heavy groups log in again before they start, so a full run longer than 60 minutes does not fail late admin steps. Playwright shifts the session, dispatches `visibilitychange`, and asserts the auth screen and notice text. One reload shows the notice again. A second reload does not.

`docs/testing.md` lists the new end-to-end cases.

## Docs

`docs/security.md` Session Management describes the 6-hour idle cap, the 24-hour absolute cap, the 12-hour grace ceiling, that refresh does not slide either clock, and that a file already transferring at 24 hours may continue until it finishes, until it goes quiet, or until the ceiling, while the rest of the queue does not start. It also describes the 60-minute cap on marked `arkfile-admin` logins, with no grace and only an already-accepted request running past the mark. The same edit corrects the temporary MFA token lifetime: the code issues 20 minutes, and the doc currently says 10. Logout is described as ending that login's family. `revoke-all`, admin force-logout, and refresh-token reuse remain the user-wide revocations. `docs/api.md` describes `POST /api/refresh` the same way, including `session_idle`, `session_absolute`, `session_logged_out`, and `session_expires_at`, and corrects the logout sentence the same way.

`docs/user-faq.md` gains one question, kept in sync with `client/static/faq.html`. The question is "How long can I stay signed in?" The answer is prose only:

A sign-in lasts until you have gone 6 hours without using Arkfile, or until 24 hours after you signed in, whichever comes first. Signing in again starts a new session. Leaving a tab open does not keep you signed in past those limits. If a download, upload, or export is already underway when the 24 hours are up, that file can keep going for up to 12 more hours, and then the session ends even if the file has not finished. Any other files you had selected wait until you sign in again. The page or the command-line tool tells you that the session ended and, when some files were still queued, how many did not start.

`docs/wip/tcp-docs.md` still says session cookies last 30 minutes and 7 days. That draft is updated to the access-token lifetime and the 36-hour refresh-cookie ceiling.

## Files to add

- `docs/wip/auto-logout.md`
- The `session_families` model, next to the refresh-token model
- The 6-hour, 24-hour, 12-hour, and 60-minute admin constants and the family clock check in `auth/`, next to the JWT middleware
- The route-aware session-lifetime middleware in `handlers/`, next to `RequireMFA`
- Unit tests for the idle check, the 24-hour check, the grace ceiling, the one-file grace, family state across rotation, the missing `family_id` claim, and the migration backfill

## Files to modify

- `database/unified_schema.sql`
- `main.go` (`runSchemaMigrations` backfill, fatal on unexpected failure, mount the middleware on `auth.Echo`, and the periodic token cleanup)
- `models/refresh_token.go`
- `models/refresh_token_test.go`
- `auth/jwt.go` (`family_id` on full access tokens; `GenerateFullAccessToken` takes the family id; the full-token branch of `MFAResetJWTMiddleware`)
- `auth/jwt_test.go`
- `auth/jwt_rotation_test.go`
- `auth/dev_admin.go`
- `auth/token_revocation.go` (periodic cleanup only; `DeleteAllRefreshTokensForUser` stays unused)
- `handlers/auth.go`
- `handlers/auth_test.go`
- `handlers/cookies.go`
- `handlers/session_extend.go` (remove `ExtendAuthenticatedSession`)
- `handlers/payments.go`
- `handlers/mfa_login_complete.go` (create the refresh token before the access token)
- `handlers/route_config.go` (lifetime middleware and `TokenRevocationMiddleware` on `pendingAllowedGroup`, `adminGroup`, and the dev-test admin group; logout exempt from the lifetime check; the dev-test session-shift endpoint)
- The user and admin export handlers, to record activity when the streamed response finishes
- `handlers/mfa_backup_integration_test.go`
- `handlers/admin_mfa_reset_test.go`
- `handlers/admin_rotation_test.go`
- `handlers/admin_user_status_test.go`
- `handlers/reregistration_test.go`
- `handlers/admin_audience_test.go`
- `client/static/js/src/utils/auth.ts`
- `client/static/js/src/app/bootstrap.ts`
- `client/static/js/src/__tests__/auth-manager.test.ts`
- `client/static/js/src/files/download.ts`
- `client/static/js/src/files/streaming-download.ts`
- `client/static/js/src/files/download-batch.ts`
- `client/static/js/src/__tests__/download-batch.test.ts`
- `client/static/js/src/files/export.ts`
- `client/static/js/src/files/export-batch.ts`
- `client/static/js/src/__tests__/export.test.ts`
- `client/static/js/src/__tests__/export-batch.test.ts`
- `client/static/js/src/files/upload.ts`
- `client/static/js/src/__tests__/upload-batch.test.ts`
- `client/static/js/src/ui/billing.ts`
- `cmd/arkfile-client/main.go` (parse the server code on every 401 path, including refresh)
- `cmd/arkfile-client/commands.go` (chunk paths, batch summary lines, session-file removal, and `agentClient.Clear()`)
- `cmd/arkfile-client/export.go`
- `cmd/arkfile-admin/session.go` (atomic write and file lock)
- `cmd/arkfile-admin/client.go` or `cmd/arkfile-admin/auth_commands.go` (refresh-before-command, shared by command entry points that call `requireAdminSession`, and the 60-minute notice; the server-side logout call is in `docs/wip/admin-sec.md`)
- `cmd/arkfile-admin/session_test.go`
- `scripts/testing/e2e-test.sh` (including `admin_login_with_totp` logging in again on the session-ended code)
- `scripts/testing/e2e-playwright.ts`
- `docs/security.md`
- `docs/api.md`
- `docs/testing.md`
- `docs/user-faq.md`
- `docs/wip/tcp-docs.md`
- `client/static/faq.html` (same FAQ answer as `docs/user-faq.md`)

## Locked decisions

- Idle cap is 6 hours. Absolute cap is 24 hours from sign-in. Both stay. The grace ceiling is 12 hours past that absolute cap. The quiet timeout inside grace is 30 minutes.
- A browser or `arkfile-client` transfer already running at 24 hours continues that one file, then the login ends. No other queued file starts. The 6-hour idle cap does not get this grace. `arkfile-admin` does not upload and has no queue, so it has no one-file grace notice.
- Grace ends through the quiet timeout, a cancel, or the ceiling, not immediately after the final chunk or complete. The grace target stays locked and retries of the final request are allowed. A refresh after the 24-hour mark with recent transfer activity but no grace target yet still rotates.
- The browser, `arkfile-client`, and `arkfile-admin` show a distinct notice for each cap. A browser or `arkfile-client` batch notice includes how many files were still queued and does not include filenames. Native browser export only reports files not started. The browser notice survives one reload of the same tab in `sessionStorage`, then is deleted. The admin notice is the 60-minute line, plus an idle line only if an admin idle limit is adopted.
- Admin routes get `TokenRevocationMiddleware` as well as the lifetime check, the same stack the other full sessions already use. A marked `arkfile-admin` login lasts at most 60 minutes from login, with no extension and no grace; a request the server accepted before the mark runs to completion, and any request that starts after it is rejected.
- Logout ends that login's family and still succeeds after either cap. It does not log out other devices. A later refresh of a logged-out family returns `session_logged_out`.
- The user FAQ and `client/static/faq.html` both gain the "How long can I stay signed in?" question, in prose.

## Open questions

Should a marked admin login also have an idle limit inside the 60-minute cap? Without one, an SSH window left open on the server keeps a working admin login for up to an hour after the last command. A 15-minute idle limit would end it sooner, at the cost of logging in again after a short break. The recommendation is 15 minutes, since admin work tends to come in short bursts.

Should an admin request that is already streaming past the 60-minute mark have any hard bound? The current decision is that an accepted request runs to completion, which for a multi-gigabyte `export-file` over a slow link could be hours. A server-side write deadline would bound it but could cut off a legitimate export.

How should a client handle a retried `CompleteUpload` during grace? Today a second complete for a session that already completed returns 400 ("Upload session is completed, not in progress"), so a client whose first complete response was lost would report a failure for an upload that succeeded. Options are to make complete return success when the session is already `completed` for the same owner, or to have the clients check `GET /api/uploads/:sessionId/status` (allowed for the grace target) before reporting a failure.
