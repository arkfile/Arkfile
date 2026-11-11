# Finish Auto Logout and Admin Access Tightening

## Status

This document tracks the work left over from `docs/wip/auto-logout.md` and `docs/wip/admin-sec.md`. Both plans were implemented on the server side and deployed to `test.arkfile.net` and `arkfile.net`. On 2026-11-11 a check from outside both servers returned 404 for `GET /api/admin/system/health` and `POST /api/bootstrap/register/response`, and 200 for `GET /api/admin-contacts`.

All code and test changes in the work list below are now in the tree. Go unit tests for the server packages and all Bun unit tests and type checks pass. What remains:

- The developer runs `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh` and `bash scripts/testing/e2e-playwright.sh`. `dev-reset.sh` also rebuilds the vendored FIDO2 stack, whose cache was built under GCC 12 while this host now has GCC 14; until then the `cmd/arkfile-client`, `cmd/arkfile-admin`, and `cli/*` unit tests cannot link (`libcbor.a` LTO version mismatch). Run `go test ./...` with the CGO flags from `AGENTS.md` after that rebuild.
- After the e2e runs pass, apply the update with `test-update.sh`, then `prod-update.sh`, and confirm on each server that `arkfile-admin login` followed by a read-only admin command works and that a normal browser sign-in reaches the file list.
- When everything is confirmed, archive this document together with `docs/wip/auto-logout.md` and `docs/wip/admin-sec.md`.

None of this requires an OPAQUE key rotation. The e2e admin re-registration case flags one account with `flag-user-reregistration`; it does not rotate server keys.

## Decisions

Full access tokens without `family_id` are refused. The rule in `handlers/session_lifetime.go` that accepted such a token when its `iat` was before process start is removed, along with `auth.ProcessStartedAt`. Because the process start time resets on every restart, the rule was a standing bypass of the idle and 24-hour checks for any still-valid token from the old binary. No data is affected. An upgrading browser user signs in once more; `arkfile-client` recovers through refresh because the startup backfill already created family rows for existing refresh tokens.

`arkfile-client` refreshes an expired or nearly expired access token before a command, the same way `arkfile-admin` does. The server still bounds the refresh token by the idle and 24-hour limits. Local diagnostics with no server URL (`agent status --show-digests`) still refuse an expired access token.

A repeated upload complete succeeds. When the upload session is already `completed`, belongs to the caller, and its file row exists, `CompleteUpload` returns 200 with the stored `file_id`, `storage_id`, and `encrypted_stream_sha256` from `file_metadata`, plus the current storage totals, and performs no storage, accounting, billing, or replication work. The complete request carries no chunk count, so the check is owner, status, and stored file. Every other status that is not `in_progress` keeps the 400.

A marked admin login has a 15-minute idle limit inside the 60-minute cap (`models.AdminIdleLimit`). The ended reason is `idle` and the code is `session_idle`; the server message and `arkfile-admin` say "admin session ended after 15 minutes without activity, please login again".

An admin export already streaming at an admin limit gets no hard stop and no write deadline.

## What changed

Server. The family-less token rule is gone. `DecideSessionUse` applies `SessionIdleLimitFor(login_kind)`. The unused `models.CheckSessionFamily` is removed and its tests use `DecideSessionUse`. `CompleteUpload` replays a completed upload through `replayCompletedUpload`. The lifetime middleware no longer records activity on either clock-shift endpoint, so a test can shift the caller's own family. `guardReregistrationCeremony` now returns whether the ceremony may continue: before, it wrote its 403 with `JSONErrorCode`, which returns nil, so both re-registration handlers kept running after refusing an unmarked token, a non-admin on the admin routes, or an admin on the public routes. Other layers (direct-local connection, no public handoff token for admins) limited the exposure, but the guard itself blocked nothing.

`arkfile-admin`. Each session code maps to its own notice (`session_idle`, `session_absolute`, `session_logged_out`), on refresh and on any admin command, and the saved session is removed when the server ends the login. `export-file` reads the code from a refused response.

`arkfile-client`. The agent has a `rebind_session` call that moves the session binding from the old access token hash to the new one; `refreshSessionToken` calls it, so the cached Account Key survives a refresh (before, the next agent request after any mid-transfer refresh wiped the key). Refresh holds a lock on the session file (`flock` on Unix, an exclusive lock file on Windows) and adopts a newer refresh token written by another process instead of presenting a superseded one. `requireSession` refreshes before a command. Upload chunks, download chunks, download metadata, and export read `session_idle` and `session_absolute` from a 401 body through `unauthorizedTransferError` and `refreshAfterUnauthorized`. Download and export batches stop on a session error. All three batches print one summary line from `batchSessionEndedSummary`, which says whether the file in progress finished and how many queued files did not start, using `transferNotStartedError` to tell a refused next file from an interrupted one. A package `TestMain` points `HOME` at a temporary directory so unit tests never touch the developer's real session file or agent socket.

Browser. `absoluteBatchNotice` takes an outcome (`finished`, `interrupted`, `none`). `AuthManager.endedSessionCode` records the code that ended the session, and `noteAbsoluteBatchEnd` replaces the stored and visible notice. The download batch counts a file refused between files as not started and reports the previous one finished; upload and directory-picker export batches now produce the same notice, native export reports only files not started, and an upload batch whose final list reload is refused reports that every upload finished. A plain-fetch export 401 refreshes once so the browser session ends the normal way. The bootstrap listener replaces the previous session toast instead of stacking a second one.

Tests and docs. New Go tests cover the admin idle limit, family-less tokens, the upload replay, the re-registration guards, admin CLI notices, agent rebind, refresh adoption, `requireSession` refresh, chunk session codes, and the batch summaries. New Bun tests cover the notice text and the download and export batch notices. `e2e-test.sh` adds two-login logout, refresh-cookie ceiling, client refresh with agent rebind, admin refresh, admin logout, admin self force-logout, admin idle, and admin re-registration; admin commands go through `admin_cli`, which signs in again once when the admin login ends during a long run. `online-integrity-test.sh` signs the admin in again before its closing admin steps. `docs/api.md`, `docs/security.md`, and `docs/testing.md` describe the admin routes, admin access layers, admin limits, refused family-less tokens, and the new e2e cases.

## Work list

1. Server session rules. Done.
2. Admin path coverage. Done.
3. `arkfile-client` session handling. Done.
4. Browser batch notices. Done.
5. Remaining e2e cases and docs. Done, pending the developer's e2e runs.

## Notes for review

Browser batch notices assume the server's grace rule: after the 24-hour mark the file in progress may finish, and the next file's first request is refused, so a refused file is counted as not started. A grace transfer that itself stops at the 12-hour ceiling or the 30-minute quiet timeout still shows the plain 24-hour line or the "previous finished" wording, because the browser download path does not report whether bytes had moved.

The maintenance scripts under `scripts/maintenance/` call `arkfile-admin` and were not changed. A long manual run with more than 15 minutes between admin commands now needs a fresh `arkfile-admin login`.

`auth.DeleteAllRefreshTokensForUser` has no callers and can be deleted in a later cleanup.
