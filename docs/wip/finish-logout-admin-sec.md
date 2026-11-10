# Finish Auto Logout and Admin Access Tightening

## Status

This document tracks the work left over from `docs/wip/auto-logout.md` and `docs/wip/admin-sec.md`. Both of those plans are implemented on the server side: session families, the six-hour idle cap, the 24-hour cap with one-file grace, the 60-minute marked admin login, the Caddy 404 on admin and bootstrap paths, the direct-local-connection check, marked-login scope, and the admin re-registration routes. Local `dev-reset.sh` followed by `e2e-test.sh` passed. What remains is client notice handling, test coverage for the admin paths, docs, three open decisions, and the VPS rollout. None of the remaining gaps weakens what the server enforces.

## Findings

The `arkfile-client` raw transfer paths do not read the session error. On HTTP 401, `uploadChunk` and `doChunkedDownload` in `cmd/arkfile-client/commands.go` call `ensureFreshSessionToken(client, session, 0)`. A zero threshold becomes the 5-minute default, so a still-valid access token is not refreshed, the same token is retried, and the second 401 returns a generic `errAuthExpired` without reading the body. `exportOneBundle` in `cmd/arkfile-client/export.go` discards the refresh result and returns `errAuthExpired`, so a `session_absolute` refresh reply is lost, and it never reads the first 401 body. A 24-hour or idle rejection in the middle of a chunk or export therefore shows the generic expired line, not the session notice.

The `arkfile-client` download batch does not stop on a session error. `runOwnerDownloadBatch` aborts a round only on cancellation. After `clearExpiredLocalSession` empties the in-memory tokens, every remaining file fails on its metadata request, and the user is then prompted to retry failed downloads. The export batch has the same gap. Only the upload batch adds the "other files in the queue were not uploaded" count, and none of the batches say whether the file in progress finished.

The browser download batch notice has the wrong wording and count. The only place that attaches the session code is `ensureFreshBatchAuth` in `client/static/js/src/files/download-batch.ts`, which runs between files. When the notice fires, the previous file has already finished and the current one never started, but the notice says "The file in progress did not finish" and its queued count omits the current file. The upload and export batches never call `absoluteBatchNotice`, so they show only the plain 24-hour line.

`CompleteUpload` in `handlers/uploads.go` returns 400 for any status other than `in_progress`, including `completed`. A client whose first complete response was lost reports a failure for an upload that succeeded.

The admin re-registration ceremony has no automated coverage. There are no unit tests for `AdminReregisterResponse` or `AdminReregisterFinalize` and no e2e case. After `arkfile-admin rotate-opaque-keys`, every admin depends on that ceremony to sign in again.

Several e2e cases listed in the original plans are missing: `arkfile-admin logout` followed by `session_logged_out` on the copied refresh token; `arkfile-admin force-logout` against the admin itself followed by 401 on the copied access token; an admin session file with `expires_at` in the past refreshing and succeeding; the refresh cookie `Max-Age` shrinking toward the 36-hour ceiling with `session_expires_at` constant; and two `arkfile-client` logins where logging out one leaves the other working.

`docs/wip/auto-logout.md` contradicts itself on `arkfile-client` with an expired access token. The Clients section says commands that never refresh stop when the access token expires, which matches `requireSession` in `cmd/arkfile-client/main.go` and the existing e2e check that expects rejection. The Tests section asks for an e2e case expecting refresh and success. `arkfile-admin` already refreshes in `requireAdminSession`.

`docs/api.md` does not list `/api/admin/reregister/response` or `/api/admin/reregister/finalize`, and its 409 description reads as if a flagged admin gets the public re-registration response. A flagged admin on the public login gets the generic failure. The OPAQUE rotation section of `docs/security.md` says the same, and it does not describe the Caddy 404, the direct-local-connection check, or that `arkfile-admin logout` ends that family on the server.

## Order of work

1. Roll out the existing code. Run `test-update.sh` on the test VPS. From outside the box, `/api/admin/system/health` should return 404. On the box, `arkfile-admin login`, a few read-only admin commands, and a normal browser sign-in should work. Then run `prod-update.sh`. Production exposes `/api/admin/*` through Caddy until it is updated. Do not run `rotate-opaque-keys` or flag any admin account until step 2 is done.

2. Cover the admin security paths. Add handler unit tests for the admin re-registration routes, including refusal of an unmarked handoff token and refusal of admin accounts on `/api/opaque/reregister/*`. Add the e2e case that flags the dev admin late in the run, completes the ceremony through `arkfile-admin login`, works on admin routes, and shows the normal login cannot re-register that account. Add the admin logout, admin self force-logout, and admin expired-token refresh cases.

3. Fix `arkfile-client` session handling. Add one helper that reads the JSON `error` from a 401 body and returns `errSessionIdle` or `errSessionAbsolute` after local cleanup, and call it from the upload chunk, download chunk, and export paths. Make the download and export batches stop on `errAuthExpired` the way the upload batch does, and print whether the file in progress finished and how many queued files were not started. Unit tests follow `upload_batch_test.go`.

4. Fix the browser batch notices to match. Correct the download batch wording and count for a refusal between files, and wire `absoluteBatchNotice` into the upload batch and the directory-picker export batch. Native export reports only files not started. Tests go in `download-batch.test.ts`, `upload-batch.test.ts`, and `export-batch.test.ts`.

5. Add the remaining e2e cases: refresh cookie `Max-Age` and constant `session_expires_at`, and the two-login logout case.

6. Update the docs: the admin re-registration routes and flagged-admin behavior in `docs/api.md`, the rotation and admin-access sections of `docs/security.md`, and the `arkfile-client` expired-token contradiction in `docs/wip/auto-logout.md` once decided.

Steps 2, 3, and 4 are each a reasonable point to save progress.

## Open questions

Should a repeated upload complete succeed? The suggestion is that `CompleteUpload` returns success with the existing `file_id` when the session is already `completed` for the same owner. That fixes both clients without client changes, and the server already holds the row. The alternative is for both clients to check `GET /api/uploads/:sessionId/status` before reporting a failure. Decide this before step 3 so the client work is written once.

Should a marked admin login have an idle limit inside the 60-minute cap? The suggestion is to adopt 15 minutes. The change is small, the notice line is already drafted, and it shortens the window of a forgotten SSH session, at the cost of entering TOTP more often.

Should an admin export already streaming past the 60-minute mark have a hard bound? The suggestion is no write deadline. The token cannot start new requests after the mark, and cutting off a legitimate multi-gigabyte export costs more than it protects.

Should `arkfile-client` refresh an expired access token before a command, as `arkfile-admin` does? Keeping today's local rejection matches the existing e2e check. Refreshing would make the two CLIs consistent and let a user resume after a short sleep without signing in again. Either way, one of the two statements in `docs/wip/auto-logout.md` must change.

## Later debt

Accepting a full access token with no `family_id` when its `iat` is before process start matches nothing once one access-token lifetime has passed after the upgrade, and can be removed in a later release. `auth.DeleteAllRefreshTokensForUser` has no callers and can be deleted.
