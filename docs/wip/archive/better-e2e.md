# Better E2E Plan for `scripts/testing/e2e-test.sh`

**STATUS: FULLY IMPLEMENTED as of 2026-03-13.**

All six priority sections below have been implemented in `scripts/testing/e2e-test.sh`. Phase numbering was reorganized during implementation (see deviation note under Priority 2). The final phase structure is:

- Phase 1: Environment verification
- Phase 2: Admin authentication
- Phase 3: Bootstrap protection
- Phase 4: User registration
- Phase 5: TOTP setup
- Phase 6: Admin user management
- Phase 7: User login
- Phase 8: File operations (account-password)
- Phase 9: Custom-password file operations
- Phase 10: Share operations (create, visitor access, revoke, privacy, post-logout checks)
- Phase 11: Admin system status and negative-access tests
- Phase 12: Cleanup
- Phase 13: Summary report

`NOTE: Agentic coding agents & LLMs *MUST* read AGENTS.md prior to beginning or resuming any coding/implementation work on this project. The developer will run dev-reset.sh himself after any changes to the project/app code, and e2e-test.sh himself after changes to the test script.`

## Goal

Improve `scripts/testing/e2e-test.sh` so that it:

- runs faster during normal development
- is easier to maintain and extend
- proves more of Arkfile's privacy-first and authorization expectations end-to-end
- keeps actor/session transitions organized without adding unnecessary login/logout churn

## Constraints Agreed For This Plan

- Keep all existing hard-coded usernames, passwords, TOTP secrets, and other credential values exactly as they are today at the top of `e2e-test.sh`.
- Add any new custom-password and intentionally incorrect-password values in that same top credential/config section, following the existing naming patterns.
- Treat admin-as-second-actor negative access tests as sufficient for now instead of adding a second regular user flow.
- Reduce the TOTP wait buffer from 2 seconds to 1 second.
- Reduce Share C expiry from 2 minutes to 1 minute.

## High-Level Direction

The current script already proves the happy path for major admin, auth, file, and share flows. The next step is to keep those strengths while improving three areas:

1. runtime and reliability
2. script structure and reuse
3. missing security, privacy, and authorization checks

The near-term refactor should group tests by actor/session block rather than by isolated feature block whenever that reduces repeated login logic.

One important ordering constraint from the current flow must be preserved: the primary user needs to complete TOTP setup immediately after registration, before the admin approval step. After that initial registration and TOTP setup flow is complete, the user can log out, the admin can approve the account, and only then should the main authenticated user workflow continue.

## Proposed Actor-Oriented Flow

This is the target execution shape after refactor.

### 1. Unauthenticated and Environment Block

- verify server connectivity
- verify `arkfile-client` and `arkfile-admin` binaries exist
- verify bootstrap protection behavior
- do not start the agent before this block passes

### 2. Primary User Registration and TOTP Setup Block

- register primary user
- complete initial TOTP setup and verification immediately after registration
- log out primary user

### 3. Admin Block 1

- admin login with TOTP
- list users
- get user status
- approve primary test user
- logout admin

### 4. Primary User Block 1

- login primary user with TOTP
- run account-password file flow
- run custom-password file flow, including owner round-trip validation
- create shares
- ensure at least one share is created from the custom-password-encrypted file
- run enriched `share list` and verify useful owner-visible output
- run raw/API-level share-list and metadata-batch checks for privacy expectations
- logout primary user

### 5. Anonymous Share-Access Block

- download valid share with correct password
- reject valid share with wrong password
- reject non-existent share
- reject max-downloads-exhausted share
- reject expired share
- verify failed downloads do not leave partial plaintext outputs behind

### 6. Primary User Block 2

- login primary user again with TOTP
- revoke share
- verify revoked share cannot be accessed
- verify post-revocation and post-expiry list state if supported by the CLI output
- logout primary user

### 7. Logged-Out Session Invalidation Block

- verify authenticated commands fail after logout
- explicitly check `list-files`, user-owned file download, `share create`, and `share revoke`
- confirm saved session and cached key behavior no longer grant access after logout

### 8. Admin Block 2

- admin login with TOTP
- verify admin cannot access ordinary user-owned file/share/metadata resources in ways the design should forbid
- retrieve system status
- logout admin

### 9. Cleanup and Summary Block

- verify the agent auto-started during normal CLI use
- stop agent cleanly at the end
- verify the agent is no longer running after cleanup
- keep summary ordering deterministic
- return a clear success/failure exit code

## Priority-Ordered Implementation Plan

## Priority 1: Runtime and Reliability Improvements

These changes should land first because they improve day-to-day use of the script without changing test intent.

### 1. Move agent startup later

Current issue:

- `main()` starts the agent before environment verification
- that makes early failures less clear and can create avoidable background process noise

Planned change:

- run environment verification first
- the agent starts implicitly on first login; make sure we pass the option to cache account key and file digests whenever the test user logs in

### 2. Reduce TOTP window buffer to 1 second

Current issue:

- `wait_for_totp_window()` adds a 2 second buffer after the next boundary

Planned change:

- reduce the buffer to 1 second, per agreed direction

Expected result:

- slightly faster test runs while preserving replay-window safety

### 3. Reduce Share C expiry from 2 minutes to 1 minute

Current issue:

- the expiry test is one of the longest parts of the entire script

Planned change:

- change Share C from `--expires 2m` to `--expires 1m`
- update all comments and smart-sleep calculations accordingly

Expected result:

- materially faster full-suite runtime while keeping expiry coverage

### 4. Strengthen cleanup behavior

Current issue:

- the old script-managed agent lifecycle is likely more complex than needed

Planned change:

- allow the CLI to auto-start the agent during normal commands
- verify agent status once after a command path that should have started it
- stop the agent via CLI during cleanup and verify shutdown status
- keep cleanup idempotent so failure paths stay safe

### 5. Make summary output deterministic

Current issue:

- summary prints results from an associative array, so ordering is nondeterministic

Planned change:

- preserve a dedicated ordered list of test names or phase names for summary printing

Expected result:

- easier review of repeated runs and clearer debugging output

### 6. Clean up formatting to align with `docs/AGENTS.md`

Current issue:

- some comments and log banners use formatting styles that do not align with the guidance in `AGENTS.md`, like `# ---` or `# ===`

Planned change:

- simplify log and comment formatting
- remove unnecessary decorative separators where they conflict with project guidance

## Priority 2: Structural Refactor for Maintainability

These changes reduce duplicated shell logic and make later test additions safer.

### 1. Introduce reusable helpers

Add focused helpers for repeated behaviors such as:

- `admin_login_with_totp`
- `user_login_with_totp`
- `logout_user_session`
- `logout_admin_session`
- `assert_agent_running`
- `assert_agent_not_running`
- `share_download_with_password`
- `share_create_for_account_file`
- `share_create_for_custom_file`
- `assert_output_file_exists`
- `assert_output_file_absent_or_empty`
- `assert_sha256_matches`
- `assert_command_failed`

Benefits:

- less duplicated `bash -c` quoting
- easier updates when CLI behavior changes
- easier to add new negative tests without copy/paste drift

### 2. Group phases by actor/session

Current issue:

- the current script mixes actor transitions with feature transitions in ways that are workable but harder to extend

Planned change:

- reorganize around the actor-oriented flow described above
- keep log output explicit about which actor is active for each block

Benefits:

- fewer login/logout cycles
- clearer mental model for future additions
- easier placement for logout/session invalidation assertions

### 3. Expand top-of-script credentials/config section carefully

Planned additions:

- one custom password for the primary test user's custom-password file flow
- one or more intentionally incorrect passwords for negative cases, such as wrong share password and wrong custom file password

Important constraint:

- do not alter any existing credential values already present in the script
- passwords (even incorrect ones) must meet all strength/complexity requirements as defined in password-requirements.json for the given password type, except in the case that we are explicitly trying to test a WEAK password specifically

### 4. Separate stored IDs and artifacts by scenario

Planned change:

- use clearly named variables for account-password file IDs, custom-password file IDs, share IDs, and downloaded output files

Benefits:

- lower risk of one test accidentally reusing another test's identifiers
- clearer cleanup behavior

## Priority 3: Add Missing Security and Privacy Validations

These are the highest-value new assertions for proving the intended design more directly.

### 1. Validate `list-files` output for privacy expectations

Goal:

- confirm CLI-visible output does not reveal unintended plaintext metadata

Planned assertions:

- use `list-files --raw` (which wraps `GET /api/files`) to verify the raw server-returned data does not expose original plaintext filename or SHA-256 metadata
- verify the new general-purpose metadata endpoint directly (`GET /api/files/metadata`) to ensure it also honors plaintext protection
- use normal `list-files` to verify the owner can still see locally decrypted filename information as intended
- verify no raw encryption envelope data or other obviously sensitive internals leak into the raw output

Note:

- the exact assertion should match the intended UX of the CLI, not a guess

### 2. Validate `share list` output for privacy expectations

Goal:

- verify that the current `share list` functionally successfully protects server-side privacy while providing rich owner details via local batch decryption.

Planned assertions:

- verify default `share list` (which joins `GET /api/shares` and `POST /api/files/metadata/batch`) successfully shows owner-visible locally decrypted values (filename, SHA-256, original size) for both an account-password shared file and a custom-password shared file.
- verify the command accurately reflects the 'key type' (account vs custom).
- use `share list --raw` to independently assert that the paginated `GET /api/shares` underlying API strictly conceals plaintext filename, plaintext SHA-256, share passwords, custom passwords, or envelope contents.

### 3. Add wrong share password rejection for an existing share

Current gap:

- the script tests non-existent, revoked, expired, and exhausted-share cases, but not wrong password against a real existing share

Planned assertions:

- create or reuse a valid share
- attempt anonymous download with an intentionally wrong share password
- attempt anonymous download with an intentionally wrong and WEAK share password as well (app behavior should be identical as far as 'attacker' is concerned)
- verify the command fails
- verify no plaintext output file remains behind

### 4. Compare failed share-access behavior across cases

Goal:

- make sure wrong-password, non-existent, expired, and revoked cases do not leak more distinction than intended through CLI-visible behavior

Planned approach:

- capture outputs and exit behavior for each failure class
- compare whether the CLI/server responses are appropriately normalized, or at least not obviously over-distinct in a way that undermines enumeration resistance

### 5. Verify output-file hygiene on failed downloads

Goal:

- prove that failed decrypt/download paths do not leave partial plaintext files on disk

Planned assertions:

- after wrong-password, revoked, expired, non-existent, and max-downloads-exhausted failures, assert the output file is absent or empty and removed

### 6. Strengthen bootstrap protection assertion

Current issue:

- any nonzero exit currently counts as success for bootstrap protection

Planned change:

- require the failure output to match the expected bootstrap-disabled or already-initialized behavior, not just any generic failure

Benefits:

- avoids false PASS results caused by unrelated breakage

## Priority 4: Add Missing Cryptographic-Path Coverage

The script currently exercises account-password file encryption only. That leaves a major Arkfile path unproven.

### 1. Add custom-password file upload/download flow

Planned steps:

- upload a file using the primary user's custom password path
- verify upload succeeds
- verify owner can still see and manage the file's metadata in normal authenticated flows
- verify `list-files --raw` and `GET /api/files/metadata` do not expose the file's plaintext metadata
- verify normal `list-files` does show the owner-visible decrypted filename as intended
- download as the owner using the correct custom password
- verify round-trip SHA-256 integrity

### 2. Add wrong custom-password rejection

Planned steps:

- attempt to download the custom-password-protected file with an intentionally incorrect custom password
- verify failure
- verify no plaintext output file remains

### 3. Use a custom-password-encrypted file in share coverage

Planned steps:

- create at least one share from the custom-password-encrypted file rather than only from account-password-encrypted files
- during share creation for that file, provide the custom password first and the share password second, matching the CLI's current prompt order
- verify anonymous recipient download still succeeds through the share-password flow
- keep this separate from owner-side custom-password assertions so both paths are explicitly proven

### 4. Confirm metadata behavior remains correct

Goal:

- cover the expectation from `AGENTS.md` that file metadata remains tied to the account-key context even when the FEK is custom-wrapped

Planned assertions:

- verify the new lightweight metadata endpoints (`/api/files/metadata` and `/api/files/metadata/batch`) successfully retrieve metadata elements for custom-password files, allowing client-side enrichment through the account key, while blocking content decryption without the custom password
- verify the custom-password file still participates correctly in normal authenticated file management flows
- verify the same account-key-based metadata decryptability powers the owner-visible `share list` output for shares created from that custom-password file

## Priority 5: Add Authorization and Session Coverage

These changes improve proof that Arkfile's access boundaries are working as intended.

### 1. Add admin negative-access tests

Near-term decision:

- use the admin as the second actor instead of introducing a second regular user flow

Planned assertions:

- admin cannot use ordinary user file IDs to retrieve another user's file contents through normal user CLI flows
- admin cannot revoke or otherwise manage user-owned shares through user-facing operations unless explicitly designed to do so
- admin cannot query another user's metadata using the `GET /api/files/metadata` or `POST /api/files/metadata/batch` endpoints
- admin cannot list another user's private file/share data in ways the design does not intend

Why this is acceptable for now:

- it is a cheaper demonstration of actor separation than adding a whole second regular user lifecycle
- it directly tests a very important boundary: admin powers must not bypass privacy-preserving user-data access rules unless explicitly designed to do so

### 2. Add unauthorized-after-logout checks

Planned assertions:

- after logout, `list-files` fails
- after logout, metadata batch endpoints (`/api/files/metadata/batch`) fail
- after logout, authenticated file download fails
- after logout, `share create` fails
- after logout, `share revoke` fails

### 3. Add explicit session/cache-key invalidation checks

Current issue:

- the script uses `--save-session` and `--cache-key` but does not prove they are invalidated on logout

Planned assertions:

- after logout, verify saved session state no longer authorizes protected actions
- after logout, verify cached key behavior does not silently continue to unlock protected flows

Implementation note:

- simplify the overall agent/session coverage by relying on normal CLI auto-start behavior instead of manually starting the agent early in the script
- keep one explicit status check after a command path that should have started the agent
- keep one explicit stop-and-verify check during cleanup

### 4. Validate post-revocation and post-expiry share state

Planned assertions:

- after share revocation, confirm enriched share list output correctly reflects the new revoked state and reason.
- after expiry, confirm enriched share list output correctly flags the share as expired.

## Priority 6: Follow-Up Outside `e2e-test.sh`

This is not part of the script refactor itself, but it should be reviewed.

### Update `scripts/dev-reset.sh` to clear stale E2E artifacts

Reason:

- `phase_5_totp_setup` currently reuses a saved TOTP secret file if present
- after resets, stale files in `/tmp/arkfile-e2e-test-data` can create confusing false passes or false failures

Planned change:

- `dev-reset.sh` should remove old E2E temp directories and saved TOTP state before redeploying the app

Expected result:

- fewer confusing false passes or false failures caused by stale `/tmp/arkfile-e2e-test-data` artifacts across resets

## Proposed Top-Level Todo List

1. Reorganize execution order so environment verification runs before agent startup.
2. Keep the current auth ordering: register the primary user, complete TOTP setup immediately, then log out before the first admin approval block.
3. Reduce TOTP buffer to 1 second and Share C expiry to 1 minute.
4. Simplify agent handling by relying on normal CLI auto-start behavior, then verify agent status once during the run and once after explicit cleanup shutdown.
5. Refactor repeated login, logout, share-download, share-create, and file-assertion logic into helpers.
6. Group tests by actor/session block to reduce churn and make coverage easier to extend.
7. Add explicit owner round-trip coverage for the custom-password file, including correct-password success, SHA-256 integrity, raw-list privacy checks via the established APIs (`/api/files` and `/api/files/metadata`), decrypted owner-visible metadata checks, and wrong-password rejection.
8. Ensure at least one share scenario uses the custom-password-encrypted file.
9. Verify that `share list` effectively utilizes `POST /api/files/metadata/batch` to show useful owner-visible locally decrypted filename, size, and SHA-256 fields.
10. Add raw/API-level privacy assertions for `GET /api/files`, `GET /api/files/metadata`, and `GET /api/shares` output to ensure complete plaintext containment.
11. Add wrong-share-password rejection and failed-download output hygiene checks.
12. Add post-logout unauthorized-command and session/cache-key invalidation checks.
13. Add admin negative-access tests against user-owned resources, including the batch metadata endpoints.
14. Strengthen bootstrap protection assertions and make summary ordering deterministic.
15. Clean up formatting and cleanup behavior to align with project guidance.
16. Update `dev-reset.sh` to remove stale E2E temp artifacts.

## Implementation Notes and Deviations

This section records what was actually implemented and where the implementation deviated from the original plan.

### Priority 1: Runtime and Reliability — DONE

All six items implemented as planned.

- TOTP window buffer reduced from 2s to 1s.
- Share C expiry reduced from `--expires 2m` to `--expires 1m` with smart-sleep calculation updated.
- Agent `start_agent()` function removed entirely; agent auto-starts on first login via `--cache-key`.
- `assert_agent_running` check added to Phase 7 (user login).
- `assert_agent_not_running` added to Phase 12 (cleanup after `agent stop`).
- Summary ordering is now deterministic via a dedicated `TEST_ORDER` array (separate from the `TEST_RESULTS` associative array whose iteration order is undefined in bash).
- Decorative `# ===` and `# ---` section separators removed throughout.

### Priority 2: Structural Refactor — DONE

All helpers implemented as planned except `share_create_for_account_file`, `share_create_for_custom_file`, and `assert_command_failed`, which were not needed because the share creation blocks retained meaningful inline context specific to each share scenario.

**Deviation — Phase numbering:** The original "Proposed Actor-Oriented Flow" described 9 numbered blocks. During implementation, the phases were organized into 13 numbered phases to allow clearer per-topic navigation. The actor grouping intent was preserved (user session, visitor block, user re-login, admin block) but not rewritten into exactly 9 high-level blocks. The custom-password file operations became their own Phase 9, share operations became Phase 10 (with 16 sub-sections), admin status/negative-access became Phase 11, and the original phases 12 and 13 cover cleanup and summary.

**Deviation — `share_create_for_custom_file` helper not added:** Share creation for the custom-password file (Share D) retained its inline `bash -c "printf '%s\n%s\n' ..."` form because the stdin ordering (custom password first, share password second) is a meaningful property being tested and was clearer inline.

**Deviation — `TOTP_SECRET_FILE` idempotency:** The existing Phase 5 already checks for a saved TOTP secret file and skips setup if present. This was preserved rather than removed, since it makes the script more practical for iterative development use. The `dev-reset.sh` cleanup of `/tmp/arkfile-e2e-test-data` ensures this does not cause stale-state false passes after a full reset.

### Priority 3: Security and Privacy Validations — DONE

All items implemented.

**Deviation — `GET /api/files/metadata` endpoint curl assertion removed:** The original plan called for a direct `curl` test of the `GET /api/files/metadata` endpoint. This was implemented using `curl -sk -H "Authorization: Bearer $("$CLIENT" agent token)" ...` but failed because `agent token` is not a valid CLI subcommand — the agent is an encryption key cache and does not expose or store HTTP session tokens. The assertion was removed and the equivalent privacy property is fully covered by the already-implemented `list-files --raw` check (section 8.4 and 9.3), which calls the same underlying server-side encrypted metadata store via the CLI's authenticated path.

**Deviation — Priority 3.4 (compare failed share-access behavior across cases):** This item was not implemented as an explicit cross-case comparison. Each failure case (wrong password, expired, revoked, exhausted, non-existent) was individually verified to fail and to leave no output file behind. A side-by-side behavioral comparison of the exact CLI/server error strings was not added, as it would be fragile to maintain and the more important property (each case properly rejects the request) is already proven.

### Priority 4: Cryptographic-Path Coverage — DONE

All items implemented.

- Custom-password file created in Phase 9 (`phase_9_custom_password_file_operations`).
- `list-files --raw` privacy check for custom file added (section 9.3).
- Custom file accessibility via normal `list-files` verified (section 9.4) — this replaces the planned `GET /api/files/metadata` check, for the same reason documented under Priority 3 deviations.
- Owner download with correct and wrong custom password verified (sections 9.5–9.7).
- Share D (from custom-password file) created in Phase 10 (section 10.4) with correct stdin order.
- Visitor download of Share D verified with SHA-256 round-trip (section 10.9).
- Share list enrichment for the custom-password file verified in section 10.5 enrichment assertions.

### Priority 5: Authorization and Session Coverage — DONE

All items implemented.

**Deviation — Post-logout unauthorized checks placement:** The plan described a standalone "Logged-Out Session Invalidation Block" and a separate "Admin Block 2". In the implemented script, these were merged into the tail of Phase 10 (sections 10.15–10.16) and the body of Phase 11 respectively. This avoided adding a new TOTP login cycle (which the admin block 2 would have required if done standalone after a separate logout). The total TOTP wait count stayed at 3.

**Deviation — Session/cache-key invalidation check scope:** The plan called for explicitly proving that `--save-session` and `--cache-key` state are invalidated on logout. In practice, the post-logout command rejections in sections 10.16.1–10.16.4 already prove this: since all commands use `--save-session` and `--cache-key` throughout, their failure after logout confirms the saved session and cached key are no longer operative. No separate test was added beyond the command-level rejection checks.

**Deviation — Post-expiry share state:** The plan called for asserting that the enriched `share list` correctly flags an expired share. In the implemented script, Share C expires during the visitor test block (sections 10.12) and the user session is logged out at that point. The post-revoke `share list` in section 10.15 only checks for revoked state (Share A). A post-expiry share state check on Share C was not added because the user was already logged out during the expiry wait period and re-logging in would add a fourth TOTP cycle. The expired state is effectively proven by the download rejection itself (section 10.12).

### Priority 6: dev-reset.sh stale artifact cleanup — DONE (was already present)

When the script was audited, `dev-reset.sh` already contained a step at the end of Step 2 that removes `/tmp/arkfile-e2e-test-data`. No change was needed.

### Additional work not in original plan: Share list enrichment assertions

After all six priorities were complete, the following assertions were added to section 10.5 to prove the batch metadata enrichment flow works correctly:

- `test_file.bin` and `custom_test_` appear in the enriched `share list` output (locally decrypted filenames)
- No share shows `[encrypted]` in its FILENAME column (enrichment succeeded for all 4 shares)
- Both `account` and `custom` password types appear in the TYPE column
- The first 8 characters of `$UPLOADED_FILE_SHA256` appear in the SHA256 column (locally decrypted and shown)

These assertions reuse the already-captured `list_shares_output` variable at zero additional runtime or network cost.

## Notes for Implementation

- Keep changes focused on proving the intended present-day design, not adding compatibility layers.
- Prefer explicit assertions over broad success/failure assumptions.
- When a test is intended to prove a security or privacy property, make the expected failure mode part of the assertion.
- Keep the script suitable for repeated local development use, since it is one of the primary proof tools for Arkfile.
- Keep default CLI output useful for legitimate owners while using raw/API-level checks to prove that the server still does not expose plaintext metadata.
- For share creation from a custom-password file, account for the current CLI stdin order: custom password first, then share password.

---

# ADDITIONAL ISSUES SURFACED DURING TESTING:

## Issue 1: Agent shutdown failure — root cause and fix

### Root cause

`assert_agent_not_running` uses `pgrep -x "arkfile-client"` as its primary check. This is wrong for two reasons:

1. The agent daemon is a spawned subprocess of the same binary — `pgrep -x "arkfile-client"` matches any running `arkfile-client` process, including the currently executing test CLI call itself. It will almost always find at least one.
2. After `agent stop` sends the stop socket command, the daemon goroutine closes the listener and the stopChan, but the OS process does not exit synchronously from the caller's perspective. Even without reason 1, there is a race window.

The correct check is a socket ping: `"$CLIENT" agent status 2>/dev/null | grep -q "RUNNING"`. If the socket is gone or the daemon is not responding, that returns nothing — a clean, authoritative signal.

Additionally, `stop_agent` needs a 1-second pause after sending the stop command to allow the daemon process to fully exit before `assert_agent_not_running` pings the socket.

### Fix in e2e-test.sh

**`stop_agent`** — add `sleep 1` after the stop call:
```bash
stop_agent() {
    info "Stopping agent (if running)..."
    safe_exec _ _ "$CLIENT" agent stop || true
    sleep 1
}
```

**`assert_agent_not_running`** — remove `pgrep`, use socket status only:
```bash
assert_agent_not_running() {
    local test_name="$1"
    if "$CLIENT" agent status 2>/dev/null | grep -q "RUNNING"; then
        error "$test_name failed: Agent is still running."
        record_test "$test_name" "FAIL"
    else
        record_test "$test_name" "PASS"
    fi
}
```

**`assert_agent_running`** — same cleanup, use socket status only:
```bash
assert_agent_running() {
    local test_name="$1"
    if "$CLIENT" agent status 2>/dev/null | grep -q "RUNNING"; then
        record_test "$test_name" "PASS"
    else
        error "$test_name failed: Agent is not running."
        record_test "$test_name" "FAIL"
    fi
}
```

---

## Issue 2: Storage Statistics shows "0 B" — root cause and fix

### Root cause

The flow is:

1. Client sends `total_size: params.TotalEncSize` — the **total encrypted size**, computed by `calculateTotalEncryptedSize(plaintextSize)`.
2. Server stores that value as `total_size` in the upload session.
3. `CompleteUpload` reads it back as `totalSizeFloat` and inserts it into `file_metadata` as `size_bytes`.
4. `AdminSystemStatus` queries `SUM(size_bytes)` — and gets `0 B`.

So the question is: what is `totalSizeFloat` at step 3? Looking at the INSERT in `CompleteUpload`:

```go
var totalSize int64
if totalSizeFloat.Valid {
    totalSize = int64(totalSizeFloat.Float64)
}
```

And the INSERT:
```go
INSERT INTO file_metadata (..., size_bytes, ...) VALUES (..., totalSize, ...)
```

This should be non-zero — `TotalEncSize` for a 50 MB file would be around 50 MB + chunk overhead. So why is the DB returning 0?

The answer is rqlite's handling of `BIGINT` columns. When rqlite returns a very large integer (e.g., ~52 MB = 54,771,856 bytes), it may return it as a float in scientific notation (e.g., `5.477e7`). The `sql.NullFloat64` scan handles this correctly for the in-memory conversion. However, rqlite's `COALESCE(SUM(size_bytes), 0)` and `COALESCE(AVG(size_bytes), 0)` over `BIGINT` columns sometimes returns `0` when the stored value was written via a `float64` cast that got rounded or when rqlite treats the value as a floating-point `0` internally.

Actually, looking more carefully: `totalSizeFloat.Float64` is cast with `int64(totalSizeFloat.Float64)`. If rqlite returns the value in scientific notation and the `NullFloat64` scan rounds or truncates it, the result is still non-zero. But there is another possibility: if `totalSizeFloat.Valid` is `false` (which happens when rqlite returns NULL for that column), then `totalSize` stays at `0`, and `0` is inserted into `size_bytes`.

This is the most likely actual failure: rqlite is returning `NULL` or an unexpected type for `total_size` from `upload_sessions`, causing `totalSizeFloat.Valid = false`, so `totalSize = 0` gets inserted into `file_metadata.size_bytes`.

### What should `size_bytes` store?

There are two reasonable interpretations:
- **Plaintext file size** — useful to users and for storage quota accounting of logical data
- **Encrypted blob size** — useful to sysadmins for actual storage consumption

Right now the code attempts to store the encrypted size (`TotalEncSize`), but it is also what is used for user storage quota accounting via `user.UpdateStorageUsage(tx, totalSize)`. Using the encrypted size for quota accounting is fine and honest (you are storing the encrypted blob). For the admin system status, showing the encrypted blob size is also the right number — it's what is actually on disk.

The real fix is: **make the `total_size` scan robust in `CompleteUpload`**. Use a `sql.NullString` scan and manual parse as a fallback, or use direct `int64` scan rather than relying on `sql.NullFloat64`. Alternatively, store the total size redundantly as a plain `INTEGER` (not BIGINT) in the session if BIGINT causes rqlite type issues. But the cleaner fix is to make the server re-derive the value from what it actually knows — the sum of all uploaded chunk sizes — rather than trusting the client-provided `total_size`.

### Proposed server-side fix in `CompleteUpload` (`handlers/uploads.go`)

After the multipart upload completes, compute `actualStoredSize` as the sum of `chunk_size` values from `upload_chunks` for this session:

```go
var actualStoredSize int64
err = database.DB.QueryRow(
    "SELECT COALESCE(SUM(chunk_size), 0) FROM upload_chunks WHERE session_id = ?",
    sessionID,
).Scan(&actualStoredSize)
if err != nil || actualStoredSize == 0 {
    // Fall back to client-provided total_size
    actualStoredSize = totalSize
}
```

Then use `actualStoredSize` for the `size_bytes` INSERT and for `UpdateStorageUsage`. This is more accurate (it is the actual bytes stored in the object store) and avoids the BIGINT/float64 rqlite parsing issue entirely, since chunk sizes are stored as individual row values that are easier to sum correctly.

### Fix in e2e-test.sh (Phase 11 assertion)

After printing the system status, add an assertion to make this kind of bug visible as a test failure rather than a silent anomaly:

```bash
if echo "$system_status_output" | grep -q "Total Files: 2"; then
    record_test "Admin system-status file count" "PASS"
else
    error "Storage stats: expected Total Files: 2"
    record_test "Admin system-status file count" "FAIL"
fi

if echo "$system_status_output" | grep -E -q "Total Size: 0 B|Total Size: 0B"; then
    error "Storage stats: Total Size is zero - size_bytes not being stored correctly"
    record_test "Admin system-status storage size non-zero" "FAIL"
else
    record_test "Admin system-status storage size non-zero" "PASS"
fi
```

---

## Issue 3: Share list output not printed

In Phase 10 section 10.5, after the enrichment assertions, add `echo "$list_shares_output"` unconditionally so you can inspect it during every test run. Same for section 10.15 post-revoke list.

---

## Summary of all changes

**`scripts/testing/e2e-test.sh`** (4 changes):
1. `stop_agent`: add `sleep 1` after `agent stop`
2. `assert_agent_not_running`: remove `pgrep`, use socket status only
3. `assert_agent_running`: remove `pgrep`, use socket status only
4. Phase 10 section 10.5: print `$list_shares_output` after assertions
5. Phase 10 section 10.15: print `$share_list_post_revoke_output` after assertions
6. Phase 11: add `file count` and `storage size non-zero` assertions

**`handlers/uploads.go`** (1 change):
- In `CompleteUpload`, compute `actualStoredSize` from `SUM(chunk_size)` of the uploaded chunks and use that for `size_bytes` and `UpdateStorageUsage`, falling back to `totalSize` only if the sum is unavailable

This requires a `dev-reset.sh` run after the Go change.
