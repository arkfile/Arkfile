# Better E2E Plan for `scripts/testing/e2e-test.sh`

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
- run raw/API-level share-list checks for privacy expectations
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
- verify admin cannot access ordinary user-owned file/share resources in ways the design should forbid
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

- use `list-files --raw` to verify the raw server-returned data does not expose original plaintext filename or SHA-256 metadata
- use normal `list-files` to verify the owner can still see locally decrypted filename information as intended
- verify no raw encryption envelope data or other obviously sensitive internals leak into the raw output

Note:

- the exact assertion should match the intended UX of the CLI, not a guess

### 2. Validate `share list` output for privacy expectations

Goal:

- make `share list` useful to owners while still proving raw server-side privacy properties

Planned assertions:

- improve default `arkfile-client share list` so it fetches owner share records, then fetches file metadata for each `file_id`, then locally decrypts and displays useful owner-visible fields
- display server-visible share-management fields on the left and locally decrypted owner-visible file metadata on the right
- include original filename, original size, and original SHA-256 in that owner-visible section
- clearly indicate that those fields are locally decrypted / client-side derived values
- verify default `share list` shows those useful locally decrypted values for both an account-password shared file and a custom-password shared file
- add a 'key type' or 'type' field to indicate which type of password was used by the owner for encryption originally: account or custom
- separately verify the raw/API-level share list data does not expose plaintext filename, plaintext SHA-256, share password, custom password, or share-envelope contents
- once code changes are made to the arkfile-client for the improved `share list` command the developer will redeploy with `dev-reset.sh` prior to re-running `e2e-test.sh`

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
- verify `list-files --raw` does not expose the file's plaintext metadata
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

- verify the custom-password file still participates correctly in normal authenticated file management flows
- verify the owner can view/list that file with normal account-authenticated operations even though file-content decryption still requires the custom password
- verify the same account-key-based metadata decryptability also enables enriched owner-visible `share list` output for shares created from that custom-password file

## Priority 5: Add Authorization and Session Coverage

These changes improve proof that Arkfile's access boundaries are working as intended.

### 1. Add admin negative-access tests

Near-term decision:

- use the admin as the second actor instead of introducing a second regular user flow

Planned assertions:

- admin cannot use ordinary user file IDs to retrieve another user's file contents through normal user CLI flows
- admin cannot revoke or otherwise manage user-owned shares through user-facing operations unless explicitly designed to do so
- admin cannot list another user's private file/share data in ways the design does not intend

Why this is acceptable for now:

- it is a cheaper demonstration of actor separation than adding a whole second regular user lifecycle
- it directly tests a very important boundary: admin powers must not bypass privacy-preserving user-data access rules unless explicitly designed to do so

### 2. Add unauthorized-after-logout checks

Planned assertions:

- after logout, `list-files` fails
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

- after share revocation, confirm share list or management output reflects the new state if that state is supposed to be visible
- after expiry, confirm share list or management output reflects expiration if supported by the CLI output

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
7. Add explicit owner round-trip coverage for the custom-password file, including correct-password success, SHA-256 integrity, raw-list privacy checks, decrypted owner-visible metadata checks, and wrong-password rejection.
8. Ensure at least one share scenario uses the custom-password-encrypted file.
9. Improve default `share list` so it shows useful owner-visible locally decrypted filename, size, and SHA-256 fields for shared files.
10. Add raw/API-level privacy assertions for `list-files` and `share list` output.
11. Add wrong-share-password rejection and failed-download output hygiene checks.
12. Add post-logout unauthorized-command and session/cache-key invalidation checks.
13. Add admin negative-access tests against user-owned resources.
14. Strengthen bootstrap protection assertions and make summary ordering deterministic.
15. Clean up formatting and cleanup behavior to align with project guidance.
16. Update `dev-reset.sh` to remove stale E2E temp artifacts.

## Notes for Implementation

- Keep changes focused on proving the intended present-day design, not adding compatibility layers.
- Prefer explicit assertions over broad success/failure assumptions.
- When a test is intended to prove a security or privacy property, make the expected failure mode part of the assertion.
- Keep the script suitable for repeated local development use, since it is one of the primary proof tools for Arkfile.
- Keep default CLI output useful for legitimate owners while using raw/API-level checks to prove that the server still does not expose plaintext metadata.
- For share creation from a custom-password file, account for the current CLI stdin order: custom password first, then share password.