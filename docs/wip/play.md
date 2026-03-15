# Playwright E2E Frontend Test Plan

## Overview

A Playwright-based frontend E2E test that exercises the web frontend (`client/static/`) against
a live local server at `https://localhost:8443`, mirroring the functional coverage of
`scripts/testing/e2e-test.sh`.

## Architecture

**Two deliverables:**

1. `scripts/testing/e2e-playwright.sh` -- Bash wrapper that handles TOTP generation, test file
   creation, environment setup, Playwright invocation, and cleanup.
2. `scripts/testing/e2e-playwright.ts` -- The Playwright test spec (TypeScript, run via
   `bunx playwright test`).

**Supporting files:**

3. `playwright.config.ts` -- Playwright configuration (self-signed TLS, base URL, downloads dir).

## Prerequisites

- Server deployed locally via `scripts/dev-reset.sh`
- `scripts/testing/e2e-test.sh` has already run successfully (test user exists, is approved,
  has TOTP configured)
- TOTP secret available at `/tmp/arkfile-e2e-test-data/totp-secret`
- `bun` available as runtime
- Playwright installed: `bun add -d @playwright/test` + `bunx playwright install chromium`

## Test Credentials

- Username: `arkfile-dev-test-user`
- Password: `MyVacation2025PhotosForFamily!ExtraSecure`
- TOTP secret: read from `/tmp/arkfile-e2e-test-data/totp-secret`
- Custom file password: `Tr0pic@lSunset2025!SecureCustomKey`
- Share passwords: `MyShareP@ssw0rd-789q&*(::1` (A), `::2` (B), `::3` (C)

## Bash Wrapper Responsibilities (e2e-playwright.sh)

1. Verify server is running (`curl -sk https://localhost:8443/health`)
2. Verify TOTP secret file exists
3. Generate two test files:
   - `test_upload.txt` (account-password file, ~1KB with known content)
   - `custom_upload.txt` (custom-password file, ~1KB with different content)
4. Compute SHA-256 of each test file
5. Export environment variables for Playwright
6. Run `bunx playwright test scripts/testing/e2e-playwright.ts`
7. Clean up temp files
8. Report results

## Environment Variables (bash -> Playwright)

| Variable | Description |
|---|---|
| `TOTP_SECRET` | Test user TOTP secret from `/tmp/arkfile-e2e-test-data/totp-secret` |
| `TEST_FILE_PATH` | Path to account-password test file |
| `TEST_FILE_SHA256` | SHA-256 hex of the test file |
| `CUSTOM_FILE_PATH` | Path to custom-password test file |
| `CUSTOM_FILE_SHA256` | SHA-256 hex of the custom test file |
| `TEST_USERNAME` | `arkfile-dev-test-user` |
| `TEST_PASSWORD` | Account password |
| `CUSTOM_FILE_PASSWORD` | Custom file password |
| `SHARE_A_PASSWORD` | Share A password (no limits) |
| `SHARE_B_PASSWORD` | Share B password (max downloads=2) |
| `SHARE_C_PASSWORD` | Share C password (expires 1m) |
| `SERVER_URL` | `https://localhost:8443` |

## Test Phases (mirroring e2e-test.sh)

### Phase 1: Login

1. Navigate to `https://localhost:8443`
2. Click `#login-btn`
3. Fill `#login-username` and `#login-password`
4. Click `#login-submit-btn`
5. Wait for TOTP modal (`#totp-login-code` to appear)
6. Generate TOTP code via `execSync('arkfile-client generate-totp --secret ...')`
   after calling `waitForTotpWindow()`
7. Type 6-digit code into `#totp-login-code`
8. Click `#verify-totp-login`
9. Handle cache opt-in modal: click `#cache-optin-ok-btn`
10. Verify `#file-section` becomes visible

### Phase 2: File Upload (Account Password)

1. `page.setInputFiles('#fileInput', testFilePath)`
2. Verify `#useAccountPassword` is checked
3. Click `#upload-file-btn`
4. Wait for success message and file appearing in `#filesList`
5. Verify filename appears in `.file-item .file-info strong`

### Phase 3: File Download + Integrity

1. Set up download listener: `page.waitForEvent('download')`
2. Click the "Download" button for the uploaded file
3. Save downloaded file to temp directory
4. Compute SHA-256 of downloaded file, compare with `TEST_FILE_SHA256`

### Phase 4: Duplicate Upload Rejection

1. `page.setInputFiles('#fileInput', testFilePath)` (same file)
2. Click `#upload-file-btn`
3. Wait for error message containing "Duplicate" or "duplicate"

### Phase 5: Custom-Password Upload

1. `page.setInputFiles('#fileInput', customFilePath)`
2. Click `#useCustomPassword` radio
3. Fill `#filePassword` with custom password
4. Click `#upload-file-btn`
5. Wait for success, verify file appears in list

### Phase 6: Custom-Password Download

1. Click Download for the custom-password file
2. Handle `prompt()` dialog with correct password
3. Verify download integrity (SHA-256)
4. Click Download again, handle `prompt()` with wrong password
5. Verify error message appears

### Phase 7: Raw API Privacy

1. `page.evaluate()` to call `fetch('/api/files')` with JWT from sessionStorage
2. Verify response JSON does NOT contain plaintext filenames or SHA-256 hashes
3. Verify encrypted fields are present

### Phase 8: Share Creation

For shares A (no limits), B (max_downloads=2), C (expires=1m):
1. Click "Share" button for the target file
2. Wait for share modal `#arkfile-share-modal-overlay`
3. Fill `#share-password-input` and `#share-password-confirm`
4. Set `#share-expiry-value` and `#share-expiry-unit` as appropriate
5. Set `#share-max-downloads` if needed
6. Click submit (`#share-modal-submit`)
7. Wait for result modal, extract URL from `#share-result-url`
8. Click `#share-result-done`
9. Store share URLs for later phases

### Phase 9: Share List Verification

1. Click `#refresh-shares-btn`
2. Wait for `#sharesList` to populate with `.share-item` elements
3. Verify decrypted filenames appear (no `[Encrypted]`)
4. Verify key types (account/custom) present
5. Verify SHA-256 prefix visible in `.hash-value` elements

### Phase 10: Anonymous Share Download

1. Click `#logout-link` to log out
2. Navigate to Share A URL
3. Wait for `#share-access-container`
4. Enter share password in `#sharePassword`
5. Submit form
6. Wait for `#fileDetails` to appear
7. Click `#downloadBtn`
8. Verify downloaded file SHA-256 matches

### Phase 11: Share Access Controls

**Max downloads (Share B):**
- Download 1/2: success
- Download 2/2: success
- Download 3: should fail (error message or no download button)

**Expiry (Share C):**
- Download before expiry: success
- Wait ~65s for expiry
- Download attempt after expiry: should fail

**Non-existent share:**
- Navigate to bogus share URL, verify error

### Phase 12: Share Revocation

1. Re-login (full OPAQUE + TOTP flow; generate fresh TOTP code mid-test)
2. Click `#refresh-shares-btn`
3. Find Share A, click its `.btn-revoke` button
4. Handle `confirm()` dialog (accept)
5. Verify Share A status changes to "Revoked"
6. Log out
7. Navigate to Share A URL, verify access denied

### Phase 13: Logout + Post-Logout Checks

1. After final logout, verify auth section is shown
2. `page.evaluate()` to check `sessionStorage` has no `arkfile.sessionToken`
3. `page.evaluate()` to verify no account key cache or digest cache entries
4. Attempt authenticated API fetch, verify 401 response

## Key Technical Decisions

1. **TOTP code generation mid-test**: Use `execSync()` to call
   `/opt/arkfile/bin/arkfile-client generate-totp --secret ...` from within the Playwright
   test after a `waitForTotpWindow()` helper function. This avoids needing to pre-generate
   codes in the bash wrapper.

2. **TOTP window waiting**: Port the same logic from e2e-test.sh:
   `seconds_to_wait = 30 - (current_seconds % 30) + 1`

3. **File downloads**: Use Playwright's download event API. Save to temp dir, compute SHA-256
   using `crypto.createHash('sha256')` from Node/Bun.

4. **Dialog handling**: Register `page.on('dialog')` for `prompt()` and `confirm()` dialogs
   before clicking buttons that trigger them.

5. **Self-signed TLS**: `ignoreHTTPSErrors: true` in Playwright config.

6. **Sequential execution**: All phases in a single `test.describe.serial` block to maintain
   state (session, file list, share URLs).

7. **No emojis**: Per AGENTS.md, all output uses `[OK]`, `[X]`, `[!]`, `[i]` markers.

## Files to Create/Modify

| File | Action |
|---|---|
| `docs/wip/play.md` | This plan document |
| `playwright.config.ts` | New: Playwright configuration |
| `scripts/testing/e2e-playwright.sh` | New: Bash wrapper script |
| `scripts/testing/e2e-playwright.ts` | New: Playwright test spec |
| `package.json` | Add `@playwright/test` devDependency |
