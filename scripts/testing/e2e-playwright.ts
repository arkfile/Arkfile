/**
 * Playwright E2E Frontend Test Spec
 *
 * Exercises the Arkfile web frontend against a live local server,
 * mirroring the functional coverage of scripts/testing/e2e-test.sh.
 *
 * Architecture note:
 *   Most authenticated tests run on a SINGLE shared page (login through share
 *   list, share revocation, billing, and logout). This is critical because the
 *   Account Key cache uses a two-part design:
 *   - Part 1 (AES-GCM ciphertext) lives in sessionStorage
 *   - Part 2 (ephemeral wrapping key) lives in JS heap memory
 *   If we close the page and open a new one, Part 2 is lost and every
 *   file operation would prompt for the account password again.
 *   By staying on one page throughout, the wrapping key remains alive.
 *
 * Anonymous visitor tests (anonymous share download and share access controls)
 * use isolated browser contexts. Share revocation and logout reuse the shared page.
 *
 * A separate describe block runs one isolated registration flow (new browser
 * context): register → TOTP → 25 MB custom-password round trip → revoke-all.
 * That flow requires e2e-test.sh to have enabled auto-approval beforehand.
 *
 * Prerequisites:
 *   - Server deployed via scripts/dev-reset.sh
 *   - scripts/testing/e2e-test.sh has run (test user exists, approved, MFA configured;
 *     require_approval=false via run_enable_auto_approval)
 *   - Environment variables set by scripts/testing/e2e-playwright.sh
 *
 * Run via: sudo bash scripts/testing/e2e-playwright.sh
 */

import { test, expect, type Page, type Download, type BrowserContext } from '@playwright/test';
import { execFileSync, execSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// ============================================================================
// Environment Variables (set by e2e-playwright.sh)
// ============================================================================

const SERVER_URL = process.env.SERVER_URL || 'https://localhost:8443';
const MFA_SECRET = process.env.MFA_SECRET!;
const TEST_FILE_PATH = process.env.TEST_FILE_PATH!;
const TEST_FILE_SHA256 = process.env.TEST_FILE_SHA256!;
const TEST_FILE_NAME = process.env.TEST_FILE_NAME!;
const CUSTOM_FILE_PATH = process.env.CUSTOM_FILE_PATH!;
const CUSTOM_FILE_SHA256 = process.env.CUSTOM_FILE_SHA256!;
const CUSTOM_FILE_NAME = process.env.CUSTOM_FILE_NAME!;
const TEST_USERNAME = process.env.TEST_USERNAME!;
const TEST_PASSWORD = process.env.TEST_PASSWORD!;
const CUSTOM_FILE_PASSWORD = process.env.CUSTOM_FILE_PASSWORD!;
const SHARE_A_PASSWORD = process.env.SHARE_A_PASSWORD!;
const SHARE_B_PASSWORD = process.env.SHARE_B_PASSWORD!;
const SHARE_C_PASSWORD = process.env.SHARE_C_PASSWORD!;
const PLAYWRIGHT_TEMP_DIR = process.env.PLAYWRIGHT_TEMP_DIR!;
const REG_FLOW_FILE_PATH = process.env.REG_FLOW_FILE_PATH!;
const REG_FLOW_FILE_SHA256 = process.env.REG_FLOW_FILE_SHA256!;
const REG_FLOW_FILE_NAME = process.env.REG_FLOW_FILE_NAME!;
const REG_FLOW_USERNAME = process.env.REG_FLOW_USERNAME!;
const REG_FLOW_PASSWORD = process.env.REG_FLOW_PASSWORD!;
const REG_FLOW_CUSTOM_PASSWORD = process.env.REG_FLOW_CUSTOM_PASSWORD!;
const CLIENT_BIN = '/opt/arkfile/bin/arkfile-client';

// Directories
const DOWNLOADS_DIR = join(PLAYWRIGHT_TEMP_DIR, 'downloads');

// ============================================================================
// Shared State (carried between sequential tests)
// ============================================================================

let shareAUrl = '';
let shareBUrl = '';
let shareCUrl = '';
let shareAId = '';

// ============================================================================
// Helper Functions
// ============================================================================

function logStep(context: string, message: string) {
  console.log(`[i] [${context}] ${message}`);
}

/**
 * Attaches console listener to forward browser logs to stdout.
 * Should only be called once per page (not called for every test).
 */
function attachConsoleListener(page: Page, label: string) {
  page.on('console', msg => {
    const type = msg.type();
    if (type === 'error' || type === 'warning' || type === 'log' || type === 'info') {
      console.log(`[browser:${type}] [${label}] ${msg.text()}`);
    }
  });
}

/**
 * Wait for the next TOTP time window to avoid replay rejection.
 * Same logic as e2e-test.sh wait_for_totp_window: sleep until (30 - seconds_into_window + 1).
 */
async function waitForMfaWindow(context: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const secondsIntoWindow = now % 30;
  const secondsToWait = 30 - secondsIntoWindow + 1;
  logStep(context, `Waiting ${secondsToWait}s for next TOTP window...`);
  await new Promise((resolve) => setTimeout(resolve, secondsToWait * 1000));
}

/**
 * Generate a TOTP code using arkfile-client CLI for an arbitrary secret.
 * Must be called AFTER waitForMfaWindow().
 *
 * UI "manual entry" secrets are space-grouped (e.g. "ABCD EFGH ..."); strip
 * whitespace and pass via argv so the full base32 secret reaches the CLI.
 */
function generateTotpCode(secret: string, context: string): string {
  const normalized = secret.replace(/\s+/g, '');
  if (normalized.length < 16) {
    throw new Error(`TOTP secret too short after normalization (len=${normalized.length})`);
  }
  const output = execFileSync(
    CLIENT_BIN,
    ['generate-totp', '--secret', normalized],
    { encoding: 'utf-8', timeout: 10_000 },
  ).trim();
  if (!/^\d{6}$/.test(output)) {
    throw new Error(`generate-totp returned unexpected output: ${output}`);
  }
  logStep(context, `Generated TOTP code: ${output}`);
  return output;
}

/**
 * Generate a TOTP code for the shared e2e-test.sh MFA secret.
 * Must be called AFTER waitForMfaWindow().
 */
function generateMfaCode(context: string): string {
  return generateTotpCode(MFA_SECRET, context);
}

/**
 * Compute SHA-256 hex digest of a file.
 */
function computeSha256(filePath: string): string {
  const data = readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Perform the full login flow on the given page: OPAQUE auth + MFA (TOTP) + cache opt-in.
 * After this returns, the Account Key wrapping key is live in the page's JS heap.
 */
async function performLogin(page: Page, context: string): Promise<void> {
  logStep(context, 'Navigating to app and initiating login...');
  await page.goto(SERVER_URL);

  await page.waitForSelector('#login-btn', { state: 'visible', timeout: 15_000 });
  await page.click('#login-btn');

  await page.waitForSelector('#login-username', { state: 'visible', timeout: 10_000 });
  await page.fill('#login-username', TEST_USERNAME);
  await page.fill('#login-password', TEST_PASSWORD);

  logStep(context, 'Submitting OPAQUE authentication...');
  await page.click('#login-submit-btn');

  await page.waitForSelector('#totp-login-code', { state: 'visible', timeout: 60_000 });

  await waitForMfaWindow(context);
  const totpCode = generateMfaCode(context);

  await page.fill('#totp-login-code', totpCode);

  logStep(context, 'Verifying TOTP code...');
  await page.waitForSelector('#verify-totp-login:not([disabled])', { timeout: 5_000 });
  await page.click('#verify-totp-login');

  logStep(context, 'Opting into Account Key cache (Argon2id derivation running)...');
  await page.waitForSelector('#cache-optin-ok-btn', { state: 'visible', timeout: 120_000 });
  await page.click('#cache-optin-ok-btn');

  await page.waitForSelector('#file-section', { state: 'visible', timeout: 120_000 });
  logStep(context, 'Login complete -- file section visible, Account Key cached in JS heap');
}

/**
 * Checks if a specific filename is already present in the UI file list.
 */
async function fileExistsInList(page: Page, filename: string): Promise<boolean> {
  return await page.evaluate((name) => {
    const items = document.querySelectorAll('.file-item .file-info strong');
    for (const item of items) {
      if (item.textContent === name) return true;
    }
    return false;
  }, filename);
}

/**
 * Extract share ID from a share URL.
 * URL format: https://localhost:8443/shared/{shareId}
 */
function extractShareId(shareUrl: string): string {
  const parts = shareUrl.split('/');
  return parts[parts.length - 1];
}

/**
 * Save a Playwright Download to disk and return the file path.
 */
async function saveDownload(download: Download, filename: string): Promise<string> {
  const savePath = join(DOWNLOADS_DIR, filename);
  await download.saveAs(savePath);
  return savePath;
}

/**
 * Find a file item in the file list by filename text content.
 */
function findFileItem(page: Page, filename: string) {
  return page.locator('.file-item').filter({
    has: page.locator('.file-info strong', { hasText: filename }),
  });
}

/**
 * Click a button (Download or Share) within a specific file item.
 */
async function clickFileAction(page: Page, filename: string, buttonText: string): Promise<void> {
  const fileItem = findFileItem(page, filename);
  await fileItem.locator('.file-actions button', { hasText: buttonText }).click();
}

// ============================================================================
// Validate Environment
// ============================================================================

test.beforeAll(() => {
  const required = [
    'MFA_SECRET', 'TEST_FILE_PATH', 'TEST_FILE_SHA256', 'TEST_FILE_NAME',
    'CUSTOM_FILE_PATH', 'CUSTOM_FILE_SHA256', 'CUSTOM_FILE_NAME',
    'TEST_USERNAME', 'TEST_PASSWORD', 'CUSTOM_FILE_PASSWORD',
    'SHARE_A_PASSWORD', 'SHARE_B_PASSWORD', 'SHARE_C_PASSWORD',
    'PLAYWRIGHT_TEMP_DIR',
  ];
  for (const key of required) {
    if (!process.env[key]) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }

  if (!existsSync(TEST_FILE_PATH)) {
    throw new Error(`Test file not found: ${TEST_FILE_PATH}`);
  }
  if (!existsSync(CUSTOM_FILE_PATH)) {
    throw new Error(`Custom test file not found: ${CUSTOM_FILE_PATH}`);
  }

  execSync(`mkdir -p "${DOWNLOADS_DIR}"`);

  console.log('[OK] Environment validated');
  console.log(`[i] Server: ${SERVER_URL}`);
  console.log(`[i] User: ${TEST_USERNAME}`);
  console.log(`[i] Test file: ${TEST_FILE_NAME} (${TEST_FILE_SHA256.substring(0, 16)}...)`);
  console.log(`[i] Custom file: ${CUSTOM_FILE_NAME} (${CUSTOM_FILE_SHA256.substring(0, 16)}...)`);
});

// ============================================================================
// Sequential tests (single shared page for authenticated flows)
// ============================================================================

test.describe.serial('Arkfile Playwright E2E', () => {

  // Single shared page for authenticated tests.
  // Account Key wrapping key stays alive in JS heap as long as this page lives.
  let sharedPage: Page;
  let sharedContext: BrowserContext;

  test.beforeAll(async ({ browser }) => {
    sharedContext = await browser.newContext({
      baseURL: SERVER_URL,
      ignoreHTTPSErrors: true,
    });
    sharedPage = await sharedContext.newPage();
    attachConsoleListener(sharedPage, 'shared');
  });

  test.afterAll(async () => {
    await sharedContext.close();
  });

  // Login
  // --------------------------------------------------------------------------
  test('Login (OPAQUE + MFA + cache opt-in)', async () => {
    await performLogin(sharedPage, 'login');

    await expect(sharedPage.locator('#filesList')).toBeVisible({ timeout: 15_000 });
    // Wait a beat for the digest cache to populate from the files API response
    await sharedPage.waitForTimeout(1500);

    console.log('[OK] Login successful, Account Key cached in page heap');
  });

  // --------------------------------------------------------------------------
  // Account-password upload
  // --------------------------------------------------------------------------
  test('Upload file with account password', async () => {
    if (await fileExistsInList(sharedPage, TEST_FILE_NAME)) {
      throw new Error(
        `Unexpected state: ${TEST_FILE_NAME} already in file list. Run after a fresh dev-reset + e2e-test.sh.`,
      );
    }

    logStep('account-upload', `Uploading ${TEST_FILE_NAME}...`);
    await sharedPage.setInputFiles('#fileInput', TEST_FILE_PATH);
    await expect(sharedPage.locator('#useAccountPassword')).toBeChecked();
    await sharedPage.click('#upload-file-btn');

    logStep('account-upload', 'Waiting for upload success message (timeout: 180s)...');
    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('uploaded successfully');
      },
      { timeout: 180_000 },
    );
    logStep('account-upload', 'Upload success message detected');

    // Give the app a moment to refresh the file list automatically
    await sharedPage.waitForTimeout(3000);

    // Belt-and-suspenders: if the file doesn't appear in the list (e.g. refresh failed), reload
    let appeared = await fileExistsInList(sharedPage, TEST_FILE_NAME);
    if (!appeared) {
      logStep('account-upload', 'File not in list after upload success -- reloading page to refresh file list...');
      await sharedPage.reload({ waitUntil: 'networkidle' });
      await sharedPage.waitForSelector('#file-section', { state: 'visible', timeout: 30_000 });
      await sharedPage.waitForTimeout(2000);
    }

    await sharedPage.waitForFunction(
      (filename) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return true;
        }
        return false;
      },
      TEST_FILE_NAME,
      { timeout: 30_000 },
    );

    logStep('account-upload', `File ${TEST_FILE_NAME} found in file list`);
    const fileItem = findFileItem(sharedPage, TEST_FILE_NAME);
    await expect(fileItem.locator('.encryption-type')).toContainText('Account Password');

    console.log('[OK] Account-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Account-password download and SHA-256 integrity
  // --------------------------------------------------------------------------
  test('Download file and verify SHA-256 integrity', async () => {
    const fileItem = findFileItem(sharedPage, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    logStep('account-download', `Downloading ${TEST_FILE_NAME}...`);
    const downloadPromise = sharedPage.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(sharedPage, TEST_FILE_NAME, 'Download');

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'account_password_download.bin');

    logStep('account-download', 'Download complete, verifying SHA-256...');
    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    console.log(`[OK] Account-password download integrity verified (SHA-256: ${actualHash.substring(0, 16)}...)`);
  });

  // --------------------------------------------------------------------------
  // Duplicate upload rejection
  // --------------------------------------------------------------------------
  test('Duplicate upload rejection', async () => {
    await expect(findFileItem(sharedPage, TEST_FILE_NAME)).toBeVisible({ timeout: 60_000 });

    logStep('duplicate-upload', `Attempting duplicate upload of ${TEST_FILE_NAME}...`);
    await sharedPage.setInputFiles('#fileInput', TEST_FILE_PATH);
    await sharedPage.click('#upload-file-btn');

    logStep('duplicate-upload', 'Waiting for duplicate error message...');
    await sharedPage.waitForFunction(
      () => document.body.innerText.toLowerCase().includes('duplicate file detected'),
      { timeout: 30_000 },
    );

    console.log('[OK] Duplicate upload correctly rejected');
  });

  // --------------------------------------------------------------------------
  // File deletion via UI
  // --------------------------------------------------------------------------
  test('File deletion via Delete button', async () => {
    const deleteFileName = 'pw_delete_test.bin';
    const deleteFilePath = join(PLAYWRIGHT_TEMP_DIR, deleteFileName);

    // Generate a small throwaway file inline
    logStep('file-deletion', `Generating ${deleteFileName} for deletion test...`);
    execSync(`${CLIENT_BIN} generate-test-file --filename "${deleteFilePath}" --size 1024 --pattern random`, {
      timeout: 10_000,
    });

    // Upload it via the browser UI
    logStep('file-deletion', `Uploading ${deleteFileName}...`);
    await sharedPage.setInputFiles('#fileInput', deleteFilePath);
    await expect(sharedPage.locator('#useAccountPassword')).toBeChecked();
    await sharedPage.click('#upload-file-btn');

    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('uploaded successfully');
      },
      { timeout: 180_000 },
    );
    logStep('file-deletion', 'Delete-test file uploaded');

    await sharedPage.waitForTimeout(3000);

    // Ensure file appears in list (reload if needed)
    let appeared = await fileExistsInList(sharedPage, deleteFileName);
    if (!appeared) {
      await sharedPage.reload({ waitUntil: 'networkidle' });
      await sharedPage.waitForSelector('#file-section', { state: 'visible', timeout: 30_000 });
      await sharedPage.waitForTimeout(2000);
    }

    await sharedPage.waitForFunction(
      (filename: string) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return true;
        }
        return false;
      },
      deleteFileName,
      { timeout: 30_000 },
    );

    // Verify the Delete button exists on this file
    const deleteFileItem = findFileItem(sharedPage, deleteFileName);
    const deleteBtn = deleteFileItem.locator('.file-actions button.danger-button', { hasText: 'Delete' });
    await expect(deleteBtn).toBeVisible({ timeout: 5_000 });
    logStep('file-deletion', 'Delete button found on file item');

    // Click Delete and accept the confirmation dialog
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') {
        const msg = dialog.message();
        logStep('file-deletion', `Confirmation dialog: "${msg.substring(0, 80)}..."`);
        expect(msg).toContain('Export Backup');
        await dialog.accept();
      }
    });

    logStep('file-deletion', 'Clicking Delete button...');
    await deleteBtn.click();

    // Wait for file to disappear from the list (loadFiles re-renders after deletion)
    await sharedPage.waitForFunction(
      (filename: string) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return false;
        }
        return true;
      },
      deleteFileName,
      { timeout: 15_000 },
    );

    sharedPage.removeAllListeners('dialog');

    // Verify file is truly gone
    const stillExists = await fileExistsInList(sharedPage, deleteFileName);
    expect(stillExists).toBe(false);

    logStep('file-deletion', `File ${deleteFileName} deleted and removed from list`);
    console.log('[OK] File deletion via UI verified');
  });

  // --------------------------------------------------------------------------
  // Custom-password upload
  // --------------------------------------------------------------------------
  test('Upload file with custom password', async () => {
    if (await fileExistsInList(sharedPage, CUSTOM_FILE_NAME)) {
      throw new Error(
        `Unexpected state: ${CUSTOM_FILE_NAME} already in file list. Run after a fresh dev-reset + e2e-test.sh.`,
      );
    }

    logStep('custom-upload', `Uploading ${CUSTOM_FILE_NAME} with custom password...`);
    await sharedPage.setInputFiles('#fileInput', CUSTOM_FILE_PATH);
    await sharedPage.click('#useCustomPassword');
    await sharedPage.waitForSelector('#customPasswordSection:not(.hidden)', { timeout: 5_000 });
    await sharedPage.fill('#filePassword', CUSTOM_FILE_PASSWORD);
    await sharedPage.click('#upload-file-btn');

    logStep('custom-upload', 'Waiting for upload success message (timeout: 180s)...');
    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('uploaded successfully');
      },
      { timeout: 180_000 },
    );
    logStep('custom-upload', 'Upload success message detected');

    // Give the app a moment to refresh the file list automatically
    await sharedPage.waitForTimeout(3000);

    // Belt-and-suspenders: if the file doesn't appear in the list, reload
    let customAppeared = await fileExistsInList(sharedPage, CUSTOM_FILE_NAME);
    if (!customAppeared) {
      logStep('custom-upload', 'File not in list after upload success -- reloading page...');
      await sharedPage.reload({ waitUntil: 'networkidle' });
      await sharedPage.waitForSelector('#file-section', { state: 'visible', timeout: 30_000 });
      await sharedPage.waitForTimeout(2000);
    }

    await sharedPage.waitForFunction(
      (filename) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return true;
        }
        return false;
      },
      CUSTOM_FILE_NAME,
      { timeout: 30_000 },
    );

    logStep('custom-upload', `File ${CUSTOM_FILE_NAME} found in file list`);
    const customFileItem = findFileItem(sharedPage, CUSTOM_FILE_NAME);
    await expect(customFileItem.locator('.encryption-type')).toContainText('Custom Password');

    console.log('[OK] Custom-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Custom-password download (correct and wrong password)
  // --------------------------------------------------------------------------
  test('Custom-password download (correct + wrong password)', async () => {
    const customFileItem = findFileItem(sharedPage, CUSTOM_FILE_NAME);
    await expect(customFileItem).toBeVisible({ timeout: 60_000 });

    // Correct custom password — fill in the themed password modal
    logStep('custom-download', 'Testing download with correct custom password...');

    const downloadPromise = sharedPage.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');

    // Wait for the themed password modal to appear and fill it in
    const passwordInputCorrect = sharedPage.locator('#password-modal-input');
    await passwordInputCorrect.waitFor({ state: 'visible', timeout: 15_000 });
    logStep('custom-download', 'Password modal appeared -- providing correct password');
    await passwordInputCorrect.fill(CUSTOM_FILE_PASSWORD);
    await sharedPage.locator('#password-modal-submit-btn').click();

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'custom_password_download.bin');

    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(CUSTOM_FILE_SHA256);
    console.log('[OK] Custom-password download integrity verified');

    // Wrong custom password
    logStep('custom-download', 'Testing download with wrong custom password...');

    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');

    // Wait for the themed password modal and fill in the wrong password
    const passwordInputWrong = sharedPage.locator('#password-modal-input');
    await passwordInputWrong.waitFor({ state: 'visible', timeout: 15_000 });
    logStep('custom-download', 'Password modal appeared -- providing WRONG password');
    await passwordInputWrong.fill('WrongPassword123!NotCorrect');
    await sharedPage.locator('#password-modal-submit-btn').click();

    await sharedPage.waitForSelector('[data-testid="wrong-custom-password"]', { timeout: 60_000 });

    // Dismiss the error toast we just asserted on. Error toasts have
    // duration: 0 (never auto-dismiss), so if we leave it on the page it
    // sits in #message-container and intercepts pointer events on any
    // element it overlaps -- notably #logout-link in the top-right nav,
    // which causes the anonymous share download test's logout click to time out.
    await sharedPage.evaluate(() => {
      document.querySelectorAll<HTMLButtonElement>('#message-container .toast button')
        .forEach((b) => b.click());
    });
    await sharedPage.waitForFunction(
      () => !document.querySelector('#message-container .toast'),
      { timeout: 5_000 },
    );

    console.log('[OK] Wrong custom password correctly rejected');
  });

  // --------------------------------------------------------------------------
  // Raw API privacy verification
  // --------------------------------------------------------------------------
  test('Raw API privacy verification', async () => {
    logStep('raw-api-privacy', 'Fetching /api/files raw JSON...');

    const apiResponse = await sharedPage.evaluate(async () => {
      // Tokens are now in HttpOnly cookies; use credentials:'include' to send them.
      // Also send the CSRF token from the non-HttpOnly cookie.
      const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('__Host-arkfile-csrf='));
      const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.trim().split('=').slice(1).join('=')) : '';

      const resp = await fetch('/api/files', {
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
      });
      if (!resp.ok) return { error: `HTTP ${resp.status}` };
      return resp.json();
    });

    expect(apiResponse).not.toHaveProperty('error');

    const responseStr = JSON.stringify(apiResponse);
    expect(responseStr).not.toContain(TEST_FILE_NAME);
    expect(responseStr).not.toContain(CUSTOM_FILE_NAME);
    expect(responseStr).not.toContain(TEST_FILE_SHA256);
    expect(responseStr).not.toContain(CUSTOM_FILE_SHA256);
    expect(responseStr).toContain('encrypted_filename');
    expect(responseStr).toContain('encrypted_sha256sum');

    console.log('[OK] Raw API does not expose plaintext filenames or hashes');
  });

  // --------------------------------------------------------------------------
  // Share creation (A, B, C)
  // --------------------------------------------------------------------------
  test('Create shares A (no limits), B (max_downloads=2), C (expires=1m)', async () => {
    const fileItem = findFileItem(sharedPage, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    async function createShare(
      targetFilename: string,
      password: string,
      opts: { expiryValue?: number; expiryUnit?: string; maxDownloads?: number },
    ): Promise<string> {
      await clickFileAction(sharedPage, targetFilename, 'Share');
      await sharedPage.waitForSelector('#arkfile-share-modal-overlay', { state: 'visible', timeout: 15_000 });
      await sharedPage.fill('#share-password-input', password);
      await sharedPage.fill('#share-password-confirm', password);

      if (opts.expiryValue !== undefined) {
        await sharedPage.click('#share-expiry-value');
        await sharedPage.fill('#share-expiry-value', String(opts.expiryValue));
      }
      if (opts.expiryUnit) {
        await sharedPage.selectOption('#share-expiry-unit', opts.expiryUnit);
      }
      if (opts.maxDownloads !== undefined) {
        await sharedPage.click('#share-max-downloads');
        await sharedPage.fill('#share-max-downloads', String(opts.maxDownloads));
      }

      await sharedPage.click('#share-modal-submit');

      await sharedPage.waitForSelector('#share-result-url', { state: 'visible', timeout: 120_000 });
      const shareUrl = await sharedPage.inputValue('#share-result-url');
      expect(shareUrl).toBeTruthy();
      expect(shareUrl).toContain('/shared/');

      await sharedPage.click('#share-result-done');
      await sharedPage.waitForSelector('#arkfile-share-result-overlay', { state: 'detached', timeout: 5_000 }).catch(() => {});

      return shareUrl;
    }

    logStep('share-create', 'Creating Share A (no limits)...');
    shareAUrl = await createShare(TEST_FILE_NAME, SHARE_A_PASSWORD, { expiryValue: 0, expiryUnit: 'hours', maxDownloads: 0 });
    shareAId = extractShareId(shareAUrl);
    console.log(`[OK] Share A created: ${shareAId}`);

    logStep('share-create', 'Creating Share B (max_downloads=2)...');
    shareBUrl = await createShare(TEST_FILE_NAME, SHARE_B_PASSWORD, { expiryValue: 0, expiryUnit: 'hours', maxDownloads: 2 });
    const shareBId = extractShareId(shareBUrl);
    console.log(`[OK] Share B created: ${shareBId}`);

    logStep('share-create', 'Creating Share C (expires=1m)...');
    shareCUrl = await createShare(TEST_FILE_NAME, SHARE_C_PASSWORD, { expiryValue: 1, expiryUnit: 'minutes', maxDownloads: 0 });
    const shareCId = extractShareId(shareCUrl);
    console.log(`[OK] Share C created: ${shareCId}`);

    console.log('[OK] All three shares created successfully');
  });

  // --------------------------------------------------------------------------
  // Share list verification
  // --------------------------------------------------------------------------
  test('Share list verification (decrypted metadata)', async () => {
    logStep('share-list', 'Refreshing share list...');
    await sharedPage.click('#refresh-shares-btn');
    await sharedPage.waitForSelector('.share-item', { state: 'visible', timeout: 30_000 });

    const shareItems = sharedPage.locator('.share-item');
    const count = await shareItems.count();
    expect(count).toBeGreaterThanOrEqual(3);

    const sharesText = await sharedPage.locator('#sharesList').innerText();
    expect(sharesText).toContain(TEST_FILE_NAME);
    expect(sharesText).not.toContain('[Encrypted]');
    expect(sharesText.toLowerCase()).toContain('account');
    expect(sharesText).toContain(TEST_FILE_SHA256.substring(0, 8));

    console.log('[OK] Share list shows decrypted filenames, key types, and SHA-256');
  });

  // --------------------------------------------------------------------------
  // Anonymous share download
  // --------------------------------------------------------------------------
  test('Anonymous share download (Share A)', async ({ browser }) => {
    // Defensive cleanup: dismiss any lingering toast that an earlier test
    // forgot to clear. Error toasts have duration: 0 (never auto-dismiss)
    // and #message-container is fixed-positioned in the top-right where it
    // overlaps #logout-link, so an undismissed toast will block the click
    // below. Each test is supposed to clean up its own toasts, but this
    // guard ensures anonymous share download cannot regress if a future test forgets.
    await sharedPage.evaluate(() => {
      document.querySelectorAll<HTMLButtonElement>('#message-container .toast button')
        .forEach((b) => b.click());
    });
    await sharedPage.waitForFunction(
      () => !document.querySelector('#message-container .toast'),
      { timeout: 5_000 },
    ).catch(() => {});

    // Log out on sharedPage first so shares can be tested anonymously
    logStep('anonymous-share', 'Logging out on shared page for anonymous test...');
    await sharedPage.click('#logout-link');
    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });

    // Anonymous visitor in isolated context (acceptDownloads required for blob URL downloads)
    const anonContext = await browser.newContext({
      baseURL: SERVER_URL,
      ignoreHTTPSErrors: true,
      acceptDownloads: true,
    });
    const page = await anonContext.newPage();
    attachConsoleListener(page, 'anonymous-share-anon');

    logStep('anonymous-share', `Navigating to Share A (${shareAUrl}) as anonymous...`);
    await page.goto(shareAUrl);
    await page.waitForSelector('#share-access-container', { state: 'visible', timeout: 15_000 });
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_A_PASSWORD);

    logStep('anonymous-share', 'Submitting share password...');
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    const filenameText = await page.locator('#fileNameDisplay').innerText();
    expect(filenameText).toBeTruthy();

    logStep('anonymous-share', 'Initiating anonymous download...');
    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'anonymous_share_download.bin');

    const actualHash = computeSha256(savePath);
    logStep('anonymous-share', `Downloaded ${readFileSync(savePath).length} bytes, SHA-256: ${actualHash.substring(0, 16)}...`);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    await anonContext.close();
    console.log('[OK] Anonymous share download verified (SHA-256 match)');
  });

  // --------------------------------------------------------------------------
  // Share access controls
  // --------------------------------------------------------------------------
  test('Share access controls (max downloads, expiry, non-existent)', async ({ browser }) => {
    const anonContext = await browser.newContext({ baseURL: SERVER_URL, ignoreHTTPSErrors: true });
    let page = await anonContext.newPage();
    attachConsoleListener(page, 'share-controls-anon');

    // Share C expiry (test FIRST -- Share C was created with 1-minute expiry during
    // share creation, so we must download before it expires. Testing this before
    // Share B avoids the time-consuming max_downloads test consuming the expiry window.)
    logStep('share-expiry', 'Testing Share C expiry');

    await page.goto(shareCUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_C_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    let dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'share_c_before_expiry.bin');
    console.log('[OK] Share C download before expiry succeeded');

    logStep('share-expiry', 'Waiting 65s for Share C to expire...');
    await new Promise((resolve) => setTimeout(resolve, 65_000));

    logStep('share-expiry', 'Attempting download after expiry...');
    // Server returns 403.html at page level for expired shares (before rendering shared.html).
    await page.goto(shareCUrl);
    await page.waitForSelector('[data-testid="share-expired"]', { timeout: 15_000 });
    console.log('[OK] Share C download after expiry correctly rejected');

    // Share B max_downloads=2
    // Use a fresh page to avoid stale state from Share C expiry test
    await page.close();
    page = await anonContext.newPage();
    attachConsoleListener(page, 'share-controls-anon');
    logStep('share-max-downloads', 'Testing Share B max_downloads=2');

    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'share_b_download_1.bin');
    console.log('[OK] Share B download 1/2');

    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'share_b_download_2.bin');
    console.log('[OK] Share B download 2/2');

    logStep('share-max-downloads', 'Attempting 3rd download (should fail at envelope level - share revoked after exhaustion)...');
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    // After the 2nd download the server marks the share revoked_reason='exhausted'.
    // GetShareEnvelope returns 403; share-access sets data-testid="share-max-downloads".
    await page.waitForSelector('[data-testid="share-max-downloads"]', { timeout: 30_000 });
    console.log('[OK] Share B download 3 correctly rejected (max_downloads exceeded, 403 at envelope)');

    // Non-existent share (43-char base64url format matching real share IDs)
    logStep('share-not-found', 'Testing non-existent share');
    await page.goto(`${SERVER_URL}/shared/xQ7mN9kR2pL5vB8wY1cF3hJ6tA0eG4iK9oU2sD5fW7`);
    await page.waitForSelector('[data-testid="share-not-found"]', { timeout: 30_000 });
    console.log('[OK] Non-existent share correctly shows error');

    await anonContext.close();
    console.log('[OK] All share access controls verified');
  });

  // --------------------------------------------------------------------------
  // Share revocation and contact info lifecycle
  // --------------------------------------------------------------------------
  test('Share revocation (revoke Share A, verify access denied)', async () => {
    // Re-login on sharedPage (we logged out during anonymous share download)
    logStep('share-revoke', 'Re-logging in for revocation test...');
    await performLogin(sharedPage, 'share-revoke');

    logStep('share-revoke', 'Refreshing share list...');
    await sharedPage.click('#refresh-shares-btn');
    await sharedPage.waitForSelector('.share-item', { state: 'visible', timeout: 30_000 });

    const shareAItem = sharedPage.locator(`.share-item[data-share-id="${shareAId}"]`);
    await expect(shareAItem).toBeVisible({ timeout: 10_000 });

    logStep('share-revoke', 'Revoking Share A...');
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') await dialog.accept();
    });

    await shareAItem.locator('.btn-revoke').click();

    await expect(shareAItem.locator('[data-testid="share-status-revoked"]')).toBeVisible({ timeout: 15_000 });

    console.log('[OK] Share A revoked successfully');
    sharedPage.removeAllListeners('dialog');

    // ---- Contact Info Lifecycle Tests (within current logged-in session) ----
    logStep('share-revoke', 'Contact Info: Navigating to app...');
    await sharedPage.goto(SERVER_URL);
    await sharedPage.waitForSelector('#file-section', { state: 'visible', timeout: 15_000 });

    // Open Contact Info panel
    logStep('share-revoke', 'Contact Info: Opening panel...');
    await sharedPage.click('#contact-info-toggle');
    await sharedPage.waitForSelector('#contact-info-panel', { state: 'visible', timeout: 5_000 });

    // Clean up any pre-existing contact info (e.g. left by e2e-test.sh CLI tests)
    const preExistingName = await sharedPage.inputValue('#contact-display-name');
    if (preExistingName !== '') {
      logStep('share-revoke', `Contact Info: Found pre-existing data (display_name="${preExistingName}"), deleting first...`);
      sharedPage.on('dialog', async (dialog) => {
        await dialog.accept();
      });
      await sharedPage.click('#delete-contact-info-btn');
      await sharedPage.waitForTimeout(1_000);
      sharedPage.removeAllListeners('dialog');
    }

    // Verify empty state (after cleanup)
    const cleanName = await sharedPage.inputValue('#contact-display-name');
    expect(cleanName).toBe('');
    const cleanRows = await sharedPage.locator('.contact-method-row').count();
    expect(cleanRows).toBe(0);
    console.log('[OK] Contact Info: Panel open, empty state verified');

    // Set initial contact info: display name + 1 email + notes
    logStep('share-revoke', 'Contact Info: Setting initial data (1 email)...');
    await sharedPage.fill('#contact-display-name', 'Playwright User');
    await sharedPage.click('#add-contact-method-btn');
    await sharedPage.waitForSelector('.contact-method-row', { state: 'visible', timeout: 3_000 });
    await sharedPage.selectOption('.contact-method-row:first-child .contact-type', 'email');
    await sharedPage.fill('.contact-method-row:first-child .contact-value', 'pw-test@example.com');
    await sharedPage.fill('#contact-notes', 'Initial notes');
    await sharedPage.click('#save-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);

    // Verify via API
    const ciData1 = await sharedPage.evaluate(async () => {
      const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('__Host-arkfile-csrf='));
      const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.trim().split('=').slice(1).join('=')) : '';
      const resp = await fetch('/api/user/contact-info', {
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
      });
      return resp.json();
    });
    expect(ciData1.data.has_contact_info).toBe(true);
    expect(ciData1.data.contact_info.display_name).toBe('Playwright User');
    expect(ciData1.data.contact_info.contacts.length).toBe(1);
    expect(ciData1.data.contact_info.contacts[0].type).toBe('email');
    expect(ciData1.data.contact_info.contacts[0].value).toBe('pw-test@example.com');
    expect(ciData1.data.contact_info.notes).toBe('Initial notes');
    console.log('[OK] Contact Info: Initial set verified (1 email, notes)');

    // Update: change only notes (leave email contact unchanged)
    logStep('share-revoke', 'Contact Info: Updating notes...');
    await sharedPage.fill('#contact-notes', '');
    await sharedPage.fill('#contact-notes', 'Updated notes from Playwright');
    await sharedPage.click('#save-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);

    // Verify update via API
    const ciData2 = await sharedPage.evaluate(async () => {
      const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('__Host-arkfile-csrf='));
      const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.trim().split('=').slice(1).join('=')) : '';
      const resp = await fetch('/api/user/contact-info', {
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
      });
      return resp.json();
    });
    expect(ciData2.data.contact_info.notes).toBe('Updated notes from Playwright');
    expect(ciData2.data.contact_info.contacts[0].value).toBe('pw-test@example.com');
    console.log('[OK] Contact Info: Update verified (notes changed, email unchanged)');

    // Delete contact info
    logStep('share-revoke', 'Contact Info: Deleting...');
    sharedPage.on('dialog', async (dialog) => {
      await dialog.accept();
    });
    await sharedPage.click('#delete-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);
    sharedPage.removeAllListeners('dialog');

    // Verify deletion via API
    const ciData3 = await sharedPage.evaluate(async () => {
      const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('__Host-arkfile-csrf='));
      const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.trim().split('=').slice(1).join('=')) : '';
      const resp = await fetch('/api/user/contact-info', {
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
      });
      return resp.json();
    });
    expect(ciData3.data.has_contact_info).toBe(false);
    console.log('[OK] Contact Info: Deletion verified');

    // Re-set with final contact info (1 signal contact, left in place)
    logStep('share-revoke', 'Contact Info: Re-setting final data (1 signal)...');
    await sharedPage.fill('#contact-display-name', 'Playwright User Final');
    await sharedPage.click('#add-contact-method-btn');
    await sharedPage.waitForSelector('.contact-method-row', { state: 'visible', timeout: 3_000 });
    await sharedPage.selectOption('.contact-method-row:first-child .contact-type', 'signal');
    await sharedPage.fill('.contact-method-row:first-child .contact-value', '+9876543210');
    await sharedPage.fill('#contact-notes', 'Final Playwright notes');
    await sharedPage.click('#save-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);

    // Verify final state via API
    const ciData4 = await sharedPage.evaluate(async () => {
      const csrfCookie = document.cookie.split(';').find(c => c.trim().startsWith('__Host-arkfile-csrf='));
      const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.trim().split('=').slice(1).join('=')) : '';
      const resp = await fetch('/api/user/contact-info', {
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : {},
      });
      return resp.json();
    });
    expect(ciData4.data.has_contact_info).toBe(true);
    expect(ciData4.data.contact_info.display_name).toBe('Playwright User Final');
    expect(ciData4.data.contact_info.contacts.length).toBe(1);
    expect(ciData4.data.contact_info.contacts[0].type).toBe('signal');
    expect(ciData4.data.contact_info.contacts[0].value).toBe('+9876543210');
    expect(ciData4.data.contact_info.notes).toBe('Final Playwright notes');
    console.log('[OK] Contact Info: Final re-set verified (1 signal contact left in place)');

    console.log('[OK] Contact info lifecycle tests passed');
    // ---- End Contact Info Tests ----

    // Log out and verify Share A is denied
    await sharedPage.click('#logout-link');
    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });

    logStep('share-revoke', 'Verifying access denied to revoked Share A...');
    await sharedPage.goto(shareAUrl);
    await sharedPage.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await sharedPage.fill('#sharePassword', SHARE_A_PASSWORD);
    await sharedPage.click('#shareAccessForm button[type="submit"]');

    await sharedPage.waitForSelector('[data-testid="share-revoked"]', { timeout: 30_000 });

    console.log('[OK] Revoked share correctly denied access');
  });

  // ── Billing Panel ──────────────────────────────────────────────────────────
  // Requires:
  //   - The shared page has been logged in earlier in the describe block.
  //   - e2e-test.sh run_billing (and run_payments) have already run, so the
  //     test user has gift, usage, and possibly payment rows in credit_transactions.
  //
  // This test opens the Billing panel, verifies the DOM layout produced by
  // client/static/js/src/ui/billing.ts.
  // --------------------------------------------------------------------------
  test('Billing panel renders balance, usage grid, and transaction history', async () => {
    // Share revocation test ends with a logout (to verify revoked share access).
    // Re-login here so we have a valid session for the billing panel test.
    // The logout test detects this session is live and skips its own
    // re-login, so no extra login/logout cycles are added to the total.
    logStep('billing', 'Re-logging in for billing panel test (share revocation ended with logout)...');
    await performLogin(sharedPage, 'billing');

    // Open the Billing panel by clicking the nav link.
    await sharedPage.click('#billing-toggle');

    // Wait for the panel to become visible.
    await sharedPage.waitForSelector('#billing-panel:not(.hidden)', { timeout: 5000 });

    // Wait for the loading placeholder to be replaced by real content.
    // (billing.ts replaces innerHTML='<p>Loading...</p>' with sections once the
    // /api/credits response arrives.)
    await sharedPage.waitForSelector('.billing-panel-section', { timeout: 10000 });

    // ── Balance ─────────────────────────────────────────────────────────────
    const balanceEl = await sharedPage.$('.billing-balance-amount');
    expect(balanceEl).not.toBeNull();

    const balanceText = await balanceEl!.innerText();
    // Must match $X.XXXX or -$X.XXXX (four decimal places, signed USD).
    expect(balanceText).toMatch(/^-?\$\d+\.\d{4}$/);

    console.log(`[OK] Billing balance displays: ${balanceText}`);

    // ── Current storage and cost grid ───────────────────────────────────
    const usageGrid = await sharedPage.$('.billing-usage-grid');
    expect(usageGrid).not.toBeNull();

    // These three labels are always present regardless of whether the user is
    // above or below the free baseline. 'Your projected cost' and 'Estimated
    // runway' are conditional (only rendered when billable_bytes > 0).
    const labels = await sharedPage.$$eval(
      '.billing-usage-grid dt',
      (els: Element[]) => els.map((el: Element) => el.textContent?.trim() ?? '')
    );
    expect(labels).toContain('Storage used');
    expect(labels).toContain('Free baseline');
    expect(labels).toContain('Billable usage');

    console.log('[OK] Billing usage grid labels:', labels);

    // ── Transaction history ─────────────────────────────────────────────
    // run_billing wrote >=1 gift row and >=1 usage row, so the table must
    // contain both transaction types.
    const txTable = await sharedPage.$('.billing-tx-table');
    expect(txTable).not.toBeNull();

    const txTypes = await sharedPage.$$eval(
      '.billing-tx-table tbody tr td:nth-child(2)',
      (cells: Element[]) => cells.map((c: Element) => c.textContent?.trim() ?? '')
    );
    expect(txTypes).toContain('gift');
    expect(txTypes).toContain('usage');

    console.log('[OK] Transaction types in table:', txTypes);

    // ── Negative-balance red highlighting ───────────────────────────────
    // At least one amount cell should carry the .negative CSS class (usage rows
    // debit from the balance, so amount_usd_microcents < 0).
    const negCount = await sharedPage.$$eval(
      '.billing-tx-amount.negative',
      (els: Element[]) => els.length
    );
    expect(negCount).toBeGreaterThan(0);

    console.log(`[OK] ${negCount} negative-amount cell(s) rendered in red`);

    // Close the panel (click the Billing toggle again).
    await sharedPage.click('#billing-toggle');

    console.log('[OK] Billing panel test complete');
  });

  test('Billing top-up modal creates invoice and embeds checkout iframe', async () => {
    await sharedPage.route('**/api/billing/invoice', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            invoice_id: 'inv_playwright_test',
            checkout_url: 'http://localhost:3000/checkout/inv_playwright_test',
            provider: 'btcpay',
          },
        }),
      });
    });

    await sharedPage.click('#billing-toggle');
    await sharedPage.waitForSelector('#billing-panel:not(.hidden)', { timeout: 5000 });
    await sharedPage.waitForSelector('.billing-panel-section', { timeout: 10000 });

    const topUpBtn = sharedPage.locator('button:has-text("Top Up Balance")');
    await expect(topUpBtn, 'Top Up Balance must be present when billing/payments are enabled in dev-reset').toBeVisible({
      timeout: 10_000,
    });

    await topUpBtn.click();
    await sharedPage.waitForSelector('#topup-form', { timeout: 5000 });
    await sharedPage.fill('#topup-amount-input', '10.00');
    await sharedPage.click('button:has-text("Generate Invoice")');

    await sharedPage.waitForSelector('#arkfile-topup-modal-overlay iframe', { timeout: 10000 });
    const iframeSrc = await sharedPage.getAttribute('#arkfile-topup-modal-overlay iframe', 'src');
    expect(iframeSrc).toContain('checkout/inv_playwright_test');

    await sharedPage.click('#arkfile-topup-modal-overlay .password-modal-close');
    await sharedPage.unroute('**/api/billing/invoice');
    console.log('[OK] Billing top-up modal and checkout iframe test complete');
  });

  test('External-tab checkout return opens billing panel and confirms paid invoice', async () => {
    const testInvoiceID = 'inv_playwright_return';

    await sharedPage.route(`**/api/billing/invoice/${testInvoiceID}`, async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            invoice_id: testInvoiceID,
            status: 'paid',
            amount_usd_microcents: 1000000000,
            provider: 'btcpay',
          },
        }),
      });
    });

    await sharedPage.goto(`/?success=true&invoice=${testInvoiceID}`, { waitUntil: 'networkidle' });

    await sharedPage.waitForSelector('#billing-panel:not(.hidden)', { timeout: 15000 });
    await sharedPage.waitForSelector('.billing-panel-section', { timeout: 15000 });

    const urlAfter = sharedPage.url();
    expect(urlAfter).not.toContain('success=true');
    expect(urlAfter).not.toContain(`invoice=${testInvoiceID}`);

    await sharedPage.unroute(`**/api/billing/invoice/${testInvoiceID}`);
    console.log('[OK] Billing checkout return test complete');
  });

  // --------------------------------------------------------------------------
  // Logout and post-logout security checks
  // --------------------------------------------------------------------------
  test('Logout and post-logout security checks', async () => {
    // The billing panel test (immediately above) leaves the page logged in.
    // Skip the re-login if the session is still valid so we don't add an
    // extra login/logout cycle. Tokens are in HttpOnly cookies; check the
    // non-HttpOnly CSRF cookie to detect an active session.
    const alreadyLoggedIn = await sharedPage.evaluate(() =>
      document.cookie.split(';').some(c => c.trim().startsWith('__Host-arkfile-csrf='))
    );
    if (!alreadyLoggedIn) {
      logStep('logout', 'Re-logging in for logout test...');
      await performLogin(sharedPage, 'logout');
    } else {
      logStep('logout', 'Session still live from billing test -- skipping re-login');
    }

    logStep('logout', 'Clicking logout...');
    await sharedPage.click('#logout-link');

    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });
    await expect(sharedPage.locator('.home-container')).toBeVisible();

    logStep('logout', 'Verifying session and cache cleanup...');

    // After logout, the CSRF cookie (non-HttpOnly, visible to JS) must be gone.
    // The full JWT and refresh cookies are HttpOnly so JS cannot read them, but
    // the server clears them via Set-Cookie: ...; Max-Age=0 on logout.
    const hasCsrfCookie = await sharedPage.evaluate(() =>
      document.cookie.split(';').some(c => c.trim().startsWith('__Host-arkfile-csrf='))
    );
    expect(hasCsrfCookie).toBe(false);

    // Regression guards: session tokens must not be stored in localStorage
    // (auth uses HttpOnly cookies). Fail if either key reappears.
    const hasToken = await sharedPage.evaluate(() =>
      localStorage.getItem('token') !== null
    );
    expect(hasToken).toBe(false);

    const hasRefreshToken = await sharedPage.evaluate(() =>
      localStorage.getItem('refresh_token') !== null
    );
    expect(hasRefreshToken).toBe(false);

    // Account key cache parts live in sessionStorage (cleared by clearAllSessionData)
    const hasCacheData = await sharedPage.evaluate(() => {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && (key.includes('arkfile') || key.includes('account') || key.includes('digest'))) {
          return true;
        }
      }
      return false;
    });
    expect(hasCacheData).toBe(false);

    // A request with an invalid bearer header (no cookie) must return 401.
    const apiStatus = await sharedPage.evaluate(async () => {
      try {
        const resp = await fetch('/api/files', {
          headers: { Authorization: 'Bearer invalid-token-12345' },
        });
        return resp.status;
      } catch {
        return 0;
      }
    });
    expect(apiStatus).toBe(401);

    console.log('[OK] Logout verified -- CSRF cookie cleared, localStorage clean, API returns 401');
  });

});

// ============================================================================
// Isolated registration flow (separate browser context / Account Key heap)
// ============================================================================

test.describe.serial('Arkfile Playwright registration flow', () => {
  test.beforeAll(() => {
    const required = [
      'REG_FLOW_FILE_PATH', 'REG_FLOW_FILE_SHA256', 'REG_FLOW_FILE_NAME',
      'REG_FLOW_USERNAME', 'REG_FLOW_PASSWORD', 'REG_FLOW_CUSTOM_PASSWORD',
      'PLAYWRIGHT_TEMP_DIR',
    ];
    for (const key of required) {
      if (!process.env[key]) {
        throw new Error(`Missing required environment variable: ${key}`);
      }
    }
    if (!existsSync(REG_FLOW_FILE_PATH)) {
      throw new Error(`Registration-flow test file not found: ${REG_FLOW_FILE_PATH}`);
    }
    execSync(`mkdir -p "${DOWNLOADS_DIR}"`);
    console.log('[OK] Registration-flow environment validated');
    console.log(`[i] Reg user: ${REG_FLOW_USERNAME}`);
    console.log(`[i] Reg file: ${REG_FLOW_FILE_NAME} (${REG_FLOW_FILE_SHA256.substring(0, 16)}...)`);
  });

  test('Register, TOTP, 25 MB custom upload, verify, revoke-all', async ({ browser }) => {
    test.setTimeout(600_000);

    const context = await browser.newContext({
      baseURL: SERVER_URL,
      ignoreHTTPSErrors: true,
      acceptDownloads: true,
    });
    const page = await context.newPage();
    attachConsoleListener(page, 'reg-flow');

    // 1. Register new unique user
    logStep('reg-flow', `Registering user ${REG_FLOW_USERNAME}...`);
    await page.goto(SERVER_URL);
    await page.waitForSelector('#login-btn', { state: 'visible', timeout: 15_000 });
    await page.click('#get-started-btn');
    await page.waitForSelector('#register-form:not(.hidden)', { timeout: 15_000 });
    await page.fill('#register-username', REG_FLOW_USERNAME);
    await page.fill('#register-password', REG_FLOW_PASSWORD);
    await page.fill('#register-password-confirm', REG_FLOW_PASSWORD);
    await page.click('#register-submit-btn');

    // 2. MFA method picker (if shown) then TOTP setup + confirm
    logStep('reg-flow', 'Waiting for MFA enrollment UI...');
    await page.waitForSelector('#mfa-pick-totp, #totp-reg-secret', { timeout: 120_000 });
    if (await page.locator('#mfa-pick-totp').isVisible().catch(() => false)) {
      await page.click('#mfa-pick-totp');
    }
    await page.waitForSelector('#totp-reg-secret', { state: 'visible', timeout: 60_000 });
    const totpSecret = (await page.locator('#totp-reg-secret').innerText()).trim();
    expect(totpSecret.length).toBeGreaterThan(10);
    logStep('reg-flow', `TOTP secret captured (${totpSecret.substring(0, 4)}...)`);

    await page.waitForSelector('#totp-setup-code', { state: 'visible', timeout: 15_000 });
    await waitForMfaWindow('reg-flow');
    const totpCode = generateTotpCode(totpSecret, 'reg-flow');
    await page.fill('#totp-setup-code', totpCode);
    await page.waitForSelector('#complete-totp-setup:not([disabled])', { timeout: 5_000 });

    const verifyResponsePromise = page.waitForResponse(
      (res) => res.url().includes('/api/mfa/verify') && res.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await page.click('#complete-totp-setup');
    const verifyResponse = await verifyResponsePromise;
    if (!verifyResponse.ok()) {
      const body = await verifyResponse.text().catch(() => '');
      throw new Error(
        `TOTP setup verify failed: HTTP ${verifyResponse.status()} ${body.slice(0, 300)}`,
      );
    }

    // Auto-approval (set by e2e-test.sh run_enable_auto_approval) yields authenticated file section.
    // Unapproved users land on pending-approval instead — fail clearly if that happens.
    logStep('reg-flow', 'Waiting for authenticated file section after TOTP...');
    const postTotp = await Promise.race([
      page.waitForSelector('#file-section', { state: 'visible', timeout: 120_000 }).then(() => 'file' as const),
      page.waitForSelector('#pending-approval-section', { state: 'visible', timeout: 120_000 }).then(() => 'pending' as const),
    ]);
    if (postTotp === 'pending') {
      throw new Error(
        'Registration completed but user is pending approval; ensure e2e-test.sh enabled require_approval=false',
      );
    }
    console.log('[OK] Registration + TOTP complete; file section visible');

    // 3. Custom-password upload of 25 MB fixture
    logStep('reg-flow', `Uploading ${REG_FLOW_FILE_NAME} (25 MB) with custom password...`);
    await page.setInputFiles('#fileInput', REG_FLOW_FILE_PATH);
    await page.click('#useCustomPassword');
    await page.waitForSelector('#customPasswordSection:not(.hidden)', { timeout: 5_000 });
    await page.fill('#filePassword', REG_FLOW_CUSTOM_PASSWORD);
    await page.click('#upload-file-btn');

    // Account Key prompt (no cache yet after registration)
    const accountPwInput = page.locator('#password-modal-input');
    await accountPwInput.waitFor({ state: 'visible', timeout: 30_000 });
    logStep('reg-flow', 'Account Key password modal appeared -- providing account password');
    await accountPwInput.fill(REG_FLOW_PASSWORD);
    await page.locator('#password-modal-submit-btn').click();

    logStep('reg-flow', 'Waiting for 25 MB upload success (timeout: 360s)...');
    await page.waitForFunction(
      () => document.body.innerText.toLowerCase().includes('uploaded successfully'),
      { timeout: 360_000 },
    );
    logStep('reg-flow', 'Upload success message detected');

    await page.waitForTimeout(3000);
    let appeared = await fileExistsInList(page, REG_FLOW_FILE_NAME);
    if (!appeared) {
      logStep('reg-flow', 'File not in list after upload -- reloading...');
      await page.reload({ waitUntil: 'networkidle' });
      await page.waitForSelector('#file-section', { state: 'visible', timeout: 30_000 });
      // Re-enter account password if reload cleared the heap wrapping key
      const rePrompt = page.locator('#password-modal-input');
      if (await rePrompt.isVisible({ timeout: 5_000 }).catch(() => false)) {
        await rePrompt.fill(REG_FLOW_PASSWORD);
        await page.locator('#password-modal-submit-btn').click();
        await page.waitForTimeout(2000);
      }
    }

    await page.waitForFunction(
      (name: string) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === name) return true;
        }
        return false;
      },
      REG_FLOW_FILE_NAME,
      { timeout: 60_000 },
    );
    const regFileItem = findFileItem(page, REG_FLOW_FILE_NAME);
    await expect(regFileItem.locator('.encryption-type')).toContainText('Custom Password');
    console.log('[OK] Registration-flow 25 MB custom-password upload complete');

    // 4. Download / decrypt / verify SHA-256
    logStep('reg-flow', 'Downloading and decrypting with custom password...');
    const downloadPromise = page.waitForEvent('download', { timeout: 360_000 });
    await clickFileAction(page, REG_FLOW_FILE_NAME, 'Download');

    await page.locator('#password-modal-input').waitFor({ state: 'visible', timeout: 60_000 });
    // First modal may be Account Key (if cache lost) or custom file password
    const modalTitle = await page.locator('#password-modal-title').innerText();
    if (/account key/i.test(modalTitle)) {
      logStep('reg-flow', 'Account Key required before custom decrypt');
      await page.locator('#password-modal-input').fill(REG_FLOW_PASSWORD);
      await page.locator('#password-modal-submit-btn').click();
      await page.locator('#password-modal-input').waitFor({ state: 'visible', timeout: 60_000 });
    }
    logStep('reg-flow', 'Providing custom password for decrypt');
    await page.locator('#password-modal-input').fill(REG_FLOW_CUSTOM_PASSWORD);
    await page.locator('#password-modal-submit-btn').click();

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'reg_flow_download.bin');
    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(REG_FLOW_FILE_SHA256);
    console.log(`[OK] Registration-flow download integrity verified (SHA-256: ${actualHash.substring(0, 16)}...)`);

    // 5. Revoke all sessions and assert protected UI requires re-login
    logStep('reg-flow', 'Opening Security Settings and revoking all sessions...');
    // Toasts / download-integrity panel share the nav overlay stack; wait for
    // toasts to clear, then open Security Settings (which hides the integrity panel).
    await page.locator('#message-container .toast').waitFor({ state: 'detached', timeout: 15_000 }).catch(() => {});
    await page.click('#security-settings-toggle');
    await page.waitForSelector('#security-settings:not(.hidden)', { timeout: 10_000 });
    await expect(page.locator('#download-integrity-panel')).toBeHidden();
    await page.click('#revoke-sessions-btn');

    await page.waitForSelector('.home-container:not(.hidden)', { state: 'visible', timeout: 30_000 });
    await expect(page.locator('.home-container')).toBeVisible();
    await expect(page.locator('#app-container')).toBeHidden();

    const apiStatus = await page.evaluate(async () => {
      try {
        const resp = await fetch('/api/files', { credentials: 'include' });
        return resp.status;
      } catch {
        return 0;
      }
    });
    expect(apiStatus).toBe(401);

    // Login UI must be required again (not auto-authenticated)
    await page.click('#login-btn');
    await page.waitForSelector('#login-form:not(.hidden)', { timeout: 15_000 });
    await expect(page.locator('#login-username')).toBeVisible();
    await expect(page.locator('#file-section')).toBeHidden();

    console.log('[OK] Revoke-all forced re-login; protected UI inaccessible');
    await context.close();
  });
});
