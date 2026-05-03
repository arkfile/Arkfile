/**
 * Playwright E2E Frontend Test Spec
 *
 * Exercises the Arkfile web frontend against a live local server,
 * mirroring the functional coverage of scripts/testing/e2e-test.sh.
 *
 * Architecture note:
 *   All authenticated phases (1-9, 12, 13) run on a SINGLE shared page.
 *   This is critical because the Account Key cache uses a two-part design:
 *   - Part 1 (AES-GCM ciphertext) lives in sessionStorage
 *   - Part 2 (ephemeral wrapping key) lives in JS heap memory
 *   If we close the page and open a new one, Part 2 is lost and every
 *   file operation would prompt for the account password again.
 *   By staying on one page throughout, the wrapping key remains alive.
 *
 * Only anonymous visitor tests (Phases 10, 11) use isolated contexts.
 * Phase 12 (revocation) and Phase 13 (logout) reuse the same shared page.
 *
 * Prerequisites:
 *   - Server deployed via scripts/dev-reset.sh
 *   - scripts/testing/e2e-test.sh has run (test user exists, approved, TOTP configured)
 *   - Environment variables set by scripts/testing/e2e-playwright.sh
 *
 * Run via: sudo bash scripts/testing/e2e-playwright.sh
 */

import { test, expect, type Page, type Download, type BrowserContext } from '@playwright/test';
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// ============================================================================
// Environment Variables (set by e2e-playwright.sh)
// ============================================================================

const SERVER_URL = process.env.SERVER_URL || 'https://localhost:8443';
const TOTP_SECRET = process.env.TOTP_SECRET!;
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

function logStep(phase: string, message: string) {
  console.log(`[i] [Phase ${phase}] ${message}`);
}

/**
 * Attaches console listener to forward browser logs to stdout.
 * Should only be called once per page (not called for every phase).
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
 * Wait for the next TOTP window to avoid replay rejection.
 * Same logic as e2e-test.sh: sleep until (30 - seconds_into_window + 1).
 */
async function waitForTotpWindow(phase: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const secondsIntoWindow = now % 30;
  const secondsToWait = 30 - secondsIntoWindow + 1;
  logStep(phase, `Waiting ${secondsToWait}s for next TOTP window...`);
  await new Promise((resolve) => setTimeout(resolve, secondsToWait * 1000));
}

/**
 * Generate a TOTP code using arkfile-client CLI.
 * Must be called AFTER waitForTotpWindow().
 */
function generateTotpCode(phase: string): string {
  const output = execSync(`${CLIENT_BIN} generate-totp --secret ${TOTP_SECRET}`, {
    encoding: 'utf-8',
    timeout: 10_000,
  }).trim();
  logStep(phase, `Generated TOTP code: ${output}`);
  return output;
}

/**
 * Compute SHA-256 hex digest of a file.
 */
function computeSha256(filePath: string): string {
  const data = readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Perform the full login flow on the given page: OPAQUE auth + TOTP + cache opt-in.
 * After this returns, the Account Key wrapping key is live in the page's JS heap.
 */
async function performLogin(page: Page, phase: string): Promise<void> {
  logStep(phase, 'Navigating to app and initiating login...');
  await page.goto(SERVER_URL);

  await page.waitForSelector('#login-btn', { state: 'visible', timeout: 15_000 });
  await page.click('#login-btn');

  await page.waitForSelector('#login-username', { state: 'visible', timeout: 10_000 });
  await page.fill('#login-username', TEST_USERNAME);
  await page.fill('#login-password', TEST_PASSWORD);

  logStep(phase, 'Submitting OPAQUE authentication...');
  await page.click('#login-submit-btn');

  await page.waitForSelector('#totp-login-code', { state: 'visible', timeout: 60_000 });

  await waitForTotpWindow(phase);
  const totpCode = generateTotpCode(phase);

  await page.fill('#totp-login-code', totpCode);

  logStep(phase, 'Verifying TOTP code...');
  await page.waitForSelector('#verify-totp-login:not([disabled])', { timeout: 5_000 });
  await page.click('#verify-totp-login');

  logStep(phase, 'Opting into Account Key cache (Argon2id derivation running)...');
  await page.waitForSelector('#cache-optin-ok-btn', { state: 'visible', timeout: 120_000 });
  await page.click('#cache-optin-ok-btn');

  await page.waitForSelector('#file-section', { state: 'visible', timeout: 120_000 });
  logStep(phase, 'Login complete -- file section visible, Account Key cached in JS heap');
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
    'TOTP_SECRET', 'TEST_FILE_PATH', 'TEST_FILE_SHA256', 'TEST_FILE_NAME',
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
// Test Phases (sequential, single shared page for authenticated phases)
// ============================================================================

test.describe.serial('Arkfile Playwright E2E', () => {

  // Single shared page for all authenticated phases.
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

  // --------------------------------------------------------------------------
  // Phase 1: Login
  // --------------------------------------------------------------------------
  test('Phase 1: Login (OPAQUE + TOTP + cache opt-in)', async () => {
    await performLogin(sharedPage, '1');

    await expect(sharedPage.locator('#filesList')).toBeVisible({ timeout: 15_000 });
    // Wait a beat for the digest cache to populate from the files API response
    await sharedPage.waitForTimeout(1500);

    console.log('[OK] Phase 1: Login successful, Account Key cached in page heap');
  });

  // --------------------------------------------------------------------------
  // Phase 2: File Upload (Account Password)
  // --------------------------------------------------------------------------
  test('Phase 2: Upload file with account password', async () => {
    // Idempotency check: skip if already uploaded in a previous run
    const alreadyExists = await fileExistsInList(sharedPage, TEST_FILE_NAME);
    if (alreadyExists) {
      logStep('2', `File ${TEST_FILE_NAME} already in list (idempotent run). Skipping.`);
      console.log('[OK] Phase 2: Account-password file upload (Skipped - already exists)');
      return;
    }

    logStep('2', `Uploading ${TEST_FILE_NAME}...`);
    await sharedPage.setInputFiles('#fileInput', TEST_FILE_PATH);
    await expect(sharedPage.locator('#useAccountPassword')).toBeChecked();
    await sharedPage.click('#upload-file-btn');

    logStep('2', 'Waiting for upload success message (timeout: 180s)...');
    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('uploaded successfully');
      },
      { timeout: 180_000 },
    );
    logStep('2', 'Upload success message detected');

    // Give the app a moment to refresh the file list automatically
    await sharedPage.waitForTimeout(3000);

    // Belt-and-suspenders: if the file doesn't appear in the list (e.g. refresh failed), reload
    let appeared = await fileExistsInList(sharedPage, TEST_FILE_NAME);
    if (!appeared) {
      logStep('2', 'File not in list after upload success -- reloading page to refresh file list...');
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

    logStep('2', `File ${TEST_FILE_NAME} found in file list`);
    const fileItem = findFileItem(sharedPage, TEST_FILE_NAME);
    await expect(fileItem.locator('.encryption-type')).toContainText('Account Password');

    console.log('[OK] Phase 2: Account-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 3: File Download + Integrity
  // --------------------------------------------------------------------------
  test('Phase 3: Download file and verify SHA-256 integrity', async () => {
    const fileItem = findFileItem(sharedPage, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    logStep('3', `Downloading ${TEST_FILE_NAME}...`);
    const downloadPromise = sharedPage.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(sharedPage, TEST_FILE_NAME, 'Download');

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase3_download.bin');

    logStep('3', 'Download complete, verifying SHA-256...');
    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    console.log(`[OK] Phase 3: Download integrity verified (SHA-256: ${actualHash.substring(0, 16)}...)`);
  });

  // --------------------------------------------------------------------------
  // Phase 4: Duplicate Upload Rejection
  // --------------------------------------------------------------------------
  test('Phase 4: Duplicate upload rejection', async () => {
    await expect(findFileItem(sharedPage, TEST_FILE_NAME)).toBeVisible({ timeout: 60_000 });

    logStep('4', `Attempting duplicate upload of ${TEST_FILE_NAME}...`);
    await sharedPage.setInputFiles('#fileInput', TEST_FILE_PATH);
    await sharedPage.click('#upload-file-btn');

    logStep('4', 'Waiting for duplicate error message...');
    await sharedPage.waitForFunction(
      () => {
        const body = document.body.innerText.toLowerCase();
        return body.includes('duplicate') ||
               body.includes('already uploaded') ||
               body.includes('already exists');
      },
      { timeout: 30_000 },
    );

    console.log('[OK] Phase 4: Duplicate upload correctly rejected');
  });

  // --------------------------------------------------------------------------
  // Phase 4b: File Deletion via UI
  // --------------------------------------------------------------------------
  test('Phase 4b: File deletion via Delete button', async () => {
    const deleteFileName = 'pw_delete_test.bin';
    const deleteFilePath = join(PLAYWRIGHT_TEMP_DIR, deleteFileName);

    // Generate a small throwaway file inline
    logStep('4b', `Generating ${deleteFileName} for deletion test...`);
    execSync(`${CLIENT_BIN} generate-test-file --filename "${deleteFilePath}" --size 1024 --pattern random`, {
      timeout: 10_000,
    });

    // Upload it via the browser UI
    logStep('4b', `Uploading ${deleteFileName}...`);
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
    logStep('4b', 'Delete-test file uploaded');

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
    logStep('4b', 'Delete button found on file item');

    // Click Delete and accept the confirmation dialog
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') {
        const msg = dialog.message();
        logStep('4b', `Confirmation dialog: "${msg.substring(0, 80)}..."`);
        expect(msg).toContain('Export Backup');
        await dialog.accept();
      }
    });

    logStep('4b', 'Clicking Delete button...');
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

    logStep('4b', `File ${deleteFileName} deleted and removed from list`);
    console.log('[OK] Phase 4b: File deletion via UI verified');
  });

  // --------------------------------------------------------------------------
  // Phase 5: Custom-Password Upload
  // --------------------------------------------------------------------------
  test('Phase 5: Upload file with custom password', async () => {
    const alreadyExists = await fileExistsInList(sharedPage, CUSTOM_FILE_NAME);
    if (alreadyExists) {
      logStep('5', `File ${CUSTOM_FILE_NAME} already in list. Skipping.`);
      console.log('[OK] Phase 5: Custom-password file upload (Skipped - already exists)');
      return;
    }

    logStep('5', `Uploading ${CUSTOM_FILE_NAME} with custom password...`);
    await sharedPage.setInputFiles('#fileInput', CUSTOM_FILE_PATH);
    await sharedPage.click('#useCustomPassword');
    await sharedPage.waitForSelector('#customPasswordSection:not(.hidden)', { timeout: 5_000 });
    await sharedPage.fill('#filePassword', CUSTOM_FILE_PASSWORD);
    await sharedPage.click('#upload-file-btn');

    logStep('5', 'Waiting for upload success message (timeout: 180s)...');
    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('uploaded successfully');
      },
      { timeout: 180_000 },
    );
    logStep('5', 'Upload success message detected');

    // Give the app a moment to refresh the file list automatically
    await sharedPage.waitForTimeout(3000);

    // Belt-and-suspenders: if the file doesn't appear in the list, reload
    let customAppeared = await fileExistsInList(sharedPage, CUSTOM_FILE_NAME);
    if (!customAppeared) {
      logStep('5', 'File not in list after upload success -- reloading page...');
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

    logStep('5', `File ${CUSTOM_FILE_NAME} found in file list`);
    const customFileItem = findFileItem(sharedPage, CUSTOM_FILE_NAME);
    await expect(customFileItem.locator('.encryption-type')).toContainText('Custom Password');

    console.log('[OK] Phase 5: Custom-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 6: Custom-Password Download
  // --------------------------------------------------------------------------
  test('Phase 6: Custom-password download (correct + wrong password)', async () => {
    const customFileItem = findFileItem(sharedPage, CUSTOM_FILE_NAME);
    await expect(customFileItem).toBeVisible({ timeout: 60_000 });

    // 6a: correct password — fill in the themed password modal
    logStep('6', 'Testing download with correct custom password...');

    const downloadPromise = sharedPage.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');

    // Wait for the themed password modal to appear and fill it in
    const passwordInput6a = sharedPage.locator('#password-modal-input');
    await passwordInput6a.waitFor({ state: 'visible', timeout: 15_000 });
    logStep('6', 'Password modal appeared -- providing correct password');
    await passwordInput6a.fill(CUSTOM_FILE_PASSWORD);
    await sharedPage.locator('#password-modal-submit-btn').click();

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase6_custom_download.bin');

    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(CUSTOM_FILE_SHA256);
    console.log('[OK] Phase 6a: Custom-password download integrity verified');

    // 6b: wrong password
    logStep('6', 'Testing download with wrong custom password...');

    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');

    // Wait for the themed password modal and fill in the wrong password
    const passwordInput6b = sharedPage.locator('#password-modal-input');
    await passwordInput6b.waitFor({ state: 'visible', timeout: 15_000 });
    logStep('6', 'Password modal appeared -- providing WRONG password');
    await passwordInput6b.fill('WrongPassword123!NotCorrect');
    await sharedPage.locator('#password-modal-submit-btn').click();

    await sharedPage.waitForFunction(
      () => {
        const body = document.body.innerText.toLowerCase();
        return body.includes('failed') || body.includes('error') || body.includes('incorrect') || body.includes('check your password');
      },
      { timeout: 60_000 },
    );

    console.log('[OK] Phase 6b: Wrong custom password correctly rejected');
  });

  // --------------------------------------------------------------------------
  // Phase 7: Raw API Privacy
  // --------------------------------------------------------------------------
  test('Phase 7: Raw API privacy verification', async () => {
    logStep('7', 'Fetching /api/files raw JSON...');

    const apiResponse = await sharedPage.evaluate(async () => {
      // AuthManager stores JWT in localStorage under 'token'
      const token = localStorage.getItem('token');
      if (!token) return { error: 'no token' };

      const resp = await fetch('/api/files', {
        headers: { Authorization: `Bearer ${token}` },
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

    console.log('[OK] Phase 7: Raw API does not expose plaintext filenames or hashes');
  });

  // --------------------------------------------------------------------------
  // Phase 8: Share Creation (A, B, C)
  // --------------------------------------------------------------------------
  test('Phase 8: Create shares A (no limits), B (max_downloads=2), C (expires=1m)', async () => {
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

    logStep('8', 'Creating Share A (no limits)...');
    shareAUrl = await createShare(TEST_FILE_NAME, SHARE_A_PASSWORD, { expiryValue: 0, expiryUnit: 'hours', maxDownloads: 0 });
    shareAId = extractShareId(shareAUrl);
    console.log(`[OK] Share A created: ${shareAId}`);

    logStep('8', 'Creating Share B (max_downloads=2)...');
    shareBUrl = await createShare(TEST_FILE_NAME, SHARE_B_PASSWORD, { expiryValue: 0, expiryUnit: 'hours', maxDownloads: 2 });
    const shareBId = extractShareId(shareBUrl);
    console.log(`[OK] Share B created: ${shareBId}`);

    logStep('8', 'Creating Share C (expires=1m)...');
    shareCUrl = await createShare(TEST_FILE_NAME, SHARE_C_PASSWORD, { expiryValue: 1, expiryUnit: 'minutes', maxDownloads: 0 });
    const shareCId = extractShareId(shareCUrl);
    console.log(`[OK] Share C created: ${shareCId}`);

    console.log('[OK] Phase 8: All three shares created successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 9: Share List Verification
  // --------------------------------------------------------------------------
  test('Phase 9: Share list verification (decrypted metadata)', async () => {
    logStep('9', 'Refreshing share list...');
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

    console.log('[OK] Phase 9: Share list shows decrypted filenames, key types, and SHA-256');
  });

  // --------------------------------------------------------------------------
  // Phase 10: Anonymous Share Download
  // --------------------------------------------------------------------------
  test('Phase 10: Anonymous share download (Share A)', async ({ browser }) => {
    // Log out on sharedPage first so shares can be tested anonymously
    logStep('10', 'Logging out on shared page for anonymous test...');
    await sharedPage.click('#logout-link');
    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });

    // Anonymous visitor in isolated context (acceptDownloads required for blob URL downloads)
    const anonContext = await browser.newContext({
      baseURL: SERVER_URL,
      ignoreHTTPSErrors: true,
      acceptDownloads: true,
    });
    const page = await anonContext.newPage();
    attachConsoleListener(page, '10-anon');

    logStep('10', `Navigating to Share A (${shareAUrl}) as anonymous...`);
    await page.goto(shareAUrl);
    await page.waitForSelector('#share-access-container', { state: 'visible', timeout: 15_000 });
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_A_PASSWORD);

    logStep('10', 'Submitting share password...');
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    const filenameText = await page.locator('#fileNameDisplay').innerText();
    expect(filenameText).toBeTruthy();

    logStep('10', 'Initiating anonymous download...');
    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase10_share_download.bin');

    const actualHash = computeSha256(savePath);
    logStep('10', `Downloaded ${readFileSync(savePath).length} bytes, SHA-256: ${actualHash.substring(0, 16)}...`);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    await anonContext.close();
    console.log('[OK] Phase 10: Anonymous share download verified (SHA-256 match)');
  });

  // --------------------------------------------------------------------------
  // Phase 11: Share Access Controls
  // --------------------------------------------------------------------------
  test('Phase 11: Share access controls (max downloads, expiry, non-existent)', async ({ browser }) => {
    const anonContext = await browser.newContext({ baseURL: SERVER_URL, ignoreHTTPSErrors: true });
    let page = await anonContext.newPage();
    attachConsoleListener(page, '11-anon');

    // 11a: Share C expiry (test FIRST -- Share C was created with 1-minute expiry in Phase 8,
    // so we must download before it expires. Testing this before Share B avoids the
    // time-consuming max_downloads test consuming the expiry window.)
    console.log('[i] [Phase 11a] Testing Share C expiry');

    await page.goto(shareCUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_C_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    let dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'phase11_c_dl1.bin');
    console.log('[OK] Share C download before expiry succeeded');

    logStep('11a', 'Waiting 65s for Share C to expire...');
    await new Promise((resolve) => setTimeout(resolve, 65_000));

    logStep('11a', 'Attempting download after expiry...');
    // Server returns 403 at page level for expired shares (before rendering shared.html)
    // so the password form never appears -- verify the error/expired response directly
    await page.goto(shareCUrl);
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('expired') || text.includes('forbidden') ||
               text.includes('error') || text.includes('403');
      },
      { timeout: 15_000 },
    );
    console.log('[OK] Share C download after expiry correctly rejected');

    // 11b: Share B max_downloads=2
    // Use a fresh page to avoid stale state from Share C expiry test
    await page.close();
    page = await anonContext.newPage();
    attachConsoleListener(page, '11-anon');
    console.log('[i] [Phase 11b] Testing Share B max_downloads=2');

    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'phase11_b_dl1.bin');
    console.log('[OK] Share B download 1/2');

    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'phase11_b_dl2.bin');
    console.log('[OK] Share B download 2/2');

    logStep('11b', 'Attempting 3rd download (should fail at envelope level - share revoked after exhaustion)...');
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    // After the 2nd download the server marks the share revoked_reason='exhausted'.
    // GetShareEnvelope now returns 403 immediately, so #fileDetails never appears.
    // share-access.ts shows "This share is no longer valid." directly.
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('error') || text.includes('exceeded') || text.includes('limit') ||
               text.includes('no longer') || text.includes('invalid') || text.includes('failed') ||
               text.includes('revoked');
      },
      { timeout: 30_000 },
    );
    console.log('[OK] Share B download 3 correctly rejected (max_downloads exceeded, 403 at envelope)');

    // 11c: Non-existent share (43-char base64url format matching real share IDs)
    console.log('[i] [Phase 11c] Testing non-existent share');
    await page.goto(`${SERVER_URL}/shared/xQ7mN9kR2pL5vB8wY1cF3hJ6tA0eG4iK9oU2sD5fW7`);
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('error') || text.includes('not found') || text.includes('invalid') || text.includes('failed');
      },
      { timeout: 30_000 },
    );
    console.log('[OK] Non-existent share correctly shows error');

    await anonContext.close();
    console.log('[OK] Phase 11: All share access controls verified');
  });

  // --------------------------------------------------------------------------
  // Phase 12: Share Revocation
  // --------------------------------------------------------------------------
  test('Phase 12: Share revocation (revoke Share A, verify access denied)', async () => {
    // Re-login on sharedPage (we logged out in Phase 10)
    logStep('12', 'Re-logging in for revocation test...');
    await performLogin(sharedPage, '12');

    logStep('12', 'Refreshing share list...');
    await sharedPage.click('#refresh-shares-btn');
    await sharedPage.waitForSelector('.share-item', { state: 'visible', timeout: 30_000 });

    const shareAItem = sharedPage.locator(`.share-item[data-share-id="${shareAId}"]`);
    await expect(shareAItem).toBeVisible({ timeout: 10_000 });

    logStep('12', 'Revoking Share A...');
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') await dialog.accept();
    });

    await shareAItem.locator('.btn-revoke').click();

    await sharedPage.waitForFunction(
      (shareId: string) => {
        const item = document.querySelector(`.share-item[data-share-id="${shareId}"]`);
        if (!item) return false;
        const text = item.textContent?.toLowerCase() || '';
        return text.includes('revoked') || !item.querySelector('.btn-revoke');
      },
      shareAId,
      { timeout: 15_000 },
    );

    console.log('[OK] Share A revoked successfully');
    sharedPage.removeAllListeners('dialog');

    // ---- Contact Info Lifecycle Tests (within current logged-in session) ----
    logStep('12', 'Contact Info: Navigating to app...');
    await sharedPage.goto(SERVER_URL);
    await sharedPage.waitForSelector('#file-section', { state: 'visible', timeout: 15_000 });

    // Open Contact Info panel
    logStep('12', 'Contact Info: Opening panel...');
    await sharedPage.click('#contact-info-toggle');
    await sharedPage.waitForSelector('#contact-info-panel', { state: 'visible', timeout: 5_000 });

    // Clean up any pre-existing contact info (e.g. left by e2e-test.sh CLI tests)
    const preExistingName = await sharedPage.inputValue('#contact-display-name');
    if (preExistingName !== '') {
      logStep('12', `Contact Info: Found pre-existing data (display_name="${preExistingName}"), deleting first...`);
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
    logStep('12', 'Contact Info: Setting initial data (1 email)...');
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
      const token = localStorage.getItem('token');
      const resp = await fetch('/api/user/contact-info', {
        headers: { Authorization: `Bearer ${token}` },
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
    logStep('12', 'Contact Info: Updating notes...');
    await sharedPage.fill('#contact-notes', '');
    await sharedPage.fill('#contact-notes', 'Updated notes from Playwright');
    await sharedPage.click('#save-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);

    // Verify update via API
    const ciData2 = await sharedPage.evaluate(async () => {
      const token = localStorage.getItem('token');
      const resp = await fetch('/api/user/contact-info', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return resp.json();
    });
    expect(ciData2.data.contact_info.notes).toBe('Updated notes from Playwright');
    expect(ciData2.data.contact_info.contacts[0].value).toBe('pw-test@example.com');
    console.log('[OK] Contact Info: Update verified (notes changed, email unchanged)');

    // Delete contact info
    logStep('12', 'Contact Info: Deleting...');
    sharedPage.on('dialog', async (dialog) => {
      await dialog.accept();
    });
    await sharedPage.click('#delete-contact-info-btn');
    await sharedPage.waitForTimeout(1_000);
    sharedPage.removeAllListeners('dialog');

    // Verify deletion via API
    const ciData3 = await sharedPage.evaluate(async () => {
      const token = localStorage.getItem('token');
      const resp = await fetch('/api/user/contact-info', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return resp.json();
    });
    expect(ciData3.data.has_contact_info).toBe(false);
    console.log('[OK] Contact Info: Deletion verified');

    // Re-set with final contact info (1 signal contact, left in place)
    logStep('12', 'Contact Info: Re-setting final data (1 signal)...');
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
      const token = localStorage.getItem('token');
      const resp = await fetch('/api/user/contact-info', {
        headers: { Authorization: `Bearer ${token}` },
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

    console.log('[OK] Phase 12 Contact Info: All contact info lifecycle tests passed');
    // ---- End Contact Info Tests ----

    // Log out and verify Share A is denied
    await sharedPage.click('#logout-link');
    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });

    logStep('12', 'Verifying access denied to revoked Share A...');
    await sharedPage.goto(shareAUrl);
    await sharedPage.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await sharedPage.fill('#sharePassword', SHARE_A_PASSWORD);
    await sharedPage.click('#shareAccessForm button[type="submit"]');

    await sharedPage.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('error') || text.includes('revoked') || text.includes('invalid') ||
               text.includes('no longer') || text.includes('failed');
      },
      { timeout: 30_000 },
    );

    console.log('[OK] Phase 12: Revoked share correctly denied access');
  });

  // ── Billing Panel ──────────────────────────────────────────────────────────
  // Requires:
  //   - The shared page has been logged in earlier in the describe block.
  //   - The e2e-test.sh phase_11d_billing has already run at least one
  //     tick-now --sweep, so the test user has >=1 'gift' row and >=1 'usage'
  //     row in their credit_transactions table, and their balance is negative.
  //
  // This test opens the Billing panel, verifies the DOM layout produced by
  // client/static/js/src/ui/billing.ts.
  //
  // See docs/wip/storage-credits-v2.md §10.5 for the test plan spec.
  // --------------------------------------------------------------------------
  test('Billing panel renders balance, usage grid, and transaction history', async () => {
    // Phase 12 always ends with a logout (to verify share revocation).
    // Re-login here so we have a valid session for the billing panel test.
    // Phase 13 (logout test) detects this session is live and skips its own
    // re-login, so no extra login/logout cycles are added to the total.
    logStep('billing', 'Re-logging in for billing panel test (Phase 12 ended with logout)...');
    await performLogin(sharedPage, 'billing');

    // Open the Billing panel by clicking the nav link.
    await sharedPage.click('#billing-toggle');

    // Wait for the panel to become visible.
    await sharedPage.waitForSelector('#billing-panel:not(.hidden)', { timeout: 5000 });

    // Wait for the loading placeholder to be replaced by real content.
    // (billing.ts replaces innerHTML='<p>Loading...</p>' with sections once the
    // /api/credits response arrives.)
    await sharedPage.waitForSelector('.billing-panel-section', { timeout: 10000 });

    // ── Section 1: Balance ──────────────────────────────────────────────
    const balanceEl = await sharedPage.$('.billing-balance-amount');
    expect(balanceEl).not.toBeNull();

    const balanceText = await balanceEl!.innerText();
    // Must match $X.XXXX or -$X.XXXX (four decimal places, signed USD).
    // The test user was drained to a negative balance by phase_11d_billing.
    expect(balanceText).toMatch(/^-?\$\d+\.\d{4}$/);

    console.log(`[OK] Billing balance displays: ${balanceText}`);

    // ── Section 2: Current Storage and Cost grid ────────────────────────
    const usageGrid = await sharedPage.$('.billing-usage-grid');
    expect(usageGrid).not.toBeNull();

    // These three labels are always present regardless of whether the user is
    // above or below the free baseline. 'Your projected cost' and 'Estimated
    // runway' are conditional (only rendered when billable_bytes > 0), and by
    // the time the Playwright suite runs, phase_12_cleanup has deleted the test
    // files, so the user is back below baseline.
    const labels = await sharedPage.$$eval(
      '.billing-usage-grid dt',
      (els: Element[]) => els.map((el: Element) => el.textContent?.trim() ?? '')
    );
    expect(labels).toContain('Storage used');
    expect(labels).toContain('Free baseline');
    expect(labels).toContain('Billable usage');

    console.log('[OK] Billing usage grid labels:', labels);

    // ── Section 3: Transaction History ─────────────────────────────────
    // Phase_11d_billing wrote >=1 'gift' row and >=1 'usage' row, so the
    // table must be present and contain both transaction types.
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

  // --------------------------------------------------------------------------
  // Phase 13: Logout + Post-Logout Checks
  // --------------------------------------------------------------------------
  test('Phase 13: Logout and post-logout security checks', async () => {
    // The billing panel test (immediately above) leaves the page logged in.
    // Skip the re-login if the session is still valid so we don't add an
    // extra login/logout cycle.
    const alreadyLoggedIn = await sharedPage.evaluate(() =>
      localStorage.getItem('token') !== null
    );
    if (!alreadyLoggedIn) {
      logStep('13', 'Re-logging in for logout test...');
      await performLogin(sharedPage, '13');
    } else {
      logStep('13', 'Session still live from billing test -- skipping re-login');
    }

    logStep('13', 'Clicking logout...');
    await sharedPage.click('#logout-link');

    await sharedPage.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });
    await expect(sharedPage.locator('.home-container')).toBeVisible();

    logStep('13', 'Verifying session and cache cleanup...');

    // AuthManager stores JWT as 'token' and refresh as 'refresh_token' in localStorage
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

    console.log('[OK] Phase 13: Logout verified -- session cleared, API returns 401');
  });

});
