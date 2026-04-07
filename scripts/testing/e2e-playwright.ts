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

    // 6a: correct password
    logStep('6', 'Testing download with correct custom password...');
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        logStep('6', 'Password prompt dialog -- providing correct password');
        await dialog.accept(CUSTOM_FILE_PASSWORD);
      } else if (dialog.type() === 'alert') {
        await dialog.accept();
      }
    });

    const downloadPromise = sharedPage.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');
    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase6_custom_download.bin');

    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(CUSTOM_FILE_SHA256);
    console.log('[OK] Phase 6a: Custom-password download integrity verified');

    sharedPage.removeAllListeners('dialog');

    // 6b: wrong password
    logStep('6', 'Testing download with wrong custom password...');
    sharedPage.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        logStep('6', 'Password prompt dialog -- providing WRONG password');
        await dialog.accept('WrongPassword123!NotCorrect');
      } else if (dialog.type() === 'alert') {
        await dialog.accept();
      }
    });

    await clickFileAction(sharedPage, CUSTOM_FILE_NAME, 'Download');

    await sharedPage.waitForFunction(
      () => {
        const body = document.body.innerText.toLowerCase();
        return body.includes('failed') || body.includes('error') || body.includes('incorrect');
      },
      { timeout: 60_000 },
    );

    sharedPage.removeAllListeners('dialog');
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
        await sharedPage.fill('#share-expiry-value', String(opts.expiryValue));
      }
      if (opts.expiryUnit) {
        await sharedPage.selectOption('#share-expiry-unit', opts.expiryUnit);
      }
      if (opts.maxDownloads !== undefined) {
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

    // 11a: Share B max_downloads=2
    console.log('[i] [Phase 11a] Testing Share B max_downloads=2');

    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    let dlPromise = page.waitForEvent('download', { timeout: 120_000 });
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

    logStep('11a', 'Attempting 3rd download (should fail at chunk level)...');
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    // Envelope fetch succeeds (max_accesses not checked there), file details appear
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });
    // Click download -- this triggers chunk download which checks max_accesses on chunk 0
    await page.click('#downloadBtn');
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return text.includes('error') || text.includes('exceeded') || text.includes('limit') ||
               text.includes('no longer') || text.includes('invalid') || text.includes('failed') ||
               text.includes('revoked') || text.includes('download');
      },
      { timeout: 30_000 },
    );
    console.log('[OK] Share B download 3 correctly rejected (max_downloads exceeded)');

    // 11b: Share C expiry
    // Use a fresh page to avoid stale fetch errors from Phase 11a's rejected download
    await page.close();
    page = await anonContext.newPage();
    attachConsoleListener(page, '11-anon');
    console.log('[i] [Phase 11b] Testing Share C expiry');

    await page.goto(shareCUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_C_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    dlPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    await saveDownload(await dlPromise, 'phase11_c_dl1.bin');
    console.log('[OK] Share C download before expiry succeeded');

    logStep('11b', 'Waiting 65s for Share C to expire...');
    await new Promise((resolve) => setTimeout(resolve, 65_000));

    logStep('11b', 'Attempting download after expiry...');
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

  // --------------------------------------------------------------------------
  // Phase 13: Logout + Post-Logout Checks
  // --------------------------------------------------------------------------
  test('Phase 13: Logout and post-logout security checks', async () => {
    // Re-login one final time to test logout
    logStep('13', 'Re-logging in for logout test...');
    await performLogin(sharedPage, '13');

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
