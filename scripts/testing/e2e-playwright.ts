/**
 * Playwright E2E Frontend Test Spec
 *
 * Exercises the Arkfile web frontend against a live local server,
 * mirroring the functional coverage of scripts/testing/e2e-test.sh.
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
const STORAGE_STATE_PATH = join(PLAYWRIGHT_TEMP_DIR, 'auth.json');

// ============================================================================
// Shared State (carried between sequential tests)
// ============================================================================

let shareAUrl = '';
let shareBUrl = '';
let shareCUrl = '';
let shareAId = '';
let shareBId = '';
let shareCId = '';

// ============================================================================
// Helper Functions
// ============================================================================

function logStep(phase: string, message: string) {
  console.log(`[i] [Phase ${phase}] ${message}`);
}

/**
 * Attaches console listener to forward browser logs to stdout
 */
function attachConsoleListener(page: Page, phase: string) {
  page.on('console', msg => {
    // Filter out some noisy things if needed, but otherwise forward
    const type = msg.type();
    if (type === 'error' || type === 'warning' || type === 'log' || type === 'info') {
      console.log(`[browser:${type}] [Phase ${phase}] ${msg.text()}`);
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
 * Perform the full login flow: OPAQUE auth + TOTP + cache opt-in.
 * Used to establish initial session and for explicit re-login tests.
 */
async function performLogin(page: Page, phase: string): Promise<void> {
  logStep(phase, 'Navigating to app and initiating login...');
  await page.goto(SERVER_URL);

  // Wait for home page to load, click Login
  await page.waitForSelector('#login-btn', { state: 'visible', timeout: 15_000 });
  await page.click('#login-btn');

  // Wait for login form to appear
  await page.waitForSelector('#login-username', { state: 'visible', timeout: 10_000 });

  // Fill credentials
  await page.fill('#login-username', TEST_USERNAME);
  await page.fill('#login-password', TEST_PASSWORD);

  logStep(phase, 'Submitting OPAQUE authentication...');
  await page.click('#login-submit-btn');

  // Wait for TOTP modal (dynamically created)
  await page.waitForSelector('#totp-login-code', { state: 'visible', timeout: 60_000 });

  // Wait for TOTP window, then generate code
  await waitForTotpWindow(phase);
  const totpCode = generateTotpCode(phase);

  // Type TOTP code
  await page.fill('#totp-login-code', totpCode);

  // Wait for verify button to become enabled
  logStep(phase, 'Verifying TOTP code...');
  await page.waitForSelector('#verify-totp-login:not([disabled])', { timeout: 5_000 });
  await page.click('#verify-totp-login');

  // Wait for cache opt-in modal
  logStep(phase, 'Opting into Account Key cache...');
  await page.waitForSelector('#cache-optin-ok-btn', { state: 'visible', timeout: 120_000 });
  await page.click('#cache-optin-ok-btn');

  // Wait for file section to become visible (login complete)
  await page.waitForSelector('#file-section', { state: 'visible', timeout: 120_000 });
  logStep(phase, 'Login complete -- file section visible');
}

/**
 * Checks if a specific filename is already present in the UI file list
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
 * Returns the .file-item element locator.
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

  // Verify test files exist
  if (!existsSync(TEST_FILE_PATH)) {
    throw new Error(`Test file not found: ${TEST_FILE_PATH}`);
  }
  if (!existsSync(CUSTOM_FILE_PATH)) {
    throw new Error(`Custom test file not found: ${CUSTOM_FILE_PATH}`);
  }

  // Create downloads directory
  execSync(`mkdir -p "${DOWNLOADS_DIR}"`);

  console.log('[OK] Environment validated');
  console.log(`[i] Server: ${SERVER_URL}`);
  console.log(`[i] User: ${TEST_USERNAME}`);
  console.log(`[i] Test file: ${TEST_FILE_NAME} (${TEST_FILE_SHA256.substring(0, 16)}...)`);
  console.log(`[i] Custom file: ${CUSTOM_FILE_NAME} (${CUSTOM_FILE_SHA256.substring(0, 16)}...)`);
});

// ============================================================================
// Test Phases (sequential)
// ============================================================================

test.describe.serial('Arkfile Playwright E2E', () => {

  // We use a single persistent context for phases 1-9 to avoid repeated logins
  let sharedContext: BrowserContext;
  
  test.beforeAll(async ({ browser }) => {
    // Create base context that uses our config
    sharedContext = await browser.newContext({
      baseURL: SERVER_URL,
      ignoreHTTPSErrors: true,
    });
  });

  test.afterAll(async () => {
    await sharedContext.close();
  });

  // --------------------------------------------------------------------------
  // Phase 1: Login & Session Establishment
  // --------------------------------------------------------------------------
  test('Phase 1: Login (OPAQUE + TOTP + cache opt-in)', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '1');
    
    await performLogin(page, '1');

    // Wait for the files list to fully load before saving state
    // so we don't save a mid-load state if the network is slow
    await expect(page.locator('#filesList')).toBeVisible({ timeout: 15_000 });
    // Also wait a beat for digest cache to populate from the API response
    await page.waitForTimeout(1000);

    // Save state for idempotency testing downstream
    await sharedContext.storageState({ path: STORAGE_STATE_PATH });

    await page.close();
    console.log('[OK] Phase 1: Login successful, session established');
  });

  // Helper to load storage state
  async function restoreSession(context: BrowserContext, page: Page, phase: string) {
    logStep(phase, 'Restoring authenticated session and navigating to app...');
    
    // Read the saved storage state
    if (existsSync(STORAGE_STATE_PATH)) {
      const stateStr = readFileSync(STORAGE_STATE_PATH, 'utf-8');
      const state = JSON.parse(stateStr);
      
      // Inject sessionStorage data before navigating
      await page.addInitScript((sessionData) => {
        for (const origin of sessionData.origins || []) {
          for (const item of origin.localStorage || []) {
            sessionStorage.setItem(item.name, item.value);
            localStorage.setItem(item.name, item.value); // App might use localStorage too
          }
        }
      }, state);
    }
    
    await page.goto(SERVER_URL);
    
    // Also inject directly after navigation just in case
    if (existsSync(STORAGE_STATE_PATH)) {
      const stateStr = readFileSync(STORAGE_STATE_PATH, 'utf-8');
      const state = JSON.parse(stateStr);
      await page.evaluate((sessionData) => {
        for (const origin of sessionData.origins || []) {
          for (const item of origin.localStorage || []) {
            sessionStorage.setItem(item.name, item.value);
            localStorage.setItem(item.name, item.value);
          }
        }
      }, state);
      
      // Force reload to pick up the injected storage
      await page.reload();
    }

    await expect(page.locator('#file-section')).toBeVisible({ timeout: 15_000 });
  }

  // --------------------------------------------------------------------------
  // Phase 2: File Upload (Account Password)
  // --------------------------------------------------------------------------
  test('Phase 2: Upload file with account password', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '2');
    await restoreSession(sharedContext, page, '2');

    // Idempotency check: did we already upload this file in a previous run?
    const alreadyExists = await fileExistsInList(page, TEST_FILE_NAME);
    if (alreadyExists) {
      logStep('2', `File ${TEST_FILE_NAME} already exists in list (idempotent run). Skipping upload.`);
      console.log('[OK] Phase 2: Account-password file upload (Skipped - already exists)');
      await page.close();
      return;
    }

    logStep('2', `Initiating upload for ${TEST_FILE_NAME}...`);

    // Set file input
    await page.setInputFiles('#fileInput', TEST_FILE_PATH);

    // Verify account password radio is checked by default
    await expect(page.locator('#useAccountPassword')).toBeChecked();

    // Click upload
    await page.click('#upload-file-btn');

    // Wait for the specific file to appear OR success message
    // Since file derivation from browser can take a long time, we wait up to 3 minutes
    logStep('2', `Waiting for Argon2id derivation, encryption, and upload (timeout: 180s)...`);
    
    await page.waitForFunction(
      (filename) => {
        // Option 1: File appears in list
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return true;
        }
        // Option 2: Success toast appears
        const toasts = document.querySelectorAll('.toast-success');
        for (const toast of toasts) {
          if (toast.textContent && toast.textContent.includes('successfully')) return true;
        }
        return false;
      },
      TEST_FILE_NAME,
      { timeout: 180_000 },
    );

    logStep('2', `File ${TEST_FILE_NAME} found in file list.`);

    // Verify encryption type shows "Account Password"
    const fileItem = findFileItem(page, TEST_FILE_NAME);
    await expect(fileItem.locator('.encryption-type')).toContainText('Account Password');

    await page.close();
    console.log('[OK] Phase 2: Account-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 3: File Download + Integrity
  // --------------------------------------------------------------------------
  test('Phase 3: Download file and verify SHA-256 integrity', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '3');
    await restoreSession(sharedContext, page, '3');

    // Wait for file list to load with our file
    const fileItem = findFileItem(page, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    logStep('3', `Initiating download of ${TEST_FILE_NAME}...`);

    // Set up download listener BEFORE clicking
    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });

    // Click Download button for our file
    await clickFileAction(page, TEST_FILE_NAME, 'Download');

    // Wait for the download to complete
    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase3_download.bin');

    logStep('3', 'Download complete, verifying hash...');

    // Verify SHA-256 integrity
    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    await page.close();
    console.log(`[OK] Phase 3: Download integrity verified (SHA-256: ${actualHash.substring(0, 16)}...)`);
  });

  // --------------------------------------------------------------------------
  // Phase 4: Duplicate Upload Rejection
  // --------------------------------------------------------------------------
  test('Phase 4: Duplicate upload rejection', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '4');
    await restoreSession(sharedContext, page, '4');

    // Wait for file list
    const fileItem = findFileItem(page, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    // Since we now skip Phase 2 if the file exists, the internal UI digest cache might not
    // have the file hash if it wasn't uploaded in this exact session. Let's explicitly
    // try the upload. The server will reject it if the UI doesn't catch it first.
    logStep('4', `Attempting duplicate upload of ${TEST_FILE_NAME}...`);

    // Try to upload the same file again
    await page.setInputFiles('#fileInput', TEST_FILE_PATH);
    await page.click('#upload-file-btn');

    // Wait for error message containing "duplicate" or "exists" or "error"
    // The UI checks the digest cache directly during upload now, so the error
    // might be immediate if the digest cache was populated on login.
    logStep('4', `Waiting for duplicate error...`);
    await page.waitForFunction(
      () => {
        // Look for common error keywords indicating rejection
        const body = document.body.innerText.toLowerCase();
        return body.includes('duplicate') || 
               body.includes('already uploaded') || 
               body.includes('exists');
      },
      { timeout: 30_000 },
    );

    await page.close();
    console.log('[OK] Phase 4: Duplicate upload correctly rejected');
  });

  // --------------------------------------------------------------------------
  // Phase 5: Custom-Password Upload
  // --------------------------------------------------------------------------
  test('Phase 5: Upload file with custom password', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '5');
    await restoreSession(sharedContext, page, '5');

    // Idempotency check
    const alreadyExists = await fileExistsInList(page, CUSTOM_FILE_NAME);
    if (alreadyExists) {
      logStep('5', `File ${CUSTOM_FILE_NAME} already exists in list. Skipping upload.`);
      console.log('[OK] Phase 5: Custom-password file upload (Skipped - already exists)');
      await page.close();
      return;
    }

    logStep('5', `Initiating custom-password upload for ${CUSTOM_FILE_NAME}...`);

    // Set custom file
    await page.setInputFiles('#fileInput', CUSTOM_FILE_PATH);

    // Select custom password radio
    await page.click('#useCustomPassword');

    // Wait for custom password section to appear
    await page.waitForSelector('#customPasswordSection:not(.hidden)', { timeout: 5_000 });

    // Fill custom password
    await page.fill('#filePassword', CUSTOM_FILE_PASSWORD);

    // Click upload
    await page.click('#upload-file-btn');

    logStep('5', `Waiting for Argon2id derivation, encryption, and upload (timeout: 180s)...`);

    // Wait for the custom file to appear in the list OR success message
    await page.waitForFunction(
      (filename) => {
        const items = document.querySelectorAll('.file-item .file-info strong');
        for (const item of items) {
          if (item.textContent === filename) return true;
        }
        const toasts = document.querySelectorAll('.toast-success');
        for (const toast of toasts) {
          if (toast.textContent && toast.textContent.includes('successfully')) return true;
        }
        return false;
      },
      CUSTOM_FILE_NAME,
      { timeout: 180_000 }
    );

    logStep('5', `File ${CUSTOM_FILE_NAME} found in file list.`);

    // Verify encryption type shows "Custom Password"
    const customFileItem = findFileItem(page, CUSTOM_FILE_NAME);
    await expect(customFileItem.locator('.encryption-type')).toContainText('Custom Password');

    await page.close();
    console.log('[OK] Phase 5: Custom-password file uploaded successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 6: Custom-Password Download
  // --------------------------------------------------------------------------
  test('Phase 6: Custom-password download (correct + wrong password)', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '6');
    await restoreSession(sharedContext, page, '6');

    // Wait for custom file in list
    const customFileItem = findFileItem(page, CUSTOM_FILE_NAME);
    await expect(customFileItem).toBeVisible({ timeout: 60_000 });

    // 6a: Download with correct custom password
    logStep('6', 'Testing download with correct custom password...');
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        logStep('6', 'Handling password prompt dialog (providing correct password)');
        await dialog.accept(CUSTOM_FILE_PASSWORD);
      } else if (dialog.type() === 'alert') {
        await dialog.accept();
      }
    });

    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await clickFileAction(page, CUSTOM_FILE_NAME, 'Download');

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase6_custom_download.bin');

    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(CUSTOM_FILE_SHA256);
    console.log(`[OK] Phase 6a: Custom-password download integrity verified`);

    // Remove all dialog listeners before setting up wrong-password test
    page.removeAllListeners('dialog');

    // 6b: Download with wrong password
    logStep('6', 'Testing download with incorrect custom password...');
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        logStep('6', 'Handling password prompt dialog (providing WRONG password)');
        await dialog.accept('WrongPassword123!NotCorrect');
      } else if (dialog.type() === 'alert') {
        await dialog.accept();
      }
    });

    // Click download again for the custom file
    await clickFileAction(page, CUSTOM_FILE_NAME, 'Download');

    // Wait for error message about decryption failure
    await page.waitForFunction(
      () => {
        const body = document.body.innerText.toLowerCase();
        return body.includes('failed') || body.includes('error') || body.includes('incorrect');
      },
      { timeout: 60_000 },
    );

    page.removeAllListeners('dialog');
    await page.close();
    console.log('[OK] Phase 6b: Wrong custom password correctly rejected');
  });

  // --------------------------------------------------------------------------
  // Phase 7: Raw API Privacy
  // --------------------------------------------------------------------------
  test('Phase 7: Raw API privacy verification', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '7');
    await restoreSession(sharedContext, page, '7');

    logStep('7', 'Fetching /api/files raw json...');

    // Call /api/files via page.evaluate() with the JWT from sessionStorage
    const apiResponse = await page.evaluate(async () => {
      const token =
        sessionStorage.getItem('arkfile.sessionToken') ||
        localStorage.getItem('arkfile.sessionToken');
      if (!token) return { error: 'no token' };

      const resp = await fetch('/api/files', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resp.ok) return { error: `HTTP ${resp.status}` };
      return resp.json();
    });

    expect(apiResponse).not.toHaveProperty('error');

    // Stringify the API response to search for plaintext leaks
    const responseStr = JSON.stringify(apiResponse);

    // Plaintext filenames must NOT appear in raw API response
    expect(responseStr).not.toContain(TEST_FILE_NAME);
    expect(responseStr).not.toContain(CUSTOM_FILE_NAME);

    // Plaintext SHA-256 hashes must NOT appear
    expect(responseStr).not.toContain(TEST_FILE_SHA256);
    expect(responseStr).not.toContain(CUSTOM_FILE_SHA256);

    // Encrypted fields MUST be present
    expect(responseStr).toContain('encrypted_filename');
    expect(responseStr).toContain('encrypted_sha256sum');

    await page.close();
    console.log('[OK] Phase 7: Raw API does not expose plaintext filenames or hashes');
  });

  // --------------------------------------------------------------------------
  // Phase 8: Share Creation (A, B, C)
  // --------------------------------------------------------------------------
  test('Phase 8: Create shares A (no limits), B (max_downloads=2), C (expires=1m)', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '8');
    await restoreSession(sharedContext, page, '8');

    // Wait for file list with account-password file
    const fileItem = findFileItem(page, TEST_FILE_NAME);
    await expect(fileItem).toBeVisible({ timeout: 60_000 });

    // Helper: create a share with given parameters
    async function createShare(
      targetFilename: string,
      password: string,
      opts: { expiryValue?: number; expiryUnit?: string; maxDownloads?: number },
    ): Promise<string> {
      // Click Share button
      await clickFileAction(page, targetFilename, 'Share');

      // Wait for share modal
      await page.waitForSelector('#arkfile-share-modal-overlay', {
        state: 'visible',
        timeout: 15_000,
      });

      // Fill share password
      await page.fill('#share-password-input', password);
      await page.fill('#share-password-confirm', password);

      // Set expiry if specified
      if (opts.expiryValue !== undefined) {
        await page.fill('#share-expiry-value', String(opts.expiryValue));
      }
      if (opts.expiryUnit) {
        await page.selectOption('#share-expiry-unit', opts.expiryUnit);
      }

      // Set max downloads if specified
      if (opts.maxDownloads !== undefined) {
        await page.fill('#share-max-downloads', String(opts.maxDownloads));
      }

      // Submit
      await page.click('#share-modal-submit');

      // Wait for result modal with share URL
      await page.waitForSelector('#share-result-url', {
        state: 'visible',
        timeout: 120_000, // Derivation/encryption takes time
      });

      // Extract share URL
      const shareUrl = await page.inputValue('#share-result-url');
      expect(shareUrl).toBeTruthy();
      expect(shareUrl).toContain('/shared/');

      // Close result modal
      await page.click('#share-result-done');

      // Wait for modal to disappear
      await page.waitForSelector('#arkfile-share-result-overlay', {
        state: 'detached',
        timeout: 5_000,
      }).catch(() => {});

      return shareUrl;
    }

    logStep('8', 'Creating Share A...');
    shareAUrl = await createShare(TEST_FILE_NAME, SHARE_A_PASSWORD, {
      expiryValue: 0,
      expiryUnit: 'hours',
      maxDownloads: 0,
    });
    shareAId = extractShareId(shareAUrl);
    console.log(`[OK] Share A created: ${shareAId} (no limits)`);

    logStep('8', 'Creating Share B...');
    shareBUrl = await createShare(TEST_FILE_NAME, SHARE_B_PASSWORD, {
      expiryValue: 0,
      expiryUnit: 'hours',
      maxDownloads: 2,
    });
    shareBId = extractShareId(shareBUrl);
    console.log(`[OK] Share B created: ${shareBId} (max_downloads=2)`);

    logStep('8', 'Creating Share C...');
    shareCUrl = await createShare(TEST_FILE_NAME, SHARE_C_PASSWORD, {
      expiryValue: 1,
      expiryUnit: 'minutes',
      maxDownloads: 0,
    });
    shareCId = extractShareId(shareCUrl);
    console.log(`[OK] Share C created: ${shareCId} (expires=1m)`);

    await page.close();
    console.log('[OK] Phase 8: All three shares created successfully');
  });

  // --------------------------------------------------------------------------
  // Phase 9: Share List Verification
  // --------------------------------------------------------------------------
  test('Phase 9: Share list verification (decrypted metadata)', async () => {
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '9');
    await restoreSession(sharedContext, page, '9');

    logStep('9', 'Refreshing share list...');
    // Click refresh shares
    await page.click('#refresh-shares-btn');

    // Wait for share list to populate
    await page.waitForSelector('.share-item', {
      state: 'visible',
      timeout: 30_000,
    });

    // Get all share items
    const shareItems = page.locator('.share-item');
    const count = await shareItems.count();
    // E2E test might have populated shares too, so assert at least 3
    expect(count).toBeGreaterThanOrEqual(3);

    // Verify decrypted filenames appear (not [Encrypted])
    const sharesText = await page.locator('#sharesList').innerText();
    expect(sharesText).toContain(TEST_FILE_NAME);
    expect(sharesText).not.toContain('[Encrypted]');

    // Verify key type is shown
    expect(sharesText.toLowerCase()).toContain('account');

    // Verify SHA-256 prefix is visible (share list shows first 16 chars)
    const sha256Prefix = TEST_FILE_SHA256.substring(0, 8);
    expect(sharesText).toContain(sha256Prefix);

    await page.close();
    console.log('[OK] Phase 9: Share list shows decrypted filenames, key types, and SHA-256');
  });

  // --------------------------------------------------------------------------
  // Phase 10: Anonymous Share Download
  // --------------------------------------------------------------------------
  test('Phase 10: Anonymous share download (Share A)', async ({ browser }) => {
    // For anonymous visitor, use a completely isolated browser context
    const anonContext = await browser.newContext({ baseURL: SERVER_URL, ignoreHTTPSErrors: true });
    const page = await anonContext.newPage();
    attachConsoleListener(page, '10');

    logStep('10', `Navigating to Share A (${shareAUrl}) as anonymous...`);
    await page.goto(shareAUrl);

    // Wait for share access container
    await page.waitForSelector('#share-access-container', {
      state: 'visible',
      timeout: 15_000,
    });

    // Wait for the password form to render
    await page.waitForSelector('#sharePassword', {
      state: 'visible',
      timeout: 15_000,
    });

    // Enter share password
    await page.fill('#sharePassword', SHARE_A_PASSWORD);

    logStep('10', 'Submitting share password...');
    await page.click('#shareAccessForm button[type="submit"]');

    // Wait for file details to appear (decryption successful)
    await page.waitForSelector('#fileDetails', {
      state: 'visible',
      timeout: 120_000,
    });

    // Verify filename is displayed
    const filenameText = await page.locator('#fileNameDisplay').innerText();
    expect(filenameText).toBeTruthy();

    logStep('10', 'Initiating download...');
    // Click download
    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');

    const download = await downloadPromise;
    const savePath = await saveDownload(download, 'phase10_share_download.bin');

    // Verify SHA-256
    const actualHash = computeSha256(savePath);
    expect(actualHash).toBe(TEST_FILE_SHA256);

    await anonContext.close();
    console.log('[OK] Phase 10: Anonymous share download verified (SHA-256 match)');
  });

  // --------------------------------------------------------------------------
  // Phase 11: Share Access Controls
  // --------------------------------------------------------------------------
  test('Phase 11: Share access controls (max downloads, expiry, non-existent)', async ({ browser }) => {
    const anonContext = await browser.newContext({ baseURL: SERVER_URL, ignoreHTTPSErrors: true });
    const page = await anonContext.newPage();
    attachConsoleListener(page, '11');

    // 11a: Share B - max_downloads = 2
    console.log('[i] [Phase 11a] Testing Share B max_downloads=2');
    
    // Download 1/2
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    let downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    let download = await downloadPromise;
    await saveDownload(download, 'phase11_b_dl1.bin');
    console.log('[OK] Share B download 1/2');

    // Download 2/2 -- reload the share page for a fresh session
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    download = await downloadPromise;
    await saveDownload(download, 'phase11_b_dl2.bin');
    console.log('[OK] Share B download 2/2');

    // Download 3 -- should fail (max downloads exceeded)
    logStep('11a', 'Attempting 3rd download (should fail)...');
    await page.goto(shareBUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_B_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');

    // Expect an error -- either the envelope fetch fails or download is rejected
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return (
          text.includes('error') ||
          text.includes('exceeded') ||
          text.includes('limit') ||
          text.includes('no longer') ||
          text.includes('invalid') ||
          text.includes('failed')
        );
      },
      { timeout: 30_000 },
    );
    console.log('[OK] Share B download 3 correctly rejected (max_downloads exceeded)');

    // 11b: Share C - expires in 1 minute
    console.log('[i] [Phase 11b] Testing Share C expiry');

    // Download before expiry -- should succeed
    await page.goto(shareCUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_C_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');
    await page.waitForSelector('#fileDetails', { state: 'visible', timeout: 120_000 });

    downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.click('#downloadBtn');
    download = await downloadPromise;
    await saveDownload(download, 'phase11_c_dl1.bin');
    console.log('[OK] Share C download before expiry succeeded');

    // Wait for expiry (65 seconds to be safe)
    logStep('11b', 'Waiting 65s for Share C to expire...');
    await new Promise((resolve) => setTimeout(resolve, 65_000));

    // Attempt download after expiry -- should fail
    logStep('11b', 'Attempting download after expiry...');
    await page.goto(shareCUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_C_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');

    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return (
          text.includes('error') ||
          text.includes('expired') ||
          text.includes('no longer') ||
          text.includes('invalid') ||
          text.includes('failed')
        );
      },
      { timeout: 30_000 },
    );
    console.log('[OK] Share C download after expiry correctly rejected');

    // 11c: Non-existent share
    console.log('[i] [Phase 11c] Testing non-existent share');
    await page.goto(`${SERVER_URL}/shared/nonexistent-share-id-that-does-not-exist`);

    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return (
          text.includes('error') ||
          text.includes('not found') ||
          text.includes('invalid') ||
          text.includes('failed')
        );
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
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '12');
    await restoreSession(sharedContext, page, '12');

    // Refresh share list
    logStep('12', 'Refreshing share list...');
    await page.click('#refresh-shares-btn');
    await page.waitForSelector('.share-item', {
      state: 'visible',
      timeout: 30_000,
    });

    // Find Share A by data-share-id attribute
    const shareAItem = page.locator(`.share-item[data-share-id="${shareAId}"]`);
    await expect(shareAItem).toBeVisible({ timeout: 10_000 });

    logStep('12', 'Clicking revoke on Share A...');
    // Set up dialog handler for confirm() BEFORE clicking revoke
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') {
        await dialog.accept();
      }
    });

    // Click the revoke button for Share A
    await shareAItem.locator('.btn-revoke').click();

    // Wait for the share list to refresh and show revoked status
    await page.waitForFunction(
      (shareId: string) => {
        const item = document.querySelector(`.share-item[data-share-id="${shareId}"]`);
        if (!item) return false;
        const text = item.textContent?.toLowerCase() || '';
        return text.includes('revoked') || !item.querySelector('.btn-revoke');
      },
      shareAId,
      { timeout: 15_000 },
    );

    console.log('[OK] Share A revoked successfully on authenticated side');

    page.removeAllListeners('dialog');
    
    // Explicit logout
    await page.click('#logout-link');
    await page.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });

    // Attempt to access revoked Share A
    logStep('12', 'Verifying access denied to revoked Share A...');
    await page.goto(shareAUrl);
    await page.waitForSelector('#sharePassword', { state: 'visible', timeout: 15_000 });
    await page.fill('#sharePassword', SHARE_A_PASSWORD);
    await page.click('#shareAccessForm button[type="submit"]');

    // Should get an error (revoked)
    await page.waitForFunction(
      () => {
        const text = document.body.innerText.toLowerCase();
        return (
          text.includes('error') ||
          text.includes('revoked') ||
          text.includes('invalid') ||
          text.includes('no longer') ||
          text.includes('failed')
        );
      },
      { timeout: 30_000 },
    );

    await page.close();
    console.log('[OK] Phase 12: Revoked share correctly denied access');
  });

  // --------------------------------------------------------------------------
  // Phase 13: Logout + Post-Logout Checks
  // --------------------------------------------------------------------------
  test('Phase 13: Logout and post-logout security checks', async () => {
    // We already have a valid session in sharedContext
    const page = await sharedContext.newPage();
    attachConsoleListener(page, '13');
    await restoreSession(sharedContext, page, '13');

    // Logout
    logStep('13', 'Clicking explicit logout link...');
    await page.click('#logout-link');

    // Verify home page is visible
    await page.waitForSelector('.home-container', { state: 'visible', timeout: 15_000 });
    await expect(page.locator('.home-container')).toBeVisible();

    logStep('13', 'Verifying session and cache cleanup...');

    // Verify sessionStorage has no session token
    const hasSessionToken = await page.evaluate(() => {
      return (
        sessionStorage.getItem('arkfile.sessionToken') !== null ||
        sessionStorage.getItem('arkfile_session_token') !== null
      );
    });
    expect(hasSessionToken).toBe(false);

    // Verify localStorage token is also cleared
    const hasLocalToken = await page.evaluate(() => {
      return (
        localStorage.getItem('arkfile.sessionToken') !== null ||
        localStorage.getItem('arkfile_session_token') !== null
      );
    });
    expect(hasLocalToken).toBe(false);

    // Verify no account key cache or digest cache entries remain
    const hasCacheData = await page.evaluate(() => {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key && (key.includes('arkfile') || key.includes('account') || key.includes('digest'))) {
          return true;
        }
      }
      return false;
    });
    expect(hasCacheData).toBe(false);

    // Attempt authenticated API fetch with invalid token -- should get 401
    const apiStatus = await page.evaluate(async () => {
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

    await page.close();
    console.log('[OK] Phase 13: Logout verified -- session cleared, API returns 401');
  });
});
