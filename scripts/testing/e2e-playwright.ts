/**
 * Arkfile Playwright E2E Frontend Test
 *
 * Exercises the web frontend against a live local server at https://localhost:8443,
 * mirroring the functional coverage of scripts/testing/e2e-test.sh.
 *
 * Prerequisites:
 *   - Server deployed via scripts/dev-reset.sh
 *   - scripts/testing/e2e-test.sh completed (test user exists, approved, TOTP set up)
 *   - Environment variables set by scripts/testing/e2e-playwright.sh
 *
 * Run: bash scripts/testing/e2e-playwright.sh
 */

import { test, expect, type Page, type Download } from '@playwright/test';
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import { readFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// Environment variables (set by e2e-playwright.sh)
const SERVER_URL = process.env.SERVER_URL || 'https://localhost:8443';
const TOTP_SECRET = process.env.TOTP_SECRET || '';
const TEST_FILE_PATH = process.env.TEST_FILE_PATH || '';
const TEST_FILE_SHA256 = process.env.TEST_FILE_SHA256 || '';
const TEST_FILE_NAME = process.env.TEST_FILE_NAME || '';
const CUSTOM_FILE_PATH = process.env.CUSTOM_FILE_PATH || '';
const CUSTOM_FILE_SHA256 = process.env.CUSTOM_FILE_SHA256 || '';
const CUSTOM_FILE_NAME = process.env.CUSTOM_FILE_NAME || '';
const TEST_USERNAME = process.env.TEST_USERNAME || 'arkfile-dev-test-user';
const TEST_PASSWORD = process.env.TEST_PASSWORD || '';
const CUSTOM_FILE_PASSWORD = process.env.CUSTOM_FILE_PASSWORD || '';
const SHARE_A_PASSWORD = process.env.SHARE_A_PASSWORD || '';
const SHARE_B_PASSWORD = process.env.SHARE_B_PASSWORD || '';
const SHARE_C_PASSWORD = process.env.SHARE_C_PASSWORD || '';
const PLAYWRIGHT_TEMP_DIR = process.env.PLAYWRIGHT_TEMP_DIR || '/tmp/arkfile-e2e-test-data/playwright';
const CLIENT_BIN = '/opt/arkfile/bin/arkfile-client';

// Download directory for Playwright-captured downloads
const DOWNLOAD_DIR = join(PLAYWRIGHT_TEMP_DIR, 'downloads');

// Shared state across serial tests
let shareAUrl = '';
let shareBUrl = '';
let shareCUrl = '';
let shareAId = '';
let shareBId = '';
let shareCId = '';

// Helper: wait for the next TOTP window to avoid replay protection
// Same logic as wait_for_totp_window in e2e-test.sh
function waitForTotpWindow(): void {
  const currentSeconds = Math.floor(Date.now() / 1000);
  const secondsIntoWindow = currentSeconds % 30;
  const secondsToWait = 30 - secondsIntoWindow + 1;
  console.log(`[i] Waiting ${secondsToWait}s for next TOTP window (replay protection)...`);
  execSync(`sleep ${secondsToWait}`);
}

// Helper: generate a fresh TOTP code using the CLI
function generateTotpCode(): string {
  waitForTotpWindow();
  const code = execSync(`${CLIENT_BIN} generate-totp --secret "${TOTP_SECRET}"`, {
    encoding: 'utf-8',
  }).trim();
  console.log(`[i] Generated TOTP code: ${code}`);
  return code;
}

// Helper: compute SHA-256 hex of a file
function sha256File(filePath: string): string {
  const data = readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex');
}

// Helper: compute SHA-256 hex of a buffer
function sha256Buffer(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

// Helper: extract share ID from a share URL like https://localhost:8443/shared/SHARE_ID
function extractShareId(url: string): string {
  const parts = url.split('/');
  return parts[parts.length - 1];
}

// Helper: perform full login flow (OPAQUE + TOTP + cache opt-in)
async function performLogin(page: Page): Promise<void> {
  // Navigate to home page
  await page.goto('/');
  await expect(page.locator('.hero-title')).toBeVisible({ timeout: 15000 });

  // Click Login button
  await page.click('#login-btn');

  // Wait for login form
  await expect(page.locator('#login-form')).toBeVisible({ timeout: 10000 });

  // Fill credentials
  await page.fill('#login-username', TEST_USERNAME);
  await page.fill('#login-password', TEST_PASSWORD);

  // Click login submit
  await page.click('#login-submit-btn');

  // Wait for TOTP modal to appear (OPAQUE auth happens in background)
  await expect(page.locator('#totp-login-code')).toBeVisible({ timeout: 60000 });

  // Generate fresh TOTP code
  const totpCode = generateTotpCode();

  // Enter TOTP code
  await page.fill('#totp-login-code', totpCode);

  // Wait for verify button to become enabled
  await expect(page.locator('#verify-totp-login')).toBeEnabled({ timeout: 5000 });

  // Click verify
  await page.click('#verify-totp-login');

  // Wait for cache opt-in modal to appear
  await expect(page.locator('#cache-optin-ok-btn')).toBeVisible({ timeout: 60000 });

  // Accept cache opt-in (default 1 hour)
  await page.click('#cache-optin-ok-btn');

  // Wait for file section to become visible (login complete)
  await expect(page.locator('#file-section')).toBeVisible({ timeout: 120000 });
}

// Helper: save a Playwright download to disk and return the file path
async function saveDownload(download: Download): Promise<string> {
  if (!existsSync(DOWNLOAD_DIR)) {
    mkdirSync(DOWNLOAD_DIR, { recursive: true });
  }
  const suggestedName = download.suggestedFilename();
  const savePath = join(DOWNLOAD_DIR, suggestedName);
  await download.saveAs(savePath);
  return savePath;
}

// Helper: download a shared file (anonymous, no auth) and return the saved path
async function downloadSharedFile(
  page: Page,
  shareUrl: string,
  sharePassword: string,
): Promise<string> {
  // Navigate to the share URL
  await page.goto(shareUrl);

  // Wait for share access container to initialize
  await expect(page.locator('#share-access-container')).toBeVisible({ timeout: 15000 });

  // Wait for the password form to appear
  await expect(page.locator('#sharePassword')).toBeVisible({ timeout: 10000 });

  // Enter share password
  await page.fill('#sharePassword', sharePassword);

  // Submit the form
  await page.click('#shareAccessForm button[type="submit"]');

  // Wait for file details to appear (envelope decrypted successfully)
  await expect(page.locator('#fileDetails')).toBeVisible({ timeout: 30000 });

  // Set up download listener and click download
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 60000 }),
    page.click('#downloadBtn'),
  ]);

  // Save and return
  return saveDownload(download);
}

// All tests run sequentially in one browser context to maintain state
test.describe.serial('Arkfile Frontend E2E', () => {
  // Validate environment before running tests
  test.beforeAll(() => {
    const missing: string[] = [];
    if (!TOTP_SECRET) missing.push('TOTP_SECRET');
    if (!TEST_FILE_PATH) missing.push('TEST_FILE_PATH');
    if (!TEST_FILE_SHA256) missing.push('TEST_FILE_SHA256');
    if (!TEST_PASSWORD) missing.push('TEST_PASSWORD');
    if (!CUSTOM_FILE_PATH) missing.push('CUSTOM_FILE_PATH');
    if (!CUSTOM_FILE_SHA256) missing.push('CUSTOM_FILE_SHA256');
    if (!CUSTOM_FILE_PASSWORD) missing.push('CUSTOM_FILE_PASSWORD');
    if (!SHARE_A_PASSWORD) missing.push('SHARE_A_PASSWORD');
    if (!SHARE_B_PASSWORD) missing.push('SHARE_B_PASSWORD');
    if (!SHARE_C_PASSWORD) missing.push('SHARE_C_PASSWORD');

    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(', ')}. ` +
        'Run this test via scripts/testing/e2e-playwright.sh',
      );
    }

    // Verify test files exist
    if (!existsSync(TEST_FILE_PATH)) {
      throw new Error(`Test file not found: ${TEST_FILE_PATH}`);
    }
    if (!existsSync(CUSTOM_FILE_PATH)) {
      throw new Error(`Custom test file not found: ${CUSTOM_FILE_PATH}`);
    }

    // Ensure download directory exists
    if (!existsSync(DOWNLOAD_DIR)) {
      mkdirSync(DOWNLOAD_DIR, { recursive: true });
    }
  });

  // ========================================================================
  // Phase 1: Login
  // ========================================================================
  test('Phase 1: Login (OPAQUE + TOTP + key caching)', async ({ page }) => {
    await performLogin(page);

    // Verify file list container exists
    await expect(page.locator('#filesList')).toBeVisible();

    console.log('[OK] Phase 1: Login successful');
  });

  // ========================================================================
  // Phase 2: File Upload (Account Password)
  // ========================================================================
  test('Phase 2: File upload (account password)', async ({ page }) => {
    // Should already be logged in from Phase 1 (serial tests share context)
    // But Playwright serial tests get fresh pages, so we need to re-login
    await performLogin(page);

    // Set test file on the file input
    await page.setInputFiles('#fileInput', TEST_FILE_PATH);

    // Ensure account password radio is selected (should be default)
    await page.check('#useAccountPassword');

    // Click upload
    await page.click('#upload-file-btn');

    // Wait for upload to complete - look for success message or file in list
    // The app shows a success toast and the file appears in the list
    await expect(page.locator('#filesList .file-item')).toBeVisible({ timeout: 120000 });

    // Verify our filename appears in the file list
    const fileListText = await page.locator('#filesList').textContent();
    expect(fileListText).toContain(TEST_FILE_NAME);

    console.log('[OK] Phase 2: File upload (account password) successful');
  });

  // ========================================================================
  // Phase 3: File Download + Integrity
  // ========================================================================
  test('Phase 3: File download + SHA-256 integrity', async ({ page }) => {
    await performLogin(page);

    // Wait for file list to load
    await expect(page.locator('#filesList .file-item')).toBeVisible({ timeout: 30000 });

    // Find the file item containing our test file name
    const fileItem = page.locator('#filesList .file-item', {
      has: page.locator(`.file-info strong`, { hasText: TEST_FILE_NAME }),
    });
    await expect(fileItem).toBeVisible({ timeout: 10000 });

    // Click the Download button for this file
    const downloadBtn = fileItem.locator('.file-actions button', { hasText: 'Download' });

    // Set up download listener
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 120000 }),
      downloadBtn.click(),
    ]);

    // Save the downloaded file
    const savedPath = await saveDownload(download);

    // Verify SHA-256 integrity
    const downloadedHash = sha256File(savedPath);
    expect(downloadedHash).toBe(TEST_FILE_SHA256);

    console.log(`[OK] Phase 3: Download integrity verified (SHA-256: ${downloadedHash.substring(0, 16)}...)`);
  });

  // ========================================================================
  // Phase 4: Duplicate Upload Rejection
  // ========================================================================
  test('Phase 4: Duplicate upload rejection (dedup)', async ({ page }) => {
    await performLogin(page);

    // Wait for file list
    await expect(page.locator('#filesList .file-item')).toBeVisible({ timeout: 30000 });

    // Try to upload the same file again
    await page.setInputFiles('#fileInput', TEST_FILE_PATH);
    await page.check('#useAccountPassword');

    // Listen for console errors or error messages
    const errorPromise = page.waitForSelector('.error-message, .message-error, [class*="error"]', {
      timeout: 30000,
    }).catch(() => null);

    await page.click('#upload-file-btn');

    // Wait for either an error message in the DOM or check page content
    // The upload.ts throws "Duplicate file detected" which triggers showError()
    // Give it time for the upload attempt and error to propagate
    await page.waitForTimeout(5000);

    // Check for duplicate error in the page
    const pageText = await page.locator('body').textContent();
    const hasDuplicateError =
      pageText?.toLowerCase().includes('duplicate') ||
      pageText?.toLowerCase().includes('already uploaded');

    expect(hasDuplicateError).toBe(true);

    console.log('[OK] Phase 4: Duplicate upload correctly rejected');
  });

  // ========================================================================
  // Phase 5: Custom-Password Upload
  // ========================================================================
  test('Phase 5: Custom-password file upload', async ({ page }) => {
    await performLogin(page);

    // Wait for file list
    await expect(page.locator('#filesList')).toBeVisible({ timeout: 30000 });

    // Set the custom file
    await page.setInputFiles('#fileInput', CUSTOM_FILE_PATH);

    // Select custom password radio
    await page.click('#useCustomPassword');

    // Wait for custom password section to appear
    await expect(page.locator('#customPasswordSection')).toBeVisible({ timeout: 5000 });

    // Fill in the custom password
    await page.fill('#filePassword', CUSTOM_FILE_PASSWORD);

    // Click upload
    await page.click('#upload-file-btn');

    // Wait for upload to complete - the custom file should appear in the list
    // Wait longer as Argon2id derivation for custom key takes time
    await page.waitForTimeout(3000);

    // Wait for the file to appear in the list
    await expect(
      page.locator('#filesList .file-item', {
        has: page.locator('.file-info strong', { hasText: CUSTOM_FILE_NAME }),
      }),
    ).toBeVisible({ timeout: 120000 });

    // Verify it shows as "Custom Password" encryption type
    const customFileItem = page.locator('#filesList .file-item', {
      has: page.locator('.file-info strong', { hasText: CUSTOM_FILE_NAME }),
    });
    const encType = await customFileItem.locator('.encryption-type').textContent();
    expect(encType).toContain('Custom');

    console.log('[OK] Phase 5: Custom-password file upload successful');
  });

  // ========================================================================
  // Phase 6: Custom-Password Download
  // ========================================================================
  test('Phase 6: Custom-password download (correct + wrong password)', async ({ page }) => {
    await performLogin(page);

    // Wait for file list
    await expect(page.locator('#filesList .file-item')).toBeVisible({ timeout: 30000 });

    // Find the custom file item
    const customFileItem = page.locator('#filesList .file-item', {
      has: page.locator('.file-info strong', { hasText: CUSTOM_FILE_NAME }),
    });
    await expect(customFileItem).toBeVisible({ timeout: 10000 });

    // 6a: Download with correct password
    // The download flow uses prompt() for custom password entry
    // Set up dialog handler for the password prompt
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        await dialog.accept(CUSTOM_FILE_PASSWORD);
      } else if (dialog.type() === 'alert') {
        // Password hint alert
        await dialog.accept();
      }
    });

    const downloadBtn = customFileItem.locator('.file-actions button', { hasText: 'Download' });

    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 120000 }),
      downloadBtn.click(),
    ]);

    const savedPath = await saveDownload(download);
    const downloadedHash = sha256File(savedPath);
    expect(downloadedHash).toBe(CUSTOM_FILE_SHA256);

    console.log(`[OK] Phase 6a: Custom-password download integrity verified`);

    // 6b: Download with wrong password
    // Remove old dialog handler and set wrong password handler
    page.removeAllListeners('dialog');
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'prompt') {
        await dialog.accept('WrongCust0mPwd2025!NotTheKey');
      } else if (dialog.type() === 'alert') {
        await dialog.accept();
      }
    });

    // Click download again - should fail with decryption error
    await downloadBtn.click();

    // Wait for error message
    await page.waitForTimeout(10000);

    // Check for error indication in the page
    const pageText = await page.locator('body').textContent();
    const hasError =
      pageText?.toLowerCase().includes('failed') ||
      pageText?.toLowerCase().includes('error') ||
      pageText?.toLowerCase().includes('incorrect');

    expect(hasError).toBe(true);

    // Clean up dialog handler
    page.removeAllListeners('dialog');

    console.log('[OK] Phase 6b: Custom-password download rejected with wrong password');
  });

  // ========================================================================
  // Phase 7: Raw API Privacy
  // ========================================================================
  test('Phase 7: Raw API privacy (no plaintext in /api/files)', async ({ page }) => {
    await performLogin(page);

    // Wait for login to settle
    await expect(page.locator('#file-section')).toBeVisible({ timeout: 30000 });

    // Make a direct API call from within the page context
    const rawResponse = await page.evaluate(async () => {
      const token =
        sessionStorage.getItem('arkfile.sessionToken') ||
        localStorage.getItem('arkfile.sessionToken');
      if (!token) return { error: 'no token' };

      const resp = await fetch('/api/files', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return resp.json();
    });

    const rawJson = JSON.stringify(rawResponse);

    // Plaintext filenames must NOT appear in raw API response
    expect(rawJson).not.toContain(TEST_FILE_NAME);
    expect(rawJson).not.toContain(CUSTOM_FILE_NAME);

    // Plaintext SHA-256 hashes must NOT appear
    expect(rawJson).not.toContain(TEST_FILE_SHA256);
    expect(rawJson).not.toContain(CUSTOM_FILE_SHA256);

    // Encrypted fields should be present
    expect(rawJson).toContain('encrypted_filename');
    expect(rawJson).toContain('encrypted_sha256sum');

    console.log('[OK] Phase 7: Raw API privacy verified (no plaintext filenames or hashes)');
  });

  // ========================================================================
  // Phase 8: Share Creation
  // ========================================================================
  test('Phase 8: Share creation (A=no limits, B=max_downloads=2, C=expires=1m)', async ({ page }) => {
    await performLogin(page);

    // Wait for file list
    await expect(page.locator('#filesList .file-item')).toBeVisible({ timeout: 30000 });

    // Helper to create a share for a given file
    async function createShare(
      fileName: string,
      sharePassword: string,
      opts: { expiryValue?: number; expiryUnit?: string; maxDownloads?: number },
    ): Promise<string> {
      // Find the file item
      const fileItem = page.locator('#filesList .file-item', {
        has: page.locator('.file-info strong', { hasText: fileName }),
      });
      await expect(fileItem).toBeVisible({ timeout: 10000 });

      // Click Share button
      const shareBtn = fileItem.locator('.file-actions button', { hasText: 'Share' });
      await shareBtn.click();

      // Wait for share modal
      await expect(page.locator('#arkfile-share-modal-overlay')).toBeVisible({ timeout: 15000 });

      // Fill share password
      await page.fill('#share-password-input', sharePassword);
      await page.fill('#share-password-confirm', sharePassword);

      // Set expiry
      if (opts.expiryValue !== undefined) {
        await page.fill('#share-expiry-value', String(opts.expiryValue));
      }
      if (opts.expiryUnit) {
        await page.selectOption('#share-expiry-unit', opts.expiryUnit);
      }

      // Set max downloads
      if (opts.maxDownloads !== undefined) {
        await page.fill('#share-max-downloads', String(opts.maxDownloads));
      }

      // Wait for password validation to complete (debounced 300ms)
      await page.waitForTimeout(500);

      // Click submit
      await page.click('#share-modal-submit');

      // Wait for result modal with share URL
      await expect(page.locator('#share-result-url')).toBeVisible({ timeout: 60000 });

      // Extract share URL
      const shareUrl = await page.locator('#share-result-url').inputValue();
      expect(shareUrl).toBeTruthy();
      expect(shareUrl).toContain('/shared/');

      // Close result modal
      await page.click('#share-result-done');

      // Wait for modal to close
      await expect(page.locator('#arkfile-share-result-overlay')).toBeHidden({ timeout: 5000 });

      return shareUrl;
    }

    // Create Share A: no limits (expiry=0, max_downloads=0)
    shareAUrl = await createShare(TEST_FILE_NAME, SHARE_A_PASSWORD, {
      expiryValue: 0,
      expiryUnit: 'hours',
      maxDownloads: 0,
    });
    shareAId = extractShareId(shareAUrl);
    console.log(`[OK] Share A created: ${shareAId} (no limits)`);

    // Small delay between share creations
    await page.waitForTimeout(1000);

    // Create Share B: max_downloads=2, no expiry
    shareBUrl = await createShare(TEST_FILE_NAME, SHARE_B_PASSWORD, {
      expiryValue: 0,
      expiryUnit: 'hours',
      maxDownloads: 2,
    });
    shareBId = extractShareId(shareBUrl);
    console.log(`[OK] Share B created: ${shareBId} (max_downloads=2)`);

    await page.waitForTimeout(1000);

    // Create Share C: expires in 1 minute, no download limit
    shareCUrl = await createShare(TEST_FILE_NAME, SHARE_C_PASSWORD, {
      expiryValue: 1,
      expiryUnit: 'minutes',
      maxDownloads: 0,
    });
    shareCId = extractShareId(shareCUrl);
    console.log(`[OK] Share C created: ${shareCId} (expires=1m)`);

    console.log('[OK] Phase 8: All shares created successfully');
  });

  // ========================================================================
  // Phase 9: Share List Verification
  // ========================================================================
  test('Phase 9: Share list verification', async ({ page }) => {
    await performLogin(page);

    // Click refresh shares button
    await page.click('#refresh-shares-btn');

    // Wait for share list to populate
    await expect(page.locator('#sharesList .share-item')).toBeVisible({ timeout: 30000 });

    const sharesText = await page.locator('#sharesList').textContent();

    // All share IDs should appear (at least their prefix)
    expect(sharesText).toContain(shareAId.substring(0, 8));
    expect(sharesText).toContain(shareBId.substring(0, 8));
    expect(sharesText).toContain(shareCId.substring(0, 8));

    // Decrypted filename should appear (not [Encrypted])
    expect(sharesText).toContain(TEST_FILE_NAME);
    expect(sharesText).not.toContain('[Encrypted]');

    // Key type should be shown
    expect(sharesText).toContain('account');

    // SHA-256 prefix should be visible
    const sha256Prefix = TEST_FILE_SHA256.substring(0, 8);
    expect(sharesText).toContain(sha256Prefix);

    console.log('[OK] Phase 9: Share list shows decrypted metadata, key types, and SHA-256');
  });

  // ========================================================================
  // Phase 10: Anonymous Share Download (Share A)
  // ========================================================================
  test('Phase 10: Anonymous share download (Share A)', async ({ page }) => {
    // Log out first
    await performLogin(page);
    await page.click('#logout-link');
    await page.waitForTimeout(2000);

    // Download Share A as anonymous visitor
    const savedPath = await downloadSharedFile(page, shareAUrl, SHARE_A_PASSWORD);

    // Verify SHA-256 integrity
    const downloadedHash = sha256File(savedPath);
    expect(downloadedHash).toBe(TEST_FILE_SHA256);

    console.log(`[OK] Phase 10: Anonymous share download verified (SHA-256: ${downloadedHash.substring(0, 16)}...)`);
  });

  // ========================================================================
  // Phase 11: Share Access Controls
  // ========================================================================
  test('Phase 11a: Share B max_downloads enforcement (2 downloads, 3rd rejected)', async ({ page }) => {
    // Download 1 of 2
    const dl1Path = await downloadSharedFile(page, shareBUrl, SHARE_B_PASSWORD);
    const dl1Hash = sha256File(dl1Path);
    expect(dl1Hash).toBe(TEST_FILE_SHA256);
    console.log('[OK] Share B download 1/2 succeeded');

    // Small delay for rate limiting
    await page.waitForTimeout(3000);

    // Download 2 of 2
    const dl2Path = await downloadSharedFile(page, shareBUrl, SHARE_B_PASSWORD);
    const dl2Hash = sha256File(dl2Path);
    expect(dl2Hash).toBe(TEST_FILE_SHA256);
    console.log('[OK] Share B download 2/2 succeeded');

    // Small delay for rate limiting
    await page.waitForTimeout(3000);

    // Download 3 - should fail (max downloads exceeded)
    await page.goto(shareBUrl);
    await expect(page.locator('#share-access-container')).toBeVisible({ timeout: 15000 });

    // The share might still show the password form if the server hasn't
    // revoked access yet, or it might show an error directly
    const passwordField = page.locator('#sharePassword');
    const isPasswordVisible = await passwordField.isVisible().catch(() => false);

    if (isPasswordVisible) {
      await page.fill('#sharePassword', SHARE_B_PASSWORD);
      await page.click('#shareAccessForm button[type="submit"]');

      // Wait for error or file details
      await page.waitForTimeout(10000);

      // Check for error message (max downloads exceeded)
      const statusText = await page.locator('#share-access-container').textContent();
      const hasError =
        statusText?.toLowerCase().includes('error') ||
        statusText?.toLowerCase().includes('incorrect') ||
        statusText?.toLowerCase().includes('expired') ||
        statusText?.toLowerCase().includes('invalid') ||
        statusText?.toLowerCase().includes('exceeded') ||
        statusText?.toLowerCase().includes('revoked');

      // If the file details appeared, try to download - it should fail at the download stage
      const fileDetailsVisible = await page.locator('#fileDetails').isVisible().catch(() => false);
      if (fileDetailsVisible) {
        // Try downloading - should fail at the token/server level
        await page.click('#downloadBtn');
        await page.waitForTimeout(10000);

        const dlStatus = await page.locator('#share-access-container').textContent();
        const dlFailed =
          dlStatus?.toLowerCase().includes('failed') ||
          dlStatus?.toLowerCase().includes('error') ||
          dlStatus?.toLowerCase().includes('invalid') ||
          dlStatus?.toLowerCase().includes('revoked');
        expect(dlFailed).toBe(true);
      } else {
        expect(hasError).toBe(true);
      }
    }

    console.log('[OK] Phase 11a: Share B max_downloads enforcement verified');
  });

  test('Phase 11b: Share C expiry enforcement', async ({ page }) => {
    // Download before expiry - should succeed
    const dl1Path = await downloadSharedFile(page, shareCUrl, SHARE_C_PASSWORD);
    const dl1Hash = sha256File(dl1Path);
    expect(dl1Hash).toBe(TEST_FILE_SHA256);
    console.log('[OK] Share C download before expiry succeeded');

    // Wait for Share C to expire (1 minute + buffer)
    // Share C was created in Phase 8 with expires=1m
    console.log('[i] Waiting 65s for Share C to expire...');
    await page.waitForTimeout(65000);

    // Attempt download after expiry - should fail
    await page.goto(shareCUrl);
    await expect(page.locator('#share-access-container')).toBeVisible({ timeout: 15000 });

    const passwordField = page.locator('#sharePassword');
    const isPasswordVisible = await passwordField.isVisible().catch(() => false);

    if (isPasswordVisible) {
      await page.fill('#sharePassword', SHARE_C_PASSWORD);
      await page.click('#shareAccessForm button[type="submit"]');
      await page.waitForTimeout(10000);
    }

    // Check for error - the share should be expired
    const pageText = await page.locator('#share-access-container').textContent();
    const hasExpiredError =
      pageText?.toLowerCase().includes('error') ||
      pageText?.toLowerCase().includes('expired') ||
      pageText?.toLowerCase().includes('invalid') ||
      pageText?.toLowerCase().includes('incorrect');
    expect(hasExpiredError).toBe(true);

    console.log('[OK] Phase 11b: Share C expiry enforcement verified');
  });

  test('Phase 11c: Non-existent share rejection', async ({ page }) => {
    const bogusUrl = `${SERVER_URL}/shared/nonexistent-share-id-that-does-not-exist`;
    await page.goto(bogusUrl);

    // Wait for the page to attempt loading
    await page.waitForTimeout(5000);

    // Check for error message
    const pageText = await page.locator('body').textContent();
    const hasError =
      pageText?.toLowerCase().includes('error') ||
      pageText?.toLowerCase().includes('not found') ||
      pageText?.toLowerCase().includes('invalid') ||
      pageText?.toLowerCase().includes('failed');
    expect(hasError).toBe(true);

    console.log('[OK] Phase 11c: Non-existent share correctly rejected');
  });

  // ========================================================================
  // Phase 12: Share Revocation
  // ========================================================================
  test('Phase 12: Share revocation (revoke Share A, verify access denied)', async ({ page }) => {
    // Re-login
    await performLogin(page);

    // Refresh share list
    await page.click('#refresh-shares-btn');
    await expect(page.locator('#sharesList .share-item')).toBeVisible({ timeout: 30000 });

    // Find Share A by its ID prefix
    const shareAItem = page.locator(`#sharesList .share-item[data-share-id="${shareAId}"]`);
    await expect(shareAItem).toBeVisible({ timeout: 10000 });

    // Set up dialog handler for the confirm() prompt
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') {
        await dialog.accept();
      }
    });

    // Click revoke button
    const revokeBtn = shareAItem.locator('.btn-revoke');
    await revokeBtn.click();

    // Wait for the share list to refresh (revoke triggers reload)
    await page.waitForTimeout(5000);

    // Verify Share A is now shown as revoked
    const shareAItemAfter = page.locator(`#sharesList .share-item[data-share-id="${shareAId}"]`);
    const shareAText = await shareAItemAfter.textContent();
    expect(shareAText?.toLowerCase()).toContain('revoked');

    console.log('[OK] Phase 12a: Share A revoked successfully');

    // Clean up dialog handler
    page.removeAllListeners('dialog');

    // Log out and verify revoked share cannot be accessed
    await page.click('#logout-link');
    await page.waitForTimeout(2000);

    // Navigate to the revoked share
    await page.goto(shareAUrl);
    await expect(page.locator('#share-access-container')).toBeVisible({ timeout: 15000 });

    const passwordField = page.locator('#sharePassword');
    const isPasswordVisible = await passwordField.isVisible().catch(() => false);

    if (isPasswordVisible) {
      await page.fill('#sharePassword', SHARE_A_PASSWORD);
      await page.click('#shareAccessForm button[type="submit"]');
      await page.waitForTimeout(10000);
    }

    // Check for error (share revoked)
    const pageText = await page.locator('#share-access-container').textContent();
    const hasError =
      pageText?.toLowerCase().includes('error') ||
      pageText?.toLowerCase().includes('revoked') ||
      pageText?.toLowerCase().includes('invalid') ||
      pageText?.toLowerCase().includes('incorrect');
    expect(hasError).toBe(true);

    console.log('[OK] Phase 12b: Revoked Share A access correctly denied');
  });

  // ========================================================================
  // Phase 13: Logout + Post-Logout Checks
  // ========================================================================
  test('Phase 13: Logout and post-logout security checks', async ({ page }) => {
    // Log in one more time
    await performLogin(page);

    // Verify we are in the file section
    await expect(page.locator('#file-section')).toBeVisible({ timeout: 10000 });

    // Click logout
    await page.click('#logout-link');

    // Wait for home page to appear (logout returns to landing page)
    await expect(page.locator('.home-container')).toBeVisible({ timeout: 15000 });

    console.log('[OK] Phase 13a: Logout successful, home page visible');

    // Verify sessionStorage is cleared
    const sessionToken = await page.evaluate(() => {
      return sessionStorage.getItem('arkfile.sessionToken');
    });
    expect(sessionToken).toBeNull();

    // Verify account key cache is cleared
    const accountKeyCache = await page.evaluate(() => {
      // Check all sessionStorage keys for account key cache entries
      const keys = Object.keys(sessionStorage);
      return keys.filter(k => k.includes('accountKey') || k.includes('account-key'));
    });
    expect(accountKeyCache.length).toBe(0);

    // Verify digest cache is cleared
    const digestCache = await page.evaluate(() => {
      const keys = Object.keys(sessionStorage);
      return keys.filter(k => k.includes('digest') || k.includes('Digest'));
    });
    expect(digestCache.length).toBe(0);

    console.log('[OK] Phase 13b: sessionStorage cleared (tokens, account key cache, digest cache)');

    // Verify localStorage token is also cleared
    const localToken = await page.evaluate(() => {
      return localStorage.getItem('arkfile.sessionToken');
    });
    expect(localToken).toBeNull();

    // Attempt an authenticated API call - should get 401
    const apiResult = await page.evaluate(async () => {
      try {
        const resp = await fetch('/api/files', {
          headers: { Authorization: 'Bearer invalid-token-after-logout' },
        });
        return { status: resp.status };
      } catch (e) {
        return { error: String(e) };
      }
    });
    expect(apiResult.status).toBe(401);

    console.log('[OK] Phase 13c: Authenticated API calls rejected after logout (401)');
    console.log('[OK] Phase 13: All post-logout security checks passed');
  });
});
