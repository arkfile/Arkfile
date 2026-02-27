/**
 * File sharing functionality — inline share creation from the file list
 *
 * This module handles the complete share creation flow:
 * 1. Fetch file metadata (encrypted FEK, filename, size, hash)
 * 2. Get the Account Key (from cache or prompt)
 * 3. Decrypt the FEK client-side
 * 4. Prompt the user for a share password
 * 5. Use ShareCreator to encrypt the FEK for the share and POST to the server
 * 6. Display the resulting share URL
 *
 * SECURITY: The FEK is decrypted in the browser and re-encrypted with the
 * share password. The server never sees the plaintext FEK.
 */

import { authenticatedFetch, getToken, getUsernameFromToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { promptForAccountKeyPassword } from '../ui/password-modal';
import {
  getCachedAccountKey,
  isAccountKeyLocked,
  deriveFileEncryptionKeyWithCache,
  type CacheDurationHours,
} from '../crypto/file-encryption';
import { decryptChunk } from '../crypto/aes-gcm';
import { ShareCreator, type FileInfo } from '../shares/share-creation';
import { validateSharePassword } from '../crypto/password-validation';

// ============================================================================
// Types
// ============================================================================

/** Mirrors the /api/files/:id/meta response */
interface FileMetaResponse {
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  password_hint: string;
  password_type: string;
  size_bytes: number;
  chunk_size: number;
  total_chunks: number;
}

// ============================================================================
// Helpers (shared with download.ts — keep in sync or extract later)
// ============================================================================

function base64ToBytes(base64: string): Uint8Array {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function getAccountKey(username: string): Promise<Uint8Array | null> {
  if (isAccountKeyLocked()) {
    showError('Account Key is locked. Please unlock it first.');
    return null;
  }
  const cached = getCachedAccountKey(username);
  if (cached) return cached;

  const result = await promptForAccountKeyPassword();
  if (!result) return null;

  try {
    return await deriveFileEncryptionKeyWithCache(
      result.password,
      username,
      'account',
      result.cacheDuration as CacheDurationHours | undefined,
    );
  } catch (err) {
    console.error('Failed to derive Account Key:', err);
    showError('Failed to derive encryption key. Please check your password.');
    return null;
  }
}

async function decryptFEK(encryptedFekBase64: string, accountKey: Uint8Array): Promise<Uint8Array> {
  const raw = base64ToBytes(encryptedFekBase64);
  if (raw.length < 31) throw new Error(`Encrypted FEK too short: ${raw.length}`);
  if (raw[0] !== 0x01) throw new Error(`Unsupported envelope version: 0x${raw[0].toString(16)}`);
  const fek = await decryptChunk(raw.slice(2), accountKey);
  if (fek.length !== 32) throw new Error(`Invalid FEK length: ${fek.length}`);
  return fek;
}

/** Decrypt a metadata field (filename / sha256) that uses its own nonce */
async function decryptMetadataField(
  ciphertextB64: string,
  nonceB64: string,
  key: Uint8Array,
): Promise<string> {
  const nonce = base64ToBytes(nonceB64);
  const ciphertext = base64ToBytes(ciphertextB64);
  // Metadata is encrypted as nonce‖ciphertext‖tag but the server returns them
  // separately, so we need to reassemble for decryptChunk which expects
  // [nonce (12)][ciphertext][tag (16)]
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);
  const plainBytes = await decryptChunk(combined, key);
  return new TextDecoder().decode(plainBytes);
}

// ============================================================================
// Share Password Prompt (modal)
// ============================================================================

/**
 * Show a modal that asks for a share password and optional expiry.
 * Returns null if the user cancels.
 */
function promptForSharePassword(): Promise<{ password: string; expiresHours: number; maxAccesses?: number } | null> {
  return new Promise((resolve) => {
    const OVERLAY_ID = 'arkfile-share-modal-overlay';

    // Remove any existing modal
    document.getElementById(OVERLAY_ID)?.remove();

    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;
    overlay.className = 'password-modal-overlay';
    overlay.innerHTML = `
      <div class="password-modal" role="dialog" aria-modal="true" aria-labelledby="share-modal-title">
        <div class="password-modal-header">
          <h2 id="share-modal-title">Create Share</h2>
          <button type="button" class="password-modal-close" id="share-modal-close">&times;</button>
        </div>
        <div class="password-modal-body">
          <p class="password-modal-message">
            Set a password for this share. The recipient will need this password to download the file.
          </p>
          <form id="share-modal-form" class="password-modal-form">
            <div class="password-modal-field">
              <label for="share-password-input">Share Password</label>
              <input type="password" id="share-password-input" class="password-modal-input"
                     placeholder="Strong password (18+ chars recommended)" required autofocus />
              <ul id="share-pw-feedback" style="list-style: none; padding: 0; margin: 6px 0 0 0; font-size: 0.85em;"></ul>
            </div>
            <div class="password-modal-field">
              <label for="share-password-confirm">Confirm Password</label>
              <input type="password" id="share-password-confirm" class="password-modal-input"
                     placeholder="Confirm password" required />
            </div>
            <div class="password-modal-duration">
              <label for="share-expiry-select">Expires after</label>
              <select id="share-expiry-select" class="password-modal-select">
                <option value="24">24 hours</option>
                <option value="72">3 days</option>
                <option value="168">7 days</option>
                <option value="720">30 days</option>
                <option value="0">Never</option>
              </select>
            </div>
            <div class="password-modal-field">
              <label for="share-max-downloads">Max downloads (0 = unlimited)</label>
              <input type="number" id="share-max-downloads" class="password-modal-input"
                     min="0" max="10000" value="0" />
            </div>
          </form>
          <p id="share-modal-error" style="color: var(--error-color, #ef4444); margin-top: 8px; display: none;"></p>
        </div>
        <div class="password-modal-footer">
          <button type="button" class="password-modal-btn password-modal-btn-cancel" id="share-modal-cancel">Cancel</button>
          <button type="submit" form="share-modal-form" class="password-modal-btn password-modal-btn-submit" id="share-modal-submit">Create Share</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const form = document.getElementById('share-modal-form') as HTMLFormElement;
    const pwInput = document.getElementById('share-password-input') as HTMLInputElement;
    const confirmInput = document.getElementById('share-password-confirm') as HTMLInputElement;
    const expirySelect = document.getElementById('share-expiry-select') as HTMLSelectElement;
    const maxDownloadsInput = document.getElementById('share-max-downloads') as HTMLInputElement;
    const feedbackEl = document.getElementById('share-pw-feedback') as HTMLUListElement;
    const errorEl = document.getElementById('share-modal-error') as HTMLElement;
    const submitBtn = document.getElementById('share-modal-submit') as HTMLButtonElement;

    // Track whether the password currently meets requirements
    let passwordValid = false;

    const cleanup = () => {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
    };

    const cancel = () => { cleanup(); resolve(null); };

    // Real-time password validation feedback (debounced)
    let validationTimer: ReturnType<typeof setTimeout> | null = null;
    pwInput.addEventListener('input', () => {
      if (validationTimer) clearTimeout(validationTimer);
      validationTimer = setTimeout(async () => {
        const pw = pwInput.value;
        if (!pw) {
          feedbackEl.innerHTML = '';
          passwordValid = false;
          return;
        }
        const result = await validateSharePassword(pw);
        passwordValid = result.meets_requirements;
        // Build feedback list
        const items: string[] = [];
        const req = result.requirements;
        const icon = (met: boolean) => met ? '✅' : '❌';
        items.push(`<li>${icon(req.length.met)} ${req.length.message}</li>`);
        items.push(`<li>${icon(req.uppercase.met)} ${req.uppercase.message}</li>`);
        items.push(`<li>${icon(req.lowercase.met)} ${req.lowercase.message}</li>`);
        items.push(`<li>${icon(req.number.met)} ${req.number.message}</li>`);
        items.push(`<li>${icon(req.special.met)} ${req.special.message}</li>`);
        // Entropy / strength
        const strengthLabels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
        const label = strengthLabels[result.strength_score] || 'Unknown';
        const color = result.meets_requirements ? 'var(--success-color, #22c55e)' : 'var(--error-color, #ef4444)';
        items.push(`<li style="color:${color}; margin-top:4px;">Strength: ${label} (${Math.round(result.entropy)} bits)</li>`);
        feedbackEl.innerHTML = items.join('');
      }, 300);
    });

    const submit = async (e: Event) => {
      e.preventDefault();
      const pw = pwInput.value;
      const confirmVal = confirmInput.value;

      if (pw !== confirmVal) {
        errorEl.textContent = 'Passwords do not match.';
        errorEl.style.display = 'block';
        return;
      }

      // Run full validation (in case debounce hasn't fired yet)
      submitBtn.disabled = true;
      submitBtn.textContent = 'Validating…';
      const validation = await validateSharePassword(pw);
      if (!validation.meets_requirements) {
        errorEl.textContent = validation.suggestions.join('. ') || 'Password does not meet requirements.';
        errorEl.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Share';
        return;
      }

      const maxDl = parseInt(maxDownloadsInput.value, 10);
      const result: { password: string; expiresHours: number; maxAccesses?: number } = {
        password: pw,
        expiresHours: parseInt(expirySelect.value, 10),
      };
      if (maxDl > 0) result.maxAccesses = maxDl;

      cleanup();
      resolve(result);
    };

    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') cancel(); };

    form.addEventListener('submit', submit);
    document.getElementById('share-modal-cancel')!.addEventListener('click', cancel);
    document.getElementById('share-modal-close')!.addEventListener('click', cancel);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
    document.addEventListener('keydown', onKey);

    setTimeout(() => pwInput.focus(), 100);
  });
}

// ============================================================================
// Share URL Result Modal
// ============================================================================

function showShareUrlModal(shareUrl: string): void {
  const OVERLAY_ID = 'arkfile-share-result-overlay';
  document.getElementById(OVERLAY_ID)?.remove();

  const overlay = document.createElement('div');
  overlay.id = OVERLAY_ID;
  overlay.className = 'password-modal-overlay';
  overlay.innerHTML = `
    <div class="password-modal" role="dialog" aria-modal="true">
      <div class="password-modal-header">
        <h2>Share Created</h2>
        <button type="button" class="password-modal-close" id="share-result-close">&times;</button>
      </div>
      <div class="password-modal-body">
        <p class="password-modal-message">
          Your share link is ready. Send this URL along with the share password to the recipient.
        </p>
        <div class="password-modal-field">
          <label for="share-result-url">Share URL</label>
          <input type="text" id="share-result-url" class="password-modal-input"
                 value="${escapeAttr(shareUrl)}" readonly onclick="this.select()" />
        </div>
      </div>
      <div class="password-modal-footer">
        <button type="button" class="password-modal-btn password-modal-btn-submit" id="share-result-copy">
          Copy URL
        </button>
        <button type="button" class="password-modal-btn password-modal-btn-cancel" id="share-result-done">
          Done
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  const close = () => overlay.remove();

  document.getElementById('share-result-close')!.addEventListener('click', close);
  document.getElementById('share-result-done')!.addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

  document.getElementById('share-result-copy')!.addEventListener('click', async () => {
    const input = document.getElementById('share-result-url') as HTMLInputElement;
    try {
      await navigator.clipboard.writeText(input.value);
      showSuccess('Share URL copied to clipboard!');
    } catch {
      input.select();
    }
  });
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Initiate the share creation flow for a file.
 *
 * Called by the Share button in the file list.
 *
 * @param fileId       - The file's UUID
 * @param passwordType - 'account' or 'custom'
 */
export async function shareFile(fileId: string, passwordType: string): Promise<void> {
  try {
    const authToken = getToken();
    if (!authToken) { showError('Not authenticated. Please log in again.'); return; }

    const username = getUsernameFromToken();
    if (!username) { showError('Username not found. Please log in again.'); return; }

    // 1. Fetch file metadata
    const metaResp = await authenticatedFetch(`/api/files/${fileId}/meta`);
    if (!metaResp.ok) {
      const err = await metaResp.json().catch(() => ({}));
      showError(err.message || 'Failed to retrieve file metadata.');
      return;
    }
    const meta: FileMetaResponse = await metaResp.json();

    // 2. Get Account Key
    const accountKey = await getAccountKey(username);
    if (!accountKey) return; // user cancelled

    // 3. Decrypt FEK
    let fek: Uint8Array;
    if (passwordType === 'account' || meta.password_type === 'account') {
      try {
        fek = await decryptFEK(meta.encrypted_fek, accountKey);
      } catch (err) {
        console.error('Failed to decrypt FEK:', err);
        showError('Failed to decrypt file key. Your password may be incorrect.');
        return;
      }
    } else {
      // Custom-password file: need the custom password to decrypt the FEK
      const hint = meta.password_hint;
      if (hint) alert(`Password Hint: ${hint}`);
      const customPw = prompt('Enter the file password:');
      if (!customPw) return;
      try {
        const { deriveFileEncryptionKey } = await import('../crypto/file-encryption');
        const customKey = await deriveFileEncryptionKey(customPw, username, 'custom');
        fek = await decryptFEK(meta.encrypted_fek, customKey);
      } catch (err) {
        console.error('Failed to decrypt FEK with custom password:', err);
        showError('Failed to decrypt file key. Check your password.');
        return;
      }
    }

    // 4. Decrypt filename for the share envelope metadata
    let filename = 'unknown';
    try {
      filename = await decryptMetadataField(
        meta.encrypted_filename,
        meta.filename_nonce,
        accountKey,
      );
    } catch {
      console.warn('Could not decrypt filename for share metadata');
    }

    // 5. Decrypt sha256 for the share envelope metadata
    let sha256 = '';
    try {
      sha256 = await decryptMetadataField(
        meta.encrypted_sha256sum,
        meta.sha256sum_nonce,
        accountKey,
      );
    } catch {
      console.warn('Could not decrypt sha256 for share metadata');
    }

    // 6. Prompt for share password
    const shareInput = await promptForSharePassword();
    if (!shareInput) return; // user cancelled

    // 7. Build FileInfo and create the share
    const fileInfo: FileInfo = {
      filename,
      fek,
      sizeBytes: meta.size_bytes,
      sha256,
    };

    const creator = new ShareCreator(fileInfo);
    const shareRequest: Parameters<typeof creator.createShare>[0] = {
      fileId,
      sharePassword: shareInput.password,
      expiresAfterHours: shareInput.expiresHours,
    };
    if (shareInput.maxAccesses !== undefined) {
      shareRequest.maxAccesses = shareInput.maxAccesses;
    }
    const result = await creator.createShare(shareRequest);

    if (!result.success) {
      showError(result.error || 'Failed to create share.');
      return;
    }

    // 8. Show the share URL
    showShareUrlModal(result.shareUrl!);

  } catch (err) {
    console.error('Share creation error:', err);
    showError('An error occurred while creating the share.');
  }
}
