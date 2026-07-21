/**
 * Share Access UI with Chunked Download Support
 *
 * Handles accessing shared files with password-based decryption
 * and chunked download for efficient downloads.
 *
 * LARGE FILE DOWNLOADS
 * --------------------
 * Prefer Service Worker streaming (/sw-download.js). The SW intercepts a
 * synthetic /sw-download/<uuid> request and responds with a streaming Response
 * carrying Content-Disposition: attachment so the browser writes bytes to disk
 * with chunk-bounded page memory and no Arkfile-imposed size cap.
 *
 * Whole-file SHA-256 on the SW path may finish only after bytes are on disk
 * (same post-write class as CLI computeStreamingSHA256 and offline decrypt-blob).
 * Never claim unqualified success on mismatch; show expected digest from the
 * share envelope and tips to Verify File / delete a bad download.
 *
 * Blob fallback remains when SW is unavailable or cannot initialize before
 * generator consumption. It buffers the complete plaintext with no Arkfile
 * size cap; browser resources may still fail. Check hashVerification BEFORE
 * triggerBrowserDownloadFromUrl; revoke on mismatch and do not claim success.
 */

import { shareCrypto } from './share-crypto';
import { showError, showSuccess } from '../ui/messages';
import { isSwAvailable } from '../files/sw-streaming-download';
import {
  downloadSharedFileWithTicket,
  triggerBrowserDownloadFromUrl,
  StreamingDownloadResult,
} from '../files/streaming-download';
import {
  finalizeDownloadIntegrity,
  showSwStreamingTip,
  showBlobBufferWarning,
  showPartialDownloadWarning,
} from '../files/download-integrity';
import { addPasswordToggle } from '../utils/password-toggle';
import { ShareTicketHolder } from './share-ticket';

/**
 * Map envelope API failures to stable status identities for Playwright and UI.
 * Server messages from GetShareEnvelope distinguish expired / exhausted / revoked / not found.
 */
function classifyShareAccessError(status: number, apiMessage: string): string {
  const msg = apiMessage.toLowerCase();
  if (status === 404 || msg.includes('not found')) {
    return 'share-not-found';
  }
  if (msg.includes('expired')) {
    return 'share-expired';
  }
  if (msg.includes('exhausted') || msg.includes('download limit')) {
    return 'share-max-downloads';
  }
  return 'share-revoked';
}

interface ShareEnvelope {
  share_id: string;
  file_id: string;
  salt: string;
  encrypted_envelope: string;
  size_bytes: number;
}

export class ShareAccessUI {
  private containerId: string;
  private shareId: string;
  private envelope: ShareEnvelope | null = null;
  private downloadToken: string | null = null; // Static token from envelope (proof of decryption)
  private ticketHolder: ShareTicketHolder | null = null;
  /** Expected SHA-256 from decrypted share envelope metadata (when present). */
  private expectedSha256: string | undefined;

  constructor(containerId: string, shareId: string) {
    this.containerId = containerId;
    this.shareId = shareId;
  }

  async initialize(): Promise<void> {
    const container = document.getElementById(this.containerId);
    if (!container) return;

    // Render initial password form
    container.innerHTML = `
      <h2>Access Shared File</h2>
      <div class="file-icon">Locked</div>
      <p>This file is protected with a password.</p>
      
      <form id="shareAccessForm" class="password-form">
        <div class="form-group">
          <label for="sharePassword">Share Password:</label>
          <input type="password" id="sharePassword" placeholder="Enter share password" required>
        </div>
        <button type="submit" class="btn primary">Unlock File</button>
      </form>
      
      <div id="shareStatus" class="hidden"></div>
      
      <div id="fileDetails" class="hidden">
        <h3>File Details</h3>
        <p id="fileNameDisplay"></p>
        <p id="fileSizeDisplay"></p>
        <div id="shareExpectedDigestRow" class="hidden" style="margin: 0.75rem 0;">
          <p><strong>Expected SHA-256</strong></p>
          <code id="shareExpectedDigest" style="word-break: break-all; font-size: 0.85rem;"></code>
          <button type="button" id="shareCopyDigestBtn" class="btn-copy-hash" style="margin-left: 0.5rem;">copy</button>
        </div>
        <p id="swUnavailableNote" class="warning-note" style="display:none;"></p>
        <button id="downloadBtn" class="btn primary">Download</button>
        <div id="share-integrity-panel" class="hidden" style="margin-top: 1rem;"></div>
        <div id="share-verify-section" style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--depth-4, #444);">
          <h3>Verify File</h3>
          <p style="font-size: 0.9rem;">Hash a local copy and compare it to the expected digest (works offline once you have the digest).</p>
          <label for="share-verify-file-input">Local file</label>
          <input type="file" id="share-verify-file-input">
          <label for="share-verify-expected" style="display:block; margin-top: 0.5rem;">Expected SHA-256</label>
          <input type="text" id="share-verify-expected" placeholder="64 hex characters" style="width: 100%; font-family: monospace; font-size: 0.85rem;">
          <button type="button" id="share-verify-run-btn" class="btn secondary" style="margin-top: 0.5rem;">Verify</button>
          <div id="share-verify-result" style="margin-top: 0.5rem;"></div>
        </div>
      </div>
    `;

    const form = document.getElementById('shareAccessForm') as HTMLFormElement;
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleUnlock();
    });

    const sharePassword = document.getElementById('sharePassword') as HTMLInputElement | null;
    if (sharePassword) {
      addPasswordToggle(sharePassword);
    }

    this.wireShareVerify();
  }

  private wireShareVerify(): void {
    const runBtn = document.getElementById('share-verify-run-btn');
    if (!runBtn || (runBtn as HTMLElement).dataset['wired'] === '1') return;
    (runBtn as HTMLElement).dataset['wired'] = '1';

    runBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { verifyLocalFileDigest } = await import('../files/verify-file.js');
      const fileInput = document.getElementById('share-verify-file-input') as HTMLInputElement | null;
      const expectedInput = document.getElementById('share-verify-expected') as HTMLInputElement | null;
      const resultEl = document.getElementById('share-verify-result');
      const file = fileInput?.files?.[0];
      if (!file) {
        showError('Choose a local file to verify.');
        return;
      }
      const expected = expectedInput?.value || this.expectedSha256 || '';
      if (!expected.trim()) {
        showError('Paste the expected SHA-256 hex digest.');
        return;
      }
      if (resultEl) {
        resultEl.textContent = 'Hashing…';
        resultEl.className = '';
      }
      const result = await verifyLocalFileDigest(file, expected);
      if (!resultEl) return;
      if (result.outcome === 'match') {
        resultEl.textContent = 'Match: local file SHA-256 matches the expected digest.';
        resultEl.className = 'success-message';
      } else if (result.outcome === 'mismatch') {
        resultEl.textContent = 'Mismatch: local file does not match the expected digest.';
        resultEl.className = 'error-message';
      } else if (result.outcome === 'invalid_expected') {
        resultEl.textContent = 'Expected digest must be 64 hexadecimal characters.';
        resultEl.className = 'error-message';
      } else {
        resultEl.textContent = result.error || 'Verification failed.';
        resultEl.className = 'error-message';
      }
    });
  }

  private async handleUnlock(): Promise<void> {
    const passwordInput = document.getElementById('sharePassword') as HTMLInputElement;
    const password = passwordInput.value;
    const statusDiv = document.getElementById('shareStatus');
    
    if (!password) {
      showError('Please enter the password');
      return;
    }

    // Show the progress message immediately when unlock starts.
    //
    // We previously tried a 5-second quiet-period pattern (plain "Verifying..."
    // for the first 5 s, then swap to the informative message), but the
    // Argon2id KDF inside `decryptShareEnvelope` runs synchronously on the
    // main thread and blocks the JavaScript event loop for its entire
    // duration (3–4 minutes observed on Tor Browser Safer mode). With the
    // event loop blocked, `setTimeout` callbacks cannot fire, so the
    // 5-second timer never executed and users on slow devices/networks
    // never saw the message.
    //
    // The correct fix would be to move Argon2id into a Web Worker so the
    // event loop stays responsive during the derivation. Until then, the
    // simplest honest UX is: always show the message. Fast desktops see it
    // for <1 s before the unlock completes; slow ones see it for the
    // entire wait. Wording is deliberately neutral — does not reveal
    // cryptographic internals like "decrypting password" or "Argon2id"
    // (privacy posture) and makes no oversold speed promise.
    if (statusDiv) {
      statusDiv.textContent =
        'Verifying… can take a few minutes on slow networks/old devices.';
      statusDiv.className = '';
      statusDiv.removeAttribute('data-testid');
    }
    console.log('[arkfile-share] Verifying share access…');

    try {
      // 1. Get share envelope (public metadata + encrypted FEK)
      if (!this.envelope) {
        const response = await fetch(`/api/public/shares/${this.shareId}/envelope`);
        if (!response.ok) {
          // 403: share is expired, revoked, or download limit reached
          // 404: share does not exist
          // Both mean the recipient cannot access this share - show a clear message
          // and do not attempt decryption (no point running the KDF)
          if (response.status === 403 || response.status === 404) {
            const errBody = await response.json().catch(() => ({} as { message?: string; error?: string }));
            const apiMessage = String(errBody.message || errBody.error || '');
            const testId = classifyShareAccessError(response.status, apiMessage);
            if (statusDiv) {
              statusDiv.textContent = 'This share is no longer valid.';
              statusDiv.className = 'error-message';
              statusDiv.setAttribute('data-testid', testId);
            }
            // Disable the password form - retrying will not help
            const form = document.getElementById('shareAccessForm') as HTMLFormElement | null;
            if (form) {
              const submitBtn = form.querySelector('button[type="submit"]') as HTMLButtonElement | null;
              if (submitBtn) submitBtn.disabled = true;
            }
            return;
          }
          throw new Error('Failed to retrieve share data');
        }
        this.envelope = await response.json();
      }

      if (!this.envelope) throw new Error('No envelope data');

      // 2. Decrypt Share Envelope to get FEK and Download Token (with AAD binding)
      // This runs Argon2id KDF + AES-GCM decryption client-side.
      // A decryption failure here means the password is wrong.
      const decryptedEnvelope = await shareCrypto.decryptShareEnvelope(
        this.envelope.encrypted_envelope,
        password,
        this.shareId,
        this.envelope.file_id,
        this.envelope.salt
      );

      // Store the Download Token for later use (proof of decryption for the
      // ticket issuance endpoint) and create the short-lived ticket holder.
      this.downloadToken = decryptedEnvelope.downloadToken;
      this.ticketHolder = new ShareTicketHolder(this.shareId, this.downloadToken);

      // 3. Get filename from the decrypted ShareEnvelope metadata
      // Share recipients cannot decrypt server-side encrypted_filename because
      // it's encrypted with the owner's account key. Instead, the filename
      // is included in the ShareEnvelope JSON (encrypted with share password).
      const filename = decryptedEnvelope.metadata?.filename || 'shared-file';
      const sha256 = decryptedEnvelope.metadata?.sha256;
      const sizeBytes = decryptedEnvelope.metadata?.sizeBytes || this.envelope.size_bytes;
      this.expectedSha256 = sha256;

      // 4. Show file details and enable download
      this.showFileDetails(filename, sizeBytes, decryptedEnvelope.fek, sha256);

      if (statusDiv) statusDiv.className = 'hidden';

    } catch (error) {
      console.error('Unlock failed:', error);
      if (statusDiv) {
        // At this point the envelope fetch succeeded (200) but decryption failed:
        // the password is incorrect.
        statusDiv.textContent = 'Incorrect password.';
        statusDiv.className = 'error-message';
      }
    }
  }

  private showFileDetails(filename: string, size: number, fek: Uint8Array, sha256?: string): void {
    const form = document.getElementById('shareAccessForm');
    const details = document.getElementById('fileDetails');
    const nameDisplay = document.getElementById('fileNameDisplay');
    const sizeDisplay = document.getElementById('fileSizeDisplay');
    const downloadBtn = document.getElementById('downloadBtn');

    if (form) form.classList.add('hidden');
    if (details) details.classList.remove('hidden');
    if (nameDisplay) nameDisplay.textContent = filename;
    if (sizeDisplay) sizeDisplay.textContent = this.formatBytes(size);

    // Surface expected digest from share envelope when available.
    const digestRow = document.getElementById('shareExpectedDigestRow');
    const digestCode = document.getElementById('shareExpectedDigest');
    const copyBtn = document.getElementById('shareCopyDigestBtn') as HTMLButtonElement | null;
    const verifyExpected = document.getElementById('share-verify-expected') as HTMLInputElement | null;
    if (sha256 && digestRow && digestCode) {
      digestCode.textContent = sha256;
      digestRow.classList.remove('hidden');
      if (verifyExpected) verifyExpected.value = sha256;
      if (copyBtn) {
        copyBtn.onclick = async (e) => {
          e.preventDefault();
          try {
            await navigator.clipboard.writeText(sha256);
            showSuccess('SHA-256 copied to clipboard!');
          } catch {
            showError('Could not copy to clipboard.');
          }
        };
      }
    }

    // When SW streaming is unavailable, warn that Blob buffers the complete
    // plaintext and may fail under browser resource limits. No Arkfile size
    // cap — download remains available.
    const swNote = document.getElementById('swUnavailableNote');
    if (!isSwAvailable() && swNote) {
      swNote.textContent =
        'Service Worker streaming is unavailable. Download will buffer the complete decrypted file in the browser before saving. Large files may fail under browser memory or storage limits. Prefer a desktop browser with Service Worker support, or the arkfile-client CLI.';
      swNote.style.display = '';
    }

    if (downloadBtn) {
      downloadBtn.onclick = () => {
        console.log('[arkfile-share] Download button clicked');
        this.downloadFile(filename, fek, sha256);
      };
    }
  }

  private async downloadFile(
    filename: string,
    fek: Uint8Array,
    sha256?: string,
  ): Promise<void> {
    const statusDiv = document.getElementById('shareStatus');

    if (statusDiv) {
      statusDiv.textContent = 'Downloading...';
      statusDiv.className = '';
    }

    if (isSwAvailable()) {
      showSwStreamingTip();
    } else {
      showBlobBufferWarning();
    }

    try {
      // Validate we have the Download Token (proof of decryption used to
      // obtain a short-lived download ticket) and the ticket holder.
      if (!this.downloadToken) {
        throw new Error('Download token not available');
      }
      if (!this.ticketHolder) {
        this.ticketHolder = new ShareTicketHolder(this.shareId, this.downloadToken);
      }

      // The streaming-download manager picks the SW path when available and
      // falls back to incremental Blob construction only when generator
      // consumption has not started. It sends the short-lived X-Share-Ticket
      // per chunk (refreshing on 403), mirroring the arkfile-client CLI flow.
      const result: StreamingDownloadResult = await downloadSharedFileWithTicket(
        this.shareId,
        fek,
        this.ticketHolder,
        { filename, sha256 },
        {
          showProgressUI: true,
          onProgress: (progress: { stage: string; percentage: number; error?: string | undefined }) => {
            if (statusDiv && progress.stage === 'downloading') {
              const percentage = Math.round(progress.percentage);
              statusDiv.textContent = `Downloading... ${percentage}%`;
              statusDiv.className = '';
            } else if (progress.stage === 'error') {
              console.error('Download error:', progress.error);
            }
          },
        }
      );

      if (!result.success) {
        if (result.error === 'Download cancelled') {
          if (statusDiv) {
            statusDiv.textContent = 'Download cancelled.';
            statusDiv.className = '';
          }
          return;
        }
        if (result.error && /partial file may already/i.test(result.error)) {
          showPartialDownloadWarning();
        }
        if (result.error?.includes('403') || result.error?.includes('invalid')) {
          throw new Error('Download token invalid or share has been revoked');
        }
        throw new Error(result.error || 'Download failed');
      }

      // Use the filename from the result, or fall back to the one we already have
      const downloadFilename = result.filename || filename;
      const expected = result.sha256sum || sha256;

      const integrity = {
        filename: downloadFilename,
        expectedSha256: expected,
        computedSha256: result.computedSha256Hex,
        hashVerification: result.hashVerification,
        streamedViaSw: result.streamedViaSw === true,
      };

      if (result.streamedViaSw) {
        console.log('[arkfile-share] File streamed via Service Worker');
        const decision = finalizeDownloadIntegrity(integrity, 'share-integrity-panel');
        if (statusDiv) {
          if (decision.allowSuccess) {
            statusDiv.textContent = 'Download complete!';
            statusDiv.className = 'success-message';
          } else {
            statusDiv.textContent = 'Download finished with integrity failure. See details below.';
            statusDiv.className = 'error-message';
          }
        }
        return;
      }

      // Blob fallback path: check hash BEFORE trigger; revoke on mismatch.
      if (!result.blobUrl) {
        throw new Error('Download completed but no file data was produced');
      }

      const decision = finalizeDownloadIntegrity(integrity, 'share-integrity-panel');
      if (decision.blockBlobTrigger) {
        console.warn('[arkfile-share] Blob download blocked due to hash mismatch; revoking Blob URL');
        URL.revokeObjectURL(result.blobUrl);
        if (statusDiv) {
          statusDiv.textContent = 'Integrity check failed. Download was not started.';
          statusDiv.className = 'error-message';
        }
        return;
      }

      console.log('[arkfile-share] Triggering browser download from blob URL (SW unavailable)');
      triggerBrowserDownloadFromUrl(result.blobUrl, downloadFilename);

      if (statusDiv) {
        statusDiv.textContent = 'Download complete!';
        statusDiv.className = 'success-message';
      }

    } catch (error) {
      console.error('Download error:', error);
      const msg = error instanceof Error ? error.message : 'Download failed.';
      if (/partial file may already/i.test(msg)) {
        showPartialDownloadWarning();
      }
      if (statusDiv) {
        statusDiv.textContent = msg;
        statusDiv.className = 'error-message';
      }
    }
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}
