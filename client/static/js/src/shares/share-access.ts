/**
 * Share Access UI with Chunked Download Support
 *
 * Handles accessing shared files with password-based decryption
 * and chunked download for efficient downloads.
 *
 * LARGE FILE DOWNLOADS
 * --------------------
 * Downloads stream through the same-origin Service Worker registered at
 * /sw-download.js (see sw-download.ts and sw-streaming-download.ts). The SW
 * intercepts a synthetic /sw-download/<uuid> request and responds with a
 * streaming Response carrying Content-Disposition: attachment, so the browser's
 * download manager writes the bytes straight to disk. This bypasses the
 * Chromium blob-URL ~2 GB ceiling and works first-class in Tor Browser.
 *
 * If the SW is unavailable (rare: very old browsers, certain private-browsing
 * modes), the streaming-download manager falls back to incremental Blob
 * construction and we trigger the download from a blob URL here.
 */

import { shareCrypto } from './share-crypto';
import { showError, showWarning } from '../ui/messages';
import { isSwAvailable } from '../files/sw-streaming-download';
import {
  downloadSharedFileChunked,
  triggerBrowserDownloadFromUrl,
  StreamingDownloadResult,
} from '../files/streaming-download';

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
  private downloadToken: string | null = null; // Store Download Token after decryption

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
        <p id="swUnavailableNote" class="warning-note" style="display:none;"></p>
        <button id="downloadBtn" class="btn primary">Download</button>
      </div>
    `;

    const form = document.getElementById('shareAccessForm') as HTMLFormElement;
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleUnlock();
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

    // Show the full message immediately when unlock starts.
    //
    // We previously tried a 5-second quiet-period pattern (plain "Verifying..."
    // for the first 5 s, then swap to the informative message), but the
    // Argon2id KDF inside `decryptShareEnvelope` runs synchronously on the
    // main thread and blocks the JavaScript event loop for its entire
    // duration (3–4 minutes observed on Tor Browser Safer mode). With the
    // event loop blocked, `setTimeout` callbacks cannot fire, so the
    // 5-second timer never executed and users on slow devices/networks
    // never saw the message — exactly the opposite of what we wanted.
    //
    // The correct fix would be to move Argon2id into a Web Worker so the
    // event loop can keep running during the derivation. Until then, the
    // simplest honest UX is: always show the message. Fast desktops see it
    // for <1 s before the unlock completes; slow ones see it for the
    // entire wait. No oversold speed promise.
    if (statusDiv) {
      statusDiv.textContent =
        'Verifying share access... This can take a few minutes on older devices or slow networks.';
      statusDiv.className = '';
    }
    console.log(
      '[arkfile-share] Deriving share password key... '
        + '(Argon2id is computationally heavy by design; can take a few '
        + 'minutes on older devices or slow networks)',
    );

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
            if (statusDiv) {
              statusDiv.textContent = 'This share is no longer valid.';
              statusDiv.className = 'error-message';
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

      // Store the Download Token for later use
      this.downloadToken = decryptedEnvelope.downloadToken;

      // 3. Get filename from the decrypted ShareEnvelope metadata
      // Share recipients cannot decrypt server-side encrypted_filename because
      // it's encrypted with the owner's account key. Instead, the filename
      // is included in the ShareEnvelope JSON (encrypted with share password).
      const filename = decryptedEnvelope.metadata?.filename || 'shared-file';
      const sha256 = decryptedEnvelope.metadata?.sha256;
      const sizeBytes = decryptedEnvelope.metadata?.sizeBytes || this.envelope.size_bytes;

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

    // Surface a warning when SW streaming is unavailable AND the file is
    // larger than ~2 GiB. This is the case where Chromium-based private/
    // incognito tabs fall through to the Blob path and hit Chromium's blob
    // URL ceiling. The recipient cannot work around this from inside a
    // private tab; we tell them in advance instead of letting them spend
    // minutes downloading and then failing.
    const SW_LARGE_FILE_WARN_THRESHOLD = 2 * 1024 * 1024 * 1024; // 2 GiB
    const swNote = document.getElementById('swUnavailableNote');
    if (swNote && !isSwAvailable() && size > SW_LARGE_FILE_WARN_THRESHOLD) {
      swNote.textContent =
        'This file is large. Your browser may not be able to complete the download in private/incognito mode. ' +
        'Options: open this link in a regular (non-private) browser tab, try a different browser ' +
        '(Firefox or Tor Browser), or use the arkfile-client CLI tool to download.';
      swNote.style.display = '';
    }

    if (downloadBtn) {
      downloadBtn.onclick = () => {
        console.log('[arkfile-share] Download button clicked');
        // SW path: registration happens at app init; the download function picks
        // it up via isSwAvailable(). No synchronous user-gesture work is required
        // here, so this can simply kick off the async download.
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

    try {
      // Validate we have the Download Token
      if (!this.downloadToken) {
        throw new Error('Download token not available');
      }

      // The streaming-download manager picks the SW path when available and
      // falls back to incremental Blob construction otherwise.
      const result: StreamingDownloadResult = await downloadSharedFileChunked(
        this.shareId,
        fek,
        this.downloadToken,
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
        if (result.error?.includes('403') || result.error?.includes('invalid')) {
          throw new Error('Download token invalid or share has been revoked');
        }
        throw new Error(result.error || 'Download failed');
      }

      // Use the filename from the result, or fall back to the one we already have
      const downloadFilename = result.filename || filename;

      if (result.streamedViaSw) {
        // SW path: bytes were streamed directly to the browser's download manager.
        console.log('[arkfile-share] File streamed via Service Worker');
        if (statusDiv) {
          statusDiv.textContent = 'Download complete!';
          statusDiv.className = 'success-message';
        }
        if (result.hashVerification === 'mismatch') {
          showWarning('SHA-256 verification failed. The downloaded file may be corrupted or tampered with. Consider deleting it and re-downloading.');
        }
        return;
      }

      // Blob fallback path: trigger browser download from blob URL
      if (!result.blobUrl) {
        throw new Error('Download completed but no file data was produced');
      }

      console.log('[arkfile-share] Triggering browser download from blob URL (SW unavailable)');
      triggerBrowserDownloadFromUrl(result.blobUrl, downloadFilename);

      if (statusDiv) {
        statusDiv.textContent = 'Download complete!';
        statusDiv.className = 'success-message';
      }

    } catch (error) {
      console.error('Download error:', error);
      if (statusDiv) {
        statusDiv.textContent = error instanceof Error ? error.message : 'Download failed.';
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
