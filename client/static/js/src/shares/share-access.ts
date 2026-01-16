/**
 * Share Access UI with Chunked Download Support
 * 
 * Handles accessing shared files with password-based decryption
 * and chunked download for efficient, resumable downloads.
 */

import { shareCrypto } from './share-crypto';
import { showError } from '../ui/messages';
import { 
  downloadSharedFileChunked, 
  triggerBrowserDownload,
  StreamingDownloadResult 
} from '../files/streaming-download';

interface ShareEnvelope {
  share_id: string;
  file_id: string;
  salt: string;
  encrypted_envelope: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  size_bytes: number;
  download_token?: string; // Will be decrypted from the envelope
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

    if (statusDiv) {
      statusDiv.textContent = 'Verifying...';
      statusDiv.className = '';
    }

    try {
      // 1. Get share envelope (public metadata + encrypted FEK)
      if (!this.envelope) {
        const response = await fetch(`/api/public/shares/${this.shareId}/envelope`);
        if (!response.ok) {
          throw new Error('Failed to retrieve share data');
        }
        this.envelope = await response.json();
      }

      if (!this.envelope) throw new Error('No envelope data');

      // 2. Decrypt Share Envelope to get FEK and Download Token (with AAD binding)
      const decryptedEnvelope = await shareCrypto.decryptShareEnvelope(
        this.envelope.encrypted_envelope,
        password,
        this.shareId,
        this.envelope.file_id,
        this.envelope.salt
      );

      // Store the Download Token for later use
      this.downloadToken = decryptedEnvelope.downloadToken;

      // 3. Decrypt Filename
      const filename = await shareCrypto.decryptMetadata(
        this.envelope.encrypted_filename,
        this.envelope.filename_nonce,
        decryptedEnvelope.fek
      );

      // 4. Show file details and enable download
      this.showFileDetails(filename, this.envelope.size_bytes, decryptedEnvelope.fek);
      
      if (statusDiv) statusDiv.className = 'hidden';

    } catch (error) {
      console.error('Unlock failed:', error);
      if (statusDiv) {
        statusDiv.textContent = 'Incorrect password or invalid share.';
        statusDiv.className = 'error-message';
      }
    }
  }

  private showFileDetails(filename: string, size: number, fek: Uint8Array): void {
    const form = document.getElementById('shareAccessForm');
    const details = document.getElementById('fileDetails');
    const nameDisplay = document.getElementById('fileNameDisplay');
    const sizeDisplay = document.getElementById('fileSizeDisplay');
    const downloadBtn = document.getElementById('downloadBtn');

    if (form) form.classList.add('hidden');
    if (details) details.classList.remove('hidden');
    if (nameDisplay) nameDisplay.textContent = filename;
    if (sizeDisplay) sizeDisplay.textContent = this.formatBytes(size);

    if (downloadBtn) {
      downloadBtn.onclick = () => this.downloadFile(filename, fek);
    }
  }

  private async downloadFile(filename: string, fek: Uint8Array): Promise<void> {
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

      // Use chunked download with progress tracking
      const result: StreamingDownloadResult = await downloadSharedFileChunked(
        this.shareId,
        fek,
        this.downloadToken,
        {
          showProgressUI: true,
          onProgress: (progress) => {
            // Update status with progress info
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
        if (result.error?.includes('403') || result.error?.includes('invalid')) {
          throw new Error('Download token invalid or share has been revoked');
        }
        throw new Error(result.error || 'Download failed');
      }

      if (!result.data) {
        throw new Error('Download completed but data is missing');
      }

      // Use the decrypted filename from the result, or fall back to the one we already have
      const downloadFilename = result.filename || filename;
      
      // Trigger browser download
      triggerBrowserDownload(result.data, downloadFilename);
      
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
