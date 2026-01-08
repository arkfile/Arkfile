import { shareCrypto } from './share-crypto';
import { showError } from '../ui/messages';

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
        const response = await fetch(`/api/shares/${this.shareId}/envelope`);
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

      // Request download with Download Token in header
      const response = await fetch(`/api/shares/${this.shareId}/download`, {
        headers: {
          'X-Download-Token': this.downloadToken
        }
      });
      
      if (!response.ok) {
        if (response.status === 403) {
          throw new Error('Download token invalid or share has been revoked');
        }
        throw new Error('Download failed');
      }

      // Get encrypted file data as binary stream
      const encryptedArrayBuffer = await response.arrayBuffer();
      const encryptedData = new Uint8Array(encryptedArrayBuffer);
      
      // Decrypt content using FEK
      const decryptedContent = await shareCrypto.decryptFileData(encryptedData, fek);
      
      // Trigger download (create new Uint8Array to ensure proper ArrayBuffer type)
      const downloadData = new Uint8Array(decryptedContent);
      const blob = new Blob([downloadData], { type: 'application/octet-stream' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      if (statusDiv) statusDiv.textContent = 'Download complete!';

    } catch (error) {
      console.error('Download error:', error);
      if (statusDiv) statusDiv.textContent = 'Download failed.';
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
