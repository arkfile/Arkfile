import { shareCrypto } from './share-crypto';
import { showError } from '../ui/messages';

interface ShareEnvelope {
  share_id: string;
  file_id: string;
  salt: string;
  encrypted_fek: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  size_bytes: number;
}

export class ShareAccessUI {
  private containerId: string;
  private shareId: string;
  private envelope: ShareEnvelope | null = null;

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

      // 2. Decrypt FEK (implicitly derives key from password)
      // We construct the metadata object expected by decryptFEKFromShare
      const fek = await shareCrypto.decryptFEKFromShare({
        encryptedFEK: this.envelope.encrypted_fek,
        salt: this.envelope.salt,
        nonce: '' // Not used by decryptFEKFromShare as it extracts nonce from encryptedFEK
      }, password, this.shareId);

      // 4. Decrypt Filename
      const filename = await shareCrypto.decryptMetadata(
        this.envelope.encrypted_filename,
        this.envelope.filename_nonce,
        fek
      );

      // 5. Show file details and enable download
      this.showFileDetails(filename, this.envelope.size_bytes, fek);
      
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
      // Request download (this might need a token or just the share ID)
      // The backend `DownloadSharedFile` returns encrypted data
      const response = await fetch(`/api/shares/${this.shareId}/download`);
      if (!response.ok) {
        throw new Error('Download failed');
      }

      const data = await response.json();
      
      // Decrypt content
      // The data.data is base64 encoded encrypted content
      // We need to use the FEK to decrypt the content.
      
      const encryptedContent = data.data; // Base64
      const decryptedContent = await shareCrypto.decryptData(encryptedContent, fek);
      
      // Trigger download
      const blob = new Blob([decryptedContent as unknown as BlobPart], { type: 'application/octet-stream' });
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
