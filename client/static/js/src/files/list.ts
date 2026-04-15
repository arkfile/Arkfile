/**
 * File listing functionality
 *
 * Fetches the authenticated user's file list from the server and renders it.
 * The server returns encrypted metadata (filenames, SHA-256 hashes) which
 * must be decrypted client-side using the Account Key.
 *
 * Server response shape (GET /api/files):
 * {
 *   files: [{
 *     file_id, storage_id, password_type, password_hint,
 *     encrypted_filename, filename_nonce,
 *     encrypted_sha256sum, sha256sum_nonce,
 *     encrypted_fek, size_bytes, upload_date,
 *     size_readable
 *   }, ...],
 *   storage: { total_readable, limit_readable, usage_percent, ... }
 * }
 */

import { authenticatedFetch, getUsernameFromToken, getToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { downloadFile } from './download';
import { shareFile } from './share';
import { exportBackup } from './export';
import {
  getAccountKey,
  decryptMetadataField,
} from '../crypto/metadata-helpers';
import { getCachedAccountKey } from '../crypto/file-encryption';

// ============================================================================
// Types (match server response, snake_case)
// ============================================================================

/** Single file entry as returned by GET /api/files */
export interface ServerFileEntry {
  file_id: string;
  storage_id: string;
  password_type: 'account' | 'custom';
  password_hint?: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  size_bytes: number;
  upload_date: string;
  size_readable: string;
}

/** Server response for GET /api/files */
export interface FilesResponse {
  files: ServerFileEntry[];
  storage: {
    total_readable: string;
    limit_readable: string;
    usage_percent: number;
  };
}

/** A file entry after client-side metadata decryption */
interface DecryptedFileEntry {
  file_id: string;
  password_type: 'account' | 'custom';
  password_hint: string;
  filename: string;        // decrypted or "[Encrypted]"
  sha256sum: string;       // decrypted hex or ""
  size_readable: string;
  upload_date: string;
  metadata_decrypted: boolean;
}

// ============================================================================
// File Loading
// ============================================================================

export async function loadFiles(): Promise<void> {
  try {
    const response = await authenticatedFetch('/api/files');

    if (response.ok) {
      const data: FilesResponse = await response.json();
      await displayFiles(data);
    } else {
      showError('Failed to load files.');
    }
  } catch (error) {
    console.error('Load files error:', error);
    showError('An error occurred while loading files.');
  }
}

// ============================================================================
// File Display (with client-side decryption)
// ============================================================================

export async function displayFiles(data: FilesResponse): Promise<void> {
  const filesList = document.getElementById('filesList');
  if (!filesList) return;

  filesList.innerHTML = '';

  if (!data.files || data.files.length === 0) {
    filesList.innerHTML = '<div class="no-files">No files uploaded yet.</div>';
    updateStorageInfo(data.storage);
    return;
  }

  // Try to get the Account Key for metadata decryption.
  // If cached, use it silently. If not cached (e.g. after page refresh),
  // show a banner prompting the user to enter their password.
  const username = getUsernameFromToken();
  let accountKey: Uint8Array | null = null;
  if (username) {
    accountKey = await getCachedAccountKey(username, getToken() ?? undefined);
  }

  // If account key is not available, show a banner to let the user unlock
  if (!accountKey && username && data.files.length > 0) {
    const banner = document.createElement('div');
    banner.className = 'decrypt-banner';

    const bannerText = document.createElement('span');
    bannerText.textContent = 'File names are encrypted. Enter your account password to decrypt.';

    const decryptBtn = document.createElement('button');
    decryptBtn.textContent = 'Decrypt File Names';
    decryptBtn.addEventListener('click', async () => {
      const key = await getAccountKey(username);
      if (key) {
        // Re-render the file list with the newly derived account key
        await displayFiles(data);
      }
    });

    banner.appendChild(bannerText);
    banner.appendChild(decryptBtn);
    filesList.appendChild(banner);
  }

  // Decrypt metadata for each file (or fall back to placeholders)
  const decryptedFiles: DecryptedFileEntry[] = [];
  for (const file of data.files) {
    const entry: DecryptedFileEntry = {
      file_id: file.file_id,
      password_type: file.password_type,
      password_hint: file.password_hint || '',
      filename: '[Encrypted]',
      sha256sum: '',
      size_readable: file.size_readable,
      upload_date: file.upload_date,
      metadata_decrypted: false,
    };

    if (accountKey) {
      try {
        entry.filename = await decryptMetadataField(
          file.encrypted_filename,
          file.filename_nonce,
          accountKey,
        );
        entry.metadata_decrypted = true;
      } catch (err) {
        console.warn(`Failed to decrypt filename for ${file.file_id}:`, err);
      }

      try {
        entry.sha256sum = await decryptMetadataField(
          file.encrypted_sha256sum,
          file.sha256sum_nonce,
          accountKey,
        );
      } catch (err) {
        console.warn(`Failed to decrypt sha256 for ${file.file_id}:`, err);
      }
    }

    decryptedFiles.push(entry);
  }

  // Render the file list
  for (const file of decryptedFiles) {
    const fileElement = document.createElement('div');
    fileElement.className = 'file-item';

    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';

    const nameEl = document.createElement('strong');
    nameEl.textContent = file.filename;

    const sizeEl = document.createElement('span');
    sizeEl.className = 'file-size';
    sizeEl.textContent = file.size_readable;

    const dateEl = document.createElement('span');
    dateEl.className = 'file-date';
    dateEl.textContent = new Date(file.upload_date).toLocaleString();

    const typeEl = document.createElement('span');
    typeEl.className = file.password_type === 'account'
      ? 'encryption-type encryption-type-account'
      : 'encryption-type encryption-type-custom';
    typeEl.textContent = file.password_type === 'account' ? 'Account Password' : 'Custom Password';

    fileInfo.appendChild(nameEl);
    fileInfo.appendChild(sizeEl);
    fileInfo.appendChild(dateEl);
    fileInfo.appendChild(typeEl);

    const fileActions = document.createElement('div');
    fileActions.className = 'file-actions';

    // Download button
    const downloadBtn = document.createElement('button');
    downloadBtn.textContent = 'Download';
    downloadBtn.addEventListener('click', () => {
      downloadFile(file.file_id, file.password_hint, file.sha256sum, file.password_type);
    });

    // Share button
    const shareBtn = document.createElement('button');
    shareBtn.textContent = 'Share';
    shareBtn.addEventListener('click', () => {
      shareFile(file.file_id, file.password_type);
    });

    // Export backup button
    const exportBtn = document.createElement('button');
    exportBtn.textContent = 'Export Backup';
    exportBtn.title = file.password_type === 'custom'
      ? 'Export encrypted backup. Decrypt offline with arkfile-client using your account password and file password.'
      : 'Export encrypted backup. Decrypt offline with arkfile-client using your account password.';
    exportBtn.addEventListener('click', () => {
      exportBackup(file.file_id);
    });

    // View Metadata button (only when metadata is decrypted)
    if (file.metadata_decrypted) {
      const metaBtn = document.createElement('button');
      metaBtn.textContent = 'Metadata';
      metaBtn.title = 'View full file metadata including SHA-256 digest';
      metaBtn.addEventListener('click', () => {
        showMetadataModal(file);
      });
      fileActions.appendChild(metaBtn);
    }

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.className = 'danger-button';
    deleteBtn.title = 'Permanently delete this file from the server';
    deleteBtn.addEventListener('click', () => {
      confirmAndDeleteFile(file.file_id, file.filename);
    });

    fileActions.appendChild(downloadBtn);
    fileActions.appendChild(shareBtn);
    fileActions.appendChild(exportBtn);
    fileActions.appendChild(deleteBtn);
    fileElement.appendChild(fileInfo);
    fileElement.appendChild(fileActions);
    filesList.appendChild(fileElement);
  }

  // Update storage info
  updateStorageInfo(data.storage);
}

// ============================================================================
// Storage Info
// ============================================================================

export function updateStorageInfo(storage: FilesResponse['storage']): void {
  const storageInfo = document.getElementById('storageInfo');
  if (!storageInfo) return;

  storageInfo.innerHTML = `
    <div class="storage-bar">
      <div class="used" style="width: ${storage.usage_percent}%"></div>
    </div>
    <div class="storage-text">
      Used: ${escapeHtml(storage.total_readable)} of ${escapeHtml(storage.limit_readable)} (${storage.usage_percent.toFixed(1)}%)
    </div>
  `;
}

// ============================================================================
// File Deletion
// ============================================================================

async function confirmAndDeleteFile(fileId: string, filename: string): Promise<void> {
  const displayName = filename === '[Encrypted]' ? fileId : filename;
  const confirmed = window.confirm(
    `Are you sure you want to permanently delete "${displayName}"?\n\n` +
    `This action cannot be undone.\n\n` +
    `Consider using "Export Backup" first to save an offline-decryptable ` +
    `copy (.arkbackup) before deleting, if this file is important.`
  );

  if (!confirmed) return;

  try {
    const response = await authenticatedFetch(`/api/files/${fileId}`, {
      method: 'DELETE',
    });

    if (response.ok) {
      showSuccess(`File deleted: ${displayName}`);
      await loadFiles();
    } else {
      const data = await response.json().catch(() => ({}));
      showError(data.message || `Failed to delete file (HTTP ${response.status})`);
    }
  } catch (error) {
    console.error('Delete file error:', error);
    showError('An error occurred while deleting the file.');
  }
}

// ============================================================================
// Metadata Modal
// ============================================================================

function showMetadataModal(file: DecryptedFileEntry): void {
  const overlay = document.createElement('div');
  overlay.className = 'metadata-modal-overlay';

  const modal = document.createElement('div');
  modal.className = 'metadata-modal';

  const makeRow = (label: string, value: string, monospace = false, copyable = false): HTMLElement => {
    const row = document.createElement('div');
    row.className = 'metadata-row';

    const labelEl = document.createElement('span');
    labelEl.className = 'metadata-label';
    labelEl.textContent = label;

    const valueEl = document.createElement('span');
    valueEl.className = monospace ? 'metadata-value monospace' : 'metadata-value';
    valueEl.textContent = value;

    row.appendChild(labelEl);
    row.appendChild(valueEl);

    if (copyable && value) {
      const copyBtn = document.createElement('button');
      copyBtn.className = 'metadata-copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(value);
          showSuccess('Copied to clipboard!');
        } catch {
          showError('Please copy manually');
        }
      });
      row.appendChild(copyBtn);
    }

    return row;
  };

  const title = document.createElement('h3');
  title.textContent = 'File Metadata';
  modal.appendChild(title);

  modal.appendChild(makeRow('Filename', file.filename));
  modal.appendChild(makeRow('Size', file.size_readable));
  modal.appendChild(makeRow('Uploaded', new Date(file.upload_date).toLocaleString()));
  modal.appendChild(makeRow('Encryption', file.password_type === 'account' ? 'Account Password' : 'Custom Password'));
  if (file.sha256sum) {
    modal.appendChild(makeRow('SHA-256', file.sha256sum, true, true));
  }
  modal.appendChild(makeRow('File ID', file.file_id, true, true));

  const closeSection = document.createElement('div');
  closeSection.className = 'metadata-modal-close';

  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'Close';
  closeBtn.addEventListener('click', () => {
    document.body.removeChild(overlay);
  });
  closeSection.appendChild(closeBtn);
  modal.appendChild(closeSection);

  overlay.appendChild(modal);

  // Close on backdrop click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      document.body.removeChild(overlay);
    }
  });

  // Close on Escape key
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      if (document.body.contains(overlay)) {
        document.body.removeChild(overlay);
      }
      document.removeEventListener('keydown', handleKey);
    }
  };
  document.addEventListener('keydown', handleKey);

  document.body.appendChild(overlay);
}

// ============================================================================
// Utility
// ============================================================================

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
