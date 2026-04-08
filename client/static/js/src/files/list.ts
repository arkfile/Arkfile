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
import { showError } from '../ui/messages';
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
  // If cached, use it silently. If not cached, show files as [Encrypted]
  // and let the user decrypt on demand (via download/share which prompt).
  const username = getUsernameFromToken();
  let accountKey: Uint8Array | null = null;
  if (username) {
    accountKey = await getCachedAccountKey(username, getToken() ?? undefined);
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
    typeEl.className = 'encryption-type';
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

    fileActions.appendChild(downloadBtn);
    fileActions.appendChild(shareBtn);
    fileActions.appendChild(exportBtn);
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
