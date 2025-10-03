/**
 * File listing functionality
 */

import { authenticatedFetch } from '../utils/auth-wasm';
import { showError } from '../ui/messages';

export interface FileMetadata {
  filename: string;
  size_readable: string;
  uploadDate: string;
  passwordType: 'account' | 'custom';
  passwordHint?: string;
  sha256sum: string;
}

export interface FilesResponse {
  files: FileMetadata[];
  storage: {
    total_readable: string;
    limit_readable: string;
    usage_percent: number;
  };
}

export async function loadFiles(): Promise<void> {
  try {
    const response = await authenticatedFetch('/api/files');

    if (response.ok) {
      const data: FilesResponse = await response.json();
      displayFiles(data);
    } else {
      showError('Failed to load files.');
    }
  } catch (error) {
    console.error('Load files error:', error);
    showError('An error occurred while loading files.');
  }
}

export function displayFiles(data: FilesResponse): void {
  const filesList = document.getElementById('filesList');
  if (!filesList) return;

  filesList.innerHTML = '';

  data.files.forEach(file => {
    const fileElement = document.createElement('div');
    fileElement.className = 'file-item';
    fileElement.innerHTML = `
      <div class="file-info">
        <strong>${escapeHtml(file.filename)}</strong>
        <span class="file-size">${escapeHtml(file.size_readable)}</span>
        <span class="file-date">${escapeHtml(new Date(file.uploadDate).toLocaleString())}</span>
        <span class="encryption-type">${file.passwordType === 'account' ? 'Account Password' : 'Custom Password'}</span>
      </div>
      <div class="file-actions">
        <button onclick="downloadFile('${escapeHtml(file.filename)}', '${escapeHtml(file.passwordHint || '')}', '${escapeHtml(file.sha256sum)}', '${escapeHtml(file.passwordType)}')">Download</button>
        <button onclick="showShareForm('${escapeHtml(file.filename)}', '${escapeHtml(file.sha256sum)}')">Share</button>
      </div>
    `;
    filesList.appendChild(fileElement);
  });

  // Update storage info
  updateStorageInfo(data.storage);
}

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

// Utility function to escape HTML to prevent XSS
function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Make downloadFile and showShareForm available globally for onclick handlers
// This is a temporary solution until we convert to proper event handling
declare global {
  function downloadFile(filename: string, hint: string, expectedHash: string, passwordType: string): void;
  function showShareForm(filename: string, fileId: string): void;
}

// Export for global access (temporary compatibility)
if (typeof window !== 'undefined') {
  (window as any).downloadFile = async (filename: string, hint: string, expectedHash: string, passwordType: string) => {
    const { downloadFile } = await import('./download');
    downloadFile(filename, hint, expectedHash, passwordType);
  };

  (window as any).showShareForm = async (filename: string, fileId: string) => {
    const { showShareForm } = await import('./share-integration');
    showShareForm(filename, fileId);
  };
}
