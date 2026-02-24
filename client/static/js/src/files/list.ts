/**
 * File listing functionality
 */

import { authenticatedFetch } from '../utils/auth';
import { showError } from '../ui/messages';
import { downloadFile } from './download';

export interface FileMetadata {
  file_id: string;
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

    // Build DOM structure
    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';
    fileInfo.innerHTML = `
      <strong>${escapeHtml(file.filename)}</strong>
      <span class="file-size">${escapeHtml(file.size_readable)}</span>
      <span class="file-date">${escapeHtml(new Date(file.uploadDate).toLocaleString())}</span>
      <span class="encryption-type">${file.passwordType === 'account' ? 'Account Password' : 'Custom Password'}</span>
    `;

    const fileActions = document.createElement('div');
    fileActions.className = 'file-actions';

    // Download button with proper event listener
    const downloadBtn = document.createElement('button');
    downloadBtn.textContent = 'Download';
    downloadBtn.addEventListener('click', () => {
      downloadFile(file.file_id, file.passwordHint || '', file.sha256sum, file.passwordType);
    });

    // Share button with proper event listener
    const shareBtn = document.createElement('button');
    shareBtn.textContent = 'Share';
    shareBtn.addEventListener('click', () => {
      window.location.href = `/file-share.html?file=${encodeURIComponent(file.file_id)}`;
    });

    fileActions.appendChild(downloadBtn);
    fileActions.appendChild(shareBtn);
    fileElement.appendChild(fileInfo);
    fileElement.appendChild(fileActions);
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
