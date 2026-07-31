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
 *     file_id, storage_id, password_type,
 *     encrypted_password_hint?, password_hint_nonce?,
 *     encrypted_filename, filename_nonce,
 *     encrypted_sha256sum, sha256sum_nonce,
 *     encrypted_fek, size_bytes, upload_date,
 *     size_readable
 *   }, ...],
 *   storage: { total_readable, limit_readable, usage_percent, ... }
 * }
 */

import { authenticatedFetch, getUsernameFromToken, getCurrentUser, fetchAdminContacts } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { downloadFile } from './download';
import { shareFile } from './share';
import { debugLog } from '../utils/debug-log.js';
import { exportBackup } from './export';
import {
  getAccountKey,
  decryptMetadataField,
} from '../crypto/metadata-helpers';
import { AAD_FIELD_FILENAME, AAD_FIELD_SHA256, AAD_FIELD_PASSWORD_HINT, AAD_FIELD_TAGS } from '../crypto/aad';
import { getCachedAccountKey } from '../crypto/file-encryption';
import {
  buildTagVocabulary,
  fileHasAllTags,
  getCachedFileTagsParams,
  loadFileTagsParams,
  suggestTags,
  type FileTagsParams,
} from '../crypto/file-tags';
import { openEditTagsModal, wireEditTagsModal, type TagMutationTarget } from './tags';

// Types (match server response, snake_case)

/** Single file entry as returned by GET /api/files */
export interface ServerFileEntry {
  file_id: string;
  /** Canonical owner_username (required for metadata-field AAD). */
  owner_username: string;
  storage_id: string;
  password_type: 'account' | 'custom';
  encrypted_password_hint?: string;
  password_hint_nonce?: string;
  encrypted_tags?: string;
  tags_nonce?: string;
  tags_revision?: number;
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
  owner_username: string;
  password_type: 'account' | 'custom';
  /** Plaintext custom-password hint after Account Key decrypt (empty if none). */
  password_hint: string;
  filename: string;        // decrypted or "[Encrypted]"
  sha256sum: string;       // decrypted hex or ""
  tags: string[];
  tags_available: boolean;
  tags_revision: number;
  size_readable: string;
  upload_date: string;
  metadata_decrypted: boolean;
}

let decryptedListCache: DecryptedFileEntry[] = [];
let activeFilterTags: string[] = [];
let tagFilterParams: FileTagsParams | null = null;
let tagFilterWired = false;

// File Loading

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

// File Display (with client-side decryption)

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
  let username = getUsernameFromToken();
  if (!username) {
    // Cache miss (e.g. page reload): fetch from server to populate.
    const userInfo = await getCurrentUser(true);
    username = userInfo?.username ?? null;
  }
  let accountKey: Uint8Array | null = null;
  if (username) {
    accountKey = await getCachedAccountKey(username, undefined);
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
      owner_username: file.owner_username,
      password_type: file.password_type,
      password_hint: '',
      filename: '[Encrypted]',
      sha256sum: '',
      tags: [],
      tags_available: !(file.encrypted_tags && file.tags_nonce),
      tags_revision: file.tags_revision ?? 0,
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
          file.file_id,
          AAD_FIELD_FILENAME,
          file.owner_username,
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
          file.file_id,
          AAD_FIELD_SHA256,
          file.owner_username,
        );
      } catch (err) {
        console.warn(`Failed to decrypt sha256 for ${file.file_id}:`, err);
      }

      if (file.encrypted_password_hint && file.password_hint_nonce) {
        try {
          entry.password_hint = await decryptMetadataField(
            file.encrypted_password_hint,
            file.password_hint_nonce,
            accountKey,
            file.file_id,
            AAD_FIELD_PASSWORD_HINT,
            file.owner_username,
          );
        } catch (err) {
          console.warn(`Failed to decrypt password hint for ${file.file_id}:`, err);
        }
      }

      if (file.encrypted_tags && file.tags_nonce) {
        try {
          const plaintext = await decryptMetadataField(
            file.encrypted_tags,
            file.tags_nonce,
            accountKey,
            file.file_id,
            AAD_FIELD_TAGS,
            file.owner_username,
          );
          entry.tags = plaintext ? plaintext.split(',') : [];
          entry.tags_available = true;
        } catch (err) {
          console.warn(`Failed to decrypt tags for ${file.file_id}:`, err);
          entry.tags_available = false;
        }
      } else {
        entry.tags_available = true;
      }
    }

    decryptedFiles.push(entry);
  }

  decryptedListCache = decryptedFiles;
  await ensureTagFilterReady(!!accountKey);
  renderFilteredFileList();

  // Update storage info
  updateStorageInfo(data.storage);
}

function renderFilteredFileList(): void {
  const filesList = document.getElementById('filesList');
  if (!filesList) return;

  // Keep decrypt banner if present as first child with that class
  const banner = filesList.querySelector('.decrypt-banner');
  filesList.innerHTML = '';
  if (banner) {
    filesList.appendChild(banner);
  }

  let undecryptableSkipped = 0;
  const visible = decryptedListCache.filter((file) => {
    if (activeFilterTags.length === 0) {
      return true;
    }
    if (!file.tags_available) {
      undecryptableSkipped += 1;
      return false;
    }
    return fileHasAllTags(file.tags, activeFilterTags);
  });

  updateTagFilterChrome(undecryptableSkipped, visible.length, decryptedListCache.length);

  for (const file of visible) {
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
    if (file.tags_available && file.tags.length > 0) {
      const tagsRow = document.createElement('div');
      tagsRow.className = 'file-tags';
      for (const tag of file.tags) {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'tag-chip';
        chip.textContent = tag;
        chip.title = `Filter by ${tag}`;
        chip.addEventListener('click', () => {
          addFilterTag(tag);
        });
        tagsRow.appendChild(chip);
      }
      fileInfo.appendChild(tagsRow);
    }
    fileInfo.appendChild(sizeEl);
    fileInfo.appendChild(dateEl);
    fileInfo.appendChild(typeEl);

    const fileActions = document.createElement('div');
    fileActions.className = 'file-actions';

    // Download button. Downloads stream through the same-origin Service Worker
    // registered at app init (see app.ts -> registerSwDownload). No synchronous
    // user-gesture work is required here; the click handler simply invokes the
    // async download function which picks the SW path when available and falls
    // back to incremental Blob construction otherwise.
    const downloadBtn = document.createElement('button');
    downloadBtn.textContent = 'Download';
    downloadBtn.addEventListener('click', () => {
      debugLog('[arkfile-download] Download button clicked');
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

      const editTagsBtn = document.createElement('button');
      editTagsBtn.textContent = 'Edit Tags';
      editTagsBtn.title = 'Add, remove, or replace tags for this file';
      editTagsBtn.addEventListener('click', () => {
        const target: TagMutationTarget = {
          file_id: file.file_id,
          owner_username: file.owner_username,
          filename: file.filename,
          tags: file.tags.slice(),
          tags_available: file.tags_available,
          tags_revision: file.tags_revision,
        };
        openEditTagsModal(target, (updated) => {
          file.tags = updated.tags;
          file.tags_revision = updated.tags_revision;
          file.tags_available = updated.tags_available;
          renderFilteredFileList();
        });
      });
      fileActions.appendChild(editTagsBtn);
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
}

async function ensureTagFilterReady(metadataUnlocked: boolean): Promise<void> {
  wireTagFilterOnce();
  const input = document.getElementById('tagFilterInput') as HTMLInputElement | null;
  const status = document.getElementById('tagFilterStatus');
  if (!metadataUnlocked) {
    if (input) input.disabled = true;
    if (status) status.textContent = 'Unlock file metadata to filter by tags';
    return;
  }
  try {
    tagFilterParams = getCachedFileTagsParams() || await loadFileTagsParams();
    if (input) input.disabled = false;
    if (status) status.textContent = '';
  } catch {
    tagFilterParams = null;
    if (input) input.disabled = true;
    if (status) status.textContent = 'Tag filtering unavailable (config not loaded)';
  }
}

function wireTagFilterOnce(): void {
  if (tagFilterWired) return;
  tagFilterWired = true;
  wireEditTagsModal();

  const input = document.getElementById('tagFilterInput') as HTMLInputElement | null;
  const suggestions = document.getElementById('tagFilterSuggestions');
  const clearBtn = document.getElementById('tagFilterClearBtn');

  input?.addEventListener('input', () => {
    refreshTagSuggestions();
  });
  input?.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      ev.preventDefault();
      const value = input.value.trim();
      if (value) {
        addFilterTag(value);
        input.value = '';
        refreshTagSuggestions();
      }
    }
  });
  clearBtn?.addEventListener('click', () => {
    activeFilterTags = [];
    renderFilteredFileList();
  });
  document.addEventListener('click', (ev) => {
    if (!suggestions) return;
    const target = ev.target as Node;
    if (input && (input === target || input.contains(target))) return;
    if (suggestions.contains(target)) return;
    suggestions.classList.add('hidden');
    input?.setAttribute('aria-expanded', 'false');
  });
}

function refreshTagSuggestions(): void {
  const input = document.getElementById('tagFilterInput') as HTMLInputElement | null;
  const suggestions = document.getElementById('tagFilterSuggestions');
  if (!input || !suggestions || !tagFilterParams) return;
  const vocab = buildTagVocabulary(decryptedListCache.map((f) => (f.tags_available ? f.tags : null)));
  const items = suggestTags(vocab, input.value, activeFilterTags);
  suggestions.innerHTML = '';
  if (items.length === 0) {
    suggestions.classList.add('hidden');
    input.setAttribute('aria-expanded', 'false');
    return;
  }
  for (const item of items) {
    const li = document.createElement('li');
    li.setAttribute('role', 'option');
    li.textContent = item;
    li.addEventListener('click', () => {
      addFilterTag(item);
      input.value = '';
      suggestions.classList.add('hidden');
      input.setAttribute('aria-expanded', 'false');
    });
    suggestions.appendChild(li);
  }
  suggestions.classList.remove('hidden');
  input.setAttribute('aria-expanded', 'true');
}

function addFilterTag(tag: string): void {
  if (!tagFilterParams) return;
  const key = tag.toLowerCase();
  if (activeFilterTags.some((t) => t.toLowerCase() === key)) {
    renderFilteredFileList();
    return;
  }
  if (activeFilterTags.length >= tagFilterParams.maxTagsPerFilterQuery) {
    showError(`At most ${tagFilterParams.maxTagsPerFilterQuery} filter tags`);
    return;
  }
  activeFilterTags.push(tag);
  renderFilteredFileList();
}

function updateTagFilterChrome(undecryptableSkipped: number, visible: number, total: number): void {
  const chips = document.getElementById('tagFilterChips');
  const count = document.getElementById('tagFilterCount');
  const clearBtn = document.getElementById('tagFilterClearBtn');
  const status = document.getElementById('tagFilterStatus');
  if (chips) {
    chips.innerHTML = '';
    for (const tag of activeFilterTags) {
      const chip = document.createElement('span');
      chip.className = 'tag-chip';
      chip.textContent = tag;
      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'tag-chip-remove';
      removeBtn.textContent = 'x';
      removeBtn.addEventListener('click', () => {
        activeFilterTags = activeFilterTags.filter((t) => t.toLowerCase() !== tag.toLowerCase());
        renderFilteredFileList();
      });
      chip.appendChild(removeBtn);
      chips.appendChild(chip);
    }
  }
  if (count) {
    count.textContent = activeFilterTags.length > 0 ? `${visible} of ${total} files` : '';
  }
  clearBtn?.classList.toggle('hidden', activeFilterTags.length === 0);
  if (status && tagFilterParams) {
    status.textContent = undecryptableSkipped > 0
      ? `${undecryptableSkipped} file(s) could not be evaluated for the current tag filter`
      : '';
  }
}

// Storage Info

export function updateStorageInfo(storage: FilesResponse['storage']): void {
  const storageInfo = document.getElementById('storageInfo');
  if (!storageInfo) return;

  const pct = storage.usage_percent;
  // Use existing theme colors for storage bar states
  let barClass = 'storage-bar-normal';
  if (pct >= 90) {
    barClass = 'storage-bar-critical';
  } else if (pct >= 80) {
    barClass = 'storage-bar-warning';
  }

  storageInfo.innerHTML = `
    <div class="storage-bar ${barClass}">
      <div class="used" style="width: ${Math.min(pct, 100)}%"></div>
    </div>
    <div class="storage-text">
      Used: ${escapeHtml(storage.total_readable)} of ${escapeHtml(storage.limit_readable)} (${pct.toFixed(1)}%)
    </div>
    <div class="storage-contact-note" id="storageContactNote"></div>
  `;

  // Fetch admin contact info (public endpoint) and display note
  fetchAdminContactForStorage();
}

// Fetch admin contact info and display it in the storage section as plain text.
async function fetchAdminContactForStorage(): Promise<void> {
  const noteEl = document.getElementById('storageContactNote');
  if (!noteEl) return;

  try {
    const { contact, configured } = await fetchAdminContacts();
    if (configured && contact) {
      noteEl.textContent = `To request a storage limit increase, contact the admin: ${contact}`;
    } else {
      noteEl.textContent = 'To request a storage limit increase, contact your admin.';
    }
  } catch {
    noteEl.textContent = 'To request a storage limit increase, contact your admin.';
  }
}

// File Deletion

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

// Metadata Modal

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

// Utility

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
