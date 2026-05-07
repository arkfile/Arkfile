/**
 * File download functionality with chunked download support
 *
 * This module provides file download capabilities using the chunked download
 * infrastructure for efficient, resumable downloads with client-side decryption.
 *
 * SECURITY: All FEK decryption happens client-side using Argon2id-derived keys.
 * The server NEVER sees the plaintext FEK or the user's password.
 */

import { authenticatedFetch, getToken, getUsernameFromToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { showProgress, hideProgress } from '../ui/progress';
import { showPasswordPrompt } from '../ui/password-modal';
import {
  downloadFileChunked,
  triggerBrowserDownloadFromUrl,
  StreamingDownloadResult,
} from './streaming-download';

import { deriveFileEncryptionKey } from '../crypto/file-encryption';
import { getAccountKey, decryptFEK } from '../crypto/metadata-helpers';

/** Open a FileSystem writable while the user gesture is still fresh */
async function openFsapiWritable(suggestedName: string): Promise<any | null> {
  if (typeof window === 'undefined' || !('showSaveFilePicker' in window)) return null;
  try {
    const handle = await (window as any).showSaveFilePicker({ suggestedName });
    return await handle.createWritable();
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') return 'cancelled';
    return null;
  }
}

/**
 * File metadata response from the server (snake_case)
 */
interface FileMetaResponse {
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  password_hint: string;
  password_type: string;
  size_bytes: number;
  chunk_size: number;
  total_chunks: number;
}

/**
 * Download a file using chunked download with client-side decryption
 *
 * This function:
 * 1. Fetches file metadata including the encrypted FEK
 * 2. Gets the Account Key (from cache or by prompting for password)
 * 3. Decrypts the FEK client-side
 * 4. Uses the FEK to download and decrypt the file chunks
 *
 * @param fileId       - The file ID to download
 * @param hint         - Optional password hint to display
 * @param expectedHash - Expected SHA-256 hash for verification (already decrypted by caller)
 * @param passwordType - 'account' or 'custom' indicating encryption type
 */
export async function downloadFile(
  fileId: string,
  hint: string,
  expectedHash: string,
  passwordType: string,
): Promise<void> {
  // ── Call showSaveFilePicker HERE — as the very first await, one async frame
  // from the Download button click. Chrome's user-gesture token is still fresh.
  let preOpenedWritable: any = null;
  if (typeof window !== 'undefined' && 'showSaveFilePicker' in window) {
    const writable = await openFsapiWritable('arkfile-download');
    if (writable === 'cancelled') {
      return; // User dismissed save dialog — silent cancel
    }
    preOpenedWritable = writable;
  }

  try {
    const authToken = getToken();
    if (!authToken) {
      if (preOpenedWritable) { try { await preOpenedWritable.abort(); } catch { /* ignore */ } }
      showError('Not authenticated. Please log in again.');
      return;
    }

    const username = getUsernameFromToken();
    if (!username) {
      if (preOpenedWritable) { try { await preOpenedWritable.abort(); } catch { /* ignore */ } }
      showError('Username not found. Please log in again.');
      return;
    }

    // Fetch file metadata including encrypted FEK
    const metaResponse = await authenticatedFetch(`/api/files/${fileId}/meta`);
    if (!metaResponse.ok) {
      const errorData = await metaResponse.json().catch(() => ({}));
      showError(errorData.message || 'Failed to retrieve file metadata.');
      return;
    }

    const meta: FileMetaResponse = await metaResponse.json();

    let fek: Uint8Array;
    let metadataDecryptionKey: Uint8Array;

    if (passwordType === 'account' || meta.password_type === 'account') {
      // Account-encrypted: get Account Key, decrypt FEK
      const accountKey = await getAccountKey(username);
      if (!accountKey) return;

      metadataDecryptionKey = accountKey;

      try {
        fek = await decryptFEK(meta.encrypted_fek, accountKey);
      } catch (error) {
        console.error('Failed to decrypt FEK:', error);
        showError('Failed to decrypt file key. Your password may be incorrect.');
        return;
      }
    } else {
      // Custom-encrypted: need account key for metadata AND custom key for FEK
      const accountKey = await getAccountKey(username);
      if (!accountKey) return;

      metadataDecryptionKey = accountKey;

      const hintText = hint || meta.password_hint || '';
      const promptResult = await showPasswordPrompt({
        title: 'File Password Required',
        message: 'This file is encrypted with a custom password.',
        ...(hintText ? { hint: hintText } : {}),
        showCacheDuration: false,
        submitLabel: 'Decrypt',
        cancelLabel: 'Cancel',
      });
      if (!promptResult) return;
      const password = promptResult.password;

      try {
        showProgress({
          title: 'Deriving Custom Key',
          message: 'Running Argon2id key derivation -- this may take a few seconds...',
          indeterminate: true,
        });

        const customKey = await deriveFileEncryptionKey(password, username, 'custom');
        hideProgress();

        fek = await decryptFEK(meta.encrypted_fek, customKey);
      } catch (error) {
        hideProgress();
        console.error('Failed to decrypt FEK with custom password:', error);
        showError('Failed to decrypt file key. Check your password.');
        return;
      }
    }

    // Chunked download with the decrypted FEK.
    // preOpenedWritable is passed so the manager writes directly without
    // calling showSaveFilePicker again (gesture is already consumed).
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      authToken,
      {
        accountKey: metadataDecryptionKey,
        showProgressUI: true,
        preOpenedWritable,
        onProgress: (progress) => {
          if (progress.stage === 'error') {
            console.error('Download error:', progress.error);
          }
        },
      },
    );

    if (!result.success) {
      showError(result.error || 'Download failed.');
      return;
    }

    if (!result.filename) {
      showError('Download completed but filename is missing.');
      return;
    }

    // Verify SHA-256 hash if available
    if (result.sha256sum && expectedHash) {
      if (result.sha256sum !== expectedHash) {
        console.warn('SHA-256 hash mismatch - file may be corrupted');
      }
    }

    if (result.savedViaFileSystemAPI) {
      // File was streamed directly to disk via File System Access API — done.
      showSuccess(`Downloaded: ${result.filename}`);
    } else if (result.blobUrl) {
      // Firefox / legacy fallback: file is in a Blob URL; trigger the download link.
      triggerBrowserDownloadFromUrl(result.blobUrl, result.filename);
      showSuccess(`Downloaded: ${result.filename}`);
    } else {
      showError('Download completed but no file data was produced.');
    }
  } catch (error) {
    console.error('Download error:', error);
    showError('An error occurred during file download.');
  }
}
