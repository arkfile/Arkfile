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
  triggerBrowserDownload,
  StreamingDownloadResult,
} from './streaming-download';
import { deriveFileEncryptionKey } from '../crypto/file-encryption';
import { getAccountKey, decryptFEK } from '../crypto/metadata-helpers';

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
  try {
    const authToken = getToken();
    if (!authToken) {
      showError('Not authenticated. Please log in again.');
      return;
    }

    const username = getUsernameFromToken();
    if (!username) {
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

    // Chunked download with the decrypted FEK
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      authToken,
      {
        accountKey: metadataDecryptionKey,
        showProgressUI: true,
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

    if (!result.data || !result.filename) {
      showError('Download completed but data is missing.');
      return;
    }

    // Verify SHA-256 hash if available
    if (result.sha256sum && expectedHash) {
      if (result.sha256sum !== expectedHash) {
        console.warn('SHA-256 hash mismatch - file may be corrupted');
      }
    }

    triggerBrowserDownload(result.data, result.filename);
    showSuccess(`Downloaded: ${result.filename}`);
  } catch (error) {
    console.error('Download error:', error);
    showError('An error occurred during file download.');
  }
}
