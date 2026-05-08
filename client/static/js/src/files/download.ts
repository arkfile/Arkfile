/**
 * File download functionality with chunked download support
 *
 * This module provides file download capabilities using the chunked download
 * infrastructure for efficient downloads with client-side decryption.
 *
 * LARGE FILE DOWNLOADS (Chromium/Brave/Edge)
 * ------------------------------------------
 * The File System Access API (FSAPI) is used to stream decrypted chunks
 * directly to disk, bypassing the browser's blob URL download pipeline.
 * This avoids the ~2 GB Chromium blob URL ceiling that causes "check
 * internet connection" errors on large file downloads.
 *
 * CRITICAL: The caller (list.ts) MUST call showSaveFilePicker() synchronously
 * as the very first action in the click event handler, before any await, and
 * pass the resulting Promise here. This function awaits it at the appropriate
 * point after all async key setup is complete.
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

const LOG_PREFIX = '[arkfile-download]';

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
 * Download a file using chunked download with client-side decryption.
 *
 * Flow:
 * 1. Fetch file metadata (encrypted FEK, encrypted filename/sha256)
 * 2. Resolve account key (cache or password prompt)
 * 3. For custom-password files, prompt for the file password and derive custom key
 * 4. Decrypt FEK
 * 5. Stream-decrypt all chunks via the streaming manager:
 *    - FSAPI path (Chromium/Brave/Edge): write directly to disk via fsapiHandlePromise
 *    - Blob fallback (Firefox): accumulate incrementally, trigger download from blob URL
 * 6. Show success message
 *
 * @param fsapiHandlePromise - Promise from showSaveFilePicker() called synchronously
 *   in the click handler by the caller. If null/undefined, falls back to Blob path.
 */
export async function downloadFile(
  fileId: string,
  hint: string,
  expectedHash: string,
  passwordType: string,
  fsapiHandlePromise?: Promise<FileSystemFileHandle> | null,
): Promise<void> {
  const t0 = Date.now();
  console.log(`${LOG_PREFIX} downloadFile() invoked (passwordType=${passwordType})`);

  try {
    const authToken = getToken();
    if (!authToken) {
      console.error(`${LOG_PREFIX} No auth token available`);
      showError('Not authenticated. Please log in again.');
      return;
    }

    const username = getUsernameFromToken();
    if (!username) {
      console.error(`${LOG_PREFIX} Username could not be extracted from token`);
      showError('Username not found. Please log in again.');
      return;
    }

    // Fetch file metadata
    const tMeta = Date.now();
    console.log(`${LOG_PREFIX} Fetching file metadata...`);
    const metaResponse = await authenticatedFetch(`/api/files/${fileId}/meta`);
    if (!metaResponse.ok) {
      const errorData = await metaResponse.json().catch(() => ({}));
      console.error(`${LOG_PREFIX} Metadata fetch failed: HTTP ${metaResponse.status}`);
      showError(errorData.message || 'Failed to retrieve file metadata.');
      return;
    }
    const meta: FileMetaResponse = await metaResponse.json();
    console.log(`${LOG_PREFIX} Metadata fetched in ${Date.now() - tMeta}ms (size_bytes=${meta.size_bytes}, total_chunks=${meta.total_chunks}, password_type=${meta.password_type})`);

    let fek: Uint8Array;
    let metadataDecryptionKey: Uint8Array;

    if (passwordType === 'account' || meta.password_type === 'account') {
      // Account-encrypted: get Account Key, decrypt FEK
      console.log(`${LOG_PREFIX} Resolving account key for FEK decryption (passwordType=account)`);
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        console.log(`${LOG_PREFIX} Account key resolution cancelled or failed`);
        return;
      }
      metadataDecryptionKey = accountKey;

      try {
        const tDec = Date.now();
        fek = await decryptFEK(meta.encrypted_fek, accountKey);
        console.log(`${LOG_PREFIX} FEK decrypted in ${Date.now() - tDec}ms`);
      } catch (error) {
        console.error(`${LOG_PREFIX} Failed to decrypt FEK with account key:`, error instanceof Error ? error.message : error);
        showError('Failed to decrypt file key. Your password may be incorrect.');
        return;
      }
    } else {
      // Custom-encrypted: need account key for metadata AND custom key for FEK
      console.log(`${LOG_PREFIX} Resolving account key for metadata decryption (passwordType=custom)`);
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        console.log(`${LOG_PREFIX} Account key resolution cancelled or failed`);
        return;
      }
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
      if (!promptResult) {
        console.log(`${LOG_PREFIX} Custom password prompt cancelled`);
        return;
      }
      const password = promptResult.password;

      try {
        showProgress({
          title: 'Deriving Custom Key',
          message: 'Running Argon2id key derivation -- this may take a few seconds...',
          indeterminate: true,
        });

        const tKdf = Date.now();
        const customKey = await deriveFileEncryptionKey(password, username, 'custom');
        console.log(`${LOG_PREFIX} Custom key derived (Argon2id) in ${Date.now() - tKdf}ms`);
        hideProgress();

        const tDec = Date.now();
        fek = await decryptFEK(meta.encrypted_fek, customKey);
        console.log(`${LOG_PREFIX} FEK decrypted with custom key in ${Date.now() - tDec}ms`);
      } catch (error) {
        hideProgress();
        console.error(`${LOG_PREFIX} Failed to decrypt FEK with custom password:`, error instanceof Error ? error.message : error);
        showError('Failed to decrypt file key. Check your password.');
        return;
      }
    }

    // Stream-decrypt all chunks via the streaming download manager.
    // Pass fsapiHandlePromise so the manager can write directly to the
    // user-selected file (FSAPI path) or fall back to Blob (Firefox).
    console.log(`${LOG_PREFIX} Beginning chunked streaming download...`);
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      authToken,
      {
        accountKey: metadataDecryptionKey,
        showProgressUI: true,
        fsapiHandlePromise: fsapiHandlePromise ?? null,
        onProgress: (progress) => {
          if (progress.stage === 'error') {
            console.error(`${LOG_PREFIX} Streaming progress error:`, progress.error);
          }
        },
      },
    );

    if (!result.success) {
      if (result.error === 'Download cancelled') {
        console.log(`${LOG_PREFIX} Download cancelled by user`);
        return;
      }
      console.error(`${LOG_PREFIX} Streaming download returned failure: ${result.error}`);
      showError(result.error || 'Download failed.');
      return;
    }

    if (!result.filename) {
      console.error(`${LOG_PREFIX} Result missing filename`);
      showError('Download completed but filename is missing.');
      return;
    }

    if (result.sha256sum && expectedHash && result.sha256sum !== expectedHash) {
      console.warn(`${LOG_PREFIX} SHA-256 hash mismatch — file may be corrupted`);
    }

    if (result.savedViaFileSystemAPI) {
      // FSAPI path: file was written directly to disk
      console.log(`${LOG_PREFIX} File saved directly to disk via FSAPI (total elapsed ${Date.now() - t0}ms)`);
      showSuccess(`Downloaded: ${result.filename}`);
      return;
    }

    // Blob fallback path (Firefox): trigger browser download from blob URL
    if (!result.blobUrl) {
      console.error(`${LOG_PREFIX} Result missing blobUrl on fallback path`);
      showError('Download completed but no file data was produced.');
      return;
    }

    console.log(`${LOG_PREFIX} Triggering browser download (total elapsed ${Date.now() - t0}ms)`);
    triggerBrowserDownloadFromUrl(result.blobUrl, result.filename);
    showSuccess(`Downloaded: ${result.filename}`);
  } catch (error) {
    console.error(`${LOG_PREFIX} Unhandled download error:`, error instanceof Error ? error.message : error);
    showError('An error occurred during file download.');
  }
}
