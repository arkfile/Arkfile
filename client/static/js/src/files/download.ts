/**
 * File download functionality with chunked download support
 *
 * This module provides file download capabilities using the chunked download
 * infrastructure for efficient downloads with client-side decryption.
 *
 * LARGE FILE DOWNLOADS
 * --------------------
 * Prefer Service Worker streaming (registerSwDownload at app init). The SW
 * intercepts /sw-download/<uuid> and responds with a streaming Response
 * carrying Content-Disposition: attachment so the browser writes bytes to
 * disk with chunk-bounded page memory and no Arkfile-imposed size cap.
 *
 * Whole-file SHA-256 on the SW path is computed as data flows; a mismatch may
 * be detected only after the OS download manager has saved bytes. Same class
 * of post-write limit as CLI computeStreamingSHA256 and offline decrypt-blob.
 * Never claim unqualified success on mismatch; show expected digest and tips.
 *
 * Blob fallback remains when SW is unavailable or cannot initialize before
 * generator consumption. It buffers the complete plaintext in browser Blob
 * storage with no Arkfile size cap; browser resources may still be
 * insufficient. Check hashVerification BEFORE triggerBrowserDownloadFromUrl;
 * revoke the Blob URL on mismatch and do not claim success.
 *
 * SECURITY: All FEK decryption happens client-side using Argon2id-derived keys.
 * The server NEVER sees the plaintext FEK or the user's password.
 */

import { authenticatedFetch, isAuthenticated, getUsernameFromToken, getCurrentUser } from '../utils/auth';
import { showError } from '../ui/messages';
import { showProgress, hideProgress } from '../ui/progress';
import { showPasswordPrompt } from '../ui/password-modal';
import {
  downloadFileChunked,
  triggerBrowserDownloadFromUrl,
  StreamingDownloadResult,
} from './streaming-download';
import { isSwAvailable } from './sw-streaming-download';
import {
  finalizeDownloadIntegrity,
  showSwStreamingTip,
  showBlobBufferWarning,
  showPartialDownloadWarning,
} from './download-integrity';
import { debugLog } from '../utils/debug-log.js';

import { deriveFileEncryptionKey } from '../crypto/file-encryption';
import { getAccountKey, decryptFEK } from '../crypto/metadata-helpers';

const LOG_PREFIX = '[arkfile-download]';
const INTEGRITY_PANEL_ID = 'download-integrity-panel';

interface FileMetaResponse {
  /** Canonical file_id (required to reconstruct FEK / metadata AAD). */
  file_id: string;
  /** Canonical owner_username (required for metadata-field AAD). */
  owner_username: string;
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
 *    - SW path (preferred): bytes flow to the browser's download manager via
 *      the Service Worker; SHA-256 verified inline (may be post-write on disk).
 *    - Blob fallback: accumulate incrementally; check hash before trigger.
 * 6. Show integrity panel (expected digest, inline result, Verify File entry).
 */
export async function downloadFile(
  fileId: string,
  hint: string,
  expectedHash: string,
  passwordType: string,
): Promise<void> {
  const t0 = Date.now();
  debugLog(`${LOG_PREFIX} downloadFile() invoked (passwordType=${passwordType})`);

  try {
    if (!isAuthenticated()) {
      console.error(`${LOG_PREFIX} No auth token available`);
      showError('Not authenticated. Please log in again.');
      return;
    }

    let username = getUsernameFromToken();
    if (!username) {
      // Cache miss (e.g. page reload): fetch from /api/auth/me to repopulate.
      const userInfo = await getCurrentUser(true);
      username = userInfo?.username ?? null;
    }
    if (!username) {
      console.error(`${LOG_PREFIX} Username could not be determined`);
      showError('Username not found. Please log in again.');
      return;
    }

    // Fetch file metadata
    const tMeta = Date.now();
    debugLog(`${LOG_PREFIX} Fetching file metadata...`);
    const metaResponse = await authenticatedFetch(`/api/files/${fileId}/meta`);
    if (!metaResponse.ok) {
      const errorData = await metaResponse.json().catch(() => ({}));
      console.error(`${LOG_PREFIX} Metadata fetch failed: HTTP ${metaResponse.status}`);
      showError(errorData.message || 'Failed to retrieve file metadata.');
      return;
    }
    const meta: FileMetaResponse = await metaResponse.json();
    debugLog(`${LOG_PREFIX} Metadata fetched in ${Date.now() - tMeta}ms (size_bytes=${meta.size_bytes}, total_chunks=${meta.total_chunks}, password_type=${meta.password_type})`);

    let fek: Uint8Array;
    let metadataDecryptionKey: Uint8Array;

    if (passwordType === 'account' || meta.password_type === 'account') {
      // Account-encrypted: get Account Key, decrypt FEK
      debugLog(`${LOG_PREFIX} Resolving account key for FEK decryption (passwordType=account)`);
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        debugLog(`${LOG_PREFIX} Account key resolution cancelled or failed`);
        return;
      }
      metadataDecryptionKey = accountKey;

      try {
        const tDec = Date.now();
        fek = await decryptFEK(meta.encrypted_fek, accountKey, meta.file_id);
        debugLog(`${LOG_PREFIX} FEK decrypted in ${Date.now() - tDec}ms`);
      } catch (error) {
        console.error(`${LOG_PREFIX} Failed to decrypt FEK with account key:`, error instanceof Error ? error.message : error);
        showError('Failed to decrypt file key. Your password may be incorrect.');
        return;
      }
    } else {
      // Custom-encrypted: need account key for metadata AND custom key for FEK
      debugLog(`${LOG_PREFIX} Resolving account key for metadata decryption (passwordType=custom)`);
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        debugLog(`${LOG_PREFIX} Account key resolution cancelled or failed`);
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
        debugLog(`${LOG_PREFIX} Custom password prompt cancelled`);
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
        debugLog(`${LOG_PREFIX} Custom key derived (Argon2id) in ${Date.now() - tKdf}ms`);
        hideProgress();

        const tDec = Date.now();
        fek = await decryptFEK(meta.encrypted_fek, customKey, meta.file_id);
        debugLog(`${LOG_PREFIX} FEK decrypted with custom key in ${Date.now() - tDec}ms`);
      } catch (error) {
        hideProgress();
        console.error(`${LOG_PREFIX} Failed to decrypt FEK with custom password:`, error instanceof Error ? error.message : error);
        const toast = showError('Failed to decrypt file key. Check your password.');
        toast.setAttribute('data-testid', 'wrong-custom-password');
        return;
      }
    }

    if (isSwAvailable()) {
      showSwStreamingTip();
    } else {
      showBlobBufferWarning();
    }

    // Stream-decrypt all chunks via the streaming download manager.
    // Picks the SW path when available; falls back to Blob only when safe.
    debugLog(`${LOG_PREFIX} Beginning chunked streaming download...`);
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      null,
      {
        accountKey: metadataDecryptionKey,
        showProgressUI: true,
        onProgress: (progress) => {
          if (progress.stage === 'error') {
            console.error(`${LOG_PREFIX} Streaming progress error:`, progress.error);
          }
        },
      },
    );

    if (!result.success) {
      if (result.error === 'Download cancelled') {
        debugLog(`${LOG_PREFIX} Download cancelled by user`);
        return;
      }
      console.error(`${LOG_PREFIX} Streaming download returned failure: ${result.error}`);
      if (result.error && /partial file may already/i.test(result.error)) {
        showPartialDownloadWarning();
      }
      showError(result.error || 'Download failed.');
      return;
    }

    if (!result.filename) {
      console.error(`${LOG_PREFIX} Result missing filename`);
      showError('Download completed but filename is missing.');
      return;
    }

    // Sanity check: server-stored expectedHash from list.ts row should match
    // the freshly-decrypted sha256sum from this download's metadata. They are
    // both ciphertext over the same value with the same account key, so a
    // mismatch here indicates metadata tampering or a stale list view.
    if (result.sha256sum && expectedHash && result.sha256sum !== expectedHash) {
      console.warn(`${LOG_PREFIX} SHA-256 metadata mismatch -- possible tampering or stale list view`);
    }

    const integrity = {
      filename: result.filename,
      expectedSha256: result.sha256sum,
      computedSha256: result.computedSha256Hex,
      hashVerification: result.hashVerification,
      streamedViaSw: result.streamedViaSw === true,
    };

    if (result.streamedViaSw) {
      debugLog(`${LOG_PREFIX} File streamed via Service Worker (total elapsed ${Date.now() - t0}ms, hash_verification=${result.hashVerification ?? 'n/a'})`);
      finalizeDownloadIntegrity(integrity, INTEGRITY_PANEL_ID);
      return;
    }

    // Blob fallback path: check hash BEFORE trigger; revoke on mismatch.
    if (!result.blobUrl) {
      console.error(`${LOG_PREFIX} Result missing blobUrl on fallback path`);
      showError('Download completed but no file data was produced.');
      return;
    }

    const decision = finalizeDownloadIntegrity(integrity, INTEGRITY_PANEL_ID);
    if (decision.blockBlobTrigger) {
      console.warn(`${LOG_PREFIX} Blob download blocked due to hash mismatch; revoking Blob URL`);
      URL.revokeObjectURL(result.blobUrl);
      return;
    }

    debugLog(`${LOG_PREFIX} Triggering browser download from blob URL (SW unavailable, total elapsed ${Date.now() - t0}ms)`);
    triggerBrowserDownloadFromUrl(result.blobUrl, result.filename);
  } catch (error) {
    console.error(`${LOG_PREFIX} Unhandled download error:`, error instanceof Error ? error.message : error);
    const msg = error instanceof Error ? error.message : '';
    if (/partial file may already/i.test(msg)) {
      showPartialDownloadWarning();
    }
    showError('An error occurred during file download.');
  }
}
