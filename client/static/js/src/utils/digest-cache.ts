/**
 * Digest Cache -- Client-Side Deduplication
 *
 * Maintains an in-memory map of fileId -> plaintextSHA256 hex digest.
 * Used to detect duplicate uploads before sending any data to the server.
 *
 * Privacy: plaintext SHA-256 digests are NEVER sent to the server.
 * The server stores only encrypted sha256 values. This module decrypts
 * them client-side and keeps the plaintext only in JS heap memory, never in
 * Web Storage, which browsers may write to disk for session restore.
 *
 * Lifecycle:
 *   Login  -> populateDigestCache (fetch file list, decrypt each sha256)
 *   Upload -> checkDuplicate (pre-upload), addDigest (post-upload)
 *   Delete -> removeDigest
 *   Logout -> clearDigestCache
 */

import { decryptMetadataField } from '../crypto/metadata-helpers.js';
import { AAD_FIELD_SHA256 } from '../crypto/aad.js';

// Former sessionStorage key; removed so a tab open across an update keeps no plaintext digests.
const LEGACY_STORAGE_KEY = 'arkfile.digestCache';

const cache = new Map<string, string>();

function removeLegacyStorage(): void {
  try {
    sessionStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // sessionStorage unavailable
  }
}

removeLegacyStorage();

// Public API

/**
 * Raw file entry as returned by GET /api/files
 *
 * owner_username is required for metadata-field AAD reconstruction.
 * The digest cache populates from the authenticated user's
 * own files only, so in practice owner_username always equals the
 * authenticated username; we still pull it from the server response rather
 * than passing the auth-derived username separately, so the AAD is built
 * from exactly the same value the server stored.
 */
export interface RawFileEntry {
  file_id: string;
  owner_username: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
}

/**
 * Populate the digest cache from the file list returned by the server.
 * Call this once after a successful login (account key must be available).
 *
 * @param accountKey  - 32-byte account-derived AES key
 * @param files       - raw file entries from GET /api/files
 */
export async function populateDigestCache(
  accountKey: Uint8Array,
  files: RawFileEntry[]
): Promise<void> {
  cache.clear();

  for (const file of files) {
    try {
      if (file.encrypted_sha256sum && file.sha256sum_nonce) {
        const plaintext = await decryptMetadataField(
          file.encrypted_sha256sum,
          file.sha256sum_nonce,
          accountKey,
          file.file_id,
          AAD_FIELD_SHA256,
          file.owner_username,
        );
        cache.set(file.file_id, plaintext);
      }
    } catch (err) {
      // Non-fatal: skip individual entry if decryption fails
      console.warn(`digest-cache: failed to decrypt sha256 for file ${file.file_id}:`, err);
    }
  }
}

/**
 * Check whether a plaintext SHA-256 digest already exists in the cache.
 *
 * @param plaintextSha256Hex - hex-encoded SHA-256 of the plaintext file
 * @returns fileId of the matching file, or null if no duplicate found
 */
export function checkDuplicate(plaintextSha256Hex: string): string | null {
  for (const [fileId, digest] of cache) {
    if (digest === plaintextSha256Hex) {
      return fileId;
    }
  }
  return null;
}

/**
 * Add a new digest entry after a successful upload.
 *
 * @param fileId           - server-assigned file ID
 * @param plaintextSha256Hex - hex-encoded SHA-256 of the plaintext file
 */
export function addDigest(fileId: string, plaintextSha256Hex: string): void {
  cache.set(fileId, plaintextSha256Hex);
}

/**
 * Remove a digest entry after a file is deleted.
 *
 * @param fileId - the file ID to remove
 */
export function removeDigest(fileId: string): void {
  cache.delete(fileId);
}

/**
 * Clear the entire digest cache.
 * Call this on logout.
 */
export function clearDigestCache(): void {
  cache.clear();
  removeLegacyStorage();
}
