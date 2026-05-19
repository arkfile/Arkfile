/**
 * Digest Cache — Client-Side Deduplication
 *
 * Maintains a sessionStorage map of fileId -> plaintextSHA256 hex digest.
 * Used to detect duplicate uploads before sending any data to the server.
 *
 * Privacy: plaintext SHA-256 digests are NEVER sent to the server.
 * The server stores only encrypted sha256 values. This module decrypts
 * them client-side and stores the plaintext only in sessionStorage.
 *
 * Lifecycle:
 *   Login  -> populateDigestCache (fetch file list, decrypt each sha256)
 *   Upload -> checkDuplicate (pre-upload), addDigest (post-upload)
 *   Delete -> removeDigest
 *   Logout -> clearDigestCache
 */

import { decryptMetadataField } from '../crypto/metadata-helpers.js';
import { AAD_FIELD_SHA256 } from '../crypto/aad.js';

// ============================================================================
// Storage key
// ============================================================================

const CACHE_KEY = 'arkfile.digestCache';

// ============================================================================
// Internal helpers
// ============================================================================

function readCache(): Record<string, string> {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY);
    if (!raw) return {};
    return JSON.parse(raw) as Record<string, string>;
  } catch {
    return {};
  }
}

function writeCache(cache: Record<string, string>): void {
  try {
    sessionStorage.setItem(CACHE_KEY, JSON.stringify(cache));
  } catch {
    // sessionStorage full or unavailable — silently skip
    console.warn('digest-cache: unable to write to sessionStorage');
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Raw file entry as returned by GET /api/files
 *
 * Phase C: owner_username is required for metadata-field AAD
 * reconstruction. The digest cache populates from the authenticated user's
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
  const cache: Record<string, string> = {};

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
        cache[file.file_id] = plaintext;
      }
    } catch (err) {
      // Non-fatal: skip individual entry if decryption fails
      console.warn(`digest-cache: failed to decrypt sha256 for file ${file.file_id}:`, err);
    }
  }

  writeCache(cache);
}

/**
 * Check whether a plaintext SHA-256 digest already exists in the cache.
 *
 * @param plaintextSha256Hex - hex-encoded SHA-256 of the plaintext file
 * @returns fileId of the matching file, or null if no duplicate found
 */
export function checkDuplicate(plaintextSha256Hex: string): string | null {
  const cache = readCache();
  for (const [fileId, digest] of Object.entries(cache)) {
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
  const cache = readCache();
  cache[fileId] = plaintextSha256Hex;
  writeCache(cache);
}

/**
 * Remove a digest entry after a file is deleted.
 *
 * @param fileId - the file ID to remove
 */
export function removeDigest(fileId: string): void {
  const cache = readCache();
  delete cache[fileId];
  writeCache(cache);
}

/**
 * Clear the entire digest cache.
 * Call this on logout.
 */
export function clearDigestCache(): void {
  try {
    sessionStorage.removeItem(CACHE_KEY);
  } catch {
    // ignore
  }
}
