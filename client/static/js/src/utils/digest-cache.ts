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

import { decryptAESGCM, fromBase64 } from '../crypto/primitives.js';

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

/**
 * Decrypts a single encrypted metadata field (filename or sha256sum).
 *
 * The server stores metadata split as:
 *   encrypted_sha256sum  — base64(ciphertext || tag)
 *   sha256sum_nonce      — base64(nonce)
 *
 * This matches how upload.ts encrypts with encryptMetadata():
 *   encrypted = base64(ciphertext || tag)
 *   nonce     = base64(iv)
 */
async function decryptMetadataField(
  encryptedBase64: string,
  nonceBase64: string,
  accountKey: Uint8Array
): Promise<string> {
  const encryptedWithTag = fromBase64(encryptedBase64);
  const iv = fromBase64(nonceBase64);

  // Split ciphertext and tag (last 16 bytes are the GCM auth tag)
  if (encryptedWithTag.length < 16) {
    throw new Error('Encrypted metadata too short');
  }
  const tagOffset = encryptedWithTag.length - 16;
  const ciphertext = encryptedWithTag.slice(0, tagOffset);
  const tag = encryptedWithTag.slice(tagOffset);

  const result = await decryptAESGCM({ ciphertext, iv, tag, key: accountKey });
  return new TextDecoder().decode(result.plaintext);
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Raw file entry as returned by GET /api/files
 */
export interface RawFileEntry {
  file_id: string;
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
          accountKey
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
