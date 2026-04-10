/**
 * Shared Metadata Helpers
 *
 * Common utilities for decrypting file metadata (filenames, SHA-256 hashes)
 * and FEKs. Used by download, share, file list, and share list modules.
 *
 * These helpers are the single source of truth for metadata decryption
 * in the TypeScript frontend, mirroring the Go CLI's DecryptFileMetadata()
 * and DecryptFEK() functions.
 */

import { decryptChunk } from './aes-gcm.js';
import { showError } from '../ui/messages.js';
import { showProgress, hideProgress } from '../ui/progress.js';
import { getToken, getUsernameFromToken } from '../utils/auth.js';
import {
  getCachedAccountKey,
  isAccountKeyLocked,
  deriveFileEncryptionKeyWithCache,
  type CacheDurationHours,
} from './file-encryption.js';
import { unlockAccountKey } from './account-key-cache.js';
import { promptForAccountKeyPassword } from '../ui/password-modal.js';

// ============================================================================
// Base64 Helpers
// ============================================================================

/**
 * Decode a base64 string to a Uint8Array.
 * Uses the browser's built-in atob().
 */
export function base64ToBytes(base64: string): Uint8Array {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ============================================================================
// Account Key Resolution
// ============================================================================

/**
 * Resolve the Account Key from cache or by prompting the user.
 *
 * 1. If the key is locked (e.g. after page refresh or inactivity), clear
 *    the locked flag so the password prompt can proceed.
 * 2. If the key is cached, return it.
 * 3. Otherwise, prompt the user for their account password, derive the key
 *    via Argon2id, optionally cache it, and return it.
 *
 * @param username - The authenticated user's username
 * @returns The 32-byte Account Key, or null if the user cancelled
 */
export async function getAccountKey(username: string): Promise<Uint8Array | null> {
  // If the key is locked (e.g. after page refresh or inactivity timeout),
  // clear the locked flag and fall through to the password prompt below.
  // The wrapping key is already gone so there is nothing to "unlock" --
  // we just need to let the user re-enter their password.
  if (isAccountKeyLocked()) {
    unlockAccountKey();
  }

  const cached = await getCachedAccountKey(username, getToken() ?? undefined);
  if (cached) return cached;

  const result = await promptForAccountKeyPassword();
  if (!result) return null;

  try {
    showProgress({
      title: 'Deriving Account Key',
      message: 'Running Argon2id key derivation -- this may take a few seconds...',
      indeterminate: true,
    });

    const key = await deriveFileEncryptionKeyWithCache(
      result.password,
      username,
      'account',
      getToken() ?? undefined,
      result.cacheDuration as CacheDurationHours | undefined,
    );

    hideProgress();
    return key;
  } catch (err) {
    hideProgress();
    console.error('Failed to derive Account Key:', err);
    showError('Failed to derive encryption key. Please check your password.');
    return null;
  }
}

// ============================================================================
// FEK Decryption
// ============================================================================

/**
 * Decrypt an encrypted FEK (File Encryption Key).
 *
 * Encrypted FEK wire format (matches Go crypto.EncryptFEK):
 *   [version (1 byte)][keyType (1 byte)][nonce (12)][ciphertext][tag (16)]
 *
 * The 2-byte envelope header is stripped before AES-GCM decryption.
 *
 * @param encrypted_fek_base64 - Base64-encoded encrypted FEK with envelope header
 * @param kek                  - The Key Encryption Key (account or custom derived, 32 bytes)
 * @returns The decrypted FEK (32 bytes)
 */
export async function decryptFEK(
  encrypted_fek_base64: string,
  kek: Uint8Array,
): Promise<Uint8Array> {
  const raw = base64ToBytes(encrypted_fek_base64);

  // Minimum: 2 (envelope) + 12 (nonce) + 16 (tag) + 1 (min ciphertext) = 31
  if (raw.length < 31) {
    throw new Error(`Encrypted FEK too short: expected >= 31 bytes, got ${raw.length}`);
  }

  const version = raw[0];
  if (version !== 0x01) {
    throw new Error(
      `Unsupported envelope version: 0x${version.toString(16).padStart(2, '0')} (expected 0x01)`,
    );
  }

  // Strip 2-byte envelope header, then decrypt
  // Remaining: [nonce (12)][ciphertext][tag (16)]
  const fek = await decryptChunk(raw.slice(2), kek);

  if (fek.length !== 32) {
    throw new Error(`Invalid FEK length: expected 32 bytes, got ${fek.length}`);
  }

  return fek;
}

// ============================================================================
// Metadata Field Decryption
// ============================================================================

/**
 * Decrypt a single metadata field (filename or SHA-256 hash).
 *
 * The server stores the nonce and ciphertext+tag separately. We reassemble
 * them into the format expected by AES-GCM decryption:
 *   [nonce (12 bytes)][ciphertext][tag (16 bytes)]
 *
 * Metadata is always encrypted with the Account Key (Argon2id derived from
 * account password + username), regardless of whether the file uses account
 * or custom password for FEK encryption.
 *
 * @param ciphertext_base64 - Base64-encoded ciphertext + auth tag
 * @param nonce_base64      - Base64-encoded nonce (12 bytes)
 * @param account_key       - The Account Key (32 bytes)
 * @returns The decrypted plaintext string (e.g. filename or hex SHA-256)
 */
export async function decryptMetadataField(
  ciphertext_base64: string,
  nonce_base64: string,
  account_key: Uint8Array,
): Promise<string> {
  const nonce = base64ToBytes(nonce_base64);
  const ciphertext = base64ToBytes(ciphertext_base64);

  // Reassemble: [nonce][ciphertext+tag]
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);

  const plainBytes = await decryptChunk(combined, account_key);
  return new TextDecoder().decode(plainBytes);
}
