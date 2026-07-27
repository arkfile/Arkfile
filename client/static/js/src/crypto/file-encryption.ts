/**
 * File Encryption Key Derivation & Caching
 * 
 * Provides Argon2id-based key derivation and Account Key caching for the
 * chunked encryption system. This module is completely independent from
 * OPAQUE authentication and enables:
 * - Offline decryption from self-describing backup metadata
 * - Data portability across browser and CLI clients
 * - Explicit random public salts with account/custom domain separation
 * 
 */

import {
  deriveKeyArgon2id,
  generateSalt,
  hash256,
} from './primitives';
import {
  KEY_SIZES,
  getArgon2Params,
} from './constants';
import type { PasswordContext } from './constants';
export type { PasswordContext } from './constants';
import { wrapError } from './errors';

// Salt handling

export function generatePasswordSalt(): Uint8Array {
  return generateSalt();
}

export function validatePasswordSalt(salt: Uint8Array): void {
  if (salt.length !== KEY_SIZES.SALT) {
    throw new Error(`Password salt must be ${KEY_SIZES.SALT} bytes, got ${salt.length}`);
  }
}

function deriveContextSalt(publicSalt: Uint8Array, context: PasswordContext): Uint8Array {
  validatePasswordSalt(publicSalt);
  const encoder = new TextEncoder();
  const prefix = encoder.encode('arkfile-owner-kdf-v1');
  const contextBytes = encoder.encode(context);
  const input = new Uint8Array(prefix.length + 1 + contextBytes.length + 1 + publicSalt.length);
  let offset = 0;
  input.set(prefix, offset);
  offset += prefix.length + 1;
  input.set(contextBytes, offset);
  offset += contextBytes.length + 1;
  input.set(publicSalt, offset);
  return hash256(input);
}

/**
 * Derives an Account or Custom Key from a password and explicit public salt.
 * @param password - The user's password
 * @param publicSalt - Random 32-byte public salt
 * @param context - The password context (account or custom)
 * @returns A 32-byte encryption key
 */
export async function deriveFileEncryptionKey(
  password: string,
  publicSalt: Uint8Array,
  context: PasswordContext = 'account'
): Promise<Uint8Array> {
  const salt = deriveContextSalt(publicSalt, context);
  
  try {
    // Get Argon2id parameters from config
    const argon2Params = await getArgon2Params();
    
    // Derive key using Argon2id
    const result = await deriveKeyArgon2id({
      password,
      salt,
      params: argon2Params,
    });
    
    return result.key;
  } catch (error) {
    throw wrapError(error, 'Failed to derive file encryption key');
  }
}

// Key Caching (Session Storage)

// Import the new Account Key cache module for consistent caching
import {
  cacheAccountKey,
  getCachedAccountKey,
  clearCachedAccountKey,
  clearAllCachedAccountKeys,
  isAccountKeyCached,
  cachedAccountKeyExpiresAt,
  lockAccountKey,
  unlockAccountKey,
  isAccountKeyLocked,
  cleanupAccountKeyCache,
  type CacheDurationHours,
} from './account-key-cache.js';
import { getAccountCryptoMetadata } from './account-crypto.js';

// Re-export Account Key cache functions for convenience
export {
  cacheAccountKey,
  getCachedAccountKey,
  clearCachedAccountKey,
  clearAllCachedAccountKeys,
  isAccountKeyCached,
  cachedAccountKeyExpiresAt,
  lockAccountKey,
  unlockAccountKey,
  isAccountKeyLocked,
  cleanupAccountKeyCache,
  type CacheDurationHours,
};

/**
 * Derives a file encryption key with caching
 * 
 * This is the recommended way to derive keys, as it will use
 * a cached key if available, avoiding expensive Argon2id computation.
 * 
 * For 'account' context, uses the new Account Key cache.
 * For 'custom' context, derives fresh keys (no caching).
 * 
 * @param password - The user's password
 * @param username - The user's username
 * @param context - The password context (account or custom)
 * @param accessToken - Optional; omitted under cookie auth (heap wrapping is the real bind)
 * @param cacheDuration - Optional cache duration in hours (1-4, only for 'account' context)
 * @returns A 32-byte encryption key
 */
export async function deriveFileEncryptionKeyWithCache(
  password: string,
  username: string,
  context: PasswordContext = 'account',
  accessToken?: string,
  cacheDuration?: CacheDurationHours,
  publicSalt?: Uint8Array,
): Promise<Uint8Array> {
  // Only cache 'account' context keys
  if (context === 'account') {
    const metadata = await getAccountCryptoMetadata(username);
    // Try to get cached Account Key
    const cachedKey = await getCachedAccountKey(username, accessToken);
    if (cachedKey) {
      return cachedKey;
    }
    
    // Derive new key
    const key = await deriveFileEncryptionKey(password, metadata.salt, context);
    
    // Cache it with the specified duration whenever the user opted in.
    if (cacheDuration !== undefined) {
      await cacheAccountKey(username, key, accessToken, cacheDuration);
    }
    
    return key;
  }
  
  // For 'custom' context, always derive fresh (no caching)
  if (!publicSalt) {
    throw new Error('Custom Key derivation requires an explicit public salt');
  }
  return deriveFileEncryptionKey(password, publicSalt, context);
}

/**
 * Derives an Account Key with caching
 * 
 * This is a convenience wrapper for deriveFileEncryptionKeyWithCache
 * specifically for the 'account' context.
 * 
 * @param password - The user's account password
 * @param username - The user's username
 * @param accessToken - Optional; omitted under cookie auth
 * @param cacheDuration - Optional cache duration in hours (1-4)
 * @returns A 32-byte Account Key
 */
export async function deriveAccountKeyWithCache(
  password: string,
  username: string,
  accessToken?: string,
  cacheDuration?: CacheDurationHours
): Promise<Uint8Array> {
  return deriveFileEncryptionKeyWithCache(password, username, 'account', accessToken, cacheDuration);
}

