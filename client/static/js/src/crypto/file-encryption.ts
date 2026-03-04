/**
 * File Encryption Key Derivation & Caching
 * 
 * Provides Argon2id-based key derivation and Account Key caching for the
 * chunked encryption system. This module is completely independent from
 * OPAQUE authentication and enables:
 * - Offline decryption (no server required)
 * - Data portability (decrypt anywhere with password + username)
 * - Deterministic key derivation (same password always produces same key)
 * 
 */

import {
  deriveKeyArgon2id,
  hashString,
} from './primitives';
import {
  KEY_SIZES,
  getArgon2Params,
  SALT_DOMAIN_PREFIXES,
} from './constants';
import type { PasswordContext } from './constants';
export type { PasswordContext } from './constants';
import {
  InvalidUsernameError,
  SaltDerivationError,
  wrapError,
} from './errors';

// ============================================================================
// Salt Derivation
// ============================================================================

/**
 * Derives a deterministic salt from username with domain separation
 * 
 * This ensures the same username + context always produces the same salt,
 * which is critical for deterministic key derivation and cross-platform compatibility.
 * 
 * IMPORTANT: This implementation MUST match the Go implementation in crypto/key_derivation.go
 * to ensure files encrypted by the browser can be decrypted by CLI tools and vice versa.
 * 
 * Security note: The salt is derived from the username using SHA-256 with domain separation.
 * While this makes the salt predictable for a given username + context, it's acceptable because:
 * 1. Argon2id is designed to be secure even with known salts
 * 2. The high memory/time cost (256MB, 8 iterations) makes brute force attacks impractical
 * 3. Domain separation ensures different contexts produce different keys
 * 4. This enables offline decryption without server-stored salts
 * 
 * @param username - The user's username
 * @param context - The password context (account or custom)
 * @returns A deterministic 32-byte salt
 */
export function deriveSaltFromUsername(username: string, context: PasswordContext = 'account'): Uint8Array {
  // Validate username
  if (!username || username.trim().length === 0) {
    throw new InvalidUsernameError('Username cannot be empty');
  }
  
  // Normalize username (lowercase, trim whitespace)
  // NOTE: Go does NOT normalize to lowercase, so we need to match that behavior
  const normalizedUsername = username.trim();
  
  if (normalizedUsername.length < 3) {
    throw new InvalidUsernameError('Username must be at least 3 characters');
  }
  
  if (normalizedUsername.length > 64) {
    throw new InvalidUsernameError('Username must be at most 64 characters');
  }
  
  try {
    // Get domain prefix for this context
    const domainPrefix = SALT_DOMAIN_PREFIXES[context];
    
    // Construct salt input: "arkfile-{context}-key-salt:{username}"
    // This MUST match Go's implementation exactly
    const saltInput = domainPrefix + normalizedUsername;
    
    // Hash the salt input to get a deterministic salt
    const hash = hashString(saltInput);
    
    // Take the first 32 bytes as the salt
    return hash.slice(0, KEY_SIZES.SALT);
  } catch (error) {
    throw new SaltDerivationError(
      'Failed to derive salt from username',
      { username: normalizedUsername, context, error: String(error) }
    );
  }
}

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * Derives a file encryption key from password and username
 * 
 * This is the core function that enables offline decryption.
 * The same password + username + context will always produce the same key.
 * 
 * IMPORTANT: This must match the Go implementation for cross-platform compatibility.
 * 
 * @param password - The user's password
 * @param username - The user's username
 * @param context - The password context (account or custom)
 * @returns A 32-byte encryption key
 */
export async function deriveFileEncryptionKey(
  password: string,
  username: string,
  context: PasswordContext = 'account'
): Promise<Uint8Array> {
  // Derive deterministic salt from username with domain separation
  const salt = deriveSaltFromUsername(username, context);
  
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

// ============================================================================
// Key Caching (Session Storage)
// ============================================================================

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
 * @param accessToken - The current JWT access token (for session binding)
 * @param cacheDuration - Optional cache duration in hours (1-4, only for 'account' context)
 * @returns A 32-byte encryption key
 */
export async function deriveFileEncryptionKeyWithCache(
  password: string,
  username: string,
  context: PasswordContext = 'account',
  accessToken?: string,
  cacheDuration?: CacheDurationHours
): Promise<Uint8Array> {
  // Only cache 'account' context keys
  if (context === 'account') {
    // Try to get cached Account Key
    const cachedKey = await getCachedAccountKey(username, accessToken);
    if (cachedKey) {
      return cachedKey;
    }
    
    // Derive new key
    const key = await deriveFileEncryptionKey(password, username, context);
    
    // Cache it with specified duration (requires accessToken for session binding)
    if (accessToken) {
      await cacheAccountKey(username, key, accessToken, cacheDuration);
    }
    
    return key;
  }
  
  // For 'custom' context, always derive fresh (no caching)
  return deriveFileEncryptionKey(password, username, context);
}

/**
 * Derives an Account Key with caching
 * 
 * This is a convenience wrapper for deriveFileEncryptionKeyWithCache
 * specifically for the 'account' context.
 * 
 * @param password - The user's account password
 * @param username - The user's username
 * @param accessToken - The current JWT access token (for session binding)
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

// ============================================================================
// Exports
// ============================================================================

export const fileEncryption = {
  // Salt derivation
  deriveSaltFromUsername,
  
  // Key derivation
  deriveFileEncryptionKey,
  deriveFileEncryptionKeyWithCache,
  deriveAccountKeyWithCache,
  
  // Account Key caching
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
};
