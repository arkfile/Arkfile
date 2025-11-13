/**
 * File Encryption System
 * 
 * High-level API for encrypting and decrypting files using Argon2id-based key derivation.
 * This system is completely independent from OPAQUE authentication and enables:
 * - Offline decryption (no server required)
 * - Data portability (decrypt anywhere with password + username)
 * - Deterministic key derivation (same password always produces same key)
 */

import {
  deriveKeyArgon2id,
  encryptAESGCM,
  decryptAESGCM,
  hashString,
  generateSalt,
  toBase64,
  fromBase64,
  secureWipe,
} from './primitives';
import {
  KEY_SIZES,
  getArgon2Params,
  FILE_ENCRYPTION_VERSION,
  LIMITS,
} from './constants';
import {
  FileTooLargeError,
  InvalidUsernameError,
  SaltDerivationError,
  EncryptionError,
  DecryptionError,
  UnsupportedProtocolVersionError,
  CorruptedDataError,
  wrapError,
} from './errors';
import type {
  FileEncryptionMetadata,
  EncryptedFileData,
  FileEncryptionOptions,
  FileDecryptionOptions,
} from './types';

// ============================================================================
// Salt Derivation
// ============================================================================

/**
 * Password context types for domain separation
 * These match the Go implementation in crypto/key_derivation.go
 */
export type PasswordContext = 'account' | 'custom' | 'share';

/**
 * Domain prefixes for salt derivation
 * CRITICAL: These MUST match the Go implementation exactly for cross-platform compatibility
 * See: crypto/key_derivation.go - DeriveAccountPasswordKey, DeriveCustomPasswordKey, DeriveSharePasswordKey
 */
const SALT_DOMAIN_PREFIXES: Record<PasswordContext, string> = {
  account: 'arkfile-account-key-salt:',
  custom: 'arkfile-custom-key-salt:',
  share: 'arkfile-share-key-salt:',
} as const;

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
 * @param context - The password context (account, custom, or share)
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
 * @param context - The password context (account, custom, or share)
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
// File Encryption
// ============================================================================

/**
 * Encrypts a file using password-based encryption
 * 
 * @param file - The file to encrypt (as Uint8Array)
 * @param password - The user's password
 * @param username - The user's username (used for deterministic salt)
 * @param options - Optional encryption parameters
 * @returns Encrypted file data with metadata
 */
export async function encryptFile(
  file: Uint8Array,
  password: string,
  username: string,
  options: FileEncryptionOptions = {}
): Promise<EncryptedFileData> {
  // Validate file size
  if (file.length > LIMITS.MAX_FILE_SIZE) {
    throw new FileTooLargeError(file.length, LIMITS.MAX_FILE_SIZE);
  }
  
  try {
    // Derive encryption key with context (default to 'account')
    const context = options.context || 'account';
    const key = await deriveFileEncryptionKey(password, username, context);
    
    // Get Argon2id parameters from config for metadata
    const argon2Params = await getArgon2Params();
    
    // Encrypt the file
    const encryptionResult = await encryptAESGCM({
      data: file,
      key,
      ...(options.additionalData && { aad: options.additionalData }),
    });
    
    // Create metadata
    const metadata: FileEncryptionMetadata = {
      version: FILE_ENCRYPTION_VERSION,
      algorithm: 'AES-256-GCM',
      kdf: 'Argon2id',
      kdfParams: {
        memoryCost: argon2Params.memoryCost,
        timeCost: argon2Params.timeCost,
        parallelism: argon2Params.parallelism,
      },
      timestamp: Date.now(),
      originalSize: file.length,
    };
    
    // Clean up sensitive data
    secureWipe(key);
    
    return {
      metadata,
      ciphertext: encryptionResult.ciphertext,
      iv: encryptionResult.iv,
      tag: encryptionResult.tag,
    };
  } catch (error) {
    throw wrapError(error, 'File encryption failed');
  }
}

/**
 * Encrypts a file and returns it as a base64-encoded string
 * 
 * This is useful for storing encrypted files in JSON or sending over HTTP.
 */
export async function encryptFileToBase64(
  file: Uint8Array,
  password: string,
  username: string,
  options: FileEncryptionOptions = {}
): Promise<string> {
  const encrypted = await encryptFile(file, password, username, options);
  
  // Serialize to JSON
  const serialized = {
    metadata: encrypted.metadata,
    ciphertext: toBase64(encrypted.ciphertext),
    iv: toBase64(encrypted.iv),
    tag: toBase64(encrypted.tag),
  };
  
  return JSON.stringify(serialized);
}

// ============================================================================
// File Decryption
// ============================================================================

/**
 * Decrypts a file using password-based decryption
 * 
 * This function works completely offline - no server required.
 * As long as the user has the correct password and username,
 * they can decrypt their files anywhere.
 * 
 * @param encryptedData - The encrypted file data
 * @param password - The user's password
 * @param username - The user's username
 * @param options - Optional decryption parameters
 * @returns The decrypted file
 */
export async function decryptFile(
  encryptedData: EncryptedFileData,
  password: string,
  username: string,
  options: FileDecryptionOptions = {}
): Promise<Uint8Array> {
  try {
    // Validate version
    if (encryptedData.metadata.version !== FILE_ENCRYPTION_VERSION) {
      throw new UnsupportedProtocolVersionError(
        encryptedData.metadata.version,
        FILE_ENCRYPTION_VERSION
      );
    }
    
    // Validate algorithm
    if (encryptedData.metadata.algorithm !== 'AES-256-GCM') {
      throw new CorruptedDataError(
        `Unsupported algorithm: ${encryptedData.metadata.algorithm}`
      );
    }
    
    // Validate KDF
    if (encryptedData.metadata.kdf !== 'Argon2id') {
      throw new CorruptedDataError(
        `Unsupported KDF: ${encryptedData.metadata.kdf}`
      );
    }
    
    // Derive decryption key (same as encryption key) with context
    const context = options.context || 'account';
    const key = await deriveFileEncryptionKey(password, username, context);
    
    // Decrypt the file
    const decryptionResult = await decryptAESGCM({
      ciphertext: encryptedData.ciphertext,
      key,
      iv: encryptedData.iv,
      tag: encryptedData.tag,
      ...(options.additionalData && { aad: options.additionalData }),
    });
    
    // Validate decrypted size matches metadata
    if (decryptionResult.plaintext.length !== encryptedData.metadata.originalSize) {
      throw new CorruptedDataError(
        `Size mismatch: expected ${encryptedData.metadata.originalSize}, got ${decryptionResult.plaintext.length}`
      );
    }
    
    // Clean up sensitive data
    secureWipe(key);
    
    return decryptionResult.plaintext;
  } catch (error) {
    throw wrapError(error, 'File decryption failed');
  }
}

/**
 * Decrypts a base64-encoded encrypted file
 */
export async function decryptFileFromBase64(
  base64Data: string,
  password: string,
  username: string,
  options: FileDecryptionOptions = {}
): Promise<Uint8Array> {
  try {
    // Parse JSON
    const parsed = JSON.parse(base64Data);
    
    // Reconstruct EncryptedFileData
    const encryptedData: EncryptedFileData = {
      metadata: parsed.metadata,
      ciphertext: fromBase64(parsed.ciphertext),
      iv: fromBase64(parsed.iv),
      tag: fromBase64(parsed.tag),
    };
    
    return await decryptFile(encryptedData, password, username, options);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new CorruptedDataError('Invalid JSON format');
    }
    throw error;
  }
}

// ============================================================================
// Key Caching (Session Storage)
// ============================================================================

const KEY_CACHE_PREFIX = 'arkfile_file_key_';
const KEY_CACHE_EXPIRY = 3600000; // 1 hour in milliseconds

interface CachedKey {
  key: string; // base64-encoded key
  expiresAt: number;
  username: string;
}

/**
 * Caches a derived file encryption key in sessionStorage
 * 
 * This improves performance by avoiding repeated Argon2id derivations
 * during a single session. The key is automatically cleared when the
 * browser tab is closed.
 */
export function cacheFileEncryptionKey(
  username: string,
  key: Uint8Array
): void {
  try {
    const cached: CachedKey = {
      key: toBase64(key),
      expiresAt: Date.now() + KEY_CACHE_EXPIRY,
      username,
    };
    
    const cacheKey = KEY_CACHE_PREFIX + username;
    sessionStorage.setItem(cacheKey, JSON.stringify(cached));
  } catch (error) {
    // Silently fail if sessionStorage is not available
    console.warn('Failed to cache file encryption key:', error);
  }
}

/**
 * Retrieves a cached file encryption key from sessionStorage
 * 
 * Returns null if the key is not cached or has expired.
 */
export function getCachedFileEncryptionKey(username: string): Uint8Array | null {
  try {
    const cacheKey = KEY_CACHE_PREFIX + username;
    const cached = sessionStorage.getItem(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    const parsed: CachedKey = JSON.parse(cached);
    
    // Check if expired
    if (Date.now() > parsed.expiresAt) {
      sessionStorage.removeItem(cacheKey);
      return null;
    }
    
    // Verify username matches
    if (parsed.username !== username) {
      sessionStorage.removeItem(cacheKey);
      return null;
    }
    
    return fromBase64(parsed.key);
  } catch (error) {
    // Silently fail and return null
    return null;
  }
}

/**
 * Clears the cached file encryption key for a user
 */
export function clearCachedFileEncryptionKey(username: string): void {
  try {
    const cacheKey = KEY_CACHE_PREFIX + username;
    sessionStorage.removeItem(cacheKey);
  } catch (error) {
    // Silently fail
  }
}

/**
 * Clears all cached file encryption keys
 */
export function clearAllCachedKeys(): void {
  try {
    const keys = Object.keys(sessionStorage);
    for (const key of keys) {
      if (key.startsWith(KEY_CACHE_PREFIX)) {
        sessionStorage.removeItem(key);
      }
    }
  } catch (error) {
    // Silently fail
  }
}

/**
 * Derives a file encryption key with caching
 * 
 * This is the recommended way to derive keys, as it will use
 * a cached key if available, avoiding expensive Argon2id computation.
 * 
 * @param password - The user's password
 * @param username - The user's username
 * @param context - The password context (account, custom, or share)
 * @returns A 32-byte encryption key
 */
export async function deriveFileEncryptionKeyWithCache(
  password: string,
  username: string,
  context: PasswordContext = 'account'
): Promise<Uint8Array> {
  // Create cache key that includes context
  const cacheKey = `${username}:${context}`;
  
  // Try to get cached key
  const cachedKey = getCachedFileEncryptionKey(cacheKey);
  if (cachedKey) {
    return cachedKey;
  }
  
  // Derive new key
  const key = await deriveFileEncryptionKey(password, username, context);
  
  // Cache it
  cacheFileEncryptionKey(cacheKey, key);
  
  return key;
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
  
  // Encryption
  encryptFile,
  encryptFileToBase64,
  
  // Decryption
  decryptFile,
  decryptFileFromBase64,
  
  // Key caching
  cacheFileEncryptionKey,
  getCachedFileEncryptionKey,
  clearCachedFileEncryptionKey,
  clearAllCachedKeys,
};
