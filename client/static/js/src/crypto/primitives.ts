/**
 * Cryptographic Primitives
 * 
 * Low-level wrappers around Web Crypto API and @noble/hashes.
 * These primitives provide a clean interface for all cryptographic operations.
 */

import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';
import {
  KEY_SIZES,
  AES_GCM_CONFIG,
  LIMITS,
} from './constants';
import {
  WebCryptoUnavailableError,
  WebCryptoError,
  InvalidKeyLengthError,
  EncryptionError,
  DecryptionError,
  KeyDerivationError,
  KeyDerivationTimeoutError,
  wrapError,
} from './errors';
import type {
  EncryptionRequest,
  EncryptionResult,
  DecryptionRequest,
  DecryptionResult,
  KeyDerivationRequest,
  KeyDerivationResult,
  Argon2Params,
} from './types';

// ============================================================================
// Web Crypto API Availability Check
// ============================================================================

/**
 * Checks if Web Crypto API is available
 */
export function isWebCryptoAvailable(): boolean {
  return typeof crypto !== 'undefined' && 
         typeof crypto.subtle !== 'undefined';
}

/**
 * Ensures Web Crypto API is available, throws if not
 */
function ensureWebCrypto(): void {
  if (!isWebCryptoAvailable()) {
    throw new WebCryptoUnavailableError();
  }
}

// ============================================================================
// Random Number Generation
// ============================================================================

/**
 * Generates cryptographically secure random bytes
 */
export function randomBytes(length: number): Uint8Array {
  ensureWebCrypto();
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generates a random IV for AES-GCM
 */
export function generateIV(): Uint8Array {
  return randomBytes(KEY_SIZES.IV);
}

/**
 * Generates a random salt
 */
export function generateSalt(): Uint8Array {
  return randomBytes(KEY_SIZES.SALT);
}

// ============================================================================
// Hashing
// ============================================================================

/**
 * Computes SHA-256 hash
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Computes SHA-512 hash
 */
export function hash512(data: Uint8Array): Uint8Array {
  return sha512(data);
}

/**
 * Computes SHA-256 hash of a string (UTF-8 encoded)
 */
export function hashString(data: string): Uint8Array {
  const encoder = new TextEncoder();
  return hash256(encoder.encode(data));
}

// ============================================================================
// Key Derivation (Argon2id)
// ============================================================================

/**
 * Derives a key using Argon2id
 * 
 * This is the core function for file encryption key derivation.
 * It uses deterministic parameters to ensure the same password + salt
 * always produces the same key.
 */
export async function deriveKeyArgon2id(
  request: KeyDerivationRequest
): Promise<KeyDerivationResult> {
  const startTime = Date.now();
  
  try {
    // Validate parameters
    validateArgon2Params(request.params);
    
    // Encode password as UTF-8
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(request.password);
    
    // Derive key with timeout protection
    const key = await withTimeout(
      async () => {
        return argon2id(
          passwordBytes,
          request.salt,
          {
            t: request.params.timeCost,
            m: request.params.memoryCost,
            p: request.params.parallelism,
            dkLen: request.params.keyLength,
          }
        );
      },
      LIMITS.KEY_DERIVATION_TIMEOUT,
      'Argon2id key derivation'
    );
    
    const duration = Date.now() - startTime;
    
    return {
      key,
      duration,
    };
  } catch (error) {
    if (error instanceof KeyDerivationTimeoutError) {
      throw error;
    }
    throw new KeyDerivationError(
      'Failed to derive key using Argon2id',
      { error: String(error) }
    );
  }
}

/**
 * Validates Argon2 parameters
 */
function validateArgon2Params(params: Argon2Params): void {
  if (params.memoryCost < 1024) {
    throw new KeyDerivationError(
      'Memory cost must be at least 1024 KiB',
      { memoryCost: params.memoryCost }
    );
  }
  
  if (params.timeCost < 1) {
    throw new KeyDerivationError(
      'Time cost must be at least 1',
      { timeCost: params.timeCost }
    );
  }
  
  if (params.parallelism < 1) {
    throw new KeyDerivationError(
      'Parallelism must be at least 1',
      { parallelism: params.parallelism }
    );
  }
  
  if (params.keyLength < 16 || params.keyLength > 64) {
    throw new KeyDerivationError(
      'Key length must be between 16 and 64 bytes',
      { keyLength: params.keyLength }
    );
  }
}

// ============================================================================
// AES-GCM Encryption/Decryption
// ============================================================================

/**
 * Encrypts data using AES-256-GCM
 * 
 * AES-GCM provides both confidentiality and authenticity.
 * The authentication tag is included in the ciphertext.
 */
export async function encryptAESGCM(
  request: EncryptionRequest
): Promise<EncryptionResult> {
  ensureWebCrypto();
  
  try {
    // Validate key length
    if (request.key.length !== KEY_SIZES.AES_256) {
      throw new InvalidKeyLengthError(request.key.length, KEY_SIZES.AES_256);
    }
    
    // Generate random IV
    const iv = generateIV();
    
    // Import key (create proper ArrayBuffer copy)
    const keyBuffer = request.key.buffer.slice(
      request.key.byteOffset,
      request.key.byteOffset + request.key.byteLength
    ) as ArrayBuffer;
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: AES_GCM_CONFIG.name },
      false,
      ['encrypt']
    );
    
    // Encrypt (create proper ArrayBuffer copies)
    const ivBuffer = iv.buffer.slice(
      iv.byteOffset,
      iv.byteOffset + iv.byteLength
    ) as ArrayBuffer;
    const dataBuffer = request.data.buffer.slice(
      request.data.byteOffset,
      request.data.byteOffset + request.data.byteLength
    ) as ArrayBuffer;
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: AES_GCM_CONFIG.name,
        iv: ivBuffer,
        tagLength: AES_GCM_CONFIG.tagLength,
        ...(request.aad && { additionalData: request.aad }),
      },
      cryptoKey,
      dataBuffer
    );
    
    // Split ciphertext and tag
    // In AES-GCM, the tag is appended to the ciphertext
    const ciphertextArray = new Uint8Array(ciphertext);
    const tagLength = AES_GCM_CONFIG.tagLength / 8;
    const actualCiphertext = ciphertextArray.slice(0, -tagLength);
    const tag = ciphertextArray.slice(-tagLength);
    
    return {
      ciphertext: actualCiphertext,
      iv,
      tag,
    };
  } catch (error) {
    throw wrapError(error, 'AES-GCM encryption failed');
  }
}

/**
 * Decrypts data using AES-256-GCM
 * 
 * Verifies the authentication tag and decrypts the data.
 * Throws AuthenticationError if the tag is invalid.
 */
export async function decryptAESGCM(
  request: DecryptionRequest
): Promise<DecryptionResult> {
  ensureWebCrypto();
  
  try {
    // Validate key length
    if (request.key.length !== KEY_SIZES.AES_256) {
      throw new InvalidKeyLengthError(request.key.length, KEY_SIZES.AES_256);
    }
    
    // Validate IV length
    if (request.iv.length !== KEY_SIZES.IV) {
      throw new DecryptionError(
        `Invalid IV length: expected ${KEY_SIZES.IV}, got ${request.iv.length}`
      );
    }
    
    // Validate tag length
    if (request.tag.length !== KEY_SIZES.AUTH_TAG) {
      throw new DecryptionError(
        `Invalid tag length: expected ${KEY_SIZES.AUTH_TAG}, got ${request.tag.length}`
      );
    }
    
    // Import key (create proper ArrayBuffer copy)
    const keyBuffer = request.key.buffer.slice(
      request.key.byteOffset,
      request.key.byteOffset + request.key.byteLength
    ) as ArrayBuffer;
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: AES_GCM_CONFIG.name },
      false,
      ['decrypt']
    );
    
    // Combine ciphertext and tag for Web Crypto API
    const combined = new Uint8Array(request.ciphertext.length + request.tag.length);
    combined.set(request.ciphertext);
    combined.set(request.tag, request.ciphertext.length);
    
    // Decrypt (create proper ArrayBuffer copies)
    const ivBuffer = request.iv.buffer.slice(
      request.iv.byteOffset,
      request.iv.byteOffset + request.iv.byteLength
    ) as ArrayBuffer;
    const combinedBuffer = combined.buffer.slice(
      combined.byteOffset,
      combined.byteOffset + combined.byteLength
    ) as ArrayBuffer;
    const plaintext = await crypto.subtle.decrypt(
      {
        name: AES_GCM_CONFIG.name,
        iv: ivBuffer,
        tagLength: AES_GCM_CONFIG.tagLength,
        ...(request.aad && { additionalData: request.aad }),
      },
      cryptoKey,
      combinedBuffer
    );
    
    return {
      plaintext: new Uint8Array(plaintext),
    };
  } catch (error) {
    // Web Crypto API throws a generic error for authentication failures
    // We need to detect this and throw our custom AuthenticationError
    if (error instanceof Error && error.name === 'OperationError') {
      throw new DecryptionError('Authentication tag verification failed');
    }
    throw wrapError(error, 'AES-GCM decryption failed');
  }
}

// ============================================================================
// HKDF (HMAC-based Key Derivation Function)
// ============================================================================

/**
 * Derives a key using HKDF-SHA256
 * 
 * Used for deriving session keys from OPAQUE export keys.
 */
export async function deriveKeyHKDF(
  inputKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  ensureWebCrypto();
  
  try {
    // Import the input key (create proper ArrayBuffer copy)
    const keyBuffer = inputKey.buffer.slice(
      inputKey.byteOffset,
      inputKey.byteOffset + inputKey.byteLength
    ) as ArrayBuffer;
    const baseKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );
    
    // Derive bits using HKDF (create proper ArrayBuffer copies)
    const saltBuffer = salt.buffer.slice(
      salt.byteOffset,
      salt.byteOffset + salt.byteLength
    ) as ArrayBuffer;
    const infoBuffer = info.buffer.slice(
      info.byteOffset,
      info.byteOffset + info.byteLength
    ) as ArrayBuffer;
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuffer,
        info: infoBuffer,
      },
      baseKey,
      length * 8 // Convert bytes to bits
    );
    
    return new Uint8Array(derivedBits);
  } catch (error) {
    throw new WebCryptoError('HKDF', error as Error);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Securely compares two byte arrays in constant time
 * 
 * This prevents timing attacks when comparing secrets.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
}

/**
 * Securely wipes a Uint8Array by overwriting with zeros
 */
export function secureWipe(data: Uint8Array): void {
  crypto.getRandomValues(data);
  data.fill(0);
}

/**
 * Concatenates multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  
  return result;
}

/**
 * Converts a Uint8Array to a base64 string
 */
export function toBase64(data: Uint8Array): string {
  // Use btoa with binary string conversion
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/**
 * Converts a base64 string to a Uint8Array
 */
export function fromBase64(base64: string): Uint8Array {
  // Use atob to decode base64
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts a Uint8Array to a hex string
 */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a hex string to a Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Wraps a promise with a timeout
 */
async function withTimeout<T>(
  promise: () => Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  let timeoutId: number;
  
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = window.setTimeout(() => {
      reject(new KeyDerivationTimeoutError(timeoutMs));
    }, timeoutMs);
  });
  
  try {
    const result = await Promise.race([promise(), timeoutPromise]);
    clearTimeout(timeoutId!);
    return result;
  } catch (error) {
    clearTimeout(timeoutId!);
    throw error;
  }
}

// ============================================================================
// Exports
// ============================================================================

export const primitives = {
  // Random generation
  randomBytes,
  generateIV,
  generateSalt,
  
  // Hashing
  hash256,
  hash512,
  hashString,
  
  // Key derivation
  deriveKeyArgon2id,
  deriveKeyHKDF,
  
  // Encryption/Decryption
  encryptAESGCM,
  decryptAESGCM,
  
  // Utilities
  constantTimeEqual,
  secureWipe,
  concatBytes,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  
  // Availability check
  isWebCryptoAvailable,
};
