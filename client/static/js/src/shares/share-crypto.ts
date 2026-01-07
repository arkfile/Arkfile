/**
 * Share Cryptography Module
 * 
 * Handles encryption and decryption of File Encryption Keys (FEKs) for anonymous file sharing.
 * Uses Argon2id key derivation with random salts for share password protection.
 * 
 * Architecture:
 * 1. Files are encrypted with user's account/custom password (generates FEK)
 * 2. To share: FEK is re-encrypted with Argon2id-derived key from share password + random salt
 * 3. Share recipient: Derives key from share password + salt, decrypts FEK, then decrypts file
 */

import {
  deriveKeyArgon2id,
  encryptAESGCM,
  decryptAESGCM,
  generateSalt,
  randomBytes,
  toBase64,
  fromBase64,
  secureWipe,
} from '../crypto/primitives.js';
import {
  KEY_SIZES,
  getArgon2Params,
} from '../crypto/constants.js';
import {
  EncryptionError,
  DecryptionError,
  wrapError,
} from '../crypto/errors.js';
import { validateSharePassword, type PasswordValidationResult } from '../crypto/password-validation.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Share encryption metadata
 * Contains the encrypted FEK and the salt used for Argon2id derivation
 */
export interface ShareEncryptionMetadata {
  encryptedFEK: string; // Base64-encoded encrypted FEK
  salt: string;         // Base64-encoded random salt (32 bytes)
  nonce: string;        // Base64-encoded nonce (12 bytes) - included in encryptedFEK by primitives
}

/**
 * Share password validation result
 */
export interface SharePasswordValidation {
  valid: boolean;
  result: PasswordValidationResult;
}

// ============================================================================
// Share Password Validation
// ============================================================================

/**
 * Validates a share password meets security requirements
 * 
 * Share passwords should be strong since they protect file access.
 * 
 * @param password - The share password to validate
 * @param userInputs - Optional array of user-specific strings to check against
 * @returns Validation result with feedback
 */
export async function validateSharePasswordStrength(
  password: string,
  userInputs?: string[]
): Promise<SharePasswordValidation> {
  const result = await validateSharePassword(password, userInputs);
  
  return {
    valid: result.meets_requirements && result.strength_score >= 3,
    result,
  };
}

// ============================================================================
// FEK Encryption for Shares
// ============================================================================

/**
 * Encrypts a File Encryption Key (FEK) for sharing
 * 
 * This function:
 * 1. Generates a cryptographically secure random salt
 * 2. Derives an encryption key from the share password using Argon2id
 * 3. Encrypts the FEK with AES-256-GCM
 * 4. Returns the encrypted FEK and salt for storage
 * 
 * The salt must be stored alongside the encrypted FEK so that share recipients
 * can derive the same key to decrypt the FEK.
 * 
 * @param fek - The File Encryption Key to encrypt (32 bytes)
 * @param sharePassword - The password to protect the share
 * @returns Encryption metadata (encrypted FEK + salt)
 */
export async function encryptFEKForShare(
  fek: Uint8Array,
  sharePassword: string,
  shareId: string
): Promise<ShareEncryptionMetadata> {
  if (fek.length !== KEY_SIZES.FILE_ENCRYPTION_KEY) {
    throw new EncryptionError(
      `Invalid FEK size: expected ${KEY_SIZES.FILE_ENCRYPTION_KEY} bytes, got ${fek.length}`
    );
  }
  
  if (!sharePassword || sharePassword.length === 0) {
    throw new EncryptionError('Share password cannot be empty');
  }

  if (!shareId || shareId.length === 0) {
    throw new EncryptionError('Share ID cannot be empty');
  }
  
  try {
    // Generate a cryptographically secure random salt
    const salt = generateSalt();
    
    // Get Argon2id parameters from config
    const argon2Params = await getArgon2Params();
    
    // Derive encryption key from share password using Argon2id
    const keyDerivation = await deriveKeyArgon2id({
      password: sharePassword,
      salt,
      params: argon2Params, // Use same params as file encryption
    });
    
    // Prepare AAD (Share ID)
    const aad = new TextEncoder().encode(shareId);

    // Encrypt the FEK
    const encryptionResult = await encryptAESGCM({
      data: fek,
      key: keyDerivation.key,
      aad: aad,
    });
    
    // Clean up sensitive data
    secureWipe(keyDerivation.key);
    
    // The encryptionResult contains: ciphertext, iv (nonce), and tag
    // We need to combine them for storage: [nonce][ciphertext][tag]
    const combined = new Uint8Array(
      encryptionResult.iv.length + 
      encryptionResult.ciphertext.length + 
      encryptionResult.tag.length
    );
    combined.set(encryptionResult.iv, 0);
    combined.set(encryptionResult.ciphertext, encryptionResult.iv.length);
    combined.set(encryptionResult.tag, encryptionResult.iv.length + encryptionResult.ciphertext.length);
    
    return {
      encryptedFEK: toBase64(combined),
      salt: toBase64(salt),
      nonce: toBase64(encryptionResult.iv), // Also return nonce separately for compatibility
    };
  } catch (error) {
    throw wrapError(error, 'Failed to encrypt FEK for share');
  }
}

// ============================================================================
// FEK Decryption from Shares
// ============================================================================

/**
 * Decrypts a File Encryption Key (FEK) from a share
 * 
 * This function:
 * 1. Derives the decryption key from the share password and stored salt
 * 2. Decrypts the FEK using AES-256-GCM
 * 3. Returns the decrypted FEK for file decryption
 * 
 * @param metadata - Share encryption metadata (encrypted FEK + salt)
 * @param sharePassword - The share password
 * @returns The decrypted FEK (32 bytes)
 * @throws DecryptionError if password is incorrect or data is corrupted
 */
export async function decryptFEKFromShare(
  metadata: ShareEncryptionMetadata,
  sharePassword: string,
  shareId: string
): Promise<Uint8Array> {
  if (!sharePassword || sharePassword.length === 0) {
    throw new DecryptionError('Share password cannot be empty');
  }

  if (!shareId || shareId.length === 0) {
    throw new DecryptionError('Share ID cannot be empty');
  }
  
  try {
    // Decode the salt and encrypted FEK
    const salt = fromBase64(metadata.salt);
    const encryptedData = fromBase64(metadata.encryptedFEK);
    
    // Validate salt size
    if (salt.length !== KEY_SIZES.SALT) {
      throw new DecryptionError(
        `Invalid salt size: expected ${KEY_SIZES.SALT} bytes, got ${salt.length}`
      );
    }
    
    // The encrypted data format is: [nonce (12)][ciphertext][tag (16)]
    if (encryptedData.length < 12 + 16) {
      throw new DecryptionError('Encrypted FEK data is too short');
    }
    
    // Extract components
    const nonce = encryptedData.slice(0, 12);
    const ciphertextAndTag = encryptedData.slice(12);
    const ciphertext = ciphertextAndTag.slice(0, -16);
    const tag = ciphertextAndTag.slice(-16);
    
    // Get Argon2id parameters from config
    const argon2Params = await getArgon2Params();
    
    // Derive decryption key from share password using Argon2id
    const keyDerivation = await deriveKeyArgon2id({
      password: sharePassword,
      salt,
      params: argon2Params,
    });
    
    // Prepare AAD (Share ID)
    const aad = new TextEncoder().encode(shareId);

    // Decrypt the FEK
    const decryptionResult = await decryptAESGCM({
      ciphertext,
      key: keyDerivation.key,
      iv: nonce,
      tag,
      aad: aad,
    });
    
    // Clean up sensitive data
    secureWipe(keyDerivation.key);
    
    // Validate FEK size
    if (decryptionResult.plaintext.length !== KEY_SIZES.FILE_ENCRYPTION_KEY) {
      throw new DecryptionError(
        `Invalid decrypted FEK size: expected ${KEY_SIZES.FILE_ENCRYPTION_KEY} bytes, got ${decryptionResult.plaintext.length}`
      );
    }
    
    return decryptionResult.plaintext;
  } catch (error) {
    if (error instanceof DecryptionError) {
      throw error;
    }
    // Wrap other errors (likely authentication failures from AES-GCM)
    throw new DecryptionError('Failed to decrypt FEK - incorrect password or corrupted data');
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generates a random File Encryption Key (FEK)
 * 
 * @returns A 32-byte FEK
 */
export function generateFEK(): Uint8Array {
  return randomBytes(KEY_SIZES.FILE_ENCRYPTION_KEY);
}

/**
 * Encodes a FEK to base64 for transmission
 */
export function encodeFEK(fek: Uint8Array): string {
  return toBase64(fek);
}

/**
 * Decodes a FEK from base64
 */
export function decodeFEK(fekBase64: string): Uint8Array {
  return fromBase64(fekBase64);
}

// ============================================================================
// Exports
// ============================================================================

export const shareCrypto = {
  // Password validation
  validateSharePasswordStrength,
  
  // FEK encryption/decryption
  encryptFEKForShare,
  decryptFEKFromShare,
  
  // Utility functions
  generateFEK,
  encodeFEK,
  decodeFEK,

  // Additional helpers for share access
  deriveKey,
  decryptMetadata,
  decryptData,
};

/**
 * Derives a key from a password and salt using Argon2id
 */
export async function deriveKey(password: string, saltBase64: string): Promise<Uint8Array> {
  const salt = fromBase64(saltBase64);
  const argon2Params = await getArgon2Params();
  const result = await deriveKeyArgon2id({
    password,
    salt,
    params: argon2Params,
  });
  return result.key;
}

/**
 * Decrypts metadata (like filename) using the FEK
 */
export async function decryptMetadata(
  encryptedBase64: string,
  nonceBase64: string,
  fek: Uint8Array
): Promise<string> {
  const ciphertext = fromBase64(encryptedBase64);
  const nonce = fromBase64(nonceBase64);
  
  // The ciphertext likely includes the tag at the end?
  // In Go's GCM, Seal appends the tag.
  // So we need to split it if our decryptAESGCM expects separate tag.
  // Let's check decryptAESGCM signature in primitives.js (implied by usage above)
  
  // Usage in decryptFEKFromShare:
  // const ciphertext = ciphertextAndTag.slice(0, -16);
  // const tag = ciphertextAndTag.slice(-16);
  // decryptAESGCM({ ciphertext, key, iv, tag })
  
  // So we need to split the tag here too.
  const tag = ciphertext.slice(-16);
  const actualCiphertext = ciphertext.slice(0, -16);
  
  const result = await decryptAESGCM({
    ciphertext: actualCiphertext,
    key: fek,
    iv: nonce,
    tag,
  });
  
  return new TextDecoder().decode(result.plaintext);
}

/**
 * Decrypts file data using the FEK
 */
export async function decryptData(
  encryptedBase64: string,
  fek: Uint8Array
): Promise<Uint8Array> {
  // The encrypted data from DownloadSharedFile is base64 encoded.
  // It was encrypted using storage.PutObject which uses crypto.EncryptFile?
  // No, `handlers/file_shares.go` says:
  // "Return encrypted file data and encrypted metadata for client-side decryption"
  // It reads the object directly from storage.
  // The object in storage was encrypted using `crypto.EncryptFile` (presumably).
  // `crypto.EncryptFile` uses `gcm.Seal(nonce, nonce, data, nil)`.
  // So the data in storage is [nonce][ciphertext+tag].
  
  const encryptedData = fromBase64(encryptedBase64);
  
  // Extract nonce (standard nonce size is 12 bytes for GCM)
  const nonce = encryptedData.slice(0, 12);
  const ciphertextAndTag = encryptedData.slice(12);
  const ciphertext = ciphertextAndTag.slice(0, -16);
  const tag = ciphertextAndTag.slice(-16);
  
  const result = await decryptAESGCM({
    ciphertext,
    key: fek,
    iv: nonce,
    tag,
  });
  
  return result.plaintext;
}
