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
  hash256,
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
 * Encrypts a File Encryption Key (FEK) and Download Token for sharing
 * 
 * This function:
 * 1. Generates a cryptographically secure random salt
 * 2. Generates a random Download Token (32 bytes)
 * 3. Derives an encryption key from the share password using Argon2id
 * 4. Encrypts [FEK + Download Token] with AES-256-GCM with AAD binding
 * 5. Returns the encrypted envelope and salt for storage
 * 
 * The encrypted payload format is: [FEK (32 bytes)][Download Token (32 bytes)]
 * AAD binding: share_id + file_id prevents envelope swapping attacks
 * 
 * @param fek - The File Encryption Key to encrypt (32 bytes)
 * @param sharePassword - The password to protect the share
 * @param shareId - The Share ID (used as AAD)
 * @param fileId - The File ID (used as AAD binding)
 * @returns Encryption metadata (encrypted envelope + salt + download token hash)
 */
export async function encryptFEKForShare(
  fek: Uint8Array,
  sharePassword: string,
  shareId: string,
  fileId: string
): Promise<ShareEncryptionMetadata & { downloadToken: string; downloadTokenHash: string }> {
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
    
    // Generate a random Download Token (32 bytes)
    const downloadToken = randomBytes(32);
    
    // Combine FEK and Download Token into a single payload
    const payload = new Uint8Array(64); // 32 + 32
    payload.set(fek, 0);
    payload.set(downloadToken, 32);
    
    // Get Argon2id parameters from config
    const argon2Params = await getArgon2Params();
    
    // Derive encryption key from share password using Argon2id
    const keyDerivation = await deriveKeyArgon2id({
      password: sharePassword,
      salt,
      params: argon2Params,
    });
    
    // Prepare AAD (Share ID + File ID for binding)
    const aad = new TextEncoder().encode(shareId + fileId);

    // Encrypt the payload (FEK + Download Token) with AAD binding
    const encryptionResult = await encryptAESGCM({
      data: payload,
      key: keyDerivation.key,
      aad: aad,
    });
    
    // Clean up sensitive data
    secureWipe(keyDerivation.key);
    secureWipe(payload);
    
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
    
    // Hash the Download Token for server storage (SHA-256)
    const downloadTokenHash = hash256(downloadToken);
    
    return {
      encryptedFEK: toBase64(combined),
      salt: toBase64(salt),
      nonce: toBase64(encryptionResult.iv),
      downloadToken: toBase64(downloadToken),
      downloadTokenHash: toBase64(downloadTokenHash),
    };
  } catch (error) {
    throw wrapError(error, 'Failed to encrypt FEK for share');
  }
}

// ============================================================================
// FEK Decryption from Shares
// ============================================================================

/**
 * Decrypts a Share Envelope to extract FEK and Download Token
 * 
 * The Share Envelope contains the encrypted FEK. The encrypted payload format is:
 * [FEK (32 bytes)][Download Token (32 bytes)]
 * 
 * This function needs both the encrypted envelope and the salt to derive the decryption key.
 * 
 * @param encryptedEnvelopeBase64 - The encrypted envelope (base64) containing FEK + Download Token
 * @param sharePassword - The share password
 * @param shareId - The share ID (used as AAD)
 * @param fileId - The file ID (used as AAD binding)
 * @param saltBase64 - The salt used for key derivation (base64)
 * @returns Object containing the FEK and Download Token
 * @throws DecryptionError if password is incorrect or data is corrupted
 */
export async function decryptShareEnvelope(
  encryptedEnvelopeBase64: string,
  sharePassword: string,
  shareId: string,
  fileId: string,
  saltBase64?: string
): Promise<{ fek: Uint8Array; downloadToken: string }> {
  if (!sharePassword || sharePassword.length === 0) {
    throw new DecryptionError('Share password cannot be empty');
  }

  if (!shareId || shareId.length === 0) {
    throw new DecryptionError('Share ID cannot be empty');
  }
  
  // For now, we'll use the existing decryptFEKFromShare which only returns the FEK
  // The Download Token is not yet implemented in the backend envelope
  // So we'll return a placeholder for now
  
  try {
    // If salt is provided, use it; otherwise extract from envelope
    if (!saltBase64) {
      throw new DecryptionError('Salt is required for envelope decryption');
    }
    
    const salt = fromBase64(saltBase64);
    const encryptedData = fromBase64(encryptedEnvelopeBase64);
    
    // Validate salt size
    if (salt.length !== KEY_SIZES.SALT) {
      throw new DecryptionError(
        `Invalid salt size: expected ${KEY_SIZES.SALT} bytes, got ${salt.length}`
      );
    }
    
    // The encrypted data format is: [nonce (12)][ciphertext][tag (16)]
    if (encryptedData.length < 12 + 16) {
      throw new DecryptionError('Encrypted envelope data is too short');
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
    
    // Prepare AAD (Share ID + File ID for binding)
    const aad = new TextEncoder().encode(shareId + fileId);

    // Decrypt the envelope with AAD verification
    const decryptionResult = await decryptAESGCM({
      ciphertext,
      key: keyDerivation.key,
      iv: nonce,
      tag,
      aad: aad,
    });
    
    // Clean up sensitive data
    secureWipe(keyDerivation.key);
    
    // The plaintext should contain: [FEK (32 bytes)][Download Token (32 bytes)]
    const plaintext = decryptionResult.plaintext;
    
    // Expected size: 32 (FEK) + 32 (Download Token) = 64 bytes
    if (plaintext.length !== 64) {
      throw new DecryptionError(
        `Invalid envelope format: expected 64 bytes (FEK + Download Token), got ${plaintext.length} bytes`
      );
    }
    
    // Extract FEK and Download Token
    const fek = plaintext.slice(0, 32);
    const downloadToken = plaintext.slice(32, 64);
    
    return {
      fek,
      downloadToken: toBase64(downloadToken),
    };
  } catch (error) {
    if (error instanceof DecryptionError) {
      throw error;
    }
    // Wrap other errors (likely authentication failures from AES-GCM)
    throw new DecryptionError('Failed to decrypt share envelope - incorrect password or corrupted data');
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
  decryptShareEnvelope,
  
  // Utility functions
  generateFEK,
  encodeFEK,
  decodeFEK,

  // Additional helpers for share access
  deriveKey,
  decryptMetadata,
  decryptData,
  decryptFileData,
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
 * Decrypts file data using the FEK (from base64)
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

/**
 * Decrypts file data using the FEK (from binary Uint8Array)
 * Used for streaming downloads where data is received as binary
 */
export async function decryptFileData(
  encryptedData: Uint8Array,
  fek: Uint8Array
): Promise<Uint8Array> {
  // The encrypted data format is [nonce][ciphertext+tag]
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
