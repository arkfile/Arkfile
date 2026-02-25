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
 * Share Envelope JSON structure (matches Go's crypto.ShareEnvelope)
 * 
 * This JSON payload is encrypted with AES-GCM-AAD before storage.
 * The share recipient decrypts it to get the FEK, download token, and file metadata.
 */
interface ShareEnvelopeJSON {
  fek: string;            // base64-encoded FEK
  download_token: string; // base64-encoded Download Token
  filename?: string;      // plaintext filename (for preview before download)
  size_bytes?: number;    // file size in bytes (for preview before download)
  sha256?: string;        // plaintext SHA256 hex digest (for post-download verification)
}

/**
 * File metadata to include in the share envelope
 */
export interface ShareFileMetadata {
  filename: string;
  sizeBytes: number;
  sha256: string;
}

/**
 * Encrypts a File Encryption Key (FEK), Download Token, and file metadata for sharing
 * 
 * This function:
 * 1. Generates a cryptographically secure random salt
 * 2. Generates a random Download Token (32 bytes)
 * 3. Derives an encryption key from the share password using Argon2id
 * 4. Creates a JSON envelope with FEK, Download Token, and file metadata
 * 5. Encrypts the JSON envelope with AES-256-GCM with AAD binding
 * 6. Returns the encrypted envelope and salt for storage
 * 
 * The JSON envelope format matches Go's crypto.ShareEnvelope for cross-platform compatibility:
 *   {"fek":"base64...","download_token":"base64...","filename":"...","size_bytes":N,"sha256":"..."}
 * 
 * AAD binding: share_id + file_id prevents envelope swapping attacks
 * 
 * @param fek - The File Encryption Key to encrypt (32 bytes)
 * @param sharePassword - The password to protect the share
 * @param shareId - The Share ID (used as AAD)
 * @param fileId - The File ID (used as AAD binding)
 * @param metadata - File metadata to include in the envelope (filename, size, sha256)
 * @returns Encryption metadata (encrypted envelope + salt + download token hash)
 */
export async function encryptFEKForShare(
  fek: Uint8Array,
  sharePassword: string,
  shareId: string,
  fileId: string,
  metadata?: ShareFileMetadata
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
    
    // Build JSON envelope matching Go's crypto.ShareEnvelope format
    const envelopeJSON: ShareEnvelopeJSON = {
      fek: toBase64(fek),
      download_token: toBase64(downloadToken),
    };
    
    // Include file metadata if provided
    if (metadata) {
      envelopeJSON.filename = metadata.filename;
      envelopeJSON.size_bytes = metadata.sizeBytes;
      envelopeJSON.sha256 = metadata.sha256;
    }
    
    // Serialize to JSON bytes (matches Go's json.Marshal)
    const payload = new TextEncoder().encode(JSON.stringify(envelopeJSON));
    
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

    // Encrypt the JSON envelope with AAD binding
    const encryptionResult = await encryptAESGCM({
      data: payload,
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
 * Result of decrypting a share envelope
 * Includes FEK, download token, and optional file metadata
 */
export interface DecryptedShareEnvelope {
  fek: Uint8Array;
  downloadToken: string;
  /** File metadata from the envelope (available if included during share creation) */
  metadata?: {
    filename?: string;
    sizeBytes?: number;
    sha256?: string;
  };
}

/**
 * Decrypts a Share Envelope to extract FEK, Download Token, and file metadata
 * 
 * The Share Envelope is a JSON payload encrypted with AES-GCM-AAD:
 *   {"fek":"base64...","download_token":"base64...","filename":"...","size_bytes":N,"sha256":"..."}
 * 
 * This format matches Go's crypto.ShareEnvelope for cross-platform compatibility.
 * 
 * @param encryptedEnvelopeBase64 - The encrypted envelope (base64)
 * @param sharePassword - The share password
 * @param shareId - The share ID (used as AAD)
 * @param fileId - The file ID (used as AAD binding)
 * @param saltBase64 - The salt used for key derivation (base64)
 * @returns Object containing the FEK, Download Token, and optional file metadata
 * @throws DecryptionError if password is incorrect or data is corrupted
 */
export async function decryptShareEnvelope(
  encryptedEnvelopeBase64: string,
  sharePassword: string,
  shareId: string,
  fileId: string,
  saltBase64?: string
): Promise<DecryptedShareEnvelope> {
  if (!sharePassword || sharePassword.length === 0) {
    throw new DecryptionError('Share password cannot be empty');
  }

  if (!shareId || shareId.length === 0) {
    throw new DecryptionError('Share ID cannot be empty');
  }
  
  try {
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
    
    // Parse the JSON envelope (matches Go's crypto.ShareEnvelope)
    const plaintext = decryptionResult.plaintext;
    const envelopeText = new TextDecoder().decode(plaintext);
    
    let envelope: ShareEnvelopeJSON;
    try {
      envelope = JSON.parse(envelopeText) as ShareEnvelopeJSON;
    } catch {
      throw new DecryptionError('Invalid share envelope format: not valid JSON');
    }
    
    // Validate required fields
    if (!envelope.fek || !envelope.download_token) {
      throw new DecryptionError('Invalid share envelope: missing fek or download_token');
    }
    
    // Decode FEK from base64
    const fek = fromBase64(envelope.fek);
    if (fek.length !== KEY_SIZES.FILE_ENCRYPTION_KEY) {
      throw new DecryptionError(
        `Invalid FEK size in envelope: expected ${KEY_SIZES.FILE_ENCRYPTION_KEY} bytes, got ${fek.length}`
      );
    }
    
    // Build result with optional metadata
    const result: DecryptedShareEnvelope = {
      fek,
      downloadToken: envelope.download_token,
    };
    
    // Include metadata if present in the envelope
    if (envelope.filename || envelope.size_bytes || envelope.sha256) {
      result.metadata = {};
      if (envelope.filename) result.metadata.filename = envelope.filename;
      if (envelope.size_bytes) result.metadata.sizeBytes = envelope.size_bytes;
      if (envelope.sha256) result.metadata.sha256 = envelope.sha256;
    }
    
    return result;
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
};
