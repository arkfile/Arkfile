/**
 * Share Creation Module
 * 
 * Handles the creation of file shares with password-based encryption.
 * This module integrates with the share-crypto module for encryption
 * and the password validation system for security.
 */

import { shareCrypto } from './share-crypto.js';
import { validateSharePassword, type PasswordValidationResult } from '../crypto/password-validation.js';
import { authenticatedFetch } from '../utils/auth.js';
import { randomBytes, toBase64 } from '../crypto/primitives.js';

// ============================================================================
// Types
// ============================================================================

/**
 * File information needed for share creation
 */
export interface FileInfo {
  filename: string;
  fek: Uint8Array; // Raw FEK bytes (32 bytes)
}

/**
 * Share creation request
 */
export interface ShareCreationRequest {
  fileId: string;
  sharePassword: string;
  expiresAfterHours?: number;
}

/**
 * Share creation result
 */
export interface ShareCreationResult {
  success: boolean;
  shareUrl?: string;
  error?: string;
}

/**
 * API response from share creation endpoint
 */
interface ShareCreationAPIResponse {
  share_id: string;
  share_url: string;
}

// ============================================================================
// ShareCreator Class
// ============================================================================

/**
 * Handles share creation workflow including validation and encryption
 */
export class ShareCreator {
  private fileInfo: FileInfo;

  constructor(fileInfo: FileInfo) {
    this.fileInfo = fileInfo;
  }

  /**
   * Validates a share password
   * 
   * @param password - The password to validate
   * @returns Validation result with strength score and feedback
   */
  async validatePassword(password: string): Promise<PasswordValidationResult> {
    return await validateSharePassword(password);
  }

  /**
   * Generates a secure random Share ID
   */
  private generateShareID(): string {
    // Generate 32 bytes of random data
    const bytes = randomBytes(32);
    // Convert to URL-safe Base64 (replace + with -, / with _, remove =)
    return toBase64(bytes)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Creates a share for the file
   * 
   * This performs the following steps:
   * 1. Validates the share password
   * 2. Re-encrypts the FEK with the share password
   * 3. Generates a Share ID
   * 4. Sends the encrypted share data to the server
   * 5. Returns the share URL
   * 
   * @param request - Share creation request
   * @returns Share creation result with URL or error
   */
  async createShare(request: ShareCreationRequest): Promise<ShareCreationResult> {
    try {
      // Validate password
      const validation = await this.validatePassword(request.sharePassword);
      if (!validation.meets_requirements) {
        return {
          success: false,
          error: 'Password does not meet requirements: ' + validation.feedback.join('. ')
        };
      }

      // Generate Share ID
      const shareId = this.generateShareID();

      // Encrypt the FEK with the share password
      // The FEK should already be decrypted (raw 32 bytes) when passed to ShareCreator
      const shareEncryptionResult = await shareCrypto.encryptFEKForShare(
        this.fileInfo.fek,
        request.sharePassword,
        shareId
      );

      // Generate a dummy download token hash for now (backend requires it)
      // In a full implementation, this would be part of a download token system
      const downloadTokenHash = toBase64(randomBytes(32));

      // Send share creation request to server
      const response = await authenticatedFetch(`/api/files/${request.fileId}/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          share_id: shareId,
          file_id: request.fileId,
          encrypted_fek: shareEncryptionResult.encryptedFEK,
          salt: shareEncryptionResult.salt,
          download_token_hash: downloadTokenHash,
          expires_after_hours: request.expiresAfterHours || 0
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: errorData.error || errorData.message || `Server error: ${response.status}`
        };
      }

      const data: ShareCreationAPIResponse = await response.json();

      return {
        success: true,
        shareUrl: data.share_url
      };

    } catch (error) {
      console.error('Share creation error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }
}

// ============================================================================
// Exports
// ============================================================================

export { shareCrypto as ShareCrypto };
