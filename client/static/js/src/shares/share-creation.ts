/**
 * Share Creation Module
 * 
 * Handles the creation of file shares with password-based encryption.
 * This module integrates with the share-crypto module for encryption
 * and the password validation system for security.
 */

import { shareCrypto } from '../crypto/share-crypto.js';
import { validateSharePassword, type PasswordValidationResult } from '../crypto/password-validation.js';
import { authenticatedFetch } from '../utils/auth.js';

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
   * Creates a share for the file
   * 
   * This performs the following steps:
   * 1. Validates the share password
   * 2. Re-encrypts the FEK with the share password
   * 3. Sends the encrypted share data to the server
   * 4. Returns the share URL
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

      // Encrypt the FEK with the share password
      // The FEK should already be decrypted (raw 32 bytes) when passed to ShareCreator
      const shareEncryptionResult = await shareCrypto.encryptFEKForShare(
        this.fileInfo.fek,
        request.sharePassword
      );

      // Send share creation request to server
      const response = await authenticatedFetch('/api/shares', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          file_id: request.fileId,
          encrypted_fek: shareEncryptionResult.encryptedFEK,
          salt: shareEncryptionResult.salt,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: errorData.error || `Server error: ${response.status}`
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
