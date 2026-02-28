/**
 * File download functionality with chunked download support
 * 
 * This module provides file download capabilities using the chunked download
 * infrastructure for efficient, resumable downloads with client-side decryption.
 * 
 * SECURITY: All FEK decryption happens client-side using Argon2id-derived keys.
 * The server NEVER sees the plaintext FEK or the user's password.
 */

import { authenticatedFetch, getToken, getUsernameFromToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { 
  downloadFileChunked, 
  triggerBrowserDownload,
  StreamingDownloadResult 
} from './streaming-download';
import { 
  getCachedAccountKey,
  isAccountKeyLocked,
  deriveFileEncryptionKeyWithCache,
  type CacheDurationHours,
} from '../crypto/file-encryption';
import { promptForAccountKeyPassword } from '../ui/password-modal';
import { decryptChunk } from '../crypto/aes-gcm';

/**
 * File metadata response from the server
 */
interface FileMetaResponse {
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  password_hint: string;
  password_type: string;
  size_bytes: number;
  chunk_size: number;
  total_chunks: number;
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Get the Account Key for decrypting the FEK
 * 
 * This function:
 * 1. Checks if the Account Key is cached and not locked
 * 2. If not cached or locked, prompts the user for their password
 * 3. Derives the Account Key using Argon2id
 * 4. Optionally caches the key based on user preference
 * 
 * @param username - The user's username
 * @returns The Account Key, or null if the user cancelled
 */
async function getAccountKey(username: string): Promise<Uint8Array | null> {
  // Check if Account Key is locked (user manually locked it)
  if (isAccountKeyLocked()) {
    showError('Account Key is locked. Please unlock it first.');
    return null;
  }

  // Try to get cached Account Key
  const cachedKey = await getCachedAccountKey(username, getToken() ?? undefined);
  if (cachedKey) {
    return cachedKey;
  }
  
  // No cached key - prompt for password
  const result = await promptForAccountKeyPassword();
  if (!result) {
    // User cancelled
    return null;
  }
  
  try {
    // Derive Account Key using Argon2id with caching
    const accountKey = await deriveFileEncryptionKeyWithCache(
      result.password,
      username,
      'account',
      getToken() ?? undefined,
      result.cacheDuration as CacheDurationHours | undefined
    );
    
    return accountKey;
  } catch (error) {
    console.error('Failed to derive Account Key:', error);
    showError('Failed to derive encryption key. Please check your password.');
    return null;
  }
}

/**
 * Decrypt the FEK using the Account Key
 * 
 * The encrypted FEK format is: [version (1 byte)][keyType (1 byte)][nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
 * The 2-byte envelope header must be stripped before AES-GCM decryption.
 * 
 * Envelope format (from crypto/file_operations.go):
 *   version = 0x01 (Unified FEK-based encryption)
 *   keyType = 0x01 (account) or 0x02 (custom)
 * 
 * @param encryptedFekBase64 - Base64-encoded encrypted FEK (with envelope header)
 * @param accountKey - The Account Key (32 bytes)
 * @returns The decrypted FEK (32 bytes)
 */
async function decryptFEK(encryptedFekBase64: string, accountKey: Uint8Array): Promise<Uint8Array> {
  const encryptedFek = base64ToBytes(encryptedFekBase64);
  
  // Validate minimum length: 2 (envelope) + 12 (nonce) + 16 (tag) + 1 (min ciphertext) = 31
  if (encryptedFek.length < 31) {
    throw new Error(`Encrypted FEK too short: expected at least 31 bytes, got ${encryptedFek.length}`);
  }
  
  // Validate envelope header
  const version = encryptedFek[0];
  const keyType = encryptedFek[1];
  
  if (version !== 0x01) {
    throw new Error(`Unsupported envelope version: 0x${version.toString(16).padStart(2, '0')} (expected 0x01)`);
  }
  
  if (keyType !== 0x01 && keyType !== 0x02) {
    console.warn(`Unknown key type in FEK envelope: 0x${keyType.toString(16).padStart(2, '0')}`);
  }
  
  // Strip the 2-byte envelope header, then decrypt
  // Remaining format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
  const fekCiphertext = encryptedFek.slice(2);
  const fek = await decryptChunk(fekCiphertext, accountKey);
  
  if (fek.length !== 32) {
    throw new Error(`Invalid FEK length: expected 32 bytes, got ${fek.length}`);
  }
  
  return fek;
}

/**
 * Download a file using chunked download with client-side decryption
 * 
 * This function:
 * 1. Fetches file metadata including the encrypted FEK
 * 2. Gets the Account Key (from cache or by prompting for password)
 * 3. Decrypts the FEK client-side
 * 4. Uses the FEK to download and decrypt the file chunks
 * 
 * @param fileId - The file ID to download
 * @param hint - Optional password hint to display (unused for account-encrypted files)
 * @param expectedHash - Expected SHA256 hash for verification (encrypted, will be decrypted)
 * @param passwordType - 'account' or 'custom' indicating encryption type
 */
export async function downloadFile(
  fileId: string, 
  hint: string, 
  expectedHash: string, 
  passwordType: string
): Promise<void> {
  try {
    // Get auth token for authenticated requests
    const authToken = getToken();
    if (!authToken) {
      showError('Not authenticated. Please log in again.');
      return;
    }
    
    // Get username for key derivation
    const username = getUsernameFromToken();
    if (!username) {
      showError('Username not found. Please log in again.');
      return;
    }

    // Fetch file metadata including encrypted FEK
    const metaResponse = await authenticatedFetch(`/api/files/${fileId}/meta`);
    if (!metaResponse.ok) {
      const errorData = await metaResponse.json().catch(() => ({}));
      showError(errorData.message || 'Failed to retrieve file metadata.');
      return;
    }
    
    const meta: FileMetaResponse = await metaResponse.json();
    
    let fek: Uint8Array;
    let metadataDecryptionKey: Uint8Array; // Account key — always needed for metadata decryption

    if (passwordType === 'account' || meta.password_type === 'account') {
      // For account-encrypted files:
      // 1. Get Account Key (from cache or prompt for password)
      // 2. Decrypt FEK client-side
      
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        // User cancelled password prompt
        return;
      }
      
      metadataDecryptionKey = accountKey;
      
      try {
        fek = await decryptFEK(meta.encrypted_fek, accountKey);
      } catch (error) {
        console.error('Failed to decrypt FEK:', error);
        showError('Failed to decrypt file key. Your password may be incorrect.');
        return;
      }
      
    } else {
      // For custom password-encrypted files:
      // We need BOTH the account key (for metadata) AND the custom key (for FEK)
      
      // First, get the account key for metadata decryption
      const accountKey = await getAccountKey(username);
      if (!accountKey) {
        return;
      }
      metadataDecryptionKey = accountKey;
      
      // Show hint if provided
      if (hint || meta.password_hint) {
        alert(`Password Hint: ${hint || meta.password_hint}`);
      }
      
      // Prompt for custom password
      const password = prompt('Enter the file password:');
      if (!password) return;

      try {
        // Derive custom key using Argon2id with 'custom' context
        const { deriveFileEncryptionKey } = await import('../crypto/file-encryption');
        const customKey = await deriveFileEncryptionKey(password, username, 'custom');
        
        // Decrypt FEK with custom key
        fek = await decryptFEK(meta.encrypted_fek, customKey);
      } catch (error) {
        console.error('Failed to decrypt FEK with custom password:', error);
        showError('Failed to decrypt file key. Check your password.');
        return;
      }
    }

    // Use chunked download with the decrypted FEK
    // Pass account key for metadata decryption (filename, sha256sum are encrypted with account key)
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      authToken,
      {
        accountKey: metadataDecryptionKey,
        showProgressUI: true,
        onProgress: (progress) => {
          // Progress is handled by the built-in UI
          if (progress.stage === 'error') {
            console.error('Download error:', progress.error);
          }
        },
      }
    );

    if (!result.success) {
      showError(result.error || 'Download failed.');
      return;
    }

    if (!result.data || !result.filename) {
      showError('Download completed but data is missing.');
      return;
    }

    // Verify SHA256 hash if we have the expected hash
    if (result.sha256sum && expectedHash) {
      // Note: expectedHash from the file list is already decrypted by the list endpoint
      // result.sha256sum is decrypted by the download manager
      if (result.sha256sum !== expectedHash) {
        console.warn('SHA256 hash mismatch - file may be corrupted');
        // Don't block download, just warn
      }
    }

    // Trigger browser download
    triggerBrowserDownload(result.data, result.filename);
    showSuccess(`Downloaded: ${result.filename}`);

  } catch (error) {
    console.error('Download error:', error);
    showError('An error occurred during file download.');
  }
}

