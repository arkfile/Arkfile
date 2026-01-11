/**
 * File download functionality with chunked download support
 * 
 * This module provides file download capabilities using the chunked download
 * infrastructure for efficient, resumable downloads with client-side decryption.
 */

import { authenticatedFetch, getToken } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import { 
  downloadFileChunked, 
  triggerBrowserDownload,
  StreamingDownloadResult 
} from './streaming-download';

/**
 * Download metadata response from the server
 */
interface FileDownloadMetadata {
  file_id: string;
  encrypted_fek: string;
  fek_nonce: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  size_bytes: number;
  chunk_count: number;
  chunk_size_bytes: number;
  hint?: string;
}

/**
 * Download a file using chunked download with client-side decryption
 * 
 * @param fileId - The file ID to download
 * @param hint - Optional password hint to display
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
    // Show hint if provided
    if (hint) {
      alert(`Password Hint: ${hint}`);
    }

    // Get auth token for authenticated requests
    const authToken = getToken();
    if (!authToken) {
      showError('Not authenticated. Please log in again.');
      return;
    }

    let fek: Uint8Array;

    if (passwordType === 'account') {
      // For account-encrypted files, get the FEK from the server
      // The server decrypts the FEK using the user's account key
      const fekResponse = await authenticatedFetch(`/api/files/${fileId}/key`);
      
      if (!fekResponse.ok) {
        const errorData = await fekResponse.json().catch(() => ({}));
        showError(errorData.message || 'Failed to retrieve file key.');
        return;
      }
      
      const fekData = await fekResponse.json();
      fek = base64ToBytes(fekData.fek);
      
    } else {
      // For custom password-encrypted files, derive FEK from password
      const password = prompt('Enter the file password:');
      if (!password) return;

      // Get the salt and encrypted FEK from the server
      const fekResponse = await authenticatedFetch(`/api/files/${fileId}/key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password }),
      });

      if (!fekResponse.ok) {
        const errorData = await fekResponse.json().catch(() => ({}));
        showError(errorData.message || 'Failed to retrieve file key. Check your password.');
        return;
      }

      const fekData = await fekResponse.json();
      fek = base64ToBytes(fekData.fek);
    }

    // Use chunked download with the FEK
    const result: StreamingDownloadResult = await downloadFileChunked(
      fileId,
      fek,
      authToken,
      {
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

/**
 * Download a file by filename (legacy compatibility)
 * 
 * This function looks up the file ID by filename and then uses chunked download.
 * 
 * @param filename - The filename to download
 * @param hint - Optional password hint
 * @param expectedHash - Expected SHA256 hash
 * @param passwordType - 'account' or 'custom'
 */
export async function downloadFileByName(
  filename: string,
  hint: string,
  expectedHash: string,
  passwordType: string
): Promise<void> {
  try {
    // Look up file ID by filename
    const response = await authenticatedFetch('/api/files');
    if (!response.ok) {
      showError('Failed to retrieve file list.');
      return;
    }

    const data = await response.json();
    const files = data.files || [];
    
    // Find the file by filename (need to decrypt filenames to match)
    // For now, assume the caller has the file_id
    // This is a compatibility shim - new code should use downloadFile with fileId
    
    const file = files.find((f: { filename?: string; encrypted_filename?: string }) => 
      f.filename === filename || f.encrypted_filename === filename
    );
    
    if (!file) {
      showError('File not found.');
      return;
    }

    // Use the file_id for chunked download
    await downloadFile(file.file_id, hint, expectedHash, passwordType);
    
  } catch (error) {
    console.error('Download error:', error);
    showError('An error occurred during file download.');
  }
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
