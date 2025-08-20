/**
 * File download functionality
 */

import { wasmManager } from '../utils/wasm';
import { getUserEmailFromToken, authenticatedFetch } from '../utils/auth-wasm';
import { showError } from '../ui/messages';

export async function downloadFile(filename: string, hint: string, expectedHash: string, passwordType: string): Promise<void> {
  try {
    await wasmManager.ensureReady();

    if (hint) {
      alert(`Password Hint: ${hint}`);
    }

    let decryptedData: string | Uint8Array;
    
    if (passwordType === 'account') {
      // For account-encrypted files, use secure session decryption
      const userEmail = getUserEmailFromToken();
      if (!userEmail) {
        showError('Cannot determine user email. Please log in again.');
        return;
      }
      
      // Validate secure session exists
      const sessionValidation = await wasmManager.validateSecureSession(userEmail);
      if (!sessionValidation.valid) {
        showError('Your session has expired. Please log in again to decrypt account-encrypted files.');
        return;
      }
      
      const response = await authenticatedFetch(`/api/download/${encodeURIComponent(filename)}`);

      if (response.ok) {
        const data = await response.json();
        
        // Use secure session decryption (no password exposed to JavaScript)
        const decryptResult = await wasmManager.decryptFileWithSecureSession(data.data, userEmail);
        if (!decryptResult.success) {
          showError('Failed to decrypt file: ' + decryptResult.error);
          return;
        }
        decryptedData = decryptResult.data!;
      } else {
        showError('Failed to download file.');
        return;
      }
    } else {
      // For custom password-encrypted files
      const password = prompt('Enter the file password:');
      if (!password) return;

      const response = await authenticatedFetch(`/api/download/${encodeURIComponent(filename)}`);

      if (response.ok) {
        const data = await response.json();
        decryptedData = await wasmManager.decryptFile(data.data, password);

        if (decryptedData === 'Failed to decrypt data') {
          showError('Incorrect password or corrupted file.');
          return;
        }
      } else {
        showError('Failed to download file.');
        return;
      }
    }

    // Convert base64 to Uint8Array for hash verification
    const decryptedBytes = Uint8Array.from(atob(decryptedData as string), c => c.charCodeAt(0));
    
    // Verify file integrity
    const calculatedHash = await wasmManager.calculateSHA256(decryptedBytes);
    if (calculatedHash !== expectedHash) {
      showError('File integrity check failed. The file may be corrupted.');
      return;
    }

    // Create and download the file
    const blob = new Blob([decryptedBytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

  } catch (error) {
    console.error('Download error:', error);
    showError('An error occurred during file download.');
  }
}
