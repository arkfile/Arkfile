/**
 * File download functionality
 */

import { getUserEmailFromToken, authenticatedFetch } from '../utils/auth';
import { showError } from '../ui/messages';

export async function downloadFile(filename: string, hint: string, expectedHash: string, passwordType: string): Promise<void> {
  try {
    if (hint) {
      alert(`Password Hint: ${hint}`);
    }

    let decryptedData: string;
    
    if (passwordType === 'account') {
      // For account-encrypted files, backend handles decryption
      const response = await authenticatedFetch(`/api/download/${encodeURIComponent(filename)}`);

      if (response.ok) {
        const data = await response.json();
        decryptedData = data.data;
      } else {
        const errorData = await response.json().catch(() => ({}));
        showError(errorData.message || 'Failed to download file.');
        return;
      }
    } else {
      // For custom password-encrypted files
      const password = prompt('Enter the file password:');
      if (!password) return;

      const response = await authenticatedFetch(`/api/download/${encodeURIComponent(filename)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password }),
      });

      if (response.ok) {
        const data = await response.json();
        decryptedData = data.data;
      } else {
        const errorData = await response.json().catch(() => ({}));
        showError(errorData.message || 'Failed to download file. Check your password.');
        return;
      }
    }

    // Convert base64 to Uint8Array
    const decryptedBytes = Uint8Array.from(atob(decryptedData), c => c.charCodeAt(0));

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
