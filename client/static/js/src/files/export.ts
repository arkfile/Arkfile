// export.ts - Export encrypted .arkbackup bundles from the browser.
// Uses a short-lived download token so the browser handles the download natively
// (no memory buffering for large files).

import { authenticatedFetch } from '../utils/auth';

/**
 * Export a file as an encrypted .arkbackup bundle.
 * Requests a short-lived export token, then triggers a native browser download
 * via window.location.href so the file streams directly to disk.
 */
export async function exportBackup(fileId: string): Promise<void> {
  try {
    // Step 1: Request a short-lived download token
    const response = await authenticatedFetch(`/api/files/${fileId}/export-token`, {
      method: 'POST',
    });

    if (!response.ok) {
      const err = await response.json();
      const message = err.message || 'Failed to request export token';
      console.error('Export token error:', message);
      alert('Export failed: ' + message);
      return;
    }

    const data = await response.json();
    const token = data.data?.token;
    if (!token) {
      console.error('Export token missing from response');
      alert('Export failed: no token received');
      return;
    }

    // Step 2: Open the export URL with the token. The browser handles the
    // download natively (Content-Disposition: attachment), so there is no
    // memory buffering regardless of file size.
    window.location.href = `/api/files/${fileId}/export?token=${encodeURIComponent(token)}`;

  } catch (error) {
    console.error('Export error:', error);
    alert('An error occurred during export.');
  }
}
