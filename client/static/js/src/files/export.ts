// export.ts - Export encrypted .arkbackup bundles from the browser.
// GET /api/files/:fileId/export is a protected route: the session cookie
// authenticates it like every other owner API call, so no export token or
// URL credential is needed. Bundles stream straight to disk either through a
// native download or through a directory-picker writable; neither path
// buffers a bundle in memory.

import { ensureFreshBatchAuth } from './download-batch';

/** Delay between native export downloads so the browser can hand each to its download manager. */
export const EXPORT_DOWNLOAD_PACING_MS = 250;

export function exportUrl(fileId: string): string {
  return `/api/files/${encodeURIComponent(fileId)}/export`;
}

/**
 * Start a native download of one bundle with a hidden same-origin anchor.
 * The response's Content-Disposition name (<file_id>.arkbackup) is used and
 * the browser resolves collisions. The page never navigates and cannot see
 * completion or HTTP errors on this path.
 */
export function triggerNativeExportDownload(fileId: string): void {
  const anchor = document.createElement('a');
  anchor.href = exportUrl(fileId);
  anchor.download = `${fileId}.arkbackup`;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

/** Fetch one bundle for streaming into a directory-picker writable. */
export function fetchExportResponse(fileId: string, signal?: AbortSignal): Promise<Response> {
  return fetch(exportUrl(fileId), {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    ...(signal ? { signal } : {}),
  });
}

/** Per-row Export Backup: refresh the session, then start a native download. */
export async function exportBackup(fileId: string): Promise<void> {
  try {
    await ensureFreshBatchAuth();
  } catch {
    alert('Export failed: your session has expired. Please log in again.');
    return;
  }
  try {
    triggerNativeExportDownload(fileId);
  } catch (error) {
    console.error('Export error:', error);
    alert('An error occurred during export.');
  }
}
