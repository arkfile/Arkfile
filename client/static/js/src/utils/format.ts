/**
 * Shared human-readable formatting helpers for the browser client.
 */

/**
 * Format a byte count using 1024-based units (Bytes, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return '0 Bytes';
  }
  if (bytes === 0) {
    return '0 Bytes';
  }
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  const value = bytes / Math.pow(k, i);
  return `${parseFloat(value.toFixed(2))} ${sizes[i]}`;
}

/** Alias used by share-list and similar UI. */
export function formatFileSize(bytes: number): string {
  return formatBytes(bytes);
}
