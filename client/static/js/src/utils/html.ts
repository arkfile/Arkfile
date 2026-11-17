/**
 * Escape a value for interpolation into HTML text or a quoted attribute.
 * Required for any decrypted, sharer-authored, or server-supplied string
 * placed into an innerHTML template.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
