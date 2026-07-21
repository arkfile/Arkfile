/**
 * Gated debug/info logging for the browser client.
 *
 * Production builds set ARKFILE_DEBUG_LOG to false via bun --define so these
 * helpers become no-ops after minify. console.warn / console.error remain for
 * security-relevant failures and are not routed through this module.
 */

declare const ARKFILE_DEBUG_LOG: boolean | undefined;

function debugEnabled(): boolean {
  try {
    if (typeof ARKFILE_DEBUG_LOG !== 'undefined') {
      return ARKFILE_DEBUG_LOG === true;
    }
  } catch {
    // Compile-time define may be absent in unit tests.
  }
  return false;
}

export function debugLog(...args: unknown[]): void {
  if (debugEnabled()) {
    console.log(...args);
  }
}
