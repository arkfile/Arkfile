/**
 * Register the CSP Trusted Types default policy for innerHTML and script URL sinks.
 */
export function registerTrustedTypesPolicy(): void {
  if (typeof window === 'undefined' || !(window as any).trustedTypes?.createPolicy) {
    return;
  }
  try {
    (window as any).trustedTypes.createPolicy('default', {
      createHTML: (string: string) => {
        // Safe pass-through of application static templates and escaped markup
        return string;
      },
      createScriptURL: (url: string) => {
        // Only the same-origin streaming-download Service Worker is permitted.
        if (url === '/sw-download.js') {
          return url;
        }
        throw new TypeError(`Blocked TrustedScriptURL for disallowed URL: ${url}`);
      },
    });
  } catch (err) {
    console.warn('Trusted Types policy registration failed or was already created:', err);
  }
}
