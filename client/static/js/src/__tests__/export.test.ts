/**
 * Unit Tests -- exportBackup
 *
 * Tests the browser export flow: token request via authenticatedFetch,
 * then navigation to the export URL with the token.
 */

import './setup';
import { describe, test, expect, beforeEach, mock } from 'bun:test';

// localStorage mock (needed by AuthManager)
class MockLocalStorage implements Storage {
  private store = new Map<string, string>();
  get length(): number { return this.store.size; }
  clear(): void { this.store.clear(); }
  getItem(key: string): string | null { return this.store.get(key) ?? null; }
  key(index: number): string | null { return Array.from(this.store.keys())[index] ?? null; }
  removeItem(key: string): void { this.store.delete(key); }
  setItem(key: string, value: string): void { this.store.set(key, value); }
}

if (typeof globalThis.localStorage === 'undefined') {
  (globalThis as any).localStorage = new MockLocalStorage();
}

// Track window.location.href assignments
let lastLocationHref = '';
if (typeof globalThis.window !== 'undefined') {
  Object.defineProperty(globalThis.window, 'location', {
    value: {
      href: '',
      get _lastHref() { return lastLocationHref; },
    },
    writable: true,
    configurable: true,
  });
  // Override href setter to capture assignments
  const loc = (globalThis.window as any).location;
  const originalDescriptor = Object.getOwnPropertyDescriptor(loc, 'href');
  Object.defineProperty(loc, 'href', {
    get() { return lastLocationHref; },
    set(value: string) { lastLocationHref = value; },
    configurable: true,
  });
}

// Mock alert
let lastAlert = '';
(globalThis as any).alert = (msg: string) => { lastAlert = msg; };

// Track fetch calls
let fetchCalls: { url: string; options: any }[] = [];
let mockFetchResponse: { ok: boolean; status: number; body: any } = {
  ok: true, status: 200, body: { success: true, data: { token: 'test-export-token-abc123' } },
};

// Mock fetch globally
(globalThis as any).fetch = async (url: string, options?: any) => {
  fetchCalls.push({ url, options });
  return {
    ok: mockFetchResponse.ok,
    status: mockFetchResponse.status,
    json: async () => mockFetchResponse.body,
  };
};

// Import after mocks are set up
import { exportBackup } from '../files/export';

describe('exportBackup', () => {
  beforeEach(() => {
    fetchCalls = [];
    lastLocationHref = '';
    lastAlert = '';
    mockFetchResponse = {
      ok: true, status: 200,
      body: { success: true, data: { token: 'test-export-token-abc123' } },
    };
    // Set a valid JWT token so authenticatedFetch includes Authorization header
    localStorage.setItem('token', 'fake-jwt-token');
  });

  test('requests export token then navigates to export URL', async () => {
    await exportBackup('file-id-123');

    // Should have made one fetch call for the export token
    expect(fetchCalls.length).toBe(1);
    expect(fetchCalls[0].url).toBe('/api/files/file-id-123/export-token');
    expect(fetchCalls[0].options.method).toBe('POST');

    // Should have set window.location.href to the export URL with token
    expect(lastLocationHref).toContain('/api/files/file-id-123/export');
    expect(lastLocationHref).toContain('token=test-export-token-abc123');
  });

  test('URL-encodes the export token', async () => {
    mockFetchResponse.body = {
      success: true,
      data: { token: 'token+with/special=chars' },
    };

    await exportBackup('file-456');

    expect(lastLocationHref).toContain('token=token%2Bwith%2Fspecial%3Dchars');
  });

  test('shows alert on fetch error response', async () => {
    mockFetchResponse = {
      ok: false, status: 404,
      body: { success: false, message: 'File not found' },
    };

    await exportBackup('nonexistent-file');

    // Should NOT navigate
    expect(lastLocationHref).toBe('');

    // Should show alert with error message
    expect(lastAlert).toContain('File not found');
  });

  test('shows alert on missing token in response', async () => {
    mockFetchResponse = {
      ok: true, status: 200,
      body: { success: true, data: {} },
    };

    await exportBackup('file-no-token');

    // Should NOT navigate (no token)
    expect(lastLocationHref).toBe('');

    // Should alert about missing token
    expect(lastAlert).toContain('no token received');
  });

  test('shows alert on network exception', async () => {
    // Override fetch to throw
    const originalFetch = (globalThis as any).fetch;
    (globalThis as any).fetch = async () => { throw new Error('Network error'); };

    await exportBackup('file-network-err');

    // Should NOT navigate
    expect(lastLocationHref).toBe('');

    // Should alert about error
    expect(lastAlert).toContain('error occurred during export');

    // Restore
    (globalThis as any).fetch = originalFetch;
  });

  test('includes Authorization header via authenticatedFetch', async () => {
    await exportBackup('file-auth-test');

    expect(fetchCalls.length).toBe(1);
    const headers = fetchCalls[0].options.headers;
    // authenticatedFetch adds Authorization header from localStorage token
    expect(headers?.['Authorization']).toBe('Bearer fake-jwt-token');
  });
});
