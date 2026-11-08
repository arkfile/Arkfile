import { resetMocks } from './setup';
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { AuthManager } from '../utils/auth';

let originalFetch: typeof globalThis.fetch;
let originalLocks: unknown;
let refreshCalls = 0;

beforeEach(() => {
  resetMocks();
  originalFetch = globalThis.fetch;
  originalLocks = (globalThis.navigator as any)?.locks;
  refreshCalls = 0;
  (globalThis as any).document = { cookie: '', visibilityState: 'visible', addEventListener(): void {} };
  globalThis.fetch = (async (url: string) => {
    if (String(url) === '/api/refresh') {
      refreshCalls++;
      await new Promise((r) => setTimeout(r, 10));
      return new Response('{}', { status: 200 });
    }
    return new Response('{}', { status: 404 });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (globalThis.navigator) {
    Object.defineProperty(globalThis.navigator, 'locks', { value: originalLocks, configurable: true });
  }
});

describe('AuthManager.refreshToken serialization', () => {
  test('concurrent callers in one tab share a single refresh request', async () => {
    const [a, b, c] = await Promise.all([
      AuthManager.refreshToken(),
      AuthManager.refreshToken(),
      AuthManager.refreshToken(),
    ]);
    expect(a.ok && b.ok && c.ok).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  test('takes the cross-tab Web Lock when available', async () => {
    const lockNames: string[] = [];
    const locks = {
      request: async (name: string, cb: () => Promise<unknown>) => {
        lockNames.push(name);
        return cb();
      },
    };
    if (!globalThis.navigator) {
      (globalThis as any).navigator = {};
    }
    Object.defineProperty(globalThis.navigator, 'locks', { value: locks, configurable: true });

    const result = await AuthManager.refreshToken();
    expect(result.ok).toBe(true);
    expect(lockNames).toEqual(['arkfile-refresh']);
    expect(refreshCalls).toBe(1);
  });

  test('still refreshes when the lock request fails', async () => {
    const locks = { request: async () => { throw new Error('locks unavailable'); } };
    if (!globalThis.navigator) {
      (globalThis as any).navigator = {};
    }
    Object.defineProperty(globalThis.navigator, 'locks', { value: locks, configurable: true });

    const result = await AuthManager.refreshToken();
    expect(result.ok).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  test('a new refresh starts after the previous one finished', async () => {
    await AuthManager.refreshToken();
    await AuthManager.refreshToken();
    expect(refreshCalls).toBe(2);
  });
});
