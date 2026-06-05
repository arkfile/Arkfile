/**
 * Unit Tests -- OPAQUE server identity (idS) wiring
 *
 * Covers OpaqueClient.initialize() fetching the server identity from
 * /api/config/opaque. All OPAQUE participants (server, browser, CLI) must bind
 * the exact same idS or authentication fails, so the browser must:
 *   - adopt the server_id returned by /api/config/opaque, and
 *   - fall back to the 'localhost' default when the endpoint is unreachable or
 *     returns an unusable value (matching the server's own default).
 *
 * The libopaque WASM module itself is mocked out; this test only exercises the
 * fetch/fallback wiring, not the protocol math (which is covered by e2e).
 */

import './setup';
import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { OpaqueClient } from '../crypto/opaque';

const originalFetch = globalThis.fetch;

// Minimal libopaque stand-in so initialize() can set config constants without
// loading the real WASM module.
function installLibopaqueMock(): void {
  (globalThis as any).libopaque = {
    ready: Promise.resolve(),
    NotPackaged: 0,
    InSecEnv: 1,
  };
}

function uninstallLibopaqueMock(): void {
  delete (globalThis as any).libopaque;
}

beforeEach(() => {
  installLibopaqueMock();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  uninstallLibopaqueMock();
});

describe('OpaqueClient server identity (idS)', () => {
  test('defaults to "localhost" before initialize()', () => {
    const client = new OpaqueClient();
    expect(client.getServerId()).toBe('localhost');
  });

  test('adopts server_id returned by /api/config/opaque', async () => {
    globalThis.fetch = (async (input: any) => {
      expect(String(input)).toContain('/api/config/opaque');
      return new Response(JSON.stringify({ server_id: 'test.arkfile.net' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    const client = new OpaqueClient();
    await client.initialize();
    expect(client.getServerId()).toBe('test.arkfile.net');
  });

  test('falls back to "localhost" when the endpoint returns non-ok', async () => {
    globalThis.fetch = (async () => {
      return new Response('nope', { status: 500 });
    }) as typeof fetch;

    const client = new OpaqueClient();
    await client.initialize();
    expect(client.getServerId()).toBe('localhost');
  });

  test('falls back to "localhost" when fetch rejects', async () => {
    globalThis.fetch = (async () => {
      throw new TypeError('network down');
    }) as typeof fetch;

    const client = new OpaqueClient();
    await client.initialize();
    expect(client.getServerId()).toBe('localhost');
  });

  test('falls back to "localhost" when server_id is empty or missing', async () => {
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ server_id: '' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    const client = new OpaqueClient();
    await client.initialize();
    expect(client.getServerId()).toBe('localhost');
  });
});
