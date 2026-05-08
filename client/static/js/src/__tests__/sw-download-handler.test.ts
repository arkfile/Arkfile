/**
 * Direct unit test for the Service Worker's fetch handler logic in sw-download.ts.
 *
 * Verifies the post-2026-05-08 behavior:
 *   - First fetch matching a UUID -> 200 streaming Response (Content-Disposition).
 *   - Subsequent fetch matching the SAME UUID while consumed -> empty 200
 *     (NOT 404). This is the StreamSaver.js pattern that handles Chromium's
 *     habit of issuing more than one fetch for an `<a download>`-clicked
 *     SW URL on a single user click.
 *   - Fetch for a UUID that never existed (or was cleaned up) -> 404.
 *
 * This is the regression test for the "File wasn't available on site" bug.
 */

import './setup';
import { describe, test, expect, beforeAll } from 'bun:test';

// ── ServiceWorker globals stub ─────────────────────────────────────────────
// The SW source uses `self.addEventListener(...)` to register install/activate/
// message/fetch handlers, and references self.skipWaiting / self.clients.claim.
// We stub a minimal self object that captures registered listeners so the test
// can dispatch synthetic events.

interface CapturedListeners {
  install: Array<(ev: any) => void>;
  activate: Array<(ev: any) => void>;
  message: Array<(ev: any) => void>;
  fetch: Array<(ev: any) => void>;
}

const listeners: CapturedListeners = { install: [], activate: [], message: [], fetch: [] };

const fakeSelf = {
  location: { origin: 'https://test.example' },
  addEventListener(name: keyof CapturedListeners, fn: (ev: any) => void) {
    if (listeners[name]) listeners[name].push(fn);
  },
  skipWaiting: async () => {},
  clients: {
    claim: async () => {},
  },
};

beforeAll(async () => {
  // Install fake self so the SW's `declare const self` resolves at runtime.
  (globalThis as any).self = fakeSelf;
  // Import the SW module under test. This is the only side-effect we want.
  await import('../sw-download');
  // Sanity: the SW must have registered a fetch listener.
  if (listeners.fetch.length === 0) throw new Error('SW did not register fetch listener');
  if (listeners.message.length === 0) throw new Error('SW did not register message listener');
});

// ── Helpers ────────────────────────────────────────────────────────────────

interface FakeFetchEvent {
  request: { url: string };
  responsePromise: Promise<Response> | null;
  respondWith(p: Promise<Response> | Response): void;
}

function makeFetchEvent(uuid: string): FakeFetchEvent {
  const ev: FakeFetchEvent = {
    request: { url: `https://test.example/sw-download/${uuid}` },
    responsePromise: null,
    respondWith(p: Promise<Response> | Response) {
      ev.responsePromise = Promise.resolve(p);
    },
  };
  return ev;
}

interface FakeMessageEvent {
  data: any;
  ports: MessagePort[];
  source: any;
}

function makeMessageEvent(data: any, port?: MessagePort): FakeMessageEvent {
  return {
    data,
    ports: port ? [port] : [],
    source: null,
  };
}

async function dispatchFetch(uuid: string): Promise<Response> {
  const ev = makeFetchEvent(uuid);
  for (const fn of listeners.fetch) fn(ev);
  if (!ev.responsePromise) throw new Error('SW fetch handler did not call respondWith');
  return ev.responsePromise;
}

async function dispatchInit(uuid: string, stream: ReadableStream<Uint8Array>, contentLength?: number): Promise<void> {
  const channel = new MessageChannel();
  const ackPromise = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('init ack timeout')), 1000);
    channel.port1.onmessage = (ev) => {
      clearTimeout(timer);
      const d = ev.data as { type?: string; uuid?: string };
      if (d?.type === 'ack' && d.uuid === uuid) resolve();
      else reject(new Error('unexpected reply from SW init'));
    };
  });

  const msgEv = makeMessageEvent(
    { type: 'init', uuid, stream, filename: 'test.bin', contentLength },
    channel.port2,
  );
  for (const fn of listeners.message) fn(msgEv);

  await ackPromise;
  channel.port1.close();
}

function makeStream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (i < chunks.length) {
        c.enqueue(chunks[i++]!);
      } else {
        c.close();
      }
    },
  });
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('SW fetch handler - regression test for double-fetch (File-wasnt-available-on-site)', () => {
  test('UUID never registered -> 404', async () => {
    const res = await dispatchFetch('11111111-aaaa-bbbb-cccc-000000000000');
    expect(res.status).toBe(404);
  });

  test('First fetch -> 200 with Content-Disposition; subsequent fetches with same UUID -> empty 200 (NOT 404)', async () => {
    const uuid = '22222222-aaaa-bbbb-cccc-000000000001';
    const stream = makeStream([new Uint8Array([1, 2, 3, 4]), new Uint8Array([5, 6, 7, 8])]);
    await dispatchInit(uuid, stream, 8);

    // First fetch: should deliver the streaming Response.
    const first = await dispatchFetch(uuid);
    expect(first.status).toBe(200);
    expect(first.headers.get('Content-Disposition')?.startsWith('attachment;')).toBe(true);
    expect(first.headers.get('Content-Type')).toBe('application/octet-stream');
    expect(first.headers.get('Content-Length')).toBe('8');

    // Drain the body to verify it really is the streaming body.
    const body = new Uint8Array(await first.arrayBuffer());
    expect(Array.from(body)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

    // SECOND fetch for the SAME UUID — this is what Brave's DM does on a
    // single user click.  Must return 200 (empty body), NOT 404.
    const second = await dispatchFetch(uuid);
    expect(second.status).toBe(200);
    // Empty body — NOT a 404 with the "stream not found" message.
    const secondBody = new Uint8Array(await second.arrayBuffer());
    expect(secondBody.length).toBe(0);
    // No Content-Disposition header on the empty response (it's a side-channel
    // probe acknowledgement, not a real download).
    expect(second.headers.get('Content-Disposition')).toBeNull();

    // THIRD fetch for the SAME UUID — should also be empty 200 (still in
    // post-consumption grace window).
    const third = await dispatchFetch(uuid);
    expect(third.status).toBe(200);
    expect(new Uint8Array(await third.arrayBuffer()).length).toBe(0);
  });

  test('Fetch for a different (unrelated) UUID still returns 404 even after another UUID was registered', async () => {
    const registered = '33333333-aaaa-bbbb-cccc-000000000002';
    const unregistered = '44444444-aaaa-bbbb-cccc-000000000003';
    const stream = makeStream([new Uint8Array([9, 9, 9])]);
    await dispatchInit(registered, stream, 3);

    const res = await dispatchFetch(unregistered);
    expect(res.status).toBe(404);
  });
});
