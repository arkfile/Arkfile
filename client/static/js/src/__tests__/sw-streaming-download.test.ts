/**
 * Tests for files/sw-streaming-download.ts
 *
 * The page-side wrapper is exercised in isolation here:
 *   - isSwAvailable / registration plumbing
 *   - swStreamDownload happy path: postMessage payload + ack
 *   - swStreamDownload throws when no SW controller
 *   - Generator -> ReadableStream pumping (chunks emerge in order, stream closes)
 *   - Streaming SHA-256 hash verification (match, mismatch, skipped)
 *   - Cancellation propagates via the AbortSignal
 *
 * Real Service Worker registration cannot run under Bun's test environment;
 * the SW itself is exercised by manual cross-browser testing on test.arkfile.net.
 */

import './setup';
import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  isSwAvailable,
  swStreamDownload,
  type SwStreamDownloadCompletion,
} from '../files/sw-streaming-download';

// ── DOM-ish shims ───────────────────────────────────────────────────────────

interface FakeAnchor {
  href: string;
  download: string;
  rel: string;
  style: { display: string };
  parentNode: { removeChild: (a: FakeAnchor) => void } | null;
  clicked: boolean;
}

let createdAnchors: FakeAnchor[] = [];

function installFakeDocument(): () => void {
  const orig = (globalThis as any).document;
  const body = {
    appendChild(a: FakeAnchor) {
      a.parentNode = body as any;
    },
    removeChild(_a: FakeAnchor) {
      _a.parentNode = null;
    },
  };
  (globalThis as any).document = {
    body,
    createElement(tag: string): FakeAnchor {
      if (tag !== 'a') throw new Error('only <a> expected');
      const a: FakeAnchor = {
        href: '',
        download: '',
        rel: '',
        style: { display: '' },
        parentNode: null,
        clicked: false,
      };
      // Add a click() method that flips a flag, no actual navigation.
      (a as any).click = () => {
        a.clicked = true;
      };
      createdAnchors.push(a);
      return a;
    },
  };
  return () => {
    (globalThis as any).document = orig;
  };
}

// Capture the messages the SW would receive via controller.postMessage().
interface CapturedSwMessage {
  data: any;
  transfer: Transferable[];
}

interface FakeController {
  messages: CapturedSwMessage[];
  postMessage: (message: any, transfer: Transferable[]) => void;
}

function installFakeServiceWorker(): { controller: FakeController; restore: () => void } {
  const messages: CapturedSwMessage[] = [];
  const controller: FakeController = {
    messages,
    postMessage(message: any, transfer: Transferable[]) {
      messages.push({ data: message, transfer });
      // Simulate the SW immediately acking via the transferred MessagePort.
      const port = transfer.find((t): t is MessagePort => t instanceof MessagePort);
      if (port && message?.type === 'init') {
        // postMessage on the port the page kept (port1) is achieved by sending
        // through the port the SW received (port2).
        try {
          (port as MessagePort).postMessage({ type: 'ack', uuid: message.uuid });
        } catch {
          // ignore
        }
      }
    },
  };

  const fakeSwApi: any = {
    controller,
    register: async () => ({ active: { state: 'activated' }, installing: null, waiting: null }),
    addEventListener: () => {},
    removeEventListener: () => {},
  };

  const origNavigator = (globalThis as any).navigator;
  (globalThis as any).navigator = {
    ...(origNavigator || {}),
    serviceWorker: fakeSwApi,
  };

  return {
    controller,
    restore: () => {
      (globalThis as any).navigator = origNavigator;
    },
  };
}

function uninstallServiceWorker(): () => void {
  const origNavigator = (globalThis as any).navigator;
  (globalThis as any).navigator = {
    ...(origNavigator || {}),
    serviceWorker: undefined,
  };
  return () => {
    (globalThis as any).navigator = origNavigator;
  };
}

async function* fromArray(items: Uint8Array[]): AsyncGenerator<Uint8Array> {
  for (const it of items) yield it;
}

// ── Tests ────────────────────────────────────────────────────────────────

describe('sw-streaming-download - isSwAvailable', () => {
  test('returns false when no controller', () => {
    const restore = uninstallServiceWorker();
    expect(isSwAvailable()).toBe(false);
    restore();
  });

  test('returns true when navigator.serviceWorker.controller is present', () => {
    const { restore } = installFakeServiceWorker();
    expect(isSwAvailable()).toBe(true);
    restore();
  });
});

describe('sw-streaming-download - swStreamDownload', () => {
  let restoreNav: () => void = () => {};
  let restoreDoc: () => void = () => {};
  let controller: FakeController;

  beforeEach(() => {
    createdAnchors = [];
    const sw = installFakeServiceWorker();
    controller = sw.controller;
    restoreNav = sw.restore;
    restoreDoc = installFakeDocument();
  });

  afterEach(() => {
    restoreNav();
    restoreDoc();
  });

  test('throws when SW controller is missing', async () => {
    const restore = uninstallServiceWorker();
    let err: unknown;
    try {
      await swStreamDownload({
        contentLength: 1,
        filename: 'x',
        chunks: fromArray([new Uint8Array([1])]),
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toContain('Service Worker is not active');
    restore();
  });

  test('happy path: posts init to SW, transfers the stream, triggers anchor click', async () => {
    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
    const res = await swStreamDownload({
      contentLength: 6,
      filename: 'test.bin',
      chunks: fromArray(chunks),
    });

    expect(res.initiated).toBe(true);

    // SW received exactly one init message.
    expect(controller.messages.length).toBe(1);
    const m = controller.messages[0]!;
    expect(m.data.type).toBe('init');
    expect(typeof m.data.uuid).toBe('string');
    expect(m.data.uuid.length).toBeGreaterThan(10);
    expect(m.data.filename).toBe('test.bin');
    expect(m.data.contentLength).toBe(6);
    expect(m.data.stream).toBeInstanceOf(ReadableStream);
    // Transfer list should contain the stream + the message port.
    expect(m.transfer.some((t: any) => t instanceof ReadableStream)).toBe(true);
    expect(m.transfer.some((t: any) => t instanceof MessagePort)).toBe(true);

    // Anchor was created and clicked at /sw-download/<uuid>.
    expect(createdAnchors.length).toBe(1);
    const a = createdAnchors[0]!;
    expect(a.href).toBe(`/sw-download/${m.data.uuid}`);
    expect(a.download).toBe('test.bin');
    expect(a.clicked).toBe(true);

    // Drain the stream that was handed to the "SW" so the completion promise resolves.
    const reader = (m.data.stream as ReadableStream<Uint8Array>).getReader();
    const collected: Uint8Array[] = [];
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) collected.push(value);
    }
    expect(collected.length).toBe(2);
    expect(collected[0]).toEqual(chunks[0]!);
    expect(collected[1]).toEqual(chunks[1]!);

    const completion: SwStreamDownloadCompletion = await res.completion;
    expect(completion.ok).toBe(true);
    expect(completion.bytesStreamed).toBe(6);
    expect(completion.hashVerification).toBe('skipped'); // no expectedSha256Hex
  });

  test('streaming SHA-256 verifies a match', async () => {
    const data = new TextEncoder().encode('the quick brown fox jumps over the lazy dog');
    const expectedHex = bytesToHex(sha256(data));

    // Split into two chunks to exercise incremental hashing.
    const chunks = [data.slice(0, 10), data.slice(10)];

    const res = await swStreamDownload({
      contentLength: data.length,
      filename: 'fox.txt',
      chunks: fromArray(chunks),
      expectedSha256Hex: expectedHex,
    });

    // Drain the stream so the completion finalizes.
    const reader = (controller.messages[0]!.data.stream as ReadableStream<Uint8Array>).getReader();
    while (!(await reader.read()).done) { /* drain */ }

    const completion = await res.completion;
    expect(completion.ok).toBe(true);
    expect(completion.bytesStreamed).toBe(data.length);
    expect(completion.hashVerification).toBe('match');
    expect(completion.computedSha256Hex).toBe(expectedHex);
  });

  test('streaming SHA-256 reports mismatch on tampered data', async () => {
    const data = new TextEncoder().encode('abcdefghij');
    const wrongExpected = '00'.repeat(32); // all zeros

    const res = await swStreamDownload({
      contentLength: data.length,
      filename: 'tampered.bin',
      chunks: fromArray([data]),
      expectedSha256Hex: wrongExpected,
    });

    const reader = (controller.messages[0]!.data.stream as ReadableStream<Uint8Array>).getReader();
    while (!(await reader.read()).done) { /* drain */ }

    const completion = await res.completion;
    expect(completion.ok).toBe(true);
    expect(completion.hashVerification).toBe('mismatch');
    expect(completion.computedSha256Hex).not.toBe(wrongExpected);
  });

  test('cancellation: AbortSignal causes the stream to error and posts cancel to SW', async () => {
    const ac = new AbortController();
    // Generator yields one chunk then waits; we'll abort before it yields the second.
    const slowGen = (async function* () {
      yield new Uint8Array([1, 2, 3]);
      // Simulate a long pause for the next chunk
      await new Promise((r) => setTimeout(r, 100));
      yield new Uint8Array([4, 5, 6]);
    })();

    const res = await swStreamDownload({
      contentLength: 6,
      filename: 'cancel.bin',
      chunks: slowGen,
      signal: ac.signal,
    });

    const reader = (controller.messages[0]!.data.stream as ReadableStream<Uint8Array>).getReader();
    // Read the first chunk
    const r1 = await reader.read();
    expect(r1.done).toBe(false);

    // Abort -- this should both error the stream's pull (next iteration) AND
    // post a cancel message to the SW.
    ac.abort();

    // The next read should resolve with error/done
    let readError: unknown;
    try {
      const r2 = await reader.read();
      // If it returned done=true that's also acceptable
      expect(r2.done || r2.value === undefined).toBe(true);
    } catch (e) {
      readError = e;
    }
    // Either path is acceptable; ensure the cancel message was posted.
    const cancelMsg = controller.messages.find((m) => m.data?.type === 'cancel');
    expect(cancelMsg).toBeDefined();
    expect(cancelMsg!.data.uuid).toBe(controller.messages[0]!.data.uuid);

    const completion = await res.completion;
    expect(completion.ok).toBe(false);
    expect(completion.hashVerification).toBe('unavailable');
    void readError; // silence unused warning
  });
});

// ── helpers ─────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0');
  return out;
}
