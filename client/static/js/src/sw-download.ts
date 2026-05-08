/// <reference lib="WebWorker" />
/**
 * Arkfile Streaming Download Service Worker
 *
 * Intercepts /sw-download/<uuid>?... requests from same-origin pages and responds
 * with a Content-Disposition: attachment Response whose body is a ReadableStream
 * provided by the page via postMessage transfer.
 *
 * Why this exists:
 *   Chromium-based browsers cannot serve blob URLs for Blobs above ~2 GB through
 *   their internal download pipeline. By returning a synthetic streaming Response,
 *   the browser hands the bytes to its download manager just like any other HTTP
 *   download, with no blob URL ceiling and bounded memory.
 *
 * Privacy guarantees:
 *   - This SW makes NO network requests of its own.
 *   - It only intercepts same-origin synthetic URLs and forwards an already
 *     decrypted byte stream from the page to the browser's download manager.
 *   - No persistent storage. The pendingStreams Map is in-memory and lives only
 *     as long as the SW process. No filenames, UUIDs, or hashes are persisted.
 *   - No console output of filenames, UUIDs, or hash digests.
 *
 * Lifecycle:
 *   - On install -> skipWaiting() so a new SW activates immediately.
 *   - On activate -> clients.claim() so already-loaded pages are controlled.
 *   - Stale streams are cleaned up after a 5 minute TTL.
 */

export {};

declare const self: ServiceWorkerGlobalScope;

const SW_VERSION = '1';
const STREAM_TTL_MS = 5 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 1000;
const SW_PATH_PREFIX = '/sw-download/';

interface PendingStream {
  stream: ReadableStream<Uint8Array>;
  filename: string;
  contentLength: number | undefined;
  expiresAt: number;
  /**
   * Set to true after the first matching fetch consumes the stream. Subsequent
   * fetches for the same UUID return an empty 200 response (not a 404) so
   * Chromium-style download managers — which fire more than one fetch for
   * the same SW URL on a single user click (probe + download commit) — do
   * not abort the download with "File wasn't available on site."
   */
  consumed: boolean;
}

const pendingStreams = new Map<string, PendingStream>();

// Post-consumption grace window: how long the entry stays around so a second
// (or third) fetch from the browser's download manager for the same UUID is
// answered with an empty 200 instead of a 404.
const POST_CONSUMED_GRACE_MS = 30 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [uuid, entry] of pendingStreams) {
    if (entry.expiresAt < now) {
      if (!entry.consumed) {
        try { entry.stream.cancel('expired'); } catch (_) { /* ignore */ }
      }
      pendingStreams.delete(uuid);
    }
  }
}, CLEANUP_INTERVAL_MS);


self.addEventListener('install', (event: ExtendableEvent) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event: ExtendableMessageEvent) => {
  const data = event.data as Record<string, unknown> | null;
  if (!data || typeof data !== 'object') return;

  const type = data['type'];

  if (type === 'init') {
    const uuid = data['uuid'];
    const stream = data['stream'];
    const filename = data['filename'];
    const contentLength = data['contentLength'];
    if (typeof uuid !== 'string' || !(stream instanceof ReadableStream)) {
      replyAck(event, { type: 'error', message: 'invalid init payload' });
      return;
    }
    pendingStreams.set(uuid, {
      stream,
      filename: typeof filename === 'string' ? filename : 'download',
      contentLength: typeof contentLength === 'number' && Number.isFinite(contentLength)
        ? contentLength
        : undefined,
      expiresAt: Date.now() + STREAM_TTL_MS,
      consumed: false,
    });
    replyAck(event, { type: 'ack', uuid });
    return;
  }

  if (type === 'cancel') {
    const uuid = data['uuid'];
    if (typeof uuid !== 'string') return;
    const entry = pendingStreams.get(uuid);
    if (entry) {
      try { entry.stream.cancel('user-cancelled'); } catch (_) { /* ignore */ }
      pendingStreams.delete(uuid);
    }
    return;
  }

  if (type === 'ping') {
    replyAck(event, { type: 'pong', version: SW_VERSION });
    return;
  }
});

function replyAck(event: ExtendableMessageEvent, payload: Record<string, unknown>): void {
  // Prefer MessageChannel reply if a port was transferred; otherwise reply to the source client.
  const port = event.ports && event.ports[0];
  if (port) {
    try { port.postMessage(payload); } catch (_) { /* ignore */ }
    return;
  }
  const source = event.source as Client | null;
  if (source && typeof source.postMessage === 'function') {
    try { source.postMessage(payload); } catch (_) { /* ignore */ }
  }
}

self.addEventListener('fetch', (event: FetchEvent) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith(SW_PATH_PREFIX)) return;

  const uuid = url.pathname.substring(SW_PATH_PREFIX.length);
  const entry = pendingStreams.get(uuid);
  if (!entry) {
    // No entry at all: either it never existed, was cancelled, or its
    // post-consumption grace window already elapsed. 404 is appropriate here.
    console.log('[arkfile-sw] fetch: no entry for path; returning 404');
    event.respondWith(new Response('SW: stream not found or expired', {
      status: 404,
      headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
    }));
    return;
  }

  if (entry.consumed) {
    // Subsequent fetch for an already-consumed entry. Chromium-style
    // download managers commonly issue more than one fetch for the same
    // SW URL on a single user click (probe + download commit). Returning
    // a 404 here causes the DM to abort with "File wasn't available on
    // site." Returning an empty 200 keeps the DM happy; the actual data
    // is being delivered through the original fetch's streaming Response.
    console.log('[arkfile-sw] fetch: subsequent match (already consumed); returning empty 200');
    event.respondWith(new Response(new Uint8Array(0), {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'no-store',
      },
    }));
    return;
  }

  // First match: deliver the streaming Response. Mark consumed and
  // schedule cleanup for after the post-consumed grace window.
  entry.consumed = true;
  entry.expiresAt = Date.now() + POST_CONSUMED_GRACE_MS;
  console.log('[arkfile-sw] fetch: first match; delivering streaming Response');

  const safeName = encodeFilenameForContentDisposition(entry.filename);
  const headers: Record<string, string> = {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename*=UTF-8''${safeName}`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  if (entry.contentLength != null) {
    headers['Content-Length'] = String(entry.contentLength);
  }

  event.respondWith(new Response(entry.stream, { status: 200, headers }));
});

/**
 * Encode a filename for the Content-Disposition `filename*=UTF-8''...` form (RFC 5987).
 * Percent-encodes everything that is not in the attr-char set, plus quotes and parens.
 */
function encodeFilenameForContentDisposition(name: string): string {
  return encodeURIComponent(name)
    .replace(/['()]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
}
