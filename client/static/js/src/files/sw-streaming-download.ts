/**
 * Page-side wrapper for the Arkfile streaming download Service Worker.
 *
 * Registers /sw-download.js (top-level scope `/`), then for each download:
 *
 *   1. Builds a ReadableStream from the existing async chunk-decryption generator.
 *   2. Pipes the stream through a TransformStream that incrementally hashes the
 *      plaintext bytes with SHA-256 (using @noble/hashes for the same
 *      implementation used elsewhere in the codebase).
 *   3. Generates a UUID and posts the stream to the SW via postMessage transfer
 *      list. Awaits an ack via MessageChannel.
 *   4. Triggers the download by navigating a hidden iframe to
 *      /sw-download/<uuid>; the SW intercepts and responds with the streaming
 *      Response so the browser hands the bytes straight to its download manager.
 *   5. On AbortSignal abort, posts {type:'cancel', uuid} to the SW; the SW
 *      cancels the stream and the browser shows the download as interrupted.
 *
 * Post-write SHA-256 limits:
 *   Whole-file digest is computed as plaintext flows to the download manager.
 *   A mismatch is often detected only after bytes may already be on disk. The
 *   page cannot revoke an OS download without buffering the entire file first,
 *   which defeats streaming. Callers must show expected + computed digests and
 *   must not claim unqualified success on mismatch. Same class of limit as CLI
 *   computeStreamingSHA256 after write and offline decrypt-blob post-write
 *   checks. Per-chunk AES-GCM still fails during the stream on chunk tampering.
 *
 * Ack timeout vs pre-transfer clone failure:
 *   Synchronous DataCloneError / transfer rejection during postMessage means
 *   the generator was not consumed and Blob fallback is safe. Ack timeout means
 *   the stream may already have been transferred; do not fall back to Blob with
 *   the same generator.
 *
 * Privacy notes:
 *   - The synthetic /sw-download/<uuid> URL is intercepted by the SW and never
 *     reaches the network.
 *   - No filenames, UUIDs, or hash digest values are ever logged to console.
 *     Hash mismatches are logged as a generic verification-failed message; the
 *     UI is responsible for surfacing the warning to the user.
 */

import { sha256 } from '@noble/hashes/sha2.js';

const SW_URL = '/sw-download.js';
const SW_SCOPE = '/';
const SW_ACK_TIMEOUT_MS = 5000;
const LOG_PREFIX = '[arkfile-sw]';

let registrationPromise: Promise<boolean> | null = null;

/**
 * Register the streaming-download Service Worker. Idempotent — multiple calls
 * return the same promise. Resolves to true once the SW is active and
 * controlling the page; false if registration is unavailable or fails.
 */
export function registerSwDownload(): Promise<boolean> {
  if (registrationPromise) return registrationPromise;
  registrationPromise = doRegister();
  return registrationPromise;
}

async function doRegister(): Promise<boolean> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
    console.warn(`${LOG_PREFIX} Service Workers not supported in this browser`);
    return false;
  }

  try {
    const registration = await navigator.serviceWorker.register(SW_URL, { scope: SW_SCOPE });

    // If we already have an active controller for our origin, we're good.
    if (navigator.serviceWorker.controller) return true;

    // Otherwise wait for the SW to become activated (and claim the page).
    await new Promise<void>((resolve) => {
      const candidate = registration.installing || registration.waiting || registration.active;
      if (candidate && candidate.state === 'activated') {
        resolve();
        return;
      }
      const sw = registration.installing || registration.waiting;
      if (!sw) {
        // Already activated but no controller yet; wait briefly for controllerchange.
        const onChange = () => {
          navigator.serviceWorker.removeEventListener('controllerchange', onChange);
          resolve();
        };
        navigator.serviceWorker.addEventListener('controllerchange', onChange);
        // Safety timeout
        setTimeout(() => {
          navigator.serviceWorker.removeEventListener('controllerchange', onChange);
          resolve();
        }, 2000);
        return;
      }
      sw.addEventListener('statechange', () => {
        if (sw.state === 'activated') resolve();
      });
    });

    // Final controller check; if still null, treat as failure (very rare).
    return navigator.serviceWorker.controller != null;
  } catch (err) {
    console.warn(`${LOG_PREFIX} SW registration failed:`, err);
    return false;
  }
}

/** True if the SW is active and currently controls this page. */
export function isSwAvailable(): boolean {
  if (typeof navigator === 'undefined') return false;
  // navigator.serviceWorker can be present-but-undefined (e.g. when a host
  // has stubbed it out for tests, or in privacy-restricted contexts).
  const sw = (navigator as Navigator).serviceWorker;
  if (!sw) return false;
  return sw.controller != null;
}

export interface SwStreamDownloadOptions {
  /** Plaintext byte length for Content-Length header (download manager progress). */
  contentLength: number;
  /** Suggested filename (used by the SW in Content-Disposition). */
  filename: string;
  /** Async generator yielding decrypted plaintext chunks. */
  chunks: AsyncGenerator<Uint8Array>;
  /** Optional AbortSignal for user-initiated cancellation. */
  signal?: AbortSignal;
  /**
   * Optional expected SHA-256 hex digest. If provided, plaintext bytes are
   * hashed as they stream and the result is compared at completion. Mismatch
   * is reported via the result, never thrown — the file is on disk by then.
   */
  expectedSha256Hex?: string;
}

export interface SwStreamDownloadResult {
  /** True if the browser accepted the download (anchor click succeeded). */
  initiated: boolean;
  /**
   * Resolves once the underlying stream has fully drained (or errored). The
   * caller can await this to know when hash verification has finished.
   */
  completion: Promise<SwStreamDownloadCompletion>;
}

export interface SwStreamDownloadCompletion {
  /** True if the stream ended cleanly. False if cancelled or errored. */
  ok: boolean;
  /** Total plaintext bytes streamed. */
  bytesStreamed: number;
  /**
   * Hex-encoded SHA-256 of plaintext if hashing was enabled (expectedSha256Hex
   * provided). Empty string otherwise.
   */
  computedSha256Hex: string;
  /**
   * Result of comparing computedSha256Hex against the expected hash.
   *   - 'skipped'  : no expected hash was provided
   *   - 'match'    : computed == expected
   *   - 'mismatch' : computed != expected (caller MUST surface a warning)
   *   - 'unavailable' : streaming was cancelled/errored before completion
   */
  hashVerification: 'skipped' | 'match' | 'mismatch' | 'unavailable';
  /** Error if streaming did not complete cleanly. */
  error?: Error;
}

/**
 * Stream decrypted bytes to the browser's download manager via the Service Worker.
 *
 * Returns immediately after the SW has been handed the stream and the anchor
 * click has fired. The actual byte transfer happens asynchronously — await
 * `result.completion` if you need to know when streaming + hash verification
 * have finished.
 */
export async function swStreamDownload(opts: SwStreamDownloadOptions): Promise<SwStreamDownloadResult> {
  if (!isSwAvailable()) {
    throw new Error('Service Worker is not active');
  }
  const controller = navigator.serviceWorker.controller!;

  const uuid = generateUuid();

  const wantHash = typeof opts.expectedSha256Hex === 'string' && opts.expectedSha256Hex.length === 64;
  const hasher = wantHash ? sha256.create() : null;

  let bytesStreamed = 0;
  let streamError: Error | undefined;
  let resolveCompletion: (value: SwStreamDownloadCompletion) => void = () => {};
  const completionPromise = new Promise<SwStreamDownloadCompletion>((resolve) => {
    resolveCompletion = resolve;
  });

  // Build the ReadableStream from the async generator, hashing as we go.
  const stream = new ReadableStream<Uint8Array>({
    async pull(streamCtrl) {
      try {
        if (opts.signal?.aborted) {
          streamError = new Error('Download cancelled');
          streamCtrl.error(streamError);
          try { await opts.chunks.return?.(undefined); } catch (_) { /* ignore */ }
          finalizeCompletion();
          return;
        }
        // Race the generator's next() against the abort signal so a cancel
        // mid-await responds promptly instead of waiting for the chunk to
        // finish materialising.
        const nextPromise = opts.chunks.next();
        const abortPromise = opts.signal
          ? new Promise<{ aborted: true }>((resolve) => {
              opts.signal!.addEventListener('abort', () => resolve({ aborted: true }), { once: true });
            })
          : null;
        const result = abortPromise
          ? await Promise.race([nextPromise.then((r) => ({ aborted: false as const, r })), abortPromise])
          : { aborted: false as const, r: await nextPromise };
        if ('aborted' in result && result.aborted) {
          streamError = new Error('Download cancelled');
          streamCtrl.error(streamError);
          try { await opts.chunks.return?.(undefined); } catch (_) { /* ignore */ }
          finalizeCompletion();
          return;
        }
        const { value, done } = (result as { aborted: false; r: IteratorResult<Uint8Array> }).r;
        if (done) {
          streamCtrl.close();
          finalizeCompletion();
          return;
        }
        if (value && value.length > 0) {
          bytesStreamed += value.length;
          if (hasher) hasher.update(value);
          streamCtrl.enqueue(value);
        }
      } catch (err) {
        streamError = err instanceof Error ? err : new Error(String(err));
        streamCtrl.error(streamError);
        try { await opts.chunks.return?.(undefined); } catch (_) { /* ignore */ }
        finalizeCompletion();
      }
    },
    async cancel(_reason) {
      streamError = streamError ?? new Error('Stream cancelled');
      try { await opts.chunks.return?.(undefined); } catch (_) { /* ignore */ }
      finalizeCompletion();
    },
  });

  function finalizeCompletion(): void {
    let hashVerification: SwStreamDownloadCompletion['hashVerification'] = 'skipped';
    let computedSha256Hex = '';
    if (streamError) {
      hashVerification = 'unavailable';
    } else if (hasher && opts.expectedSha256Hex) {
      computedSha256Hex = bytesToHex(hasher.digest());
      hashVerification = constantTimeHexEqual(computedSha256Hex, opts.expectedSha256Hex)
        ? 'match'
        : 'mismatch';
      if (hashVerification === 'mismatch') {
        // No digest values, no filename, no UUID in the log.
        console.warn(`${LOG_PREFIX} SHA-256 verification FAILED for downloaded file (computed digest does not match expected)`);
      }
    } else if (hasher) {
      computedSha256Hex = bytesToHex(hasher.digest());
    }
    const result: SwStreamDownloadCompletion = {
      ok: !streamError,
      bytesStreamed,
      computedSha256Hex,
      hashVerification,
      ...(streamError ? { error: streamError } : {}),
    };
    resolveCompletion(result);
  }

  // Hand the stream to the SW, awaiting the ack via MessageChannel.
  await new Promise<void>((resolve, reject) => {
    const channel = new MessageChannel();
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      channel.port1.close();
      reject(new Error('SW init ack timeout'));
    }, SW_ACK_TIMEOUT_MS);
    channel.port1.onmessage = (ev: MessageEvent) => {
      if (settled) return;
      const data = ev.data as Record<string, unknown> | null;
      if (data && data['type'] === 'ack' && data['uuid'] === uuid) {
        settled = true;
        clearTimeout(timer);
        channel.port1.close();
        resolve();
      } else {
        settled = true;
        clearTimeout(timer);
        channel.port1.close();
        reject(new Error('SW init returned non-ack response'));
      }
    };
    try {
      controller.postMessage(
        {
          type: 'init',
          uuid,
          filename: opts.filename,
          contentLength: opts.contentLength,
          stream,
        },
        // Transfer the stream and the response port to the SW.
        [stream as unknown as Transferable, channel.port2],
      );
    } catch (err) {
      settled = true;
      clearTimeout(timer);
      channel.port1.close();
      reject(err instanceof Error ? err : new Error(String(err)));
    }
  });

  // Wire AbortSignal to send a cancel message to the SW.
  if (opts.signal) {
    const onAbort = () => {
      try {
        controller.postMessage({ type: 'cancel', uuid });
      } catch (_) { /* ignore */ }
    };
    if (opts.signal.aborted) onAbort();
    else opts.signal.addEventListener('abort', onAbort, { once: true });
  }

  // Trigger the download via a hidden iframe pointed at the synthetic URL.
  //
  // We previously used `<a download>` + `a.click()`, but on Chromium-based
  // browsers (Brave/Chrome) that variant is unreliable when the anchor has
  // `display:none` and/or `rel="noopener"` — `a.click()` may silently no-op,
  // the browser never issues a fetch for /sw-download/<uuid>, the SW never
  // sees a fetch event, and after ~32 MiB are buffered into the transferred
  // ReadableStream the page-side stream times out. The empty SW console
  // alongside `bytes_streamed=33554432` exactly is the fingerprint of this
  // behavior.
  //
  // An iframe pointed at the synthetic URL fetches reliably across browsers
  // and is the same pattern used by StreamSaver.js. The SW intercepts the
  // iframe's navigation, returns its Content-Disposition: attachment Response,
  // and the browser turns that into a download — no main-frame navigation,
  // no anchor click required.
  const iframe = document.createElement('iframe');
  iframe.src = `/sw-download/${uuid}`;
  iframe.style.cssText = 'position:fixed; left:-9999px; top:-9999px; width:1px; height:1px; border:0;';
  document.body.appendChild(iframe);
  // Leave the iframe in the DOM long enough for the SW Response to fully
  // drain (large downloads can take many minutes). The SW's own grace
  // window for the entry is 30s after first match plus the stream lifetime,
  // so removing the iframe early would not abort the download — but keeping
  // it for a generous window avoids any chance of premature teardown.
  setTimeout(() => {
    if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
  }, 60_000);

  console.log(`${LOG_PREFIX} download initiated via SW (bytes_expected=${opts.contentLength})`);

  return {
    initiated: true,
    completion: completionPromise,
  };
}

/** Generate a v4 UUID using crypto.randomUUID where available, falling back to randomBytes. */
function generateUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // Set version (4) and variant (10xx) bits.
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}`;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Constant-time hex string comparison. Both inputs are lowercased first;
 * non-equal lengths are immediately not-equal but still fully scanned to avoid
 * timing leaks.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  const aLow = a.toLowerCase();
  const bLow = b.toLowerCase();
  const len = Math.max(aLow.length, bLow.length);
  let diff = aLow.length ^ bLow.length;
  for (let i = 0; i < len; i++) {
    const ac = i < aLow.length ? aLow.charCodeAt(i) : 0;
    const bc = i < bLow.length ? bLow.charCodeAt(i) : 0;
    diff |= ac ^ bc;
  }
  return diff === 0;
}
