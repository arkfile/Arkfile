/**
 * Tests for streaming-download.ts
 *
 * Covers:
 * - Blob fallback path (when SW is not available): chunks decrypted, Blob assembled, blobUrl returned
 * - Owner download path: metadata decryption, error handling
 * - StreamingDownloadResult shape on error
 *
 * The SW streaming path itself is exercised by sw-streaming-download.test.ts;
 * here the SW is mocked out (navigator.serviceWorker.controller === null) so
 * that streaming-download falls through to the Blob path.
 */

import './setup';
import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { StreamingDownloadManager } from '../files/streaming-download';
import { randomBytes } from '../crypto/primitives';
import { buildChunkAAD } from '../crypto/aad';

// ── Helpers ────────────────────────────────────────────────────────────────

/** Lowercase hex of a SHA-256 digest (mirrors the Blob-fallback bytesToHex helper). */
function hexDigest(data: Uint8Array): string {
  const bytes = sha256(data);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0');
  return out;
}

/**
 * Build a chunk: AES-GCM([nonce(12)][ciphertext][tag(16)]) under
 * AAD = BuildChunkAAD(fileID, chunkIndex, totalChunks). No chunk-0 envelope
 * header (uniform chunks).
 */
async function buildEncryptedChunk(
  plaintext: Uint8Array,
  rawKey: Uint8Array,
  fileID: string,
  chunkIndex: number,
  totalChunks: number,
): Promise<Uint8Array> {
  const keyBuf = rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ptBuf = plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength) as ArrayBuffer;
  const aad = buildChunkAAD(fileID, BigInt(chunkIndex), BigInt(totalChunks));
  const aadBuf = new Uint8Array(aad).buffer as ArrayBuffer;
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aadBuf },
      key,
      ptBuf,
    ),
  );
  const result = new Uint8Array(12 + ciphertextWithTag.length);
  result.set(nonce, 0);
  result.set(ciphertextWithTag, 12);
  return result;
}

/** Build a minimal valid share metadata response (file_id required for chunk AAD). */
function makeShareMeta(
  totalBytes: number,
  chunkCount: number,
  chunkSizeBytes: number,
  fileID = 'test-share-file',
) {
  return {
    file_id: fileID,
    encrypted_filename: '',
    filename_nonce: '',
    encrypted_sha256sum: '',
    sha256sum_nonce: '',
    encrypted_fek: '',
    password_hint: '',
    password_type: 'account',
    size_bytes: totalBytes,
    chunk_size: chunkSizeBytes,
    total_chunks: chunkCount,
    chunk_count: chunkCount,
    chunk_size_bytes: chunkSizeBytes,
    encrypted_file_sha256: false,
  };
}

// Helper to assign fetch mock without hitting the strict `typeof fetch` type guard
function setFetchMock(fn: (url: string, ...args: any[]) => Promise<Response>): void {
  (globalThis as any).fetch = fn;
}

/**
 * Force the SW to appear unavailable so that streamDecryptedChunks() takes the
 * Blob fallback path. Must be called before constructing the manager.
 */
function disableServiceWorker(): void {
  if (typeof navigator !== 'undefined') {
    Object.defineProperty(navigator, 'serviceWorker', {
      configurable: true,
      get: () => undefined,
    });
  }
}

/**
 * Minimal chunking config matching crypto/chunking-params.json.
 * The constants.ts module caches this at module level after the first fetch.
 * All fetch mocks that invoke the generator path must handle /api/config/chunking.
 */
const CHUNKING_CONFIG = {
  plaintextChunkSizeBytes: 16777216,
  envelope: {
    version: 1,
    headerSizeBytes: 2,
    keyTypes: { account: 0, custom: 1 },
  },
  aesGcm: {
    nonceSizeBytes: 12,
    tagSizeBytes: 16,
    keySizeBytes: 32,
  },
};

/**
 * Wrap a fetch mock handler so that /api/config/chunking is always served.
 * Required for any test that exercises the chunk generator path, because
 * StreamingDownloadManager calls getChunkingParams() which fetches this URL.
 */
function withChunkingConfig(fn: (url: string) => Promise<Response>): (url: string) => Promise<Response> {
  return async (url: string) => {
    if (url.includes('/api/config/chunking')) {
      return new Response(JSON.stringify(CHUNKING_CONFIG), { status: 200 });
    }
    return fn(url);
  };
}

const FAKE_FILE_ID = 'test-file-1234';
const FAKE_SHARE_ID = 'test-share-5678';
const FAKE_AUTH_TOKEN = 'test-auth-token';
const FAKE_DOWNLOAD_TOKEN = 'test-download-token';

// ── Blob fallback path tests (SW unavailable) ──────────────────────────────

describe('StreamingDownloadManager - Blob fallback path (SW unavailable)', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
    disableServiceWorker();
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('downloadSharedFile assembles a Blob and returns a blobUrl when SW is unavailable', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hello streaming world');
    const FILE_ID = 'test-share-file';
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FILE_ID, 0, 1);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length, FILE_ID)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.bin' });

    expect(result.success).toBe(true);
    expect(result.streamedViaSw).toBeFalsy();
    expect(result.blobUrl).toBeDefined();
    expect(typeof result.blobUrl).toBe('string');
    expect(result.blobUrl!.startsWith('blob:')).toBe(true);
  });

  test('returns failure with no blobUrl when share metadata fetch fails', async () => {
    setFetchMock(async () => new Response('server error', { status: 500 }));

    const fek = randomBytes(32);
    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      accountKey: fek,
      showProgressUI: false,
    });

    const result = await manager.downloadFile('nonexistent', fek);

    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
    expect(result.streamedViaSw).toBeUndefined();
    expect(result.error).toBeDefined();
  });

  test('Blob fallback returns hashVerification match when expected hash is correct', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hash verification match test');
    const FILE_ID = 'test-hash-match-file';
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FILE_ID, 0, 1);
    const expectedHash = hexDigest(plaintext);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length, FILE_ID)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.bin', sha256: expectedHash });

    expect(result.success).toBe(true);
    expect(result.blobUrl).toBeDefined();
    expect(result.hashVerification).toBe('match');
  });

  test('Blob fallback returns hashVerification mismatch when expected hash is wrong', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hash verification mismatch test');
    const FILE_ID = 'test-hash-mismatch-file';
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FILE_ID, 0, 1);
    const wrongHash = '0'.repeat(64);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length, FILE_ID)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.bin', sha256: wrongHash });

    expect(result.success).toBe(true);
    expect(result.blobUrl).toBeDefined();
    expect(result.hashVerification).toBe('mismatch');
  });

  test('Blob fallback returns hashVerification skipped when no expected hash is provided', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('no hash provided');
    const FILE_ID = 'test-hash-skipped-file';
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FILE_ID, 0, 1);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length, FILE_ID)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.bin' });

    expect(result.success).toBe(true);
    expect(result.blobUrl).toBeDefined();
    expect(result.hashVerification).toBe('skipped');
  });
});

// ── Owner download path tests ───────────────────────────────────────────────

describe('StreamingDownloadManager - owner download path', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
    disableServiceWorker();
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('returns failure with no blobUrl when metadata fetch fails', async () => {
    setFetchMock(async () => new Response('server error', { status: 500 }));

    const fek = randomBytes(32);
    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      accountKey: fek,
      showProgressUI: false,
    });

    const result = await manager.downloadFile(FAKE_FILE_ID, fek);

    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
    expect(result.error).toBeDefined();
  });

  test('returns failure when account key is missing', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('test data');
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FAKE_FILE_ID, 0, 1);

    setFetchMock(async (url: string) => {
      if (url.includes('/meta')) {
        return new Response(JSON.stringify({
          file_id: FAKE_FILE_ID,
          owner_username: 'someowner',
          encrypted_filename: 'AAAAAAAAAAAAAAAA',
          filename_nonce: btoa(String.fromCharCode(...new Uint8Array(12))),
          encrypted_sha256sum: 'AAAAAAAAAAAAAAAA',
          sha256sum_nonce: btoa(String.fromCharCode(...new Uint8Array(12))),
          encrypted_fek: '',
          password_hint: '',
          password_type: 'account',
          size_bytes: plaintext.length,
          chunk_size: plaintext.length,
          total_chunks: 1,
          chunk_count: 1,
          chunk_size_bytes: plaintext.length,
          encrypted_file_sha256: false,
        }), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    });

    // No accountKey provided -- metadata decryption will fail
    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadFile(FAKE_FILE_ID, fek);

    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
  });
});

// ── StreamingDownloadResult shape ───────────────────────────────────────────

describe('StreamingDownloadResult shape', () => {
  test('error results have no blobUrl, no filename, no streamedViaSw, no hashVerification', async () => {
    const origFetch = globalThis.fetch;
    disableServiceWorker();
    setFetchMock(async () => new Response('server error', { status: 500 }));

    const fek = randomBytes(32);
    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      accountKey: fek,
      showProgressUI: false,
    });

    const result = await manager.downloadFile('nonexistent', fek);

    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
    expect(result.filename).toBeUndefined();
    expect(result.streamedViaSw).toBeUndefined();
    expect(result.hashVerification).toBeUndefined();

    globalThis.fetch = origFetch;
  });
});

// ── SW DataCloneError Fallback Path Tests ───────────────────────────────────

describe('StreamingDownloadManager - SW DataCloneError Fallback', () => {
  let origFetch: typeof globalThis.fetch;
  let origNavigator: any;

  beforeEach(() => {
    origFetch = globalThis.fetch;
    origNavigator = (globalThis as any).navigator;
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
    (globalThis as any).navigator = origNavigator;
  });

  test('falls back to Blob download when swStreamDownload throws a DataCloneError', async () => {
    // 1. Mock the Service Worker to report as available/active
    const controller = {
      postMessage: () => {
        // Old browser environment: throwing a synchronous DataCloneError simulated via DOMException
        throw new DOMException('The object cannot be cloned.', 'DataCloneError');
      }
    };
    (globalThis as any).navigator = {
      serviceWorker: {
        controller,
        register: async () => ({ active: { state: 'activated' } }),
      }
    };

    // 2. Prepare test data and mocks
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('safari clone fallback test');
    const FILE_ID = 'test-safari-fallback';
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek, FILE_ID, 0, 1);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length, FILE_ID)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(encryptedChunk.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    // 3. Trigger download
    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'safari-test.bin' });

    // 4. Verify fallback occurred successfully
    expect(result.success).toBe(true);
    expect(result.streamedViaSw).toBeFalsy(); // should not have streamed via SW
    expect(result.blobUrl).toBeDefined(); // should have generated a Blob url instead!
    expect(result.blobUrl!.startsWith('blob:')).toBe(true);
  });
});
