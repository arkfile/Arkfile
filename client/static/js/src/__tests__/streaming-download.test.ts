/**
 * Tests for streaming-download.ts
 *
 * Covers:
 * - FSAPI path: showSaveFilePicker + FileSystemWritableFileStream, writes chunks to disk
 * - Blob fallback path: incremental Blob construction, returns blobUrl
 * - Error and cancellation handling
 */

import './setup';
import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { StreamingDownloadManager } from '../files/streaming-download';
import { randomBytes } from '../crypto/primitives';

// ── Helpers ────────────────────────────────────────────────────────────────

async function buildEncryptedChunk(plaintext: Uint8Array, rawKey: Uint8Array): Promise<Uint8Array> {
  const keyBuf = rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ptBuf = plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength) as ArrayBuffer;
  const ciphertextWithTag = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, ptBuf));
  const result = new Uint8Array(12 + ciphertextWithTag.length);
  result.set(nonce, 0);
  result.set(ciphertextWithTag, 12);
  return result;
}

function addEnvelopeHeader(chunk: Uint8Array): Uint8Array {
  const result = new Uint8Array(2 + chunk.length);
  result[0] = 0x01;
  result[1] = 0x00;
  result.set(chunk, 2);
  return result;
}

/** Build a minimal valid share metadata response */
function makeShareMeta(totalBytes: number, chunkCount: number, chunkSizeBytes: number) {
  return {
    file_id: 'test-share-file',
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

// ── FSAPI path tests ────────────────────────────────────────────────────────

describe('StreamingDownloadManager — FSAPI path (Chromium/Brave/Edge)', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('downloadSharedFile uses FSAPI when fsapiHandlePromise is provided', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hello large file streaming');
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek);
    const withHeader = addEnvelopeHeader(encryptedChunk);

    // Track what was written to the mock writable stream
    const writtenChunks: Uint8Array[] = [];
    let closeCalled = false;
    let abortCalled = false;

    const mockWritable = {
      write: mock(async (chunk: Uint8Array) => { writtenChunks.push(chunk); }),
      close: mock(async () => { closeCalled = true; }),
      abort: mock(async () => { abortCalled = true; }),
    };
    const mockHandle = {
      createWritable: mock(async () => mockWritable),
    };
    const fsapiHandlePromise = Promise.resolve(mockHandle as unknown as FileSystemFileHandle);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(withHeader.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
      fsapiHandlePromise,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.iso' });

    expect(result.success).toBe(true);
    expect(result.savedViaFileSystemAPI).toBe(true);
    expect(result.blobUrl).toBeUndefined();
    expect(closeCalled).toBe(true);
    expect(abortCalled).toBe(false);
    expect(writtenChunks.length).toBe(1);
    // Verify the written chunk matches the original plaintext
    expect(writtenChunks[0]).toEqual(plaintext);
  });

  test('downloadSharedFile returns cancelled error when FSAPI picker is dismissed', async () => {
    const fek = randomBytes(32);

    // Simulate user dismissing the save dialog (AbortError)
    const abortError = new DOMException('The user aborted a request.', 'AbortError');
    const fsapiHandlePromise = Promise.reject(abortError);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(100, 1, 100)), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
      fsapiHandlePromise,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.iso' });

    expect(result.success).toBe(false);
    expect(result.error).toBe('Download cancelled');
    expect(result.savedViaFileSystemAPI).toBeUndefined();
    expect(result.blobUrl).toBeUndefined();
  });

  test('downloadSharedFile FSAPI path aborts writable on chunk write error', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('chunk data');
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek);
    const withHeader = addEnvelopeHeader(encryptedChunk);

    let abortCalled = false;
    const mockWritable = {
      write: mock(async (_chunk: Uint8Array) => { throw new Error('Disk write error'); }),
      close: mock(async () => {}),
      abort: mock(async () => { abortCalled = true; }),
    };
    const mockHandle = {
      createWritable: mock(async () => mockWritable),
    };
    const fsapiHandlePromise = Promise.resolve(mockHandle as unknown as FileSystemFileHandle);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(withHeader.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
      fsapiHandlePromise,
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.iso' });

    expect(result.success).toBe(false);
    expect(abortCalled).toBe(true);
  });
});

// ── Blob fallback path tests ────────────────────────────────────────────────

describe('StreamingDownloadManager — Blob fallback path (Firefox)', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('returns a blobUrl when no FSAPI handle is provided', async () => {
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hello streaming world');
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek);
    const withHeader = addEnvelopeHeader(encryptedChunk);

    setFetchMock(withChunkingConfig(async (url: string) => {
      if (url.includes('/metadata')) {
        return new Response(JSON.stringify(makeShareMeta(plaintext.length, 1, plaintext.length)), { status: 200 });
      }
      if (url.includes('/chunks/0')) {
        return new Response(withHeader.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }));

    const manager = new StreamingDownloadManager('', {
      downloadToken: FAKE_DOWNLOAD_TOKEN,
      showProgressUI: false,
      // No fsapiHandlePromise — falls back to Blob path
    });

    const result = await manager.downloadSharedFile(FAKE_SHARE_ID, fek, { filename: 'test.bin' });

    expect(result.success).toBe(true);
    expect(result.savedViaFileSystemAPI).toBeFalsy();
    expect(result.blobUrl).toBeDefined();
    expect(typeof result.blobUrl).toBe('string');
    expect(result.blobUrl!.startsWith('blob:')).toBe(true);
  });

  test('returns failure with no blobUrl when metadata fetch fails', async () => {
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
    expect(result.savedViaFileSystemAPI).toBeUndefined();
    expect(result.error).toBeDefined();
  });
});

// ── Owner download path tests ───────────────────────────────────────────────

describe('StreamingDownloadManager — owner download path', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
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
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek);
    const withHeader = addEnvelopeHeader(encryptedChunk);

    setFetchMock(async (url: string) => {
      if (url.includes('/meta')) {
        return new Response(JSON.stringify({
          file_id: FAKE_FILE_ID,
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
        return new Response(withHeader.buffer as ArrayBuffer, { status: 200 });
      }
      return new Response('not found', { status: 404 });
    });

    // No accountKey provided — metadata decryption will fail
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
  test('error results have no blobUrl, no filename, and no savedViaFileSystemAPI', async () => {
    const origFetch = globalThis.fetch;
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
    expect(result.savedViaFileSystemAPI).toBeUndefined();

    globalThis.fetch = origFetch;
  });
});
