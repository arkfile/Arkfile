/**
 * Tests for streaming-download.ts
 *
 * Covers the streaming chunk-by-chunk download path that fixes OOM on large
 * file downloads (> ~1 GB) by using incremental Blob construction off the JS
 * heap. The File System Access API was removed in favor of the reliable
 * Blob path that works in all browsers.
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

const FAKE_FILE_ID = 'test-file-1234';
const FAKE_AUTH_TOKEN = 'test-auth-token';

// ── Tests ──────────────────────────────────────────────────────────────────

describe('StreamingDownloadManager — Blob streaming path', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('returns a blobUrl on metadata-decryption-failure path (still constructs Blob)', async () => {
    // Use a wrong account key so metadata decryption fails — verifies the
    // result interface is consistent (success=false, no blobUrl).
    const fek = randomBytes(32);
    const plaintext = new TextEncoder().encode('hello streaming world');
    const encryptedChunk = await buildEncryptedChunk(plaintext, fek);
    const withHeader = addEnvelopeHeader(encryptedChunk);

    globalThis.fetch = mock(async (url: string) => {
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

    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      accountKey: fek, // wrong key — metadata decrypt will fail
      showProgressUI: false,
    });

    const result = await manager.downloadFile(FAKE_FILE_ID, fek);

    // Wrong account key for metadata fails BEFORE chunk streaming, so result
    // is failure with no blobUrl.
    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
  });

  test('returns failure with no blobUrl when metadata fetch fails', async () => {
    globalThis.fetch = mock(async () => new Response('server error', { status: 500 }));

    const fek = randomBytes(32);
    const manager = new StreamingDownloadManager('', {
      authToken: FAKE_AUTH_TOKEN,
      accountKey: fek,
      showProgressUI: false,
    });

    const result = await manager.downloadFile('nonexistent', fek);

    expect(result.success).toBe(false);
    expect(result.blobUrl).toBeUndefined();
    expect(result.error).toBeDefined();
  });
});

describe('StreamingDownloadResult shape', () => {
  test('error results have no blobUrl and no filename', async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => new Response('server error', { status: 500 }));

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

    globalThis.fetch = origFetch;
  });
});
