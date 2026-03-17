/**
 * Unit Tests -- AES-GCM Chunk Decryptor
 *
 * Tests for: AESGCMDecryptor.fromRawKey, decryptChunk, decryptChunks, verifyChunk
 *
 * Chunk format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
 *
 * Requires fetch mock for getChunkingParams() which calls /api/config/chunking.
 * Uses Web Crypto API (provided natively by Bun) for test encryption.
 */

import './setup';
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { randomBytes } from '../crypto/primitives';

// ============================================================================
// Fetch mock -- returns production chunking config
// ============================================================================

const originalFetch = globalThis.fetch;

const CHUNKING_CONFIG = {
  plaintextChunkSizeBytes: 16777216,
  envelope: {
    version: 1,
    headerSizeBytes: 2,
    keyTypes: { account: 1, custom: 2 },
  },
  aesGcm: {
    nonceSizeBytes: 12,
    tagSizeBytes: 16,
    keySizeBytes: 32,
  },
};

function installFetchMock(): void {
  (globalThis as any).fetch = async (url: string | URL | Request) => {
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
    if (urlStr.includes('/api/config/chunking')) {
      return new Response(JSON.stringify(CHUNKING_CONFIG), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(url as any);
  };
}

function removeFetchMock(): void {
  globalThis.fetch = originalFetch;
}

beforeAll(() => installFetchMock());
afterAll(() => removeFetchMock());

// Import after fetch mock is installed (getChunkingParams caches on first call)
import { AESGCMDecryptor, verifyChunk } from '../crypto/aes-gcm';

// ============================================================================
// Helper: encrypt a chunk in the expected format using Web Crypto
// Output: [nonce(12)][ciphertext][tag(16)]
// ============================================================================

async function encryptChunk(plaintext: Uint8Array, rawKey: Uint8Array): Promise<Uint8Array> {
  // Copy into fresh ArrayBuffer to satisfy Web Crypto BufferSource types
  const keyBuf = new Uint8Array(rawKey).buffer as ArrayBuffer;
  const key = await crypto.subtle.importKey(
    'raw',
    keyBuf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ptBuf = new Uint8Array(plaintext).buffer as ArrayBuffer;
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    ptBuf
  );
  // Web Crypto returns ciphertext + tag concatenated
  const ciphertextWithTag = new Uint8Array(encrypted);
  // Output format: [nonce][ciphertext+tag]
  const result = new Uint8Array(12 + ciphertextWithTag.length);
  result.set(nonce, 0);
  result.set(ciphertextWithTag, 12);
  return result;
}

// ============================================================================
// AESGCMDecryptor.fromRawKey
// ============================================================================

describe('AESGCMDecryptor.fromRawKey', () => {
  test('creates instance from 32-byte key', async () => {
    const key = randomBytes(32);
    const decryptor = await AESGCMDecryptor.fromRawKey(key);
    expect(decryptor).toBeDefined();
  });

  test('rejects non-32-byte key', async () => {
    await expect(AESGCMDecryptor.fromRawKey(randomBytes(16))).rejects.toThrow('Invalid key length');
    await expect(AESGCMDecryptor.fromRawKey(randomBytes(64))).rejects.toThrow('Invalid key length');
    await expect(AESGCMDecryptor.fromRawKey(new Uint8Array(0))).rejects.toThrow('Invalid key length');
  });
});

// ============================================================================
// AESGCMDecryptor.decryptChunk
// ============================================================================

describe('AESGCMDecryptor.decryptChunk', () => {
  test('round-trip: encrypt then decrypt recovers plaintext', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('Hello, Arkfile chunked encryption!');

    const encrypted = await encryptChunk(plaintext, key);
    const decryptor = await AESGCMDecryptor.fromRawKey(key);
    const decrypted = await decryptor.decryptChunk(encrypted);

    expect(decrypted).toEqual(plaintext);
  });

  test('round-trip with empty plaintext', async () => {
    const key = randomBytes(32);
    const plaintext = new Uint8Array(0);

    const encrypted = await encryptChunk(plaintext, key);
    const decryptor = await AESGCMDecryptor.fromRawKey(key);
    const decrypted = await decryptor.decryptChunk(encrypted);

    expect(decrypted).toEqual(plaintext);
  });

  test('rejects too-small chunk', async () => {
    const key = randomBytes(32);
    const decryptor = await AESGCMDecryptor.fromRawKey(key);

    // Overhead is nonce(12) + tag(16) = 28 bytes minimum
    const tooSmall = new Uint8Array(27);
    await expect(decryptor.decryptChunk(tooSmall)).rejects.toThrow('too small');
  });

  test('wrong key fails decryption', async () => {
    const correctKey = randomBytes(32);
    const wrongKey = randomBytes(32);
    const plaintext = new TextEncoder().encode('secret data');

    const encrypted = await encryptChunk(plaintext, correctKey);
    const decryptor = await AESGCMDecryptor.fromRawKey(wrongKey);

    await expect(decryptor.decryptChunk(encrypted)).rejects.toThrow('Decryption failed');
  });
});

// ============================================================================
// AESGCMDecryptor.decryptChunks
// ============================================================================

describe('AESGCMDecryptor.decryptChunks', () => {
  test('decrypts multiple chunks with progress callback', async () => {
    const key = randomBytes(32);
    const plaintexts = [
      new TextEncoder().encode('chunk one'),
      new TextEncoder().encode('chunk two'),
      new TextEncoder().encode('chunk three'),
    ];

    const encryptedChunks = await Promise.all(
      plaintexts.map(pt => encryptChunk(pt, key))
    );

    const decryptor = await AESGCMDecryptor.fromRawKey(key);

    const progressCalls: Array<[number, number]> = [];
    const decrypted = await decryptor.decryptChunks(encryptedChunks, (completed, total) => {
      progressCalls.push([completed, total]);
    });

    // Verify all chunks decrypted correctly
    expect(decrypted.length).toBe(3);
    for (let i = 0; i < plaintexts.length; i++) {
      expect(decrypted[i]).toEqual(plaintexts[i]);
    }

    // Verify progress callback fired correctly
    expect(progressCalls).toEqual([
      [1, 3],
      [2, 3],
      [3, 3],
    ]);
  });
});

// ============================================================================
// verifyChunk (convenience function)
// ============================================================================

describe('verifyChunk', () => {
  test('returns true for valid chunk', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('verify me');
    const encrypted = await encryptChunk(plaintext, key);

    const valid = await verifyChunk(encrypted, key);
    expect(valid).toBe(true);
  });

  test('returns false for tampered chunk', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('tamper test');
    const encrypted = await encryptChunk(plaintext, key);

    // Tamper with a byte in the ciphertext region (after the 12-byte nonce)
    encrypted[14] ^= 0xff;

    const valid = await verifyChunk(encrypted, key);
    expect(valid).toBe(false);
  });
});
