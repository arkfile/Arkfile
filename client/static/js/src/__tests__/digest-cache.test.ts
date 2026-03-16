/**
 * Unit Tests — Digest Cache (Client-Side Deduplication)
 *
 * Tests for: addDigest, checkDuplicate, removeDigest, clearDigestCache,
 * populateDigestCache
 *
 * The digest cache stores fileId → plaintextSHA256 hex mappings in
 * sessionStorage. It enables pre-upload duplicate detection without
 * ever sending plaintext hashes to the server.
 */

import './setup';
import { describe, test, expect, beforeEach } from 'bun:test';
import { resetMocks } from './setup';
import {
  addDigest,
  checkDuplicate,
  removeDigest,
  clearDigestCache,
  populateDigestCache,
} from '../utils/digest-cache';
import {
  randomBytes,
  toHex,
  encryptAESGCM,
  toBase64,
} from '../crypto/primitives';

// ============================================================================
// Setup — clean slate before each test
// ============================================================================

beforeEach(() => {
  resetMocks();
});

// ============================================================================
// addDigest + checkDuplicate
// ============================================================================

describe('addDigest / checkDuplicate', () => {
  test('finds a duplicate after addDigest', () => {
    const fileId = 'file-001';
    const sha256Hex = toHex(randomBytes(32));

    addDigest(fileId, sha256Hex);

    const result = checkDuplicate(sha256Hex);
    expect(result).toBe(fileId);
  });

  test('returns null when no duplicate exists', () => {
    const sha256Hex = toHex(randomBytes(32));
    const result = checkDuplicate(sha256Hex);
    expect(result).toBeNull();
  });

  test('returns null for different digest', () => {
    const fileId = 'file-001';
    const sha256a = toHex(randomBytes(32));
    const sha256b = toHex(randomBytes(32));

    addDigest(fileId, sha256a);

    const result = checkDuplicate(sha256b);
    expect(result).toBeNull();
  });

  test('handles multiple entries', () => {
    const sha1 = toHex(randomBytes(32));
    const sha2 = toHex(randomBytes(32));
    const sha3 = toHex(randomBytes(32));

    addDigest('file-001', sha1);
    addDigest('file-002', sha2);
    addDigest('file-003', sha3);

    expect(checkDuplicate(sha1)).toBe('file-001');
    expect(checkDuplicate(sha2)).toBe('file-002');
    expect(checkDuplicate(sha3)).toBe('file-003');
  });

  test('overwrites existing entry for same fileId', () => {
    const sha1 = toHex(randomBytes(32));
    const sha2 = toHex(randomBytes(32));

    addDigest('file-001', sha1);
    addDigest('file-001', sha2);

    // Old digest should no longer match
    expect(checkDuplicate(sha1)).toBeNull();
    // New digest should match
    expect(checkDuplicate(sha2)).toBe('file-001');
  });
});

// ============================================================================
// removeDigest
// ============================================================================

describe('removeDigest', () => {
  test('removes a specific entry', () => {
    const sha256Hex = toHex(randomBytes(32));
    addDigest('file-001', sha256Hex);

    removeDigest('file-001');

    expect(checkDuplicate(sha256Hex)).toBeNull();
  });

  test('does not affect other entries', () => {
    const sha1 = toHex(randomBytes(32));
    const sha2 = toHex(randomBytes(32));

    addDigest('file-001', sha1);
    addDigest('file-002', sha2);

    removeDigest('file-001');

    expect(checkDuplicate(sha1)).toBeNull();
    expect(checkDuplicate(sha2)).toBe('file-002');
  });

  test('is a no-op for non-existent fileId', () => {
    const sha256Hex = toHex(randomBytes(32));
    addDigest('file-001', sha256Hex);

    // Should not throw
    removeDigest('file-999');

    expect(checkDuplicate(sha256Hex)).toBe('file-001');
  });
});

// ============================================================================
// clearDigestCache
// ============================================================================

describe('clearDigestCache', () => {
  test('removes all entries', () => {
    const sha1 = toHex(randomBytes(32));
    const sha2 = toHex(randomBytes(32));

    addDigest('file-001', sha1);
    addDigest('file-002', sha2);

    clearDigestCache();

    expect(checkDuplicate(sha1)).toBeNull();
    expect(checkDuplicate(sha2)).toBeNull();
  });

  test('is safe to call when cache is empty', () => {
    // Should not throw
    clearDigestCache();
    expect(checkDuplicate('anything')).toBeNull();
  });
});

// ============================================================================
// populateDigestCache
// ============================================================================

describe('populateDigestCache', () => {
  test('decrypts and populates from encrypted file entries', async () => {
    const accountKey = randomBytes(32);
    const plaintext1 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
    const plaintext2 = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

    // Encrypt the plaintext digests the same way upload.ts does:
    // encrypted = base64(ciphertext || tag), nonce = base64(iv)
    async function encryptField(plaintext: string, key: Uint8Array) {
      const data = new TextEncoder().encode(plaintext);
      const result = await encryptAESGCM({ key, data });
      // Concatenate ciphertext + tag (matches upload.ts encryptMetadata format)
      const combined = new Uint8Array(result.ciphertext.length + result.tag.length);
      combined.set(result.ciphertext, 0);
      combined.set(result.tag, result.ciphertext.length);
      return {
        encrypted: toBase64(combined),
        nonce: toBase64(result.iv),
      };
    }

    const enc1 = await encryptField(plaintext1, accountKey);
    const enc2 = await encryptField(plaintext2, accountKey);

    const files = [
      {
        file_id: 'file-aaa',
        encrypted_sha256sum: enc1.encrypted,
        sha256sum_nonce: enc1.nonce,
      },
      {
        file_id: 'file-bbb',
        encrypted_sha256sum: enc2.encrypted,
        sha256sum_nonce: enc2.nonce,
      },
    ];

    await populateDigestCache(accountKey, files);

    expect(checkDuplicate(plaintext1)).toBe('file-aaa');
    expect(checkDuplicate(plaintext2)).toBe('file-bbb');
  });

  test('skips entries with missing encrypted fields', async () => {
    const accountKey = randomBytes(32);

    const files = [
      {
        file_id: 'file-aaa',
        encrypted_sha256sum: '',
        sha256sum_nonce: '',
      },
    ];

    // Should not throw
    await populateDigestCache(accountKey, files);

    // Nothing should be cached
    expect(checkDuplicate('anything')).toBeNull();
  });

  test('skips entries that fail decryption (wrong key)', async () => {
    const accountKey = randomBytes(32);
    const wrongKey = randomBytes(32);

    const data = new TextEncoder().encode('somedigest');
    const result = await encryptAESGCM({ key: wrongKey, data });
    const combined = new Uint8Array(result.ciphertext.length + result.tag.length);
    combined.set(result.ciphertext, 0);
    combined.set(result.tag, result.ciphertext.length);

    const files = [
      {
        file_id: 'file-bad',
        encrypted_sha256sum: toBase64(combined),
        sha256sum_nonce: toBase64(result.iv),
      },
    ];

    // Should not throw — individual failures are non-fatal
    await populateDigestCache(accountKey, files);

    expect(checkDuplicate('somedigest')).toBeNull();
  });
});
