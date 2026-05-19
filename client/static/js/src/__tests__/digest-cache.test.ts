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
  const OWNER = 'aliceusername'; // canonical owner_username for the test entries

  // Encrypt plaintext digests under the Phase C metadata-field AAD =
  // BuildMetadataFieldAAD(file_id, AAD_FIELD_SHA256, owner_username).
  async function encryptShaField(
    plaintext: string, key: Uint8Array, fileID: string, owner: string,
  ) {
    const { buildMetadataFieldAAD, AAD_FIELD_SHA256 } = await import('../crypto/aad');
    const data = new TextEncoder().encode(plaintext);
    const aad = buildMetadataFieldAAD(fileID, AAD_FIELD_SHA256, owner);
    const result = await encryptAESGCM({ key, data, aad });
    const combined = new Uint8Array(result.ciphertext.length + result.tag.length);
    combined.set(result.ciphertext, 0);
    combined.set(result.tag, result.ciphertext.length);
    return {
      encrypted: toBase64(combined),
      nonce: toBase64(result.iv),
    };
  }

  test('decrypts and populates from encrypted file entries', async () => {
    const accountKey = randomBytes(32);
    const plaintext1 = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
    const plaintext2 = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

    const enc1 = await encryptShaField(plaintext1, accountKey, 'file-aaa', OWNER);
    const enc2 = await encryptShaField(plaintext2, accountKey, 'file-bbb', OWNER);

    const files = [
      {
        file_id: 'file-aaa',
        owner_username: OWNER,
        encrypted_sha256sum: enc1.encrypted,
        sha256sum_nonce: enc1.nonce,
      },
      {
        file_id: 'file-bbb',
        owner_username: OWNER,
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
        owner_username: OWNER,
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

    // Encrypt under wrongKey but tag with the correct AAD shape, so that
    // populateDigestCache hits a key-mismatch failure (not an AAD failure).
    const enc = await encryptShaField('somedigest', wrongKey, 'file-bad', OWNER);

    const files = [
      {
        file_id: 'file-bad',
        owner_username: OWNER,
        encrypted_sha256sum: enc.encrypted,
        sha256sum_nonce: enc.nonce,
      },
    ];

    // Should not throw — individual failures are non-fatal
    await populateDigestCache(accountKey, files);

    expect(checkDuplicate('somedigest')).toBeNull();
  });
});
