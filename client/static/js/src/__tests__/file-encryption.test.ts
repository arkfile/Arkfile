/**
 * Unit Tests — File Encryption (Salt Derivation + Key Derivation)
 *
 * Tests for: deriveSaltFromUsername, deriveFileEncryptionKey
 * These are the core functions that enable offline decryption and
 * cross-platform compatibility with the Go CLI.
 *
 * Username constraints (must match Go server):
 *   MinUsernameLength = 10
 *   MaxUsernameLength = 50
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import {
  deriveSaltFromUsername,
  deriveFileEncryptionKey,
} from '../crypto/file-encryption';
import { toHex, hashString } from '../crypto/primitives';
import { InvalidUsernameError } from '../crypto/errors';

// ============================================================================
// deriveSaltFromUsername
// ============================================================================

describe('deriveSaltFromUsername', () => {
  test('returns 32-byte Uint8Array', () => {
    const salt = deriveSaltFromUsername('testuser01');
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(32);
  });

  test('is deterministic', () => {
    const a = deriveSaltFromUsername('alicealice');
    const b = deriveSaltFromUsername('alicealice');
    expect(toHex(a)).toBe(toHex(b));
  });

  test('different usernames → different salts', () => {
    const a = deriveSaltFromUsername('alicealice');
    const b = deriveSaltFromUsername('bobbobbobb');
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('different contexts → different salts', () => {
    const account = deriveSaltFromUsername('testuser01', 'account');
    const custom = deriveSaltFromUsername('testuser01', 'custom');
    expect(toHex(account)).not.toBe(toHex(custom));
  });

  test('default context is account', () => {
    const defaultSalt = deriveSaltFromUsername('testuser01');
    const accountSalt = deriveSaltFromUsername('testuser01', 'account');
    expect(toHex(defaultSalt)).toBe(toHex(accountSalt));
  });

  test('matches manual SHA-256 computation', () => {
    // deriveSaltFromUsername("testuser01", "account") should equal:
    // SHA-256("arkfile-account-key-salt:testuser01")[0:32]
    const expected = hashString('arkfile-account-key-salt:testuser01').slice(0, 32);
    const actual = deriveSaltFromUsername('testuser01', 'account');
    expect(toHex(actual)).toBe(toHex(expected));
  });

  test('custom context matches manual computation', () => {
    const expected = hashString('arkfile-custom-key-salt:testuser01').slice(0, 32);
    const actual = deriveSaltFromUsername('testuser01', 'custom');
    expect(toHex(actual)).toBe(toHex(expected));
  });

  test('trims whitespace from username', () => {
    const a = deriveSaltFromUsername('  testuser01  ');
    const b = deriveSaltFromUsername('testuser01');
    expect(toHex(a)).toBe(toHex(b));
  });

  test('does NOT lowercase (matches Go behavior)', () => {
    const upper = deriveSaltFromUsername('TestUser01');
    const lower = deriveSaltFromUsername('testuser01');
    // Go does NOT normalize to lowercase, so these should differ
    expect(toHex(upper)).not.toBe(toHex(lower));
  });

  // --- Validation errors ---

  test('throws InvalidUsernameError for empty string', () => {
    expect(() => deriveSaltFromUsername('')).toThrow(InvalidUsernameError);
  });

  test('throws InvalidUsernameError for whitespace-only', () => {
    expect(() => deriveSaltFromUsername('   ')).toThrow(InvalidUsernameError);
  });

  test('throws InvalidUsernameError for username < 10 chars', () => {
    expect(() => deriveSaltFromUsername('abcdefghi')).toThrow(InvalidUsernameError);
  });

  test('throws InvalidUsernameError for username > 50 chars', () => {
    const longName = 'a'.repeat(51);
    expect(() => deriveSaltFromUsername(longName)).toThrow(InvalidUsernameError);
  });

  test('accepts exactly 10-char username', () => {
    const salt = deriveSaltFromUsername('abcdefghij');
    expect(salt.length).toBe(32);
  });

  test('accepts exactly 50-char username', () => {
    const salt = deriveSaltFromUsername('a'.repeat(50));
    expect(salt.length).toBe(32);
  });
});

// ============================================================================
// deriveFileEncryptionKey
// ============================================================================

describe('deriveFileEncryptionKey', () => {
  // NOTE: These tests call the real Argon2id via getArgon2Params() which
  // fetches from /api/config/argon2. In unit test mode (no server), this
  // will fail. We mock the fetch to return minimal params.

  // Mock fetch for Argon2 config endpoint
  const originalFetch = globalThis.fetch;

  const mockArgon2Config = {
    memoryCostKiB: 1024,
    timeCost: 1,
    parallelism: 1,
    keyLength: 32,
  };

  function installFetchMock(): void {
    (globalThis as any).fetch = async (url: string | URL | Request) => {
      const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
      if (urlStr.includes('/api/config/argon2')) {
        return new Response(JSON.stringify(mockArgon2Config), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (urlStr.includes('/api/config/chunking')) {
        return new Response(JSON.stringify({
          plaintextChunkSizeBytes: 65536,
          envelope: { version: 1, headerSizeBytes: 5, keyTypes: { account: 1, custom: 2 } },
          aesGcm: { nonceSizeBytes: 12, tagSizeBytes: 16, keySizeBytes: 32 },
        }), {
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

  // Install mock before these tests
  test('produces 32-byte key', async () => {
    installFetchMock();
    try {
      const key = await deriveFileEncryptionKey('Password12345!!!', 'testuser01');
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    } finally {
      removeFetchMock();
    }
  });

  test('is deterministic (same password + username → same key)', async () => {
    installFetchMock();
    try {
      const k1 = await deriveFileEncryptionKey('MyTestPassword1!!', 'alicealice');
      const k2 = await deriveFileEncryptionKey('MyTestPassword1!!', 'alicealice');
      expect(toHex(k1)).toBe(toHex(k2));
    } finally {
      removeFetchMock();
    }
  });

  test('different passwords → different keys', async () => {
    installFetchMock();
    try {
      const k1 = await deriveFileEncryptionKey('PasswordAlpha99!!', 'testuser01');
      const k2 = await deriveFileEncryptionKey('PasswordBravo99!!', 'testuser01');
      expect(toHex(k1)).not.toBe(toHex(k2));
    } finally {
      removeFetchMock();
    }
  });

  test('different usernames → different keys', async () => {
    installFetchMock();
    try {
      const k1 = await deriveFileEncryptionKey('SamePassword123!!', 'alicealice');
      const k2 = await deriveFileEncryptionKey('SamePassword123!!', 'bobbobbobb');
      expect(toHex(k1)).not.toBe(toHex(k2));
    } finally {
      removeFetchMock();
    }
  });

  test('different contexts → different keys', async () => {
    installFetchMock();
    try {
      const k1 = await deriveFileEncryptionKey('GenericPasswd99!!', 'testuser01', 'account');
      const k2 = await deriveFileEncryptionKey('GenericPasswd99!!', 'testuser01', 'custom');
      expect(toHex(k1)).not.toBe(toHex(k2));
    } finally {
      removeFetchMock();
    }
  });

  test('rejects invalid username', async () => {
    installFetchMock();
    try {
      await expect(deriveFileEncryptionKey('GenericPasswd99!!', '')).rejects.toThrow(InvalidUsernameError);
    } finally {
      removeFetchMock();
    }
  });
});
