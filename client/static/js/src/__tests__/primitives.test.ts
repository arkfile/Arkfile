/**
 * Unit Tests — Cryptographic Primitives
 *
 * Tests for: randomBytes, hash256, hash512, hashString, toBase64/fromBase64,
 * toHex/fromHex, constantTimeEqual, secureWipe, concatBytes,
 * encryptAESGCM/decryptAESGCM, deriveKeyArgon2id
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import {
  randomBytes,
  generateIV,
  generateSalt,
  hash256,
  hash512,
  hashString,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  constantTimeEqual,
  secureWipe,
  concatBytes,
  encryptAESGCM,
  decryptAESGCM,
  deriveKeyArgon2id,
  isWebCryptoAvailable,
} from '../crypto/primitives';

// ============================================================================
// Web Crypto availability
// ============================================================================

describe('isWebCryptoAvailable', () => {
  test('returns true in Bun (has crypto.subtle)', () => {
    expect(isWebCryptoAvailable()).toBe(true);
  });
});

// ============================================================================
// Random generation
// ============================================================================

describe('randomBytes', () => {
  test('returns correct length', () => {
    expect(randomBytes(32).length).toBe(32);
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(1).length).toBe(1);
  });

  test('two calls produce different output (probabilistic)', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('generateIV', () => {
  test('returns 12 bytes', () => {
    expect(generateIV().length).toBe(12);
  });
});

describe('generateSalt', () => {
  test('returns 32 bytes', () => {
    expect(generateSalt().length).toBe(32);
  });
});

// ============================================================================
// Hashing
// ============================================================================

describe('hash256', () => {
  test('produces 32-byte output', () => {
    const h = hash256(new Uint8Array([1, 2, 3]));
    expect(h.length).toBe(32);
  });

  test('is deterministic', () => {
    const input = new TextEncoder().encode('hello');
    const a = hash256(input);
    const b = hash256(input);
    expect(toHex(a)).toBe(toHex(b));
  });

  test('matches known SHA-256 vector', () => {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const h = hash256(new Uint8Array(0));
    expect(toHex(h)).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('hash512', () => {
  test('produces 64-byte output', () => {
    const h = hash512(new Uint8Array([1, 2, 3]));
    expect(h.length).toBe(64);
  });

  test('matches known SHA-512 vector for empty input', () => {
    // SHA-512("") = cf83e1357eefb8bd...
    const h = hash512(new Uint8Array(0));
    expect(toHex(h).startsWith('cf83e1357eefb8bd')).toBe(true);
  });
});

describe('hashString', () => {
  test('hashes UTF-8 string to 32 bytes', () => {
    const h = hashString('test');
    expect(h.length).toBe(32);
  });

  test('is deterministic', () => {
    expect(toHex(hashString('foo'))).toBe(toHex(hashString('foo')));
  });

  test('different inputs produce different hashes', () => {
    expect(toHex(hashString('a'))).not.toBe(toHex(hashString('b')));
  });
});

// ============================================================================
// Encoding: Base64
// ============================================================================

describe('toBase64 / fromBase64', () => {
  test('round-trips arbitrary bytes', () => {
    const original = randomBytes(64);
    const encoded = toBase64(original);
    const decoded = fromBase64(encoded);
    expect(toHex(decoded)).toBe(toHex(original));
  });

  test('round-trips empty array', () => {
    const empty = new Uint8Array(0);
    expect(fromBase64(toBase64(empty)).length).toBe(0);
  });

  test('round-trips known value', () => {
    const data = new TextEncoder().encode('Hello, World!');
    const b64 = toBase64(data);
    expect(b64).toBe('SGVsbG8sIFdvcmxkIQ==');
    const back = fromBase64(b64);
    expect(new TextDecoder().decode(back)).toBe('Hello, World!');
  });
});

// ============================================================================
// Encoding: Hex
// ============================================================================

describe('toHex / fromHex', () => {
  test('round-trips arbitrary bytes', () => {
    const original = randomBytes(48);
    const hex = toHex(original);
    const decoded = fromHex(hex);
    expect(toHex(decoded)).toBe(hex);
  });

  test('produces lowercase hex', () => {
    const data = new Uint8Array([0xab, 0xcd, 0xef]);
    expect(toHex(data)).toBe('abcdef');
  });

  test('fromHex rejects odd-length strings', () => {
    expect(() => fromHex('abc')).toThrow('Invalid hex string length');
  });

  test('round-trips empty', () => {
    expect(toHex(fromHex(''))).toBe('');
  });
});

// ============================================================================
// Utility: constantTimeEqual
// ============================================================================

describe('constantTimeEqual', () => {
  test('returns true for identical arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  test('returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 5]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  test('returns false for different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  test('returns true for empty arrays', () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

// ============================================================================
// Utility: secureWipe
// ============================================================================

describe('secureWipe', () => {
  test('zeroes out the array', () => {
    const data = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
    secureWipe(data);
    expect(data.every(b => b === 0)).toBe(true);
  });
});

// ============================================================================
// Utility: concatBytes
// ============================================================================

describe('concatBytes', () => {
  test('concatenates multiple arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);
    const c = new Uint8Array([5]);
    const result = concatBytes(a, b, c);
    expect(Array.from(result)).toEqual([1, 2, 3, 4, 5]);
  });

  test('handles empty arrays', () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array([1]);
    expect(Array.from(concatBytes(a, b))).toEqual([1]);
  });

  test('handles no arguments', () => {
    expect(concatBytes().length).toBe(0);
  });
});

// ============================================================================
// AES-GCM encrypt / decrypt round-trip
// ============================================================================

describe('encryptAESGCM / decryptAESGCM', () => {
  test('round-trips plaintext', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('secret message');

    const encrypted = await encryptAESGCM({ key, data: plaintext });
    expect(encrypted.ciphertext.length).toBeGreaterThan(0);
    expect(encrypted.iv.length).toBe(12);
    expect(encrypted.tag.length).toBe(16);

    const decrypted = await decryptAESGCM({
      key,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('secret message');
  });

  test('wrong key fails decryption', async () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const plaintext = new TextEncoder().encode('data');

    const encrypted = await encryptAESGCM({ key: key1, data: plaintext });

    await expect(
      decryptAESGCM({
        key: key2,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        tag: encrypted.tag,
      })
    ).rejects.toThrow();
  });

  test('tampered ciphertext fails decryption', async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode('data');

    const encrypted = await encryptAESGCM({ key, data: plaintext });

    // Flip a bit in ciphertext
    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[0] ^= 0xff;

    await expect(
      decryptAESGCM({
        key,
        ciphertext: tampered,
        iv: encrypted.iv,
        tag: encrypted.tag,
      })
    ).rejects.toThrow();
  });

  test('rejects invalid key length', async () => {
    const shortKey = randomBytes(16); // should be 32
    const data = new Uint8Array([1, 2, 3]);

    await expect(encryptAESGCM({ key: shortKey, data })).rejects.toThrow();
  });

  test('round-trips empty plaintext', async () => {
    const key = randomBytes(32);
    const plaintext = new Uint8Array(0);

    const encrypted = await encryptAESGCM({ key, data: plaintext });
    const decrypted = await decryptAESGCM({
      key,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
    expect(decrypted.plaintext.length).toBe(0);
  });
});

// ============================================================================
// Argon2id key derivation
// ============================================================================

describe('deriveKeyArgon2id', () => {
  // Use minimal params for fast tests
  const fastParams = {
    memoryCost: 1024,  // 1 MiB — minimum allowed
    timeCost: 1,
    parallelism: 1,
    keyLength: 32,
    variant: 2 as const,
  };

  test('produces 32-byte key', async () => {
    const result = await deriveKeyArgon2id({
      password: 'TestPassword123!!',
      salt: randomBytes(32),
      params: fastParams,
    });
    expect(result.key.length).toBe(32);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  test('is deterministic (same inputs → same key)', async () => {
    const salt = new Uint8Array(32).fill(0xaa);
    const r1 = await deriveKeyArgon2id({ password: 'TestPassword123!!', salt, params: fastParams });
    const r2 = await deriveKeyArgon2id({ password: 'TestPassword123!!', salt, params: fastParams });
    expect(toHex(r1.key)).toBe(toHex(r2.key));
  });

  test('different passwords → different keys', async () => {
    const salt = randomBytes(32);
    const r1 = await deriveKeyArgon2id({ password: 'AlphaPassword99!!', salt, params: fastParams });
    const r2 = await deriveKeyArgon2id({ password: 'BravoPassword99!!', salt, params: fastParams });
    expect(toHex(r1.key)).not.toBe(toHex(r2.key));
  });

  test('different salts → different keys', async () => {
    const s1 = new Uint8Array(32).fill(0x01);
    const s2 = new Uint8Array(32).fill(0x02);
    const r1 = await deriveKeyArgon2id({ password: 'TestPassword123!!', salt: s1, params: fastParams });
    const r2 = await deriveKeyArgon2id({ password: 'TestPassword123!!', salt: s2, params: fastParams });
    expect(toHex(r1.key)).not.toBe(toHex(r2.key));
  });

  test('rejects memoryCost < 1024', async () => {
    await expect(
      deriveKeyArgon2id({
        password: 'TestPassword123!!',
        salt: randomBytes(32),
        params: { ...fastParams, memoryCost: 512 },
      })
    ).rejects.toThrow('Memory cost must be at least 1024');
  });

  test('rejects timeCost < 1', async () => {
    await expect(
      deriveKeyArgon2id({
        password: 'TestPassword123!!',
        salt: randomBytes(32),
        params: { ...fastParams, timeCost: 0 },
      })
    ).rejects.toThrow('Time cost must be at least 1');
  });

  test('rejects parallelism < 1', async () => {
    await expect(
      deriveKeyArgon2id({
        password: 'TestPassword123!!',
        salt: randomBytes(32),
        params: { ...fastParams, parallelism: 0 },
      })
    ).rejects.toThrow('Parallelism must be at least 1');
  });

  test('rejects keyLength out of range', async () => {
    await expect(
      deriveKeyArgon2id({
        password: 'TestPassword123!!',
        salt: randomBytes(32),
        params: { ...fastParams, keyLength: 8 },
      })
    ).rejects.toThrow('Key length must be between 16 and 64');
  });
});
