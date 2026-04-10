/**
 * Unit Tests -- Share Crypto
 *
 * Tests for: encryptFEKForShare, decryptShareEnvelope, generateFEK,
 *            encodeFEK, decodeFEK, validateSharePasswordStrength
 *
 * Uses production Argon2id parameters (see crypto/argon2id-params.json).
 * Each encrypt/decrypt round-trip takes ~200-400ms.
 */

import './setup';
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import {
  encryptFEKForShare,
  decryptShareEnvelope,
  generateFEK,
  encodeFEK,
  decodeFEK,
} from '../shares/share-crypto';
import { toBase64, fromBase64, toHex } from '../crypto/primitives';
import { EncryptionError, DecryptionError } from '../crypto/errors';
import { KEY_SIZES } from '../crypto/constants';

// ============================================================================
// Fetch mock -- returns production Argon2 params + password requirements
// ============================================================================

const originalFetch = globalThis.fetch;

const PROD_ARGON2_CONFIG = {
  memoryCostKiB: 65536,
  timeCost: 3,
  parallelism: 1,
  keyLength: 32,
};

const PASSWORD_REQUIREMENTS = {
  minAccountPasswordLength: 15,
  minCustomPasswordLength: 15,
  minSharePasswordLength: 20,
  minCharacterClassesRequired: 2,
  specialCharacters: '`~!@#$%^&*()-_=+[]{}|;:,.<>? ',
};

function installFetchMock(): void {
  (globalThis as any).fetch = async (url: string | URL | Request) => {
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
    if (urlStr.includes('/api/config/argon2')) {
      return new Response(JSON.stringify(PROD_ARGON2_CONFIG), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (urlStr.includes('/api/config/password-requirements')) {
      return new Response(JSON.stringify(PASSWORD_REQUIREMENTS), {
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

// ============================================================================
// generateFEK / encodeFEK / decodeFEK
// ============================================================================

describe('generateFEK', () => {
  test('returns 32-byte Uint8Array', () => {
    const fek = generateFEK();
    expect(fek).toBeInstanceOf(Uint8Array);
    expect(fek.length).toBe(KEY_SIZES.FILE_ENCRYPTION_KEY);
  });

  test('returns unique values each call', () => {
    const a = generateFEK();
    const b = generateFEK();
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('encodeFEK / decodeFEK', () => {
  test('round-trip preserves bytes', () => {
    const fek = generateFEK();
    const encoded = encodeFEK(fek);
    const decoded = decodeFEK(encoded);
    expect(toHex(decoded)).toBe(toHex(fek));
  });

  test('encoded value is valid base64', () => {
    const fek = generateFEK();
    const encoded = encodeFEK(fek);
    // Should not throw
    const decoded = fromBase64(encoded);
    expect(decoded.length).toBe(32);
  });
});

// ============================================================================
// encryptFEKForShare + decryptShareEnvelope round-trip
// ============================================================================

describe('encryptFEKForShare / decryptShareEnvelope', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  const SHARE_PASSWORD = 'TestSharePassword!99';
  const SHARE_ID = 'share-abc-123';
  const FILE_ID = 'file-xyz-789';

  test('full round-trip: encrypt then decrypt recovers FEK', async () => {
    const fek = generateFEK();
    const fekHex = toHex(fek);

    const encrypted = await encryptFEKForShare(
      fek, SHARE_PASSWORD, SHARE_ID, FILE_ID
    );

    expect(encrypted.encryptedFEK).toBeTruthy();
    expect(encrypted.salt).toBeTruthy();
    expect(encrypted.downloadToken).toBeTruthy();
    expect(encrypted.downloadTokenHash).toBeTruthy();

    const decrypted = await decryptShareEnvelope(
      encrypted.encryptedFEK,
      SHARE_PASSWORD,
      SHARE_ID,
      FILE_ID,
      encrypted.salt
    );

    expect(toHex(decrypted.fek)).toBe(fekHex);
    expect(decrypted.downloadToken).toBeTruthy();
  }, 30_000);

  test('round-trip with metadata preserves filename, sizeBytes, sha256', async () => {
    const fek = generateFEK();
    const metadata = {
      filename: 'secret-document.pdf',
      sizeBytes: 1048576,
      sha256: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
    };

    const encrypted = await encryptFEKForShare(
      fek, SHARE_PASSWORD, SHARE_ID, FILE_ID, metadata
    );

    const decrypted = await decryptShareEnvelope(
      encrypted.encryptedFEK,
      SHARE_PASSWORD,
      SHARE_ID,
      FILE_ID,
      encrypted.salt
    );

    expect(decrypted.metadata).toBeDefined();
    expect(decrypted.metadata!.filename).toBe('secret-document.pdf');
    expect(decrypted.metadata!.sizeBytes).toBe(1048576);
    expect(decrypted.metadata!.sha256).toBe(metadata.sha256);
  }, 30_000);

  test('download token is present in encrypted result', async () => {
    const fek = generateFEK();
    const encrypted = await encryptFEKForShare(
      fek, SHARE_PASSWORD, SHARE_ID, FILE_ID
    );

    // downloadToken should be base64-encoded 32 bytes
    const tokenBytes = fromBase64(encrypted.downloadToken);
    expect(tokenBytes.length).toBe(32);

    // downloadTokenHash should also be base64
    const hashBytes = fromBase64(encrypted.downloadTokenHash);
    expect(hashBytes.length).toBe(32); // SHA-256 output
  }, 30_000);
});

// ============================================================================
// Input validation -- encryptFEKForShare
// ============================================================================

describe('encryptFEKForShare input validation', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  test('rejects FEK with wrong size', async () => {
    const badFek = new Uint8Array(16); // too short
    await expect(
      encryptFEKForShare(badFek, 'TestSharePassword!99', 'share-1', 'file-1')
    ).rejects.toThrow(EncryptionError);
  });

  test('rejects empty password', async () => {
    const fek = generateFEK();
    await expect(
      encryptFEKForShare(fek, '', 'share-1', 'file-1')
    ).rejects.toThrow(EncryptionError);
  });

  test('rejects empty shareId', async () => {
    const fek = generateFEK();
    await expect(
      encryptFEKForShare(fek, 'TestSharePassword!99', '', 'file-1')
    ).rejects.toThrow(EncryptionError);
  });
});

// ============================================================================
// Decryption failures -- wrong password, wrong AAD
// ============================================================================

describe('decryptShareEnvelope failure cases', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  const SHARE_PASSWORD = 'CorrectPassword!1234';
  const SHARE_ID = 'share-aad-test';
  const FILE_ID = 'file-aad-test';

  // Pre-encrypt once for all failure tests
  let encryptedFEK: string;
  let salt: string;

  beforeAll(async () => {
    const fek = generateFEK();
    const result = await encryptFEKForShare(fek, SHARE_PASSWORD, SHARE_ID, FILE_ID);
    encryptedFEK = result.encryptedFEK;
    salt = result.salt;
  });

  test('wrong password throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, 'WrongPassword!12345', SHARE_ID, FILE_ID, salt)
    ).rejects.toThrow(DecryptionError);
  }, 30_000);

  test('wrong shareId (AAD mismatch) throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, SHARE_PASSWORD, 'wrong-share-id', FILE_ID, salt)
    ).rejects.toThrow(DecryptionError);
  }, 30_000);

  test('wrong fileId (AAD mismatch) throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, SHARE_PASSWORD, SHARE_ID, 'wrong-file-id', salt)
    ).rejects.toThrow(DecryptionError);
  }, 30_000);

  test('empty password throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, '', SHARE_ID, FILE_ID, salt)
    ).rejects.toThrow(DecryptionError);
  });

  test('empty shareId throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, SHARE_PASSWORD, '', FILE_ID, salt)
    ).rejects.toThrow(DecryptionError);
  });

  test('missing salt throws DecryptionError', async () => {
    await expect(
      decryptShareEnvelope(encryptedFEK, SHARE_PASSWORD, SHARE_ID, FILE_ID, undefined)
    ).rejects.toThrow(DecryptionError);
  });

  test('truncated encrypted data throws DecryptionError', async () => {
    // Take only first 10 bytes of the encrypted data
    const fullBytes = fromBase64(encryptedFEK);
    const truncated = toBase64(fullBytes.slice(0, 10));
    await expect(
      decryptShareEnvelope(truncated, SHARE_PASSWORD, SHARE_ID, FILE_ID, salt)
    ).rejects.toThrow(DecryptionError);
  });
});
