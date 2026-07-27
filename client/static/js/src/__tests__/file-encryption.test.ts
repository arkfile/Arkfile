import { describe, expect, test } from 'bun:test';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';
import {
  deriveFileEncryptionKey,
  generatePasswordSalt,
  validatePasswordSalt,
} from '../crypto/file-encryption';
import { fromHex, toHex } from '../crypto/primitives';

describe('explicit-salt owner key derivation', () => {
  test('matches the shared account and custom vectors', async () => {
    const salt = fromHex(fixture.public_salt_hex);
    const accountKey = await deriveFileEncryptionKey(
      fixture.password_kdf.password,
      salt,
      'account',
    );
    const customKey = await deriveFileEncryptionKey(
      fixture.password_kdf.password,
      salt,
      'custom',
    );

    expect(toHex(accountKey)).toBe(fixture.password_kdf.account_key_hex);
    expect(toHex(customKey)).toBe(fixture.password_kdf.custom_key_hex);
    expect(toHex(accountKey)).not.toBe(toHex(customKey));
  }, 60000);

  test('different public salts produce different keys', async () => {
    const first = new Uint8Array(32).fill(1);
    const second = new Uint8Array(32).fill(2);
    const firstKey = await deriveFileEncryptionKey('ValidPassword-2026!', first, 'account');
    const secondKey = await deriveFileEncryptionKey('ValidPassword-2026!', second, 'account');
    expect(toHex(firstKey)).not.toBe(toHex(secondKey));
  }, 60000);

  test('generates distinct validated salts', () => {
    const first = generatePasswordSalt();
    const second = generatePasswordSalt();
    expect(() => validatePasswordSalt(first)).not.toThrow();
    expect(toHex(first)).not.toBe(toHex(second));
  });

  test('rejects malformed salt lengths', async () => {
    expect(() => validatePasswordSalt(new Uint8Array(31))).toThrow();
    await expect(
      deriveFileEncryptionKey('ValidPassword-2026!', new Uint8Array(33), 'account'),
    ).rejects.toThrow();
  });
});
