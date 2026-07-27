import './setup';
import { describe, expect, test } from 'bun:test';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';
import {
  createOwnerEnvelopeHeader,
  parseOwnerEnvelopeHeader,
} from '../crypto/owner-envelope';
import { fromHex, toHex } from '../crypto/primitives';
import { toBase64 } from '../crypto/primitives';
import { deriveFileEncryptionKey } from '../crypto/file-encryption';
import { decryptFEK } from '../crypto/metadata-helpers';

describe('owner FEK envelope v2', () => {
  test('creates and parses the shared account and custom headers', () => {
    const salt = fromHex(fixture.public_salt_hex);
    const account = createOwnerEnvelopeHeader('account', salt);
    const custom = createOwnerEnvelopeHeader('custom', salt);
    expect(toHex(account)).toBe(fixture.owner_headers.account_hex);
    expect(toHex(custom)).toBe(fixture.owner_headers.custom_hex);

    const parsed = parseOwnerEnvelopeHeader(account);
    expect(parsed.version).toBe(fixture.owner_envelope_version);
    expect(parsed.kdfProfile).toBe(fixture.kdf_profile);
    expect(parsed.keyType).toBe('account');
    expect(toHex(parsed.salt)).toBe(fixture.public_salt_hex);
  });

  test('rejects malformed and unsupported headers', () => {
    const valid = fromHex(fixture.owner_headers.account_hex);
    expect(() => parseOwnerEnvelopeHeader(valid.slice(0, 34))).toThrow();

    const badVersion = valid.slice();
    badVersion[0] = 3;
    expect(() => parseOwnerEnvelopeHeader(badVersion)).toThrow();

    const badKeyType = valid.slice();
    badKeyType[1] = 255;
    expect(() => parseOwnerEnvelopeHeader(badKeyType)).toThrow();

    const badProfile = valid.slice();
    badProfile[2] = 255;
    expect(() => parseOwnerEnvelopeHeader(badProfile)).toThrow();
  });

  test('decrypts the shared account envelope', async () => {
    const accountKey = await deriveFileEncryptionKey(
      fixture.password_kdf.password,
      fromHex(fixture.public_salt_hex),
      'account',
    );
    const fek = await decryptFEK(
      toBase64(fromHex(fixture.owner_envelope.account_envelope_hex)),
      accountKey,
      fixture.file_id,
    );
    expect(toHex(fek)).toBe(fixture.owner_envelope.fek_hex);
  }, 30000);
});
