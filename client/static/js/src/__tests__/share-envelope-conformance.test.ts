import { describe, expect, test } from 'bun:test';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';
import { decryptShareEnvelope } from '../shares/share-crypto';
import { fromBase64, toBase64, toHex } from '../crypto/primitives';

const vector = fixture.share_envelope;

describe('shared Go and TypeScript share-envelope fixture', () => {
  test('decrypts every pinned field', async () => {
    expect(fixture.corpus_version).toBe(2);
    const decrypted = await decryptShareEnvelope(
      vector.encrypted_envelope_base64,
      vector.password,
      vector.share_id,
      vector.file_id,
      vector.salt_base64,
    );

    expect(toHex(decrypted.fek)).toBe(vector.fek_hex);
    expect(decrypted.downloadToken).toBe(vector.download_token_base64);
    expect(decrypted.metadata?.filename).toBe(vector.filename);
    expect(decrypted.metadata?.sizeBytes).toBe(vector.size_bytes);
    expect(decrypted.metadata?.sha256).toBe(vector.sha256);
  }, 30000);

  test('rejects wrong binding, corruption, and sub-floor KDF parameters', async () => {
    await expect(decryptShareEnvelope(
      vector.encrypted_envelope_base64,
      vector.password,
      'wrong-share',
      vector.file_id,
      vector.salt_base64,
    )).rejects.toThrow();

    await expect(decryptShareEnvelope(
      vector.encrypted_envelope_base64,
      vector.password,
      vector.share_id,
      'wrong-file',
      vector.salt_base64,
    )).rejects.toThrow();

    const corrupted = fromBase64(vector.encrypted_envelope_base64);
    const lastIndex = corrupted.length - 1;
    corrupted[lastIndex] = corrupted[lastIndex]! ^ 0x01;
    await expect(decryptShareEnvelope(
      toBase64(corrupted),
      vector.password,
      vector.share_id,
      vector.file_id,
      vector.salt_base64,
    )).rejects.toThrow();

    await expect(decryptShareEnvelope(
      vector.weak_kdf_encrypted_envelope_base64,
      vector.password,
      vector.share_id,
      vector.file_id,
      vector.salt_base64,
    )).rejects.toThrow();
  }, 60000);
});
