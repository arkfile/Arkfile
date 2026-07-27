import { describe, expect, test } from 'bun:test';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';
import { fromHex, toHex } from '../crypto/primitives';

describe('AES-256-GCM shared fixture', () => {
  test('matches pinned ciphertext and decrypts it', async () => {
    const keyBytes = fromHex(fixture.aes_gcm.key_hex);
    const nonce = fromHex(fixture.aes_gcm.nonce_hex);
    const plaintext = fromHex(fixture.aes_gcm.plaintext_hex);
    const aad = fromHex(fixture.aes_gcm.aad_hex);
    const expected = fromHex(fixture.aes_gcm.ciphertext_and_tag_hex);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);

    const encrypted = new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength: 128,
    }, key, plaintext));
    expect(toHex(encrypted)).toBe(toHex(expected));

    const decrypted = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength: 128,
    }, key, expected));
    expect(toHex(decrypted)).toBe(fixture.aes_gcm.plaintext_hex);
  });
});
