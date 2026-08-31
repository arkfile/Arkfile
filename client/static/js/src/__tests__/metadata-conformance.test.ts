import './setup';
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';
import {
  AAD_FIELD_FILENAME,
  AAD_FIELD_PASSWORD_HINT,
  AAD_FIELD_SHA256,
  AAD_FIELD_TAGS,
} from '../crypto/aad';
import { fromHex, toBase64, toHex } from '../crypto/primitives';

const originalFetch = globalThis.fetch;
const CHUNKING_CONFIG = {
  plaintextChunkSizeBytes: 16777216,
  envelope: {
    version: 2,
    headerSizeBytes: 35,
    saltSizeBytes: 32,
    kdfProfile: 1,
    keyTypes: { account: 1, custom: 2 },
  },
  aesGcm: {
    nonceSizeBytes: 12,
    tagSizeBytes: 16,
    keySizeBytes: 32,
  },
};

beforeAll(() => {
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
});
afterAll(() => {
  globalThis.fetch = originalFetch;
});

import { decryptMetadataField } from '../crypto/metadata-helpers';

describe('owner metadata shared fixture', () => {
  const fields = [
    {
      name: 'filename',
      field: AAD_FIELD_FILENAME,
      plaintext: fixture.owner_metadata.filename_plaintext,
      nonceHex: fixture.owner_metadata.filename_nonce_hex,
      cipherHex: fixture.owner_metadata.filename_ciphertext_and_tag_hex,
    },
    {
      name: 'sha256',
      field: AAD_FIELD_SHA256,
      plaintext: fixture.owner_metadata.sha256_plaintext,
      nonceHex: fixture.owner_metadata.sha256_nonce_hex,
      cipherHex: fixture.owner_metadata.sha256_ciphertext_and_tag_hex,
    },
    {
      name: 'password_hint',
      field: AAD_FIELD_PASSWORD_HINT,
      plaintext: fixture.owner_metadata.password_hint_plaintext,
      nonceHex: fixture.owner_metadata.password_hint_nonce_hex,
      cipherHex: fixture.owner_metadata.password_hint_ciphertext_and_tag_hex,
    },
    {
      name: 'tags',
      field: AAD_FIELD_TAGS,
      plaintext: fixture.owner_metadata.tags_plaintext,
      nonceHex: fixture.owner_metadata.tags_nonce_hex,
      cipherHex: fixture.owner_metadata.tags_ciphertext_and_tag_hex,
    },
  ] as const;

  test('decrypts pinned filename, hash, hint, and tags ciphertext', async () => {
    const key = fromHex(fixture.password_kdf.account_key_hex);
    for (const field of fields) {
      const nonce = fromHex(field.nonceHex);
      const ciphertext = fromHex(field.cipherHex);
      const got = await decryptMetadataField(
        toBase64(ciphertext),
        toBase64(nonce),
        key,
        fixture.file_id,
        field.field,
        fixture.owner_username,
      );
      expect(got).toBe(field.plaintext);
    }
  });

  test('re-encrypts to the pinned ciphertext', async () => {
    const keyBytes = fromHex(fixture.password_kdf.account_key_hex);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const aadByField: Record<string, string> = {
      [AAD_FIELD_FILENAME]: fixture.aad.encrypted_filename_hex,
      [AAD_FIELD_SHA256]: fixture.aad.encrypted_sha256sum_hex,
      [AAD_FIELD_PASSWORD_HINT]: fixture.aad.encrypted_password_hint_hex,
      [AAD_FIELD_TAGS]: fixture.aad.encrypted_tags_hex,
    };
    for (const field of fields) {
      const nonce = fromHex(field.nonceHex);
      const aad = fromHex(aadByField[field.field]);
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aad,
        tagLength: 128,
      }, key, new TextEncoder().encode(field.plaintext)));
      expect(toHex(encrypted)).toBe(field.cipherHex);
    }
  });
});
