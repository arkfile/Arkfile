/**
 * Unit Tests -- metadata-helpers.ts (AAD wiring)
 *
 * Covers:
 *   - decryptFEK round-trip with FEK-envelope AAD
 *   - decryptFEK negative cases: wrong fileID, flipped key-type byte,
 *     short input, unsupported envelope version, missing fileID
 *   - decryptMetadataField round-trip with metadata-field AAD
 *   - decryptMetadataField negative cases: wrong fileID, wrong fieldName,
 *     wrong ownerUsername, missing args
 *
 * Encryption helper here mirrors the on-the-wire layout produced by the
 * Go server (crypto.EncryptFEK / crypto.EncryptGCMWithAAD):
 *   FEK envelope: [0x01][keyType][nonce][ciphertext][tag]   AAD = fek-envelope-AAD
 *   Metadata     :  nonce_b64 + (ciphertext||tag)_b64       AAD = metadata-field-AAD
 */

import './setup';
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import {
  randomBytes,
  toBase64,
} from '../crypto/primitives';
import {
  buildFEKEnvelopeAAD,
  buildMetadataFieldAAD,
  AAD_FIELD_FILENAME,
  AAD_FIELD_SHA256,
  AAD_FIELD_PASSWORD_HINT,
} from '../crypto/aad';

// ----------------------------------------------------------------------------
// Fetch mock for getChunkingParams() -- AESGCMDecryptor.fromRawKey calls
// /api/config/chunking on first use; we mirror aes-gcm.test.ts here.
// ----------------------------------------------------------------------------

const originalFetch = globalThis.fetch;

const CHUNKING_CONFIG = {
  plaintextChunkSizeBytes: 16777216,
  envelope: {
    version: 1,
    headerSizeBytes: 2,
    keyTypes: { account: 1, custom: 2 },
  },
  aesGcm: {
    nonceSizeBytes: 12,
    tagSizeBytes: 16,
    keySizeBytes: 32,
  },
};

function installFetchMock(): void {
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
}

beforeAll(() => installFetchMock());
afterAll(() => { globalThis.fetch = originalFetch; });

// Import after the fetch mock is in place.
import { decryptFEK, decryptMetadataField } from '../crypto/metadata-helpers';

// ----------------------------------------------------------------------------
// AES-GCM helpers (encrypt with optional AAD)
// ----------------------------------------------------------------------------

async function aesGcmEncrypt(
  plaintext: Uint8Array,
  rawKey: Uint8Array,
  aad?: Uint8Array,
): Promise<{ nonce: Uint8Array; ciphertextWithTag: Uint8Array }> {
  const keyBuf = new Uint8Array(rawKey).buffer as ArrayBuffer;
  const key = await crypto.subtle.importKey(
    'raw', keyBuf, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ptBuf = new Uint8Array(plaintext).buffer as ArrayBuffer;
  const params: AesGcmParams = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
  if (aad !== undefined) {
    params.additionalData = new Uint8Array(aad).buffer as ArrayBuffer;
  }
  const encrypted = await crypto.subtle.encrypt(params, key, ptBuf);
  return { nonce, ciphertextWithTag: new Uint8Array(encrypted) };
}

/**
 * Build the wire-format encrypted FEK exactly as the Go server emits it:
 *   [0x01][keyType][nonce(12)][ciphertext][tag(16)]
 * encrypted under AAD = BuildFEKEnvelopeAAD(fileID, keyType).
 */
async function buildEncryptedFEK(
  fek: Uint8Array,
  kek: Uint8Array,
  fileID: string,
  keyTypeByte: number,
): Promise<string> {
  const aad = buildFEKEnvelopeAAD(fileID, keyTypeByte);
  const { nonce, ciphertextWithTag } = await aesGcmEncrypt(fek, kek, aad);

  const out = new Uint8Array(2 + nonce.length + ciphertextWithTag.length);
  out[0] = 0x01;
  out[1] = keyTypeByte;
  out.set(nonce, 2);
  out.set(ciphertextWithTag, 2 + nonce.length);
  return toBase64(out);
}

/**
 * Build server-shaped metadata pair (separate nonce + ciphertext-with-tag)
 * under AAD = BuildMetadataFieldAAD(fileID, fieldName, ownerUsername).
 */
async function buildEncryptedMetadata(
  plaintext: string,
  accountKey: Uint8Array,
  fileID: string,
  fieldName: string,
  ownerUsername: string,
): Promise<{ encrypted: string; nonce: string }> {
  const data = new TextEncoder().encode(plaintext);
  const aad = buildMetadataFieldAAD(fileID, fieldName, ownerUsername);
  const { nonce, ciphertextWithTag } = await aesGcmEncrypt(data, accountKey, aad);
  return {
    encrypted: toBase64(ciphertextWithTag),
    nonce: toBase64(nonce),
  };
}

// ----------------------------------------------------------------------------
// decryptFEK
// ----------------------------------------------------------------------------

describe('decryptFEK', () => {
  const FILE_ID = 'a1b2c3d4-e5f6-4890-abcd-ef1234567890';

  test('round-trip with account key-type (0x01)', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x01);

    const recovered = await decryptFEK(wrapped, kek, FILE_ID);
    expect(recovered).toEqual(fek);
  });

  test('round-trip with custom key-type (0x02)', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x02);

    const recovered = await decryptFEK(wrapped, kek, FILE_ID);
    expect(recovered).toEqual(fek);
  });

  test('wrong fileID fails AEAD verification', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x01);

    const otherFileID = 'b2c3d4e5-f6a7-4901-bcde-f23456789012';
    await expect(decryptFEK(wrapped, kek, otherFileID)).rejects.toThrow('Decryption failed');
  });

  test('flipped key-type byte fails AEAD verification', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x01);

    // Decode, flip the keyType byte, re-encode. AAD on-decrypt uses the
    // flipped byte but the tag was produced under the original byte.
    const bin = atob(wrapped);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    bytes[1] = 0x02; // flip account -> custom
    let flipped = '';
    for (let i = 0; i < bytes.length; i++) flipped += String.fromCharCode(bytes[i]);
    const flippedB64 = btoa(flipped);

    await expect(decryptFEK(flippedB64, kek, FILE_ID)).rejects.toThrow('Decryption failed');
  });

  test('missing fileID throws before touching crypto', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x01);

    await expect(decryptFEK(wrapped, kek, '')).rejects.toThrow('fileID is required');
  });

  test('rejects unsupported envelope version byte', async () => {
    const fek = randomBytes(32);
    const kek = randomBytes(32);
    const wrapped = await buildEncryptedFEK(fek, kek, FILE_ID, 0x01);

    // Flip the version byte (0x01 -> 0x02). decryptFEK should refuse at
    // header-parse time, before attempting AEAD.
    const bin = atob(wrapped);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    bytes[0] = 0x02;
    let bad = '';
    for (let i = 0; i < bytes.length; i++) bad += String.fromCharCode(bytes[i]);
    const badB64 = btoa(bad);

    await expect(decryptFEK(badB64, kek, FILE_ID)).rejects.toThrow('Unsupported envelope version');
  });

  test('rejects too-short input', async () => {
    const kek = randomBytes(32);
    // Anything <31 bytes is below the minimum (2 envelope + 12 nonce + 16 tag + 1 ct).
    const shortB64 = toBase64(new Uint8Array(20));
    await expect(decryptFEK(shortB64, kek, FILE_ID)).rejects.toThrow('Encrypted FEK too short');
  });
});

// ----------------------------------------------------------------------------
// decryptMetadataField
// ----------------------------------------------------------------------------

describe('decryptMetadataField', () => {
  const FILE_ID = 'a1b2c3d4-e5f6-4890-abcd-ef1234567890';
  const OWNER = 'alice123456';

  test('round-trip for filename field', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'document.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );

    const got = await decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_FILENAME, OWNER);
    expect(got).toBe('document.pdf');
  });

  test('round-trip for sha256 field', async () => {
    const key = randomBytes(32);
    const hex = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
    const { encrypted, nonce } = await buildEncryptedMetadata(
      hex, key, FILE_ID, AAD_FIELD_SHA256, OWNER,
    );

    const got = await decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_SHA256, OWNER);
    expect(got).toBe(hex);
  });

  test('round-trip for password hint field', async () => {
    const key = randomBytes(32);
    const hint = 'my favorite color';
    const { encrypted, nonce } = await buildEncryptedMetadata(
      hint, key, FILE_ID, AAD_FIELD_PASSWORD_HINT, OWNER,
    );

    const got = await decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_PASSWORD_HINT, OWNER);
    expect(got).toBe(hint);
  });

  test('wrong fileID fails AEAD verification', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    const other = 'b2c3d4e5-f6a7-4901-bcde-f23456789012';
    await expect(
      decryptMetadataField(encrypted, nonce, key, other, AAD_FIELD_FILENAME, OWNER),
    ).rejects.toThrow('Decryption failed');
  });

  test('swapping fieldName label (filename -> sha256) fails AEAD verification', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    await expect(
      decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_SHA256, OWNER),
    ).rejects.toThrow('Decryption failed');
  });

  test('wrong ownerUsername fails AEAD verification', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    await expect(
      decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_FILENAME, 'bobsmith0000'),
    ).rejects.toThrow('Decryption failed');
  });

  test('missing fileID throws before touching crypto', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    await expect(
      decryptMetadataField(encrypted, nonce, key, '', AAD_FIELD_FILENAME, OWNER),
    ).rejects.toThrow('fileID is required');
  });

  test('missing fieldName throws before touching crypto', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    await expect(
      decryptMetadataField(encrypted, nonce, key, FILE_ID, '', OWNER),
    ).rejects.toThrow('fieldName is required');
  });

  test('missing ownerUsername throws before touching crypto', async () => {
    const key = randomBytes(32);
    const { encrypted, nonce } = await buildEncryptedMetadata(
      'doc.pdf', key, FILE_ID, AAD_FIELD_FILENAME, OWNER,
    );
    await expect(
      decryptMetadataField(encrypted, nonce, key, FILE_ID, AAD_FIELD_FILENAME, ''),
    ).rejects.toThrow('ownerUsername is required');
  });
});
