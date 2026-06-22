/**
 * Unit Tests -- OPAQUE re-registration password verifier
 *
 * Before finalizing an admin-initiated OPAQUE re-registration, the client must
 * confirm the entered password still derives the Account Key that wraps the
 * user's existing files. It does this by test-decrypting the server-provided
 * verifier sample (an account-key-encrypted filename) with the Account Key
 * derived from the entered password:
 *   - correct password -> Account Key matches -> decrypt succeeds -> proceed
 *   - wrong password    -> Account Key differs -> decrypt throws  -> abort
 *
 * These tests lock that decision rule at the crypto layer using the exact
 * primitive the verifier calls (decryptMetadataField) and the exact wire shape
 * the server returns (separate encrypted_filename + filename_nonce, AAD bound
 * to file_id + AAD_FIELD_FILENAME + owner_username).
 */

import './setup';
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { randomBytes, toBase64 } from '../crypto/primitives';
import { buildMetadataFieldAAD, AAD_FIELD_FILENAME } from '../crypto/aad';

const originalFetch = globalThis.fetch;

const CHUNKING_CONFIG = {
  plaintextChunkSizeBytes: 16777216,
  envelope: { version: 1, headerSizeBytes: 2, keyTypes: { account: 1, custom: 2 } },
  aesGcm: { nonceSizeBytes: 12, tagSizeBytes: 16, keySizeBytes: 32 },
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
afterAll(() => { globalThis.fetch = originalFetch; });

import { decryptMetadataField } from '../crypto/metadata-helpers';

interface ServerVerifier {
  file_id: string;
  owner_username: string;
  encrypted_filename: string;
  filename_nonce: string;
}

// Build the server's verifier sample: a filename encrypted under the given
// Account Key with AAD bound to (file_id, AAD_FIELD_FILENAME, owner_username),
// stored as separate base64 nonce + ciphertext, exactly as the 409 payload.
async function buildServerVerifier(
  filename: string,
  accountKey: Uint8Array,
  fileID: string,
  owner: string,
): Promise<ServerVerifier> {
  const keyBuf = new Uint8Array(accountKey).buffer as ArrayBuffer;
  const key = await crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = buildMetadataFieldAAD(fileID, AAD_FIELD_FILENAME, owner);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128, additionalData: new Uint8Array(aad).buffer as ArrayBuffer },
    key,
    new TextEncoder().encode(filename).buffer as ArrayBuffer,
  );
  return {
    file_id: fileID,
    owner_username: owner,
    encrypted_filename: toBase64(new Uint8Array(encrypted)),
    filename_nonce: toBase64(nonce),
  };
}

// The verifier's decision rule, isolated from UI/OPAQUE wiring: returns true
// iff the entered-password Account Key decrypts the server verifier sample.
async function verifierAccepts(accountKey: Uint8Array, v: ServerVerifier): Promise<boolean> {
  try {
    await decryptMetadataField(
      v.encrypted_filename,
      v.filename_nonce,
      accountKey,
      v.file_id,
      AAD_FIELD_FILENAME,
      v.owner_username,
    );
    return true;
  } catch {
    return false;
  }
}

describe('OPAQUE re-registration password verifier', () => {
  const FILE_ID = 'a1b2c3d4-e5f6-4890-abcd-ef1234567890';
  const OWNER = 'alice123456';

  test('correct-password Account Key accepts the verifier sample', async () => {
    const correctAccountKey = randomBytes(32);
    const v = await buildServerVerifier('annual-report.pdf', correctAccountKey, FILE_ID, OWNER);
    expect(await verifierAccepts(correctAccountKey, v)).toBe(true);
  });

  test('wrong-password Account Key rejects the verifier sample', async () => {
    const correctAccountKey = randomBytes(32);
    const wrongAccountKey = randomBytes(32); // a different password derives a different key
    const v = await buildServerVerifier('annual-report.pdf', correctAccountKey, FILE_ID, OWNER);
    expect(await verifierAccepts(wrongAccountKey, v)).toBe(false);
  });

  test('verifier sample is bound to the file (tampered file_id is rejected)', async () => {
    const correctAccountKey = randomBytes(32);
    const v = await buildServerVerifier('annual-report.pdf', correctAccountKey, FILE_ID, OWNER);
    const tampered = { ...v, file_id: 'b2c3d4e5-f6a7-4901-bcde-f23456789012' };
    expect(await verifierAccepts(correctAccountKey, tampered)).toBe(false);
  });

  test('verifier sample is bound to the owner (tampered owner_username is rejected)', async () => {
    const correctAccountKey = randomBytes(32);
    const v = await buildServerVerifier('annual-report.pdf', correctAccountKey, FILE_ID, OWNER);
    const tampered = { ...v, owner_username: 'mallory00000' };
    expect(await verifierAccepts(correctAccountKey, tampered)).toBe(false);
  });
});
