import './setup';
import { beforeEach, describe, expect, test } from 'bun:test';
import {
  cacheAccountKey,
  cleanupAccountKeyCache,
  clearCachedAccountKey,
  getCachedAccountKey,
  isAccountKeyCached,
  isAccountKeyLocked,
  lockAccountKey,
  unlockAccountKey,
} from '../crypto/account-key-cache';
import { randomBytes, toBase64, toHex } from '../crypto/primitives';

const USERNAME = 'cache-user-2026';
const TOKEN = 'header.cache-token-payload.signature';
let metadataSalt = new Uint8Array(32).fill(1);
let metadataProfile = 1;

beforeEach(() => {
  cleanupAccountKeyCache();
  unlockAccountKey();
  metadataSalt = new Uint8Array(32).fill(1);
  metadataProfile = 1;
  globalThis.fetch = async () => new Response(JSON.stringify({
    data: {
      username: USERNAME,
      account_kdf_salt: toBase64(metadataSalt),
      account_kdf_profile: metadataProfile,
    },
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
});

describe('Account Key cache metadata binding', () => {
  test('round-trips a key bound to username, salt, profile, and session', async () => {
    const key = randomBytes(32);
    await cacheAccountKey(USERNAME, key, TOKEN, 1);
    const recovered = await getCachedAccountKey(USERNAME, TOKEN);
    expect(recovered).not.toBeNull();
    expect(toHex(recovered!)).toBe(toHex(key));
  });

  test('invalidates the entry after the account salt changes', async () => {
    await cacheAccountKey(USERNAME, randomBytes(32), TOKEN, 1);
    const storageKey = `arkfile_account_key_${USERNAME}`;
    const cached = JSON.parse(sessionStorage.getItem(storageKey)!);
    cached.account_kdf_salt = toBase64(new Uint8Array(32).fill(2));
    sessionStorage.setItem(storageKey, JSON.stringify(cached));
    expect(await getCachedAccountKey(USERNAME, TOKEN)).toBeNull();
    expect(isAccountKeyCached(USERNAME)).toBe(false);
  });

  test('invalidates the entry after the KDF profile changes', async () => {
    await cacheAccountKey(USERNAME, randomBytes(32), TOKEN, 1);
    const storageKey = `arkfile_account_key_${USERNAME}`;
    const cached = JSON.parse(sessionStorage.getItem(storageKey)!);
    cached.account_kdf_profile = 2;
    sessionStorage.setItem(storageKey, JSON.stringify(cached));
    expect(await getCachedAccountKey(USERNAME, TOKEN)).toBeNull();
  });

  test('locks on a session-token mismatch', async () => {
    await cacheAccountKey(USERNAME, randomBytes(32), TOKEN, 1);
    expect(await getCachedAccountKey(USERNAME, 'different-token')).toBeNull();
    expect(isAccountKeyLocked()).toBe(true);
  });

  test('lock and explicit clear make cached material unavailable', async () => {
    await cacheAccountKey(USERNAME, randomBytes(32), TOKEN, 1);
    lockAccountKey();
    expect(await getCachedAccountKey(USERNAME, TOKEN)).toBeNull();
    unlockAccountKey();
    clearCachedAccountKey(USERNAME);
    expect(isAccountKeyCached(USERNAME)).toBe(false);
  });
});
