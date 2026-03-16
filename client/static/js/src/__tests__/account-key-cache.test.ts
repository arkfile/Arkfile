/**
 * Unit Tests — Account Key Cache
 *
 * Tests for: cacheAccountKey, getCachedAccountKey, clearCachedAccountKey,
 * clearAllCachedAccountKeys, isAccountKeyCached, lockAccountKey,
 * unlockAccountKey, isAccountKeyLocked, getAccountKeyCacheConfig,
 * setAccountKeyCacheConfig, cleanupAccountKeyCache
 *
 * The Account Key cache encrypts the derived key with an ephemeral wrapping
 * key (JS heap only) and stores the ciphertext in sessionStorage. These tests
 * verify the full round-trip, session binding, expiration, locking, and config.
 */

import './setup';
import { describe, test, expect, beforeEach } from 'bun:test';
import { resetMocks } from './setup';
import { randomBytes, toHex } from '../crypto/primitives';
import {
  cacheAccountKey,
  getCachedAccountKey,
  clearCachedAccountKey,
  clearAllCachedAccountKeys,
  isAccountKeyCached,
  lockAccountKey,
  unlockAccountKey,
  isAccountKeyLocked,
  cleanupAccountKeyCache,
} from '../crypto/account-key-cache';
import {
  getAccountKeyCacheConfig,
  setAccountKeyCacheConfig,
} from '../crypto/account-key-cache';

// ============================================================================
// Helpers
// ============================================================================

const TEST_USERNAME = 'testuser01';  // 10+ chars
const TEST_TOKEN = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test-token-payload';

function makeKey(): Uint8Array {
  return randomBytes(32);
}

// ============================================================================
// Setup — clean slate before each test
// ============================================================================

beforeEach(() => {
  resetMocks();
  // Ensure unlocked state and clean wrapping key by running cleanup
  cleanupAccountKeyCache();
});

// ============================================================================
// cacheAccountKey + getCachedAccountKey round-trip
// ============================================================================

describe('cacheAccountKey / getCachedAccountKey', () => {
  test('round-trips a 32-byte key', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    const retrieved = await getCachedAccountKey(TEST_USERNAME, TEST_TOKEN);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.length).toBe(32);
    expect(toHex(retrieved!)).toBe(toHex(key));
  });

  test('returns null when nothing is cached', async () => {
    const result = await getCachedAccountKey(TEST_USERNAME, TEST_TOKEN);
    expect(result).toBeNull();
  });

  test('returns null for wrong username', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    const result = await getCachedAccountKey('otheruserx', TEST_TOKEN);
    expect(result).toBeNull();
  });
});

// ============================================================================
// isAccountKeyCached
// ============================================================================

describe('isAccountKeyCached', () => {
  test('returns true after caching', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);
    expect(isAccountKeyCached(TEST_USERNAME)).toBe(true);
  });

  test('returns false when nothing cached', () => {
    expect(isAccountKeyCached(TEST_USERNAME)).toBe(false);
  });

  test('returns false after clear', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);
    clearCachedAccountKey(TEST_USERNAME);
    // After clearing the storage entry, isAccountKeyCached should be false
    expect(isAccountKeyCached(TEST_USERNAME)).toBe(false);
  });
});

// ============================================================================
// clearCachedAccountKey
// ============================================================================

describe('clearCachedAccountKey', () => {
  test('removes specific user key', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    clearCachedAccountKey(TEST_USERNAME);

    const result = await getCachedAccountKey(TEST_USERNAME, TEST_TOKEN);
    expect(result).toBeNull();
  });

  test('does not affect other users', async () => {
    const key1 = makeKey();
    const key2 = makeKey();
    const user2 = 'otheruser1';

    await cacheAccountKey(TEST_USERNAME, key1, TEST_TOKEN, 1);
    await cacheAccountKey(user2, key2, TEST_TOKEN, 1);

    clearCachedAccountKey(TEST_USERNAME);

    // user2's key should still be retrievable
    const result = await getCachedAccountKey(user2, TEST_TOKEN);
    expect(result).not.toBeNull();
    expect(toHex(result!)).toBe(toHex(key2));
  });
});

// ============================================================================
// clearAllCachedAccountKeys
// ============================================================================

describe('clearAllCachedAccountKeys', () => {
  test('removes all cached keys', async () => {
    const key1 = makeKey();
    const key2 = makeKey();
    const user2 = 'otheruser1';

    await cacheAccountKey(TEST_USERNAME, key1, TEST_TOKEN, 1);
    await cacheAccountKey(user2, key2, TEST_TOKEN, 1);

    clearAllCachedAccountKeys();

    expect(isAccountKeyCached(TEST_USERNAME)).toBe(false);
    expect(isAccountKeyCached(user2)).toBe(false);
  });
});

// ============================================================================
// Lock / Unlock
// ============================================================================

describe('lockAccountKey / unlockAccountKey / isAccountKeyLocked', () => {
  test('isAccountKeyLocked returns false initially', () => {
    expect(isAccountKeyLocked()).toBe(false);
  });

  test('lockAccountKey sets locked state', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    lockAccountKey();

    expect(isAccountKeyLocked()).toBe(true);
  });

  test('getCachedAccountKey returns null when locked', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    lockAccountKey();

    const result = await getCachedAccountKey(TEST_USERNAME, TEST_TOKEN);
    expect(result).toBeNull();
  });

  test('isAccountKeyCached returns false when locked', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    lockAccountKey();

    expect(isAccountKeyCached(TEST_USERNAME)).toBe(false);
  });

  test('unlockAccountKey clears locked state', () => {
    lockAccountKey();
    expect(isAccountKeyLocked()).toBe(true);

    unlockAccountKey();
    expect(isAccountKeyLocked()).toBe(false);
  });
});

// ============================================================================
// Session binding (token mismatch → auto-lock)
// ============================================================================

describe('session binding', () => {
  test('mismatched token causes getCachedAccountKey to return null and lock', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    const differentToken = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.different-payload';
    const result = await getCachedAccountKey(TEST_USERNAME, differentToken);

    expect(result).toBeNull();
    expect(isAccountKeyLocked()).toBe(true);
  });

  test('getCachedAccountKey works without token (no session check)', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    // Passing undefined skips session binding check
    const result = await getCachedAccountKey(TEST_USERNAME);
    expect(result).not.toBeNull();
    expect(toHex(result!)).toBe(toHex(key));
  });
});

// ============================================================================
// Configuration
// ============================================================================

describe('getAccountKeyCacheConfig / setAccountKeyCacheConfig', () => {
  test('returns default config when nothing set', () => {
    const config = getAccountKeyCacheConfig();
    expect(config.enabled).toBe(false);
    expect(config.durationHours).toBe(1);
    expect(config.inactivityTimeoutMinutes).toBe(15);
  });

  test('round-trips custom config', () => {
    setAccountKeyCacheConfig({
      enabled: true,
      durationHours: 3,
      inactivityTimeoutMinutes: 30,
    });

    const config = getAccountKeyCacheConfig();
    expect(config.enabled).toBe(true);
    expect(config.durationHours).toBe(3);
    expect(config.inactivityTimeoutMinutes).toBe(30);
  });

  test('clamps duration to 1-4 range', () => {
    setAccountKeyCacheConfig({
      enabled: true,
      durationHours: 10 as any,
      inactivityTimeoutMinutes: 15,
    });

    const config = getAccountKeyCacheConfig();
    expect(config.durationHours).toBeLessThanOrEqual(4);
    expect(config.durationHours).toBeGreaterThanOrEqual(1);
  });
});

// ============================================================================
// cleanupAccountKeyCache
// ============================================================================

describe('cleanupAccountKeyCache', () => {
  test('wipes everything and resets state', async () => {
    const key = makeKey();
    await cacheAccountKey(TEST_USERNAME, key, TEST_TOKEN, 1);

    setAccountKeyCacheConfig({
      enabled: true,
      durationHours: 2,
      inactivityTimeoutMinutes: 30,
    });

    cleanupAccountKeyCache();

    expect(isAccountKeyCached(TEST_USERNAME)).toBe(false);
    expect(isAccountKeyLocked()).toBe(false);
    // Config should be cleared (returns default)
    const config = getAccountKeyCacheConfig();
    expect(config.enabled).toBe(false);
  });
});
