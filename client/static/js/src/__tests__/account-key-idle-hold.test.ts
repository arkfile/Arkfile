import './setup';
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import {
  cacheAccountKey,
  checkInactivityTimeout,
  cleanupAccountKeyCache,
  isAccountKeyIdleLockHeld,
  isAccountKeyLocked,
  setAccountKeyIdleLockHold,
  unlockAccountKey,
} from '../crypto/account-key-cache';
import { randomBytes, toBase64 } from '../crypto/primitives';

const USERNAME = 'idle-hold-user';
const MINUTE = 60_000;
const realNow = Date.now;
let clock = 0;

function advance(ms: number): void {
  clock += ms;
}

beforeEach(async () => {
  clock = realNow();
  Date.now = () => clock;
  cleanupAccountKeyCache();
  unlockAccountKey();
  globalThis.fetch = async () => new Response(JSON.stringify({
    data: {
      username: USERNAME,
      account_kdf_salt: toBase64(new Uint8Array(32).fill(3)),
      account_kdf_profile: 1,
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  await cacheAccountKey(USERNAME, randomBytes(32), undefined, 4);
});

afterEach(() => {
  setAccountKeyIdleLockHold(false);
  cleanupAccountKeyCache();
  Date.now = realNow;
});

describe('Account Key idle-lock hold during checkout', () => {
  test('locks after the idle timeout without a hold', () => {
    advance(16 * MINUTE);
    checkInactivityTimeout();
    expect(isAccountKeyLocked()).toBe(true);
  });

  test('does not lock while a hold is active', () => {
    setAccountKeyIdleLockHold(true);
    advance(16 * MINUTE);
    checkInactivityTimeout();
    advance(60 * MINUTE);
    checkInactivityTimeout();
    expect(isAccountKeyIdleLockHeld()).toBe(true);
    expect(isAccountKeyLocked()).toBe(false);
  });

  test('releasing the hold restarts the idle window', () => {
    setAccountKeyIdleLockHold(true);
    advance(90 * MINUTE);
    checkInactivityTimeout();
    setAccountKeyIdleLockHold(false);
    advance(10 * MINUTE);
    checkInactivityTimeout();
    expect(isAccountKeyLocked()).toBe(false);
    advance(6 * MINUTE);
    checkInactivityTimeout();
    expect(isAccountKeyLocked()).toBe(true);
  });

  test('a hold expires after two hours', () => {
    setAccountKeyIdleLockHold(true);
    advance(121 * MINUTE);
    expect(isAccountKeyIdleLockHeld()).toBe(false);
    advance(16 * MINUTE);
    checkInactivityTimeout();
    expect(isAccountKeyLocked()).toBe(true);
  });
});
