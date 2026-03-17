/**
 * Crypto Type Guards Unit Tests
 * 
 * Tests for crypto/types.ts — type guard functions for cryptographic
 * key types and Result discriminated unions.
 */

import { describe, test, expect } from 'bun:test';
import {
  isFileEncryptionKey,
  isOpaqueExportKey,
  isSessionKey,
  isSuccess,
  isFailure,
  type FileEncryptionKey,
  type OpaqueExportKey,
  type SessionKey,
  type Result,
} from '../crypto/types';

// ============================================================================
// isFileEncryptionKey
// ============================================================================

describe('isFileEncryptionKey', () => {
  test('returns true for valid FileEncryptionKey', () => {
    const key: FileEncryptionKey = {
      key: new Uint8Array(32),
      username: 'testuser1234',
      derivedAt: Date.now(),
    };
    expect(isFileEncryptionKey(key)).toBe(true);
  });

  test('returns false when key is not Uint8Array', () => {
    expect(isFileEncryptionKey({
      key: 'not-bytes',
      username: 'testuser1234',
      derivedAt: Date.now(),
    })).toBe(false);
  });

  test('returns false when username is missing', () => {
    expect(isFileEncryptionKey({
      key: new Uint8Array(32),
      derivedAt: Date.now(),
    })).toBe(false);
  });

  test('returns false when username is not a string', () => {
    expect(isFileEncryptionKey({
      key: new Uint8Array(32),
      username: 123,
      derivedAt: Date.now(),
    })).toBe(false);
  });

  test('returns false when derivedAt is missing', () => {
    expect(isFileEncryptionKey({
      key: new Uint8Array(32),
      username: 'testuser1234',
    })).toBe(false);
  });

  test('returns false when derivedAt is not a number', () => {
    expect(isFileEncryptionKey({
      key: new Uint8Array(32),
      username: 'testuser1234',
      derivedAt: 'not-a-number',
    })).toBe(false);
  });

  test('returns false for null', () => {
    expect(isFileEncryptionKey(null)).toBe(false);
  });

  test('returns false for undefined', () => {
    expect(isFileEncryptionKey(undefined)).toBe(false);
  });

  test('returns false for string', () => {
    expect(isFileEncryptionKey('key')).toBe(false);
  });

  test('returns false for number', () => {
    expect(isFileEncryptionKey(42)).toBe(false);
  });

  test('returns false for empty object', () => {
    expect(isFileEncryptionKey({})).toBe(false);
  });
});

// ============================================================================
// isOpaqueExportKey
// ============================================================================

describe('isOpaqueExportKey', () => {
  test('returns true for valid OpaqueExportKey', () => {
    const key: OpaqueExportKey = {
      key: new Uint8Array(64),
      generatedAt: Date.now(),
    };
    expect(isOpaqueExportKey(key)).toBe(true);
  });

  test('returns false when key is not Uint8Array', () => {
    expect(isOpaqueExportKey({
      key: [1, 2, 3],
      generatedAt: Date.now(),
    })).toBe(false);
  });

  test('returns false when generatedAt is missing', () => {
    expect(isOpaqueExportKey({
      key: new Uint8Array(64),
    })).toBe(false);
  });

  test('returns false when generatedAt is not a number', () => {
    expect(isOpaqueExportKey({
      key: new Uint8Array(64),
      generatedAt: 'yesterday',
    })).toBe(false);
  });

  test('returns false for null', () => {
    expect(isOpaqueExportKey(null)).toBe(false);
  });

  test('returns false for undefined', () => {
    expect(isOpaqueExportKey(undefined)).toBe(false);
  });

  test('returns false for empty object', () => {
    expect(isOpaqueExportKey({})).toBe(false);
  });
});

// ============================================================================
// isSessionKey
// ============================================================================

describe('isSessionKey', () => {
  test('returns true for valid SessionKey', () => {
    const key: SessionKey = {
      key: new Uint8Array(32),
      derivedAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    };
    expect(isSessionKey(key)).toBe(true);
  });

  test('returns false when key is not Uint8Array', () => {
    expect(isSessionKey({
      key: 'not-bytes',
      derivedAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    })).toBe(false);
  });

  test('returns false when derivedAt is missing', () => {
    expect(isSessionKey({
      key: new Uint8Array(32),
      expiresAt: Date.now() + 3600000,
    })).toBe(false);
  });

  test('returns false when expiresAt is missing', () => {
    expect(isSessionKey({
      key: new Uint8Array(32),
      derivedAt: Date.now(),
    })).toBe(false);
  });

  test('returns false when expiresAt is not a number', () => {
    expect(isSessionKey({
      key: new Uint8Array(32),
      derivedAt: Date.now(),
      expiresAt: 'tomorrow',
    })).toBe(false);
  });

  test('returns false for null', () => {
    expect(isSessionKey(null)).toBe(false);
  });

  test('returns false for undefined', () => {
    expect(isSessionKey(undefined)).toBe(false);
  });

  test('returns false for empty object', () => {
    expect(isSessionKey({})).toBe(false);
  });

  test('distinguishes SessionKey from FileEncryptionKey (no expiresAt)', () => {
    // A FileEncryptionKey has username but no expiresAt
    expect(isSessionKey({
      key: new Uint8Array(32),
      username: 'testuser1234',
      derivedAt: Date.now(),
    })).toBe(false);
  });
});

// ============================================================================
// isSuccess / isFailure
// ============================================================================

describe('isSuccess', () => {
  test('returns true for success result', () => {
    const result: Result<string> = { success: true, value: 'hello' };
    expect(isSuccess(result)).toBe(true);
  });

  test('returns false for failure result', () => {
    const result: Result<string> = { success: false, error: new Error('fail') };
    expect(isSuccess(result)).toBe(false);
  });

  test('narrows type — value is accessible after check', () => {
    const result: Result<number> = { success: true, value: 42 };
    if (isSuccess(result)) {
      expect(result.value).toBe(42);
    } else {
      // Should not reach here
      expect(true).toBe(false);
    }
  });
});

describe('isFailure', () => {
  test('returns true for failure result', () => {
    const result: Result<string> = { success: false, error: new Error('fail') };
    expect(isFailure(result)).toBe(true);
  });

  test('returns false for success result', () => {
    const result: Result<string> = { success: true, value: 'hello' };
    expect(isFailure(result)).toBe(false);
  });

  test('narrows type — error is accessible after check', () => {
    const result: Result<number> = { success: false, error: new Error('oops') };
    if (isFailure(result)) {
      expect(result.error.message).toBe('oops');
    } else {
      // Should not reach here
      expect(true).toBe(false);
    }
  });
});
