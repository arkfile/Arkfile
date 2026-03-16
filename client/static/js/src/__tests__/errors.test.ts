/**
 * Unit Tests — Crypto Error Hierarchy
 *
 * Tests for: CryptoError, all subclasses, wrapError, isCryptoError,
 * getUserFriendlyMessage
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import {
  CryptoError,
  KeyDerivationError,
  KeyDerivationTimeoutError,
  InvalidArgon2ParamsError,
  EncryptionError,
  DecryptionError,
  AuthenticationError,
  CorruptedDataError,
  FileTooLargeError,
  OpaqueError,
  OpaqueRegistrationError,
  OpaqueAuthenticationError,
  InvalidOpaqueResponseError,
  InvalidOpaqueStateError,
  SaltDerivationError,
  InvalidUsernameError,
  InvalidKeyError,
  InvalidKeyLengthError,
  ExpiredKeyError,
  KeyNotFoundError,
  StorageError,
  StorageUnavailableError,
  StorageQuotaExceededError,
  UnsupportedProtocolVersionError,
  WebCryptoUnavailableError,
  WebCryptoError,
  ValidationError,
  InvalidPasswordError,
  NetworkError,
  ServerError,
  wrapError,
  isCryptoError,
  getUserFriendlyMessage,
} from '../crypto/errors';

// ============================================================================
// Base CryptoError
// ============================================================================

describe('CryptoError', () => {
  test('has correct name, code, message, timestamp', () => {
    const err = new CryptoError('test message', 'TEST_CODE', { foo: 'bar' });
    expect(err.name).toBe('CryptoError');
    expect(err.code).toBe('TEST_CODE');
    expect(err.message).toBe('test message');
    expect(err.context).toEqual({ foo: 'bar' });
    expect(err.timestamp).toBeGreaterThan(0);
  });

  test('is instanceof Error', () => {
    const err = new CryptoError('msg', 'CODE');
    expect(err instanceof Error).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
  });

  test('context is optional', () => {
    const err = new CryptoError('msg', 'CODE');
    expect(err.context).toBeUndefined();
  });
});

// ============================================================================
// Inheritance chains
// ============================================================================

describe('Error hierarchy', () => {
  test('KeyDerivationError extends CryptoError', () => {
    const err = new KeyDerivationError('kd fail');
    expect(err instanceof CryptoError).toBe(true);
    expect(err instanceof KeyDerivationError).toBe(true);
    expect(err.code).toBe('KEY_DERIVATION_ERROR');
    expect(err.name).toBe('KeyDerivationError');
  });

  test('KeyDerivationTimeoutError extends KeyDerivationError', () => {
    const err = new KeyDerivationTimeoutError(5000);
    expect(err instanceof KeyDerivationError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.name).toBe('KeyDerivationTimeoutError');
    expect(err.message).toContain('5000');
  });

  test('InvalidArgon2ParamsError extends KeyDerivationError', () => {
    const err = new InvalidArgon2ParamsError('bad memory', { memoryCost: 0 });
    expect(err instanceof KeyDerivationError).toBe(true);
    expect(err.name).toBe('InvalidArgon2ParamsError');
  });

  test('DecryptionError extends CryptoError', () => {
    const err = new DecryptionError('dec fail');
    expect(err instanceof CryptoError).toBe(true);
    expect(err.code).toBe('DECRYPTION_ERROR');
  });

  test('AuthenticationError extends DecryptionError', () => {
    const err = new AuthenticationError();
    expect(err instanceof DecryptionError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.name).toBe('AuthenticationError');
  });

  test('CorruptedDataError extends DecryptionError', () => {
    const err = new CorruptedDataError('bad header');
    expect(err instanceof DecryptionError).toBe(true);
    expect(err.message).toContain('bad header');
  });

  test('FileTooLargeError extends EncryptionError', () => {
    const err = new FileTooLargeError(10, 5);
    expect(err instanceof EncryptionError).toBe(true);
    expect(err.name).toBe('FileTooLargeError');
  });

  test('OpaqueRegistrationError extends OpaqueError', () => {
    const err = new OpaqueRegistrationError('reg fail');
    expect(err instanceof OpaqueError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
  });

  test('OpaqueAuthenticationError extends OpaqueError', () => {
    const err = new OpaqueAuthenticationError('auth fail');
    expect(err instanceof OpaqueError).toBe(true);
  });

  test('InvalidUsernameError extends SaltDerivationError', () => {
    const err = new InvalidUsernameError('too short');
    expect(err instanceof SaltDerivationError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.name).toBe('InvalidUsernameError');
  });

  test('InvalidKeyLengthError extends InvalidKeyError', () => {
    const err = new InvalidKeyLengthError(16, 32);
    expect(err instanceof InvalidKeyError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.message).toContain('16');
    expect(err.message).toContain('32');
  });

  test('StorageUnavailableError extends StorageError', () => {
    const err = new StorageUnavailableError('sessionStorage');
    expect(err instanceof StorageError).toBe(true);
    expect(err.message).toContain('sessionStorage');
  });

  test('StorageQuotaExceededError extends StorageError', () => {
    const err = new StorageQuotaExceededError();
    expect(err instanceof StorageError).toBe(true);
    expect(err.name).toBe('StorageQuotaExceededError');
  });

  test('ServerError extends NetworkError', () => {
    const err = new ServerError(500, 'internal');
    expect(err instanceof NetworkError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.message).toContain('500');
  });

  test('InvalidPasswordError extends ValidationError', () => {
    const err = new InvalidPasswordError('too short');
    expect(err instanceof ValidationError).toBe(true);
    expect(err instanceof CryptoError).toBe(true);
    expect(err.name).toBe('InvalidPasswordError');
  });
});

// ============================================================================
// wrapError
// ============================================================================

describe('wrapError', () => {
  test('returns CryptoError unchanged', () => {
    const original = new EncryptionError('enc fail');
    const wrapped = wrapError(original, 'default');
    expect(wrapped).toBe(original); // same reference
  });

  test('wraps plain Error', () => {
    const original = new Error('plain error');
    const wrapped = wrapError(original, 'default msg');
    expect(wrapped instanceof CryptoError).toBe(true);
    expect(wrapped.code).toBe('WRAPPED_ERROR');
    expect(wrapped.message).toBe('plain error');
  });

  test('wraps string', () => {
    const wrapped = wrapError('some string', 'default msg');
    expect(wrapped instanceof CryptoError).toBe(true);
    expect(wrapped.code).toBe('UNKNOWN_ERROR');
    expect(wrapped.message).toBe('default msg');
  });

  test('wraps null/undefined', () => {
    const wrapped = wrapError(null, 'fallback');
    expect(wrapped.message).toBe('fallback');
    expect(wrapped.code).toBe('UNKNOWN_ERROR');
  });

  test('wraps number', () => {
    const wrapped = wrapError(42, 'fallback');
    expect(wrapped instanceof CryptoError).toBe(true);
    expect(wrapped.message).toBe('fallback');
  });
});

// ============================================================================
// isCryptoError
// ============================================================================

describe('isCryptoError', () => {
  test('returns true for CryptoError', () => {
    expect(isCryptoError(new CryptoError('msg', 'CODE'))).toBe(true);
  });

  test('returns true for subclasses', () => {
    expect(isCryptoError(new EncryptionError('msg'))).toBe(true);
    expect(isCryptoError(new AuthenticationError())).toBe(true);
    expect(isCryptoError(new ServerError(500, 'err'))).toBe(true);
  });

  test('returns false for plain Error', () => {
    expect(isCryptoError(new Error('msg'))).toBe(false);
  });

  test('returns false for non-errors', () => {
    expect(isCryptoError('string')).toBe(false);
    expect(isCryptoError(null)).toBe(false);
    expect(isCryptoError(undefined)).toBe(false);
    expect(isCryptoError(42)).toBe(false);
  });
});

// ============================================================================
// getUserFriendlyMessage
// ============================================================================

describe('getUserFriendlyMessage', () => {
  test('AuthenticationError → tampered/wrong password message', () => {
    const msg = getUserFriendlyMessage(new AuthenticationError());
    expect(msg).toContain('Authentication failed');
    expect(msg).toContain('password');
  });

  test('CorruptedDataError → corrupted message', () => {
    const msg = getUserFriendlyMessage(new CorruptedDataError('bad'));
    expect(msg).toContain('corrupted');
  });

  test('ExpiredKeyError → session expired', () => {
    const msg = getUserFriendlyMessage(new ExpiredKeyError('session', Date.now()));
    expect(msg).toContain('expired');
  });

  test('FileTooLargeError → max size message', () => {
    const msg = getUserFriendlyMessage(new FileTooLargeError(10, 5));
    expect(msg).toContain('too large');
  });

  test('InvalidPasswordError → check password', () => {
    const msg = getUserFriendlyMessage(new InvalidPasswordError('short'));
    expect(msg).toContain('Invalid password');
  });

  test('KeyDerivationTimeoutError → took too long', () => {
    const msg = getUserFriendlyMessage(new KeyDerivationTimeoutError(5000));
    expect(msg).toContain('too long');
  });

  test('OpaqueAuthenticationError → check credentials', () => {
    const msg = getUserFriendlyMessage(new OpaqueAuthenticationError('fail'));
    expect(msg).toContain('credentials');
  });

  test('ServerError → try again later', () => {
    const msg = getUserFriendlyMessage(new ServerError(500, 'err'));
    expect(msg).toContain('Server error');
  });

  test('StorageQuotaExceededError → clear space', () => {
    const msg = getUserFriendlyMessage(new StorageQuotaExceededError());
    expect(msg).toContain('quota');
  });

  test('UnsupportedProtocolVersionError → update app', () => {
    const msg = getUserFriendlyMessage(new UnsupportedProtocolVersionError(2, 1));
    expect(msg).toContain('unsupported version');
  });

  test('WebCryptoUnavailableError → browser support', () => {
    const msg = getUserFriendlyMessage(new WebCryptoUnavailableError());
    expect(msg).toContain('browser');
  });

  test('generic CryptoError → returns message', () => {
    const msg = getUserFriendlyMessage(new CryptoError('custom msg', 'CODE'));
    expect(msg).toBe('custom msg');
  });

  test('plain Error → returns message', () => {
    const msg = getUserFriendlyMessage(new Error('plain'));
    expect(msg).toBe('plain');
  });

  test('non-error → unknown error', () => {
    expect(getUserFriendlyMessage(42)).toBe('An unknown error occurred.');
    expect(getUserFriendlyMessage(null)).toBe('An unknown error occurred.');
  });
});
