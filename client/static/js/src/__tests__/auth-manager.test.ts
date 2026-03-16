/**
 * Unit Tests -- AuthManager
 *
 * Tests for: token storage, JWT parsing, expiry checks, clearAllSessionData,
 *            ServiceUnavailableError, admin contact defaults
 *
 * AuthManager uses localStorage (not sessionStorage), so we install a
 * Map-backed localStorage mock before importing the module.
 */

import './setup';
import { describe, test, expect, beforeEach } from 'bun:test';

// ============================================================================
// localStorage mock (Map-backed) -- AuthManager uses localStorage
// ============================================================================

class MockLocalStorage implements Storage {
  private store = new Map<string, string>();

  get length(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  key(index: number): string | null {
    const keys = Array.from(this.store.keys());
    return keys[index] ?? null;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

if (typeof globalThis.localStorage === 'undefined') {
  (globalThis as any).localStorage = new MockLocalStorage();
}

// Import after localStorage is available
import {
  AuthManager,
  ServiceUnavailableError,
} from '../utils/auth';

// ============================================================================
// Helper: build a fake JWT with given payload
// ============================================================================

function buildJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const sig = btoa('fake-signature');
  return `${header}.${body}.${sig}`;
}

// ============================================================================
// Setup
// ============================================================================

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
});

// ============================================================================
// Token storage
// ============================================================================

describe('AuthManager token storage', () => {
  test('getToken returns null when no token stored', () => {
    expect(AuthManager.getToken()).toBeNull();
  });

  test('getRefreshToken returns null when no token stored', () => {
    expect(AuthManager.getRefreshToken()).toBeNull();
  });

  test('setTokens stores both tokens', () => {
    AuthManager.setTokens('access-tok', 'refresh-tok');
    expect(AuthManager.getToken()).toBe('access-tok');
    expect(AuthManager.getRefreshToken()).toBe('refresh-tok');
  });

  test('clearTokens removes both tokens', () => {
    AuthManager.setTokens('a', 'b');
    AuthManager.clearTokens();
    expect(AuthManager.getToken()).toBeNull();
    expect(AuthManager.getRefreshToken()).toBeNull();
  });

  test('isAuthenticated returns false when no token', () => {
    expect(AuthManager.isAuthenticated()).toBe(false);
  });

  test('isAuthenticated returns true when token present', () => {
    AuthManager.setTokens('tok', 'ref');
    expect(AuthManager.isAuthenticated()).toBe(true);
  });
});

// ============================================================================
// JWT parsing
// ============================================================================

describe('AuthManager.parseJwtToken', () => {
  test('parses valid JWT payload', () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = buildJwt({
      username: 'testuser01',
      exp: now + 3600,
      iat: now,
      sub: 'testuser01',
      jti: 'abc-123',
      is_admin: false,
    });

    const payload = AuthManager.parseJwtToken(jwt);
    expect(payload).not.toBeNull();
    expect(payload!.username).toBe('testuser01');
    expect(payload!.exp).toBe(now + 3600);
    expect(payload!.iat).toBe(now);
    expect(payload!.sub).toBe('testuser01');
    expect(payload!.jti).toBe('abc-123');
    expect(payload!.is_admin).toBe(false);
  });

  test('returns null for malformed JWT (not 3 parts)', () => {
    expect(AuthManager.parseJwtToken('not-a-jwt')).toBeNull();
    expect(AuthManager.parseJwtToken('a.b')).toBeNull();
    expect(AuthManager.parseJwtToken('')).toBeNull();
  });

  test('returns null for invalid base64 payload', () => {
    expect(AuthManager.parseJwtToken('a.!!!invalid!!!.c')).toBeNull();
  });

  test('returns null when payload missing username', () => {
    const jwt = buildJwt({ exp: 9999999999 });
    expect(AuthManager.parseJwtToken(jwt)).toBeNull();
  });

  test('returns null when payload missing exp', () => {
    const jwt = buildJwt({ username: 'testuser01' });
    expect(AuthManager.parseJwtToken(jwt)).toBeNull();
  });

  test('returns null when username is not a string', () => {
    const jwt = buildJwt({ username: 12345, exp: 9999999999 });
    expect(AuthManager.parseJwtToken(jwt)).toBeNull();
  });

  test('returns null when exp is not a number', () => {
    const jwt = buildJwt({ username: 'testuser01', exp: 'not-a-number' });
    expect(AuthManager.parseJwtToken(jwt)).toBeNull();
  });
});

// ============================================================================
// getUsernameFromToken / getTokenExpiry / isTokenExpired
// ============================================================================

describe('AuthManager token utility methods', () => {
  test('getUsernameFromToken extracts username', () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = buildJwt({ username: 'alice.user.2024', exp: now + 3600, iat: now });
    AuthManager.setTokens(jwt, 'ref');
    expect(AuthManager.getUsernameFromToken()).toBe('alice.user.2024');
  });

  test('getUsernameFromToken returns null when no token', () => {
    expect(AuthManager.getUsernameFromToken()).toBeNull();
  });

  test('getTokenExpiry returns Date object', () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const jwt = buildJwt({ username: 'testuser01', exp, iat: exp - 100 });
    AuthManager.setTokens(jwt, 'ref');
    const expiry = AuthManager.getTokenExpiry();
    expect(expiry).toBeInstanceOf(Date);
    expect(expiry!.getTime()).toBe(exp * 1000);
  });

  test('getTokenExpiry returns null when no token', () => {
    expect(AuthManager.getTokenExpiry()).toBeNull();
  });

  test('isTokenExpired returns true when no token', () => {
    expect(AuthManager.isTokenExpired()).toBe(true);
  });

  test('isTokenExpired returns false for future expiry', () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const jwt = buildJwt({ username: 'testuser01', exp, iat: exp - 100 });
    AuthManager.setTokens(jwt, 'ref');
    expect(AuthManager.isTokenExpired()).toBe(false);
  });

  test('isTokenExpired returns true for past expiry', () => {
    const exp = Math.floor(Date.now() / 1000) - 100; // expired 100s ago
    const jwt = buildJwt({ username: 'testuser01', exp, iat: exp - 3600 });
    AuthManager.setTokens(jwt, 'ref');
    expect(AuthManager.isTokenExpired()).toBe(true);
  });
});

// ============================================================================
// clearAllSessionData
// ============================================================================

describe('AuthManager.clearAllSessionData', () => {
  test('clears tokens from localStorage', () => {
    AuthManager.setTokens('tok', 'ref');
    AuthManager.clearAllSessionData();
    expect(AuthManager.getToken()).toBeNull();
    expect(AuthManager.getRefreshToken()).toBeNull();
  });

  test('clears sessionStorage (account key cache, digest cache)', () => {
    sessionStorage.setItem('arkfile_account_key_testuser01', 'cached-key');
    sessionStorage.setItem('arkfile.digestCache', '{"file1":"abc123"}');
    AuthManager.clearAllSessionData();
    expect(sessionStorage.getItem('arkfile_account_key_testuser01')).toBeNull();
    expect(sessionStorage.getItem('arkfile.digestCache')).toBeNull();
  });
});

// ============================================================================
// ServiceUnavailableError
// ============================================================================

describe('ServiceUnavailableError', () => {
  test('has correct name', () => {
    const err = new ServiceUnavailableError();
    expect(err.name).toBe('ServiceUnavailableError');
  });

  test('has default message', () => {
    const err = new ServiceUnavailableError();
    expect(err.message).toContain('temporarily unavailable');
  });

  test('accepts custom message', () => {
    const err = new ServiceUnavailableError('custom msg');
    expect(err.message).toBe('custom msg');
  });

  test('is instanceof Error', () => {
    const err = new ServiceUnavailableError();
    expect(err).toBeInstanceOf(Error);
  });
});

// ============================================================================
// Admin contact defaults
// ============================================================================

describe('AuthManager admin contacts', () => {
  test('getAdminUsernames returns default array', () => {
    const usernames = AuthManager.getAdminUsernames();
    expect(Array.isArray(usernames)).toBe(true);
    expect(usernames.length).toBeGreaterThan(0);
  });

  test('getAdminContact returns default string', () => {
    const contact = AuthManager.getAdminContact();
    expect(typeof contact).toBe('string');
    expect(contact.length).toBeGreaterThan(0);
  });
});
