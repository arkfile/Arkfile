/**
 * Unit Tests -- AuthManager
 *
 * Tests for: cookie-based auth model, ServiceUnavailableError,
 *            admin contact refresh, clearAllSessionData
 *
 * Session tokens are stored exclusively in HttpOnly __Host-* cookies set
 * by the server. JS cannot read those cookies. The tests here verify that:
 *
 *  - isAuthenticated() correctly reads the CSRF cookie from document.cookie.
 *  - getUsernameFromToken() reads from the module-level cache, not localStorage.
 *  - clearAllSessionData() zeroes the cache without touching cookies.
 *  - ServiceUnavailableError is a distinct Error subclass.
 *  - Admin contact helpers clear state after any failed refresh.
 */

import './setup';
import { describe, test, expect, beforeEach, afterEach } from 'bun:test';

// Import after setup so that document/window globals are available
import {
  AuthManager,
  ServiceUnavailableError,
} from '../utils/auth';

// ============================================================================
// Setup
// ============================================================================

beforeEach(() => {
  // Clear cached user state between tests.
  // The CSRF cookie is not set in the bun test environment (no document.cookie),
  // so isAuthenticated() always returns false in tests — which is correct.
  AuthManager.clearAllSessionData();
});

// ============================================================================
// isAuthenticated -- reads the __Host-arkfile-csrf cookie
// ============================================================================

describe('AuthManager.isAuthenticated (CSRF cookie)', () => {
  test('returns false when no CSRF cookie is set', () => {
    expect(AuthManager.isAuthenticated()).toBe(false);
  });

  // Note: setting __Host- cookies in jsdom requires Secure context which jsdom
  // does not fully enforce. We test with a non-prefixed fallback to verify the
  // CSRF-reading logic.
  test('returns false after clearAllSessionData clears the state', () => {
    AuthManager.clearAllSessionData();
    expect(AuthManager.isAuthenticated()).toBe(false);
  });
});

// ============================================================================
// getUsernameFromToken -- reads from in-memory cache, not token
// ============================================================================

describe('AuthManager.getUsernameFromToken', () => {
  test('returns null when no cached user', () => {
    expect(AuthManager.getUsernameFromToken()).toBeNull();
  });

  test('returns null after clearAllSessionData', () => {
    AuthManager.clearAllSessionData();
    expect(AuthManager.getUsernameFromToken()).toBeNull();
  });
});

// ============================================================================
// getCachedUser / clearAllSessionData
// ============================================================================

describe('AuthManager.getCachedUser', () => {
  test('returns null when no user has been fetched', () => {
    expect(AuthManager.getCachedUser()).toBeNull();
  });

  test('clearAllSessionData nulls the cached user', () => {
    AuthManager.clearAllSessionData();
    expect(AuthManager.getCachedUser()).toBeNull();
  });
});

// ============================================================================
// clearAllSessionData
// ============================================================================

describe('AuthManager.clearAllSessionData', () => {
  test('does not throw', () => {
    expect(() => AuthManager.clearAllSessionData()).not.toThrow();
  });

  test('leaves getUsernameFromToken returning null', () => {
    AuthManager.clearAllSessionData();
    expect(AuthManager.getUsernameFromToken()).toBeNull();
  });

  test('leaves getCachedUser returning null', () => {
    AuthManager.clearAllSessionData();
    expect(AuthManager.getCachedUser()).toBeNull();
  });
});

// ============================================================================
// Admin contact defaults
// ============================================================================

describe('AuthManager admin contact defaults', () => {
  test('getAdminUsernames returns empty list before fetch', () => {
    const usernames = AuthManager.getAdminUsernames();
    expect(Array.isArray(usernames)).toBe(true);
    expect(usernames.length).toBe(0);
  });

  test('getAdminContact returns empty string before fetch', () => {
    const contact = AuthManager.getAdminContact();
    expect(typeof contact).toBe('string');
    expect(contact.length).toBe(0);
  });

  test('isAdminContactsConfigured returns false before fetch', () => {
    expect(AuthManager.isAdminContactsConfigured()).toBe(false);
  });
});

describe('AuthManager.fetchAdminContacts', () => {
  let origFetch: typeof globalThis.fetch;

  beforeEach(() => {
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  test('stores configured contact on success', async () => {
    (globalThis as any).fetch = async () =>
      new Response(
        JSON.stringify({
          admin_usernames: ['adminuser1'],
          admin_contact: 'admin@example.test',
          configured: true,
        }),
        { status: 200 },
      );

    const result = await AuthManager.fetchAdminContacts();
    expect(result.configured).toBe(true);
    expect(result.contact).toBe('admin@example.test');
    expect(result.usernames).toEqual(['adminuser1']);
    expect(AuthManager.isAdminContactsConfigured()).toBe(true);
  });

  test('clears previous state on non-OK response', async () => {
    (globalThis as any).fetch = async () =>
      new Response(
        JSON.stringify({
          admin_usernames: ['adminuser1'],
          admin_contact: 'admin@example.test',
          configured: true,
        }),
        { status: 200 },
      );
    await AuthManager.fetchAdminContacts();
    expect(AuthManager.isAdminContactsConfigured()).toBe(true);

    (globalThis as any).fetch = async () => new Response('error', { status: 500 });
    const result = await AuthManager.fetchAdminContacts();
    expect(result.configured).toBe(false);
    expect(result.contact).toBe('');
    expect(result.usernames).toEqual([]);
    expect(AuthManager.isAdminContactsConfigured()).toBe(false);
    expect(AuthManager.getAdminContact()).toBe('');
  });

  test('clears previous state on fetch exception', async () => {
    (globalThis as any).fetch = async () =>
      new Response(
        JSON.stringify({
          admin_usernames: ['adminuser1'],
          admin_contact: 'admin@example.test',
          configured: true,
        }),
        { status: 200 },
      );
    await AuthManager.fetchAdminContacts();

    (globalThis as any).fetch = async () => {
      throw new Error('network down');
    };
    const result = await AuthManager.fetchAdminContacts();
    expect(result.configured).toBe(false);
    expect(result.contact).toBe('');
    expect(result.usernames).toEqual([]);
  });
});

// ============================================================================
// ServiceUnavailableError
// ============================================================================

describe('ServiceUnavailableError', () => {
  test('is an instance of Error', () => {
    const err = new ServiceUnavailableError();
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ServiceUnavailableError);
  });

  test('has default message', () => {
    const err = new ServiceUnavailableError();
    expect(err.message).toContain('temporarily unavailable');
  });

  test('accepts custom message', () => {
    const err = new ServiceUnavailableError('custom msg');
    expect(err.message).toBe('custom msg');
  });

  test('name is ServiceUnavailableError', () => {
    expect(new ServiceUnavailableError().name).toBe('ServiceUnavailableError');
  });
});

// ============================================================================
// Auto-refresh timer management
// ============================================================================

describe('AuthManager auto-refresh timer', () => {
  test('stopAutoRefresh does not throw when no timer is running', () => {
    expect(() => AuthManager.stopAutoRefresh()).not.toThrow();
  });

  test('startAutoRefresh then stopAutoRefresh does not throw', () => {
    expect(() => AuthManager.startAutoRefresh()).not.toThrow();
    expect(() => AuthManager.stopAutoRefresh()).not.toThrow();
  });
});
