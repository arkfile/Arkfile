/**
 * Authentication utilities
 *
 * Session tokens are stored in HttpOnly __Host-* cookies set by the server.
 * JavaScript cannot read those cookies. This module provides:
 *
 *  - getCsrfToken()       reads the NON-HttpOnly __Host-arkfile-csrf cookie
 *  - isAuthenticated()    infers session presence from the CSRF cookie
 *  - authenticatedFetch() adds X-CSRF-Token + credentials:'include'
 *  - getCurrentUser()     calls GET /api/auth/me to retrieve username/role
 *  - logout()             calls POST /api/logout (cookies cleared server-side)
 *  - revokeAllSessions()  calls POST /api/auth/revoke-all
 *  - refreshToken()       calls POST /api/refresh
 */

import { clearAllCachedAccountKeys } from '../crypto/file-encryption.js';
import { clearDigestCache } from './digest-cache.js';

// Cookie names (must match handlers/cookies.go constants)
const CSRF_COOKIE_NAME = '__Host-arkfile-csrf';

/**
 * Read the CSRF token from the non-HttpOnly cookie set by the server.
 * Returns empty string when no browser session is active.
 */
function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, ...valueParts] = cookie.trim().split('=');
    if (name === CSRF_COOKIE_NAME) {
      return decodeURIComponent(valueParts.join('='));
    }
  }
  return '';
}

/**
 * Infer whether a full browser session is active by checking for the CSRF
 * cookie. The full JWT itself is HttpOnly and not readable here; the CSRF
 * cookie co-exists with it and has the same Max-Age.
 */
function checkAuthenticated(): boolean {
  return getCsrfToken() !== '';
}

export interface JwtPayload {
  username: string;
  exp: number;
  iat: number;
  sub?: string;
  jti?: string;
  is_admin?: boolean;
}

export interface CurrentUserInfo {
  username: string;
  is_approved: boolean;
  is_admin: boolean;
  total_storage: number;
  storage_limit: number;
  storage_used_pc: number;
}

/**
 * Custom error for 503 Service Unavailable responses.
 */
export class ServiceUnavailableError extends Error {
  constructor(message = 'Service is temporarily unavailable. Please try again in a moment.') {
    super(message);
    this.name = 'ServiceUnavailableError';
  }
}

// Module-private cache for the current user info loaded after login.
// Populated by getCurrentUser(); cleared on logout.
let _cachedUser: CurrentUserInfo | null = null;

export class AuthManager {
  // Auto-refresh timer: fires slightly before the 30-minute JWT TTL.
  private static autoRefreshTimer: number | null = null;
  private static visibilityRefreshAttached = false;
  // 25 minutes — fires with 5 minutes to spare before the 30-minute JWT TTL.
  private static readonly AUTO_REFRESH_INTERVAL = 25 * 60 * 1000;

  public static isAuthenticated(): boolean {
    return checkAuthenticated();
  }

  public static getCsrfToken(): string {
    return getCsrfToken();
  }

  // Token refresh: sends cookie automatically; no body needed for browser clients.
  public static async refreshToken(): Promise<boolean> {
    try {
      const response = await fetch('/api/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        // Body empty: browser sends __Host-arkfile-refresh cookie automatically.
        body: JSON.stringify({}),
      });

      if (response.ok) {
        // New cookies issued by server automatically replace old ones.
        return true;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Token refresh error:', error);
      return false;
    }
  }

  // Session revocation
  public static async revokeAllSessions(): Promise<boolean> {
    try {
      const response = await fetch('/api/auth/revoke-all', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
      });

      if (response.ok) {
        _cachedUser = null;
        return true;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Revoke sessions error:', error);
      return false;
    }
  }

  // Logout: server expires all cookies.
  public static async logout(): Promise<boolean> {
    try {
      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          // Logout sends CSRF to prove it's intentional (not a CSRF attack).
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({}),
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
    // Clear the non-HttpOnly CSRF cookie directly from JavaScript. This ensures checkAuthenticated()
    // instantly fails on the next reload, preventing unauthenticated page auto-rendering.
    document.cookie = `${CSRF_COOKIE_NAME}=; Path=/; Max-Age=0; Secure; SameSite=Strict`;
    
    // Always clear local caches regardless of network outcome.
    _cachedUser = null;
    return true;
  }

  // Fetch user identity from the server (JWT is HttpOnly; JS cannot decode it).
  public static async getCurrentUser(force = false): Promise<CurrentUserInfo | null> {
    if (_cachedUser && !force) return _cachedUser;
    try {
      const response = await this.authenticatedFetch('/api/auth/me');
      if (response.ok) {
        const data = await response.json();
        _cachedUser = data.data as CurrentUserInfo;
        return _cachedUser;
      }
    } catch (error) {
      console.error('getCurrentUser error:', error);
    }
    return null;
  }

  public static getCachedUser(): CurrentUserInfo | null {
    return _cachedUser;
  }

  // Username from cache (populated after login via getCurrentUser).
  public static getUsernameFromToken(): string | null {
    return _cachedUser?.username ?? null;
  }

  // Token expiry: not available client-side (JWT is HttpOnly).
  // Auto-refresh timer provides the functional equivalent.
  public static getTokenExpiry(): Date | null { return null; }
  public static isTokenExpired(): boolean { return !checkAuthenticated(); }

  // Admin contact management
  private static adminUsernames: string[] = ['default-admin'];
  private static adminContact: string = 'admin@example.com';

  public static async fetchAdminContacts(): Promise<{usernames: string[], contact: string}> {
    try {
      const response = await fetch('/api/admin-contacts');
      if (response.ok) {
        const data = await response.json();
        this.adminUsernames = data.adminUsernames || ['default-admin'];
        this.adminContact = data.adminContact || 'admin@example.com';
      }
    } catch (error) {
      console.warn('Could not fetch admin contacts:', error);
    }
    return { usernames: this.adminUsernames, contact: this.adminContact };
  }

  public static getAdminUsernames(): string[] {
    return this.adminUsernames;
  }

  public static getAdminContact(): string {
    return this.adminContact;
  }

  // Auto-refresh timer management
  public static startAutoRefresh(): void {
    this.stopAutoRefresh();
    this.attachVisibilityRefresh();
    this.autoRefreshTimer = window.setInterval(async () => {
      if (this.isAuthenticated()) {
        const success = await this.refreshToken();
        if (!success) {
          console.warn('Auto-refresh failed, session may expire soon');
        }
      }
    }, this.AUTO_REFRESH_INTERVAL);
  }

  /** Refresh the session when the user returns to this tab (e.g. from BTCPay checkout). */
  public static attachVisibilityRefresh(): void {
    if (this.visibilityRefreshAttached || typeof document === 'undefined') {
      return;
    }
    this.visibilityRefreshAttached = true;
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && this.isAuthenticated()) {
        void this.refreshToken();
      }
    });
  }

  public static stopAutoRefresh(): void {
    if (this.autoRefreshTimer !== null) {
      clearInterval(this.autoRefreshTimer);
      this.autoRefreshTimer = null;
    }
  }

  // Authenticated fetch for browser clients.
  // Sends cookies automatically (credentials:'include') and adds the CSRF header.
  // Safe methods (GET/HEAD) also include the header for simplicity; server only
  // enforces it on state-changing methods.
  public static async authenticatedFetch(
    url: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const csrfToken = getCsrfToken();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    // Remove any Authorization header that might have been set by old code;
    // browser auth is entirely cookie-based.
    delete headers['Authorization'];

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include',
    });

    if (response.status === 503) {
      throw new ServiceUnavailableError();
    }

    return response;
  }

  // Validate session by calling the /api/auth/me endpoint.
  public static async validateToken(): Promise<boolean> {
    try {
      const response = await this.authenticatedFetch('/api/auth/me');
      return response.ok;
    } catch (error) {
      console.error('Token validation error:', error);
      return false;
    }
  }

  // Session state management
  public static clearAllSessionData(): void {
    _cachedUser = null;
    this.stopAutoRefresh();

    // Clear cached encryption keys and digest cache.
    clearAllCachedAccountKeys();
    clearDigestCache();

    // Clear any window-level auth flow data that may still be present.
    if (typeof window !== 'undefined') {
      delete window.registrationData;
      delete window.totpLoginData;
      delete window.totpSetupData;
    }
  }
}

// Returns a headers fragment carrying the CSRF token when a browser session
// cookie is present, or an empty object otherwise. Used by bootstrap/auth POSTs
// (OPAQUE login/register, MFA handoff) that issue plain fetches but may run
// while a stale full-tier cookie still exists in the browser, which would
// otherwise trip CSRFMiddleware with "CSRF token missing".
export function csrfHeader(): Record<string, string> {
  const token = getCsrfToken();
  return token ? { 'X-CSRF-Token': token } : {};
}

// Utility function exports
export const getCsrfTokenExport = getCsrfToken;
export const isAuthenticated = AuthManager.isAuthenticated.bind(AuthManager);
export const getUsernameFromToken = AuthManager.getUsernameFromToken.bind(AuthManager);
export const isTokenExpired = AuthManager.isTokenExpired.bind(AuthManager);
export const getTokenExpiry = AuthManager.getTokenExpiry.bind(AuthManager);
export const refreshToken = AuthManager.refreshToken.bind(AuthManager);
export const revokeAllSessions = AuthManager.revokeAllSessions.bind(AuthManager);
export const logout = AuthManager.logout.bind(AuthManager);
export const validateToken = AuthManager.validateToken.bind(AuthManager);
export const authenticatedFetch = AuthManager.authenticatedFetch.bind(AuthManager);
export const clearAllSessionData = AuthManager.clearAllSessionData.bind(AuthManager);
export const fetchAdminContacts = AuthManager.fetchAdminContacts.bind(AuthManager);
export const getAdminUsernames = AuthManager.getAdminUsernames.bind(AuthManager);
export const getAdminContact = AuthManager.getAdminContact.bind(AuthManager);
export const startAutoRefresh = AuthManager.startAutoRefresh.bind(AuthManager);
export const stopAutoRefresh = AuthManager.stopAutoRefresh.bind(AuthManager);
export const getCurrentUser = AuthManager.getCurrentUser.bind(AuthManager);
export const getCachedUser = AuthManager.getCachedUser.bind(AuthManager);
