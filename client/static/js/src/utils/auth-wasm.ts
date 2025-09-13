/**
 * Minimal TypeScript wrapper for Go/WASM JWT token management
 * This replaces the AuthManager class with direct WASM function calls
 */

// Type declarations for WASM functions
declare global {
  function setJWTTokens(token: string, refreshToken: string): any;
  function getJWTToken(): any;
  function getRefreshToken(): any;
  function clearJWTTokens(): any;
  function isJWTTokenExpired(): any;
  function parseJWTClaims(token: string): any;
  function isAuthenticated(): any;
  function refreshJWTToken(): any;
  function startAutoRefresh(): any;
  function stopAutoRefresh(): any;
  function authenticatedFetch(url: string, options?: any): any;
  function clearSession(): any;
}

// Global callback function for auto-refresh (called from Go/WASM)
declare global {
  function handleAutoRefresh(): void;
}

// Setup auto-refresh callback
(window as any).handleAutoRefresh = async () => {
  try {
    const result = await refreshToken();
    if (!result) {
      console.warn('Auto-refresh failed - clearing tokens');
      clearTokens();
      // Redirect to login if needed
      if (window.location.pathname !== '/') {
        window.location.href = '/';
      }
    }
  } catch (error) {
    console.error('Auto-refresh error:', error);
    clearTokens();
  }
};

// Wrapper functions that call WASM and return TypeScript-friendly results

export function getToken(): string | null {
  const result = getJWTToken();
  return result.success ? result.token : null;
}

export function getRefreshTokenValue(): string | null {
  const result = getRefreshToken();
  return result.success ? result.refresh_token : null;
}

export function setTokens(token: string, refreshToken: string): void {
  const result = setJWTTokens(token, refreshToken);
  if (!result.success) {
    console.error('Failed to set tokens:', result.error);
    throw new Error(result.error);
  }
  
  // Start auto-refresh after setting tokens
  const autoRefreshResult = startAutoRefresh();
  if (!autoRefreshResult.success) {
    console.warn('Failed to start auto-refresh:', autoRefreshResult.error);
  }
}

export function clearTokens(): void {
  const result = clearJWTTokens();
  if (!result.success) {
    console.error('Failed to clear tokens:', result.error);
  }
  // Auto-refresh is automatically stopped in clearJWTTokens
}

export function isAuthenticated(): boolean {
  const result = (window as any).isAuthenticated();
  return result.authenticated === true;
}

export function isTokenExpired(): boolean {
  const result = isJWTTokenExpired();
  return result.expired === true;
}

export async function refreshToken(): Promise<boolean> {
  const result = refreshJWTToken();
  
  if (!result.success) {
    console.error('Refresh token failed:', result.error);
    return false;
  }

  // Handle the Promise returned from WASM
  try {
    const response = await result.promise;
    
    if (response.ok) {
      const data = await response.json();
      setTokens(data.token, data.refresh_token);
      return true;
    } else {
      console.error('Refresh response not ok:', response.status);
      clearTokens();
      return false;
    }
  } catch (error) {
    console.error('Refresh token error:', error);
    clearTokens();
    return false;
  }
}

export function getUsernameFromToken(): string | null {
  const token = getToken();
  if (!token) return null;
  
  const result = parseJWTClaims(token);
  if (!result.success) return null;
  
  return result.claims?.username || null;
}

// Legacy compatibility
export function getUserEmailFromToken(): string | null {
  return getUsernameFromToken();
}

export function getTokenExpiry(): Date | null {
  const token = getToken();
  if (!token) return null;
  
  const result = parseJWTClaims(token);
  if (!result.success || !result.claims?.exp) return null;
  
  return new Date(result.claims.exp * 1000);
}

export async function authenticatedFetch(
  url: string, 
  options: RequestInit = {}
): Promise<Response> {
  const result = (window as any).authenticatedFetch(url, options);
  
  if (!result.success) {
    throw new Error(result.error);
  }
  
  return await result.promise;
}

export async function logout(): Promise<boolean> {
  try {
    const refreshTokenValue = getRefreshTokenValue();
    
    if (refreshTokenValue) {
      // Call the logout API to revoke the refresh token
      await fetch('/api/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshTokenValue }),
      });
    }
    
    // Clear all session data
    const result = clearSession();
    return result.success;
  } catch (error) {
    console.error('Logout error:', error);
    // Still clear session data even on error
    clearSession();
    return false;
  }
}

export async function revokeAllSessions(): Promise<boolean> {
  try {
    const token = getToken();
    if (!token) return false;

    const response = await fetch('/api/revoke-all', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      }
    });

    if (response.ok) {
      clearTokens();
      return true;
    } else {
      return false;
    }
  } catch (error) {
    console.error('Revoke sessions error:', error);
    return false;
  }
}

export async function validateToken(): Promise<boolean> {
  try {
    const response = await authenticatedFetch('/api/files');
    return response.ok;
  } catch (error) {
    console.error('Token validation error:', error);
    return false;
  }
}

export function clearAllSessionData(): void {
  const result = clearSession();
  if (!result.success) {
    console.error('Failed to clear session data:', result.error);
  }
}

// Admin contact management (simplified - these could move to WASM later if needed)
export async function fetchAdminContacts(): Promise<{usernames: string[], contact: string}> {
  try {
    const response = await fetch('/api/admin-contacts');
    if (response.ok) {
      const data = await response.json();
      return {
        usernames: data.adminUsernames || ['admin.user.2024'],
        contact: data.adminContact || 'admin@arkfile.demo'
      };
    }
  } catch (error) {
    console.warn('Could not fetch admin contacts:', error);
  }
  return { usernames: ['admin.user.2024'], contact: 'admin@arkfile.demo' };
}

export function getAdminUsernames(): string[] {
  return ['admin.user.2024'];
}

export function getAdminContact(): string {
  return 'admin@arkfile.demo';
}

// Legacy compatibility
export async function fetchAdminEmails(): Promise<string[]> {
  const contacts = await fetchAdminContacts();
  return [contacts.contact];
}

export function getAdminEmails(): string[] {
  return [getAdminContact()];
}

// Re-export for backward compatibility with existing code
export {
  getToken as getJWTToken,
  getRefreshTokenValue as getRefreshToken,
  setTokens as setJWTTokens,
  clearTokens as clearJWTTokens,
  refreshToken as refreshJWTToken,
  clearAllSessionData as clearSession
};

/**
 * AuthManager class for backward compatibility
 * This maintains the same interface but delegates to WASM functions
 */
export class AuthManager {
  private static readonly TOKEN_KEY = 'token';
  private static readonly REFRESH_TOKEN_KEY = 'refreshToken';
  private static readonly AUTO_REFRESH_INTERVAL = 25 * 60 * 1000; // 25 minutes

  // Token management
  public static getToken(): string | null {
    return getToken();
  }

  public static getRefreshToken(): string | null {
    return getRefreshTokenValue();
  }

  public static setTokens(token: string, refreshToken: string): void {
    setTokens(token, refreshToken);
  }

  public static clearTokens(): void {
    clearTokens();
  }

  public static isAuthenticated(): boolean {
    return isAuthenticated();
  }

  public static async refreshToken(): Promise<boolean> {
    return await refreshToken();
  }

  public static async revokeAllSessions(): Promise<boolean> {
    return await revokeAllSessions();
  }

  public static async logout(): Promise<boolean> {
    return await logout();
  }

  public static parseJwtToken(token: string): any | null {
    const result = parseJWTClaims(token);
    return result.success ? result.claims : null;
  }

  public static getUsernameFromToken(): string | null {
    return getUsernameFromToken();
  }

  public static getUserEmailFromToken(): string | null {
    return getUserEmailFromToken();
  }

  public static getTokenExpiry(): Date | null {
    return getTokenExpiry();
  }

  public static isTokenExpired(): boolean {
    return isTokenExpired();
  }

  public static async authenticatedFetch(
    url: string, 
    options: RequestInit = {}
  ): Promise<Response> {
    return await authenticatedFetch(url, options);
  }

  public static async validateToken(): Promise<boolean> {
    return await validateToken();
  }

  public static clearAllSessionData(): void {
    clearAllSessionData();
  }

  public static async fetchAdminContacts(): Promise<{usernames: string[], contact: string}> {
    return await fetchAdminContacts();
  }

  public static getAdminUsernames(): string[] {
    return getAdminUsernames();
  }

  public static getAdminContact(): string {
    return getAdminContact();
  }

  public static async fetchAdminEmails(): Promise<string[]> {
    return await fetchAdminEmails();
  }

  public static getAdminEmails(): string[] {
    return getAdminEmails();
  }
}
