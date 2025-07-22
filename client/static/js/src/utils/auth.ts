/**
 * Authentication utilities
 */

export class AuthManager {
  private static readonly TOKEN_KEY = 'token';
  private static readonly REFRESH_TOKEN_KEY = 'refreshToken';

  // Token management
  public static getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  public static getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  public static setTokens(token: string, refreshToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }

  public static clearTokens(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }

  public static isAuthenticated(): boolean {
    return this.getToken() !== null;
  }

  // Token refresh functionality
  public static async refreshToken(): Promise<boolean> {
    try {
      const refreshToken = this.getRefreshToken();
      if (!refreshToken) {
        this.clearTokens();
        return false;
      }

      const response = await fetch('/api/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken }),
      });

      if (response.ok) {
        const data = await response.json();
        this.setTokens(data.token, data.refreshToken);
        return true;
      } else {
        this.clearTokens();
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
      const token = this.getToken();
      if (!token) return false;

      const response = await fetch('/api/revoke-all', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        }
      });

      if (response.ok) {
        this.clearTokens();
        return true;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Revoke sessions error:', error);
      return false;
    }
  }

  // Logout functionality
  public static async logout(): Promise<boolean> {
    try {
      const refreshToken = this.getRefreshToken();
      
      if (refreshToken) {
        // Call the logout API to revoke the refresh token
        await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ refreshToken }),
        });
      }
      
      this.clearTokens();
      return true;
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear tokens even on error
      this.clearTokens();
      return false;
    }
  }

  // JWT token parsing
  public static parseJwtToken(token: string): any | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = JSON.parse(atob(parts[1]));
      return payload;
    } catch (error) {
      console.error('Error parsing JWT token:', error);
      return null;
    }
  }

  public static getUserEmailFromToken(): string | null {
    const token = this.getToken();
    if (!token) return null;
    
    const payload = this.parseJwtToken(token);
    return payload?.email || null;
  }

  public static getTokenExpiry(): Date | null {
    const token = this.getToken();
    if (!token) return null;
    
    const payload = this.parseJwtToken(token);
    if (!payload?.exp) return null;
    
    return new Date(payload.exp * 1000);
  }

  public static isTokenExpired(): boolean {
    const expiry = this.getTokenExpiry();
    if (!expiry) return true;
    
    return Date.now() >= expiry.getTime();
  }

  // Admin contact management
  private static adminEmails: string[] = ['admin@arkfile.demo'];

  public static async fetchAdminEmails(): Promise<string[]> {
    try {
      const response = await fetch('/api/admin-contacts');
      if (response.ok) {
        const data = await response.json();
        this.adminEmails = data.adminEmails || ['admin@arkfile.demo'];
      }
    } catch (error) {
      console.warn('Could not fetch admin emails:', error);
    }
    return this.adminEmails;
  }

  public static getAdminEmails(): string[] {
    return this.adminEmails;
  }

  // API helpers with authentication
  public static async authenticatedFetch(
    url: string, 
    options: RequestInit = {}
  ): Promise<Response> {
    const token = this.getToken();
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return fetch(url, {
      ...options,
      headers,
    });
  }

  // Token validation by making API call
  public static async validateToken(): Promise<boolean> {
    try {
      const response = await this.authenticatedFetch('/api/files');
      return response.ok;
    } catch (error) {
      console.error('Token validation error:', error);
      return false;
    }
  }

  // Session state management
  public static clearAllSessionData(): void {
    // Clear tokens
    this.clearTokens();
    
    // Clear any legacy session context
    if (typeof window !== 'undefined') {
      // @ts-ignore - Legacy cleanup
      delete window.arkfileSecurityContext;
      
      // @ts-ignore - Legacy cleanup
      delete window.registrationData;
      
      // @ts-ignore - Legacy cleanup
      delete window.totpLoginData;
      
      // @ts-ignore - Legacy cleanup
      delete window.totpSetupData;
    }
  }
}

// Optimized utility function exports - direct references to reduce bundle size
export const getToken = AuthManager.getToken.bind(AuthManager);
export const getRefreshToken = AuthManager.getRefreshToken.bind(AuthManager);
export const setTokens = AuthManager.setTokens.bind(AuthManager);
export const clearTokens = AuthManager.clearTokens.bind(AuthManager);
export const isAuthenticated = AuthManager.isAuthenticated.bind(AuthManager);
export const getUserEmailFromToken = AuthManager.getUserEmailFromToken.bind(AuthManager);
export const isTokenExpired = AuthManager.isTokenExpired.bind(AuthManager);
export const refreshToken = AuthManager.refreshToken.bind(AuthManager);
export const revokeAllSessions = AuthManager.revokeAllSessions.bind(AuthManager);
export const logout = AuthManager.logout.bind(AuthManager);
export const validateToken = AuthManager.validateToken.bind(AuthManager);
export const authenticatedFetch = AuthManager.authenticatedFetch.bind(AuthManager);
export const clearAllSessionData = AuthManager.clearAllSessionData.bind(AuthManager);
export const fetchAdminEmails = AuthManager.fetchAdminEmails.bind(AuthManager);
export const getAdminEmails = AuthManager.getAdminEmails.bind(AuthManager);
