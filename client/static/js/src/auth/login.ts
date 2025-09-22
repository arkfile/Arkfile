/**
 * Login functionality
 */

import { wasmManager } from '../utils/wasm';
import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { setTokens, getUsernameFromToken, getUserEmailFromToken, clearAllSessionData } from '../utils/auth-wasm';
import { showFileSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { handleTOTPFlow } from './totp';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  refresh_token: string;
  session_key: string;
  auth_method: 'OPAQUE';
  requires_totp?: boolean;
  temp_token?: string;
}

export class LoginManager {
  public static async login(credentials: LoginCredentials): Promise<void> {
    if (!credentials.username || !credentials.password) {
      showError('Please enter both username and password.');
      return;
    }

    try {
      // Ensure WASM is ready
      await wasmManager.ensureReady();

      showProgressMessage('Authenticating...');

      // FIXED: Use Go/WASM HTTP request to OPAQUE endpoint
      const result = await wasmManager.performOpaqueLogin(credentials.username, credentials.password);
      
      if (result.success && result.promise) {
        try {
          const response = await result.promise;
          
          if (!response.ok) {
            const errorText = await response.text();
            hideProgress();
            showError(`Login failed: ${errorText}`);
            return;
          }
          
          const loginData = await response.json();
          
          // Handle TOTP if required
          if (loginData.requires_totp) {
            hideProgress();
            handleTOTPFlow({
              tempToken: loginData.temp_token!,
              sessionKey: loginData.session_key,
              username: credentials.username
            });
            return;
          }
          
          // Complete authentication with tokens from OPAQUE
          await this.completeLogin({
            token: loginData.token,
            refresh_token: loginData.refresh_token,
            session_key: loginData.session_key,
            auth_method: 'OPAQUE'
          }, credentials.username);
          
        } catch (error) {
          hideProgress();
          console.error('OPAQUE login error:', error);
          showError('Authentication failed - server error');
        }
      } else {
        hideProgress();
        showError(result.error || 'Login failed');
      }
    } catch (error) {
      hideProgress();
      console.error('Login error:', error);
      showError('Authentication failed');
    }
  }

  public static async completeLogin(data: LoginResponse, username: string): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refresh_token);

      // Create secure session in WASM (NEVER store session key in JavaScript)
      const sessionResult = await wasmManager.createSecureSessionFromKey(data.session_key, username);
      if (!sessionResult.success) {
        hideProgress();
        showError('Failed to create secure session: ' + sessionResult.error);
        return;
      }
      
      hideProgress();
      showSuccess('Login successful');
      
      // Navigate to file section and load files
      showFileSection();
      await loadFiles();
      
    } catch (error) {
      hideProgress();
      console.error('Login completion error:', error);
      showError('Failed to complete login');
    }
  }

  public static async logout(): Promise<void> {
    try {
      // Get username for secure session cleanup
      const username = getUsernameFromToken();
      
      // Clear secure session from WASM memory
      if (username) {
        await wasmManager.clearSecureSessionForUser(username);
      }
      
      // Use auth manager to handle token cleanup and API call
        const { logout } = await import('../utils/auth-wasm');
      await logout();
      
      // Clear all session data
      clearAllSessionData();
      
      // Navigate back to auth section
      const { showAuthSection } = await import('../ui/sections');
      showAuthSection();
      
      showSuccess('Logged out successfully.');
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still attempt cleanup even on error
      const username = getUsernameFromToken();
      if (username) {
        try {
          await wasmManager.clearSecureSessionForUser(username);
        } catch (e) {
          console.warn('Failed to clear secure session on logout error:', e);
        }
      }
      
      clearAllSessionData();
      
      const { showAuthSection } = await import('../ui/sections');
      showAuthSection();
    }
  }
}

// Form handling utilities
export function setupLoginForm(): void {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;

  const usernameInput = document.getElementById('login-username') as HTMLInputElement;
  const passwordInput = document.getElementById('login-password') as HTMLInputElement;
  const submitButton = loginForm.querySelector('button[type="submit"]') as HTMLButtonElement;

  if (!usernameInput || !passwordInput || !submitButton) return;

  // Handle form submission
  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    
    const credentials: LoginCredentials = {
      username: usernameInput.value.trim(),
      password: passwordInput.value
    };

    await LoginManager.login(credentials);
  };

  // Add event listeners
  loginForm.addEventListener('submit', handleSubmit);
  
  // Handle Enter key in form fields
  [usernameInput, passwordInput].forEach(input => {
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleSubmit(e);
      }
    });
  });

  // Clear any previous error states when user starts typing
  [usernameInput, passwordInput].forEach(input => {
    input.addEventListener('input', () => {
      input.classList.remove('error');
    });
  });
}

// Export utility functions for compatibility
export async function login(): Promise<void> {
  const usernameInput = document.getElementById('login-username') as HTMLInputElement;
  const passwordInput = document.getElementById('login-password') as HTMLInputElement;
  
  if (!usernameInput || !passwordInput) {
    showError('Login form not found.');
    return;
  }

  const credentials: LoginCredentials = {
    username: usernameInput.value.trim(),
    password: passwordInput.value
  };

  await LoginManager.login(credentials);
}

export async function logout(): Promise<void> {
  await LoginManager.logout();
}
