/**
 * Login functionality using OPAQUE protocol
 */

import { showError, showSuccess } from '../ui/messages.js';
import { showProgressMessage, hideProgress } from '../ui/progress.js';
import { setTokens, getUsernameFromToken, clearAllSessionData } from '../utils/auth.js';
import { showFileSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';
import { handleTOTPFlow } from './totp.js';
import { getOpaqueClient, storeClientSecret, retrieveClientSecret, clearClientSecret } from '../crypto/opaque.js';

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
      showProgressMessage('Authenticating...');

      // Initialize OPAQUE client
      const opaqueClient = await getOpaqueClient();

      // Step 1: Generate credential request using OPAQUE
      const loginInit = await opaqueClient.startLogin({
        username: credentials.username,
        password: credentials.password
      });

      // Store client secret in sessionStorage for step 2
      storeClientSecret('login_secret', loginInit.clientSecret);

      // Send credential request to server
      const responseStep1 = await fetch('/api/opaque/auth/response', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          credential_request: loginInit.requestData
        })
      });
      
      if (!responseStep1.ok) {
        const errorText = await responseStep1.text();
        clearClientSecret('login_secret');
        hideProgress();
        showError(`Authentication failed: ${errorText}`);
        return;
      }
      
      const step1Data = await responseStep1.json();
      
      // Retrieve client secret from sessionStorage
      const clientSecret = retrieveClientSecret('login_secret');
      if (!clientSecret) {
        hideProgress();
        showError('Session expired. Please try again.');
        return;
      }

      // Step 2: Finalize authentication with server's credential response
      const loginFinalize = await opaqueClient.finalizeLogin({
        username: credentials.username,
        serverResponse: step1Data.credential_response,
        serverPublicKey: step1Data.server_public_key || null,
        clientSecret: clientSecret
      });

      // Clear client secret after use
      clearClientSecret('login_secret');

      // Send authentication token to server for verification
      const responseStep2 = await fetch('/api/opaque/auth/finalize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          auth_u: loginFinalize.authData
        })
      });
      
      if (!responseStep2.ok) {
        const errorText = await responseStep2.text();
        hideProgress();
        showError(`Authentication finalization failed: ${errorText}`);
        return;
      }
      
      const loginData = await responseStep2.json();
      
      // Handle TOTP if required
      if (loginData.requires_totp) {
        hideProgress();
        // Convert session key to base64 for TOTP flow
        const sessionKeyBase64 = btoa(String.fromCharCode(...loginFinalize.sessionKey));
        handleTOTPFlow({
          tempToken: loginData.temp_token!,
          sessionKey: sessionKeyBase64,
          username: credentials.username
        });
        return;
      }
      
      // Convert session key to base64 for storage
      const sessionKeyBase64 = btoa(String.fromCharCode(...loginFinalize.sessionKey));
      
      // Complete authentication with tokens from server
      await this.completeLogin({
        token: loginData.token,
        refresh_token: loginData.refresh_token,
        session_key: sessionKeyBase64,
        auth_method: 'OPAQUE'
      }, credentials.username);
      
    } catch (error) {
      // Clean up on error
      clearClientSecret('login_secret');
      hideProgress();
      console.error('Login error:', error);
      showError('Authentication failed');
    }
  }

  public static async completeLogin(data: LoginResponse, username: string): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refresh_token);
      
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
      // Use auth manager to handle token cleanup and API call
      const { logout } = await import('../utils/auth.js');
      await logout();
      
      // Clear all session data including OPAQUE secrets
      clearAllSessionData();
      clearClientSecret('login_secret');
      
      // Navigate back to auth section
      const { showAuthSection } = await import('../ui/sections.js');
      showAuthSection();
      
      showSuccess('Logged out successfully.');
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still attempt cleanup even on error
      clearAllSessionData();
      clearClientSecret('login_secret');
      
      const { showAuthSection } = await import('../ui/sections.js');
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
