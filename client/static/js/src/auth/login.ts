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
import { 
  deriveAccountKeyWithCache,
  deriveFileEncryptionKeyWithCache,
  cleanupAccountKeyCache,
} from '../crypto/file-encryption.js';
import { registerAccountKeyCleanupHandlers } from '../crypto/account-key-cache.js';
import { showPasswordPrompt } from '../ui/password-modal.js';
import type { CacheDurationHours } from '../crypto/account-key-cache.js';
import { populateDigestCache, clearDigestCache, type RawFileEntry } from '../utils/digest-cache.js';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  refresh_token: string;
  auth_method: 'OPAQUE';
  requires_totp?: boolean;
  temp_token?: string;
  is_approved?: boolean;
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
      const responseStep1 = await fetch('/api/opaque/login/response', {
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
      
      // Extract data from standard API response structure
      const responseData = step1Data.data;
      if (!responseData || !responseData.credential_response || !responseData.session_id) {
        hideProgress();
        showError('Invalid server response: missing credential data');
        return;
      }
      
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
        serverResponse: responseData.credential_response,
        serverPublicKey: null, // Server public key is packaged in credential response (InSecEnv mode)
        clientSecret: clientSecret
      });

      // Clear client secret after use
      clearClientSecret('login_secret');

      // Send authentication token to server for verification
      const responseStep2 = await fetch('/api/opaque/login/finalize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          session_id: responseData.session_id,
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
      
      const loginResponse = await responseStep2.json();
      const loginData = loginResponse.data || loginResponse;
      
      // Discard session key immediately (not needed for this application)
      // JWT tokens handle all session management
      if (loginFinalize.sessionKey) {
        loginFinalize.sessionKey.fill(0);
      }

      // Cache the account key for file operations
      // This ensures the user doesn't need to re-enter their password for file operations
      // The key is stored in sessionStorage and cleared on logout/tab close
      let cachedAccountKey: Uint8Array | undefined;
      try {
        cachedAccountKey = await deriveFileEncryptionKeyWithCache(credentials.password, credentials.username, 'account');
      } catch (error) {
        console.warn('Failed to cache account key:', error);
        // Non-fatal error, user will just be prompted later if needed
      }
      
      // Populate digest cache for deduplication (non-fatal if it fails)
      if (cachedAccountKey) {
        try {
          const token = sessionStorage.getItem('arkfile.sessionToken') ||
                        localStorage.getItem('arkfile.sessionToken') ||
                        loginData.token;
          if (token) {
            const filesResp = await fetch('/api/files', {
              headers: { 'Authorization': `Bearer ${token}` },
            });
            if (filesResp.ok) {
              const filesData = await filesResp.json();
              const files: RawFileEntry[] = (filesData.files || filesData.data?.files || []);
              await populateDigestCache(cachedAccountKey, files);
            }
          }
        } catch (err) {
          console.warn('Failed to populate digest cache:', err);
        }
      }

      // Handle TOTP if required
      if (loginData.requires_totp) {
        hideProgress();
        handleTOTPFlow({
          tempToken: loginData.temp_token!,
          username: credentials.username
        });
        return;
      }
      
      // Complete authentication with tokens from server
      await this.completeLogin({
        token: loginData.token,
        refresh_token: loginData.refresh_token,
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
      
      // Check if user is approved
      if (data.is_approved === false) {
        // User is not approved - show pending approval section
        const { showPendingApprovalSection } = await import('../ui/sections.js');
        showPendingApprovalSection();
        showSuccess('Account created. Awaiting administrator approval.');
        return;
      }
      
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
      
      // Clear all session data including OPAQUE secrets, Account Key cache, and digest cache
      clearAllSessionData();
      clearClientSecret('login_secret');
      cleanupAccountKeyCache();
      clearDigestCache();
      
      // Navigate back to auth section
      const { showAuthSection } = await import('../ui/sections.js');
      showAuthSection();
      
      showSuccess('Logged out successfully.');
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still attempt cleanup even on error
      clearAllSessionData();
      clearClientSecret('login_secret');
      cleanupAccountKeyCache();
      clearDigestCache();
      
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
