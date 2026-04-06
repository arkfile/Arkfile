/**
 * Login functionality using OPAQUE protocol
 *
 * Login flow:
 * 1. OPAQUE two-step authentication (password never sent to server)
 * 2. If TOTP required: hand off to TOTP modal with password carried through
 * 3. After full authentication: cache opt-in, Account Key derivation, digest cache
 * 4. Show file section and load files
 */

import { showError, showSuccess } from '../ui/messages.js';
import { showProgressMessage, hideProgress } from '../ui/progress.js';
import { setTokens, clearAllSessionData, getToken } from '../utils/auth.js';
import { showFileSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';
import { handleTOTPFlow } from './totp.js';
import { getOpaqueClient, storeClientSecret, retrieveClientSecret, clearClientSecret } from '../crypto/opaque.js';
import {
  deriveFileEncryptionKeyWithCache,
  cleanupAccountKeyCache,
} from '../crypto/file-encryption.js';
import { promptForCacheOptIn } from '../ui/password-modal.js';
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
  private static loginInProgress = false;

  public static async login(credentials: LoginCredentials): Promise<void> {
    if (!credentials.username || !credentials.password) {
      showError('Please enter both username and password.');
      return;
    }

    // Re-entrancy guard: OPAQUE is a stateful multi-step protocol.
    // Parallel login attempts create conflicting server sessions and
    // cause RecoverCredentials failures. Reject if already in flight.
    if (LoginManager.loginInProgress) {
      console.warn('Login already in progress, ignoring duplicate call');
      return;
    }
    LoginManager.loginInProgress = true;

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
        serverPublicKey: null,
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
      if (loginFinalize.sessionKey) {
        loginFinalize.sessionKey.fill(0);
      }

      hideProgress();

      // Check TOTP FIRST, before any cache/digest operations
      if (loginData.requires_totp) {
        handleTOTPFlow({
          tempToken: loginData.temp_token!,
          username: credentials.username,
          password: credentials.password,
        });
        return;
      }

      // No TOTP required: complete login with post-auth steps
      await this.completeLogin({
        token: loginData.token,
        refresh_token: loginData.refresh_token,
        auth_method: 'OPAQUE',
        is_approved: loginData.is_approved,
      }, credentials.username, credentials.password);

    } catch (error) {
      // Clean up on error
      clearClientSecret('login_secret');
      hideProgress();
      console.error('Login error:', error);
      showError('Authentication failed');
    } finally {
      LoginManager.loginInProgress = false;
    }
  }

  /**
   * Complete login after full authentication (OPAQUE + TOTP if required).
   *
   * This is called either:
   * - Directly from login() when TOTP is not required
   * - From verifyTOTPLogin() in totp.ts after successful TOTP verification
   *
   * Post-authentication steps:
   * 1. Store JWT tokens
   * 2. Cache opt-in prompt + Argon2id Account Key derivation
   * 3. Populate digest cache for deduplication
   * 4. Navigate to file section
   *
   * @param data     - Login response with tokens
   * @param username - Authenticated username
   * @param password - Account password (for key derivation; wiped after use)
   */
  public static async completeLogin(
    data: LoginResponse,
    username: string,
    password?: string,
  ): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refresh_token);

      // Check if user is approved
      if (data.is_approved === false) {
        const { showPendingApprovalSection } = await import('../ui/sections.js');
        showPendingApprovalSection();
        showSuccess('Account created. Awaiting administrator approval.');
        return;
      }

      // Post-auth: Account Key caching (only if password is available)
      let cachedAccountKey: Uint8Array | undefined;
      if (password) {
        const cacheChoice = await promptForCacheOptIn();
        if (cacheChoice && cacheChoice.cacheDuration) {
          try {
            showProgressMessage('Deriving Account Key (Argon2id) -- this may take a few seconds...');
            cachedAccountKey = await deriveFileEncryptionKeyWithCache(
              password, username, 'account',
              data.token, cacheChoice.cacheDuration,
            );
            hideProgress();
          } catch (error) {
            hideProgress();
            console.warn('Failed to cache account key:', error);
          }
        }
      }

      // Post-auth: Populate digest cache for deduplication
      if (cachedAccountKey) {
        try {
          const token = getToken() || data.token;
          if (token) {
            const filesResp = await fetch('/api/files', {
              headers: { 'Authorization': `Bearer ${token}` },
            });
            if (filesResp.ok) {
              const filesData = await filesResp.json();
              const files: RawFileEntry[] = (filesData.files || []);
              await populateDigestCache(cachedAccountKey, files);
            }
          }
        } catch (err) {
          console.warn('Failed to populate digest cache:', err);
        }
      }

      showSuccess('Login successful');

      // Navigate to file section and load files
      showFileSection();
      await loadFiles();

      // Initialize share list UI (refresh button handler + initial load)
      try {
        const { initializeShareList } = await import('../shares/share-list.js');
        await initializeShareList();
      } catch (err) {
        console.warn('Failed to initialize share list:', err);
      }

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
let loginFormSetupDone = false;

export function setupLoginForm(): void {
  if (loginFormSetupDone) return;
  loginFormSetupDone = true;

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
