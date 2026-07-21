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
import { clearAllSessionData, authenticatedFetch, csrfHeader, startAutoRefresh } from '../utils/auth.js';
import { showFileSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';
import { handleTOTPFlow } from './totp.js';
import { handleMFASetupFlow } from './mfa-setup.js';
import { handleWebAuthnLoginFlow, buildWebAuthnLoginFlowData } from './webauthn.js';
import { showMFALoginMethodPicker, type MFALoginMethodOption } from './mfa-method.js';
import { getOpaqueClient, storeClientSecret, retrieveClientSecret, clearClientSecret } from '../crypto/opaque.js';
import {
  deriveFileEncryptionKey,
  deriveFileEncryptionKeyWithCache,
} from '../crypto/file-encryption.js';
import { decryptMetadataField } from '../crypto/metadata-helpers.js';
import { AAD_FIELD_FILENAME } from '../crypto/aad.js';
import { promptForCacheOptIn } from '../ui/password-modal.js';
import { populateDigestCache, type RawFileEntry } from '../utils/digest-cache.js';
import type { ReregistrationVerifier, ReregistrationRequiredData } from '../types/api.js';

// Stable error code the server returns (HTTP 409) when an account has been
// flagged for a one-time OPAQUE re-registration after an operator-initiated
// OPAQUE credential rotation.
const ACCOUNT_REQUIRES_REREGISTRATION = 'account_requires_reregistration';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  refresh_token: string;
  auth_method: 'OPAQUE' | 'OPAQUE+TOTP' | 'OPAQUE+WebAuthn';
  requires_mfa?: boolean;
  requires_mfa_setup?: boolean;
  mfa_method?: 'totp' | 'webauthn' | '';
  mfa_methods?: MFALoginMethodOption[];
  temp_token?: string;
  is_approved?: boolean;
}

export type { MFALoginMethodOption } from './mfa-method.js';

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
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...csrfHeader()
        },
        body: JSON.stringify({
          username: credentials.username,
          credential_request: loginInit.requestData
        })
      });

      if (!responseStep1.ok) {
        clearClientSecret('login_secret');

        // A 409 carrying account_requires_reregistration means an operator
        // rotated this account's OPAQUE credentials. Run the one-time
        // re-registration ceremony within this same login attempt.
        if (responseStep1.status === 409) {
          const errBody = await responseStep1.json().catch(() => null);
          if (errBody && errBody.error === ACCOUNT_REQUIRES_REREGISTRATION) {
            await LoginManager.handleReregistration(credentials, (errBody.data || {}) as ReregistrationRequiredData);
            return;
          }
          hideProgress();
          showError(errBody?.message || 'Authentication failed');
          return;
        }

        const errorText = await responseStep1.text();
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
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...csrfHeader()
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

      await LoginManager.routeAfterOpaque(loginData, credentials);

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
   * Route to the appropriate next step after a successful OPAQUE exchange,
   * whether from a normal login finalize or the re-registration ceremony.
   * Both produce the same response shape (requires_mfa + temp_token, or tokens).
   */
  private static async routeAfterOpaque(loginData: any, credentials: LoginCredentials): Promise<void> {
    // Check MFA FIRST, before any cache/digest operations
    if (loginData.requires_mfa) {
      if (Array.isArray(loginData.mfa_methods) && loginData.mfa_methods.length > 1) {
        document.querySelector('.modal-overlay')?.remove();
        showMFALoginMethodPicker(loginData.mfa_methods as MFALoginMethodOption[], (choice) => {
          LoginManager.startChosenMFALogin(choice, loginData.temp_token!, credentials);
        });
        return;
      }

      const mfaMethod = (loginData.mfa_method || '').trim();

      if (loginData.requires_mfa_setup) {
        document.querySelector('.modal-overlay')?.remove();
        handleMFASetupFlow({
          tempToken: loginData.temp_token!,
          username: credentials.username,
          password: credentials.password,
          mfaMethod: mfaMethod as 'totp' | 'webauthn' | '',
        });
        showSuccess('Please complete two-factor authentication setup to finish logging in.');
        return;
      }

      if (mfaMethod === 'webauthn') {
        const webauthnMethod = loginData.mfa_methods?.find(
          (m: MFALoginMethodOption) => m.type === 'webauthn',
        );
        handleWebAuthnLoginFlow(buildWebAuthnLoginFlowData({
          tempToken: loginData.temp_token!,
          username: credentials.username,
          password: credentials.password,
          credentialId: webauthnMethod?.credential_id,
          label: webauthnMethod?.label,
        }));
        return;
      }

      handleTOTPFlow({
        tempToken: loginData.temp_token!,
        username: credentials.username,
        password: credentials.password,
      });
      return;
    }

    // No MFA required: complete login with post-auth steps
    await LoginManager.completeLogin({
      token: loginData.token,
      refresh_token: loginData.refresh_token,
      auth_method: 'OPAQUE',
      is_approved: loginData.is_approved,
    }, credentials.username, credentials.password);
  }

  static startChosenMFALogin(
    choice: MFALoginMethodOption,
    tempToken: string,
    credentials: LoginCredentials,
  ): void {
    if (choice.type === 'webauthn') {
      handleWebAuthnLoginFlow(buildWebAuthnLoginFlowData({
        tempToken,
        username: credentials.username,
        password: credentials.password,
        credentialId: choice.credential_id,
        label: choice.label,
      }));
      return;
    }
    handleTOTPFlow({
      tempToken,
      username: credentials.username,
      password: credentials.password,
    });
  }

  /**
   * Run the one-time OPAQUE re-registration ceremony for a flagged account.
   *
   * Invoked from login() when the login response step returns
   * account_requires_reregistration. The browser carries the short-lived
   * handoff token via the temp-tier HttpOnly cookie the server set on the 409,
   * so the ceremony requests need no explicit Authorization header.
   *
   * When the user owns files, the entered password is first confirmed against
   * an account-key-encrypted metadata sample, so a mismatched password can
   * never be bound to the account and lock the user out of their own files.
   * On success the ceremony yields the same MFA-pending shape as a normal
   * login, so we hand off to routeAfterOpaque() and never add a second login.
   */
  public static async handleReregistration(
    credentials: LoginCredentials,
    data: ReregistrationRequiredData,
  ): Promise<void> {
    try {
      const fileCount = data.file_count ?? 0;

      if (fileCount > 0) {
        showProgressMessage('Verifying your password against your existing files...');
        const verified = await LoginManager.verifyReregistrationPassword(credentials, data.verifier);
        if (!verified) {
          hideProgress();
          showError('The password you entered does not match this account\'s existing files. Re-registration was cancelled and no changes were made.');
          return;
        }
      }

      showProgressMessage('Re-registering your account after a security key update...');

      const opaqueClient = await getOpaqueClient();
      const registrationInit = await opaqueClient.startRegistration({
        username: credentials.username,
        password: credentials.password,
      });
      storeClientSecret('reregistration_secret', registrationInit.clientSecret);

      const respStep1 = await fetch('/api/opaque/reregister/response', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', ...csrfHeader() },
        body: JSON.stringify({ registration_request: registrationInit.requestData }),
      });
      if (!respStep1.ok) {
        clearClientSecret('reregistration_secret');
        hideProgress();
        const errBody = await respStep1.json().catch(() => null);
        showError(errBody?.message || 'Re-registration failed. Please try again.');
        return;
      }

      const step1 = await respStep1.json();
      const respData = step1.data;
      if (!respData || !respData.registration_response || !respData.session_id) {
        clearClientSecret('reregistration_secret');
        hideProgress();
        showError('Invalid server response during re-registration.');
        return;
      }

      const clientSecret = retrieveClientSecret('reregistration_secret');
      if (!clientSecret) {
        hideProgress();
        showError('Re-registration session expired. Please try again.');
        return;
      }

      const registrationFinalize = await opaqueClient.finalizeRegistration({
        username: credentials.username,
        serverResponse: respData.registration_response,
        clientSecret: clientSecret,
      });
      clearClientSecret('reregistration_secret');

      const respStep2 = await fetch('/api/opaque/reregister/finalize', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', ...csrfHeader() },
        body: JSON.stringify({
          session_id: respData.session_id,
          registration_record: registrationFinalize.record,
        }),
      });

      if (registrationFinalize.exportKey) {
        registrationFinalize.exportKey.fill(0);
      }

      if (!respStep2.ok) {
        hideProgress();
        const errBody = await respStep2.json().catch(() => null);
        showError(errBody?.message || 'Re-registration finalization failed. Please try again.');
        return;
      }

      const finalizeResponse = await respStep2.json();
      const finalizeData = finalizeResponse.data || finalizeResponse;

      hideProgress();
      // Re-registration preserves MFA enrollment, so this continues straight
      // into the existing second-factor flow — no extra login round-trip.
      await LoginManager.routeAfterOpaque(finalizeData, credentials);
    } catch (error) {
      clearClientSecret('reregistration_secret');
      hideProgress();
      console.error('Re-registration error:', error);
      showError('Re-registration failed. Please try again.');
    }
  }

  /**
   * Confirm the entered password derives the Account Key that wraps the user's
   * existing files, using the account-key-encrypted verifier sample the server
   * returned with the 409. Returns false on any failure so the caller can abort
   * the ceremony without modifying server-side state.
   */
  private static async verifyReregistrationPassword(
    credentials: LoginCredentials,
    verifier?: ReregistrationVerifier,
  ): Promise<boolean> {
    if (!verifier || !verifier.file_id || !verifier.encrypted_filename || !verifier.filename_nonce) {
      // Server reported files but provided no usable verifier sample; fail safe.
      return false;
    }

    let accountKey: Uint8Array | undefined;
    try {
      accountKey = await deriveFileEncryptionKey(credentials.password, credentials.username, 'account');
      const owner = verifier.owner_username || credentials.username;
      await decryptMetadataField(
        verifier.encrypted_filename,
        verifier.filename_nonce,
        accountKey,
        verifier.file_id,
        AAD_FIELD_FILENAME,
        owner,
      );
      return true;
    } catch {
      return false;
    } finally {
      if (accountKey) accountKey.fill(0);
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
      // Populate the username/role cache so getUsernameFromToken() works for
      // the rest of this session (upload, share creation, etc.).
      const { getCurrentUser } = await import('../utils/auth.js');
      await getCurrentUser();

      // Check if user is approved
      if (data.is_approved === false) {
        hideProgress(); // Clear any lingering progress modals before showing pending screen
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
              undefined, cacheChoice.cacheDuration,
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
          const filesResp = await authenticatedFetch('/api/files');
          if (filesResp.ok) {
            const filesData = await filesResp.json();
            const files: RawFileEntry[] = (filesData.files || []);
            await populateDigestCache(cachedAccountKey, files);
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

      startAutoRefresh();

      try {
        const { resumePendingBillingCheckout } = await import('../ui/billing.js');
        await resumePendingBillingCheckout();
      } catch (err) {
        console.warn('Failed to resume pending billing checkout:', err);
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

      // clearAllSessionData wipes Account Key ciphertext + wrapping key and digest cache
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
