/**
 * TOTP (Two-Factor Authentication) functionality
 */

import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { showModal, showTOTPAppsModal } from '../ui/modals';
import { clearAllSessionData, AuthManager } from '../utils/auth';
import { getAdminContactForDisplay } from '../ui/footer';
import { showFileSection, showAuthSection, showTOTPSetupSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { LoginManager } from './login';

// Make showTOTPAppsModal available globally for inline onclick handlers
if (typeof window !== 'undefined') {
  window.showTOTPAppsModal = showTOTPAppsModal;
}

export interface TOTPFlowData {
  tempToken: string;
  username: string;
  /** Account password carried through for post-auth key derivation (wiped after use) */
  password?: string;
}

export interface TOTPSetupData {
  secret: string;
  qr_code_url: string;
  backup_codes: string[];
  manual_entry: string;
}

export interface TOTPLoginResponse {
  token: string;
  refresh_token: string;
  auth_method: string;
  user: any;
}

export interface TOTPSetupResponse {
  secret: string;
  qr_code_url: string;
  backup_codes: string[];
  manual_entry: string;
}

// Module-private TOTP flow state set by handleTOTPFlow() and consumed by verifyTOTPLogin().
// Stored here rather than on window so the account password never appears on a
// globally-accessible object during the TOTP entry window.
let _pendingTOTPFlowData: TOTPFlowData | null = null;

export function handleTOTPFlow(data: TOTPFlowData): void {
  // Store flow data in module-private scope (NOT on window).
  _pendingTOTPFlowData = data;
  
  // Show TOTP input modal
  const totpModal = showModal({
    title: "Two-Factor Authentication",
    message: "Please enter your 6-digit TOTP code from your authenticator app:",
    buttons: [
      {
        text: 'Cancel',
        action: () => {
          // Clear module-private flow data on cancel.
          _pendingTOTPFlowData = null;
        },
        variant: 'secondary'
      }
    ],
    allowClose: true
  });
  
  // Replace the modal content with TOTP input form
  const modalContent = totpModal.querySelector('.modal-content');
  if (!modalContent) return;

  const closeButton = modalContent.querySelector('button');
  if (closeButton) closeButton.remove();
  
  const totpForm = document.createElement('div');
  totpForm.innerHTML = `
    <div id="totp-code-section">
      <input type="text" id="totp-login-code" maxlength="6" placeholder="000000" style="
        width: 100%;
        padding: 10px;
        font-size: 18px;
        text-align: center;
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        margin-bottom: 15px;
        letter-spacing: 0.2em;
      ">
      <button id="verify-totp-login" disabled style="
        width: 100%;
        padding: 10px;
        background-color: var(--current-2);
        color: var(--salt);
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        margin-bottom: 10px;
      ">Verify</button>
    </div>
    <div id="backup-code-section" class="hidden">
      <p id="backup-mode-hint" style="font-size: 13px; color: var(--foam-2); margin: 0 0 10px 0; text-align: center;"></p>
      <input type="text" id="backup-login-code" maxlength="10" placeholder="10-character backup code" style="
        width: 100%;
        padding: 10px;
        font-size: 16px;
        text-align: center;
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        margin-bottom: 15px;
        letter-spacing: 0.1em;
      ">
      <button id="verify-backup-login" disabled style="
        width: 100%;
        padding: 10px;
        background-color: var(--current-2);
        color: var(--salt);
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        margin-bottom: 10px;
      ">Continue</button>
      <button id="backup-back-to-totp" type="button" style="
        width: 100%;
        padding: 8px;
        background: transparent;
        color: var(--foam-2);
        border: none;
        cursor: pointer;
        font-size: 14px;
        margin-bottom: 10px;
      ">Back to authenticator code</button>
    </div>
    <div id="backup-trouble-section" style="margin-bottom: 10px; padding-top: 8px; border-top: 1px solid var(--depth-4);">
      <p style="font-size: 13px; color: var(--foam-2); margin: 0 0 8px 0; text-align: center;">Having trouble?</p>
      <button id="backup-signin-once" type="button" style="
        width: 100%;
        padding: 8px;
        margin-bottom: 6px;
        background-color: var(--depth-3);
        color: var(--salt);
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
      ">Sign in once with a backup code</button>
      <button id="backup-reenroll" type="button" style="
        width: 100%;
        padding: 8px;
        background-color: var(--depth-3);
        color: var(--salt);
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
      ">Set up a new second factor with a backup code</button>
      <p id="mfa-admin-recovery-hint" style="font-size: 12px; color: var(--foam-2); margin: 10px 0 0; text-align: center; line-height: 1.4;"></p>
    </div>
    <button onclick="this.closest('.modal-overlay').remove();" style="
      width: 100%;
      padding: 10px;
      background-color: var(--depth-4);
      color: var(--salt);
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
    ">Cancel</button>
  `;
  
  modalContent.appendChild(totpForm);
  
  let backupMode: 'signin' | 'reenroll' | null = null;

  const totpSection = document.getElementById('totp-code-section');
  const backupSection = document.getElementById('backup-code-section');
  const troubleSection = document.getElementById('backup-trouble-section');
  const totpInput = document.getElementById('totp-login-code') as HTMLInputElement;
  const backupInput = document.getElementById('backup-login-code') as HTMLInputElement;
  const verifyTotpButton = document.getElementById('verify-totp-login') as HTMLButtonElement;
  const verifyBackupButton = document.getElementById('verify-backup-login') as HTMLButtonElement;
  const backupHint = document.getElementById('backup-mode-hint');
  const signinOnceBtn = document.getElementById('backup-signin-once');
  const reenrollBtn = document.getElementById('backup-reenroll');
  const backToTotpBtn = document.getElementById('backup-back-to-totp');

  const showTotpMode = (): void => {
    backupMode = null;
    totpSection?.classList.remove('hidden');
    backupSection?.classList.add('hidden');
    troubleSection?.classList.remove('hidden');
    setTimeout(() => totpInput?.focus(), 50);
  };

  const showBackupMode = (mode: 'signin' | 'reenroll'): void => {
    backupMode = mode;
    totpSection?.classList.add('hidden');
    backupSection?.classList.remove('hidden');
    troubleSection?.classList.add('hidden');
    if (backupHint) {
      backupHint.textContent = mode === 'signin'
        ? 'One-time sign-in. Your enrolled second factor stays unchanged; you will need it again on the next login.'
        : 'Replaces your second factor. You will set up a new authenticator and receive fresh backup codes.';
    }
    if (verifyBackupButton) {
      verifyBackupButton.textContent = mode === 'signin' ? 'Sign in once' : 'Set up new second factor';
    }
    if (backupInput) {
      backupInput.value = '';
      verifyBackupButton.disabled = true;
      setTimeout(() => backupInput.focus(), 50);
    }
  };

  if (totpInput && verifyTotpButton) {
    totpInput.addEventListener('input', function() {
      this.value = this.value.replace(/[^0-9]/g, '');
      verifyTotpButton.disabled = this.value.length !== 6;
    });
    totpInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && !verifyTotpButton.disabled) {
        verifyTOTPLogin();
      }
    });
    verifyTotpButton.addEventListener('click', verifyTOTPLogin);
  }

  if (backupInput && verifyBackupButton) {
    backupInput.addEventListener('input', function() {
      this.value = this.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
      verifyBackupButton.disabled = this.value.length !== 10;
    });
    backupInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && !verifyBackupButton.disabled) {
        verifyBackupLogin(backupMode);
      }
    });
    verifyBackupButton.addEventListener('click', () => verifyBackupLogin(backupMode));
  }

  signinOnceBtn?.addEventListener('click', () => showBackupMode('signin'));
  reenrollBtn?.addEventListener('click', () => showBackupMode('reenroll'));
  backToTotpBtn?.addEventListener('click', showTotpMode);

  void populateMfaAdminRecoveryHint();

  setTimeout(() => totpInput?.focus(), 100);
}

async function populateMfaAdminRecoveryHint(): Promise<void> {
  const hintEl = document.getElementById('mfa-admin-recovery-hint');
  if (!hintEl) return;

  const contact = await getAdminContactForDisplay();
  if (contact) {
    hintEl.textContent =
      `If you have lost your second factor and all backup codes, contact the admin: ${contact} (also shown as Contact Admin in the site footer).`;
  } else {
    hintEl.textContent =
      'If you have lost your second factor and all backup codes, contact the instance admin (see Contact Admin in the site footer).';
  }
}

async function verifyTOTPLogin(): Promise<void> {
  const codeInput = document.getElementById('totp-login-code') as HTMLInputElement;
  if (!codeInput) return;

  const code = codeInput.value;
  if (!code || code.length !== 6) {
    showError('Please enter a 6-digit code.');
    return;
  }

  await submitMFAAuth(code, false);
}

async function verifyBackupLogin(mode: 'signin' | 'reenroll' | null): Promise<void> {
  const codeInput = document.getElementById('backup-login-code') as HTMLInputElement;
  if (!codeInput || !mode) return;

  const code = codeInput.value;
  if (code.length !== 10) {
    showError('Please enter a valid 10-character backup code.');
    return;
  }

  if (mode === 'signin') {
    await submitMFAAuth(code, true);
    return;
  }

  await submitBackupReenroll(code);
}

async function submitMFAAuth(code: string, isBackup: boolean): Promise<void> {
  const pendingData = _pendingTOTPFlowData;
  if (!pendingData) {
    showError('Login session expired. Please try again.');
    return;
  }

  try {
    showProgressMessage('Verifying...');

    const response = await fetch('/api/mfa/auth', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code: code,
        is_backup: isBackup
      }),
    });

    if (response.ok) {
      const responseData = await response.json();
      // Handle standard API response structure: { data: { ... } }
      const data: TOTPLoginResponse = responseData.data || responseData;
      
      // Extract and immediately zero the carried password.
      const carriedPassword = pendingData.password;
      if (pendingData.password) {
        pendingData.password = '';
      }
      // Clear module-private state.
      _pendingTOTPFlowData = null;

      // Complete authentication using LoginManager (with password for key derivation).
      // Tokens are now in HttpOnly cookies; completeLogin no longer needs to store them.
      await LoginManager.completeLogin({
        token: data.token || '',
        refresh_token: data.refresh_token || '',
        auth_method: 'OPAQUE',
        is_approved: data.user?.is_approved
      }, pendingData.username, carriedPassword);

      document.querySelector('.modal-overlay')?.remove();
      
      showSuccess('Authentication successful!');
      
    } else {
      hideProgress();
      // Session expired: clear state and redirect to login
      if (response.status === 401) {
        _pendingTOTPFlowData = null;
        document.querySelector('.modal-overlay')?.remove();
        clearAllSessionData();
        showAuthSection();
        showError('Session expired. Please log in again.');
        return;
      }
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'TOTP verification failed');
    }
  } catch (error) {
    hideProgress();
    console.error('MFA verification error:', error);
    showError('Authentication failed');
  }
}

async function submitBackupReenroll(code: string): Promise<void> {
  try {
    showProgressMessage('Verifying backup code...');

    const recoveryResponse = await fetch('/api/mfa/recover-with-backup-code', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backup_code: code }),
    });

    if (!recoveryResponse.ok) {
      hideProgress();
      const errBody = await recoveryResponse.json().catch(() => ({}));
      showError(errBody.message || 'Invalid backup code');
      return;
    }

    document.querySelector('.modal-overlay')?.remove();
    showProgressMessage('Setting up new second factor...');

    const resetResponse = await fetch('/api/mfa/reset', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    hideProgress();
    if (resetResponse.ok) {
      const resetData = await resetResponse.json();
      const data = resetData.data || resetData;
      showSuccess('Second factor reset complete');
      showTOTPSetupSection({
        secret: data.secret,
        qr_code_url: data.qr_code_image || data.qr_code_url,
        backup_codes: data.backup_codes,
        manual_entry: data.manual_entry,
      });
    } else {
      const errBody = await resetResponse.json().catch(() => ({}));
      showError(errBody.message || 'Second factor reset failed');
    }
  } catch (error) {
    hideProgress();
    console.error('Backup re-enrollment error:', error);
    showError('Second factor reset failed');
  }
}

/**
 * Generate TOTP setup data and populate the static #totp-setup-form fields.
 * Used by both the auto-trigger in showTOTPSetupSection() and the Regenerate button.
 */
export async function generateAndDisplayTOTPSetup(): Promise<void> {
  const generateBtn = document.getElementById('generate-totp-btn') as HTMLButtonElement | null;
  if (generateBtn) generateBtn.disabled = true;

  const data = await initiateTOTPSetup();

  if (generateBtn) generateBtn.disabled = false;

  if (!data) return; // initiateTOTPSetup already showed an error

  // Populate QR code display
  const qrDisplay = document.getElementById('qr-code-display');
  const qrSection = document.getElementById('qr-code-section');
  const manualCode = document.getElementById('manual-entry-code');
  const verifyBtn = document.getElementById('verify-totp-btn') as HTMLButtonElement | null;
  const backupSection = document.getElementById('backup-codes-section');
  const backupList = document.getElementById('backup-codes-list');

  if (qrDisplay) {
    qrDisplay.innerHTML = `<img src="${data.qr_code_url}" alt="TOTP QR Code" style="max-width:200px;height:auto;border:1px solid var(--depth-4);border-radius:4px;">`;
  }
  if (manualCode) {
    manualCode.textContent = data.manual_entry;
  }
  if (qrSection) {
    qrSection.classList.remove('hidden');
  }
  if (verifyBtn) {
    verifyBtn.disabled = false;
  }
  if (backupList && data.backup_codes?.length) {
    backupList.innerHTML = data.backup_codes.map(c => `<li>${c}</li>`).join('');
  }
  if (backupSection) {
    backupSection.classList.remove('hidden');
  }

  // Start session countdown timer for the static TOTP setup form
  startSetupSessionCountdown();
}

/**
 * Start a countdown timer for the static TOTP setup form (#totp-setup-form).
 * The temp token is valid for 20 minutes. Since it is now HttpOnly and JS
 * cannot read it, we start a local 20-minute countdown from now.
 * Displays when less than 5 minutes remain; auto-logs out and reloads on expiry.
 */
function startSetupSessionCountdown(): void {
  const expiryMs = Date.now() + 20 * 60 * 1000; // 20-minute temp-token TTL
  const SHOW_THRESHOLD = 5 * 60 * 1000; // Show countdown in last 5 minutes

  const timerEl = document.getElementById('totp-setup-session-timer');
  if (!timerEl) return;

  const intervalId = window.setInterval(() => {
    const remaining = expiryMs - Date.now();

    if (remaining <= 0) {
      // Session expired: clean up and force reload
      clearInterval(intervalId);
      if (typeof window !== 'undefined') {
        delete window.totpLoginData;
        delete window.totpSetupData;
      }
      clearAllSessionData();
      showAuthSection();
      showError('Setup session expired. Please log in to continue TOTP setup.');
      setTimeout(() => window.location.reload(), 1500);
      return;
    }

    if (remaining <= SHOW_THRESHOLD) {
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      const pad = secs < 10 ? '0' : '';
      timerEl.textContent = `Session expires in ${mins}:${pad}${secs}`;
      timerEl.style.display = 'block';
    }
  }, 1000);
}

// TOTP Setup Functions
//
// /api/mfa/setup is gated by MFAJWTMiddleware (aud=arkfile-mfa). The
// temp token (in TEMP_TOKEN_KEY) is the credential to use here. As a
// fallback, accept the full token for the rare "user is already logged in
// and wants to re-run TOTP setup" path -- although in practice that path
// is currently locked off because TOTP setup is only initiated when no
// TOTP is enrolled.
export async function initiateTOTPSetup(): Promise<TOTPSetupData | null> {
  try {
    showProgressMessage('Setting up TOTP...');

    // The temp token is in the __Host-arkfile-temp cookie; credentials:'include'
    // sends it automatically.
    const response = await fetch('/api/mfa/setup', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    
    hideProgress();
    
    if (response.ok) {
      const result = await response.json();
      // Unwrap JSONResponse envelope: { success, message, data: { ... } }
      const data = (result.data || result) as any;
      return {
        secret: data.secret,
        // Prefer the base64 data URI (qr_code_image) over the otpauth:// URL (qr_code_url)
        qr_code_url: data.qr_code_image || data.qr_code_url,
        backup_codes: data.backup_codes,
        manual_entry: data.manual_entry
      };
    } else {
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'Failed to setup TOTP');
      return null;
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP setup error:', error);
    showError('Failed to setup TOTP');
    return null;
  }
}

/**
 * Complete TOTP setup verification.
 * Returns the full response data (including tokens and is_approved) on success, or null on failure.
 */
export async function completeTOTPSetup(code: string): Promise<Record<string, any> | null> {
  try {
    showProgressMessage('Completing TOTP setup...');

    // Temp token is in __Host-arkfile-temp cookie; credentials:'include' sends it automatically.
    const response = await fetch('/api/mfa/verify', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    
    hideProgress();
    
    if (response.ok) {
      const result = await response.json();
      // Unwrap JSONResponse envelope
      const data = result.data || result;
      showSuccess('TOTP setup completed successfully!');
      return data;
    } else {
      // Session expired: clear state and redirect to login
      if (response.status === 401) {
        if (typeof window !== 'undefined') {
          delete window.totpLoginData;
          delete window.totpSetupData;
        }
        document.querySelector('.modal-overlay')?.remove();
        clearAllSessionData();
        showAuthSection();
        showError('Setup session expired. Please log in to continue TOTP setup.');
        return null;
      }
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'Invalid TOTP code');
      return null;
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP verification error:', error);
    showError('Failed to complete TOTP setup');
    return null;
  }
}

export async function getTOTPStatus(): Promise<{enabled: boolean, setupRequired: boolean} | null> {
  try {
    const response = await fetch('/api/mfa/status', {
      method: 'GET',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    });
    
    if (response.ok) {
      return await response.json();
    } else {
      console.error('Failed to get TOTP status');
      return null;
    }
  } catch (error) {
    console.error('TOTP status error:', error);
    return null;
  }
}

// TOTP Setup Modal
export function showTOTPSetupModal(): void {
  const modal = showModal({
    title: "Setup Two-Factor Authentication",
    message: "Setting up TOTP will add an extra layer of security to your account.",
    buttons: [],
    allowClose: false
  });
  
  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  // Clear existing content
  modalContent.innerHTML = `
    <h3 style="margin: 0 0 20px 0;">Setup Two-Factor Authentication</h3>
    <div id="totp-setup-content">
      <div style="text-align: center; padding: 20px;">
        <div style="margin-bottom: 15px;">Initializing TOTP setup...</div>
        <div style="width: 20px; height: 20px; border: 2px solid var(--current-2); border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
      </div>
    </div>
  `;

  // Add CSS for spinner
  if (!document.getElementById('totp-spinner-style')) {
    const style = document.createElement('style');
    style.id = 'totp-spinner-style';
    style.textContent = `
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }

  // Initialize TOTP setup
  initiateTOTPSetup().then(setupData => {
    if (setupData) {
      showTOTPSetupData(modalContent, setupData);
    } else {
      modal.remove();
    }
  });
}

function showTOTPSetupData(modalContent: Element, setupData: TOTPSetupData): void {
  modalContent.innerHTML = `
    <h3 style="margin: 0 0 20px 0;">Setup Two-Factor Authentication</h3>
    <div style="margin-bottom: 20px;">
      <h4>Step 1: Scan QR Code</h4>
      <div style="text-align: center; margin: 15px 0;">
        <img src="${setupData.qr_code_url}" alt="TOTP QR Code" style="max-width: 200px;">
      </div>
      <p style="font-size: 14px; color: var(--foam-2);">
        Scan this QR code with your authenticator app 
        <a href="#" onclick="event.preventDefault(); window.showTOTPAppsModal();" style="color: var(--current-2); text-decoration: none; font-size: 13px;">
          Need a TOTP app?
        </a>
      </p>
    </div>
    
    <div style="margin-bottom: 20px;">
      <h4>Step 2: Manual Entry (Alternative)</h4>
      <div style="background: var(--depth-2); padding: 10px; border-radius: 4px; margin: 10px 0;">
        <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:nowrap;">
          <code id="totp-modal-secret" style="font-family: monospace; white-space: nowrap; overflow-x: auto;">${setupData.manual_entry}</code>
          <button type="button" id="totp-modal-copy-btn" class="btn-copy-hash">copy</button>
        </div>
      </div>
      <p style="font-size: 14px; color: var(--foam-2);">
        If you can't scan the QR code, enter this code manually in your authenticator app.
      </p>
    </div>
    
    <div style="margin-bottom: 20px;">
      <h4>Step 3: Backup Codes</h4>
      <div style="background: color-mix(in srgb, var(--phosphor) 15%, var(--depth-3)); border: 1px solid var(--phosphor); padding: 15px; border-radius: 4px; margin: 10px 0;">
        <p style="margin: 0 0 10px 0; font-weight: bold; color: var(--phosphor);">
          Save these backup codes in a secure location:
        </p>
        <div style="font-family: monospace; font-size: 14px; line-height: 1.5;">
          ${setupData.backup_codes.map((code: string) => `<div>${code}</div>`).join('')}
        </div>
      </div>
      <p style="font-size: 14px; color: var(--foam-2);">
        Use these codes if you lose access to your authenticator app. Each code can only be used once.
      </p>
    </div>
    
    <div style="margin-bottom: 20px;">
      <h4>Step 4: Verify Setup</h4>
      <input type="text" id="totp-setup-code" maxlength="6" placeholder="000000" style="
        width: 100%;
        padding: 10px;
        font-size: 18px;
        text-align: center;
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        margin-bottom: 15px;
        letter-spacing: 0.2em;
      ">
      <p style="font-size: 14px; color: var(--foam-2); margin-bottom: 15px;">
        Enter the 6-digit code from your authenticator app to complete setup.
      </p>
    </div>
    
    <div style="display: flex; gap: 10px;">
      <button id="complete-totp-setup" disabled style="
        flex: 1;
        padding: 10px;
        background-color: var(--biolum);
        color: var(--salt);
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
      ">Complete Setup</button>
      <button onclick="this.closest('.modal-overlay').remove();" style="
        flex: 1;
        padding: 10px;
        background-color: var(--depth-4);
        color: var(--salt);
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
      ">Cancel</button>
    </div>
  `;

  // Add event listeners for verification
  const setupCodeInput = document.getElementById('totp-setup-code') as HTMLInputElement;
  const completeButton = document.getElementById('complete-totp-setup') as HTMLButtonElement;
  
  if (setupCodeInput && completeButton) {
    setupCodeInput.addEventListener('input', function() {
      this.value = this.value.replace(/[^0-9]/g, '');
      completeButton.disabled = this.value.length !== 6;
    });
    
    setupCodeInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && this.value.length === 6) {
        completeTOTPSetupFlow(setupCodeInput.value);
      }
    });
    
    completeButton.addEventListener('click', () => {
      completeTOTPSetupFlow(setupCodeInput.value);
    });
    
    // Focus the input
    setTimeout(() => setupCodeInput.focus(), 100);
  }

  // Wire the copy button for the manual-entry secret
  const copyBtn = document.getElementById('totp-modal-copy-btn') as HTMLButtonElement | null;
  const secretEl = document.getElementById('totp-modal-secret');
  if (copyBtn && secretEl) {
    copyBtn.addEventListener('click', () => {
      const secret = secretEl.textContent?.trim() ?? '';
      if (!secret) return;
      navigator.clipboard.writeText(secret).then(() => {
        const orig = copyBtn.textContent;
        copyBtn.textContent = 'copied!';
        setTimeout(() => { copyBtn.textContent = orig; }, 2000);
      }).catch(() => {});
    });
  }
}

async function completeTOTPSetupFlow(code: string): Promise<void> {
  const verifyResult = await completeTOTPSetup(code);
  if (verifyResult) {
    document.querySelector('.modal-overlay')?.remove();

    // Tokens are in HttpOnly cookies (set by the server on /api/mfa/verify).
    // If we got here from the registration flow (incomplete TOTP setup),
    // _pendingTOTPFlowData holds the password and username.
    const flowData = _pendingTOTPFlowData;
    if (flowData) {
      const carriedPassword = flowData.password;
      if (flowData.password) { flowData.password = ''; }
      _pendingTOTPFlowData = null;
      const { LoginManager } = await import('./login.js');
      await LoginManager.completeLogin({
        token: verifyResult.token || '',
        refresh_token: verifyResult.refresh_token || '',
        auth_method: 'OPAQUE',
        is_approved: verifyResult.user?.is_approved,
      }, flowData.username, carriedPassword);
    }
  }
}

/**
 * Download backup codes as a text file
 * Retrieves backup codes from the DOM (displayed during TOTP setup) and triggers download
 */
export function downloadBackupCodes(): void {
  // Try to find backup codes in the TOTP setup modal - look for the container with monospace font
  const backupCodesContainer = document.querySelector('[style*="font-family: monospace"]');
  if (!backupCodesContainer) {
    // No backup codes displayed - user may need to regenerate them
    showError('No backup codes available. Complete TOTP setup first.');
    return;
  }

  // Extract backup codes from the container
  const codeElements = backupCodesContainer.querySelectorAll('div');
  const codes: string[] = [];
  codeElements.forEach(el => {
    const code = el.textContent?.trim();
    if (code && code.length > 0) {
      codes.push(code);
    }
  });

  if (codes.length === 0) {
    showError('No backup codes found.');
    return;
  }

  // Create file content
  const content = [
    'ARKFILE TOTP BACKUP CODES',
    '========================',
    '',
    'Store these codes in a secure location.',
    'Each code can only be used once.',
    '',
    'Generated: ' + new Date().toISOString(),
    '',
    ...codes.map((code, i) => `${i + 1}. ${code}`),
    '',
    'WARNING: Keep these codes secret!',
  ].join('\n');

  // Create and trigger download
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'arkfile-backup-codes.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showSuccess('Backup codes downloaded.');
}
