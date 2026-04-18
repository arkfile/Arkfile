/**
 * TOTP (Two-Factor Authentication) functionality
 */

import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { showModal, showTOTPAppsModal } from '../ui/modals';
import { getToken, clearAllSessionData, AuthManager } from '../utils/auth';
import { showFileSection, showAuthSection } from '../ui/sections';
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

export function handleTOTPFlow(data: TOTPFlowData): void {
  // Store the partial login data temporarily
  if (typeof window !== 'undefined') {
    window.totpLoginData = data;
  }
  
  // Show TOTP input modal
  const totpModal = showModal({
    title: "Two-Factor Authentication",
    message: "Please enter your 6-digit TOTP code from your authenticator app:",
    buttons: [
      {
        text: 'Cancel',
        action: () => {
          // Clean up temporary data
          if (typeof window !== 'undefined') {
            delete window.totpLoginData;
          }
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
    <div style="margin-bottom: 15px;">
      <label style="display: flex; align-items: center; justify-content: center; font-size: 14px; color: var(--foam-2); cursor: pointer;">
        <input type="checkbox" id="use-backup-code" style="margin: 0 8px 0 0; cursor: pointer; width: auto;">
        Use backup code instead
      </label>
    </div>
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
    <button onclick="this.closest('.modal-overlay').remove(); delete window.totpLoginData;" style="
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
  
  // Add event listeners
  const totpInput = document.getElementById('totp-login-code') as HTMLInputElement;
  const verifyButton = document.getElementById('verify-totp-login') as HTMLButtonElement;
  const backupCheckbox = document.getElementById('use-backup-code') as HTMLInputElement;
  
  if (totpInput && verifyButton && backupCheckbox) {
    // Handle backup code toggle
    backupCheckbox.addEventListener('change', function() {
      if (this.checked) {
        totpInput.placeholder = 'Enter backup code';
        totpInput.maxLength = 16;
        verifyButton.disabled = totpInput.value.length < 8;
      } else {
        totpInput.placeholder = '000000';
        totpInput.maxLength = 6;
        totpInput.value = totpInput.value.replace(/[^0-9]/g, '');
        verifyButton.disabled = totpInput.value.length !== 6;
      }
      totpInput.focus();
    });

    totpInput.addEventListener('input', function() {
      if (backupCheckbox.checked) {
        // Allow alphanumeric for backup codes
        this.value = this.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
        verifyButton.disabled = this.value.length < 8;
      } else {
        // Only digits for TOTP codes
        this.value = this.value.replace(/[^0-9]/g, '');
        verifyButton.disabled = this.value.length !== 6;
      }
    });
    
    totpInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && !verifyButton.disabled) {
        verifyTOTPLogin();
      }
    });
    
    verifyButton.addEventListener('click', verifyTOTPLogin);
    
    // Focus the input
    setTimeout(() => totpInput.focus(), 100);
  }
}

async function verifyTOTPLogin(): Promise<void> {
  const codeInput = document.getElementById('totp-login-code') as HTMLInputElement;
  const backupCheckbox = document.getElementById('use-backup-code') as HTMLInputElement;
  
  if (!codeInput) return;

  const code = codeInput.value;
  const isBackup = backupCheckbox?.checked || false;
  
  if (!code || (isBackup ? code.length < 8 : code.length !== 6)) {
    showError(isBackup ? 'Please enter a valid backup code.' : 'Please enter a 6-digit code.');
    return;
  }
  
  // Get stored login data
  const totpLoginData = typeof window !== 'undefined' ? window.totpLoginData : null;
  if (!totpLoginData) {
    showError('Login session expired (30 minutes). Please try again.');
    return;
  }
  
  try {
    showProgressMessage('Verifying TOTP...');
    
    const response = await fetch('/api/totp/auth', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${totpLoginData.tempToken}`
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
      
      // Extract password before cleanup (for post-auth key derivation)
      const carriedPassword = totpLoginData.password;

      // Wipe password from the flow data object immediately
      if (totpLoginData.password) {
        totpLoginData.password = '';
      }
      delete (totpLoginData as any).password;

      // Complete authentication using LoginManager (with password for key derivation)
      await LoginManager.completeLogin({
        token: data.token,
        refresh_token: data.refresh_token,
        auth_method: 'OPAQUE',
        is_approved: data.user?.is_approved
      }, totpLoginData.username, carriedPassword);

      // Clean up the entire flow data object from window
      if (typeof window !== 'undefined') {
        delete window.totpLoginData;
      }
      document.querySelector('.modal-overlay')?.remove();
      
      showSuccess('Authentication successful!');
      
    } else {
      hideProgress();
      // Session expired: clear state and redirect to login
      if (response.status === 401) {
        if (typeof window !== 'undefined') {
          delete window.totpLoginData;
        }
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
    console.error('TOTP verification error:', error);
    showError('TOTP verification failed');
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
 * Reads the JWT expiry from the token in localStorage.
 * Displays when less than 5 minutes remain; auto-logs out and reloads on expiry.
 */
function startSetupSessionCountdown(): void {
  const token = getToken();
  if (!token) return;

  const payload = AuthManager.parseJwtToken(token);
  if (!payload?.exp) return;

  const expiryMs = payload.exp * 1000;
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
export async function initiateTOTPSetup(): Promise<TOTPSetupData | null> {
  try {
    showProgressMessage('Setting up TOTP...');
    
    const token = getToken();
    if (!token) {
      hideProgress();
      showError('Authentication required');
      return null;
    }
    
    const response = await fetch('/api/totp/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
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
    
    const token = getToken();
    if (!token) {
      hideProgress();
      showError('Authentication required');
      return null;
    }
    
    const response = await fetch('/api/totp/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        code: code
      }),
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
    const token = getToken();
    if (!token) {
      console.error('No authentication token available');
      return null;
    }
    
    const response = await fetch('/api/totp/status', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
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
        <code style="font-family: monospace; word-break: break-all;">${setupData.manual_entry}</code>
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
}

async function completeTOTPSetupFlow(code: string): Promise<void> {
  const verifyResult = await completeTOTPSetup(code);
  if (verifyResult) {
    document.querySelector('.modal-overlay')?.remove();

    // Extract tokens and approval status from the server response
    const newToken = verifyResult.token;
    const newRefreshToken = verifyResult.refresh_token || '';
    const isApproved = verifyResult.user?.is_approved;

    // Store the new full-access tokens
    if (newToken) {
      const { setTokens } = await import('../utils/auth.js');
      setTokens(newToken, newRefreshToken);
    }

    // If we got here from the login flow (incomplete TOTP setup on login),
    // window.totpLoginData holds the password and username. Use them to complete login.
    const flowData = typeof window !== 'undefined' ? window.totpLoginData : null;
    if (flowData) {
      const { LoginManager } = await import('./login.js');
      const carriedPassword = flowData.password;
      if (flowData.password) { (flowData as any).password = ''; }
      delete (window as any).totpLoginData;
      await LoginManager.completeLogin({
        token: newToken || '',
        refresh_token: newRefreshToken,
        auth_method: 'OPAQUE',
        is_approved: isApproved,
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
