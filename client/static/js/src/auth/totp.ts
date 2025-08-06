/**
 * TOTP (Two-Factor Authentication) functionality
 */

import { wasmManager } from '../utils/wasm';
import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { showModal, showTOTPAppsModal } from '../ui/modals';
import { setTokens } from '../utils/auth';
import { showFileSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { LoginManager } from './login';

// Make showTOTPAppsModal available globally for inline onclick handlers
if (typeof window !== 'undefined') {
  (window as any).showTOTPAppsModal = showTOTPAppsModal;
}

export interface TOTPFlowData {
  tempToken: string;
  sessionKey: string;
  username: string;
}

export interface TOTPSetupData {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
  manualEntry: string;
}

export interface TOTPLoginResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
  authMethod: string;
  user: any;
}

export interface TOTPSetupResponse {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
  manualEntry: string;
}

export function handleTOTPFlow(data: TOTPFlowData): void {
  // Store the partial login data temporarily
  if (typeof window !== 'undefined') {
    (window as any).totpLoginData = data;
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
            delete (window as any).totpLoginData;
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
      border: 1px solid #ddd;
      border-radius: 4px;
      margin-bottom: 15px;
      letter-spacing: 0.2em;
    ">
    <div style="margin-bottom: 15px;">
      <label style="display: flex; align-items: center; font-size: 14px;">
        <input type="checkbox" id="use-backup-code" style="margin-right: 8px;">
        Use backup code instead
      </label>
    </div>
    <button id="verify-totp-login" disabled style="
      width: 100%;
      padding: 10px;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
      margin-bottom: 10px;
    ">Verify</button>
    <button onclick="this.closest('.modal-overlay').remove(); delete window.totpLoginData;" style="
      width: 100%;
      padding: 10px;
      background-color: #6c757d;
      color: white;
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
  const totpLoginData = typeof window !== 'undefined' ? (window as any).totpLoginData : null;
  if (!totpLoginData) {
    showError('Login session expired. Please try again.');
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
        sessionKey: totpLoginData.sessionKey,
        isBackup: isBackup
      }),
    });
    
    if (response.ok) {
      const data: TOTPLoginResponse = await response.json();
      
      // Complete authentication using LoginManager
      await LoginManager.completeLogin({
        token: data.token,
        refreshToken: data.refreshToken,
        sessionKey: data.sessionKey,
        authMethod: 'OPAQUE'
      }, totpLoginData.username);
      
      // Clean up
      if (typeof window !== 'undefined') {
        delete (window as any).totpLoginData;
      }
      document.querySelector('.modal-overlay')?.remove();
      
      showSuccess('Authentication successful!');
      
    } else {
      hideProgress();
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'TOTP verification failed');
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP verification error:', error);
    showError('TOTP verification failed');
  }
}

// TOTP Setup Functions
export async function initiateTOTPSetup(sessionKey: string): Promise<TOTPSetupData | null> {
  try {
    showProgressMessage('Setting up TOTP...');
    
    const response = await fetch('/api/totp/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        sessionKey: sessionKey
      }),
    });
    
    hideProgress();
    
    if (response.ok) {
      const data: TOTPSetupResponse = await response.json();
      return {
        secret: data.secret,
        qrCodeUrl: data.qrCodeUrl,
        backupCodes: data.backupCodes,
        manualEntry: data.manualEntry
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

export async function completeTOTPSetup(code: string, sessionKey: string): Promise<boolean> {
  try {
    showProgressMessage('Completing TOTP setup...');
    
    const response = await fetch('/api/totp/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        code: code,
        sessionKey: sessionKey
      }),
    });
    
    hideProgress();
    
    if (response.ok) {
      const data = await response.json();
      showSuccess('TOTP setup completed successfully!');
      return true;
    } else {
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'Invalid TOTP code');
      return false;
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP verification error:', error);
    showError('Failed to complete TOTP setup');
    return false;
  }
}

export async function getTOTPStatus(): Promise<{enabled: boolean, setupRequired: boolean} | null> {
  try {
    const response = await fetch('/api/totp/status', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
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

export async function disableTOTP(currentCode: string, sessionKey: string): Promise<boolean> {
  try {
    showProgressMessage('Disabling TOTP...');
    
    const response = await fetch('/api/totp/disable', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        currentCode: currentCode,
        sessionKey: sessionKey
      }),
    });
    
    hideProgress();
    
    if (response.ok) {
      showSuccess('TOTP disabled successfully');
      return true;
    } else {
      const errorData = await response.json().catch(() => ({}));
      showError(errorData.message || 'Failed to disable TOTP');
      return false;
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP disable error:', error);
    showError('Failed to disable TOTP');
    return false;
  }
}

// TOTP Setup Modal
export function showTOTPSetupModal(sessionKey: string): void {
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
        <div style="width: 20px; height: 20px; border: 2px solid #007bff; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto;"></div>
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
  initiateTOTPSetup(sessionKey).then(setupData => {
    if (setupData) {
      showTOTPSetupData(modalContent, setupData, sessionKey);
    } else {
      modal.remove();
    }
  });
}

function showTOTPSetupData(modalContent: Element, setupData: TOTPSetupData, sessionKey: string): void {
  modalContent.innerHTML = `
    <h3 style="margin: 0 0 20px 0;">Setup Two-Factor Authentication</h3>
    <div style="margin-bottom: 20px;">
      <h4>Step 1: Scan QR Code</h4>
      <div style="text-align: center; margin: 15px 0;">
        <img src="${setupData.qrCodeUrl}" alt="TOTP QR Code" style="max-width: 200px;">
      </div>
      <p style="font-size: 14px; color: #666;">
        Scan this QR code with your authenticator app 
        <a href="#" onclick="event.preventDefault(); window.showTOTPAppsModal();" style="color: #007bff; text-decoration: none; font-size: 13px;">
          Need a TOTP app?
        </a>
      </p>
    </div>
    
    <div style="margin-bottom: 20px;">
      <h4>Step 2: Manual Entry (Alternative)</h4>
      <div style="background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 10px 0;">
        <code style="font-family: monospace; word-break: break-all;">${setupData.manualEntry}</code>
      </div>
      <p style="font-size: 14px; color: #666;">
        If you can't scan the QR code, enter this code manually in your authenticator app.
      </p>
    </div>
    
    <div style="margin-bottom: 20px;">
      <h4>Step 3: Backup Codes</h4>
      <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 10px 0;">
        <p style="margin: 0 0 10px 0; font-weight: bold; color: #856404;">
          ⚠️ Save these backup codes in a secure location:
        </p>
        <div style="font-family: monospace; font-size: 14px; line-height: 1.5;">
          ${setupData.backupCodes.map(code => `<div>${code}</div>`).join('')}
        </div>
      </div>
      <p style="font-size: 14px; color: #666;">
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
        border: 1px solid #ddd;
        border-radius: 4px;
        margin-bottom: 15px;
        letter-spacing: 0.2em;
      ">
      <p style="font-size: 14px; color: #666; margin-bottom: 15px;">
        Enter the 6-digit code from your authenticator app to complete setup.
      </p>
    </div>
    
    <div style="display: flex; gap: 10px;">
      <button id="complete-totp-setup" disabled style="
        flex: 1;
        padding: 10px;
        background-color: #28a745;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
      ">Complete Setup</button>
      <button onclick="this.closest('.modal-overlay').remove();" style="
        flex: 1;
        padding: 10px;
        background-color: #6c757d;
        color: white;
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
        completeTOTPSetupFlow(setupCodeInput.value, sessionKey);
      }
    });
    
    completeButton.addEventListener('click', () => {
      completeTOTPSetupFlow(setupCodeInput.value, sessionKey);
    });
    
    // Focus the input
    setTimeout(() => setupCodeInput.focus(), 100);
  }
}

async function completeTOTPSetupFlow(code: string, sessionKey: string): Promise<void> {
  const success = await completeTOTPSetup(code, sessionKey);
  if (success) {
    document.querySelector('.modal-overlay')?.remove();
  }
}

// Export utility functions for WASM integration
export async function validateTOTPCode(code: string, username: string): Promise<boolean> {
  try {
    const result = await wasmManager.validateTOTPCode(code, username);
    return result.valid;
  } catch (error) {
    console.error('TOTP validation error:', error);
    return false;
  }
}

export async function generateTOTPSetup(username: string): Promise<TOTPSetupData | null> {
  try {
    const result = await wasmManager.generateTOTPSetupData(username);
    return result.success ? result.data! : null;
  } catch (error) {
    console.error('TOTP setup generation error:', error);
    return null;
  }
}

export async function verifyTOTPSetup(code: string, secret: string, username: string): Promise<boolean> {
  try {
    const result = await wasmManager.verifyTOTPSetup(code, secret, username);
    return result.valid;
  } catch (error) {
    console.error('TOTP setup verification error:', error);
    return false;
  }
}
