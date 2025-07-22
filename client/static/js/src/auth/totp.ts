/**
 * TOTP (Two-Factor Authentication) functionality
 */

import { wasmManager } from '../utils/wasm';
import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { showModal } from '../ui/modals';
import { setTokens } from '../utils/auth';
import { showFileSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { LoginManager } from './login';

export interface TOTPFlowData {
  partialToken: string;
  email: string;
}

export interface TOTPLoginResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
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
  
  if (totpInput && verifyButton) {
    totpInput.addEventListener('input', function() {
      this.value = this.value.replace(/[^0-9]/g, '');
      verifyButton.disabled = this.value.length !== 6;
    });
    
    totpInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && this.value.length === 6) {
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
  if (!codeInput) return;

  const code = codeInput.value;
  
  if (!code || code.length !== 6) {
    showError('Please enter a 6-digit code.');
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
    
    const response = await fetch('/api/opaque/login-totp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        partialToken: totpLoginData.partialToken,
        totpCode: code
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
      }, totpLoginData.email);
      
      // Clean up
      if (typeof window !== 'undefined') {
        delete (window as any).totpLoginData;
      }
      document.querySelector('.modal-overlay')?.remove();
      
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

// Export utility functions
export async function validateTOTPCode(code: string, userEmail: string): Promise<boolean> {
  try {
    const result = await wasmManager.validateTOTPCode(code, userEmail);
    return result.valid;
  } catch (error) {
    console.error('TOTP validation error:', error);
    return false;
  }
}

export async function generateTOTPSetup(userEmail: string): Promise<TOTPSetupData | null> {
  try {
    const result = await wasmManager.generateTOTPSetupData(userEmail);
    return result.success ? result.data! : null;
  } catch (error) {
    console.error('TOTP setup generation error:', error);
    return null;
  }
}

export async function verifyTOTPSetup(code: string, secret: string, userEmail: string): Promise<boolean> {
  try {
    const result = await wasmManager.verifyTOTPSetup(code, secret, userEmail);
    return result.valid;
  } catch (error) {
    console.error('TOTP setup verification error:', error);
    return false;
  }
}
