/**
 * TOTP Setup flow for new user registration
 * Handles the mandatory TOTP setup after OPAQUE registration completes
 */

import { showError, showSuccess } from '../ui/messages.js';
import { showProgressMessage, hideProgress } from '../ui/progress.js';
import { showModal, showTOTPAppsModal } from '../ui/modals.js';
import { setTokens } from '../utils/auth.js';
import { showFileSection, showPendingApprovalSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';

// Make showTOTPAppsModal available globally for inline onclick handlers
if (typeof window !== 'undefined') {
  (window as any).showTOTPAppsModal = showTOTPAppsModal;
}

export interface TOTPSetupFlowData {
  tempToken: string;
  username: string;
}

export interface TOTPSetupData {
  secret: string;
  qr_code_url: string;
  qr_code_image: string; // Base64 data URI for QR code PNG
  backup_codes: string[];
  manual_entry: string;
}

/**
 * Handle TOTP setup flow after registration
 * This is called when the server returns requires_totp_setup: true
 */
export function handleTOTPSetupFlow(data: TOTPSetupFlowData): void {
  // Store the registration data temporarily
  if (typeof window !== 'undefined') {
    (window as any).totpSetupData = data;
  }
  
  hideProgress();
  
  // Show loading modal while fetching TOTP setup data
  const modal = showModal({
    title: "Setup Two-Factor Authentication",
    message: "Two-factor authentication is required to complete your registration.",
    buttons: [],
    allowClose: false
  });
  
  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  // Show loading state
  modalContent.innerHTML = `
    <h3 class="totp-setup-title">Setup Two-Factor Authentication</h3>
    <div id="totp-setup-content" class="totp-info">
      <div style="text-align: center; padding: 1.5rem;">
        <div style="margin-bottom: 1rem; color: var(--muted-text-color);">Initializing TOTP setup...</div>
        <div class="spinner"></div>
      </div>
    </div>
  `;

  // Add CSS for spinner if not already present
  if (!document.getElementById('totp-spinner-style')) {
    const style = document.createElement('style');
    style.id = 'totp-spinner-style';
    style.textContent = `
      .spinner {
        width: 24px;
        height: 24px;
        border: 3px solid var(--background-color);
        border-top: 3px solid var(--secondary-color);
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin: 0 auto;
      }
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .totp-setup-title {
        margin: 0 0 1.5rem 0;
        color: var(--primary-color);
        font-size: 1.2rem;
      }
    `;
    document.head.appendChild(style);
  }

  // Fetch TOTP setup data from server
  initiateTOTPSetupForRegistration(data.tempToken).then(setupData => {
    if (setupData) {
      showTOTPSetupUI(modalContent, setupData, data);
    } else {
      modal.remove();
      showError('Failed to initialize TOTP setup. Please try logging in.');
    }
  });
}

/**
 * Fetch TOTP setup data from server using temp token
 */
async function initiateTOTPSetupForRegistration(tempToken: string): Promise<TOTPSetupData | null> {
  try {
    const response = await fetch('/api/totp/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tempToken}`
      },
      body: JSON.stringify({}),
    });
    
    if (response.ok) {
      const responseData = await response.json();
      // Handle both direct response and wrapped response
      const data = responseData.data || responseData;
      return {
        secret: data.secret,
        qr_code_url: data.qr_code_url,
        qr_code_image: data.qr_code_image || '',
        backup_codes: data.backup_codes,
        manual_entry: data.manual_entry
      };
    } else {
      const errorData = await response.json().catch(() => ({}));
      console.error('TOTP setup failed:', errorData);
      return null;
    }
  } catch (error) {
    console.error('TOTP setup error:', error);
    return null;
  }
}

/**
 * Display TOTP setup UI with QR code and backup codes
 */
function showTOTPSetupUI(modalContent: Element, setupData: TOTPSetupData, flowData: TOTPSetupFlowData): void {
  modalContent.innerHTML = `
    <h3 class="totp-setup-title">Setup Two-Factor Authentication</h3>
    <p style="margin-bottom: 1.5rem; color: var(--muted-text-color);">
      Two-factor authentication adds an extra layer of security to your account.
    </p>
    
    <div class="totp-step">
      <h3>Step 1: Scan QR Code</h3>
      <div class="qr-code-container">
        ${setupData.qr_code_image 
          ? `<img src="${setupData.qr_code_image}" alt="TOTP QR Code" style="width: 200px; height: 200px;">`
          : `<div style="padding: 1rem; background: #f8d7da; color: #721c24; border-radius: 4px;">QR code unavailable. Please use manual entry below.</div>`
        }
      </div>
      <p style="font-size: 0.9rem; color: var(--muted-text-color); text-align: center;">
        Scan this QR code with your authenticator app.
        <a href="#" onclick="event.preventDefault(); window.showTOTPAppsModal();" style="color: var(--secondary-color); text-decoration: none;">
          Need a TOTP app?
        </a>
      </p>
    </div>
    
    <div class="totp-step">
      <h3>Step 2: Manual Entry (Alternative)</h3>
      <div class="manual-entry">
        <code>${setupData.manual_entry}</code>
      </div>
      <p style="font-size: 0.9rem; color: var(--muted-text-color);">
        If you cannot scan the QR code, enter this code manually in your authenticator app.
      </p>
    </div>
    
    <div class="backup-codes-section">
      <p class="backup-warning">
        <strong>[!] Important:</strong> Save these backup codes in a secure location.
      </p>
      <div class="backup-codes-container">
        <div class="backup-codes-grid">
          ${setupData.backup_codes.map((code: string) => `<span class="backup-code">${code}</span>`).join('')}
        </div>
      </div>
      <p style="font-size: 0.9rem; color: #856404;">
        Use these codes if you lose access to your authenticator app. Each code can only be used once.
      </p>
      <button id="download-backup-codes" class="secondary-button" style="width: auto; margin-top: 0.5rem;">
        Download Backup Codes
      </button>
    </div>
    
    <div class="totp-step">
      <h3>Step 3: Verify Setup</h3>
      <div style="text-align: center;">
        <input type="text" id="totp-setup-code" class="totp-input" maxlength="6" placeholder="000000">
      </div>
      <p style="font-size: 0.9rem; color: var(--muted-text-color); text-align: center;">
        Enter the 6-digit code from your authenticator app to complete registration.
      </p>
    </div>
    
    <button id="complete-totp-setup" disabled style="
      width: 100%;
      padding: 0.8rem 1.5rem;
      background-color: var(--success-color);
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      transition: background-color 0.3s ease;
    ">Complete Registration</button>
  `;

  // Add event listeners
  const setupCodeInput = document.getElementById('totp-setup-code') as HTMLInputElement;
  const completeButton = document.getElementById('complete-totp-setup') as HTMLButtonElement;
  const downloadButton = document.getElementById('download-backup-codes') as HTMLButtonElement;
  
  if (setupCodeInput && completeButton) {
    setupCodeInput.addEventListener('input', function() {
      this.value = this.value.replace(/[^0-9]/g, '');
      completeButton.disabled = this.value.length !== 6;
    });
    
    setupCodeInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && this.value.length === 6) {
        completeTOTPSetupForRegistration(setupCodeInput.value, flowData);
      }
    });
    
    completeButton.addEventListener('click', () => {
      completeTOTPSetupForRegistration(setupCodeInput.value, flowData);
    });
    
    // Focus the input, then scroll modal to top so user sees QR code first
    setTimeout(() => {
      setupCodeInput.focus();
      // Scroll modal content back to top after focus (focus causes auto-scroll to input)
      modalContent.scrollTop = 0;
    }, 100);
  }
  
  if (downloadButton) {
    downloadButton.addEventListener('click', () => {
      downloadBackupCodes(setupData.backup_codes);
    });
  }
}

/**
 * Complete TOTP setup and finish registration
 */
async function completeTOTPSetupForRegistration(code: string, flowData: TOTPSetupFlowData): Promise<void> {
  try {
    showProgressMessage('Completing registration...');
    
    const response = await fetch('/api/totp/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${flowData.tempToken}`
      },
      body: JSON.stringify({
        code: code
      }),
    });
    
    if (response.ok) {
      const responseData = await response.json();
      // Handle both direct response and wrapped response
      const data = responseData.data || responseData;
      
      // Store the full access tokens
      if (data.token && data.refresh_token) {
        setTokens(data.token, data.refresh_token);
      }
      
      // Clean up
      if (typeof window !== 'undefined') {
        delete (window as any).totpSetupData;
      }
      document.querySelector('.modal-overlay')?.remove();
      
      hideProgress();
      showSuccess('Registration complete! Welcome to Arkfile.');
      
      // Check if user is approved - if not, show pending approval section
      const isApproved = data.user?.is_approved ?? data.is_approved ?? false;
      
      if (!isApproved) {
        // User needs admin approval before accessing files
        showPendingApprovalSection();
      } else {
        // Navigate to file section
        showFileSection();
        await loadFiles();
      }
      
    } else {
      hideProgress();
      const errorData = await response.json().catch(() => ({}));
      const errorMessage = errorData.message || errorData.error || 'Invalid TOTP code';
      showError(errorMessage);
    }
  } catch (error) {
    hideProgress();
    console.error('TOTP verification error:', error);
    showError('Failed to complete TOTP setup');
  }
}

/**
 * Download backup codes as a text file
 */
function downloadBackupCodes(codes: string[]): void {
  const content = [
    'ARKFILE TOTP BACKUP CODES',
    '-------------------------',
    '',
    'Store these codes in a secure location.',
    'Each code can only be used once.',
    '',
    'Generated: ' + new Date().toISOString(),
    '',
    ...codes.map((code, i) => `${i + 1}. ${code}`),
    '',
    '[!] WARNING: Keep these codes secret!',
  ].join('\n');

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
