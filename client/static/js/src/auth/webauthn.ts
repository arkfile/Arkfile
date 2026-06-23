/**
 * WebAuthn (security key) enrollment and login for browser clients.
 */

import {
  startRegistration,
  startAuthentication,
} from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser';
import { showError, showSuccess } from '../ui/messages.js';
import { showProgressMessage, hideProgress } from '../ui/progress.js';
import { showModal } from '../ui/modals.js';
import { clearAllSessionData, csrfHeader } from '../utils/auth.js';
import { getAdminContactForDisplay } from '../ui/footer.js';
import { showFileSection, showPendingApprovalSection, showAuthSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';
import { LoginManager } from './login.js';
import type { MFASetupFlowData } from './mfa-method.js';
import { isTorBrowser, isWebAuthnAvailable, validateWebAuthnLabelInput } from './mfa-method.js';

const BACKUP_CODES_STORAGE_KEY = 'arkfile_mfa_backup_codes';

interface WebAuthnBeginResponse {
  options: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialRequestOptionsJSON;
  backup_codes?: string[];
  resume?: boolean;
}

function stashBackupCodes(codes: string[]): void {
  try {
    sessionStorage.setItem(BACKUP_CODES_STORAGE_KEY, JSON.stringify(codes));
  } catch {
    // sessionStorage unavailable
  }
}

function loadStashedBackupCodes(): string[] {
  try {
    const raw = sessionStorage.getItem(BACKUP_CODES_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as string[];
  } catch {
    return [];
  }
}

function clearStashedBackupCodes(): void {
  try {
    sessionStorage.removeItem(BACKUP_CODES_STORAGE_KEY);
  } catch {
    // ignore
  }
}

function downloadBackupCodes(codes: string[]): void {
  const content = [
    'ARKFILE MFA BACKUP CODES',
    '------------------------',
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

/**
 * Start MFA enrollment with a security key after OPAQUE registration or login resume.
 */
export function handleWebAuthnSetupFlow(flowData: MFASetupFlowData): void {
  if (isTorBrowser() || !isWebAuthnAvailable()) {
    showError('Security keys are not supported in this browser. Use an authenticator app instead.');
    return;
  }

  const modal = showModal({
    title: 'Setup Security Key',
    message: 'Connect your security key when prompted.',
    buttons: [],
    allowClose: false,
  });

  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0;">Setup Security Key</h3>
    <div id="webauthn-setup-body" style="text-align: center; padding: 1.5rem 0;">
      <div class="spinner" style="
        width: 24px; height: 24px; margin: 0 auto 1rem;
        border: 3px solid var(--depth-1); border-top: 3px solid var(--current-1);
        border-radius: 50%; animation: spin 1s linear infinite;
      "></div>
      <p style="color: var(--foam-2); margin: 0;">Preparing security key enrollment...</p>
    </div>
  `;

  beginWebAuthnEnrollment(modal, modalContent, flowData);
}

async function beginWebAuthnEnrollment(
  modal: Element,
  modalContent: Element,
  flowData: MFASetupFlowData,
): Promise<void> {
  try {
    const response = await fetch(flowData.addSecondFactor
      ? '/api/mfa/credentials/webauthn/register/begin'
      : '/api/mfa/webauthn/register/begin', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({}),
    });

    if (!response.ok) {
      modal.remove();
      showError('Failed to start security key enrollment.');
      return;
    }

    const envelope = await response.json();
    const data: WebAuthnBeginResponse = envelope.data || envelope;

    let backupCodes = data.backup_codes || [];
    if (data.resume && backupCodes.length === 0) {
      backupCodes = loadStashedBackupCodes();
    } else if (backupCodes.length > 0) {
      stashBackupCodes(backupCodes);
    }

    showWebAuthnSetupUI(modal, modalContent, flowData, data.options as PublicKeyCredentialCreationOptionsJSON, backupCodes);
  } catch (err) {
    console.error('WebAuthn register begin error:', err);
    modal.remove();
    showError('Failed to start security key enrollment.');
  }
}

function showWebAuthnSetupUI(
  modal: Element,
  modalContent: Element,
  flowData: MFASetupFlowData,
  options: PublicKeyCredentialCreationOptionsJSON,
  backupCodes: string[],
): void {
  const codesHtml = backupCodes.length > 0
    ? backupCodes.map(c => `<span class="backup-code">${c}</span>`).join('')
    : '<span style="color: var(--foam-2); font-size: 0.9rem;">Backup codes were shown earlier in this session. Check your saved copy.</span>';

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0;">Setup Security Key</h3>
    <p style="margin: 0 0 1rem 0; color: var(--foam-2); font-size: 0.95rem;">
      Insert or tap your security key, then confirm enrollment when your browser prompts you.
    </p>
    <div class="backup-codes-section" style="margin-bottom: 1.25rem;">
      <p class="backup-warning" style="color: var(--phosphor); font-size: 0.9rem;">
        <strong>[!] Important:</strong> Save these backup codes in a secure location.
      </p>
      <div class="backup-codes-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem; margin: 0.75rem 0;">
        ${codesHtml}
      </div>
      ${backupCodes.length > 0 ? `
        <button id="webauthn-download-backup" type="button" class="secondary-button" style="width: auto;">
          Download Backup Codes
        </button>
      ` : ''}
    </div>
    <button id="webauthn-enroll-btn" type="button" style="
      width: 100%;
      padding: 0.85rem;
      background-color: var(--biolum);
      color: var(--salt);
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      margin-bottom: 0.5rem;
    ">Register Security Key</button>
    <label for="webauthn-label-input" style="display:block; margin: 0.75rem 0 0.35rem; color: var(--foam-2); font-size: 0.9rem;">
      Private key label (optional, ASCII, max 64)
    </label>
    <input id="webauthn-label-input" type="text" maxlength="64" placeholder="e.g. Desk Nitrokey" style="
      width: 100%;
      padding: 0.65rem;
      margin-bottom: 0.75rem;
      border: 1px solid var(--depth-4);
      border-radius: 4px;
      background: var(--depth-2);
      color: var(--salt);
    ">
    <button id="webauthn-enroll-cancel" type="button" style="
      width: 100%;
      padding: 0.75rem;
      background: transparent;
      color: var(--foam-2);
      border: none;
      cursor: pointer;
      font-size: 0.95rem;
    ">Cancel</button>
  `;

  document.getElementById('webauthn-download-backup')?.addEventListener('click', () => {
    downloadBackupCodes(backupCodes);
  });

  document.getElementById('webauthn-enroll-cancel')?.addEventListener('click', () => {
    modal.remove();
  });

  document.getElementById('webauthn-enroll-btn')?.addEventListener('click', async () => {
    await finishWebAuthnEnrollment(modal, flowData, options, backupCodes);
  });
}

async function finishWebAuthnEnrollment(
  modal: Element,
  flowData: MFASetupFlowData,
  options: PublicKeyCredentialCreationOptionsJSON,
  backupCodes: string[],
): Promise<void> {
  const labelInput = document.getElementById('webauthn-label-input') as HTMLInputElement | null;
  const label = labelInput?.value?.trim() || '';
  const labelError = validateWebAuthnLabelInput(label);
  if (labelError) {
    showError(labelError);
    return;
  }

  try {
    showProgressMessage('Waiting for security key...');
    const credential = await startRegistration({ optionsJSON: options });

    const response = await fetch(flowData.addSecondFactor
      ? '/api/mfa/credentials/webauthn/register/finish'
      : '/api/mfa/webauthn/register/finish', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({ credential, label }),
    });

    hideProgress();

    if (!response.ok) {
      if (response.status === 401) {
        handleSetupSessionExpired();
        return;
      }
      const errBody = await response.json().catch(() => ({}));
      showError(errBody.message || 'Security key enrollment failed.');
      return;
    }

    const envelope = await response.json();
    const data = envelope.data || envelope;
    clearStashedBackupCodes();
    modal.remove();

    if (data.token && data.refresh_token) {
      showSuccess('Registration complete! Welcome to Arkfile.');
      const isApproved = data.user?.is_approved ?? false;
      if (!isApproved) {
        showPendingApprovalSection();
      } else {
        showFileSection();
        await loadFiles();
      }
      return;
    }

    if (flowData.addSecondFactor) {
      showSuccess('Security key enrolled.');
      const { loadMFASettingsPanel } = await import('./mfa-settings.js');
      await loadMFASettingsPanel();
      return;
    }

    showSuccess('Security key enrolled successfully.');
    showFileSection();
    await loadFiles();
  } catch (err) {
    hideProgress();
    console.error('WebAuthn register finish error:', err);
    showError('Security key enrollment was cancelled or failed.');
  }
}

function handleSetupSessionExpired(): void {
  clearStashedBackupCodes();
  document.querySelector('.modal-overlay')?.remove();
  clearAllSessionData();
  showAuthSection();
  showError('Setup session expired. Please log in to continue MFA setup.');
}

export interface WebAuthnLoginFlowData {
  tempToken: string;
  username: string;
  password?: string;
  credentialId?: string;
  label?: string;
}

/** Assemble login flow input without assigning undefined to optional fields. */
export function buildWebAuthnLoginFlowData(params: {
  tempToken: string;
  username: string;
  password?: string | undefined;
  credentialId?: string | undefined;
  label?: string | undefined;
}): WebAuthnLoginFlowData {
  const result: WebAuthnLoginFlowData = {
    tempToken: params.tempToken,
    username: params.username,
  };
  if (params.password !== undefined) {
    result.password = params.password;
  }
  if (params.credentialId !== undefined) {
    result.credentialId = params.credentialId;
  }
  if (params.label !== undefined) {
    result.label = params.label;
  }
  return result;
}

let _pendingWebAuthnLogin: WebAuthnLoginFlowData | null = null;

/**
 * Handle security-key authentication after OPAQUE login.
 */
export function handleWebAuthnLoginFlow(data: WebAuthnLoginFlowData): void {
  if (isTorBrowser() || !isWebAuthnAvailable()) {
    showError('Security keys are not supported in this browser. Use backup code recovery or log in from a standard browser.');
    return;
  }

  _pendingWebAuthnLogin = data;

  const modal = showModal({
    title: 'Security Key Required',
    message: 'Use your enrolled security key to complete sign-in.',
    buttons: [
      {
        text: 'Cancel',
        action: () => { _pendingWebAuthnLogin = null; },
        variant: 'secondary',
      },
    ],
    allowClose: true,
  });

  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0;">Security Key Required</h3>
    ${data.label ? `<p style="margin: 0 0 0.75rem 0; color: var(--foam-2); font-size: 0.95rem; text-align: center;">Using: ${data.label}</p>` : ''}
    <p style="margin: 0 0 1.25rem 0; color: var(--foam-2); font-size: 0.95rem; text-align: center;">
      Insert or tap your security key when prompted.
    </p>
    <button id="webauthn-login-btn" type="button" style="
      width: 100%;
      padding: 0.85rem;
      background-color: var(--current-2);
      color: var(--salt);
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      margin-bottom: 0.75rem;
    ">Use Security Key</button>
    <div style="margin-top: 0.5rem; padding-top: 0.75rem; border-top: 1px solid var(--depth-4);">
      <p style="font-size: 0.85rem; color: var(--foam-2); text-align: center; margin: 0 0 0.5rem 0;">Lost your security key?</p>
      <input type="text" id="webauthn-backup-code" maxlength="10" placeholder="10-character backup code" style="
        width: 100%;
        padding: 0.65rem;
        font-size: 0.95rem;
        text-align: center;
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        margin-bottom: 0.5rem;
        letter-spacing: 0.08em;
      ">
      <button id="webauthn-backup-signin" type="button" style="
        width: 100%;
        padding: 0.65rem;
        margin-bottom: 0.4rem;
        background-color: var(--depth-3);
        color: var(--salt);
        border: 1px solid var(--depth-4);
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.9rem;
      ">Sign in once with backup code</button>
      <p id="webauthn-admin-recovery-hint" style="font-size: 0.8rem; color: var(--foam-2); text-align: center; margin: 0.5rem 0 0; line-height: 1.4;"></p>
    </div>
  `;

  document.getElementById('webauthn-login-btn')?.addEventListener('click', () => {
    void runWebAuthnLogin(modal);
  });

  document.getElementById('webauthn-backup-signin')?.addEventListener('click', () => {
    void runBackupSignIn(modal);
  });

  void populateWebAuthnAdminRecoveryHint();
}

async function populateWebAuthnAdminRecoveryHint(): Promise<void> {
  const hintEl = document.getElementById('webauthn-admin-recovery-hint');
  if (!hintEl) return;

  const contact = await getAdminContactForDisplay();
  if (contact) {
    hintEl.textContent =
      `If you have lost your security key and all backup codes, contact the admin: ${contact} (also shown as Contact Admin in the site footer).`;
  } else {
    hintEl.textContent =
      'If you have lost your security key and all backup codes, contact the instance admin (see Contact Admin in the site footer).';
  }
}

async function runBackupSignIn(modal: Element): Promise<void> {
  const flowData = _pendingWebAuthnLogin;
  if (!flowData) return;

  const input = document.getElementById('webauthn-backup-code') as HTMLInputElement | null;
  const code = input?.value?.trim() || '';
  if (code.length !== 10) {
    showError('Please enter a valid 10-character backup code.');
    return;
  }

  try {
    showProgressMessage('Verifying backup code...');
    const response = await fetch('/api/mfa/auth', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({ code, is_backup: true }),
    });
    hideProgress();

    if (!response.ok) {
      showError('Invalid backup code.');
      return;
    }

    const envelope = await response.json();
    const data = envelope.data || envelope;
    _pendingWebAuthnLogin = null;
    modal.remove();

    await LoginManager.completeLogin(
      {
        token: data.token,
        refresh_token: data.refresh_token,
        auth_method: data.auth_method || 'OPAQUE+WebAuthn',
        is_approved: data.user?.is_approved,
      },
      flowData.username,
      flowData.password,
    );
    showSuccess('Authentication successful!');
  } catch (err) {
    hideProgress();
    console.error('Backup sign-in error:', err);
    showError('Authentication failed.');
  }
}

async function runWebAuthnLogin(modal: Element): Promise<void> {
  const flowData = _pendingWebAuthnLogin;
  if (!flowData) return;

  try {
    showProgressMessage('Waiting for security key...');

    const beginResp = await fetch('/api/mfa/webauthn/auth/begin', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({ credential_id: flowData.credentialId || '' }),
    });

    if (!beginResp.ok) {
      hideProgress();
      showError('Failed to start security key authentication.');
      return;
    }

    const beginEnvelope = await beginResp.json();
    const beginData: WebAuthnBeginResponse = beginEnvelope.data || beginEnvelope;
    const options = beginData.options as PublicKeyCredentialRequestOptionsJSON;

    const credential = await startAuthentication({ optionsJSON: options });

    const finishResp = await fetch('/api/mfa/webauthn/auth/finish', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({
        credential,
        credential_id: flowData.credentialId || '',
      }),
    });

    hideProgress();

    if (!finishResp.ok) {
      showError('Security key authentication failed.');
      return;
    }

    const finishEnvelope = await finishResp.json();
    const finishData = finishEnvelope.data || finishEnvelope;

    _pendingWebAuthnLogin = null;
    modal.remove();

    await LoginManager.completeLogin(
      {
        token: finishData.token,
        refresh_token: finishData.refresh_token,
        auth_method: finishData.auth_method || 'OPAQUE+WebAuthn',
        is_approved: finishData.user?.is_approved,
      },
      flowData.username,
      flowData.password,
    );
  } catch (err) {
    hideProgress();
    console.error('WebAuthn auth error:', err);
    showError('Security key authentication was cancelled or failed.');
  }
}
