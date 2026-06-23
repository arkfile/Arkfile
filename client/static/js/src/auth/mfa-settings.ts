/**
 * Logged-in MFA settings: list factors, add second factor, remove, regenerate backup codes.
 */

import { showError, showSuccess } from '../ui/messages.js';
import { authenticatedFetch, clearAllSessionData, csrfHeader } from '../utils/auth.js';
import { showMFAMethodPicker } from './mfa-method.js';
import { handleTOTPSetupFlow } from './totp-setup.js';
import { handleWebAuthnSetupFlow } from './webauthn.js';

interface MFACredentialSummary {
  credential_id: string;
  method_type: 'totp' | 'webauthn';
  created_at?: string;
  label?: string;
}

function methodDisplayName(cred: MFACredentialSummary): string {
  if (cred.method_type === 'totp') {
    return 'Authenticator app (TOTP)';
  }
  return cred.label ? `Security key: ${cred.label}` : 'Security key';
}

async function fetchCredentials(): Promise<MFACredentialSummary[]> {
  const response = await authenticatedFetch('/api/mfa/credentials', { method: 'GET' });
  if (!response.ok) {
    throw new Error('Failed to load MFA credentials');
  }
  const envelope = await response.json();
  const data = envelope.data || envelope;
  return (data.credentials || []) as MFACredentialSummary[];
}

function renderCredentialList(container: HTMLElement, credentials: MFACredentialSummary[]): void {
  if (credentials.length === 0) {
    container.innerHTML = '<p style="color: var(--foam-2);">No enrolled second factors found.</p>';
    return;
  }

  container.innerHTML = credentials.map((cred) => `
    <div class="mfa-credential-row" style="padding: 0.75rem 0; border-bottom: 1px solid var(--depth-4);">
      <div style="display:flex; justify-content:space-between; align-items:center; gap: 1rem;">
        <div>
          <strong>${methodDisplayName(cred)}</strong>
          ${cred.created_at ? `<div style="font-size: 0.85rem; color: var(--foam-2);">Enrolled ${new Date(cred.created_at).toLocaleString()}</div>` : ''}
        </div>
        <button type="button" class="secondary-button mfa-remove-btn" data-id="${cred.credential_id}">Remove</button>
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.mfa-remove-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = (btn as HTMLElement).dataset.id;
      if (!id || !confirm('Remove this second factor? You will be signed out on all devices.')) {
        return;
      }
      const response = await authenticatedFetch(`/api/mfa/credentials/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        showError('Failed to remove MFA credential.');
        return;
      }
      const body = await response.json();
      const data = body.data || body;
      if (data.requires_mfa_setup) {
        clearAllSessionData();
        showError('Your last second factor was removed. Please sign in and set up MFA again.');
        window.location.reload();
        return;
      }
      clearAllSessionData();
      showSuccess('Second factor removed. Please sign in again.');
      window.location.reload();
    });
  });
}

export async function loadMFASettingsPanel(): Promise<void> {
  const list = document.getElementById('mfa-settings-list');
  if (!list) return;

  try {
    const credentials = await fetchCredentials();
    renderCredentialList(list, credentials);

    const hasTOTP = credentials.some((c) => c.method_type === 'totp');
    const hasWebAuthn = credentials.some((c) => c.method_type === 'webauthn');
    const addBtn = document.getElementById('mfa-add-second-btn') as HTMLButtonElement | null;
    if (addBtn) {
      addBtn.disabled = hasTOTP && hasWebAuthn;
      addBtn.textContent = hasTOTP && hasWebAuthn
        ? 'Both factor types enrolled'
        : 'Add second factor';
    }
  } catch {
    list.innerHTML = '<p style="color: var(--phosphor);">Failed to load MFA settings.</p>';
  }
}

async function startAddSecondFactor(method: 'totp' | 'webauthn'): Promise<void> {
  if (method === 'totp') {
    handleTOTPSetupFlow({ tempToken: '', username: '', addSecondFactor: true });
    return;
  }
  handleWebAuthnSetupFlow({ tempToken: '', username: '', addSecondFactor: true });
}

export function wireMFASettingsPanel(): void {
  document.getElementById('mfa-add-second-btn')?.addEventListener('click', () => {
    void fetchCredentials().then((credentials) => {
      const hasTOTP = credentials.some((c) => c.method_type === 'totp');
      const hasWebAuthn = credentials.some((c) => c.method_type === 'webauthn');
      showMFAMethodPicker((method) => {
        if (method === 'totp' && hasTOTP) return;
        if (method === 'webauthn' && hasWebAuthn) return;
        void startAddSecondFactor(method);
      }, { addSecondFactor: true });
    });
  });

  document.getElementById('mfa-regenerate-backup-btn')?.addEventListener('click', async () => {
    if (!confirm('Generate a new set of backup codes? Old unused codes will stop working immediately.')) {
      return;
    }
    const response = await authenticatedFetch('/api/mfa/backup-codes/regenerate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...csrfHeader() },
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      showError('Failed to regenerate backup codes.');
      return;
    }
    const envelope = await response.json();
    const data = envelope.data || envelope;
    const codes = (data.backup_codes || []) as string[];
    showSuccess(`Generated ${codes.length} new backup codes. Save them securely.`);
  });
}
