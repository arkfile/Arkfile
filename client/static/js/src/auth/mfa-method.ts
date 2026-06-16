/**
 * MFA method selection and environment checks for browser enrollment/login.
 */

import { showModal } from '../ui/modals.js';

export type MFAMethod = 'totp' | 'webauthn';

export interface MFASetupFlowData {
  tempToken: string;
  username: string;
  password?: string;
  mfaMethod?: MFAMethod | '';
}

/** True when the browser is likely Tor Browser (no reliable WebAuthn for hardware keys). */
export function isTorBrowser(): boolean {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent || '';
  return ua.includes('Tor Browser');
}

export function isWebAuthnAvailable(): boolean {
  return typeof window !== 'undefined'
    && typeof PublicKeyCredential !== 'undefined'
    && typeof navigator.credentials?.create === 'function';
}

/**
 * Prompt the user to choose TOTP or a security key before enrollment begins.
 */
export function showMFAMethodPicker(
  onSelect: (method: MFAMethod) => void,
): void {
  const modal = showModal({
    title: 'Choose Second Factor',
    message: 'Select how you want to protect your account. You can use only one method.',
    buttons: [],
    allowClose: false,
  });

  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  const tor = isTorBrowser();
  const webauthnOk = isWebAuthnAvailable() && !tor;

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0; color: var(--salt);">Choose Second Factor</h3>
    <p style="margin: 0 0 1.25rem 0; color: var(--foam-2); font-size: 0.95rem;">
      Two-factor authentication is required. Pick one method to enroll now.
    </p>
    <button id="mfa-pick-totp" type="button" style="
      width: 100%;
      padding: 0.85rem 1rem;
      margin-bottom: 0.75rem;
      background-color: var(--depth-3);
      color: var(--salt);
      border: 1px solid var(--depth-4);
      border-radius: 4px;
      cursor: pointer;
      font-size: 1rem;
      text-align: left;
    ">
      <strong>Authenticator app (TOTP)</strong><br>
      <span style="font-size: 0.85rem; color: var(--foam-2);">Works in any browser, including Tor Browser.</span>
    </button>
    <button id="mfa-pick-webauthn" type="button" ${webauthnOk ? '' : 'disabled'} style="
      width: 100%;
      padding: 0.85rem 1rem;
      margin-bottom: 0.75rem;
      background-color: var(--depth-3);
      color: var(--salt);
      border: 1px solid var(--depth-4);
      border-radius: 4px;
      cursor: ${webauthnOk ? 'pointer' : 'not-allowed'};
      opacity: ${webauthnOk ? '1' : '0.55'};
      font-size: 1rem;
      text-align: left;
    ">
      <strong>Security key (WebAuthn)</strong><br>
      <span style="font-size: 0.85rem; color: var(--foam-2);">USB or NFC hardware key (YubiKey, Nitrokey, etc.).</span>
    </button>
    ${tor ? `
      <p style="margin: 0 0 0.75rem 0; padding: 0.75rem; background: color-mix(in srgb, var(--phosphor) 12%, var(--depth-3)); border: 1px solid var(--phosphor); border-radius: 4px; font-size: 0.85rem; color: var(--phosphor);">
        [!] Tor Browser does not support security keys. Use an authenticator app (TOTP) instead.
      </p>
    ` : ''}
    ${!webauthnOk && !tor ? `
      <p style="margin: 0; font-size: 0.85rem; color: var(--foam-2);">
        Security keys are not available in this browser. Use an authenticator app instead.
      </p>
    ` : ''}
  `;

  const totpBtn = document.getElementById('mfa-pick-totp');
  const webauthnBtn = document.getElementById('mfa-pick-webauthn');

  totpBtn?.addEventListener('click', () => {
    modal.remove();
    onSelect('totp');
  });

  webauthnBtn?.addEventListener('click', () => {
    if (!webauthnOk) return;
    modal.remove();
    onSelect('webauthn');
  });
}
