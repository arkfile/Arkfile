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
  addSecondFactor?: boolean;
}

export interface MFALoginMethodOption {
  type: MFAMethod;
  credential_id?: string;
  label?: string;
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

function methodButtonLabel(option: MFALoginMethodOption): string {
  if (option.type === 'totp') {
    return 'Authenticator app (TOTP)';
  }
  if (option.label) {
    return `Security key: ${option.label}`;
  }
  return 'Security key';
}

/**
 * Prompt the user to choose a second factor at login when multiple are enrolled.
 */
export function showMFALoginMethodPicker(
  methods: MFALoginMethodOption[],
  onSelect: (method: MFALoginMethodOption) => void,
): void {
  const modal = showModal({
    title: 'Choose Second Factor',
    message: 'Select how you want to complete sign-in.',
    buttons: [],
    allowClose: false,
  });

  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  const buttonsHtml = methods.map((method, index) => `
    <button id="mfa-login-pick-${index}" type="button" data-index="${index}" style="
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
    ">${methodButtonLabel(method)}</button>
  `).join('');

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0; color: var(--salt);">Choose Second Factor</h3>
    <p style="margin: 0 0 1.25rem 0; color: var(--foam-2); font-size: 0.95rem;">
      Your account has more than one second factor. Pick one to finish signing in.
    </p>
    ${buttonsHtml}
  `;

  methods.forEach((method, index) => {
    document.getElementById(`mfa-login-pick-${index}`)?.addEventListener('click', () => {
      modal.remove();
      onSelect(method);
    });
  });
}

/**
 * Prompt the user to choose TOTP or a security key before first enrollment.
 */
export function showMFAMethodPicker(
  onSelect: (method: MFAMethod) => void,
  options?: { addSecondFactor?: boolean },
): void {
  const addSecond = options?.addSecondFactor === true;
  const modal = showModal({
    title: addSecond ? 'Add Second Factor' : 'Choose Second Factor',
    message: addSecond
      ? 'Add a complementary second factor to your account.'
      : 'Select how you want to protect your account.',
    buttons: [],
    allowClose: false,
  });

  const modalContent = modal.querySelector('.modal-content');
  if (!modalContent) return;

  const tor = isTorBrowser();
  const webauthnOk = isWebAuthnAvailable() && !tor;

  modalContent.innerHTML = `
    <h3 style="margin: 0 0 1rem 0; color: var(--salt);">${addSecond ? 'Add Second Factor' : 'Choose Second Factor'}</h3>
    <p style="margin: 0 0 1.25rem 0; color: var(--foam-2); font-size: 0.95rem;">
      ${addSecond
        ? 'You may enroll one authenticator app and one security key. Your existing backup codes stay valid.'
        : 'Two-factor authentication is required. Pick your first method now; you can add the other type later from MFA settings.'}
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

  document.getElementById('mfa-pick-totp')?.addEventListener('click', () => {
    modal.remove();
    onSelect('totp');
  });

  document.getElementById('mfa-pick-webauthn')?.addEventListener('click', () => {
    if (!webauthnOk) return;
    modal.remove();
    onSelect('webauthn');
  });
}

export function validateWebAuthnLabelInput(label: string): string | null {
  const trimmed = label.trim();
  if (!trimmed) return null;
  if (trimmed.length > 64) {
    return 'Label must be at most 64 characters.';
  }
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return 'Label must use ASCII printable characters only.';
    }
  }
  return null;
}
