import { lockAccountKey } from '../crypto/account-key-cache';
import { clearAllSessionData } from '../utils/auth';
import { showError, showSuccess } from '../ui/messages';
import type { AppShell } from './shell';

/** Billing, security, contact, verify-file, lock key, and revoke-all toggles. */
export function setupShellListeners(shell: AppShell): void {
  const billingToggle = document.getElementById('billing-toggle');
  if (billingToggle) {
    billingToggle.addEventListener('click', async (e) => {
      e.preventDefault();
      const { toggleBillingPanel } = await import('../ui/billing');
      await toggleBillingPanel();
    });
  }

  void import('../files/verify-file.js').then(({ wireVerifyFilePanel, toggleVerifyFilePanel }) => {
    wireVerifyFilePanel();
    const verifyToggle = document.getElementById('verify-file-toggle');
    if (verifyToggle) {
      verifyToggle.addEventListener('click', (e) => {
        e.preventDefault();
        toggleVerifyFilePanel();
      });
    }
  });

  const securityToggle = document.getElementById('security-settings-toggle');
  if (securityToggle) {
    void import('../auth/mfa-settings.js').then(({ wireMFASettingsPanel }) => {
      wireMFASettingsPanel();
    });
    securityToggle.addEventListener('click', async (e) => {
      e.preventDefault();
      const { toggleSecuritySettings } = await import('../ui/sections');
      toggleSecuritySettings();
    });
  }

  const contactToggle = document.getElementById('contact-info-toggle');
  if (contactToggle) {
    contactToggle.addEventListener('click', async (e) => {
      e.preventDefault();
      const { toggleContactInfoPanel } = await import('../ui/contact-info');
      await toggleContactInfoPanel();
    });
  }

  const saveContactBtn = document.getElementById('save-contact-info-btn');
  if (saveContactBtn) {
    saveContactBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { saveContactInfo } = await import('../ui/contact-info');
      await saveContactInfo();
    });
  }

  const deleteContactBtn = document.getElementById('delete-contact-info-btn');
  if (deleteContactBtn) {
    deleteContactBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { deleteContactInfo } = await import('../ui/contact-info');
      await deleteContactInfo();
    });
  }

  const addContactBtn = document.getElementById('add-contact-method-btn');
  if (addContactBtn) {
    addContactBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { addContactMethodRow } = await import('../ui/contact-info');
      addContactMethodRow();
    });
  }

  const lockKeyBtn = document.getElementById('lock-key-btn');
  if (lockKeyBtn) {
    lockKeyBtn.addEventListener('click', (e) => {
      e.preventDefault();
      lockAccountKey();
      showSuccess('Encryption key locked. You will need to re-enter your password for the next file operation.');
    });
  }

  const revokeButton = document.getElementById('revoke-sessions-btn');
  if (revokeButton) {
    revokeButton.addEventListener('click', async (e) => {
      e.preventDefault();
      const { revokeAllSessions } = await import('../utils/auth');
      const success = await revokeAllSessions();
      if (success) {
        showSuccess('All sessions have been revoked. Please log in again.');
        clearAllSessionData();
        shell.showHome();
      } else {
        showError('Failed to revoke sessions.');
      }
    });
  }
}
