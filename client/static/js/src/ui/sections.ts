/**
 * UI section management utilities
 */

export function showFileSection(): void {
  const authSection = document.getElementById('auth-section');
  const fileSection = document.getElementById('file-section');
  
  if (authSection) {
    authSection.classList.add('hidden');
  }
  
  if (fileSection) {
    fileSection.classList.remove('hidden');
  }
}

export function showAuthSection(): void {
  const authSection = document.getElementById('auth-section');
  const fileSection = document.getElementById('file-section');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const totpSetupForm = document.getElementById('totp-setup-form');
  const pendingApprovalSection = document.getElementById('pending-approval-section');
  
  if (authSection) {
    authSection.classList.remove('hidden');
  }
  
  if (fileSection) {
    fileSection.classList.add('hidden');
  }
  
  // Reset all auth sub-sections to default state: only login form visible.
  // This prevents stale visibility from pending-approval, TOTP setup, or
  // register form persisting across logout -> login navigations.
  if (loginForm) loginForm.classList.remove('hidden');
  if (registerForm) registerForm.classList.add('hidden');
  if (totpSetupForm) totpSetupForm.classList.add('hidden');
  if (pendingApprovalSection) pendingApprovalSection.classList.add('hidden');

  // Clear all auth form input values so credentials don't persist after logout
  const authInputIds = [
    'login-username', 'login-password',
    'register-username', 'register-password', 'register-password-confirm',
  ];
  for (const id of authInputIds) {
    const input = document.getElementById(id) as HTMLInputElement | null;
    if (input) input.value = '';
  }
}

export function toggleAuthForm(): void {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  
  if (loginForm) {
    loginForm.classList.toggle('hidden');
  }
  
  if (registerForm) {
    registerForm.classList.toggle('hidden');
  }
}

export function showTOTPSetupSection(predefinedData?: any): void {
  const registerForm = document.getElementById('register-form');
  const loginForm = document.getElementById('login-form');
  const totpSetupForm = document.getElementById('totp-setup-form');

  if (registerForm) {
    registerForm.classList.add('hidden');
  }

  if (loginForm) {
    loginForm.classList.add('hidden');
  }

  if (totpSetupForm) {
    totpSetupForm.classList.remove('hidden');
  }

  if (predefinedData) {
    // Populate QR code display using predefined reset data directly
    const qrDisplay = document.getElementById('qr-code-display');
    const qrSection = document.getElementById('qr-code-section');
    const manualCode = document.getElementById('manual-entry-code');
    const verifyBtn = document.getElementById('verify-totp-btn') as HTMLButtonElement | null;
    const backupSection = document.getElementById('backup-codes-section');
    const backupList = document.getElementById('backup-codes-list');

    if (qrDisplay) {
      qrDisplay.innerHTML = `<img src="${predefinedData.qr_code_url}" alt="TOTP QR Code" style="max-width:200px;height:auto;border:1px solid var(--depth-4);border-radius:4px;">`;
    }
    if (manualCode) {
      manualCode.textContent = predefinedData.manual_entry;
    }
    if (qrSection) {
      qrSection.classList.remove('hidden');
    }
    if (verifyBtn) {
      verifyBtn.disabled = false;
    }
    if (backupList && predefinedData.backup_codes?.length) {
      backupList.innerHTML = predefinedData.backup_codes.map((c: string) => `<li>${c}</li>`).join('');
    }
    if (backupSection) {
      backupSection.classList.remove('hidden');
    }
  } else {
    // Auto-trigger TOTP setup so the QR code appears immediately.
    // Directly calls generateAndDisplayTOTPSetup() rather than simulating a button click,
    // because the button's event listener in app.ts may not be attached yet at this point.
    import('../auth/totp.js').then(({ generateAndDisplayTOTPSetup }) => {
      generateAndDisplayTOTPSetup().catch(() => {});
    }).catch(() => {});
  }
}

export function hideTOTPSetupSection(): void {
  const totpSetupForm = document.getElementById('totp-setup-form');
  const loginForm = document.getElementById('login-form');
  
  if (totpSetupForm) {
    totpSetupForm.classList.add('hidden');
  }
  
  if (loginForm) {
    loginForm.classList.remove('hidden');
  }
}

export function toggleSecuritySettings(): void {
  const securityPanel = document.getElementById('security-settings');
  if (securityPanel) {
    const opening = securityPanel.classList.contains('hidden');
    securityPanel.classList.toggle('hidden');
    if (opening) {
      void import('../auth/mfa-settings.js').then(({ loadMFASettingsPanel }) => loadMFASettingsPanel());
    }
  }
}

export function showPendingApprovalSection(): void {
  // Hide all other auth-related sections
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const totpSetupForm = document.getElementById('totp-setup-form');
  const pendingApprovalSection = document.getElementById('pending-approval-section');
  const fileSection = document.getElementById('file-section');

  if (loginForm) {
    loginForm.classList.add('hidden');
  }

  if (registerForm) {
    registerForm.classList.add('hidden');
  }

  if (totpSetupForm) {
    totpSetupForm.classList.add('hidden');
  }

  if (fileSection) {
    fileSection.classList.add('hidden');
  }

  if (pendingApprovalSection) {
    pendingApprovalSection.classList.remove('hidden');
  }

  // Fetch admin contact info and display it for the pending user (best-effort)
  import('../utils/auth.js').then(({ fetchAdminContacts }) => {
    fetchAdminContacts().then(({ contact, configured }) => {
      const el = document.getElementById('pending-admin-contact-display');
      if (el && configured && contact) {
        el.textContent = ` You can reach the admin at: ${contact}`;
      }
    }).catch(() => {});
  }).catch(() => {});

  // Load any previously saved contact info into the pending form (best-effort)
  import('./contact-info.js').then(({ loadPendingContactInfo }) => {
    loadPendingContactInfo().catch(() => {});
  }).catch(() => {});
}

export function hidePendingApprovalSection(): void {
  const pendingApprovalSection = document.getElementById('pending-approval-section');
  const loginForm = document.getElementById('login-form');
  
  if (pendingApprovalSection) {
    pendingApprovalSection.classList.add('hidden');
  }
  
  if (loginForm) {
    loginForm.classList.remove('hidden');
  }
}
