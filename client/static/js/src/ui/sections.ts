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

export function showTOTPSetupSection(): void {
  const registerForm = document.getElementById('register-form');
  const totpSetupForm = document.getElementById('totp-setup-form');

  if (registerForm) {
    registerForm.classList.add('hidden');
  }

  if (totpSetupForm) {
    totpSetupForm.classList.remove('hidden');
  }

  // Auto-trigger TOTP setup so the QR code appears immediately.
  // Directly calls generateAndDisplayTOTPSetup() rather than simulating a button click,
  // because the button's event listener in app.ts may not be attached yet at this point.
  import('../auth/totp.js').then(({ generateAndDisplayTOTPSetup }) => {
    generateAndDisplayTOTPSetup().catch(() => {});
  }).catch(() => {});
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
    securityPanel.classList.toggle('hidden');
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
    fetchAdminContacts().then(({ contact }) => {
      const el = document.getElementById('pending-admin-contact-display');
      if (el && contact && contact !== 'admin@example.com') {
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
