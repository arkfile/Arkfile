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
  
  if (authSection) {
    authSection.classList.remove('hidden');
  }
  
  if (fileSection) {
    fileSection.classList.add('hidden');
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

export function showTOTPSetupSection(): void {
  const registerForm = document.getElementById('register-form');
  const totpSetupForm = document.getElementById('totp-setup-form');
  
  if (registerForm) {
    registerForm.classList.add('hidden');
  }
  
  if (totpSetupForm) {
    totpSetupForm.classList.remove('hidden');
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
    securityPanel.classList.toggle('hidden');
  }
}
