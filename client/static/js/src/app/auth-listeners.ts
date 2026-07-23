import { stopAutoRefresh } from '../utils/auth';
import { showAuthSection, toggleAuthForm } from '../ui/sections';
import { setupLoginForm, login, logout } from '../auth/login';
import { setupRegisterForm, register } from '../auth/register';
import { addPasswordTogglesInContainer } from '../utils/password-toggle';
import type { AppShell } from './shell';

function setupPasswordToggles(): void {
  const authSection = document.getElementById('auth-section');
  if (authSection) {
    addPasswordTogglesInContainer(authSection);
  }

  const uploadSection = document.querySelector('.upload-section');
  if (uploadSection instanceof HTMLElement) {
    addPasswordTogglesInContainer(uploadSection);
  }
}

function setupPasswordTypeToggle(): void {
  const passwordTypeRadios = document.querySelectorAll('input[name="passwordType"]');
  const customPasswordSection = document.getElementById('customPasswordSection');
  const filePassword = document.getElementById('filePassword') as HTMLInputElement;

  passwordTypeRadios.forEach((radio) => {
    radio.addEventListener('change', (e) => {
      const target = e.target as HTMLInputElement;
      const useCustomPassword = target.value === 'custom';

      if (customPasswordSection) {
        customPasswordSection.classList.toggle('hidden', !useCustomPassword);
      }

      if (!useCustomPassword && filePassword) {
        filePassword.value = '';
      }
    });
  });
}

/** Login, register, logout, pending-approval contact actions, and password toggles. */
export function setupAuthListeners(shell: AppShell): void {
  setupLoginForm();

  const showRegisterLink = document.getElementById('show-register-link');
  if (showRegisterLink) {
    showRegisterLink.addEventListener('click', (e) => {
      e.preventDefault();
      toggleAuthForm();
    });
  }

  const showLoginLink = document.getElementById('show-login-link');
  if (showLoginLink) {
    showLoginLink.addEventListener('click', (e) => {
      e.preventDefault();
      toggleAuthForm();
      setupLoginForm();
    });
  }

  const backToHomeLink = document.getElementById('back-to-home-link');
  if (backToHomeLink) {
    backToHomeLink.addEventListener('click', (e) => {
      e.preventDefault();
      shell.showHome();
    });
  }

  const backToHomeFromRegisterLink = document.getElementById('back-to-home-from-register-link');
  if (backToHomeFromRegisterLink) {
    backToHomeFromRegisterLink.addEventListener('click', (e) => {
      e.preventDefault();
      shell.showHome();
    });
  }

  const loginSubmitBtn = document.getElementById('login-submit-btn');
  if (loginSubmitBtn) {
    loginSubmitBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await login();
    });
  }

  setupRegisterForm();

  const registerSubmitBtn = document.getElementById('register-submit-btn');
  if (registerSubmitBtn) {
    registerSubmitBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await register();
    });
  }

  const logoutLink = document.getElementById('logout-link');
  if (logoutLink) {
    logoutLink.addEventListener('click', async (e) => {
      e.preventDefault();
      stopAutoRefresh();
      await logout();
      shell.showHome();
    });
  }

  const pendingLogoutBtn = document.getElementById('pending-logout-btn');
  if (pendingLogoutBtn) {
    pendingLogoutBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      stopAutoRefresh();
      await logout();
      shell.showHome();
    });
  }

  const pendingCiAddMethodBtn = document.getElementById('pending-ci-add-method-btn');
  if (pendingCiAddMethodBtn) {
    pendingCiAddMethodBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { addPendingContactMethodRow } = await import('../ui/contact-info');
      addPendingContactMethodRow();
    });
  }

  const pendingCiSaveBtn = document.getElementById('pending-ci-save-btn');
  if (pendingCiSaveBtn) {
    pendingCiSaveBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { savePendingContactInfo } = await import('../ui/contact-info');
      await savePendingContactInfo();
    });
  }

  const pendingCiDeleteBtn = document.getElementById('pending-ci-delete-btn');
  if (pendingCiDeleteBtn) {
    pendingCiDeleteBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { deletePendingContactInfo } = await import('../ui/contact-info');
      await deletePendingContactInfo();
    });
  }

  setupPasswordTypeToggle();
  setupPasswordToggles();
}
