import { showAuthSection, toggleAuthForm } from '../ui/sections';
import { setupLoginForm } from '../auth/login';
import type { AppShell } from './shell';

/** Wire home-page CTA buttons into the auth forms. */
export function setupHomePageListeners(shell: AppShell): void {
  const getStartedBtn = document.getElementById('get-started-btn');
  if (getStartedBtn) {
    getStartedBtn.addEventListener('click', () => {
      shell.showApp();
      showAuthSection();
      toggleAuthForm(); // Switch to register form
    });
  }

  const loginBtn = document.getElementById('login-btn');
  if (loginBtn) {
    loginBtn.addEventListener('click', () => {
      shell.showApp();
      showAuthSection();
      setupLoginForm();
    });
  }
}
