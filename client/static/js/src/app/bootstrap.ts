import {
  validateToken,
  isAuthenticated,
  clearAllSessionData,
  startAutoRefresh,
  refreshToken,
} from '../utils/auth';
import { registerAccountKeyCleanupHandlers } from '../crypto/account-key-cache';
import { initSitewideFooters } from '../ui/footer';
import { showError } from '../ui/messages';
import { showFileSection, showAuthSection } from '../ui/sections';
import { registerSwDownload } from '../files/sw-streaming-download';
import { setupHomePageListeners } from './home-listeners';
import type { AppShell } from './shell';

async function checkServiceReady(): Promise<boolean> {
  try {
    const response = await fetch('/readyz');
    return response.ok;
  } catch {
    return false;
  }
}

async function resumeBillingCheckouts(): Promise<void> {
  const { resumePendingBillingCheckout, resumePendingSubscriptionCheckout } = await import('../ui/billing');
  await resumePendingBillingCheckout();
  await resumePendingSubscriptionCheckout();
}

async function enterAuthenticatedApp(shell: AppShell): Promise<void> {
  shell.showApp();
  showFileSection();
  startAutoRefresh();
  await shell.loadUserFiles();
  await resumeBillingCheckouts();
}

/**
 * Initial auth routing when the main app shell is already visible (not the marketing home).
 */
export async function handleInitialAuth(shell: AppShell): Promise<void> {
  if (isAuthenticated()) {
    try {
      const tokenValid = await validateToken();

      if (tokenValid) {
        const { getCurrentUser } = await import('../utils/auth.js');
        const currentUser = await getCurrentUser();
        if (currentUser && !currentUser.is_approved) {
          const { showPendingApprovalSection } = await import('../ui/sections.js');
          showPendingApprovalSection();
        } else {
          showFileSection();
          startAutoRefresh();
          await shell.loadUserFiles();
          await resumeBillingCheckouts();
        }
      } else {
        const refreshed = await refreshToken();
        if (refreshed && (await validateToken())) {
          const { getCurrentUser } = await import('../utils/auth.js');
          const currentUser = await getCurrentUser();
          if (currentUser && !currentUser.is_approved) {
            const { showPendingApprovalSection } = await import('../ui/sections.js');
            showPendingApprovalSection();
          } else {
            showFileSection();
            startAutoRefresh();
            await shell.loadUserFiles();
            await resumeBillingCheckouts();
          }
        } else {
          console.warn('Stored token is invalid, clearing and showing auth');
          clearAllSessionData();
          showAuthSection();
          showError('Your session has expired (30 minutes). Please log in again.');
        }
      }
    } catch (error) {
      console.error('Error validating token:', error);
      clearAllSessionData();
      showAuthSection();
    }
  } else {
    showAuthSection();
  }
}

/**
 * Full application bootstrap: readiness, SW, billing return params, home vs app routing.
 * Returns true when initialization completed (listeners/routing done); false if aborted early.
 */
export async function bootstrapApplication(shell: AppShell): Promise<boolean> {
  try {
    registerAccountKeyCleanupHandlers();

    const ready = await checkServiceReady();
    if (!ready) {
      showError('Service is starting up. Please refresh the page in a moment.');
      return false;
    }

    registerSwDownload().then((ok) => {
      if (ok) {
        console.log('[arkfile] SW streaming download ready');
      } else {
        console.warn('[arkfile] SW streaming unavailable; large file downloads (>2 GB) may fail on Chromium');
      }
    }).catch((err) => {
      console.warn('[arkfile] SW registration error:', err);
    });

    const {
      hasBillingCheckoutReturnParams,
      captureBillingCheckoutParams,
    } = await import('../ui/billing');

    if (hasBillingCheckoutReturnParams()) {
      captureBillingCheckoutParams();
    }

    if (shell.isHomePage()) {
      setupHomePageListeners(shell);

      if (isAuthenticated()) {
        const tokenValid = await validateToken();
        if (tokenValid) {
          await enterAuthenticatedApp(shell);
        } else {
          await refreshToken();
          if (await validateToken()) {
            await enterAuthenticatedApp(shell);
          }
        }
      } else if (captureBillingCheckoutParams()) {
        await refreshToken();
        if (await validateToken()) {
          await enterAuthenticatedApp(shell);
        }
      }
    } else {
      shell.setupAppListeners();
      await handleInitialAuth(shell);
    }

    console.log('ArkFile TypeScript application initialized');
    void initSitewideFooters();
    return true;
  } catch (error) {
    console.error('Failed to initialize ArkFile application:', error);
    showError('Application failed to initialize. Please refresh the page.');
    return false;
  }
}
