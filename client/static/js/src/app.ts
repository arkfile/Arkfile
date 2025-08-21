/**
 * Main application entry point
 * Coordinates all modules and handles initial setup
 * Updated for new home page with proper event listeners
 */

import { wasmManager } from './utils/wasm';
import { validateToken, isAuthenticated, clearAllSessionData } from './utils/auth-wasm';
import { showError, showSuccess } from './ui/messages';
import { showFileSection, showAuthSection, toggleAuthForm } from './ui/sections';
import { loadFiles, displayFiles } from './files/list';
import { setupLoginForm, login, logout } from './auth/login';
import { setupRegistrationForm, register } from './auth/register';

class ArkFileApp {
  private initialized = false;

  public async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Initialize WASM first
      await wasmManager.initWasm();
      
      // Check if we're on the home page or app page
      if (this.isHomePage()) {
        this.setupHomePageListeners();
        
        // Check if user is already authenticated
        if (isAuthenticated()) {
          const tokenValid = await validateToken();
          if (tokenValid) {
            // User is logged in, show app directly
            this.showApp();
            showFileSection();
            await this.loadUserFiles();
          }
        }
      } else {
        // We're in the app interface
        this.setupAppListeners();
        await this.handleInitialAuth();
      }
      
      this.initialized = true;
      console.log('ArkFile TypeScript application initialized');
      
    } catch (error) {
      console.error('Failed to initialize ArkFile application:', error);
      showError('Application failed to initialize. Please refresh the page.');
    }
  }

  private isHomePage(): boolean {
    // Check if we're showing the home page (hero section visible)
    const heroSection = document.querySelector('.hero-section');
    return heroSection !== null && !heroSection.classList.contains('hidden');
  }

  private setupHomePageListeners(): void {
    // Get Started button - shows registration form
    const getStartedBtn = document.getElementById('get-started-btn');
    if (getStartedBtn) {
      getStartedBtn.addEventListener('click', () => {
        this.showApp();
        showAuthSection();
        toggleAuthForm(); // Switch to register form
      });
    }

    // Login button - shows login form
    const loginBtn = document.getElementById('login-btn');
    if (loginBtn) {
      loginBtn.addEventListener('click', () => {
        this.showApp();
        showAuthSection();
        // Login form is shown by default
      });
    }
  }

  private setupAppListeners(): void {
    // Set up login and registration forms
    setupLoginForm();
    setupRegistrationForm();
    
    // Navigation between login and register
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
      });
    }

    // Back to home links
    const backToHomeLink = document.getElementById('back-to-home-link');
    if (backToHomeLink) {
      backToHomeLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.showHome();
      });
    }

    const backToHomeFromRegisterLink = document.getElementById('back-to-home-from-register-link');
    if (backToHomeFromRegisterLink) {
      backToHomeFromRegisterLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.showHome();
      });
    }

    // Login form submission
    const loginSubmitBtn = document.getElementById('login-submit-btn');
    if (loginSubmitBtn) {
      loginSubmitBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        await login();
      });
    }

    // Register form submission
    const registerSubmitBtn = document.getElementById('register-submit-btn');
    if (registerSubmitBtn) {
      registerSubmitBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        await register();
      });
    }

    // Logout functionality
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
      logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        await logout();
        this.showHome(); // Return to home page after logout
      });
    }

    // Security settings toggle
    const securityToggle = document.getElementById('security-settings-toggle');
    if (securityToggle) {
      securityToggle.addEventListener('click', async (e) => {
        e.preventDefault();
        const { toggleSecuritySettings } = await import('./ui/sections');
        toggleSecuritySettings();
      });
    }

    // Revoke all sessions
    const revokeButton = document.getElementById('revoke-sessions-btn');
    if (revokeButton) {
      revokeButton.addEventListener('click', async (e) => {
        e.preventDefault();
        const { revokeAllSessions } = await import('./utils/auth-wasm');
        const success = await revokeAllSessions();
        if (success) {
          showSuccess('All sessions have been revoked. Please log in again.');
          clearAllSessionData();
          this.showHome(); // Return to home page
        } else {
          showError('Failed to revoke sessions.');
        }
      });
    }

    // File upload functionality
    const uploadFileBtn = document.getElementById('upload-file-btn');
    if (uploadFileBtn) {
      uploadFileBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        const { uploadFile } = await import('./files/upload');
        await uploadFile();
      });
    }

    // Password type toggle
    this.setupPasswordTypeToggle();

    // TOTP setup functionality
    this.setupTOTPListeners();
  }

  private setupPasswordTypeToggle(): void {
    const passwordTypeRadios = document.querySelectorAll('input[name="passwordType"]');
    const customPasswordSection = document.getElementById('customPasswordSection');
    const filePassword = document.getElementById('filePassword') as HTMLInputElement;
    
    passwordTypeRadios.forEach(radio => {
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

  private setupTOTPListeners(): void {
    // TOTP generation
    const generateTOTPBtn = document.getElementById('generate-totp-btn');
    if (generateTOTPBtn) {
      generateTOTPBtn.addEventListener('click', async () => {
        const { initiateTOTPSetup } = await import('./auth/totp');
        // This needs to be called with proper session context
        console.log('TOTP setup initiated');
      });
    }

    // TOTP verification
    const verifyTOTPBtn = document.getElementById('verify-totp-btn');
    if (verifyTOTPBtn) {
      verifyTOTPBtn.addEventListener('click', async () => {
        const { completeTOTPSetup } = await import('./auth/totp');
        // This needs proper implementation
        console.log('TOTP verification attempted');
      });
    }

    // Cancel registration
    const cancelRegistrationBtn = document.getElementById('cancel-registration-btn');
    if (cancelRegistrationBtn) {
      cancelRegistrationBtn.addEventListener('click', () => {
        showAuthSection();
        toggleAuthForm(); // Switch back to login
      });
    }

    // Download backup codes
    const downloadBackupCodesBtn = document.getElementById('download-backup-codes-btn');
    if (downloadBackupCodesBtn) {
      downloadBackupCodesBtn.addEventListener('click', () => {
        console.log('Download backup codes functionality needs implementation');
      });
    }
  }

  private showHome(): void {
    // Hide app container and show home page
    const homeContainer = document.querySelector('.home-container');
    const appContainer = document.getElementById('app-container');
    
    if (homeContainer) {
      homeContainer.classList.remove('hidden');
    }
    if (appContainer) {
      appContainer.classList.add('hidden');
    }
  }

  private showApp(): void {
    // Hide home page and show app container
    const homeContainer = document.querySelector('.home-container');
    const appContainer = document.getElementById('app-container');
    
    if (homeContainer) {
      homeContainer.classList.add('hidden');
    }
    if (appContainer) {
      appContainer.classList.remove('hidden');
    }
    
    // Set up app listeners if not already done
    if (!this.isHomePage()) {
      this.setupAppListeners();
    }
  }

  private async handleInitialAuth(): Promise<void> {
    if (isAuthenticated()) {
      try {
        // Validate the stored token
        const tokenValid = await validateToken();
        
        if (tokenValid) {
          // Token is valid, show file section and load files
          showFileSection();
          await this.loadUserFiles();
        } else {
          // Token is invalid, clear storage and show auth
          console.warn('Stored token is invalid, clearing and showing auth');
          clearAllSessionData();
          showAuthSection();
          showError('Your session has expired (30 minutes). Please log in again.');
        }
      } catch (error) {
        // Network error or other issue
        console.error('Error validating token:', error);
        clearAllSessionData();
        showAuthSection();
      }
    } else {
      // No token, show auth section
      showAuthSection();
    }
  }

  private async loadUserFiles(): Promise<void> {
    try {
      const response = await loadFiles();
      // Files will be displayed by the loadFiles function
    } catch (error) {
      console.error('Error loading user files:', error);
      showError('Failed to load your files. Please refresh the page.');
    }
  }

  // Public method to show app from home page
  public navigateToApp(): void {
    this.showApp();
  }

  // Public method to return to home page
  public navigateToHome(): void {
    this.showHome();
  }
}

// Global app instance
const app = new ArkFileApp();

// Initialize app when DOM is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    app.initialize();
  });
} else {
  // DOM already loaded
  app.initialize();
}

// Export for global access
if (typeof window !== 'undefined') {
  (window as any).arkfileApp = app;
}

// Export the app instance
export default app;
