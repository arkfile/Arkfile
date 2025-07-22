/**
 * Main application entry point
 * Coordinates all modules and handles initial setup
 */

import { wasmManager } from './utils/wasm';
import { validateToken, isAuthenticated, clearAllSessionData } from './utils/auth';
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
      
      // Set up event listeners and UI handlers
      this.setupEventListeners();
      
      // Handle initial authentication state
      await this.handleInitialAuth();
      
      this.initialized = true;
      console.log('ArkFile TypeScript application initialized');
      
    } catch (error) {
      console.error('Failed to initialize ArkFile application:', error);
      showError('Application failed to initialize. Please refresh the page.');
    }
  }

  private setupEventListeners(): void {
    // Set up login and registration forms
    setupLoginForm();
    setupRegistrationForm();
    
    // Auth form toggle
    const toggleButton = document.querySelector('button[onclick="toggleAuthForm()"]');
    if (toggleButton) {
      toggleButton.addEventListener('click', (e) => {
        e.preventDefault();
        toggleAuthForm();
      });
    }

    // Logout button
    const logoutButton = document.querySelector('button[onclick="logout()"]');
    if (logoutButton) {
      logoutButton.addEventListener('click', async (e) => {
        e.preventDefault();
        await logout();
      });
    }

    // Security settings toggle
    const securityToggle = document.querySelector('button[onclick="toggleSecuritySettings()"]');
    if (securityToggle) {
      securityToggle.addEventListener('click', async (e) => {
        e.preventDefault();
        const { toggleSecuritySettings } = await import('./ui/sections');
        toggleSecuritySettings();
      });
    }

    // Revoke all sessions button
    const revokeButton = document.querySelector('button[onclick="revokeAllSessions()"]');
    if (revokeButton) {
      revokeButton.addEventListener('click', async (e) => {
        e.preventDefault();
        const { revokeAllSessions } = await import('./utils/auth');
        const success = await revokeAllSessions();
        if (success) {
          showSuccess('All sessions have been revoked. Please log in again.');
          clearAllSessionData();
          showAuthSection();
        } else {
          showError('Failed to revoke sessions.');
        }
      });
    }

    // File upload form setup (basic)
    const uploadForm = document.querySelector('form[onsubmit*="uploadFile"]');
    if (uploadForm) {
      uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        // Dynamically import upload functionality when needed
        const { uploadFile } = await import('./files/upload');
        await uploadFile();
      });
    }

    // Password type radio buttons
    this.setupPasswordTypeToggle();
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
          filePassword.value = ''; // Clear password field when switching to account password
        }
      });
    });
  }

  private async handleInitialAuth(): Promise<void> {
    if (isAuthenticated()) {
      try {
        // Validate the stored token by making an API call
        const tokenValid = await validateToken();
        
        if (tokenValid) {
          // Token is valid, show the file section and load files
          showFileSection();
          
          // Load files and display them
          const response = await loadFiles();
          
        } else {
          // Token is invalid, clear storage and show auth
          console.warn('Stored token is invalid, clearing and showing auth');
          clearAllSessionData();
          showAuthSection();
          showError('Your session has expired. Please log in again.');
        }
      } catch (error) {
        // Network error or other issue, clear storage and show auth
        console.error('Error validating token:', error);
        clearAllSessionData();
        showAuthSection();
      }
    } else {
      // No token, show auth section
      showAuthSection();
    }
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

// Export for legacy compatibility
if (typeof window !== 'undefined') {
  // Make key functions available globally for onclick handlers (temporary)
  (window as any).login = login;
  (window as any).register = register;
  (window as any).logout = logout;
  (window as any).toggleAuthForm = toggleAuthForm;
  (window as any).toggleSecuritySettings = async () => {
    const { toggleSecuritySettings } = await import('./ui/sections');
    toggleSecuritySettings();
  };
  (window as any).revokeAllSessions = async () => {
    const { revokeAllSessions } = await import('./utils/auth');
    const success = await revokeAllSessions();
    if (success) {
      showSuccess('All sessions have been revoked. Please log in again.');
      clearAllSessionData();
      showAuthSection();
    } else {
      showError('Failed to revoke sessions.');
    }
  };
}

// Export the app instance
export default app;
