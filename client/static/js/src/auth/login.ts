/**
 * Login functionality
 */

import { wasmManager } from '../utils/wasm';
import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { setTokens, getUserEmailFromToken, clearAllSessionData } from '../utils/auth';
import { showFileSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { handleTOTPFlow } from './totp';

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
  authMethod: 'OPAQUE';
  requiresTOTP?: boolean;
  partialToken?: string;
}

export class LoginManager {
  public static async login(credentials: LoginCredentials): Promise<void> {
    if (!credentials.email || !credentials.password) {
      showError('Please enter both email and password.');
      return;
    }

    try {
      // Ensure WASM is ready
      await wasmManager.ensureReady();

      // Check OPAQUE health first
      const healthCheck = await wasmManager.checkOpaqueHealth();
      if (!healthCheck.wasmReady) {
        showError('Authentication system not ready. Please try again in a few moments.');
        return;
      }

      showProgressMessage('Authenticating...');

      // Direct call to server OPAQUE endpoint
      const response = await fetch('/api/opaque/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: credentials.email,
          password: credentials.password
        }),
      });

      if (response.ok) {
        const data: LoginResponse = await response.json();
        
        // Handle TOTP if required
        if (data.requiresTOTP) {
          hideProgress();
          handleTOTPFlow({
            partialToken: data.partialToken!,
            email: credentials.email
          });
          return;
        }
        
        // Complete authentication
        await this.completeLogin(data, credentials.email);
        
      } else {
        hideProgress();
        const errorData = await response.json().catch(() => ({}));
        showError(errorData.message || 'Login failed');
      }
    } catch (error) {
      hideProgress();
      console.error('Login error:', error);
      showError('Authentication failed');
    }
  }

  public static async completeLogin(data: LoginResponse, email: string): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refreshToken);
      
      // Create secure session in WASM (NEVER store session key in JavaScript)
      const sessionResult = await wasmManager.createSecureSession(data.sessionKey, email);
      if (!sessionResult.success) {
        hideProgress();
        showError('Failed to create secure session: ' + sessionResult.error);
        return;
      }
      
      hideProgress();
      showSuccess('Login successful');
      
      // Navigate to file section and load files
      showFileSection();
      await loadFiles();
      
    } catch (error) {
      hideProgress();
      console.error('Login completion error:', error);
      showError('Failed to complete login');
    }
  }

  public static async logout(): Promise<void> {
    try {
      // Get user email for secure session cleanup
      const userEmail = getUserEmailFromToken();
      
      // Clear secure session from WASM memory
      if (userEmail) {
        await wasmManager.clearSecureSession(userEmail);
      }
      
      // Use auth manager to handle token cleanup and API call
      const { logout } = await import('../utils/auth');
      await logout();
      
      // Clear all session data
      clearAllSessionData();
      
      // Navigate back to auth section
      const { showAuthSection } = await import('../ui/sections');
      showAuthSection();
      
      showSuccess('Logged out successfully.');
    } catch (error) {
      console.error('Logout error:', error);
      
      // Still attempt cleanup even on error
      const userEmail = getUserEmailFromToken();
      if (userEmail) {
        try {
          await wasmManager.clearSecureSession(userEmail);
        } catch (e) {
          console.warn('Failed to clear secure session on logout error:', e);
        }
      }
      
      clearAllSessionData();
      
      const { showAuthSection } = await import('../ui/sections');
      showAuthSection();
    }
  }
}

// Form handling utilities
export function setupLoginForm(): void {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;

  const emailInput = document.getElementById('login-email') as HTMLInputElement;
  const passwordInput = document.getElementById('login-password') as HTMLInputElement;
  const submitButton = loginForm.querySelector('button[type="submit"]') as HTMLButtonElement;

  if (!emailInput || !passwordInput || !submitButton) return;

  // Handle form submission
  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    
    const credentials: LoginCredentials = {
      email: emailInput.value.trim(),
      password: passwordInput.value
    };

    await LoginManager.login(credentials);
  };

  // Add event listeners
  loginForm.addEventListener('submit', handleSubmit);
  
  // Handle Enter key in form fields
  [emailInput, passwordInput].forEach(input => {
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleSubmit(e);
      }
    });
  });

  // Clear any previous error states when user starts typing
  [emailInput, passwordInput].forEach(input => {
    input.addEventListener('input', () => {
      input.classList.remove('error');
    });
  });
}

// Export utility functions for compatibility
export async function login(): Promise<void> {
  const emailInput = document.getElementById('login-email') as HTMLInputElement;
  const passwordInput = document.getElementById('login-password') as HTMLInputElement;
  
  if (!emailInput || !passwordInput) {
    showError('Login form not found.');
    return;
  }

  const credentials: LoginCredentials = {
    email: emailInput.value.trim(),
    password: passwordInput.value
  };

  await LoginManager.login(credentials);
}

export async function logout(): Promise<void> {
  await LoginManager.logout();
}
