/**
 * Registration functionality using multi-step OPAQUE protocol
 */

import { showError, showSuccess } from '../ui/messages.js';
import { showProgressMessage, hideProgress } from '../ui/progress.js';
import { getOpaqueClient, storeClientSecret, retrieveClientSecret, clearClientSecret } from '../crypto/opaque.js';
import { setTokens } from '../utils/auth.js';
import { showFileSection } from '../ui/sections.js';
import { loadFiles } from '../files/list.js';

export interface RegisterCredentials {
  username: string;
  password: string;
}

export interface RegistrationResponse {
  token: string;
  refresh_token: string;
  auth_method: 'OPAQUE';
}

export class RegistrationManager {
  /**
   * Register a new user using multi-step OPAQUE protocol
   */
  public static async register(credentials: RegisterCredentials): Promise<void> {
    if (!credentials.username || !credentials.password) {
      showError('Please enter both username and password.');
      return;
    }

    try {
      showProgressMessage('Creating account...');

      // Get OPAQUE client instance
      const opaqueClient = await getOpaqueClient();

      // Step 1: Start registration - create registration request
      const registrationInit = await opaqueClient.startRegistration({
        username: credentials.username,
        password: credentials.password
      });

      // Store client secret in sessionStorage for step 2
      storeClientSecret('registration_secret', registrationInit.clientSecret);

      // Send registration request to server
      const responseStep1 = await fetch('/api/opaque/register/response', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          registration_request: registrationInit.requestData
        })
      });

      if (!responseStep1.ok) {
        const errorData = await responseStep1.json().catch(() => ({ message: 'Registration failed' }));
        clearClientSecret('registration_secret');
        hideProgress();
        showError(errorData.message || 'Registration request failed');
        return;
      }

      const step1Data = await responseStep1.json();

      // Step 2: Finalize registration - process server response
      const clientSecret = retrieveClientSecret('registration_secret');
      if (!clientSecret) {
        hideProgress();
        showError('Registration session expired. Please try again.');
        return;
      }

      const registrationFinalize = await opaqueClient.finalizeRegistration({
        username: credentials.username,
        serverResponse: step1Data.registration_response,
        clientSecret: clientSecret
      });

      // Clear client secret from sessionStorage
      clearClientSecret('registration_secret');

      // Send finalized registration record to server
      const responseStep2 = await fetch('/api/opaque/register/finalize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: credentials.username,
          registration_record: registrationFinalize.record
        })
      });

      if (!responseStep2.ok) {
        const errorData = await responseStep2.json().catch(() => ({ message: 'Registration failed' }));
        hideProgress();
        showError(errorData.message || 'Registration finalization failed');
        return;
      }

      const registrationData = await responseStep2.json();

      // Discard export key immediately (not needed for this application)
      // JWT tokens handle all session management
      if (registrationFinalize.exportKey) {
        registrationFinalize.exportKey.fill(0);
      }

      // Complete registration with tokens
      await this.completeRegistration({
        token: registrationData.token,
        refresh_token: registrationData.refresh_token,
        auth_method: 'OPAQUE'
      }, credentials.username);

    } catch (error) {
      // Clean up on error
      clearClientSecret('registration_secret');
      hideProgress();
      console.error('Registration error:', error);
      showError('Registration failed. Please try again.');
    }
  }

  /**
   * Complete registration after successful OPAQUE protocol
   */
  private static async completeRegistration(data: RegistrationResponse, username: string): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refresh_token);

      hideProgress();
      showSuccess('Registration successful! Welcome to Arkfile.');

      // Navigate to file section and load files
      showFileSection();
      await loadFiles();

    } catch (error) {
      hideProgress();
      console.error('Registration completion error:', error);
      showError('Failed to complete registration');
    }
  }
}

/**
 * Setup registration form event listeners
 */
export function setupRegisterForm(): void {
  const registerForm = document.getElementById('register-form');
  if (!registerForm) return;

  const usernameInput = document.getElementById('register-username') as HTMLInputElement;
  const passwordInput = document.getElementById('register-password') as HTMLInputElement;
  const confirmPasswordInput = document.getElementById('register-password-confirm') as HTMLInputElement;
  const submitButton = registerForm.querySelector('button[type="submit"]') as HTMLButtonElement;

  if (!usernameInput || !passwordInput || !confirmPasswordInput || !submitButton) return;

  // Handle form submission
  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // Validate passwords match
    if (password !== confirmPassword) {
      showError('Passwords do not match.');
      return;
    }

    // Validate password strength (basic check - server will do full validation)
    if (password.length < 14) {
      showError('Password must be at least 14 characters long.');
      return;
    }

    const credentials: RegisterCredentials = {
      username,
      password
    };

    await RegistrationManager.register(credentials);
  };

  // Add event listeners
  registerForm.addEventListener('submit', handleSubmit);

  // Handle Enter key in form fields
  [usernameInput, passwordInput, confirmPasswordInput].forEach(input => {
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleSubmit(e);
      }
    });
  });

  // Clear any previous error states when user starts typing
  [usernameInput, passwordInput, confirmPasswordInput].forEach(input => {
    input.addEventListener('input', () => {
      input.classList.remove('error');
    });
  });

  // Password strength indicator (optional enhancement)
  passwordInput.addEventListener('input', () => {
    updatePasswordStrength(passwordInput.value);
  });
}

/**
 * Update password strength indicator
 */
function updatePasswordStrength(password: string): void {
  const strengthMeter = document.getElementById('password-strength');
  if (!strengthMeter) return;

  let strength = 0;
  
  // Check length
  if (password.length >= 14) strength++;
  if (password.length >= 20) strength++;
  
  // Check character types
  if (/[a-z]/.test(password)) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^a-zA-Z0-9]/.test(password)) strength++;

  // Update meter
  const percentage = Math.min((strength / 6) * 100, 100);
  strengthMeter.style.width = `${percentage}%`;

  // Update color
  if (strength < 3) {
    strengthMeter.style.backgroundColor = '#dc3545'; // red
  } else if (strength < 5) {
    strengthMeter.style.backgroundColor = '#ffc107'; // yellow
  } else {
    strengthMeter.style.backgroundColor = '#28a745'; // green
  }
}

/**
 * Export utility function for compatibility
 */
export async function register(): Promise<void> {
  const usernameInput = document.getElementById('register-username') as HTMLInputElement;
  const passwordInput = document.getElementById('register-password') as HTMLInputElement;
  const confirmPasswordInput = document.getElementById('register-password-confirm') as HTMLInputElement;

  if (!usernameInput || !passwordInput || !confirmPasswordInput) {
    showError('Registration form not found.');
    return;
  }

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  // Validate passwords match
  if (password !== confirmPassword) {
    showError('Passwords do not match.');
    return;
  }

  const credentials: RegisterCredentials = {
    username,
    password
  };

  await RegistrationManager.register(credentials);
}
