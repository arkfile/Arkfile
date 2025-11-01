/**
 * Registration functionality
 */

import { wasmManager } from '../utils/wasm';
import { showError, showSuccess } from '../ui/messages';
import { showProgressMessage, hideProgress } from '../ui/progress';
import { setTokens } from '../utils/auth-wasm';
import { showFileSection } from '../ui/sections';
import { loadFiles } from '../files/list';
import { ShareCrypto } from '../shares/share-crypto.js';
import { addPasswordToggle } from '../utils/password-toggle';

export interface RegistrationCredentials {
  username: string;
  password: string;
  confirmPassword: string;
}

export interface RegistrationResponse {
  token: string;
  refresh_token: string;
  session_key: string;
  auth_method: 'OPAQUE';
  message: string;
}

export class RegistrationManager {
  public static async register(credentials: RegistrationCredentials): Promise<void> {
    // Validate inputs
    if (!this.validateRegistrationInputs(credentials)) {
      return;
    }

    try {
      // Ensure WASM is ready
      await wasmManager.ensureReady();

      showProgressMessage('Creating account...');

      // Validate password complexity using WASM
      const passwordValidation = await wasmManager.validatePasswordComplexity(credentials.password);
      if (!passwordValidation.valid) {
        hideProgress();
        
        // Build detailed error message
        let errorMessage = 'Password does not meet requirements:\n';
        const reqs = passwordValidation.requirements;
        
        if (reqs) {
          if (reqs.length && !reqs.length.met) {
            errorMessage += `\n• ${reqs.length.message}`;
          }
          if (reqs.uppercase && !reqs.uppercase.met) {
            errorMessage += `\n• ${reqs.uppercase.message}`;
          }
          if (reqs.lowercase && !reqs.lowercase.met) {
            errorMessage += `\n• ${reqs.lowercase.message}`;
          }
          if (reqs.number && !reqs.number.met) {
            errorMessage += `\n• ${reqs.number.message}`;
          }
          if (reqs.special && !reqs.special.met) {
            errorMessage += `\n• ${reqs.special.message}`;
          }
        }
        
        // Add entropy information if available
        if (passwordValidation.entropy !== undefined) {
          const requirements = await wasmManager.getPasswordRequirements('account');
          const minEntropy = requirements.minEntropy;
          errorMessage += `\n\nCurrent entropy: ${Math.floor(passwordValidation.entropy)} bits`;
          errorMessage += `\nRequired entropy: ${minEntropy} bits`;
          
          // Add specific feedback if available
          if (passwordValidation.feedback && Array.isArray(passwordValidation.feedback) && passwordValidation.feedback.length > 0) {
            errorMessage += `\n\nSuggestions:`;
            passwordValidation.feedback.forEach(fb => {
              errorMessage += `\n• ${fb}`;
            });
          }
        }
        
        showError(errorMessage);
        this.highlightPasswordRequirements(passwordValidation.requirements);
        return;
      }

      // Validate password confirmation using WASM
      const confirmationValidation = await wasmManager.validatePasswordConfirmation(
        credentials.password,
        credentials.confirmPassword
      );
      if (!confirmationValidation.match) {
        hideProgress();
        showError(confirmationValidation.message);
        return;
      }

      // Use WASM to perform OPAQUE registration (matches CLI flow)
      const result = await wasmManager.performOpaqueRegister(
        credentials.username,
        credentials.password
      );

      if (!result.success || !result.promise) {
        hideProgress();
        showError(result.error || 'Failed to initiate registration');
        return;
      }

      // Handle the response promise
      const response = await result.promise;

      if (response.ok) {
        const data: RegistrationResponse = await response.json();
        await this.completeRegistration(data, credentials.username);
      } else {
        hideProgress();
        const errorData = await response.json().catch(() => ({}));
        showError(errorData.message || 'Registration failed');
      }
    } catch (error) {
      hideProgress();
      console.error('Registration error:', error);
      showError('Registration failed. Please try again.');
    }
  }

  private static validateRegistrationInputs(credentials: RegistrationCredentials): boolean {
    if (!credentials.username || !credentials.password || !credentials.confirmPassword) {
      showError('Please fill in all required fields.');
      return false;
    }

    // Basic username validation
    const usernameRegex = /^[a-zA-Z0-9._-]+$/;
    if (!usernameRegex.test(credentials.username)) {
      showError('Username can only contain letters, numbers, dots, dashes, and underscores.');
      return false;
    }

    if (credentials.username.length < 3 || credentials.username.length > 32) {
      showError('Username must be between 3 and 32 characters.');
      return false;
    }

    return true;
  }

  private static highlightPasswordRequirements(requirements: any): void {
    this.updatePasswordRequirementsDisplay(requirements);
  }

  public static async updatePasswordRequirementsDisplay(requirements: any, entropy?: number, patternWarning?: string): Promise<void> {
    const requirementsList = document.querySelector('.requirements-list');
    if (!requirementsList) return;
    
    const items = requirementsList.querySelectorAll('li');
    
    // Get minimum entropy requirement from WASM
    const passwordReqs = await wasmManager.getPasswordRequirements('account');
    const minEntropy = passwordReqs.minEntropy;
    
    // Map requirement IDs to list items (order matches HTML)
    const requirementMap: { [key: string]: HTMLElement | null } = {
      length: items[0] as HTMLElement,
      uppercase: items[1] as HTMLElement,
      lowercase: items[2] as HTMLElement,
      number: items[3] as HTMLElement,
      special: items[4] as HTMLElement,
      entropy: items[5] as HTMLElement,
    };

    // Update each requirement based on its status with [OK]/[ ] markers
    Object.keys(requirementMap).forEach(key => {
      const item = requirementMap[key];
      if (!item) return;
      
      // Special handling for entropy requirement
      if (key === 'entropy') {
        item.classList.remove('met', 'missing');
        if (entropy !== undefined) {
          const entropyMet = entropy >= minEntropy;
          if (entropyMet) {
            item.classList.add('met');
            item.textContent = `[OK] Minimum entropy: ${minEntropy} bits (current: ${Math.floor(entropy)} bits)`;
          } else {
            item.classList.add('missing');
            item.textContent = `[ ] Minimum entropy: ${minEntropy} bits (current: ${Math.floor(entropy)} bits)`;
          }
        } else {
          item.textContent = `[ ] Minimum entropy: ${minEntropy} bits`;
        }
        return;
      }
      
      // Handle other requirements
      if (!requirements[key]) return;
      const req = requirements[key];
      
      // Remove existing classes
      item.classList.remove('met', 'missing');
      
      // Add appropriate class based on status
      if (req.met) {
        item.classList.add('met');
        item.textContent = `[OK] ${req.message}`;
      } else {
        item.classList.add('missing');
        item.textContent = `[ ] ${req.message}`;
      }
    });

    // Update entropy display if provided
    if (entropy !== undefined) {
      const strengthMeter = document.getElementById('register-password-strength');
      if (strengthMeter) {
        const entropyBits = Math.floor(entropy);
        strengthMeter.textContent = `Entropy: ${entropyBits} bits`;
        
        // Get minimum entropy requirement from WASM
        const passwordReqs = await wasmManager.getPasswordRequirements('account');
        const minEntropy = passwordReqs.minEntropy;
        
        // Color code based on entropy relative to minimum
        strengthMeter.className = 'strength-meter';
        if (entropyBits >= minEntropy) {
          strengthMeter.classList.add('strong');
        } else if (entropyBits >= minEntropy * 0.67) {
          strengthMeter.classList.add('fair');
        } else {
          strengthMeter.classList.add('weak');
        }
      }
    }

    // Display pattern warning if provided
    if (patternWarning) {
      const strengthMeter = document.getElementById('register-password-strength');
      if (strengthMeter) {
        const warningDiv = document.createElement('div');
        warningDiv.className = 'pattern-warning';
        warningDiv.textContent = patternWarning;
        strengthMeter.appendChild(warningDiv);
      }
    }
  }

  private static async completeRegistration(data: RegistrationResponse, username: string): Promise<void> {
    try {
      // Store authentication tokens
      setTokens(data.token, data.refresh_token);

      // Create secure session in WASM (NEVER store session key in JavaScript)
      const sessionResult = await wasmManager.createSecureSessionFromKey(data.session_key, username);
      if (!sessionResult.success) {
        hideProgress();
        showError('Failed to create secure session: ' + sessionResult.error);
        return;
      }
      
      hideProgress();
      showSuccess('Registration successful! Welcome to ArkFile.');
      
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

// Form handling utilities
export function setupRegistrationForm(): void {
  console.log('[Registration] Setting up registration form...');
  const registerForm = document.getElementById('register-form');
  if (!registerForm) {
    console.warn('[Registration] register-form not found');
    return;
  }

  const usernameInput = document.getElementById('register-username') as HTMLInputElement;
  const passwordInput = document.getElementById('register-password') as HTMLInputElement;
  const confirmPasswordInput = document.getElementById('register-password-confirm') as HTMLInputElement;
  const submitButton = document.getElementById('register-submit-btn') as HTMLButtonElement;

  if (!usernameInput || !passwordInput || !confirmPasswordInput || !submitButton) {
    console.warn('[Registration] Missing form elements:', {
      username: !!usernameInput,
      password: !!passwordInput,
      confirmPassword: !!confirmPasswordInput,
      submit: !!submitButton
    });
    return;
  }
  
  console.log('[Registration] All form elements found, attaching listeners...');

  // Handle form submission
  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    
    const credentials: RegistrationCredentials = {
      username: usernameInput.value.trim(),
      password: passwordInput.value,
      confirmPassword: confirmPasswordInput.value
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

  // Real-time password validation
  passwordInput.addEventListener('input', async () => {
    console.log('[Registration] Password input event fired, length:', passwordInput.value.length);
    if (passwordInput.value.length > 0) {
      await validatePasswordRealTime(passwordInput.value);
    }
  });
  console.log('[Registration] Password input listener attached');

  // Real-time password confirmation validation
  confirmPasswordInput.addEventListener('input', async () => {
    console.log('[Registration] Confirm password input event fired');
    if (confirmPasswordInput.value.length > 0 && passwordInput.value.length > 0) {
      await validatePasswordConfirmationRealTime(passwordInput.value, confirmPasswordInput.value);
    }
  });
  console.log('[Registration] Confirm password input listener attached');

  // Update password placeholder with actual requirements from Go constants
  ShareCrypto.updatePasswordPlaceholder(passwordInput, 'account');
  
  // Add password visibility toggles
  addPasswordToggle(passwordInput);
  addPasswordToggle(confirmPasswordInput);
}

// Real-time validation functions
async function validatePasswordRealTime(password: string): Promise<void> {
  console.log('[Registration] validatePasswordRealTime called with password length:', password.length);
  try {
    await wasmManager.ensureReady();
    console.log('[Registration] WASM ready');
    
    // Get password requirements from WASM
    const requirements = await wasmManager.getPasswordRequirements('account');
    console.log('[Registration] Password requirements:', requirements);
    if (!requirements || requirements.error) {
      console.warn('[Registration] Failed to get password requirements:', requirements?.error);
      return;
    }
    
    const minEntropy = requirements.minEntropy;
    console.log('[Registration] Min entropy required:', minEntropy);
    
    const validation = await wasmManager.validatePasswordComplexity(password);
    console.log('[Registration] Password validation result:', validation);
    
    const passwordInput = document.getElementById('register-password') as HTMLInputElement;
    
    if (validation.valid) {
      passwordInput.classList.remove('error');
      passwordInput.classList.add('valid');
    } else {
      passwordInput.classList.remove('valid');
      passwordInput.classList.add('error');
    }

    // Generate pattern warning if all requirements met but entropy too low
    let patternWarning = '';
    if (validation.requirements && validation.entropy !== undefined) {
      const allRequirementsMet = 
        validation.requirements.length?.met &&
        validation.requirements.uppercase?.met &&
        validation.requirements.lowercase?.met &&
        validation.requirements.number?.met &&
        validation.requirements.special?.met;
      
      if (allRequirementsMet && validation.entropy < minEntropy) {
        // Check feedback for pattern issues
        if (validation.feedback && Array.isArray(validation.feedback)) {
          const feedbackStr = validation.feedback.join(' ').toLowerCase();
          if (feedbackStr.includes('dictionary')) {
            patternWarning = 'Entropy too low; consider fewer dictionary words';
          } else if (feedbackStr.includes('keyboard') || feedbackStr.includes('spatial')) {
            patternWarning = 'Entropy too low; avoid keyboard patterns';
          } else if (feedbackStr.includes('repeat') || feedbackStr.includes('sequential')) {
            patternWarning = 'Entropy too low; add more variety';
          } else {
            patternWarning = 'Entropy too low; add more varied characters';
          }
        }
      }
    }

    // Update requirements display with entropy and pattern warning
    if (validation.requirements) {
      RegistrationManager.updatePasswordRequirementsDisplay(
        validation.requirements,
        validation.entropy,
        patternWarning
      );
    }
  } catch (error) {
    console.warn('Real-time password validation error:', error);
  }
}

async function validatePasswordConfirmationRealTime(password: string, confirmation: string): Promise<void> {
  try {
    await wasmManager.ensureReady();
    const validation = await wasmManager.validatePasswordConfirmation(password, confirmation);
    
    const confirmInput = document.getElementById('register-password-confirm') as HTMLInputElement;
    const matchStatus = document.getElementById('password-match-status');
    
    if (confirmInput) {
      if (validation.match) {
        confirmInput.classList.remove('error');
        confirmInput.classList.add('valid');
      } else {
        confirmInput.classList.remove('valid');
        confirmInput.classList.add('error');
      }
    }
    
    // Update match status indicator
    if (matchStatus) {
      matchStatus.className = 'match-status';
      if (confirmation.length === 0) {
        matchStatus.classList.add('empty');
        matchStatus.textContent = 'Please confirm your password';
      } else if (validation.match) {
        matchStatus.classList.add('matching');
        matchStatus.textContent = 'Passwords match';
      } else {
        matchStatus.classList.add('not-matching');
        matchStatus.textContent = 'Passwords do not match';
      }
    }
  } catch (error) {
    console.warn('Real-time password confirmation validation error:', error);
  }
}

// Export utility functions for compatibility
export async function register(): Promise<void> {
  const usernameInput = document.getElementById('register-username') as HTMLInputElement;
  const passwordInput = document.getElementById('register-password') as HTMLInputElement;
  const confirmPasswordInput = document.getElementById('register-password-confirm') as HTMLInputElement;
  
  if (!usernameInput || !passwordInput || !confirmPasswordInput) {
    showError('Registration form not found.');
    return;
  }

  const credentials: RegistrationCredentials = {
    username: usernameInput.value.trim(),
    password: passwordInput.value,
    confirmPassword: confirmPasswordInput.value
  };

  await RegistrationManager.register(credentials);
}
