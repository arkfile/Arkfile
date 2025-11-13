/**
 * Password Validation Module
 * 
 * Provides client-side password validation using zxcvbn library.
 * Matches the Go backend validation logic for consistent UX.
 * 
 * Uses unified config from config/password-requirements.json
 */

import type { ZXCVBNResult } from 'zxcvbn';

/**
 * Password requirements configuration
 */
interface PasswordConfig {
  minAccountPasswordLength: number;
  minCustomPasswordLength: number;
  minSharePasswordLength: number;
  minEntropyBits: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSpecial: boolean;
}

// Password requirements - loaded from config file
let PASSWORD_CONFIG: PasswordConfig | null = null;

/**
 * Load password requirements from config file
 */
async function loadPasswordConfig(): Promise<PasswordConfig> {
  if (PASSWORD_CONFIG !== null) {
    return PASSWORD_CONFIG;
  }

  try {
    const response = await fetch('/config/password-requirements.json');
    if (!response.ok) {
      throw new Error(`Failed to load password config: ${response.statusText}`);
    }
    PASSWORD_CONFIG = await response.json();
    return PASSWORD_CONFIG;
  } catch (error) {
    console.error('Failed to load password requirements config, using defaults:', error);
    // Fallback to defaults if config file can't be loaded
    PASSWORD_CONFIG = {
      minAccountPasswordLength: 14,
      minCustomPasswordLength: 14,
      minSharePasswordLength: 18,
      minEntropyBits: 60.0,
      requireUppercase: true,
      requireLowercase: true,
      requireNumber: true,
      requireSpecial: true,
    };
    return PASSWORD_CONFIG;
  }
}

/**
 * Requirement status for individual password checks
 */
export interface RequirementStatus {
  met: boolean;
  current?: number;
  needed?: number;
  message: string;
}

/**
 * Individual requirement checks
 */
export interface RequirementChecks {
  length: RequirementStatus;
  uppercase: RequirementStatus;
  lowercase: RequirementStatus;
  number: RequirementStatus;
  special: RequirementStatus;
}

/**
 * Password validation result - matches Go's PasswordValidationResult
 */
export interface PasswordValidationResult {
  entropy: number;
  strength_score: number;
  feedback: string[];
  meets_requirements: boolean;
  pattern_penalties?: string[];
  requirements: RequirementChecks;
  suggestions: string[];
}

// Lazy-loaded zxcvbn module
let zxcvbnModule: ((password: string, userInputs?: string[]) => ZXCVBNResult) | null = null;

/**
 * Lazy load zxcvbn library (only when needed)
 */
async function getZxcvbn(): Promise<(password: string, userInputs?: string[]) => ZXCVBNResult> {
  if (!zxcvbnModule) {
    const module = await import('zxcvbn');
    zxcvbnModule = module.default;
  }
  return zxcvbnModule;
}

/**
 * Check individual password requirements
 */
function checkPasswordRequirements(password: string, minLength: number): RequirementChecks {
  const length = password.length;
  let hasUpper = false;
  let hasLower = false;
  let hasNumber = false;
  let hasSpecial = false;

  for (const char of password) {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      // A-Z
      hasUpper = true;
    } else if (code >= 97 && code <= 122) {
      // a-z
      hasLower = true;
    } else if (code >= 48 && code <= 57) {
      // 0-9
      hasNumber = true;
    } else if (
      (code >= 33 && code <= 47) ||
      (code >= 58 && code <= 64) ||
      (code >= 91 && code <= 96) ||
      (code >= 123 && code <= 126)
    ) {
      // Special characters
      hasSpecial = true;
    }
  }

  const checks: RequirementChecks = {
    length: {
      met: length >= minLength,
      current: length,
      needed: minLength,
      message: '',
    },
    uppercase: {
      met: hasUpper,
      message: '',
    },
    lowercase: {
      met: hasLower,
      message: '',
    },
    number: {
      met: hasNumber,
      message: '',
    },
    special: {
      met: hasSpecial,
      message: '',
    },
  };

  // Set messages
  if (checks.length.met) {
    checks.length.message = `Length requirement met (${minLength}+ characters)`;
  } else {
    const remaining = minLength - length;
    checks.length.message = `Add ${remaining} more character${remaining !== 1 ? 's' : ''} (currently ${length}/${minLength})`;
  }

  checks.uppercase.message = checks.uppercase.met
    ? 'Uppercase letter present'
    : 'Missing: uppercase letter (A-Z)';

  checks.lowercase.message = checks.lowercase.met
    ? 'Lowercase letter present'
    : 'Missing: lowercase letter (a-z)';

  checks.number.message = checks.number.met
    ? 'Number present'
    : 'Missing: number (0-9)';

  checks.special.message = checks.special.met
    ? 'Special character present'
    : 'Missing: special character';

  return checks;
}

/**
 * Validate password entropy using zxcvbn
 * Matches Go's ValidatePasswordEntropy function
 */
export async function validatePasswordEntropy(
  password: string,
  minLength: number,
  minEntropy: number,
  userInputs?: string[]
): Promise<PasswordValidationResult> {
  if (password === '') {
    return {
      entropy: 0,
      strength_score: 0,
      feedback: ['Password cannot be empty'],
      meets_requirements: false,
      requirements: checkPasswordRequirements(password, minLength),
      suggestions: [`Enter a password (minimum ${minLength} characters)`],
    };
  }

  // Load zxcvbn and analyze password
  const zxcvbn = await getZxcvbn();
  const result = zxcvbn(password, userInputs);

  // Convert zxcvbn guesses to entropy bits: log2(guesses)
  const entropyBits = result.guesses > 0 ? Math.log2(result.guesses) : 0;

  // Generate user-friendly feedback based on zxcvbn score
  const feedback: string[] = [];

  switch (result.score) {
    case 0:
      feedback.push('This is a very weak password');
      break;
    case 1:
      feedback.push('This is a weak password');
      break;
    case 2:
      feedback.push('This is a fair password');
      break;
  }

  // Add length recommendation if password is short
  if (password.length < minLength) {
    feedback.push(`Consider using ${minLength}+ characters for better security`);
  }

  // Add entropy feedback if below threshold
  if (entropyBits < minEntropy) {
    feedback.push('Password entropy is too low - add more varied characters');
  }

  // Extract pattern penalties from zxcvbn sequence analysis
  const penalties: string[] = [];
  for (const seq of result.sequence) {
    if (seq.pattern === 'dictionary') {
      penalties.push('Contains common dictionary words');
    } else if (seq.pattern === 'spatial') {
      penalties.push('Contains keyboard patterns');
    } else if (seq.pattern === 'repeat') {
      penalties.push('Contains repeated characters');
    } else if (seq.pattern === 'sequence') {
      penalties.push('Contains sequential patterns');
    }
  }

  // Positive feedback for strong passwords
  if (entropyBits >= minEntropy && feedback.length === 0) {
    feedback.push('Strong password!');
  }

  // Check individual requirements
  const requirements = checkPasswordRequirements(password, minLength);

  // Build suggestions based on what's missing
  const suggestions: string[] = [];
  if (!requirements.length.met) {
    suggestions.push(requirements.length.message);
  }
  if (!requirements.uppercase.met) {
    suggestions.push(requirements.uppercase.message);
  }
  if (!requirements.lowercase.met) {
    suggestions.push(requirements.lowercase.message);
  }
  if (!requirements.number.met) {
    suggestions.push(requirements.number.message);
  }
  if (!requirements.special.met) {
    suggestions.push(requirements.special.message);
  }

  // Add pattern-based suggestions
  for (const penalty of penalties) {
    if (penalty === 'Contains common dictionary words') {
      suggestions.push('WARNING: Contains dictionary word - try something unique');
    } else if (penalty === 'Contains keyboard patterns') {
      suggestions.push('WARNING: Contains keyboard pattern - mix it up');
    } else if (penalty === 'Contains repeated characters') {
      suggestions.push('WARNING: Contains repeated sequence - add variety');
    } else if (penalty === 'Contains sequential patterns') {
      suggestions.push('WARNING: Contains sequential pattern - add variety');
    }
  }

  // If all requirements met, provide positive message
  if (suggestions.length === 0 && entropyBits >= minEntropy) {
    suggestions.push('Strong password! All requirements met');
  }

  const validationResult: PasswordValidationResult = {
    entropy: entropyBits,
    strength_score: result.score,
    feedback,
    meets_requirements: entropyBits >= minEntropy,
    requirements,
    suggestions,
  };

  // Only add pattern_penalties if there are any
  if (penalties.length > 0) {
    validationResult.pattern_penalties = penalties;
  }

  return validationResult;
}

/**
 * Validate account password (14+ characters, 60+ bit entropy)
 */
export async function validateAccountPassword(
  password: string,
  userInputs?: string[]
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePasswordEntropy(
    password,
    config.minAccountPasswordLength,
    config.minEntropyBits,
    userInputs
  );
}

/**
 * Validate share password (18+ characters, 60+ bit entropy)
 */
export async function validateSharePassword(
  password: string,
  userInputs?: string[]
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePasswordEntropy(
    password,
    config.minSharePasswordLength,
    config.minEntropyBits,
    userInputs
  );
}

/**
 * Validate custom password (14+ characters, 60+ bit entropy)
 */
export async function validateCustomPassword(
  password: string,
  userInputs?: string[]
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePasswordEntropy(
    password,
    config.minCustomPasswordLength,
    config.minEntropyBits,
    userInputs
  );
}

/**
 * Synchronous basic validation (for immediate feedback before zxcvbn loads)
 * Only checks length and character requirements, not entropy
 */
export function validatePasswordBasic(password: string, minLength: number): {
  meetsBasicRequirements: boolean;
  requirements: RequirementChecks;
} {
  const requirements = checkPasswordRequirements(password, minLength);
  const meetsBasicRequirements =
    requirements.length.met &&
    requirements.uppercase.met &&
    requirements.lowercase.met &&
    requirements.number.met &&
    requirements.special.met;

  return {
    meetsBasicRequirements,
    requirements,
  };
}
