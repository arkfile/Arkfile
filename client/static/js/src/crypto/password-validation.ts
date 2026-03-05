/**
 * Password Validation Module
 *
 * Deterministic password validation: length + character class checks.
 * Matches the Go backend (crypto/password_validation.go) exactly.
 *
 * Uses unified config from crypto/password-requirements.json served via API.
 * No zxcvbn, no entropy, no strength scores — pass/fail only.
 */

/**
 * Password requirements configuration (matches Go PasswordRequirements)
 */
interface PasswordConfig {
  minAccountPasswordLength: number;
  minCustomPasswordLength: number;
  minSharePasswordLength: number;
  minCharacterClassesRequired: number;
  specialCharacters: string;
}

// Password requirements - loaded from config file
let PASSWORD_CONFIG: PasswordConfig | null = null;

/**
 * Load password requirements from API endpoint.
 * Ensures client and server always use the same embedded configuration.
 */
async function loadPasswordConfig(): Promise<PasswordConfig> {
  if (PASSWORD_CONFIG !== null) {
    return PASSWORD_CONFIG;
  }

  try {
    const response = await fetch('/api/config/password-requirements');
    if (!response.ok) {
      throw new Error(`Failed to load password config: ${response.statusText}`);
    }
    const config: PasswordConfig = await response.json();
    PASSWORD_CONFIG = config;
    return config;
  } catch (error) {
    throw new Error(`Failed to load password requirements from API: ${error}`);
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
 * Individual requirement checks (matches Go RequirementChecks)
 */
export interface RequirementChecks {
  length: RequirementStatus;
  uppercase: RequirementStatus;
  lowercase: RequirementStatus;
  number: RequirementStatus;
  special: RequirementStatus;
  class_count: number;
  classes_required: number;
}

/**
 * Password validation result (matches Go PasswordValidationResult)
 */
export interface PasswordValidationResult {
  meets_requirements: boolean;
  requirements: RequirementChecks;
  reasons: string[];
}

/**
 * Check password requirements deterministically.
 * Pass = (length >= minLength) AND (character classes >= minClasses)
 */
function checkPassword(
  password: string,
  minLength: number,
  minClasses: number,
  specialChars: string
): PasswordValidationResult {
  const length = password.length;
  let hasUpper = false;
  let hasLower = false;
  let hasNumber = false;
  let hasSpecial = false;

  for (const char of password) {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      hasUpper = true;
    } else if (code >= 97 && code <= 122) {
      hasLower = true;
    } else if (code >= 48 && code <= 57) {
      hasNumber = true;
    } else if (specialChars.includes(char)) {
      hasSpecial = true;
    }
  }

  let classCount = 0;
  if (hasUpper) classCount++;
  if (hasLower) classCount++;
  if (hasNumber) classCount++;
  if (hasSpecial) classCount++;

  const lengthOK = length >= minLength;
  const classesOK = classCount >= minClasses;
  const meetsRequirements = lengthOK && classesOK;

  // Build requirement checks
  const checks: RequirementChecks = {
    length: {
      met: lengthOK,
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
    class_count: classCount,
    classes_required: minClasses,
  };

  // Set messages
  if (checks.length.met) {
    checks.length.message = `Length requirement met (${minLength}+ characters)`;
  } else {
    const remaining = minLength - length;
    checks.length.message = `Add ${remaining} more character${remaining !== 1 ? 's' : ''} (currently ${length}/${minLength})`;
  }

  checks.uppercase.message = hasUpper
    ? 'Uppercase letter present'
    : 'Missing: uppercase letter (A-Z)';

  checks.lowercase.message = hasLower
    ? 'Lowercase letter present'
    : 'Missing: lowercase letter (a-z)';

  checks.number.message = hasNumber
    ? 'Number present'
    : 'Missing: number (0-9)';

  checks.special.message = hasSpecial
    ? 'Special character present'
    : 'Missing: special character';

  // Build failure reasons
  const reasons: string[] = [];
  if (!lengthOK) {
    reasons.push(checks.length.message);
  }
  if (!classesOK) {
    const missing: string[] = [];
    if (!hasUpper) missing.push('uppercase (A-Z)');
    if (!hasLower) missing.push('lowercase (a-z)');
    if (!hasNumber) missing.push('number (0-9)');
    if (!hasSpecial) missing.push('special character');
    reasons.push(`Need ${minClasses} character classes, have ${classCount}`);
    if (missing.length > 0) {
      reasons.push(`Missing: ${missing.join(', ')}`);
    }
  }

  return {
    meets_requirements: meetsRequirements,
    requirements: checks,
    reasons,
  };
}

/**
 * Validate password with explicit parameters
 */
export function validatePassword(
  password: string,
  minLength: number,
  minClasses: number,
  specialChars: string
): PasswordValidationResult {
  if (password === '') {
    return {
      meets_requirements: false,
      requirements: {
        length: { met: false, current: 0, needed: minLength, message: `Enter a password (minimum ${minLength} characters)` },
        uppercase: { met: false, message: 'Missing: uppercase letter (A-Z)' },
        lowercase: { met: false, message: 'Missing: lowercase letter (a-z)' },
        number: { met: false, message: 'Missing: number (0-9)' },
        special: { met: false, message: 'Missing: special character' },
        class_count: 0,
        classes_required: minClasses,
      },
      reasons: [`Enter a password (minimum ${minLength} characters)`],
    };
  }

  return checkPassword(password, minLength, minClasses, specialChars);
}

/**
 * Validate account password using config requirements
 */
export async function validateAccountPassword(
  password: string
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePassword(
    password,
    config.minAccountPasswordLength,
    config.minCharacterClassesRequired,
    config.specialCharacters
  );
}

/**
 * Validate share password using config requirements
 */
export async function validateSharePassword(
  password: string
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePassword(
    password,
    config.minSharePasswordLength,
    config.minCharacterClassesRequired,
    config.specialCharacters
  );
}

/**
 * Validate custom password using config requirements
 */
export async function validateCustomPassword(
  password: string
): Promise<PasswordValidationResult> {
  const config = await loadPasswordConfig();
  return validatePassword(
    password,
    config.minCustomPasswordLength,
    config.minCharacterClassesRequired,
    config.specialCharacters
  );
}

/**
 * Synchronous basic validation (for immediate feedback before async config loads).
 * Uses hardcoded defaults matching the JSON config.
 */
export function validatePasswordBasic(password: string, minLength: number): {
  meetsBasicRequirements: boolean;
  requirements: RequirementChecks;
} {
  // Use default special chars and 4 classes required as fallback
  const result = checkPassword(password, minLength, 4, '!@#$%^&*()_+-=[]{}|;:\'",.<>?/`~');
  return {
    meetsBasicRequirements: result.meets_requirements,
    requirements: result.requirements,
  };
}
