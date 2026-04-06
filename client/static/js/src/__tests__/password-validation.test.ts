/**
 * Unit Tests -- Password Validation
 *
 * Tests for: validatePassword, validateAccountPassword, validateSharePassword,
 *            validateCustomPassword
 *
 * Deterministic pass/fail: length + character class checks.
 * Matches Go backend (crypto/password_validation.go) exactly.
 *
 * Production config (from crypto/password-requirements.json):
 *   minAccountPasswordLength: 15
 *   minCustomPasswordLength:  15
 *   minSharePasswordLength:   20
 *   minCharacterClassesRequired: 2
 *   specialCharacters: "`~!@#$%^&*()-_=+[]{}|;:,.<>? "
 */

import './setup';
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import {
  validatePassword,
  validateAccountPassword,
  validateSharePassword,
  validateCustomPassword,
} from '../crypto/password-validation';

// ============================================================================
// Constants matching production config
// ============================================================================

const SPECIAL_CHARS = '`~!@#$%^&*()-_=+[]{}|;:,.<>? ';

// ============================================================================
// Fetch mock -- returns production password requirements
// ============================================================================

const originalFetch = globalThis.fetch;

const PASSWORD_REQUIREMENTS = {
  minAccountPasswordLength: 15,
  minCustomPasswordLength: 15,
  minSharePasswordLength: 20,
  minCharacterClassesRequired: 2,
  specialCharacters: SPECIAL_CHARS,
};

function installFetchMock(): void {
  (globalThis as any).fetch = async (url: string | URL | Request) => {
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
    if (urlStr.includes('/api/config/password-requirements')) {
      return new Response(JSON.stringify(PASSWORD_REQUIREMENTS), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(url as any);
  };
}

function removeFetchMock(): void {
  globalThis.fetch = originalFetch;
}

// ============================================================================
// validatePassword (synchronous, explicit params)
// ============================================================================

describe('validatePassword', () => {
  test('empty password fails with helpful message', () => {
    const result = validatePassword('', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
    expect(result.requirements.length.met).toBe(false);
    expect(result.requirements.length.current).toBe(0);
    expect(result.requirements.length.needed).toBe(15);
  });

  test('too short password fails', () => {
    const result = validatePassword('Abc123!', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.length.met).toBe(false);
    expect(result.requirements.length.current).toBe(7);
  });

  test('long enough with 2+ classes passes', () => {
    // 15 chars, lowercase + number = 2 classes
    const result = validatePassword('abcdefghij12345', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(true);
    expect(result.requirements.length.met).toBe(true);
    expect(result.requirements.lowercase.met).toBe(true);
    expect(result.requirements.number.met).toBe(true);
    expect(result.requirements.class_count).toBe(2);
  });

  test('long enough with only 1 class fails when 2 required', () => {
    // 15 lowercase chars = 1 class
    const result = validatePassword('abcdefghijklmno', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.class_count).toBe(1);
    expect(result.requirements.classes_required).toBe(2);
  });

  test('all 4 character classes detected', () => {
    const result = validatePassword('Abcdefghij123!x', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(true);
    expect(result.requirements.uppercase.met).toBe(true);
    expect(result.requirements.lowercase.met).toBe(true);
    expect(result.requirements.number.met).toBe(true);
    expect(result.requirements.special.met).toBe(true);
    expect(result.requirements.class_count).toBe(4);
  });

  test('uppercase + special = 2 classes, passes', () => {
    const result = validatePassword('ABCDEFGHIJKLMN!', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(true);
    expect(result.requirements.class_count).toBe(2);
    expect(result.requirements.uppercase.met).toBe(true);
    expect(result.requirements.special.met).toBe(true);
    expect(result.requirements.lowercase.met).toBe(false);
    expect(result.requirements.number.met).toBe(false);
  });

  test('exactly at minimum length passes', () => {
    const result = validatePassword('Abcdefghijklmn1', 15, 2, SPECIAL_CHARS);
    // 16 chars, but minLength=15, so passes
    expect(result.meets_requirements).toBe(true);
  });

  test('one char below minimum length fails', () => {
    const result = validatePassword('Abcdefghijklm1', 15, 2, SPECIAL_CHARS);
    // 14 chars < 15
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.length.met).toBe(false);
  });

  test('special characters from config are recognized', () => {
    // Test each special char category
    for (const ch of ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', ' ']) {
      const pw = 'a'.repeat(14) + ch;
      const result = validatePassword(pw, 15, 2, SPECIAL_CHARS);
      expect(result.requirements.special.met).toBe(true);
    }
  });

  test('characters outside special set are not counted as special', () => {
    // Tab, newline, etc. are not in the special chars set
    const result = validatePassword('a'.repeat(14) + '\t', 15, 2, SPECIAL_CHARS);
    expect(result.requirements.special.met).toBe(false);
  });

  test('failure reasons list missing classes', () => {
    const result = validatePassword('abcdefghijklmno', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(false);
    // Should mention needing more character classes
    const classReason = result.reasons.find(r => r.includes('character classes'));
    expect(classReason).toBeTruthy();
  });

  test('failure reasons list length deficit', () => {
    const result = validatePassword('Ab1!', 15, 2, SPECIAL_CHARS);
    expect(result.meets_requirements).toBe(false);
    const lengthReason = result.reasons.find(r => r.includes('more character'));
    expect(lengthReason).toBeTruthy();
  });
});

// ============================================================================
// validateAccountPassword (async, uses config)
// ============================================================================

describe('validateAccountPassword', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  test('passes with 15+ chars and 2+ classes', async () => {
    const result = await validateAccountPassword('MyAccountPass!1');
    expect(result.meets_requirements).toBe(true);
  });

  test('fails with 14 chars', async () => {
    const result = await validateAccountPassword('MyAccountPas!1');
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.length.needed).toBe(15);
  });

  test('fails with only 1 class', async () => {
    const result = await validateAccountPassword('abcdefghijklmno');
    expect(result.meets_requirements).toBe(false);
  });
});

// ============================================================================
// validateSharePassword (async, uses config -- minLength=20)
// ============================================================================

describe('validateSharePassword', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  test('passes with 20+ chars and 2+ classes', async () => {
    const result = await validateSharePassword('SharePasswordIsLong1');
    expect(result.meets_requirements).toBe(true);
    expect(result.requirements.length.needed).toBe(20);
  });

  test('fails with 19 chars even with 4 classes', async () => {
    const result = await validateSharePassword('SharePassIsLong!1A');
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.length.met).toBe(false);
  });

  test('fails with 20 chars but only 1 class', async () => {
    const result = await validateSharePassword('abcdefghijklmnopqrst');
    expect(result.meets_requirements).toBe(false);
    expect(result.requirements.class_count).toBe(1);
  });
});

// ============================================================================
// validateCustomPassword (async, uses config -- minLength=15)
// ============================================================================

describe('validateCustomPassword', () => {
  beforeAll(() => installFetchMock());
  afterAll(() => removeFetchMock());

  test('passes with 15+ chars and 2+ classes', async () => {
    const result = await validateCustomPassword('CustomPassword!1');
    expect(result.meets_requirements).toBe(true);
  });

  test('fails with 14 chars', async () => {
    const result = await validateCustomPassword('CustomPasswd!1');
    expect(result.meets_requirements).toBe(false);
  });
});

