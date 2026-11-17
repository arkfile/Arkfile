import { describe, test, expect } from 'bun:test';
import { FLOOR_PASSWORD, resolvePasswordConfig } from '../crypto/floors.js';

describe('resolvePasswordConfig', () => {
  test('ignores a server attempt to lower the maximum password length', () => {
    const config = resolvePasswordConfig({ maxPasswordLength: 15 });
    expect(config.maxPasswordLength).toBe(FLOOR_PASSWORD.maxPasswordLength);
  });

  test('ignores a special-character set that adds letters or digits', () => {
    const config = resolvePasswordConfig({ specialCharacters: 'abc123!' });
    expect(config.specialCharacters).toBe(FLOOR_PASSWORD.specialCharacters);
  });

  test('accepts a narrower special-character set', () => {
    const config = resolvePasswordConfig({ specialCharacters: '!@#' });
    expect(config.specialCharacters).toBe('!@#');
  });

  test('falls back to floors when the server sends nothing', () => {
    expect(resolvePasswordConfig(null)).toEqual(FLOOR_PASSWORD);
    expect(resolvePasswordConfig({})).toEqual(FLOOR_PASSWORD);
  });
});
