import { describe, expect, test } from 'bun:test';
import { resolveMFAChallengeRoute } from '../auth/mfa-method';

describe('resolveMFAChallengeRoute', () => {
  test('setup with pending method', () => {
    const route = resolveMFAChallengeRoute({
      requires_mfa_setup: true,
      mfa_methods: [],
      pending_mfa_method: 'webauthn',
    });
    expect(route).toEqual({ kind: 'setup', pendingMethod: 'webauthn' });
  });

  test('single webauthn method', () => {
    const route = resolveMFAChallengeRoute({
      requires_mfa_setup: false,
      mfa_methods: [{ type: 'webauthn', credential_id: 'cred-1', label: 'Key' }],
    });
    expect(route.kind).toBe('single');
    if (route.kind === 'single') {
      expect(route.method.credential_id).toBe('cred-1');
    }
  });

  test('multiple methods pick', () => {
    const route = resolveMFAChallengeRoute({
      mfa_methods: [
        { type: 'totp', credential_id: 't1' },
        { type: 'webauthn', credential_id: 'w1' },
      ],
    });
    expect(route.kind).toBe('pick');
  });

  test('empty enrolled list fails closed', () => {
    const route = resolveMFAChallengeRoute({
      requires_mfa_setup: false,
      mfa_methods: [],
    });
    expect(route.kind).toBe('error');
  });
});
