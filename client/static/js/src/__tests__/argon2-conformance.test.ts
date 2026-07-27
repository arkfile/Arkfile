/**
 * Cross-Language Argon2id Conformance Test (finding E1b)
 *
 * Consumes a pinned fixture shared with Go.
 */

import { describe, test, expect } from 'bun:test';
import { deriveKeyArgon2id, toHex } from '../crypto/primitives';
import conformanceFixture from '../../../../../crypto/testdata/argon2-conformance-vectors.json';

describe('cross-language Argon2id conformance', () => {
  test('derives identical key as Go implementation', async () => {
    // Decode salt from hex
    const saltBytes = new Uint8Array(
      conformanceFixture.salt_hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
    );

    const result = await deriveKeyArgon2id({
      password: conformanceFixture.password,
      salt: saltBytes,
      params: {
        memoryCost: conformanceFixture.m_kib,
        timeCost: conformanceFixture.t,
        parallelism: conformanceFixture.p,
        keyLength: conformanceFixture.dk,
        variant: 2,
      },
    });

    const derivedHex = toHex(result.key);

    expect(derivedHex).toBe(conformanceFixture.expected_hex);
  }, 30000); // Allow up to 30s for memory-hard Argon2id derivation
});
