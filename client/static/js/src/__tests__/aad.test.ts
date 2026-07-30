/**
 * Unit Tests -- AAD construction helpers
 *
 * The cross-language conformance vector is the most important test in
 * this file. It hardcodes the same input vector and expected hex output
 * as crypto/aad_test.go (expectedChunkAADHex). If the Go and TS
 * implementations ever drift -- byte order, length prefix, string
 * encoding -- both suites fail immediately on this single vector.
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import {
  AAD_FIELD_FILENAME,
  AAD_FIELD_SHA256,
  AAD_FIELD_PASSWORD_HINT,
  AAD_FIELD_TAGS,
  buildChunkAAD,
  buildFEKEnvelopeAAD,
  buildMetadataFieldAAD,
} from '../crypto/aad';
import { fromHex, toHex } from '../crypto/primitives';
import { createOwnerEnvelopeHeader } from '../crypto/owner-envelope';
import fixture from '../../../../../crypto/testdata/crypto-conformance-v2.json';

// ============================================================================
// CROSS-LANGUAGE CONFORMANCE VECTOR
// ============================================================================
//
// MUST stay byte-identical with crypto/aad_test.go expectedChunkAADHex
// for the same input.
//
// Layout for buildChunkAAD("a1b2c3d4-e5f6-7890-abcd-ef1234567890", 3n, 10n):
//   [4B BE u32 len=36]            = 00 00 00 24
//   [36 bytes UTF-8 fileID]       = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
//   [8B BE u64 chunkIndex=3]      = 00 00 00 00 00 00 00 03
//   [8B BE u64 totalChunks=10]    = 00 00 00 00 00 00 00 0a
// Total: 4 + 36 + 8 + 8 = 56 bytes.

const CONFORMANCE_FILE_ID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const CONFORMANCE_CHUNK_INDEX = 3n;
const CONFORMANCE_TOTAL_CHUNKS = 10n;

const EXPECTED_CHUNK_AAD_HEX =
  '00000024' +
  '6131623263336434' +
  '2d65356636' +
  '2d37383930' +
  '2d61626364' +
  '2d6566313233343536373839' +
  '30' +
  '0000000000000003' +
  '000000000000000a';

describe('buildChunkAAD -- cross-language conformance', () => {
  test('byte-for-byte matches crypto/aad_test.go expectedChunkAADHex', () => {
    const got = buildChunkAAD(
      CONFORMANCE_FILE_ID,
      CONFORMANCE_CHUNK_INDEX,
      CONFORMANCE_TOTAL_CHUNKS,
    );
    const want = fromHex(EXPECTED_CHUNK_AAD_HEX);

    // Length tripwire: 4 + 36 + 8 + 8 = 56.
    expect(got.length).toBe(56);
    expect(want.length).toBe(56);

    // Byte-for-byte equality, with a hex-encoded mismatch dump on failure
    // so a future drift is trivially diagnosable.
    expect(toHex(got)).toBe(toHex(want));
  });
});

describe('shared crypto v2 AAD fixture', () => {
  test('matches chunk and metadata field bytes', () => {
    expect(toHex(buildChunkAAD(fixture.file_id, 0n, 3n)))
      .toBe(fixture.aad.chunk_zero_of_three_hex);
    expect(toHex(buildMetadataFieldAAD(
      fixture.file_id,
      AAD_FIELD_FILENAME,
      fixture.owner_username,
    ))).toBe(fixture.aad.encrypted_filename_hex);
    expect(toHex(buildMetadataFieldAAD(
      fixture.file_id,
      AAD_FIELD_SHA256,
      fixture.owner_username,
    ))).toBe(fixture.aad.encrypted_sha256sum_hex);
    expect(toHex(buildMetadataFieldAAD(
      fixture.file_id,
      AAD_FIELD_PASSWORD_HINT,
      fixture.owner_username,
    ))).toBe(fixture.aad.encrypted_password_hint_hex);
    expect(toHex(buildMetadataFieldAAD(
      fixture.file_id,
      AAD_FIELD_TAGS,
      fixture.owner_username,
    ))).toBe(fixture.aad.encrypted_tags_hex);
  });
});

// ============================================================================
// DETERMINISM + UNIQUENESS -- buildChunkAAD
// ============================================================================

describe('buildChunkAAD -- determinism and uniqueness', () => {
  test('is deterministic for identical inputs', () => {
    const a = buildChunkAAD('file-x', 5n, 20n);
    const b = buildChunkAAD('file-x', 5n, 20n);
    expect(toHex(a)).toBe(toHex(b));
  });

  test('differs across chunkIndex', () => {
    const a = buildChunkAAD('file-x', 0n, 5n);
    const b = buildChunkAAD('file-x', 1n, 5n);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('differs across fileID', () => {
    const a = buildChunkAAD('file-a', 0n, 5n);
    const b = buildChunkAAD('file-b', 0n, 5n);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('differs across totalChunks', () => {
    const a = buildChunkAAD('file-x', 0n, 5n);
    const b = buildChunkAAD('file-x', 0n, 6n);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('rejects negative chunkIndex', () => {
    expect(() => buildChunkAAD('file-x', -1n, 5n)).toThrow();
  });

  test('rejects negative totalChunks', () => {
    expect(() => buildChunkAAD('file-x', 0n, -1n)).toThrow();
  });

  test('rejects chunkIndex above uint64 range', () => {
    const aboveU64 = 1n << 64n;
    expect(() => buildChunkAAD('file-x', aboveU64, 5n)).toThrow();
  });
});

// ============================================================================
// DETERMINISM + DISTINCTION -- buildFEKEnvelopeAAD
// ============================================================================

describe('buildFEKEnvelopeAAD -- determinism and distinction', () => {
  const salt = new Uint8Array(32);

  test('is deterministic for identical inputs', () => {
    const header = createOwnerEnvelopeHeader('account', salt);
    const a = buildFEKEnvelopeAAD('file-x', header);
    const b = buildFEKEnvelopeAAD('file-x', header);
    expect(toHex(a)).toBe(toHex(b));
  });

  test('account (0x01) and custom (0x02) produce different AADs for same fileID', () => {
    const account = buildFEKEnvelopeAAD('file-x', createOwnerEnvelopeHeader('account', salt));
    const custom = buildFEKEnvelopeAAD('file-x', createOwnerEnvelopeHeader('custom', salt));
    expect(toHex(account)).not.toBe(toHex(custom));
  });

  test('differs across fileID for the same keyType', () => {
    const header = createOwnerEnvelopeHeader('account', salt);
    const a = buildFEKEnvelopeAAD('file-a', header);
    const b = buildFEKEnvelopeAAD('file-b', header);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('matches the shared complete-header fixture', () => {
    const header = fromHex(fixture.owner_headers.account_hex);
    expect(toHex(buildFEKEnvelopeAAD(fixture.file_id, header)))
      .toBe(fixture.aad.account_fek_envelope_hex);
  });
});

// ============================================================================
// DETERMINISM + DISTINCTION -- buildMetadataFieldAAD
// ============================================================================

describe('buildMetadataFieldAAD -- determinism and distinction', () => {
  test('is deterministic for identical inputs', () => {
    const a = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'alice');
    const b = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'alice');
    expect(toHex(a)).toBe(toHex(b));
  });

  test('AAD_FIELD_FILENAME vs AAD_FIELD_SHA256 produce different AADs', () => {
    const fn = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'alice');
    const sh = buildMetadataFieldAAD('file-x', AAD_FIELD_SHA256, 'alice');
    expect(toHex(fn)).not.toBe(toHex(sh));
  });

  test('AAD_FIELD_PASSWORD_HINT differs from filename and sha256 AADs', () => {
    const hint = buildMetadataFieldAAD('file-x', AAD_FIELD_PASSWORD_HINT, 'alice');
    const fn = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'alice');
    const sh = buildMetadataFieldAAD('file-x', AAD_FIELD_SHA256, 'alice');
    expect(toHex(hint)).not.toBe(toHex(fn));
    expect(toHex(hint)).not.toBe(toHex(sh));
  });

  test('differs across ownerUsername', () => {
    const a = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'alice');
    const b = buildMetadataFieldAAD('file-x', AAD_FIELD_FILENAME, 'bob');
    expect(toHex(a)).not.toBe(toHex(b));
  });

  test('differs across fileID', () => {
    const a = buildMetadataFieldAAD('file-a', AAD_FIELD_FILENAME, 'alice');
    const b = buildMetadataFieldAAD('file-b', AAD_FIELD_FILENAME, 'alice');
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

// ============================================================================
// AAD field-label tripwires
// ============================================================================
//
// These constants are permanent wire-format commitments.
// Silently changing either literal would break every previously
// encrypted file's metadata. Pin them in a test so a stray edit fails CI.

describe('AAD field-label constants', () => {
  test('AAD_FIELD_FILENAME is the exact canonical string', () => {
    expect(AAD_FIELD_FILENAME).toBe('encrypted_filename');
  });

  test('AAD_FIELD_SHA256 is the exact canonical string', () => {
    expect(AAD_FIELD_SHA256).toBe('encrypted_sha256sum');
  });

  test('AAD_FIELD_PASSWORD_HINT is the exact canonical string', () => {
    expect(AAD_FIELD_PASSWORD_HINT).toBe('encrypted_password_hint');
  });

  test('AAD_FIELD_TAGS is the exact canonical string', () => {
    expect(AAD_FIELD_TAGS).toBe('encrypted_tags');
  });
});
