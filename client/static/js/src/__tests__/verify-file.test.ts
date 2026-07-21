/**
 * Tests for crypto/streaming-hash.ts and Verify File digest comparison.
 */

import './setup';
import { describe, test, expect } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  computeStreamingSHA256,
  normalizeSha256Hex,
  constantTimeHexEqual,
} from '../crypto/streaming-hash';
import { verifyLocalFileDigest } from '../files/verify-file';
import { shouldBlockBlobDownload } from '../files/download-integrity';
import { isSafeSwToBlobFallback } from '../files/streaming-download';
import { toHex } from '../crypto/primitives';

function hexOf(data: Uint8Array): string {
  return toHex(sha256(data));
}

describe('computeStreamingSHA256', () => {
  test('matches whole-buffer SHA-256 for multi-chunk file', async () => {
    const bytes = new Uint8Array(100_000);
    crypto.getRandomValues(bytes);
    const file = new File([bytes], 'big.bin');
    const expected = hexOf(bytes);
    const got = await computeStreamingSHA256(file, 16_384);
    expect(got).toBe(expected);
  });

  test('handles empty file', async () => {
    const file = new File([], 'empty.bin');
    const expected = hexOf(new Uint8Array(0));
    const got = await computeStreamingSHA256(file, 1024);
    expect(got).toBe(expected);
  });

  test('reports progress', async () => {
    const bytes = new Uint8Array(50_000);
    const file = new File([bytes], 'prog.bin');
    const calls: number[] = [];
    await computeStreamingSHA256(file, 10_000, (hashed, total) => {
      calls.push(hashed);
      expect(total).toBe(50_000);
    });
    expect(calls.length).toBeGreaterThan(1);
    expect(calls[calls.length - 1]).toBe(50_000);
  });
});

describe('normalizeSha256Hex', () => {
  test('accepts 64 hex with optional 0x and whitespace', () => {
    const dig = 'a'.repeat(64);
    expect(normalizeSha256Hex(`  0x${dig.toUpperCase()}  `)).toBe(dig);
  });

  test('rejects invalid length', () => {
    expect(normalizeSha256Hex('abcd')).toBeNull();
  });
});

describe('constantTimeHexEqual', () => {
  test('equal digests', () => {
    const a = 'b'.repeat(64);
    expect(constantTimeHexEqual(a, a.toUpperCase())).toBe(true);
  });

  test('unequal digests', () => {
    expect(constantTimeHexEqual('a'.repeat(64), 'b'.repeat(64))).toBe(false);
  });
});

describe('verifyLocalFileDigest', () => {
  test('match outcome', async () => {
    const payload = new TextEncoder().encode('verify-tool-match');
    const file = new File([payload], 'v.bin');
    const expected = hexOf(payload);
    const result = await verifyLocalFileDigest(file, expected, { chunkSize: 8 });
    expect(result.outcome).toBe('match');
    expect(result.computedHex).toBe(expected);
  });

  test('mismatch outcome', async () => {
    const payload = new TextEncoder().encode('verify-tool-mismatch');
    const file = new File([payload], 'v.bin');
    const wrong = '0'.repeat(64);
    const result = await verifyLocalFileDigest(file, wrong, { chunkSize: 8 });
    expect(result.outcome).toBe('mismatch');
    expect(result.computedHex).toBe(hexOf(payload));
  });

  test('invalid expected digest', async () => {
    const file = new File([new Uint8Array([1])], 'v.bin');
    const result = await verifyLocalFileDigest(file, 'not-a-digest', { chunkSize: 8 });
    expect(result.outcome).toBe('invalid_expected');
  });
});

describe('shouldBlockBlobDownload', () => {
  test('blocks only on mismatch', () => {
    expect(shouldBlockBlobDownload('mismatch')).toBe(true);
    expect(shouldBlockBlobDownload('match')).toBe(false);
    expect(shouldBlockBlobDownload('skipped')).toBe(false);
    expect(shouldBlockBlobDownload('unavailable')).toBe(false);
    expect(shouldBlockBlobDownload(undefined)).toBe(false);
  });
});

describe('isSafeSwToBlobFallback', () => {
  test('allows DataCloneError', () => {
    const err = new DOMException('The object cannot be cloned.', 'DataCloneError');
    expect(isSafeSwToBlobFallback(err)).toBe(true);
  });

  test('rejects ack timeout', () => {
    expect(isSafeSwToBlobFallback(new Error('SW init ack timeout'))).toBe(false);
  });

  test('rejects mid-stream partial-file errors', () => {
    expect(
      isSafeSwToBlobFallback(
        new Error('stream broken. A partial file may already be in your downloads folder; delete it if incomplete.'),
      ),
    ).toBe(false);
  });
});
