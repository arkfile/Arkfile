/**
 * Streaming SHA-256 over File / Blob sources.
 *
 * Reads one slice at a time via file.slice() + arrayBuffer(), never loading the
 * whole file into the JS heap. Peak memory is approximately one chunk.
 *
 * Mirrors Go CLI computeStreamingSHA256() in crypto_utils.go. Used by upload,
 * the Verify File tool, and unit tests.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { toHex } from './primitives.js';

/**
 * Computes SHA-256 of a File (or Blob) using streaming reads.
 *
 * @param file - File or Blob to hash
 * @param chunkSize - bytes per slice (typically plaintextChunkSizeBytes)
 * @param onProgress - optional progress callback (bytes hashed, total bytes)
 * @returns lowercase hex digest
 */
export async function computeStreamingSHA256(
  file: Blob,
  chunkSize: number,
  onProgress?: (bytesHashed: number, totalBytes: number) => void,
): Promise<string> {
  if (chunkSize <= 0) {
    throw new Error('chunkSize must be positive');
  }

  const hasher = sha256.create();
  let offset = 0;

  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
    const slice = file.slice(offset, end);
    const buffer = await slice.arrayBuffer();
    hasher.update(new Uint8Array(buffer));
    offset = end;

    if (onProgress) {
      onProgress(offset, file.size);
    }
  }

  // Empty files: digest of zero bytes (hasher with no updates is also empty).
  if (file.size === 0) {
    hasher.update(new Uint8Array(0));
  }

  return toHex(hasher.digest());
}

/**
 * Normalize a user-supplied hex digest: strip whitespace and optional 0x prefix,
 * lowercase. Returns null if the result is not exactly 64 hex characters.
 */
export function normalizeSha256Hex(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (s.startsWith('0x')) {
    s = s.slice(2);
  }
  s = s.replace(/\s+/g, '');
  if (!/^[0-9a-f]{64}$/.test(s)) {
    return null;
  }
  return s;
}

/**
 * Constant-time hex string comparison (both inputs lowercased). Unequal lengths
 * are not equal but still fully scanned to avoid timing leaks.
 */
export function constantTimeHexEqual(a: string, b: string): boolean {
  const aLow = a.toLowerCase();
  const bLow = b.toLowerCase();
  const len = Math.max(aLow.length, bLow.length);
  let diff = aLow.length ^ bLow.length;
  for (let i = 0; i < len; i++) {
    const ac = i < aLow.length ? aLow.charCodeAt(i) : 0;
    const bc = i < bLow.length ? bLow.charCodeAt(i) : 0;
    diff |= ac ^ bc;
  }
  return diff === 0;
}
