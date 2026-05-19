/**
 * AAD (Additional Authenticated Data) construction helpers for Phase C.
 *
 * Every AES-GCM operation on the file path -- chunks, FEK envelope, and
 * metadata fields -- is bound by AAD so that the AEAD authentication tag
 * covers not just the ciphertext but the context the ciphertext belongs to.
 * A server (or DB-write attacker) that swaps, reorders, or substitutes a
 * chunk / FEK envelope / metadata field between two of a user's files
 * produces ciphertext whose AAD inputs no longer match what the client
 * expects, and AES-GCM rejects the tag.
 *
 * Encoding convention: length-prefixed big-endian concatenation.
 *
 *   - Variable-length string fields are encoded as
 *     [4-byte BE uint32 length][UTF-8 bytes].
 *   - Fixed-width integer fields (chunkIndex, totalChunks) are encoded as
 *     [8-byte BE uint64] with no length prefix.
 *   - Single-byte fields (keyTypeByte) are encoded as [1 byte] directly.
 *
 * This is the byte-for-byte counterpart of crypto/aad.go. A hardcoded
 * cross-language conformance vector lives in both aad_test.go and
 * __tests__/aad.test.ts; if either side drifts, both test suites fail
 * immediately on that vector.
 *
 * AAD shapes (Phase C, Outcome A -- uniform chunks, no chunk-0 header):
 *
 *   buildChunkAAD(fileID, chunkIndex, totalChunks)
 *     [4B len(fileID)][fileID bytes]
 *     [8B chunkIndex][8B totalChunks]
 *
 *   buildFEKEnvelopeAAD(fileID, keyTypeByte)
 *     [4B len(fileID)][fileID bytes][1B keyTypeByte]
 *
 *   buildMetadataFieldAAD(fileID, fieldName, ownerUsername)
 *     [4B len(fileID)][fileID bytes]
 *     [4B len(fieldName)][fieldName bytes]
 *     [4B len(ownerUsername)][ownerUsername bytes]
 */

// Canonical AAD field-label constants for metadata encryption.
//
// These strings are permanent wire-format commitments: once Phase C ships,
// changing either value would invalidate every existing file's metadata
// AAD. They are AAD labels only -- they are NOT renames of any DB column
// or API field. The existing schema and API field names remain
// "encrypted_filename" and "encrypted_sha256sum" (which is also why these
// are the chosen label strings -- the AAD label tracks the stored field's
// name verbatim).
//
// Callers of buildMetadataFieldAAD MUST reference these constants.
// Raw string literals at call sites are forbidden per phase-c.md §4.6.
export const AAD_FIELD_FILENAME = 'encrypted_filename';
export const AAD_FIELD_SHA256 = 'encrypted_sha256sum';

// uint64 wire-format upper bound (2^64 - 1). bigint values outside [0, MAX_U64]
// are rejected before encoding, since the wire format is a fixed 8-byte BE uint.
const MAX_U64 = (1n << 64n) - 1n;

// uint32 wire-format upper bound (2^32 - 1), used to bound length prefixes.
const MAX_U32 = 0xffffffff;

/**
 * Constructs the AAD for a file-content chunk.
 *
 * Binding fileID prevents inter-file chunk substitution (B-02, C-02).
 * Binding chunkIndex prevents intra-file chunk reordering (B-05).
 * Binding totalChunks prevents server-side truncation (C-03): if the
 * server reduces chunk_count, the client downloads fewer chunks but
 * constructs AAD with the now-smaller totalChunks, and every remaining
 * chunk's tag (computed under the original totalChunks) fails.
 */
export function buildChunkAAD(
  fileID: string,
  chunkIndex: bigint,
  totalChunks: bigint,
): Uint8Array {
  assertU64(chunkIndex, 'chunkIndex');
  assertU64(totalChunks, 'totalChunks');

  const fidBytes = encodeUtf8(fileID);
  // 4 (len(fileID)) + len(fileID) + 8 (chunkIndex) + 8 (totalChunks)
  const out = new Uint8Array(4 + fidBytes.length + 8 + 8);
  const view = new DataView(out.buffer);

  let offset = 0;
  offset = writeLenPrefixed(out, view, offset, fidBytes);
  view.setBigUint64(offset, chunkIndex, false);
  offset += 8;
  view.setBigUint64(offset, totalChunks, false);
  offset += 8;

  return out;
}

/**
 * Constructs the AAD for the FEK envelope ciphertext.
 *
 * Binding fileID prevents cross-file FEK swap (B-08): an attacker that
 * substitutes file A's encrypted_fek into file B's metadata row cannot
 * trick the client into decrypting file B's chunks with file A's FEK.
 * Binding keyTypeByte prevents an attacker from flipping the 0x01/0x02
 * indicator byte to mis-route the client to the wrong KEK derivation.
 *
 * keyTypeByte values: 0x01 = account password, 0x02 = custom password.
 * See crypto/chunking-params.json envelope.keyTypes.
 */
export function buildFEKEnvelopeAAD(
  fileID: string,
  keyTypeByte: number,
): Uint8Array {
  if (!Number.isInteger(keyTypeByte) || keyTypeByte < 0 || keyTypeByte > 0xff) {
    throw new Error(
      `buildFEKEnvelopeAAD: keyTypeByte must be an integer in [0, 255], got ${keyTypeByte}`,
    );
  }

  const fidBytes = encodeUtf8(fileID);
  // 4 (len(fileID)) + len(fileID) + 1 (keyTypeByte)
  const out = new Uint8Array(4 + fidBytes.length + 1);
  const view = new DataView(out.buffer);

  let offset = 0;
  offset = writeLenPrefixed(out, view, offset, fidBytes);
  out[offset] = keyTypeByte;

  return out;
}

/**
 * Constructs the AAD for an encrypted metadata field (filename or
 * original-plaintext SHA-256 digest).
 *
 * Binding fileID prevents moving a metadata row to a different file (C-19).
 * Binding fieldName prevents substituting encrypted_filename ciphertext
 * into the encrypted_sha256sum slot or vice versa.
 * Binding ownerUsername prevents moving a metadata row to a different
 * user's account.
 *
 * fieldName MUST be one of the canonical constants: AAD_FIELD_FILENAME or
 * AAD_FIELD_SHA256.
 */
export function buildMetadataFieldAAD(
  fileID: string,
  fieldName: string,
  ownerUsername: string,
): Uint8Array {
  const fidBytes = encodeUtf8(fileID);
  const fnBytes = encodeUtf8(fieldName);
  const usrBytes = encodeUtf8(ownerUsername);

  const out = new Uint8Array(
    4 + fidBytes.length + 4 + fnBytes.length + 4 + usrBytes.length,
  );
  const view = new DataView(out.buffer);

  let offset = 0;
  offset = writeLenPrefixed(out, view, offset, fidBytes);
  offset = writeLenPrefixed(out, view, offset, fnBytes);
  offset = writeLenPrefixed(out, view, offset, usrBytes);

  return out;
}

// Writes [4B BE uint32 length][bytes] starting at `offset`; returns the new offset.
function writeLenPrefixed(
  out: Uint8Array,
  view: DataView,
  offset: number,
  bytes: Uint8Array,
): number {
  if (bytes.length > MAX_U32) {
    throw new Error(
      `AAD length-prefixed field exceeds uint32 wire limit: ${bytes.length}`,
    );
  }
  view.setUint32(offset, bytes.length, false);
  out.set(bytes, offset + 4);
  return offset + 4 + bytes.length;
}

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function assertU64(v: bigint, name: string): void {
  if (typeof v !== 'bigint') {
    throw new Error(`${name} must be a bigint`);
  }
  if (v < 0n || v > MAX_U64) {
    throw new Error(`${name} out of uint64 range: ${v}`);
  }
}
