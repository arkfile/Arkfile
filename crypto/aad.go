// Package crypto / aad.go
//
// AAD (Additional Authenticated Data) construction helpers.
//
// Every AES-GCM operation on the file path -- chunks, FEK envelope, and
// metadata fields -- is bound by AAD so that the AEAD authentication tag
// covers not just the ciphertext but the *context* the ciphertext belongs to.
// A server (or DB-write attacker) that swaps, reorders, or substitutes a
// chunk / FEK envelope / metadata field between two of a user's files
// produces ciphertext whose AAD inputs no longer match what the client
// expects, and AES-GCM rejects the tag.
//
// Encoding convention: length-prefixed big-endian concatenation.
//
//   - Variable-length string fields are encoded as
//     [4-byte BE uint32 length][UTF-8 bytes].
//   - Fixed-width integer fields (chunkIndex, totalChunks) are encoded as
//     [8-byte BE uint64] with no length prefix.
//   - Single-byte fields (keyTypeByte) are encoded as [1 byte] directly.
//
// This convention is unambiguous: each call site produces a byte string
// determined solely by its inputs, and the same encoding is implemented
// in TypeScript (client/static/js/src/crypto/aad.ts). A hardcoded
// cross-language conformance vector in aad_test.go and aad.test.ts pins
// the two implementations together.
//
// AAD shapes (uniform chunks, no chunk-0 header):
//
//   BuildChunkAAD(fileID, chunkIndex, totalChunks)
//     [4B len(fileID)][fileID bytes]
//     [8B chunkIndex][8B totalChunks]
//
//   BuildFEKEnvelopeAAD(fileID, keyTypeByte)
//     [4B len(fileID)][fileID bytes][1B keyTypeByte]
//
//   BuildMetadataFieldAAD(fileID, fieldName, ownerUsername)
//     [4B len(fileID)][fileID bytes]
//     [4B len(fieldName)][fieldName bytes]
//     [4B len(ownerUsername)][ownerUsername bytes]

package crypto

import (
	"encoding/binary"
)

// Canonical AAD field-label constants for metadata encryption.
//
// These strings are permanent wire-format commitments:
// changing either value would invalidate every existing file's metadata
// AAD. They are AAD labels only -- they are NOT renames of any DB column
// or API field. The existing schema and API field names remain
// "encrypted_filename" and "encrypted_sha256sum" (which is also why these
// are the chosen label strings -- the AAD label tracks the stored field's
// name verbatim).
//
// Callers of BuildMetadataFieldAAD MUST reference these constants.
const (
	AADFieldFilename = "encrypted_filename"
	AADFieldSha256   = "encrypted_sha256sum"
)

// BuildChunkAAD constructs the AAD for a file-content chunk.
//
// Binding fileID prevents inter-file chunk substitution.
// Binding chunkIndex prevents intra-file chunk reordering.
// Binding totalChunks prevents server-side truncation -- if the
// server reduces chunk_count, the client downloads fewer chunks but
// constructs AAD with the now-smaller totalChunks, and every remaining
// chunk's tag (computed under the original totalChunks) fails.
func BuildChunkAAD(fileID string, chunkIndex, totalChunks int64) []byte {
	fidBytes := []byte(fileID)
	// 4 (len(fileID)) + len(fileID) + 8 (chunkIndex) + 8 (totalChunks)
	out := make([]byte, 0, 4+len(fidBytes)+8+8)

	out = appendLenPrefixedString(out, fidBytes)
	out = appendUint64BE(out, uint64(chunkIndex))
	out = appendUint64BE(out, uint64(totalChunks))

	return out
}

// BuildFEKEnvelopeAAD constructs the AAD for the FEK envelope ciphertext.
//
// Binding fileID prevents cross-file FEK swap: an attacker that
// substitutes file A's encrypted_fek into file B's metadata row cannot
// trick the client into decrypting file B's chunks with file A's FEK.
// Binding keyTypeByte prevents an attacker from flipping the 0x01/0x02
// indicator byte to mis-route the client to the wrong KEK derivation.
//
// keyTypeByte values: 0x01 = account password, 0x02 = custom password.
// See crypto/chunking-params.json envelope.keyTypes.
func BuildFEKEnvelopeAAD(fileID string, keyTypeByte byte) []byte {
	fidBytes := []byte(fileID)
	// 4 (len(fileID)) + len(fileID) + 1 (keyTypeByte)
	out := make([]byte, 0, 4+len(fidBytes)+1)

	out = appendLenPrefixedString(out, fidBytes)
	out = append(out, keyTypeByte)

	return out
}

// BuildMetadataFieldAAD constructs the AAD for an encrypted metadata field
// (filename or original-plaintext SHA-256 digest).
//
// Binding fileID prevents moving a metadata row to a different file.
// Binding fieldName prevents substituting encrypted_filename ciphertext
// into the encrypted_sha256sum slot or vice versa.
// Binding ownerUsername prevents moving a metadata row to a different
// user's account.
//
// fieldName MUST be one of the canonical constants: AADFieldFilename or
// AADFieldSha256.
func BuildMetadataFieldAAD(fileID, fieldName, ownerUsername string) []byte {
	fidBytes := []byte(fileID)
	fnBytes := []byte(fieldName)
	usrBytes := []byte(ownerUsername)
	// 4 + len(fileID) + 4 + len(fieldName) + 4 + len(ownerUsername)
	out := make([]byte, 0, 4+len(fidBytes)+4+len(fnBytes)+4+len(usrBytes))

	out = appendLenPrefixedString(out, fidBytes)
	out = appendLenPrefixedString(out, fnBytes)
	out = appendLenPrefixedString(out, usrBytes)

	return out
}

// appendLenPrefixedString appends [4B BE uint32 length][bytes] to dst.
func appendLenPrefixedString(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, b...)
	return dst
}

// appendUint64BE appends an 8-byte big-endian uint64 to dst.
func appendUint64BE(dst []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(dst, buf[:]...)
}
