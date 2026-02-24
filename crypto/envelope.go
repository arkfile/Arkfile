package crypto

// =============================================================================
// ENVELOPE FORMAT (Version 0x01 - Unified FEK-based encryption)
// =============================================================================
//
// All encrypted data uses the same envelope format:
// [0x01][key_type][nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
//
// Where key_type indicates what password was used to encrypt the FEK:
//   0x01 = account password
//   0x02 = custom password
//
// Key type values are sourced from crypto/chunking-params.json via
// chunking_constants.go (KeyTypeForContext, KeyTypeAccount, KeyTypeCustom).
//
// Files are ALWAYS encrypted with a random FEK, then the FEK is encrypted
// with the user's password. This enables file sharing without re-encryption.
//
// Share operations use a separate mechanism with random salts and AES-GCM-AAD
// (see crypto/share_kdf.go). They do NOT use the envelope key type system.
// =============================================================================
