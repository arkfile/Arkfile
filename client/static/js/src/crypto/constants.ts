/**
 * Cryptographic Constants
 * 
 * Defines all cryptographic parameters used throughout the application.
 * These constants ensure consistency and security across all crypto operations.
 */

// ============================================================================
// Argon2id Parameters (for file encryption key derivation)
// ============================================================================

/**
 * Argon2id configuration for file encryption key derivation.
 * These parameters provide strong protection against brute-force attacks
 * while remaining practical for client-side use.
 * 
 * CRITICAL: These parameters are used for deterministic file encryption keys.
 * Changing them will make existing encrypted files unreadable.
 */
export const ARGON2_PARAMS = {
  FILE_ENCRYPTION: {
    /**
     * Memory cost in KiB (64 MiB = 65536 KiB)
     * Higher values increase resistance to GPU attacks
     */
    memoryCost: 65536,
    
    /**
     * Time cost (number of iterations)
     * Higher values increase computation time
     */
    timeCost: 3,
    
    /**
     * Parallelism factor (number of threads)
     * Must match server-side configuration
     */
    parallelism: 4,
    
    /**
     * Output key length in bytes (256 bits)
     */
    keyLength: 32,
    
    /**
     * Argon2 variant (2 = Argon2id)
     * Argon2id provides balanced protection against side-channel and GPU attacks
     */
    variant: 2 as const,
  },
} as const;

// ============================================================================
// Key Sizes
// ============================================================================

/**
 * Standard key sizes used throughout the application
 */
export const KEY_SIZES = {
  /** AES-256 key size in bytes */
  AES_256: 32,
  
  /** File encryption key size in bytes (matches Argon2 output) */
  FILE_ENCRYPTION_KEY: 32,
  
  /** OPAQUE export key size in bytes */
  OPAQUE_EXPORT_KEY: 64,
  
  /** Session key size in bytes (derived from OPAQUE export key) */
  SESSION_KEY: 32,
  
  /** Salt size in bytes */
  SALT: 32,
  
  /** IV/Nonce size for AES-GCM in bytes */
  IV: 12,
  
  /** Authentication tag size for AES-GCM in bytes */
  AUTH_TAG: 16,
} as const;

// ============================================================================
// OPAQUE Protocol Configuration
// ============================================================================

/**
 * OPAQUE protocol configuration
 * Using OPRF(ristretto255, SHA-512) as specified in RFC 9497
 */
export const OPAQUE_CONFIG = {
  /** OPRF suite identifier */
  suite: 'ristretto255-SHA512' as const,
  
  /** Key exchange algorithm */
  kex: 'X25519' as const,
  
  /** Key derivation function */
  kdf: 'HKDF-SHA512' as const,
  
  /** Message authentication code */
  mac: 'HMAC-SHA512' as const,
  
  /** Hash function */
  hash: 'SHA512' as const,
} as const;

// ============================================================================
// Encryption Algorithm Configuration
// ============================================================================

/**
 * AES-GCM configuration for file encryption
 */
export const AES_GCM_CONFIG = {
  /** Algorithm name */
  name: 'AES-GCM' as const,
  
  /** Key length in bits */
  keyLength: 256,
  
  /** IV/Nonce length in bytes */
  ivLength: KEY_SIZES.IV,
  
  /** Authentication tag length in bits */
  tagLength: 128,
} as const;

// ============================================================================
// Salt Generation
// ============================================================================

/**
 * Domain separation strings for different salt derivations
 * These ensure that salts for different purposes are cryptographically independent
 */
export const SALT_DOMAINS = {
  /** Domain for file encryption salt derivation */
  FILE_ENCRYPTION: 'arkfile.file-encryption.v1',
  
  /** Domain for OPAQUE protocol */
  OPAQUE: 'arkfile.opaque.v1',
} as const;

// ============================================================================
// Storage Keys
// ============================================================================

/**
 * Keys used for sessionStorage/localStorage
 */
export const STORAGE_KEYS = {
  /** Cached file encryption key (sessionStorage only) */
  FILE_ENCRYPTION_KEY: 'arkfile.fileEncryptionKey',
  
  /** OPAQUE client state during registration/login */
  OPAQUE_STATE: 'arkfile.opaqueState',
  
  /** Session token */
  SESSION_TOKEN: 'arkfile.sessionToken',
  
  /** Refresh token */
  REFRESH_TOKEN: 'arkfile.refreshToken',
} as const;

// ============================================================================
// Protocol Version
// ============================================================================

/**
 * Protocol version for encrypted file format
 * Increment this when making breaking changes to the encryption format
 */
export const PROTOCOL_VERSION = 1;

/**
 * File encryption format version
 * This is embedded in encrypted file metadata
 */
export const FILE_ENCRYPTION_VERSION = 1;

// ============================================================================
// Timeouts and Limits
// ============================================================================

/**
 * Various timeouts and limits
 */
export const LIMITS = {
  /** Maximum time to wait for key derivation (ms) */
  KEY_DERIVATION_TIMEOUT: 30000,
  
  /** Maximum file size for client-side encryption (bytes) - 5GB */
  MAX_FILE_SIZE: 5 * 1024 * 1024 * 1024,
  
  /** Chunk size for streaming encryption (bytes) - 64MB */
  ENCRYPTION_CHUNK_SIZE: 64 * 1024 * 1024,
} as const;

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Validates that a value is a valid Argon2 variant
 */
export function isValidArgon2Variant(variant: number): variant is 2 {
  return variant === 2; // Only Argon2id is supported
}

/**
 * Validates that a key has the correct length
 */
export function isValidKeyLength(key: Uint8Array, expectedLength: number): boolean {
  return key.length === expectedLength;
}
