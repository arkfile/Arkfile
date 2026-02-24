/**
 * Cryptographic Constants
 * 
 * Defines all cryptographic parameters used throughout the application.
 * These constants ensure consistency and security across all crypto operations.
 */

// ============================================================================
// Argon2id Parameters (imported from single source of truth)
// ============================================================================

/**
 * SINGLE SOURCE OF TRUTH: config/argon2id-params.json
 * 
 * All Argon2id parameters are loaded from config/argon2id-params.json at runtime.
 * This ensures consistency across the entire application.
 * 
 * CRITICAL: These parameters are used for deterministic file encryption keys.
 * Changing them will make existing encrypted files unreadable.
 */

interface Argon2Config {
  memoryCostKiB: number;
  timeCost: number;
  parallelism: number;
  keyLength: number;
}

let cachedArgon2Config: Argon2Config | null = null;

/**
 * Load Argon2id parameters from API endpoint
 * This ensures client and server always use the same embedded configuration
 */
async function loadArgon2Config(): Promise<Argon2Config> {
  if (cachedArgon2Config !== null) {
    return cachedArgon2Config;
  }

  try {
    const response = await fetch('/api/config/argon2');
    if (!response.ok) {
      throw new Error(`Failed to load Argon2 config: ${response.statusText}`);
    }
    const config: Argon2Config = await response.json();
    cachedArgon2Config = config;
    return config;
  } catch (error) {
    throw new Error(`Failed to load Argon2id parameters from API: ${error}`);
  }
}

/**
 * Get Argon2id parameters for file encryption
 * This function loads the config on first call and caches it
 */
export async function getArgon2Params(): Promise<{
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  keyLength: number;
  variant: 2;
}> {
  const config = await loadArgon2Config();
  return {
    memoryCost: config.memoryCostKiB,
    timeCost: config.timeCost,
    parallelism: config.parallelism,
    keyLength: config.keyLength,
    variant: 2 as const, // Argon2id
  };
}

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
// Chunked Upload/Download Constants (loaded from single source of truth)
// ============================================================================

/**
 * SINGLE SOURCE OF TRUTH: crypto/chunking-params.json
 *
 * All chunking parameters are loaded from crypto/chunking-params.json at runtime
 * via the /api/config/chunking endpoint. This ensures consistency across
 * the entire application (Go server, Go CLI, and TypeScript client).
 */

export interface ChunkingConfig {
  plaintextChunkSizeBytes: number;
  envelope: {
    version: number;
    headerSizeBytes: number;
    keyTypes: {
      account: number;
      custom: number;
    };
  };
  aesGcm: {
    nonceSizeBytes: number;
    tagSizeBytes: number;
    keySizeBytes: number;
  };
}

let cachedChunkingConfig: ChunkingConfig | null = null;

/**
 * Load chunking parameters from API endpoint
 * This ensures client and server always use the same embedded configuration
 */
async function loadChunkingConfig(): Promise<ChunkingConfig> {
  if (cachedChunkingConfig !== null) {
    return cachedChunkingConfig;
  }

  try {
    const response = await fetch('/api/config/chunking');
    if (!response.ok) {
      throw new Error(`Failed to load chunking config: ${response.statusText}`);
    }
    const config: ChunkingConfig = await response.json();
    cachedChunkingConfig = config;
    return config;
  } catch (error) {
    throw new Error(`Failed to load chunking parameters from API: ${error}`);
  }
}

/**
 * Get chunking parameters for file encryption/decryption
 * This function loads the config on first call and caches it
 */
export async function getChunkingParams(): Promise<ChunkingConfig> {
  return loadChunkingConfig();
}


// ============================================================================
// Salt Domain Prefixes
// ============================================================================

/**
 * Domain separation prefixes for deterministic salt derivation
 * 
 * CRITICAL: These MUST match the Go implementation in crypto/key_derivation.go
 * Format: SHA-256("arkfile-{context}-key-salt:{username}") → first 32 bytes = salt
 * 
 * See: GenerateUserKeySalt() in crypto/key_derivation.go
 */
export type PasswordContext = 'account' | 'custom';

export const SALT_DOMAIN_PREFIXES: Record<PasswordContext, string> = {
  /** Salt prefix for account password key derivation */
  account: 'arkfile-account-key-salt:',
  
  /** Salt prefix for custom password key derivation */
  custom: 'arkfile-custom-key-salt:',
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
