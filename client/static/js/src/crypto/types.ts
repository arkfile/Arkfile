/**
 * Cryptographic Type Definitions
 * 
 * Defines TypeScript interfaces and types for all cryptographic operations.
 */

// ============================================================================
// Key Types
// ============================================================================

/**
 * File encryption key derived from password using Argon2id
 * This key is deterministic and can be derived offline
 */
export interface FileEncryptionKey {
  /** The raw key material (32 bytes) */
  key: Uint8Array;
  
  /** Username used for salt derivation */
  username: string;
  
  /** Timestamp when key was derived */
  derivedAt: number;
}

/**
 * OPAQUE export key used for session authentication
 * This key is ephemeral and only valid for the current session
 */
export interface OpaqueExportKey {
  /** The raw export key material (64 bytes) */
  key: Uint8Array;
  
  /** Timestamp when key was generated */
  generatedAt: number;
}

/**
 * Session key derived from OPAQUE export key
 * Used for JWT authentication
 */
export interface SessionKey {
  /** The raw session key material (32 bytes) */
  key: Uint8Array;
  
  /** Timestamp when key was derived */
  derivedAt: number;
  
  /** Expiration timestamp */
  expiresAt: number;
}

/**
 * Cryptographic key material (generic)
 */
export interface CryptoKey {
  /** The raw key bytes */
  key: Uint8Array;
  
  /** Key type identifier */
  type: 'file-encryption' | 'session' | 'opaque-export';
  
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

// ============================================================================
// OPAQUE Protocol Types
// ============================================================================

/**
 * OPAQUE registration request (client → server)
 */
export interface OpaqueRegistrationRequest {
  /** Username */
  username: string;
  
  /** Serialized registration request from OPAQUE client */
  request: Uint8Array;
}

/**
 * OPAQUE registration response (server → client)
 */
export interface OpaqueRegistrationResponse {
  /** Serialized registration response from OPAQUE server */
  response: Uint8Array;
}

/**
 * OPAQUE registration record (client → server)
 */
export interface OpaqueRegistrationRecord {
  /** Username */
  username: string;
  
  /** Serialized registration record */
  record: Uint8Array;
  
  /** OPAQUE export key (for session key derivation) */
  exportKey: Uint8Array;
}

/**
 * OPAQUE credential request (client → server)
 */
export interface OpaqueCredentialRequest {
  /** Username */
  username: string;
  
  /** Serialized credential request from OPAQUE client */
  request: Uint8Array;
}

/**
 * OPAQUE credential response (server → client)
 */
export interface OpaqueCredentialResponse {
  /** Serialized credential response from OPAQUE server */
  response: Uint8Array;
}

/**
 * Encrypted file metadata stored alongside ciphertext
 */
export interface EncryptedFileMetadata {
  /** Protocol version */
  version: number;
  
  /** Encryption algorithm used */
  algorithm: string;
  
  /** Key derivation function used */
  kdf: string;
  
  /** Timestamp when file was encrypted */
  timestamp: number;
}

/**
 * File encryption metadata with KDF parameters
 */
export interface FileEncryptionMetadata {
  /** Protocol version */
  version: number;
  
  /** Encryption algorithm (e.g., 'AES-256-GCM') */
  algorithm: string;
  
  /** Key derivation function (e.g., 'Argon2id') */
  kdf: string;
  
  /** KDF parameters used */
  kdfParams: {
    memoryCost: number;
    timeCost: number;
    parallelism: number;
  };
  
  /** Timestamp when file was encrypted */
  timestamp: number;
  
  /** Original file size in bytes */
  originalSize: number;
}

/**
 * Complete encrypted file data structure
 */
export interface EncryptedFileData {
  /** Metadata about the encryption */
  metadata: FileEncryptionMetadata;
  
  /** Encrypted file content */
  ciphertext: Uint8Array;
  
  /** Initialization vector */
  iv: Uint8Array;
  
  /** Authentication tag */
  tag: Uint8Array;
}

// PasswordContext: single source of truth is constants.ts
import type { PasswordContext } from './constants';
export type { PasswordContext } from './constants';

/**
 * Options for file encryption
 */
export interface FileEncryptionOptions {
  /** Additional authenticated data (optional) */
  additionalData?: Uint8Array;
  
  /** Password context for domain separation (default: 'account') */
  context?: PasswordContext;
}

/**
 * Options for file decryption
 */
export interface FileDecryptionOptions {
  /** Additional authenticated data (must match encryption) */
  additionalData?: Uint8Array;
  
  /** Password context for domain separation (default: 'account') */
  context?: PasswordContext;
}

/**
 * OPAQUE client state (stored during multi-step flows)
 */
export interface OpaqueClientState {
  /** Username */
  username: string;
  
  /** Flow type */
  flow: 'registration' | 'authentication';
  
  /** Serialized client state */
  state: Uint8Array;
  
  /** Timestamp when state was created */
  createdAt: number;
}

// ============================================================================
// File Encryption Types
// ============================================================================

/**
 * Encrypted file metadata
 */
export interface EncryptedFileMetadata {
  /** Protocol version */
  version: number;
  
  /** Original filename */
  filename: string;
  
  /** Original file size in bytes */
  size: number;
  
  /** MIME type */
  mimeType: string;
  
  /** Encryption timestamp */
  encryptedAt: number;
  
  /** Username (for salt derivation) */
  username: string;
}

/**
 * Encrypted file header
 */
export interface EncryptedFileHeader {
  /** Protocol version */
  version: number;
  
  /** IV/Nonce for AES-GCM */
  iv: Uint8Array;
  
  /** Encrypted metadata */
  encryptedMetadata: Uint8Array;
  
  /** Authentication tag for metadata */
  metadataTag: Uint8Array;
}

/**
 * Encrypted file structure
 */
export interface EncryptedFile {
  /** File header */
  header: EncryptedFileHeader;
  
  /** Encrypted file data */
  data: Uint8Array;
  
  /** Authentication tag for data */
  dataTag: Uint8Array;
}

/**
 * Decrypted file result
 */
export interface DecryptedFile {
  /** Original file data */
  data: Uint8Array;
  
  /** File metadata */
  metadata: EncryptedFileMetadata;
}

// ============================================================================
// Salt Derivation Types
// ============================================================================

/**
 * Salt derivation parameters
 */
export interface SaltDerivationParams {
  /** Username (input) */
  username: string;
  
  /** Domain separation string */
  domain: string;
  
  /** Output salt length in bytes */
  length: number;
}

/**
 * Derived salt
 */
export interface DerivedSalt {
  /** The salt bytes */
  salt: Uint8Array;
  
  /** Username used for derivation */
  username: string;
  
  /** Domain used for derivation */
  domain: string;
}

// ============================================================================
// Key Derivation Types
// ============================================================================

/**
 * Argon2id key derivation parameters
 */
export interface Argon2Params {
  /** Memory cost in KiB */
  memoryCost: number;
  
  /** Time cost (iterations) */
  timeCost: number;
  
  /** Parallelism factor */
  parallelism: number;
  
  /** Output key length in bytes */
  keyLength: number;
  
  /** Argon2 variant (2 = Argon2id) */
  variant: 2;
}

/**
 * Key derivation request
 */
export interface KeyDerivationRequest {
  /** Password */
  password: string;
  
  /** Salt */
  salt: Uint8Array;
  
  /** Argon2 parameters */
  params: Argon2Params;
}

/**
 * Key derivation result
 */
export interface KeyDerivationResult {
  /** Derived key */
  key: Uint8Array;
  
  /** Time taken in milliseconds */
  duration: number;
}

// ============================================================================
// Encryption/Decryption Types
// ============================================================================

/**
 * Encryption request
 */
export interface EncryptionRequest {
  /** Data to encrypt */
  data: Uint8Array;
  
  /** Encryption key */
  key: Uint8Array;
  
  /** Optional additional authenticated data */
  aad?: Uint8Array;
}

/**
 * Encryption result
 */
export interface EncryptionResult {
  /** Encrypted data */
  ciphertext: Uint8Array;
  
  /** IV/Nonce used */
  iv: Uint8Array;
  
  /** Authentication tag */
  tag: Uint8Array;
}

/**
 * Decryption request
 */
export interface DecryptionRequest {
  /** Encrypted data */
  ciphertext: Uint8Array;
  
  /** Decryption key */
  key: Uint8Array;
  
  /** IV/Nonce */
  iv: Uint8Array;
  
  /** Authentication tag */
  tag: Uint8Array;
  
  /** Optional additional authenticated data */
  aad?: Uint8Array;
}

/**
 * Decryption result
 */
export interface DecryptionResult {
  /** Decrypted data */
  plaintext: Uint8Array;
}

// ============================================================================
// Storage Types
// ============================================================================

/**
 * Cached key in sessionStorage
 */
export interface CachedKey {
  /** Key type */
  type: 'file-encryption' | 'session';
  
  /** Base64-encoded key */
  key: string;
  
  /** Username (for file encryption keys) */
  username?: string;
  
  /** Timestamp when cached */
  cachedAt: number;
  
  /** Expiration timestamp */
  expiresAt?: number;
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Result type for operations that can fail
 */
export type Result<T, E = Error> = 
  | { success: true; value: T }
  | { success: false; error: E };

/**
 * Async result type
 */
export type AsyncResult<T, E = Error> = Promise<Result<T, E>>;

/**
 * Base64-encoded string
 */
export type Base64String = string;

/**
 * Hex-encoded string
 */
export type HexString = string;

/**
 * Timestamp in milliseconds since epoch
 */
export type Timestamp = number;

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard for FileEncryptionKey
 */
export function isFileEncryptionKey(key: unknown): key is FileEncryptionKey {
  return (
    typeof key === 'object' &&
    key !== null &&
    'key' in key &&
    key.key instanceof Uint8Array &&
    'username' in key &&
    typeof key.username === 'string' &&
    'derivedAt' in key &&
    typeof key.derivedAt === 'number'
  );
}

/**
 * Type guard for OpaqueExportKey
 */
export function isOpaqueExportKey(key: unknown): key is OpaqueExportKey {
  return (
    typeof key === 'object' &&
    key !== null &&
    'key' in key &&
    key.key instanceof Uint8Array &&
    'generatedAt' in key &&
    typeof key.generatedAt === 'number'
  );
}

/**
 * Type guard for SessionKey
 */
export function isSessionKey(key: unknown): key is SessionKey {
  return (
    typeof key === 'object' &&
    key !== null &&
    'key' in key &&
    key.key instanceof Uint8Array &&
    'derivedAt' in key &&
    typeof key.derivedAt === 'number' &&
    'expiresAt' in key &&
    typeof key.expiresAt === 'number'
  );
}

/**
 * Type guard for Result success
 */
export function isSuccess<T, E>(result: Result<T, E>): result is { success: true; value: T } {
  return result.success === true;
}

/**
 * Type guard for Result failure
 */
export function isFailure<T, E>(result: Result<T, E>): result is { success: false; error: E } {
  return result.success === false;
}
