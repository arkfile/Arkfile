/**
 * Cryptographic Error Classes
 * 
 * Defines custom error types for all cryptographic operations.
 * These errors provide detailed context for debugging and user feedback.
 */

// ============================================================================
// Base Crypto Error
// ============================================================================

/**
 * Base class for all cryptographic errors
 */
export class CryptoError extends Error {
  /** Error code for programmatic handling */
  public readonly code: string;
  
  /** Additional context about the error */
  public readonly context?: Record<string, unknown>;
  
  /** Timestamp when error occurred */
  public readonly timestamp: number;
  
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
    this.context = context ?? undefined;
    this.timestamp = Date.now();
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    const errorConstructor = Error as any;
    if (errorConstructor.captureStackTrace) {
      errorConstructor.captureStackTrace(this, this.constructor);
    }
  }
}

// ============================================================================
// Key Derivation Errors
// ============================================================================

/**
 * Error during key derivation (Argon2id)
 */
export class KeyDerivationError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'KEY_DERIVATION_ERROR', context);
    this.name = 'KeyDerivationError';
  }
}

/**
 * Error when key derivation times out
 */
export class KeyDerivationTimeoutError extends KeyDerivationError {
  constructor(timeout: number) {
    super(
      `Key derivation timed out after ${timeout}ms`,
      { timeout }
    );
    this.name = 'KeyDerivationTimeoutError';
  }
}

/**
 * Error when Argon2 parameters are invalid
 */
export class InvalidArgon2ParamsError extends KeyDerivationError {
  constructor(reason: string, params: Record<string, unknown>) {
    super(
      `Invalid Argon2 parameters: ${reason}`,
      { reason, params }
    );
    this.name = 'InvalidArgon2ParamsError';
  }
}

// ============================================================================
// Encryption/Decryption Errors
// ============================================================================

/**
 * Error during encryption
 */
export class EncryptionError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'ENCRYPTION_ERROR', context);
    this.name = 'EncryptionError';
  }
}

/**
 * Error during decryption
 */
export class DecryptionError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'DECRYPTION_ERROR', context);
    this.name = 'DecryptionError';
  }
}

/**
 * Error when authentication tag verification fails
 */
export class AuthenticationError extends DecryptionError {
  constructor(message: string = 'Authentication tag verification failed') {
    super(message, { reason: 'invalid_tag' });
    this.name = 'AuthenticationError';
  }
}

/**
 * Error when encrypted data is corrupted
 */
export class CorruptedDataError extends DecryptionError {
  constructor(reason: string) {
    super(
      `Encrypted data is corrupted: ${reason}`,
      { reason }
    );
    this.name = 'CorruptedDataError';
  }
}

/**
 * Error when file is too large for encryption
 */
export class FileTooLargeError extends EncryptionError {
  constructor(size: number, maxSize: number) {
    super(
      `File size ${size} bytes exceeds maximum ${maxSize} bytes`,
      { size, maxSize }
    );
    this.name = 'FileTooLargeError';
  }
}

// ============================================================================
// OPAQUE Protocol Errors
// ============================================================================

/**
 * Base error for OPAQUE protocol operations
 */
export class OpaqueError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'OPAQUE_ERROR', context);
    this.name = 'OpaqueError';
  }
}

/**
 * Error during OPAQUE registration
 */
export class OpaqueRegistrationError extends OpaqueError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context);
    this.name = 'OpaqueRegistrationError';
  }
}

/**
 * Error during OPAQUE authentication
 */
export class OpaqueAuthenticationError extends OpaqueError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context);
    this.name = 'OpaqueAuthenticationError';
  }
}

/**
 * Error when OPAQUE server response is invalid
 */
export class InvalidOpaqueResponseError extends OpaqueError {
  constructor(reason: string) {
    super(
      `Invalid OPAQUE server response: ${reason}`,
      { reason }
    );
    this.name = 'InvalidOpaqueResponseError';
  }
}

/**
 * Error when OPAQUE client state is missing or invalid
 */
export class InvalidOpaqueStateError extends OpaqueError {
  constructor(reason: string) {
    super(
      `Invalid OPAQUE client state: ${reason}`,
      { reason }
    );
    this.name = 'InvalidOpaqueStateError';
  }
}

// ============================================================================
// Salt Derivation Errors
// ============================================================================

/**
 * Error during salt derivation
 */
export class SaltDerivationError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'SALT_DERIVATION_ERROR', context);
    this.name = 'SaltDerivationError';
  }
}

/**
 * Error when username is invalid for salt derivation
 */
export class InvalidUsernameError extends SaltDerivationError {
  constructor(reason: string) {
    super(
      `Invalid username for salt derivation: ${reason}`,
      { reason }
    );
    this.name = 'InvalidUsernameError';
  }
}

// ============================================================================
// Key Management Errors
// ============================================================================

/**
 * Error when a key is invalid
 */
export class InvalidKeyError extends CryptoError {
  constructor(reason: string, context?: Record<string, unknown>) {
    super(
      `Invalid key: ${reason}`,
      'INVALID_KEY_ERROR',
      context
    );
    this.name = 'InvalidKeyError';
  }
}

/**
 * Error when a key has wrong length
 */
export class InvalidKeyLengthError extends InvalidKeyError {
  constructor(actual: number, expected: number) {
    super(
      `Key length mismatch: expected ${expected} bytes, got ${actual} bytes`,
      { actual, expected }
    );
    this.name = 'InvalidKeyLengthError';
  }
}

/**
 * Error when a key is expired
 */
export class ExpiredKeyError extends CryptoError {
  constructor(keyType: string, expiresAt: number) {
    super(
      `${keyType} key expired at ${new Date(expiresAt).toISOString()}`,
      'EXPIRED_KEY_ERROR',
      { keyType, expiresAt }
    );
    this.name = 'ExpiredKeyError';
  }
}

/**
 * Error when a key is not found in storage
 */
export class KeyNotFoundError extends CryptoError {
  constructor(keyType: string) {
    super(
      `${keyType} key not found in storage`,
      'KEY_NOT_FOUND_ERROR',
      { keyType }
    );
    this.name = 'KeyNotFoundError';
  }
}

// ============================================================================
// Storage Errors
// ============================================================================

/**
 * Error during storage operations
 */
export class StorageError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'STORAGE_ERROR', context);
    this.name = 'StorageError';
  }
}

/**
 * Error when storage is not available
 */
export class StorageUnavailableError extends StorageError {
  constructor(storageType: 'sessionStorage' | 'localStorage') {
    super(
      `${storageType} is not available`,
      { storageType }
    );
    this.name = 'StorageUnavailableError';
  }
}

/**
 * Error when storage quota is exceeded
 */
export class StorageQuotaExceededError extends StorageError {
  constructor() {
    super('Storage quota exceeded');
    this.name = 'StorageQuotaExceededError';
  }
}

// ============================================================================
// Protocol Version Errors
// ============================================================================

/**
 * Error when protocol version is unsupported
 */
export class UnsupportedProtocolVersionError extends CryptoError {
  constructor(version: number, supportedVersion: number) {
    super(
      `Unsupported protocol version ${version}, expected ${supportedVersion}`,
      'UNSUPPORTED_PROTOCOL_VERSION',
      { version, supportedVersion }
    );
    this.name = 'UnsupportedProtocolVersionError';
  }
}

// ============================================================================
// Web Crypto API Errors
// ============================================================================

/**
 * Error when Web Crypto API is not available
 */
export class WebCryptoUnavailableError extends CryptoError {
  constructor() {
    super(
      'Web Crypto API is not available in this environment',
      'WEB_CRYPTO_UNAVAILABLE'
    );
    this.name = 'WebCryptoUnavailableError';
  }
}

/**
 * Error during Web Crypto API operations
 */
export class WebCryptoError extends CryptoError {
  constructor(operation: string, originalError: Error) {
    super(
      `Web Crypto API error during ${operation}: ${originalError.message}`,
      'WEB_CRYPTO_ERROR',
      { operation, originalError: originalError.message }
    );
    this.name = 'WebCryptoError';
  }
}

// ============================================================================
// Validation Errors
// ============================================================================

/**
 * Error when input validation fails
 */
export class ValidationError extends CryptoError {
  constructor(field: string, reason: string) {
    super(
      `Validation failed for ${field}: ${reason}`,
      'VALIDATION_ERROR',
      { field, reason }
    );
    this.name = 'ValidationError';
  }
}

/**
 * Error when password is invalid
 */
export class InvalidPasswordError extends ValidationError {
  constructor(reason: string) {
    super('password', reason);
    this.name = 'InvalidPasswordError';
  }
}

// ============================================================================
// Network Errors
// ============================================================================

/**
 * Error during network operations
 */
export class NetworkError extends CryptoError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'NETWORK_ERROR', context);
    this.name = 'NetworkError';
  }
}

/**
 * Error when server returns an error
 */
export class ServerError extends NetworkError {
  constructor(statusCode: number, message: string) {
    super(
      `Server error (${statusCode}): ${message}`,
      { statusCode, message }
    );
    this.name = 'ServerError';
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Wraps an unknown error in a CryptoError
 */
export function wrapError(error: unknown, defaultMessage: string): CryptoError {
  if (error instanceof CryptoError) {
    return error;
  }
  
  if (error instanceof Error) {
    return new CryptoError(
      error.message || defaultMessage,
      'WRAPPED_ERROR',
      { originalError: error.message, stack: error.stack }
    );
  }
  
  return new CryptoError(
    defaultMessage,
    'UNKNOWN_ERROR',
    { originalError: String(error) }
  );
}

/**
 * Type guard to check if an error is a CryptoError
 */
export function isCryptoError(error: unknown): error is CryptoError {
  return error instanceof CryptoError;
}

/**
 * Extracts a user-friendly error message from any error
 */
export function getUserFriendlyMessage(error: unknown): string {
  if (error instanceof AuthenticationError) {
    return 'Authentication failed. The file may have been tampered with or the password is incorrect.';
  }
  
  if (error instanceof CorruptedDataError) {
    return 'The encrypted data is corrupted and cannot be decrypted.';
  }
  
  if (error instanceof ExpiredKeyError) {
    return 'Your session has expired. Please log in again.';
  }
  
  if (error instanceof FileTooLargeError) {
    return 'The file is too large to encrypt. Maximum size is 5GB.';
  }
  
  if (error instanceof InvalidPasswordError) {
    return 'Invalid password. Please check your password and try again.';
  }
  
  if (error instanceof KeyDerivationTimeoutError) {
    return 'Key derivation took too long. Please try again.';
  }
  
  if (error instanceof OpaqueAuthenticationError) {
    return 'Authentication failed. Please check your credentials and try again.';
  }
  
  if (error instanceof ServerError) {
    return 'Server error. Please try again later.';
  }
  
  if (error instanceof StorageQuotaExceededError) {
    return 'Storage quota exceeded. Please clear some space and try again.';
  }
  
  if (error instanceof UnsupportedProtocolVersionError) {
    return 'This file was encrypted with an unsupported version. Please update your application.';
  }
  
  if (error instanceof WebCryptoUnavailableError) {
    return 'Your browser does not support the required cryptographic features.';
  }
  
  if (error instanceof CryptoError) {
    return error.message;
  }
  
  if (error instanceof Error) {
    return error.message;
  }
  
  return 'An unknown error occurred.';
}
