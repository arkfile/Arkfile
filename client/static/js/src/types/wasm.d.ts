/**
 * TypeScript definitions for ArkFile Go/WASM interface functions
 * These functions are exported from Go/WASM and available globally
 */

// Password validation types
declare global {
  interface PasswordValidationResult {
    valid: boolean;
    score: number;
    message: string;
    requirements: string[];
    missing: string[];
  }

  interface PasswordConfirmationResult {
    match: boolean;
    message: string;
    status: 'match' | 'no-match' | 'empty' | 'error';
  }

  // Session management types
  interface SecureSessionResult {
    success: boolean;
    message?: string;
    error?: string;
  }

  interface SessionValidationResult {
    valid: boolean;
    message?: string;
    error?: string;
  }

  // File encryption/decryption types
  interface FileEncryptionResult {
    success: boolean;
    data?: string; // Base64 encoded encrypted data
    error?: string;
  }

  interface FileDecryptionResult {
    success: boolean;
    data?: string; // Base64 encoded decrypted data
    error?: string;
  }

  // TOTP types
  interface TOTPValidationResult {
    valid: boolean;
    message?: string;
    error?: string;
  }

  interface TOTPSetupData {
    secret: string;
    qrCodeUrl: string;
    manualEntry: string;
    backupCodes: string[];
  }

  interface TOTPSetupResult {
    success: boolean;
    data?: TOTPSetupData;
    error?: string;
  }

  // Device capability types (for backwards compatibility)
  interface DeviceCapabilityResult {
    capability: string;
    memory: number;
    description: string;
  }

  interface PerformanceInfo {
    deviceCapability: string;
    recommendedProfile: {
      time: number;
      memory: number;
      threads: number;
      keyLen: number;
    };
    benchmarks: {
      interactive: number;
      balanced: number;
      maximum: number;
    };
  }
}

// Global WASM function declarations
declare global {
  // Password validation functions (Phase 1 - IMPLEMENTED)
  function validatePasswordComplexity(password: string): PasswordValidationResult;
  function validatePasswordConfirmation(password: string, confirm: string): PasswordConfirmationResult;

  // Secure session management functions (Phase 1 - IMPLEMENTED)
  function createSecureSessionFromOpaqueExport(opaqueExport: string, userEmail: string): SecureSessionResult;
  function encryptFileWithSecureSession(fileData: Uint8Array, userEmail: string): FileEncryptionResult;
  function decryptFileWithSecureSession(encryptedData: string, userEmail: string): FileDecryptionResult;
  function validateSecureSession(userEmail: string): SessionValidationResult;
  function clearSecureSession(userEmail: string): SecureSessionResult;

  // Multi-key encryption with secure sessions (Phase 1 - IMPLEMENTED)
  function encryptFileMultiKeyWithSecureSession(
    fileData: Uint8Array,
    userEmail: string,
    primaryType: string,
    additionalKeys: Array<{ password: string; id: string }>
  ): FileEncryptionResult;
  function decryptFileMultiKeyWithSecureSession(encryptedData: string, userEmail: string): FileDecryptionResult;
  function addKeyToEncryptedFileWithSecureSession(
    encryptedData: string,
    userEmail: string,
    newPassword: string,
    keyId: string
  ): FileEncryptionResult;

  // TOTP validation functions (Phase 1 - IMPLEMENTED)
  function validateTOTPCodeWASM(code: string, userEmail: string): TOTPValidationResult;
  function validateBackupCodeWASM(code: string, userEmail: string): TOTPValidationResult;
  function generateTOTPSetupDataWASM(userEmail: string): TOTPSetupResult;
  function verifyTOTPSetupWASM(code: string, secret: string, userEmail: string): TOTPValidationResult;

  // Legacy file encryption functions (existing - maintained for compatibility)
  function encryptFile(fileData: Uint8Array, password: string): string;
  function decryptFile(encryptedData: string, password: string): string | Uint8Array;
  function encryptFileMultiKey(
    fileData: Uint8Array,
    primaryPassword: string,
    primaryType: string,
    additionalKeys: Array<{ password: string; id: string }>
  ): string;
  function decryptFileMultiKey(encryptedData: string, password: string): string | Uint8Array;
  function addKeyToEncryptedFile(
    encryptedData: string,
    currentPassword: string,
    newPassword: string,
    newKeyId: string
  ): string;
  function calculateSHA256(fileData: Uint8Array): string;

  // Device capability functions (maintained for backwards compatibility)
  function detectDeviceCapability(): string;
  function deviceCapabilityAutoDetect(): DeviceCapabilityResult;
  function benchmarkArgonProfile(time: number, memory: number, threads: number): { duration_ms: number };
  function getRecommendedProfile(): { time: number; memory: number; threads: number; keyLen: number };
  function getPerformanceInfo(): PerformanceInfo;

  // OPAQUE health check
  function opaqueHealthCheck(): { wasmReady: boolean; timestamp: number; opaqueReady: boolean };

  // Phase 6B: Anonymous Share System WASM Functions
  function generateSecureShareSaltWASM(): { success: boolean; salt?: Uint8Array; error?: string };
  function deriveShareKeyFromPasswordWASM(password: string, salt: Uint8Array): { success: boolean; shareKey?: Uint8Array; error?: string };
  function encryptFEKWithShareKeyWASM(fek: Uint8Array, shareKey: Uint8Array): { success: boolean; encryptedFEK?: Uint8Array; error?: string };
  function decryptFEKWithShareKeyWASM(encryptedFEK: Uint8Array, shareKey: Uint8Array): { success: boolean; fek?: Uint8Array; error?: string };
  function validateSharePasswordEntropyWASM(password: string): { success: boolean; entropy: number; strength_score: number; feedback: string[]; meets_requirements: boolean; pattern_penalties: string[]; error?: string };
  function decryptFileWithFEKWASM(encryptedFileBase64: string, fek: Uint8Array): { success: boolean; data?: string; error?: string };

  // Metadata Encryption/Decryption Functions (Phase 7: Encrypted Metadata)
  function encryptFileMetadata(exportKey: string, username: string, filename: string, sha256sum: string): {
    success: boolean;
    encryptedFilename?: string;
    filenameNonce?: string;
    encryptedSha256sum?: string;
    sha256sumNonce?: string;
    error?: string;
  };
  function decryptFileMetadata(exportKey: string, username: string, encryptedFilename: string, filenameNonce: string, encryptedSha256sum: string, sha256sumNonce: string): {
    success: boolean;
    filename?: string;
    sha256sum?: string;
    error?: string;
  };

  // Utility functions that might be exposed
  var arrayBufferToBase64: ((buffer: ArrayBuffer) => string) | undefined;
  var base64ToArrayBuffer: ((base64: string) => ArrayBuffer) | undefined;
}

// Export empty object to make this a module
export {};
