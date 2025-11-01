/**
 * TypeScript wrapper for WASM share crypto functions
 * Anonymous Share System
 * 
 * This module provides TypeScript interfaces for Go/WASM cryptographic operations.
 * All actual crypto work is done in Go/WASM for security and performance.
 */

// Type definitions for share crypto operations
export interface ShareSalt {
    success: boolean;
    salt?: Uint8Array;
    error?: string;
}

export interface ShareKeyResult {
    success: boolean;
    shareKey?: Uint8Array;
    error?: string;
}

export interface FEKEncryptionResult {
    success: boolean;
    encryptedFEK?: Uint8Array;
    error?: string;
}

export interface FEKDecryptionResult {
    success: boolean;
    fek?: Uint8Array;
    error?: string;
}

export interface PasswordValidationResult {
    success: boolean;
    entropy: number;
    strength_score: number;
    feedback: string[];
    meets_requirements: boolean;
    pattern_penalties: string[];
    error?: string;
}

// Declare WASM functions that are available globally
declare global {
    function generateSecureShareSaltWASM(): ShareSalt;
    function deriveShareKeyFromPasswordWASM(password: string, salt: Uint8Array): ShareKeyResult;
    function encryptFEKWithShareKeyWASM(fek: Uint8Array, shareKey: Uint8Array): FEKEncryptionResult;
    function decryptFEKWithShareKeyWASM(encryptedFEK: Uint8Array, shareKey: Uint8Array): FEKDecryptionResult;
    function validateSharePasswordEntropyWASM(password: string): PasswordValidationResult;
    function getPasswordRequirementsWASM(passwordType: string): { minLength: number; minEntropy: number; error?: string };
}

/**
 * ShareCrypto class provides TypeScript interface to Go/WASM share crypto functions
 */
export class ShareCrypto {
    
    /**
     * Generates a cryptographically secure 32-byte salt for Argon2id
     */
    static generateSecureSalt(): ShareSalt {
        if (typeof generateSecureShareSaltWASM !== 'function') {
            return {
                success: false,
                error: 'WASM crypto functions not available'
            };
        }
        return generateSecureShareSaltWASM();
    }

    /**
     * Derives share key from password using Argon2id with secure parameters
     * - 128MB memory, 4 iterations, 4 threads
     * - 32-byte output key
     * 
     * @param password Share password (minimum length enforced by backend)
     * @param salt 32-byte salt
     */
    static deriveShareKey(password: string, salt: Uint8Array): ShareKeyResult {
        if (typeof deriveShareKeyFromPasswordWASM !== 'function') {
            return {
                success: false,
                error: 'WASM crypto functions not available'
            };
        }

        // Note: Password length validation is handled by backend WASM function
        if (!password) {
            return {
                success: false,
                error: 'Share password cannot be empty'
            };
        }

        if (!salt || salt.length !== 32) {
            return {
                success: false,
                error: 'Salt must be exactly 32 bytes'
            };
        }

        return deriveShareKeyFromPasswordWASM(password, salt);
    }

    /**
     * Encrypts a File Encryption Key (FEK) with the derived share key using AES-GCM
     * 
     * @param fek 32-byte File Encryption Key
     * @param shareKey 32-byte share key derived from Argon2id
     */
    static encryptFEKWithShareKey(fek: Uint8Array, shareKey: Uint8Array): FEKEncryptionResult {
        if (typeof encryptFEKWithShareKeyWASM !== 'function') {
            return {
                success: false,
                error: 'WASM crypto functions not available'
            };
        }

        if (!fek || fek.length !== 32) {
            return {
                success: false,
                error: 'FEK must be exactly 32 bytes'
            };
        }

        if (!shareKey || shareKey.length !== 32) {
            return {
                success: false,
                error: 'Share key must be exactly 32 bytes'
            };
        }

        return encryptFEKWithShareKeyWASM(fek, shareKey);
    }

    /**
     * Decrypts a File Encryption Key (FEK) with the derived share key using AES-GCM
     * 
     * @param encryptedFEK Encrypted FEK (includes nonce and auth tag)
     * @param shareKey 32-byte share key derived from Argon2id
     */
    static decryptFEKWithShareKey(encryptedFEK: Uint8Array, shareKey: Uint8Array): FEKDecryptionResult {
        if (typeof decryptFEKWithShareKeyWASM !== 'function') {
            return {
                success: false,
                error: 'WASM crypto functions not available'
            };
        }

        if (!encryptedFEK || encryptedFEK.length < 28) {
            return {
                success: false,
                error: 'Encrypted FEK too short'
            };
        }

        if (!shareKey || shareKey.length !== 32) {
            return {
                success: false,
                error: 'Share key must be exactly 32 bytes'
            };
        }

        return decryptFEKWithShareKeyWASM(encryptedFEK, shareKey);
    }

    /**
     * Validates share password entropy (requires 60+ bits for anonymous shares)
     * 
     * @param password Password to validate
     */
    static validateSharePassword(password: string): PasswordValidationResult {
        if (typeof validateSharePasswordEntropyWASM !== 'function') {
            return {
                success: false,
                entropy: 0,
                strength_score: 0,
                feedback: ['WASM crypto functions not available'],
                meets_requirements: false,
                pattern_penalties: [],
                error: 'WASM crypto functions not available'
            };
        }

        if (!password) {
            return {
                success: false,
                entropy: 0,
                strength_score: 0,
                feedback: ['Password cannot be empty'],
                meets_requirements: false,
                pattern_penalties: [],
                error: 'Password cannot be empty'
            };
        }

        return validateSharePasswordEntropyWASM(password);
    }

    /**
     * Utility function to convert base64 string to Uint8Array
     */
    static base64ToUint8Array(base64: string): Uint8Array {
        try {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        } catch (error) {
            throw new Error('Invalid base64 string');
        }
    }

    /**
     * Utility function to convert Uint8Array to base64 string
     */
    static uint8ArrayToBase64(bytes: Uint8Array): string {
        try {
            let binaryString = '';
            for (let i = 0; i < bytes.length; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }
            return btoa(binaryString);
        } catch (error) {
            throw new Error('Failed to convert bytes to base64');
        }
    }

    /**
     * Checks if WASM crypto functions are available
     */
    static isWASMAvailable(): boolean {
        return typeof generateSecureShareSaltWASM === 'function' &&
               typeof deriveShareKeyFromPasswordWASM === 'function' &&
               typeof encryptFEKWithShareKeyWASM === 'function' &&
               typeof decryptFEKWithShareKeyWASM === 'function' &&
               typeof validateSharePasswordEntropyWASM === 'function';
    }

    /**
     * Updates password input placeholder with actual requirements from Go constants
     */
    static async updatePasswordPlaceholder(inputElement: HTMLInputElement, type: 'share' | 'account' = 'share'): Promise<void> {
        try {
            // Get requirements from WASM
            if (typeof window.getPasswordRequirementsWASM === 'function') {
                const reqs = window.getPasswordRequirementsWASM(type);
                if (reqs && reqs.minLength) {
                    inputElement.placeholder = `Enter a strong password (${reqs.minLength}+ characters)`;
                    inputElement.setAttribute('minlength', reqs.minLength.toString());
                }
            }
        } catch (error) {
            console.warn('Failed to update password placeholder:', error);
        }
    }

    /**
     * Gets a user-friendly error message for crypto failures
     */
    static getErrorMessage(error: string): string {
        const errorMap: { [key: string]: string } = {
            'WASM crypto functions not available': 'Cryptographic functions are not loaded. Please refresh the page.',
            'Share password cannot be empty': 'Please enter a share password.',
            'Salt must be exactly 32 bytes': 'Invalid cryptographic salt format.',
            'FEK must be exactly 32 bytes': 'Invalid file encryption key format.',
            'Share key must be exactly 32 bytes': 'Invalid share key format.',
            'Encrypted FEK too short': 'Invalid encrypted file data.',
            'Failed to decrypt FEK': 'Incorrect password or corrupted data.',
            'Failed to encrypt FEK': 'Encryption failed. Please try again.',
            'Password cannot be empty': 'Please enter a password.'
        };

        return errorMap[error] || error || 'An unknown error occurred.';
    }
}

// Export for ES6 modules
export default ShareCrypto;
