/**
 * Security utilities for ArkFile
 * Provides interfaces to Go/WASM cryptographic functions
 */

// Create a namespace for security utilities
window.securityUtils = (function() {
    'use strict';

    // Flag to track WASM initialization
    let wasmInitialized = false;
    
    // This will be populated with functions from WASM
    const wasmFunctions = {
        encryptFile: null,
        decryptFile: null,
        encryptFileMultiKey: null,
        decryptFileMultiKey: null,
        addKeyToEncryptedFile: null,
        calculateSHA256: null
    };

    /**
     * Ensures WASM is initialized before operations
     * @returns {Promise<void>}
     */
    async function ensureWasmInitialized() {
        if (!wasmInitialized) {
            // Wait for WASM to be fully initialized
            if (typeof window.arkfileWasm !== 'undefined' && 
                typeof window.arkfileWasm.ready === 'function') {
                
                await window.arkfileWasm.ready();
                
                // Map WASM functions to our interface
                wasmFunctions.encryptFile = window.arkfileWasm.encryptFile;
                wasmFunctions.decryptFile = window.arkfileWasm.decryptFile;
                wasmFunctions.encryptFileMultiKey = window.arkfileWasm.encryptFileMultiKey;
                wasmFunctions.decryptFileMultiKey = window.arkfileWasm.decryptFileMultiKey;
                wasmFunctions.addKeyToEncryptedFile = window.arkfileWasm.addKeyToEncryptedFile;
                wasmFunctions.calculateSHA256 = window.arkfileWasm.calculateSHA256;
                
                wasmInitialized = true;
            } else {
                throw new Error('WASM module not available');
            }
        }
        
        return Promise.resolve();
    }

    /**
     * Validates password complexity using WASM
     * @param {string} password - Password to validate
     * @returns {Object} - Validation result {valid: boolean, message: string}
     */
    function validatePassword(password) {
        if (typeof window.validatePasswordComplexity === 'function') {
            const result = window.validatePasswordComplexity(password);
            return result; // Returns {valid: boolean, message: string}
        }
        
        // Fallback validation if WASM is not available
        if (!password) {
            return { valid: false, message: 'Password is required' };
        }

        if (password.length < 14) {
            return { valid: false, message: 'Password must be at least 14 characters long' };
        }

        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSymbol = /[`~!@#$%^&*()-_=+\[\]{}|;:,.<>?]/.test(password);

        if (!hasUppercase) {
            return { valid: false, message: 'Password must contain at least one uppercase letter' };
        }
        if (!hasLowercase) {
            return { valid: false, message: 'Password must contain at least one lowercase letter' };
        }
        if (!hasNumber) {
            return { valid: false, message: 'Password must contain at least one digit' };
        }
        if (!hasSymbol) {
            return { valid: false, message: 'Password must contain at least one special character: `~!@#$%^&*()-_=+[]{}|;:,.<>?' };
        }

        return { valid: true, message: 'Password meets requirements' };
    }

    /**
     * Converts an ArrayBuffer to a Base64 string
     * @param {ArrayBuffer} buffer - The ArrayBuffer to convert
     * @returns {string} - Base64 string
     */
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Converts a Base64 string to an ArrayBuffer
     * @param {string} base64 - The Base64 string to convert
     * @returns {ArrayBuffer} - Converted ArrayBuffer
     */
    function base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Encrypts a file using a password via WASM
     * @param {ArrayBuffer|Uint8Array} fileData - File data to encrypt
     * @param {string} password - Password for encryption
     * @returns {Promise<string>} - Base64 encoded encrypted data
     */
    async function encryptFile(fileData, password) {
        try {
            await ensureWasmInitialized();
            
            // Ensure fileData is in the right format for WASM
            const fileBytes = fileData instanceof ArrayBuffer ? 
                new Uint8Array(fileData) : fileData;
            
            // Call the WASM encryption function
            const encryptedData = await wasmFunctions.encryptFile(fileBytes, password);
            
            return encryptedData; // WASM already returns a base64 string
        } catch (error) {
            console.error('File encryption error:', error);
            throw new Error('Failed to encrypt file: ' + error.message);
        }
    }

    /**
     * Decrypts a file using a password via WASM
     * @param {string} encryptedData - Base64 encoded encrypted data
     * @param {string} password - Password for decryption
     * @returns {Promise<ArrayBuffer>} - Decrypted file data
     */
    async function decryptFile(encryptedData, password) {
        try {
            await ensureWasmInitialized();
            
            // Call the WASM decryption function
            const result = await wasmFunctions.decryptFile(encryptedData, password);
            
            // The WASM function might return either a Uint8Array or an error message
            if (typeof result === 'string' && result.startsWith('Failed')) {
                return result; // Return error message
            }
            
            return result.buffer; // Convert Uint8Array to ArrayBuffer
        } catch (error) {
            console.error('File decryption error:', error);
            return 'Failed: ' + error.message;
        }
    }

    /**
     * Encrypts a file with multiple encryption keys via WASM
     * @param {ArrayBuffer|Uint8Array} fileData - File data to encrypt
     * @param {string} primaryPassword - Primary password for encryption
     * @param {string} primaryType - Primary password type ('account' or 'custom')
     * @param {Array} additionalKeys - Array of {password, id} objects for additional keys
     * @returns {Promise<string>} - Base64 encoded encrypted data with multi-key metadata
     */
    async function encryptFileMultiKey(fileData, primaryPassword, primaryType, additionalKeys = []) {
        try {
            await ensureWasmInitialized();
            
            // Ensure fileData is in the right format for WASM
            const fileBytes = fileData instanceof ArrayBuffer ? 
                new Uint8Array(fileData) : fileData;
            
            // Call the WASM multi-key encryption function
            const encryptedData = await wasmFunctions.encryptFileMultiKey(
                fileBytes, 
                primaryPassword, 
                primaryType, 
                additionalKeys
            );
            
            return encryptedData; // WASM already returns a base64 string
        } catch (error) {
            console.error('Multi-key file encryption error:', error);
            throw new Error('Failed to encrypt file with multiple keys: ' + error.message);
        }
    }

    /**
     * Decrypts a multi-key encrypted file via WASM
     * @param {string} encryptedData - Base64 encoded encrypted data
     * @param {string} password - Password for decryption (any of the keys)
     * @returns {Promise<ArrayBuffer>} - Decrypted file data
     */
    async function decryptFileMultiKey(encryptedData, password) {
        try {
            await ensureWasmInitialized();
            
            // Call the WASM multi-key decryption function
            const result = await wasmFunctions.decryptFileMultiKey(encryptedData, password);
            
            // The WASM function might return either a Uint8Array or an error message
            if (typeof result === 'string' && result.startsWith('Failed')) {
                return result; // Return error message
            }
            
            return result.buffer; // Convert Uint8Array to ArrayBuffer
        } catch (error) {
            console.error('Multi-key file decryption error:', error);
            return 'Failed: ' + error.message;
        }
    }

    /**
     * Adds an additional key to an existing encrypted file via WASM
     * @param {string} encryptedData - Base64 encoded encrypted data
     * @param {string} currentPassword - Current password that can decrypt the file
     * @param {string} newPassword - New password to add as an additional key
     * @param {string} newKeyId - ID for the new key
     * @returns {Promise<string>} - Updated encrypted data with the new key
     */
    async function addKeyToEncryptedFile(encryptedData, currentPassword, newPassword, newKeyId) {
        try {
            await ensureWasmInitialized();
            
            // Call the WASM function to add a key
            const updatedData = await wasmFunctions.addKeyToEncryptedFile(
                encryptedData, 
                currentPassword, 
                newPassword, 
                newKeyId
            );
            
            return updatedData; // WASM already returns a base64 string
        } catch (error) {
            console.error('Error adding key to encrypted file:', error);
            throw new Error('Failed to add key: ' + error.message);
        }
    }

    /**
     * Calculate SHA-256 hash of a file via WASM
     * @param {ArrayBuffer|Uint8Array} fileData - File data to hash
     * @returns {Promise<string>} - Hex encoded SHA-256 hash
     */
    async function calculateSHA256(fileData) {
        try {
            await ensureWasmInitialized();
            
            // Ensure fileData is in the right format for WASM
            const fileBytes = fileData instanceof ArrayBuffer ? 
                new Uint8Array(fileData) : fileData;
            
            // Call the WASM hash function
            const hash = await wasmFunctions.calculateSHA256(fileBytes);
            
            return hash; // WASM returns a hex string
        } catch (error) {
            console.error('Hash calculation error:', error);
            return null;
        }
    }

    /**
     * Updates password strength UI indicator
     * @param {string} password - Password to analyze
     * @param {HTMLElement} container - Container element with strength meter
     */
    function updatePasswordStrengthUI(password, container) {
        if (!container) return;
        
        const strengthMeter = container.querySelector('.strength-meter');
        if (!strengthMeter) return;

        // Clear any existing extra warnings
        const existingWarning = container.querySelector('.extra-weak-warning');
        if (existingWarning) {
            existingWarning.remove();
        }

        if (!password) {
            strengthMeter.className = 'strength-meter';
            strengthMeter.textContent = '';
            strengthMeter.style.width = '0%';
            return;
        }

        const requirements = {
            length: password.length >= 14,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            symbol: /[`~!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(password)
        };

        const metRequirements = Object.values(requirements).filter(Boolean).length;
        
        const strengthLevels = [
            { threshold: 0, class: 'very-weak', label: 'Very Weak!', color: '#ff4d4d', width: 10 },
            { threshold: 1, class: 'very-weak', label: 'Very Weak!', color: '#ff4d4d', width: 15 },
            { threshold: 2, class: 'weak', label: 'Weak', color: '#ff8c00', width: 35 },
            { threshold: 3, class: 'moderate', label: 'Moderate', color: '#ffd700', width: 60 },
            { threshold: 4, class: 'strong', label: 'Strong', color: '#90ee90', width: 80 },
            { threshold: 5, class: 'very-strong', label: 'Very Strong', color: '#32cd32', width: 100 }
        ];

        const level = strengthLevels[metRequirements] || strengthLevels[0];
        
        strengthMeter.className = `strength-meter ${level.class}`;
        strengthMeter.textContent = level.label;
        strengthMeter.style.width = `${level.width}%`;
        strengthMeter.style.backgroundColor = level.color;
        strengthMeter.style.color = '#fff';
        strengthMeter.style.textAlign = 'center';
        strengthMeter.style.padding = '4px 8px';
        strengthMeter.style.borderRadius = '4px';
        strengthMeter.style.fontSize = '12px';
        strengthMeter.style.fontWeight = 'bold';
        strengthMeter.style.transition = 'all 0.3s ease';

        // Show extra warning for very weak passwords
        if (metRequirements <= 1) {
            const warning = document.createElement('div');
            warning.className = 'extra-weak-warning';
            warning.style.cssText = `
                color: #ff4d4d;
                font-size: 12px;
                font-weight: bold;
                margin-top: 5px;
                padding: 5px;
                background-color: #fff5f5;
                border: 1px solid #fed7d7;
                border-radius: 4px;
            `;
            warning.textContent = '⚠️ This password is very weak and easily guessable. Please use a stronger password.';
            
            const requirementsList = container.querySelector('.requirements-list');
            if (requirementsList) {
                requirementsList.parentNode.insertBefore(warning, requirementsList.nextSibling);
            }
        }

        // Update individual requirements styling
        const requirementItems = container.querySelectorAll('.requirements-list li');
        const requirementKeys = ['length', 'uppercase', 'lowercase', 'number', 'symbol'];
        
        requirementItems.forEach((item, index) => {
            if (index < requirementKeys.length) {
                const isMet = requirements[requirementKeys[index]];
                item.style.color = isMet ? '#32cd32' : '#666';
                item.style.fontWeight = isMet ? 'bold' : 'normal';
                const checkmark = isMet ? '✓ ' : '';
                if (!item.textContent.startsWith('✓') && !item.textContent.startsWith('At least')) {
                    item.textContent = checkmark + item.textContent;
                } else if (isMet && !item.textContent.startsWith('✓')) {
                    item.textContent = checkmark + item.textContent;
                } else if (!isMet && item.textContent.startsWith('✓')) {
                    item.textContent = item.textContent.substring(2);
                }
            }
        });
    }

    // Public API
    return {
        validatePassword,
        encryptFile,
        decryptFile,
        encryptFileMultiKey,
        decryptFileMultiKey,
        addKeyToEncryptedFile,
        calculateSHA256,
        arrayBufferToBase64,
        base64ToArrayBuffer,
        updatePasswordStrengthUI
    };
})();
