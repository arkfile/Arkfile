/**
 * Share Access Module
 * Phase 6B: Anonymous Share System
 * 
 * Handles anonymous access to shared files with Argon2id password verification.
 * All cryptographic operations are performed in Go/WASM.
 */

import { ShareCrypto, type PasswordValidationResult } from './share-crypto.js';

// Type definitions
export interface ShareInfo {
    success: boolean;
    shareId: string;
    fileInfo?: {
        filename: string;
        size: number;
        sha256sum?: string;
    };
    requiresPassword: boolean;
    error?: string;
}

export interface ShareAccessRequest {
    password: string;
}

export interface ShareAccessResponse {
    success: boolean;
    salt?: string;
    encrypted_fek?: string;
    file_info?: {
        filename: string;
        size: number;
        content_type?: string;
        sha256sum?: string;
    };
    error?: string;
    message?: string;
    retryAfter?: number;
}

export interface FileDownloadResponse {
    data: string; // base64-encoded encrypted file data
    filename: string;
    size: number;
}

/**
 * ShareAccessor handles anonymous access to shared files
 */
export class ShareAccessor {
    private shareId: string;
    private shareInfo: ShareInfo | null = null;
    private isProcessing = false;

    constructor(shareId: string) {
        this.shareId = shareId;
    }

    /**
     * Gets share information (public metadata, no password required)
     */
    async getShareInfo(): Promise<ShareInfo> {
        try {
            const response = await fetch(`/api/share/${this.shareId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                return {
                    success: false,
                    shareId: this.shareId,
                    requiresPassword: true,
                    error: errorData.message || `HTTP ${response.status}: ${response.statusText}`
                };
            }

            const result = await response.json();
            this.shareInfo = result;
            return result;

        } catch (error) {
            console.error('Share info error:', error);
            return {
                success: false,
                shareId: this.shareId,
                requiresPassword: true,
                error: error instanceof Error ? error.message : 'Network error occurred'
            };
        }
    }

    /**
     * Accesses the shared file with password (gets salt and encrypted FEK)
     * 
     * @param password Share password
     * @returns Promise with share access result
     */
    async accessShare(password: string): Promise<ShareAccessResponse> {
        if (this.isProcessing) {
            return {
                success: false,
                error: 'Share access already in progress'
            };
        }

        this.isProcessing = true;

        try {
            // Step 1: Validate WASM availability
            if (!ShareCrypto.isWASMAvailable()) {
                return {
                    success: false,
                    error: 'Cryptographic functions not available. Please refresh the page.'
                };
            }

            // Step 2: Basic password validation
            if (!password || password.length < 18) {
                return {
                    success: false,
                    error: 'Password must be at least 18 characters'
                };
            }

            // Step 3: Request share access (server returns salt + encrypted FEK)
            const response = await fetch(`/api/share/${this.shareId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password: password })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                return {
                    success: false,
                    error: errorData.message || `HTTP ${response.status}: ${response.statusText}`,
                    retryAfter: errorData.retryAfter
                };
            }

            const result = await response.json();
            return result;

        } catch (error) {
            console.error('Share access error:', error);
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Network error occurred'
            };
        } finally {
            this.isProcessing = false;
        }
    }

    /**
     * Decrypts the FEK using the share password and downloads the file
     * 
     * @param password Share password
     * @param salt Base64-encoded salt from share access
     * @param encryptedFEK Base64-encoded encrypted FEK from share access
     * @returns Promise with decrypted file data
     */
    async downloadAndDecryptFile(password: string, salt: string, encryptedFEK: string): Promise<{ success: boolean; data?: string; filename?: string; error?: string }> {
        try {
            // Step 1: Convert salt and encrypted FEK from base64
            const saltBytes = ShareCrypto.base64ToUint8Array(salt);
            const encryptedFEKBytes = ShareCrypto.base64ToUint8Array(encryptedFEK);

            // Step 2: Derive share key from password using Argon2id
            const shareKeyResult = ShareCrypto.deriveShareKey(password, saltBytes);
            if (!shareKeyResult.success || !shareKeyResult.shareKey) {
                return {
                    success: false,
                    error: shareKeyResult.error || 'Failed to derive share key'
                };
            }

            // Step 3: Decrypt FEK with share key
            const fekResult = ShareCrypto.decryptFEKWithShareKey(encryptedFEKBytes, shareKeyResult.shareKey);
            if (!fekResult.success || !fekResult.fek) {
                return {
                    success: false,
                    error: 'Incorrect password or corrupted data'
                };
            }

            // Step 4: Download encrypted file from server
            const downloadResponse = await fetch(`/api/share/${this.shareId}/download`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!downloadResponse.ok) {
                const errorData = await downloadResponse.json().catch(() => ({}));
                return {
                    success: false,
                    error: errorData.message || `Download failed: HTTP ${downloadResponse.status}`
                };
            }

            const downloadData: FileDownloadResponse = await downloadResponse.json();

            // Step 5: Decrypt file data with FEK using standard file decryption
            // For shared files, we need to use the global decryptFileWithSecureSession function
            // but adapt it for FEK-based decryption instead of session-based
            
            // Convert the encrypted file data to proper format for decryption
            const encryptedFileBase64 = downloadData.data;
            
            // Create a temporary session using the FEK for file decryption
            // This is a workaround since we don't have a direct FEK decryption function
            // In a real implementation, this would be handled more elegantly
            const decryptedFileBase64 = await this.decryptFileWithFEK(encryptedFileBase64, fekResult.fek);
            
            if (!decryptedFileBase64) {
                return {
                    success: false,
                    error: 'Failed to decrypt file data'
                };
            }

            // Step 6: Return the decrypted file data
            const decryptedFileBase64Final = decryptedFileBase64;

            return {
                success: true,
                data: decryptedFileBase64,
                filename: downloadData.filename
            };

        } catch (error) {
            console.error('File download/decrypt error:', error);
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred'
            };
        }
    }

    /**
     * Decrypts file data using FEK (File Encryption Key)
     * This method uses the WASM decryptFileWithFEKWASM function for real AES-GCM decryption
     */
    private async decryptFileWithFEK(encryptedFileBase64: string, fek: Uint8Array): Promise<string | null> {
        try {
            // Use the WASM function for real AES-GCM decryption
            if (typeof window.decryptFileWithFEKWASM !== 'function') {
                throw new Error('WASM decryption function not available');
            }

            const result = window.decryptFileWithFEKWASM(encryptedFileBase64, fek);
            
            if (!result || !result.success) {
                throw new Error(result?.error || 'File decryption failed');
            }
            
            return result.data || null;
            
        } catch (error) {
            console.error('File decryption error:', error);
            return null;
        }
    }

    /**
     * Validates share password for UI feedback
     */
    validatePassword(password: string): PasswordValidationResult {
        return ShareCrypto.validateSharePassword(password);
    }

    /**
     * Gets processing status
     */
    get processing(): boolean {
        return this.isProcessing;
    }
}

/**
 * UI Helper class for share access interface
 */
export class ShareAccessUI {
    private container: HTMLElement;
    private accessor: ShareAccessor;
    private passwordInput: HTMLInputElement | null = null;
    private accessButton: HTMLButtonElement | null = null;
    private statusDiv: HTMLElement | null = null;
    private progressDiv: HTMLElement | null = null;
    private fileInfoDiv: HTMLElement | null = null;

    constructor(containerId: string, shareId: string) {
        const container = document.getElementById(containerId);
        if (!container) {
            throw new Error(`Container element '${containerId}' not found`);
        }
        this.container = container;
        this.accessor = new ShareAccessor(shareId);
        this.setupUI();
    }

    /**
     * Initialize the share access interface
     */
    async initialize(): Promise<void> {
        // Load share information
        this.showProgress(true, 'Loading share information...');
        
        const shareInfo = await this.accessor.getShareInfo();
        this.showProgress(false);

        if (!shareInfo.success) {
            this.showStatus(shareInfo.error || 'Failed to load share information', true);
            return;
        }

        this.displayShareInfo(shareInfo);
        this.updateUI();
    }

    /**
     * Sets up the UI elements
     */
    private setupUI(): void {
        this.container.innerHTML = `
            <div class="share-access-form">
                <div id="share-file-info" class="file-info" style="display: none;"></div>
                
                <div class="form-group">
                    <label for="access-password">Enter Share Password:</label>
                    <input type="password" id="access-password" class="form-control" 
                           placeholder="Enter the password provided with this share" 
                           minlength="18" required>
                    <div class="password-feedback" id="password-feedback"></div>
                </div>

                <div class="form-actions">
                    <button type="button" id="access-share-btn" class="btn btn-primary" disabled>
                        Access File
                    </button>
                </div>

                <div id="access-status" class="status-message" style="display: none;"></div>
                <div id="access-progress" class="progress-indicator" style="display: none;">
                    <div class="progress-bar">
                        <div class="progress-fill"></div>
                    </div>
                    <span class="progress-text">Accessing shared file...</span>
                </div>
            </div>
        `;

        // Get references to UI elements
        this.passwordInput = this.container.querySelector('#access-password') as HTMLInputElement;
        this.accessButton = this.container.querySelector('#access-share-btn') as HTMLButtonElement;
        this.statusDiv = this.container.querySelector('#access-status') as HTMLElement;
        this.progressDiv = this.container.querySelector('#access-progress') as HTMLElement;
        this.fileInfoDiv = this.container.querySelector('#share-file-info') as HTMLElement;

        // Set up event listeners
        this.setupEventListeners();
    }

    /**
     * Sets up event listeners for UI interactions
     */
    private setupEventListeners(): void {
        if (this.passwordInput) {
            this.passwordInput.addEventListener('input', () => this.onPasswordInput());
            this.passwordInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && this.accessButton && !this.accessButton.disabled) {
                    this.onAccessShare();
                }
            });
        }

        if (this.accessButton) {
            this.accessButton.addEventListener('click', () => this.onAccessShare());
        }
    }

    /**
     * Handles real-time password validation
     */
    private onPasswordInput(): void {
        if (!this.passwordInput) return;

        const password = this.passwordInput.value;
        const feedbackDiv = this.container.querySelector('#password-feedback') as HTMLElement;

        if (!password) {
            feedbackDiv.innerHTML = '';
            this.updateAccessButton(false);
            return;
        }

        const validation = this.accessor.validatePassword(password);
        
        // Update feedback
        if (validation.meets_requirements) {
            feedbackDiv.innerHTML = '<div class="text-success">Password meets requirements</div>';
            this.updateAccessButton(true);
        } else {
            const feedback = validation.feedback.join('. ');
            feedbackDiv.innerHTML = `<div class="text-warning">${feedback}</div>`;
            this.updateAccessButton(false);
        }
    }

    /**
     * Handles share access
     */
    private async onAccessShare(): Promise<void> {
        if (!this.passwordInput) return;

        const password = this.passwordInput.value;

        // Show progress
        this.showProgress(true, 'Verifying password...');
        this.showStatus('', false);

        try {
            // Step 1: Access share (get salt and encrypted FEK)
            const accessResult = await this.accessor.accessShare(password);

            if (!accessResult.success) {
                this.showProgress(false);
                this.showStatus(accessResult.error || 'Access failed', true);
                
                if (accessResult.retryAfter) {
                    this.showRateLimitWarning(accessResult.retryAfter);
                }
                return;
            }

            // Step 2: Download and decrypt file
            this.updateProgress('Downloading and decrypting file...');
            
            const downloadResult = await this.accessor.downloadAndDecryptFile(
                password,
                accessResult.salt!,
                accessResult.encrypted_fek!
            );

            this.showProgress(false);

            if (downloadResult.success) {
                this.showDownloadSuccess(downloadResult.data!, downloadResult.filename!);
            } else {
                this.showStatus(downloadResult.error || 'Failed to decrypt file', true);
            }

        } catch (error) {
            this.showProgress(false);
            this.showStatus('Network error occurred', true);
            console.error('Share access error:', error);
        }
    }

    /**
     * Displays share information
     */
    private displayShareInfo(shareInfo: ShareInfo): void {
        if (!this.fileInfoDiv || !shareInfo.fileInfo) return;

        const fileSize = this.formatFileSize(shareInfo.fileInfo.size);
        
        this.fileInfoDiv.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">${shareInfo.fileInfo.filename}</h5>
                    <p class="card-text">
                        <small class="text-muted">Size: ${fileSize}</small>
                    </p>
                    <p class="card-text">
                        <small>Enter the password to access this shared file.</small>
                    </p>
                </div>
            </div>
        `;
        
        this.fileInfoDiv.style.display = 'block';
    }

    /**
     * Shows download success with file download
     */
    private showDownloadSuccess(fileData: string, filename: string): void {
        const statusHtml = `
            <div class="alert alert-success">
                <h4>File Decrypted Successfully!</h4>
                <p>Click the button below to download your file:</p>
                <button type="button" id="download-file-btn" class="btn btn-success">
                    Download ${filename}
                </button>
            </div>
        `;

        if (this.statusDiv) {
            this.statusDiv.innerHTML = statusHtml;
            this.statusDiv.style.display = 'block';

            // Set up download button
            const downloadBtn = this.statusDiv.querySelector('#download-file-btn') as HTMLButtonElement;
            if (downloadBtn) {
                downloadBtn.addEventListener('click', () => {
                    this.downloadFile(fileData, filename);
                });
            }
        }
    }

    /**
     * Downloads the decrypted file to user's device
     */
    private downloadFile(fileData: string, filename: string): void {
        try {
            // Convert base64 to blob
            const byteCharacters = atob(fileData);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray]);

            // Create download link
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

        } catch (error) {
            console.error('File download error:', error);
            this.showStatus('Failed to download file', true);
        }
    }

    /**
     * Shows rate limit warning
     */
    private showRateLimitWarning(retryAfter: number): void {
        const minutes = Math.ceil(retryAfter / 60);
        const warningHtml = `
            <div class="alert alert-warning">
                <h5>Rate Limited</h5>
                <p>Too many failed attempts. Please wait ${minutes} minute(s) before trying again.</p>
            </div>
        `;

        if (this.statusDiv) {
            this.statusDiv.innerHTML = warningHtml;
            this.statusDiv.style.display = 'block';
        }
    }

    /**
     * Updates UI state
     */
    private updateUI(): void {
        const available = ShareCrypto.isWASMAvailable();
        if (!available && this.statusDiv) {
            this.showStatus('Cryptographic functions not available. Please refresh the page.', true);
        }
    }

    /**
     * Updates access button state
     */
    private updateAccessButton(enabled: boolean): void {
        if (this.accessButton) {
            this.accessButton.disabled = !enabled || this.accessor.processing;
        }
    }

    /**
     * Shows/hides progress indicator
     */
    private showProgress(show: boolean, text?: string): void {
        if (this.progressDiv) {
            this.progressDiv.style.display = show ? 'block' : 'none';
            
            if (show && text) {
                const progressText = this.progressDiv.querySelector('.progress-text') as HTMLElement;
                if (progressText) {
                    progressText.textContent = text;
                }
            }
        }
        this.updateAccessButton(!show);
    }

    /**
     * Updates progress text
     */
    private updateProgress(text: string): void {
        if (this.progressDiv) {
            const progressText = this.progressDiv.querySelector('.progress-text') as HTMLElement;
            if (progressText) {
                progressText.textContent = text;
            }
        }
    }

    /**
     * Shows status message
     */
    private showStatus(message: string, isError: boolean): void {
        if (!this.statusDiv) return;

        if (!message) {
            this.statusDiv.style.display = 'none';
            return;
        }

        const alertClass = isError ? 'alert-danger' : 'alert-info';
        this.statusDiv.innerHTML = `<div class="alert ${alertClass}">${message}</div>`;
        this.statusDiv.style.display = 'block';
    }

    /**
     * Formats file size in human-readable format
     */
    private formatFileSize(bytes: number): string {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Export for ES6 modules
export default ShareAccessUI;
