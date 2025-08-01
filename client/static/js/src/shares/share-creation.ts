/**
 * Share Creation Module
 * Phase 6B: Anonymous Share System
 * 
 * Handles creating anonymous file shares with Argon2id password protection.
 * All cryptographic operations are performed in Go/WASM.
 */

import { ShareCrypto, type PasswordValidationResult } from './share-crypto.js';

// Type definitions
export interface ShareCreationRequest {
    fileId: string;
    sharePassword: string;
    expiresAfterHours?: number;
}

export interface ShareCreationResponse {
    success: boolean;
    shareId?: string;
    shareUrl?: string;
    createdAt?: string;
    expiresAt?: string;
    error?: string;
    message?: string;
}

export interface FileInfo {
    filename: string;
    fek: string; // base64-encoded FEK
}

/**
 * ShareCreator handles the creation of anonymous file shares
 */
export class ShareCreator {
    private fileInfo: FileInfo | null = null;
    private isProcessing = false;

    constructor(fileInfo: FileInfo) {
        this.fileInfo = fileInfo;
    }

    /**
     * Creates an anonymous share for the file
     * 
     * @param request Share creation parameters
     * @returns Promise with share creation result
     */
    async createShare(request: ShareCreationRequest): Promise<ShareCreationResponse> {
        if (this.isProcessing) {
            return {
                success: false,
                error: 'Share creation already in progress'
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

            // Step 2: Validate share password
            const passwordValidation = ShareCrypto.validateSharePassword(request.sharePassword);
            if (!passwordValidation.success || !passwordValidation.meets_requirements) {
                return {
                    success: false,
                    error: 'Password does not meet security requirements',
                    message: passwordValidation.feedback.join('. ')
                };
            }

            // Step 3: Generate secure salt
            const saltResult = ShareCrypto.generateSecureSalt();
            if (!saltResult.success || !saltResult.salt) {
                return {
                    success: false,
                    error: saltResult.error || 'Failed to generate cryptographic salt'
                };
            }

            // Step 4: Derive share key from password using Argon2id
            const shareKeyResult = ShareCrypto.deriveShareKey(request.sharePassword, saltResult.salt);
            if (!shareKeyResult.success || !shareKeyResult.shareKey) {
                return {
                    success: false,
                    error: shareKeyResult.error || 'Failed to derive share key'
                };
            }

            // Step 5: Get FEK and encrypt it with share key
            if (!this.fileInfo || !this.fileInfo.fek) {
                return {
                    success: false,
                    error: 'File encryption key not available'
                };
            }

            const fek = ShareCrypto.base64ToUint8Array(this.fileInfo.fek);
            const encryptionResult = ShareCrypto.encryptFEKWithShareKey(fek, shareKeyResult.shareKey);
            if (!encryptionResult.success || !encryptionResult.encryptedFEK) {
                return {
                    success: false,
                    error: encryptionResult.error || 'Failed to encrypt file key'
                };
            }

            // Step 6: Prepare request for backend
            const backendRequest = {
                fileId: request.fileId,
                salt: ShareCrypto.uint8ArrayToBase64(saltResult.salt),
                encrypted_fek: ShareCrypto.uint8ArrayToBase64(encryptionResult.encryptedFEK),
                expiresAfterHours: request.expiresAfterHours || 0
            };

            // Step 7: Send to backend API (no password sent!)
            const response = await fetch(`/api/files/${request.fileId}/share`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify(backendRequest)
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                return {
                    success: false,
                    error: errorData.message || `HTTP ${response.status}: ${response.statusText}`
                };
            }

            const result = await response.json();
            return {
                success: true,
                shareId: result.shareId,
                shareUrl: result.shareUrl,
                createdAt: result.createdAt,
                expiresAt: result.expiresAt
            };

        } catch (error) {
            console.error('Share creation error:', error);
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred'
            };
        } finally {
            this.isProcessing = false;
        }
    }

    /**
     * Validates share password in real-time for UI feedback
     * 
     * @param password Password to validate
     * @returns Password validation result
     */
    validatePassword(password: string): PasswordValidationResult {
        return ShareCrypto.validateSharePassword(password);
    }

    /**
     * Gets authentication token from localStorage or cookies
     */
    private getAuthToken(): string | null {
        // Try localStorage first
        const token = localStorage.getItem('authToken') || localStorage.getItem('jwt_token');
        if (token) {
            return token;
        }

        // Try cookies as fallback
        const cookieMatch = document.cookie.match(/(?:^|;\s*)(?:authToken|jwt_token)=([^;]*)/);
        return cookieMatch ? cookieMatch[1] : null;
    }

    /**
     * Gets processing status
     */
    get processing(): boolean {
        return this.isProcessing;
    }
}

/**
 * UI Helper class for share creation interface
 */
export class ShareCreationUI {
    private container: HTMLElement;
    private creator: ShareCreator | null = null;
    private passwordInput: HTMLInputElement | null = null;
    private hoursInput: HTMLInputElement | null = null;
    private createButton: HTMLButtonElement | null = null;
    private statusDiv: HTMLElement | null = null;
    private progressDiv: HTMLElement | null = null;

    constructor(containerId: string) {
        const container = document.getElementById(containerId);
        if (!container) {
            throw new Error(`Container element '${containerId}' not found`);
        }
        this.container = container;
        this.setupUI();
    }

    /**
     * Initialize the share creator with file information
     */
    initialize(fileInfo: FileInfo): void {
        this.creator = new ShareCreator(fileInfo);
        this.updateUI();
    }

    /**
     * Sets up the UI elements
     */
    private setupUI(): void {
        this.container.innerHTML = `
            <div class="share-creation-form">
                <h3>Create Anonymous Share</h3>
                
                <div class="form-group">
                    <label for="share-password">Share Password:</label>
                    <input type="password" id="share-password" class="form-control" 
                           placeholder="Enter a strong password (18+ characters)" 
                           minlength="18" required>
                    <div class="password-strength" id="password-strength"></div>
                    <small class="form-text">This password will be required to access the shared file.</small>
                </div>

                <div class="form-group">
                    <label for="expiry-hours">Expiry (hours, optional):</label>
                    <input type="number" id="expiry-hours" class="form-control" 
                           min="1" max="8760" placeholder="Leave empty for no expiry">
                    <small class="form-text">Maximum 8760 hours (1 year).</small>
                </div>

                <div class="form-actions">
                    <button type="button" id="create-share-btn" class="btn btn-primary" disabled>
                        Create Share
                    </button>
                </div>

                <div id="share-status" class="status-message" style="display: none;"></div>
                <div id="share-progress" class="progress-indicator" style="display: none;">
                    <div class="progress-bar">
                        <div class="progress-fill"></div>
                    </div>
                    <span class="progress-text">Creating secure share...</span>
                </div>
            </div>
        `;

        // Get references to UI elements
        this.passwordInput = this.container.querySelector('#share-password') as HTMLInputElement;
        this.hoursInput = this.container.querySelector('#expiry-hours') as HTMLInputElement;
        this.createButton = this.container.querySelector('#create-share-btn') as HTMLButtonElement;
        this.statusDiv = this.container.querySelector('#share-status') as HTMLElement;
        this.progressDiv = this.container.querySelector('#share-progress') as HTMLElement;

        // Set up event listeners
        this.setupEventListeners();
    }

    /**
     * Sets up event listeners for UI interactions
     */
    private setupEventListeners(): void {
        if (this.passwordInput) {
            this.passwordInput.addEventListener('input', () => this.onPasswordInput());
        }

        if (this.createButton) {
            this.createButton.addEventListener('click', () => this.onCreateShare());
        }
    }

    /**
     * Handles real-time password validation
     */
    private onPasswordInput(): void {
        if (!this.passwordInput || !this.creator) return;

        const password = this.passwordInput.value;
        const strengthDiv = this.container.querySelector('#password-strength') as HTMLElement;

        if (!password) {
            strengthDiv.innerHTML = '';
            this.updateCreateButton(false);
            return;
        }

        const validation = this.creator.validatePassword(password);
        
        // Update strength indicator
        const strengthClass = this.getStrengthClass(validation.strength_score);
        const strengthText = this.getStrengthText(validation.strength_score);
        
        strengthDiv.innerHTML = `
            <div class="strength-meter ${strengthClass}">
                <div class="strength-fill" style="width: ${validation.strength_score * 20}%"></div>
            </div>
            <div class="strength-text">${strengthText}</div>
            ${validation.feedback.length > 0 ? `<div class="strength-feedback">${validation.feedback.join('. ')}</div>` : ''}
        `;

        // Update create button state
        this.updateCreateButton(validation.meets_requirements);
    }

    /**
     * Handles share creation
     */
    private async onCreateShare(): Promise<void> {
        if (!this.creator || !this.passwordInput) return;

        const password = this.passwordInput.value;
        const hours = this.hoursInput?.value ? parseInt(this.hoursInput.value) : undefined;

        // Show progress
        this.showProgress(true);
        this.showStatus('', false);

        // Get file ID from current page
        const fileId = this.getFileIdFromPage();
        if (!fileId) {
            this.showStatus('Could not determine file ID', true);
            this.showProgress(false);
            return;
        }

        try {
            const shareRequest: ShareCreationRequest = {
                fileId: fileId,
                sharePassword: password,
                ...(hours !== undefined && { expiresAfterHours: hours })
            };

            const result = await this.creator.createShare(shareRequest);

            this.showProgress(false);

            if (result.success) {
                this.showShareSuccess(result);
            } else {
                this.showStatus(result.error || 'Failed to create share', true);
            }

        } catch (error) {
            this.showProgress(false);
            this.showStatus('Network error occurred', true);
            console.error('Share creation error:', error);
        }
    }

    /**
     * Shows share creation success with URL
     */
    private showShareSuccess(result: ShareCreationResponse): void {
        if (!result.shareUrl) return;

        const statusHtml = `
            <div class="alert alert-success">
                <h4>Share Created Successfully!</h4>
                <div class="share-url-container">
                    <label>Share URL:</label>
                    <div class="url-copy-group">
                        <input type="text" class="form-control" value="${result.shareUrl}" readonly id="share-url-input">
                        <button type="button" class="btn btn-secondary" onclick="copyShareUrl()">Copy</button>
                    </div>
                </div>
                ${result.expiresAt ? `<p><small>Expires: ${new Date(result.expiresAt).toLocaleString()}</small></p>` : ''}
                <p><small><strong>Important:</strong> Save this URL and password. They cannot be recovered if lost.</small></p>
            </div>
        `;

        if (this.statusDiv) {
            this.statusDiv.innerHTML = statusHtml;
            this.statusDiv.style.display = 'block';
        }

        // Add copy function to global scope temporarily
        (window as any).copyShareUrl = () => {
            const input = document.getElementById('share-url-input') as HTMLInputElement;
            if (input) {
                input.select();
                document.execCommand('copy');
                
                const button = input.nextElementSibling as HTMLButtonElement;
                if (button) {
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = originalText;
                    }, 2000);
                }
            }
        };
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
     * Updates create button state
     */
    private updateCreateButton(enabled: boolean): void {
        if (this.createButton) {
            this.createButton.disabled = !enabled || (this.creator?.processing ?? false);
        }
    }

    /**
     * Shows/hides progress indicator
     */
    private showProgress(show: boolean): void {
        if (this.progressDiv) {
            this.progressDiv.style.display = show ? 'block' : 'none';
        }
        this.updateCreateButton(!show);
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
     * Gets strength CSS class for password validation
     */
    private getStrengthClass(score: number): string {
        if (score === 0) return 'strength-very-weak';
        if (score === 1) return 'strength-weak';
        if (score === 2) return 'strength-fair';
        if (score === 3) return 'strength-good';
        return 'strength-excellent';
    }

    /**
     * Gets strength text for password validation
     */
    private getStrengthText(score: number): string {
        if (score === 0) return 'Very Weak';
        if (score === 1) return 'Weak';
        if (score === 2) return 'Fair';
        if (score === 3) return 'Good';
        return 'Excellent';
    }

    /**
     * Gets file ID from the current page URL or context
     */
    private getFileIdFromPage(): string | null {
        // Try to get from URL path (e.g., /files/file123)
        const pathMatch = window.location.pathname.match(/\/files\/([^\/]+)/);
        if (pathMatch) {
            return pathMatch[1];
        }

        // Try to get from data attributes
        const fileElement = document.querySelector('[data-file-id]') as HTMLElement;
        if (fileElement) {
            return fileElement.dataset.fileId || null;
        }

        // Try to get from input field
        const fileIdInput = document.querySelector('#file-id, [name="fileId"]') as HTMLInputElement;
        if (fileIdInput) {
            return fileIdInput.value || null;
        }

        return null;
    }
}

// Export for ES6 modules
export default ShareCreationUI;
