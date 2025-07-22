// Chunked Downloader Implementation for Arkfile
// Handles large file downloads by retrieving chunks, decrypting them,
// and reassembling the original file with progress tracking and resumability

class ChunkedDownloader {
    constructor(options = {}) {
        this.fileId = null;
        this.fileName = null;
        this.totalChunks = 0;
        this.chunkSize = 16 * 1024 * 1024; // Default 16MB
        this.totalSize = 0;
        this.originalHash = null;
        this.passwordHint = null;
        this.password = null;
        this.passwordType = null;
        this.downloadedChunks = new Map(); // Map of chunk index to ArrayBuffer
        this.onProgress = options.onProgress || (() => {});
        this.onComplete = options.onComplete || (() => {});
        this.onError = options.onError || (() => {});
        this.paused = false;
        this.cancelled = false;
        this.activeRequests = new Set();
        this.retryAttempts = 3;
    }

    // Initialize download and get file metadata
    async initialize(fileId, passwordOptions) {
        try {
            this.fileId = fileId;
            this.downloadedChunks.clear();
            this.cancelled = false;
            this.paused = false;
            this.activeRequests.clear();

            // Get file metadata
            const response = await fetch(`/api/files/${fileId}/metadata`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to get file metadata');
            }

            const metadata = await response.json();
            this.fileName = metadata.filename;
            this.totalSize = metadata.size;
            this.originalHash = metadata.sha256sum;
            this.passwordType = metadata.passwordType;
            this.passwordHint = metadata.passwordHint;
            
            // Calculate total chunks
            this.totalChunks = Math.ceil(this.totalSize / this.chunkSize);

            // Set password based on type
            if (this.passwordType === 'account') {
                // Use secure session validation via WASM
                const userEmail = getUserEmailFromToken();
                if (!userEmail) {
                    throw new Error('Cannot determine user email. Please log in again.');
                }
                
                const sessionValidation = validateSecureSession(userEmail);
                if (!sessionValidation.valid) {
                    throw new Error('Your session has expired. Please log in again.');
                }
                
                this.password = null; // Use secure session in WASM - no password exposed to JavaScript
                this.userEmail = userEmail; // Store user email for secure session operations
            } else {
                // For custom password
                if (!passwordOptions.password) {
                    throw new Error('Password is required for this file');
                }
                this.password = passwordOptions.password;
            }

            return {
                fileId: this.fileId,
                fileName: this.fileName,
                totalSize: this.totalSize,
                totalChunks: this.totalChunks,
                originalHash: this.originalHash,
                passwordType: this.passwordType,
                passwordHint: this.passwordHint
            };
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Download a single chunk
    async downloadChunk(chunkNumber) {
        if (this.cancelled) return null;
        if (this.paused) {
            // If paused, wait until resumed
            await new Promise(resolve => {
                const checkPaused = () => {
                    if (!this.paused) {
                        resolve();
                    } else {
                        setTimeout(checkPaused, 500);
                    }
                };
                checkPaused();
            });
        }

        try {
            // Check if already downloaded
            if (this.downloadedChunks.has(chunkNumber)) {
                this.onProgress({
                    fileId: this.fileId,
                    chunkNumber,
                    totalChunks: this.totalChunks,
                    downloaded: this.downloadedChunks.size,
                    percent: (this.downloadedChunks.size / this.totalChunks) * 100
                });
                return this.downloadedChunks.get(chunkNumber);
            }

            // Track this request
            const abortController = new AbortController();
            this.activeRequests.add(abortController);
            
            // Download chunk
            const response = await fetch(`/api/files/${this.fileId}/chunk/${chunkNumber}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                signal: abortController.signal
            });

            // Request completed, remove from tracking
            this.activeRequests.delete(abortController);

            if (!response.ok) {
                throw new Error(`Failed to download chunk ${chunkNumber}`);
            }

            // Get encrypted data and decrypt it
            const data = await response.json();
            
            // Make sure WASM is ready
            if (!wasmReady) {
                await initWasm();
            }
            
            // Decrypt the chunk data 
            let decryptedData;
            if (this.passwordType === 'account') {
                // Use secure session decryption for account-encrypted files
                const decryptResult = decryptFileWithSecureSession(data.data, this.userEmail);
                if (!decryptResult.success) {
                    throw new Error('Failed to decrypt chunk: ' + decryptResult.error);
                }
                decryptedData = decryptResult.data;
            } else {
                // Use custom password decryption
                decryptedData = decryptFile(data.data, this.password);
                
                // Check for decryption errors
                if (typeof decryptedData === 'string' && decryptedData.startsWith('Failed')) {
                    throw new Error('Failed to decrypt chunk: ' + decryptedData);
                }
            }
            
            // Convert base64 to Uint8Array
            const binaryString = atob(decryptedData);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Store the chunk
            this.downloadedChunks.set(chunkNumber, bytes);
            
            // Update progress
            this.onProgress({
                fileId: this.fileId,
                chunkNumber,
                totalChunks: this.totalChunks,
                downloaded: this.downloadedChunks.size,
                percent: (this.downloadedChunks.size / this.totalChunks) * 100
            });

            return bytes;
        } catch (error) {
            if (error.name === 'AbortError') {
                return null; // Request was aborted, no error needed
            }
            
            // Handle retry logic
            if (this.retryAttempts > 0 && !this.cancelled) {
                this.retryAttempts--;
                console.warn(`Retrying chunk ${chunkNumber}. Attempts left: ${this.retryAttempts}`);
                await new Promise(resolve => setTimeout(resolve, 1000)); // Wait before retry
                return this.downloadChunk(chunkNumber);
            }
            
            this.onError(error);
            throw error;
        }
    }

    // Download all chunks with concurrency control
    async downloadChunks(maxConcurrent = 3) {
        try {
            const chunks = Array.from({ length: this.totalChunks }, (_, i) => i);
            
            // Process chunks with limited concurrency
            for (let i = 0; i < chunks.length; i += maxConcurrent) {
                const batch = chunks.slice(i, i + maxConcurrent);
                const promises = batch.map(chunkNumber => this.downloadChunk(chunkNumber));
                await Promise.all(promises);
                
                if (this.cancelled) break;
            }
            
            // Only reassemble if all chunks were downloaded and not cancelled
            if (this.downloadedChunks.size === this.totalChunks && !this.cancelled) {
                return await this.reassembleFile();
            }
            
            return null;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Reassemble the file from chunks
    async reassembleFile() {
        try {
            // Create a new array to hold the entire file
            const fileData = new Uint8Array(this.totalSize);
            
            // Copy each chunk to the proper position
            for (let i = 0; i < this.totalChunks; i++) {
                const chunk = this.downloadedChunks.get(i);
                if (!chunk) {
                    throw new Error(`Missing chunk ${i}`);
                }
                
                const offset = i * this.chunkSize;
                fileData.set(chunk, offset);
            }
            
            // Verify file integrity with hash
            const hash = await this.calculateHash(fileData);
            if (hash !== this.originalHash) {
                throw new Error('File integrity check failed. The downloaded file is corrupted.');
            }
            
            // Create a blob and download URL
            const blob = new Blob([fileData], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            
            // Return the download info
            const result = {
                fileName: this.fileName,
                fileSize: this.totalSize,
                url,
                blob
            };
            
            this.onComplete(result);
            return result;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Calculate SHA-256 hash of the file
    async calculateHash(fileData) {
        if (!wasmReady) {
            await initWasm();
        }
        return calculateSHA256(fileData);
    }

    // Download the file to the user's device
    saveFile(url = null, fileName = null) {
        // If url is provided, use it; otherwise use the one we created
        const downloadUrl = url || this.result?.url;
        const downloadName = fileName || this.fileName;
        
        if (!downloadUrl) {
            throw new Error('No download URL available');
        }
        
        // Create an anchor and trigger download
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = downloadName;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    // Cancel the download
    cancel() {
        this.cancelled = true;
        // Abort all active requests
        this.activeRequests.forEach(controller => controller.abort());
        this.activeRequests.clear();
    }

    // Pause download
    pause() {
        this.paused = true;
    }

    // Resume download
    resume() {
        this.paused = false;
    }

    // Start the download process
    async start(options = {}) {
        try {
            const concurrency = options.concurrency || 3;
            const result = await this.downloadChunks(concurrency);
            this.result = result;
            
            // Auto-save if requested
            if (options.autoSave && result) {
                this.saveFile(result.url, result.fileName);
            }
            
            return result;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Clean up resources
    destroy() {
        // Revoke any object URLs we created
        if (this.result?.url) {
            URL.revokeObjectURL(this.result.url);
        }
        
        // Clear stored chunks to free memory
        this.downloadedChunks.clear();
    }
}

// Export the ChunkedDownloader class
window.ChunkedDownloader = ChunkedDownloader;
