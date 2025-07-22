// Chunked Uploader Implementation for Arkfile
// Handles large file uploads by splitting them into chunks, encrypting each chunk,
// and uploading them to the server with progress tracking and resumability

class ChunkedUploader {
    constructor(options = {}) {
        // Default chunk size: 16MB
        this.chunkSize = options.chunkSize || 16 * 1024 * 1024;
        this.file = null;
        this.fileName = null;
        this.fileSize = 0;
        this.originalHash = null;
        this.encryptedHash = null;
        this.totalChunks = 0;
        this.uploadedChunks = [];
        this.sessionId = null;
        this.password = null;
        this.passwordType = null;
        this.passwordHint = null;
        this.onProgress = options.onProgress || (() => {});
        this.onComplete = options.onComplete || (() => {});
        this.onError = options.onError || (() => {});
        this.paused = false;
        this.cancelled = false;
        this.activeRequests = new Set();
        this.retryAttempts = 3;
    }

    // Initialize upload and create session
    async initialize(file, passwordOptions) {
        try {
            this.file = file;
            this.fileName = file.name;
            this.fileSize = file.size;
            this.totalChunks = Math.ceil(this.fileSize / this.chunkSize);
            this.uploadedChunks = [];
            this.sessionId = null;
            this.cancelled = false;
            this.paused = false;
            this.activeRequests.clear();

            // Handle password options
            this.passwordType = passwordOptions.type || 'custom';
            this.passwordHint = passwordOptions.hint || '';
            
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
                this.password = passwordOptions.password;
                const validation = securityUtils.validatePassword(this.password);
                if (!validation.valid) {
                    throw new Error(validation.message);
                }
            }

            // Calculate original SHA-256 hash of the entire file
            this.originalHash = await this.calculateFileHash(file);

            // Create upload session on the server
            await this.createSession();
            
            return {
                sessionId: this.sessionId,
                totalChunks: this.totalChunks,
                fileSize: this.fileSize,
                fileName: this.fileName,
                originalHash: this.originalHash
            };
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Calculate SHA-256 hash of a file
    async calculateFileHash(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    if (!wasmReady) {
                        await initWasm(); // Make sure WASM is ready
                    }
                    
                    const fileBytes = new Uint8Array(e.target.result);
                    const hash = calculateSHA256(fileBytes);
                    resolve(hash);
                } catch (error) {
                    reject(error);
                }
            };
            reader.onerror = () => reject(new Error('Error reading file'));
            reader.readAsArrayBuffer(file);
        });
    }

    // Calculate SHA-256 hash of a chunk
    async calculateChunkHash(chunk) {
        if (!wasmReady) {
            await initWasm(); // Make sure WASM is ready
        }
        return calculateSHA256(new Uint8Array(chunk));
    }

    // Create upload session on the server
    async createSession() {
        try {
            const response = await fetch('/api/uploads/session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    filename: this.fileName,
                    totalSize: this.fileSize,
                    chunkSize: this.chunkSize,
                    originalHash: this.originalHash,
                    passwordHint: this.passwordHint,
                    passwordType: this.passwordType
                })
            });

            if (!response.ok) {
                throw new Error('Failed to create upload session');
            }

            const data = await response.json();
            this.sessionId = data.sessionId;
            return data;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Check which chunks have already been uploaded (for resume functionality)
    async checkUploadStatus() {
        try {
            const response = await fetch(`/api/uploads/${this.sessionId}/status`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to get upload status');
            }

            const data = await response.json();
            this.uploadedChunks = data.uploadedChunks || [];
            return data;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Derive file-level encryption key once per file
    async deriveFileKey() {
        if (!wasmReady) {
            await initWasm();
        }
        
        if (!this.fileKey) {
            // Generate file salt once per file
            this.fileSalt = generateSalt();
            
            // Derive file-level key using Argon2ID
            if (this.passwordType === 'account') {
                // For account passwords, use the session key directly
                this.fileKey = this.password;
            } else {
                // For custom passwords, derive key using Argon2ID
                // The WASM encryptFile function will handle this
                this.fileKey = this.password;
            }
        }
        
        return this.fileKey;
    }

    // Encrypt a chunk using the file-level key
    async encryptChunk(chunkData) {
        if (!wasmReady) {
            await initWasm();
        }
        
        const dataBytes = new Uint8Array(chunkData);
        let encryptedBase64;
        
        if (this.passwordType === 'account') {
            // Use secure session encryption for account-encrypted files
            const encryptResult = encryptFileWithSecureSession(dataBytes, this.userEmail);
            if (!encryptResult.success) {
                throw new Error('Failed to encrypt chunk: ' + encryptResult.error);
            }
            encryptedBase64 = encryptResult.data;
        } else {
            // Use custom password encryption
            encryptedBase64 = encryptFile(dataBytes, this.password, this.passwordType);
        }
        
        return {
            data: encryptedBase64,
            iv: this.fileSalt || 'secure-session' // Return file salt or indicate secure session
        };
    }

    // Upload a single chunk
    async uploadChunk(chunkNumber) {
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
            // Check if this chunk is already uploaded
            if (this.uploadedChunks.includes(chunkNumber)) {
                this.onProgress({
                    sessionId: this.sessionId,
                    chunkNumber,
                    totalChunks: this.totalChunks,
                    uploaded: this.uploadedChunks.length,
                    percent: (this.uploadedChunks.length / this.totalChunks) * 100
                });
                return true;
            }

            // Get chunk from file
            const start = chunkNumber * this.chunkSize;
            const end = Math.min(start + this.chunkSize, this.fileSize);
            const chunk = await this.file.slice(start, end).arrayBuffer();
            
            // Calculate chunk hash before encryption
            const chunkHash = await this.calculateChunkHash(chunk);
            
            // Encrypt chunk using SHAKE-256 & AES-GCM via WASM
            const { data: encryptedData, iv } = await this.encryptChunk(chunk);
            
            // Track this request
            const abortController = new AbortController();
            this.activeRequests.add(abortController);
            
            // Upload to server
            const formData = new FormData();
            formData.append('data', encryptedData);
            
            const response = await fetch(`/api/uploads/${this.sessionId}/chunk/${chunkNumber}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                    'X-Chunk-Hash': chunkHash,
                    'X-Chunk-IV': iv
                },
                signal: abortController.signal,
                body: formData
            });

            // Request completed, remove from tracking
            this.activeRequests.delete(abortController);

            if (!response.ok) {
                throw new Error(`Failed to upload chunk ${chunkNumber}`);
            }

            // Update progress
            this.uploadedChunks.push(chunkNumber);
            this.onProgress({
                sessionId: this.sessionId,
                chunkNumber,
                totalChunks: this.totalChunks,
                uploaded: this.uploadedChunks.length,
                percent: (this.uploadedChunks.length / this.totalChunks) * 100
            });

            return response.json();
        } catch (error) {
            if (error.name === 'AbortError') {
                return null; // Request was aborted, no error needed
            }
            
            // Handle retry logic
            if (this.retryAttempts > 0 && !this.cancelled) {
                this.retryAttempts--;
                console.warn(`Retrying chunk ${chunkNumber}. Attempts left: ${this.retryAttempts}`);
                await new Promise(resolve => setTimeout(resolve, 1000)); // Wait before retry
                return this.uploadChunk(chunkNumber);
            }
            
            this.onError(error);
            throw error;
        }
    }

    // Upload all chunks with concurrency control
    async uploadChunks(maxConcurrent = 3) {
        try {
            // First check which chunks are already uploaded (for resume)
            await this.checkUploadStatus();
            
            const chunks = Array.from({ length: this.totalChunks }, (_, i) => i);
            
            // Process chunks with limited concurrency
            const results = [];
            for (let i = 0; i < chunks.length; i += maxConcurrent) {
                const batch = chunks.slice(i, i + maxConcurrent);
                const promises = batch.map(chunkNumber => this.uploadChunk(chunkNumber));
                const batchResults = await Promise.all(promises);
                results.push(...batchResults);
                
                if (this.cancelled) break;
            }
            
            // Only complete if all chunks were uploaded and not cancelled
            if (this.uploadedChunks.length === this.totalChunks && !this.cancelled) {
                return await this.completeUpload();
            }
            
            return null;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Complete the upload process
    async completeUpload() {
        try {
            // If we have an encrypted file hash, include it
            const headers = {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            };
            
            if (this.encryptedHash) {
                headers['X-Encrypted-Hash'] = this.encryptedHash;
            }
            
            const response = await fetch(`/api/uploads/${this.sessionId}/complete`, {
                method: 'POST',
                headers
            });

            if (!response.ok) {
                throw new Error('Failed to complete upload');
            }

            const result = await response.json();
            this.onComplete(result);
            return result;
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    // Cancel the upload
    async cancel() {
        this.cancelled = true;
        // Abort all active requests
        this.activeRequests.forEach(controller => controller.abort());
        this.activeRequests.clear();
        
        // Cancel on server
        if (this.sessionId) {
            try {
                await fetch(`/api/uploads/${this.sessionId}/cancel`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    }
                });
            } catch (error) {
                console.error('Error cancelling upload on server', error);
            }
        }
    }

    // Pause upload
    pause() {
        this.paused = true;
    }

    // Resume upload
    resume() {
        this.paused = false;
    }

    // Start the upload process
    async start(options = {}) {
        try {
            const concurrency = options.concurrency || 3;
            return await this.uploadChunks(concurrency);
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }
}

// Export the ChunkedUploader class
window.ChunkedUploader = ChunkedUploader;
