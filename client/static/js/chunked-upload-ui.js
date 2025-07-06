// Chunked Upload/Download UI Implementation
// Provides essential UI for chunked file operations

class ChunkedUploadUI {
    constructor(containerId = 'chunked-upload-container') {
        this.container = document.getElementById(containerId);
        this.chunkSize = 16 * 1024 * 1024; // 16MB
        this.activeUploads = new Map();
        this.activeDownloads = new Map();
        
        if (!this.container) {
            console.error('Container element not found');
            return;
        }
        
        this.render();
        this.bindEvents();
    }
    
    // Render the UI components
    render() {
        this.container.innerHTML = `
            <div class="upload-section">
                <h2>Upload Files</h2>
                <div class="upload-form">
                    <input type="file" id="file-input" />
                    <select id="password-type">
                        <option value="account">Use Account Password</option>
                        <option value="custom">Use Custom Password</option>
                    </select>
                    <div id="custom-password-section" style="display:none">
                        <input type="password" id="custom-password" placeholder="Enter password" />
                        <div class="strength-meter"></div>
                    </div>
                    <input type="text" id="password-hint" placeholder="Password hint (optional)" />
                    <button id="upload-button">Upload</button>
                </div>
                <div id="upload-progress"></div>
            </div>
            <div class="files-section">
                <h2>Your Files</h2>
                <button id="refresh-button">Refresh</button>
                <div id="files-list"></div>
            </div>
            <div id="message-box" style="display:none;"></div>
        `;
        
        // Store references to key elements
        this.fileInput = document.getElementById('file-input');
        this.passwordType = document.getElementById('password-type');
        this.customPasswordSection = document.getElementById('custom-password-section');
        this.customPassword = document.getElementById('custom-password');
        this.passwordHint = document.getElementById('password-hint');
        this.uploadButton = document.getElementById('upload-button');
        this.uploadProgress = document.getElementById('upload-progress');
        this.filesList = document.getElementById('files-list');
        this.refreshButton = document.getElementById('refresh-button');
        this.messageBox = document.getElementById('message-box');
    }
    
    // Bind event listeners
    bindEvents() {
        // Password type selection
        this.passwordType.addEventListener('change', () => {
            this.customPasswordSection.style.display = 
                this.passwordType.value === 'custom' ? 'block' : 'none';
        });
        
        // Password strength meter
        this.customPassword.addEventListener('input', (e) => {
            this.updatePasswordStrength(e.target.value);
        });
        
        // Upload button
        this.uploadButton.addEventListener('click', () => {
            this.startUpload();
        });
        
        // Refresh button
        this.refreshButton.addEventListener('click', () => {
            this.loadFiles();
        });
        
        // Load files on init
        this.loadFiles();
    }
    
    // Update password strength meter
    updatePasswordStrength(password) {
        if (window.securityUtils && window.securityUtils.updatePasswordStrengthUI) {
            window.securityUtils.updatePasswordStrengthUI(password, this.customPasswordSection);
        } else {
            // Fallback if securityUtils not available
            const meter = this.customPasswordSection.querySelector('.strength-meter');
            if (meter) {
                if (!password) {
                    meter.style.width = '0%';
                    meter.textContent = '';
                    return;
                }
                // Very basic fallback - just show "Very Weak!"
                meter.style.width = '15%';
                meter.style.backgroundColor = '#ff4d4d';
                meter.textContent = 'Very Weak!';
            }
        }
    }
    
    // Start file upload process
    async startUpload() {
        const file = this.fileInput.files[0];
        if (!file) {
            this.showMessage('Please select a file', 'error');
            return;
        }
        
        // Get password options
        const passwordOptions = {
            type: this.passwordType.value,
            hint: this.passwordHint.value
        };
        
        // Validate custom password if selected
        if (passwordOptions.type === 'custom') {
            passwordOptions.password = this.customPassword.value;
            
            if (!passwordOptions.password || passwordOptions.password.length < 12) {
                this.showMessage('Password must be at least 12 characters', 'error');
                return;
            }
        }
        
        // Create upload ID and UI element
        const uploadId = Date.now().toString();
        this.createProgressElement(uploadId, file.name, 'upload');
        
        try {
            // Create and initialize uploader
            const uploader = new ChunkedUploader({
                chunkSize: this.chunkSize,
                onProgress: progress => this.updateProgress(uploadId, progress),
                onComplete: result => this.completeOperation(uploadId, result, 'upload'),
                onError: error => this.handleError(uploadId, error, 'upload')
            });
            
            // Store uploader reference
            this.activeUploads.set(uploadId, uploader);
            
            // Initialize and start upload
            await uploader.initialize(file, passwordOptions);
            uploader.start({ concurrency: 3 });
            
            // Reset form
            this.fileInput.value = '';
            this.passwordHint.value = '';
            if (passwordOptions.type === 'custom') {
                this.customPassword.value = '';
                this.updatePasswordStrength('');
            }
        } catch (error) {
            this.handleError(uploadId, error, 'upload');
        }
    }
    
    // Create progress element for upload/download
    createProgressElement(id, name, type) {
        const element = document.createElement('div');
        element.className = `${type}-item`;
        element.dataset[`${type}Id`] = id;
        
        element.innerHTML = `
            <div class="item-info">
                <span class="name">${name}</span>
                <span class="status">Starting...</span>
            </div>
            <div class="progress-container">
                <div class="progress-bar"></div>
            </div>
            <div class="actions">
                <button class="pause-button">Pause</button>
                <button class="cancel-button">Cancel</button>
            </div>
        `;
        
        // Add event listeners
        const pauseButton = element.querySelector('.pause-button');
        const cancelButton = element.querySelector('.cancel-button');
        
        pauseButton.addEventListener('click', () => {
            const operation = type === 'upload' 
                ? this.activeUploads.get(id)
                : this.activeDownloads.get(id);
                
            if (!operation) return;
            
            if (operation.paused) {
                operation.resume();
                pauseButton.textContent = 'Pause';
            } else {
                operation.pause();
                pauseButton.textContent = 'Resume';
            }
        });
        
        cancelButton.addEventListener('click', () => {
            const operation = type === 'upload' 
                ? this.activeUploads.get(id)
                : this.activeDownloads.get(id);
                
            if (!operation) return;
            
            operation.cancel();
            if (type === 'upload') {
                this.activeUploads.delete(id);
            } else {
                this.activeDownloads.delete(id);
            }
            
            element.remove();
        });
        
        // Add to container
        const container = type === 'upload' 
            ? this.uploadProgress
            : document.getElementById('download-progress');
            
        container.appendChild(element);
    }
    
    // Update progress bar and status
    updateProgress(id, progress) {
        const isUpload = 'sessionId' in progress;
        const type = isUpload ? 'upload' : 'download';
        const container = this.container.querySelector(`[data-${type}-id="${id}"]`);
        
        if (!container) return;
        
        const progressBar = container.querySelector('.progress-bar');
        const status = container.querySelector('.status');
        const percent = progress.percent || 0;
        
        progressBar.style.width = `${percent}%`;
        
        if (isUpload) {
            status.textContent = `Uploading: ${progress.uploaded}/${progress.totalChunks} chunks`;
        } else {
            status.textContent = `Downloading: ${progress.downloaded}/${progress.totalChunks} chunks`;
        }
    }
    
    // Handle completion of upload/download
    completeOperation(id, result, type) {
        const container = this.container.querySelector(`[data-${type}-id="${id}"]`);
        if (!container) return;
        
        const progressBar = container.querySelector('.progress-bar');
        const status = container.querySelector('.status');
        const actions = container.querySelector('.actions');
        
        progressBar.style.width = '100%';
        progressBar.classList.add('complete');
        status.textContent = `${type === 'upload' ? 'Upload' : 'Download'} complete!`;
        
        actions.innerHTML = `<button class="close-button">Close</button>`;
        const closeButton = actions.querySelector('.close-button');
        closeButton.addEventListener('click', () => {
            container.remove();
        });
        
        if (type === 'upload') {
            this.activeUploads.delete(id);
            this.loadFiles(); // Refresh files list
        } else {
            this.activeDownloads.delete(id);
        }
    }
    
    // Handle errors
    handleError(id, error, type) {
        const container = this.container.querySelector(`[data-${type}-id="${id}"]`);
        if (!container) return;
        
        const progressBar = container.querySelector('.progress-bar');
        const status = container.querySelector('.status');
        const actions = container.querySelector('.actions');
        
        progressBar.classList.add('error');
        status.textContent = `Error: ${error.message || 'Operation failed'}`;
        
        actions.innerHTML = `<button class="close-button">Close</button>`;
        const closeButton = actions.querySelector('.close-button');
        closeButton.addEventListener('click', () => {
            container.remove();
        });
        
        if (type === 'upload') {
            this.activeUploads.delete(id);
        } else {
            this.activeDownloads.delete(id);
        }
    }
    
    // Load files from server
    async loadFiles() {
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                this.showMessage('Authentication required', 'error');
                return;
            }
            
            const response = await fetch('/api/files', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            
            if (!response.ok) {
                throw new Error('Failed to load files');
            }
            
            const data = await response.json();
            this.renderFilesList(data.files || []);
        } catch (error) {
            this.showMessage(error.message, 'error');
        }
    }
    
    // Render files list
    renderFilesList(files) {
        this.filesList.innerHTML = '';
        
        if (files.length === 0) {
            this.filesList.innerHTML = '<p>No files found</p>';
            return;
        }
        
        files.forEach(file => {
            const fileElement = document.createElement('div');
            fileElement.className = 'file-item';
            
            const fileSize = this.formatFileSize(file.size_bytes);
            const fileIcon = file.passwordType === 'account' ? '🔑' : '🔒';
            
            fileElement.innerHTML = `
                <div class="file-info">
                    <span class="file-name">${file.filename}</span>
                    <span class="file-size">${fileSize}</span>
                    <span class="file-encryption">${fileIcon}</span>
                </div>
                <div class="file-actions">
                    <button class="download-button">Download</button>
                    <button class="share-button">Share</button>
                </div>
            `;
            
            // Download button handler
            const downloadButton = fileElement.querySelector('.download-button');
            downloadButton.addEventListener('click', () => {
                this.startDownload(file);
            });
            
            // Share button handler
            const shareButton = fileElement.querySelector('.share-button');
            shareButton.addEventListener('click', () => {
                this.showShareDialog(file);
            });
            
            this.filesList.appendChild(fileElement);
        });
    }
    
    // Format file size for display
    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
    }
    
    // Show a message to the user
    showMessage(message, type = 'info') {
        this.messageBox.textContent = message;
        this.messageBox.className = `message ${type}`;
        this.messageBox.style.display = 'block';
        
        setTimeout(() => {
            this.messageBox.style.display = 'none';
        }, 5000);
    }
    
    // Start download process
    startDownload(file) {
        // Create a download progress container if it doesn't exist
        if (!document.getElementById('download-progress')) {
            const downloadProgress = document.createElement('div');
            downloadProgress.id = 'download-progress';
            this.container.appendChild(downloadProgress);
        }
        
        // For account-encrypted files, start download immediately
        if (file.passwordType === 'account') {
            this.beginFileDownload(file, { type: 'account' });
            return;
        }
        
        // For custom passwords, show password prompt
        this.showPasswordPrompt(file);
    }
    
    // Show password prompt dialog for password-protected files
    showPasswordPrompt(file) {
        // Create modal container
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close-modal">&times;</span>
                <h3>Enter Password</h3>
                <p>This file is protected with a custom password.</p>
                ${file.passwordHint ? `<p class="password-hint">Hint: ${file.passwordHint}</p>` : ''}
                <div class="form-group">
                    <label for="file-password">Password:</label>
                    <input type="password" id="file-password" class="password-input">
                </div>
                <div class="modal-actions">
                    <button class="cancel-button">Cancel</button>
                    <button class="submit-button">Download</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Setup event handlers
        const closeBtn = modal.querySelector('.close-modal');
        const cancelBtn = modal.querySelector('.cancel-button');
        const submitBtn = modal.querySelector('.submit-button');
        const passwordInput = modal.querySelector('#file-password');
        
        const closeModal = () => {
            modal.remove();
        };
        
        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        
        // Handle form submission
        submitBtn.addEventListener('click', () => {
            const password = passwordInput.value;
            if (!password) {
                this.showMessage('Password is required', 'error');
                return;
            }
            
            this.beginFileDownload(file, {
                type: 'custom',
                password: password
            });
            
            closeModal();
        });
        
        // Handle Enter key
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                submitBtn.click();
            }
        });
        
        // Focus on password input
        setTimeout(() => passwordInput.focus(), 100);
        
        // Show modal
        modal.style.display = 'flex';
    }
    
    // Begin file download after authentication
    async beginFileDownload(file, passwordOptions) {
        // Create download ID and progress element
        const downloadId = Date.now().toString();
        this.createProgressElement(downloadId, file.filename, 'download');
        
        try {
            // Create downloader instance
            const downloader = new ChunkedDownloader({
                onProgress: progress => this.updateProgress(downloadId, progress),
                onComplete: result => {
                    this.completeOperation(downloadId, result, 'download');
                    
                    // Automatically save the file
                    setTimeout(() => downloader.saveFile(), 500);
                },
                onError: error => this.handleError(downloadId, error, 'download')
            });
            
            // Store reference to downloader
            this.activeDownloads.set(downloadId, downloader);
            
            // Initialize and start download
            await downloader.initialize(file.fileId, passwordOptions);
            downloader.start({
                concurrency: 3,
                autoSave: false // We'll save manually after completion
            });
            
        } catch (error) {
            this.handleError(downloadId, error, 'download');
        }
    }
    
    // Show share dialog
    showShareDialog(file) {
        // Create modal container
        const modal = document.createElement('div');
        modal.className = 'modal';
        
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close-modal">&times;</span>
                <h3>Share File</h3>
                <p>Create a shareable link for "${file.filename}"</p>
                
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="password-protect">
                        Password protect this file
                    </label>
                </div>
                
                <div id="share-password-section" style="display: none;">
                    <div class="form-group">
                        <label for="share-password">Password:</label>
                        <input type="password" id="share-password" class="password-input">
                    </div>
                    <div class="password-strength-container">
                        <div class="strength-meter"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="expire-after">Link expires after:</label>
                    <select id="expire-after">
                        <option value="24">24 hours</option>
                        <option value="72">3 days</option>
                        <option value="168">7 days</option>
                        <option value="720">30 days</option>
                        <option value="0">Never</option>
                    </select>
                </div>
                
                <div id="share-result" style="display: none;">
                    <div class="form-group">
                        <label for="share-link">Share Link:</label>
                        <div class="share-link-container">
                            <input type="text" id="share-link" readonly>
                            <button id="copy-link">Copy</button>
                        </div>
                    </div>
                </div>
                
                <div class="modal-actions">
                    <button class="cancel-button">Cancel</button>
                    <button class="submit-button">Create Share Link</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Setup event handlers
        const closeBtn = modal.querySelector('.close-modal');
        const cancelBtn = modal.querySelector('.cancel-button');
        const submitBtn = modal.querySelector('.submit-button');
        const passwordProtect = modal.querySelector('#password-protect');
        const passwordSection = modal.querySelector('#share-password-section');
        const passwordInput = modal.querySelector('#share-password');
        const strengthMeter = modal.querySelector('.strength-meter');
        const shareResult = modal.querySelector('#share-result');
        const shareLink = modal.querySelector('#share-link');
        const copyBtn = modal.querySelector('#copy-link');
        
        const closeModal = () => {
            modal.remove();
        };
        
        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        
        // Toggle password section visibility
        passwordProtect.addEventListener('change', () => {
            passwordSection.style.display = passwordProtect.checked ? 'block' : 'none';
            if (!passwordProtect.checked) {
                passwordInput.value = '';
                strengthMeter.style.width = '0%';
            }
        });
        
        // Password strength meter
        passwordInput.addEventListener('input', (e) => {
            const password = e.target.value;
            if (window.securityUtils && window.securityUtils.updatePasswordStrengthUI) {
                // Create a temporary container for the password section
                window.securityUtils.updatePasswordStrengthUI(password, passwordSection);
            } else {
                // Fallback basic strength meter
                if (!password) {
                    strengthMeter.style.width = '0%';
                    strengthMeter.textContent = '';
                    return;
                }
                
                let strength = 0;
                if (password.length >= 12) strength++;
                if (/[A-Z]/.test(password)) strength++;
                if (/[a-z]/.test(password)) strength++;
                if (/[0-9]/.test(password)) strength++;
                if (/[^A-Za-z0-9]/.test(password)) strength++;
                
                if (strength <= 1) {
                    strengthMeter.style.width = '15%';
                    strengthMeter.style.backgroundColor = '#ff4d4d';
                    strengthMeter.textContent = 'Very Weak!';
                } else if (strength === 2) {
                    strengthMeter.style.width = '35%';
                    strengthMeter.style.backgroundColor = '#ff8c00';
                    strengthMeter.textContent = 'Weak';
                } else if (strength === 3) {
                    strengthMeter.style.width = '60%';
                    strengthMeter.style.backgroundColor = '#ffd700';
                    strengthMeter.textContent = 'Moderate';
                } else if (strength === 4) {
                    strengthMeter.style.width = '80%';
                    strengthMeter.style.backgroundColor = '#90ee90';
                    strengthMeter.textContent = 'Strong';
                } else {
                    strengthMeter.style.width = '100%';
                    strengthMeter.style.backgroundColor = '#32cd32';
                    strengthMeter.textContent = 'Very Strong';
                }
            }
        });
        
        // Copy link button
        copyBtn.addEventListener('click', () => {
            shareLink.select();
            document.execCommand('copy');
            this.showMessage('Link copied to clipboard', 'success');
        });
        
        // Create share link
        submitBtn.addEventListener('click', async () => {
            const isPasswordProtected = passwordProtect.checked;
            const password = isPasswordProtected ? passwordInput.value : '';
            const expiresAfterHours = parseInt(modal.querySelector('#expire-after').value);
            
            // Validate password if protected
            if (isPasswordProtected) {
                if (!password || password.length < 12) {
                    this.showMessage('Password must be at least 12 characters', 'error');
                    return;
                }
                
                // More comprehensive validation
                let strength = 0;
                if (password.length >= 12) strength++;
                if (/[A-Z]/.test(password)) strength++;
                if (/[a-z]/.test(password)) strength++;
                if (/[0-9]/.test(password)) strength++;
                if (/[^A-Za-z0-9]/.test(password)) strength++;
                
                if (strength < 4) {
                    this.showMessage('Password is too weak. Use a stronger password.', 'error');
                    return;
                }
            }
            
            try {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Creating...';
                
                // Prepare share request
                const shareData = {
                    fileId: file.fileId,
                    passwordProtected: isPasswordProtected,
                    expiresAfterHours: expiresAfterHours
                };
                
                if (isPasswordProtected) {
                    shareData.password = password;
                }
                
                // Make API request
                const response = await fetch('/api/files/share', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                    },
                    body: JSON.stringify(shareData)
                });
                
                if (!response.ok) {
                    throw new Error('Failed to create share link');
                }
                
                const data = await response.json();
                
                // Show share link
                shareLink.value = data.shareUrl;
                shareResult.style.display = 'block';
                
                // Change button text
                submitBtn.textContent = 'Link Created!';
                
                // Show success message
                this.showMessage('Share link created successfully', 'success');
                
            } catch (error) {
                this.showMessage(error.message, 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Share Link';
            }
        });
        
        // Show modal
        modal.style.display = 'flex';
    }
}

// Initialize UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.uploadUI = new ChunkedUploadUI();
});
