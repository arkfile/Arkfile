// Initialize WebAssembly
let wasmReady = false;

async function initWasm() {
    const go = new Go();
    try {
        const result = await WebAssembly.instantiateStreaming(
            fetch("/main.wasm"),
            go.importObject
        );
        go.run(result.instance);
        wasmReady = true;
    } catch (err) {
        console.error('Failed to load WASM:', err);
    }
}

initWasm();

// Token management functions
async function refreshToken() {
    try {
        // Get the current refresh token from localStorage
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            // If no refresh token, force login
            localStorage.removeItem('token');
            showAuthSection();
            return false;
        }

        const response = await fetch('/api/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refreshToken }),
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('token', data.token);
            localStorage.setItem('refreshToken', data.refreshToken);
            return true;
        } else {
            // Token refresh failed, force login
            localStorage.removeItem('token');
            localStorage.removeItem('refreshToken');
            showAuthSection();
            return false;
        }
    } catch (error) {
        console.error('Token refresh error:', error);
        return false;
    }
}

async function revokeAllSessions() {
    try {
        const response = await fetch('/api/revoke-all', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json',
            }
        });

        if (response.ok) {
            showSuccess('All sessions have been revoked. Please log in again.');
            // Clear local storage and force login
            localStorage.removeItem('token');
            localStorage.removeItem('refreshToken');
            delete window.arkfileSecurityContext;
            showAuthSection();
            return true;
        } else {
            showError('Failed to revoke sessions.');
            return false;
        }
    } catch (error) {
        console.error('Revoke sessions error:', error);
        showError('An error occurred while revoking sessions.');
        return false;
    }
}

// OPAQUE Authentication Functions


// OPAQUE Authentication functions (Direct server implementation)
async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    if (!email || !password) {
        showError('Please enter both email and password.');
        return;
    }

    try {
        // Ensure WASM is ready
        if (!wasmReady) {
            await initWasm();
        }

        // Check OPAQUE health first (use actual WASM function)
        const healthCheck = opaqueHealthCheck();
        if (!healthCheck.wasmReady) {
            showError('Authentication system not ready. Please try again in a few moments.');
            return;
        }

        showProgress('Authenticating...');

        // Direct call to server OPAQUE endpoint (no client-side protocol)
        const response = await fetch('/api/opaque/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                password: password  // Send directly - OPAQUE handles protocol internally
            }),
        });

        if (response.ok) {
            const data = await response.json();
            
            // Handle TOTP if required
            if (data.requiresTOTP) {
                hideProgress();
                handleTOTPFlow(data);
                return;
            }
            
            // Complete authentication
            localStorage.setItem('token', data.token);
            localStorage.setItem('refreshToken', data.refreshToken);
            
            // Create secure session in WASM (NEVER store session key in JavaScript)
            const sessionResult = createSecureSessionFromOpaqueExport(data.sessionKey, email);
            if (!sessionResult.success) {
                hideProgress();
                showError('Failed to create secure session: ' + sessionResult.error);
                return;
            }
            
            hideProgress();
            showSuccess('Login successful');
            showFileSection();
            loadFiles();
        } else {
            hideProgress();
            const errorData = await response.json().catch(() => ({}));
            showError(errorData.message || 'Login failed');
        }
    } catch (error) {
        hideProgress();
        console.error('Login error:', error);
        showError('Authentication failed');
    }
}

async function register() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-password-confirm').value;

    if (password !== confirmPassword) {
        showError('Passwords do not match.');
        return;
    }

    // Validate password complexity
    if (!wasmReady) {
        await initWasm();
    }
    
    const validation = validatePasswordComplexity(password);
    if (!validation.valid) {
        showError(validation.message);
        return;
    }

    try {
        showProgress('Registering...');

        // Direct call to server OPAQUE endpoint (no client-side protocol)
        const response = await fetch('/api/opaque/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                password: password  // Send directly - OPAQUE handles protocol internally
            }),
        });

        if (response.ok) {
            const data = await response.json();
            
            // Store temporary token for TOTP setup
            window.registrationData = {
                email: email,
                tempToken: data.tempToken,
                sessionKey: data.sessionKey,
                authMethod: 'OPAQUE'
            };
            
            // Proceed to TOTP setup
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('totp-setup-form').classList.remove('hidden');
            
            hideProgress();
            showSuccess('Registration successful! Setting up TOTP...');
        } else {
            hideProgress();
            const errorData = await response.json().catch(() => ({}));
            showError(errorData.message || 'Registration failed');
        }
    } catch (error) {
        hideProgress();
        console.error('Registration error:', error);
        showError('Registration failed');
    }
}

// Progress indicator functions
function showProgress(message) {
    let progressDiv = document.getElementById('progress-indicator');
    if (!progressDiv) {
        progressDiv = document.createElement('div');
        progressDiv.id = 'progress-indicator';
        progressDiv.className = 'progress-message';
        document.body.appendChild(progressDiv);
    }
    progressDiv.textContent = message;
    progressDiv.style.display = 'block';
}

function hideProgress() {
    const progressDiv = document.getElementById('progress-indicator');
    if (progressDiv) {
        progressDiv.style.display = 'none';
    }
}


// File handling functions
async function uploadFile() {
    if (!wasmReady) {
        showError('WASM not ready. Please try again.');
        return;
    }

    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) {
        showError('Please select a file.');
        return;
    }

    const useCustomPassword = document.getElementById('useCustomPassword').checked;
    let password;
    let keyType;

    if (useCustomPassword) {
        password = document.getElementById('filePassword').value;
        const passwordValidation = securityUtils.validatePassword(password);
        if (!passwordValidation.valid) {
            showError(passwordValidation.message);
            return;
        }
        keyType = 'custom';
    } else {
        // Use secure session for account-encrypted files
        const userEmail = getUserEmailFromToken(); // Need to extract email from token
        if (!userEmail) {
            showError('Cannot determine user email. Please log in again.');
            localStorage.removeItem('token');
            showAuthSection();
            return;
        }
        
        // Validate secure session exists
        const sessionValidation = validateSecureSession(userEmail);
        if (!sessionValidation.valid) {
            showError('Your session has expired. Please log in again.');
            localStorage.removeItem('token');
            showAuthSection();
            return;
        }
        
        // File will be encrypted using secure session in WASM
        password = null; // Not needed - will use secure session directly
        keyType = 'account';
    }

    const passwordHint = document.getElementById('passwordHint').value;

    try {
        // Read file as ArrayBuffer
        const fileData = await file.arrayBuffer();
        const fileBytes = new Uint8Array(fileData);
        
        // Calculate SHA-256 hash of original file
        const sha256sum = calculateSHA256(fileBytes);
        
        // Encrypt the file
        let encryptedData;
        if (keyType === 'account') {
            // Use secure session encryption (no password exposed to JavaScript)
            const encryptResult = encryptFileWithSecureSession(fileBytes, userEmail);
            if (!encryptResult.success) {
                showError('Failed to encrypt file: ' + encryptResult.error);
                return;
            }
            encryptedData = encryptResult.data;
        } else {
            // Use custom password encryption
            encryptedData = encryptFile(fileBytes, password, keyType);
        }

        // Prepare form data
        const formData = new FormData();
        formData.append('filename', file.name);
        formData.append('data', encryptedData);
        formData.append('passwordHint', passwordHint);
        formData.append('passwordType', keyType);
        formData.append('sha256sum', sha256sum);

        // Upload to server
        const response = await fetch('/api/upload', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: formData,
        });

        if (response.ok) {
            showSuccess('File uploaded successfully.');
            loadFiles();
        } else {
            showError('Failed to upload file.');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showError('An error occurred during file upload.');
    }
}

async function downloadFile(filename, hint, expectedHash, passwordType) {
    if (!wasmReady) {
        showError('WASM not ready. Please try again.');
        return;
    }

    if (hint) {
        alert(`Password Hint: ${hint}`);
    }

    let decryptedData;
    
    if (passwordType === 'account') {
        // For account-encrypted files, use secure session decryption
        const userEmail = getUserEmailFromToken();
        if (!userEmail) {
            showError('Cannot determine user email. Please log in again.');
            return;
        }
        
        // Validate secure session exists
        const sessionValidation = validateSecureSession(userEmail);
        if (!sessionValidation.valid) {
            showError('Your session has expired. Please log in again to decrypt account-encrypted files.');
            return;
        }
        
        try {
            const response = await fetch(`/api/download/${filename}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                
                // Use secure session decryption (no password exposed to JavaScript)
                const decryptResult = decryptFileWithSecureSession(data.data, userEmail);
                if (!decryptResult.success) {
                    showError('Failed to decrypt file: ' + decryptResult.error);
                    return;
                }
                decryptedData = decryptResult.data;
            } else {
                showError('Failed to download file.');
                return;
            }
        } catch (error) {
            showError('An error occurred during file download.');
            return;
        }
    } else {
        // For custom password-encrypted files
        const password = prompt('Enter the file password:');
        if (!password) return;

        try {
            const response = await fetch(`/api/download/${filename}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`,
                },
            });

            if (response.ok) {
                const data = await response.json();
                decryptedData = decryptFile(data.data, password);

                if (decryptedData === 'Failed to decrypt data') {
                    showError('Incorrect password or corrupted file.');
                    return;
                }
            } else {
                showError('Failed to download file.');
                return;
            }
        } catch (error) {
            showError('An error occurred during file download.');
            return;
        }
    }

    // Convert base64 to Uint8Array for hash verification
    const decryptedBytes = Uint8Array.from(atob(decryptedData), c => c.charCodeAt(0));
    
    // Verify file integrity
    const calculatedHash = calculateSHA256(decryptedBytes);
    if (calculatedHash !== expectedHash) {
        showError('File integrity check failed. The file may be corrupted.');
        return;
    }

    // Create and download the file
    const blob = new Blob([decryptedBytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function loadFiles() {
    try {
        const response = await fetch('/api/files', {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
        });

        if (response.ok) {
            const data = await response.json();
            const filesList = document.getElementById('filesList');
            filesList.innerHTML = '';

            data.files.forEach(file => {
                const fileElement = document.createElement('div');
                fileElement.className = 'file-item';
                fileElement.innerHTML = `
                    <div class="file-info">
                        <strong>${file.filename}</strong>
                        <span class="file-size">${file.size_readable}</span>
                        <span class="file-date">${new Date(file.uploadDate).toLocaleString()}</span>
                        <span class="encryption-type">${file.passwordType === 'account' ? '🔑 Account Password' : '🔒 Custom Password'}</span>
                    </div>
                    <div class="file-actions">
                        <button onclick="downloadFile('${file.filename}', '${file.passwordHint}', '${file.sha256sum}', '${file.passwordType}')">Download</button>
                    </div>
                `;
                filesList.appendChild(fileElement);
            });

            // Update storage info
            updateStorageInfo(data.storage);
        } else {
            showError('Failed to load files.');
        }
    } catch (error) {
        showError('An error occurred while loading files.');
    }
}

// Helper function to display files in the UI
function displayFiles(data) {
    const filesList = document.getElementById('filesList');
    filesList.innerHTML = '';

    data.files.forEach(file => {
        const fileElement = document.createElement('div');
        fileElement.className = 'file-item';
        fileElement.innerHTML = `
            <div class="file-info">
                <strong>${file.filename}</strong>
                <span class="file-size">${file.size_readable}</span>
                <span class="file-date">${new Date(file.uploadDate).toLocaleString()}</span>
                <span class="encryption-type">${file.passwordType === 'account' ? '🔑 Account Password' : '🔒 Custom Password'}</span>
            </div>
            <div class="file-actions">
                <button onclick="downloadFile('${file.filename}', '${file.passwordHint}', '${file.sha256sum}', '${file.passwordType}')">Download</button>
            </div>
        `;
        filesList.appendChild(fileElement);
    });

    // Update storage info
    updateStorageInfo(data.storage);
}

function updateStorageInfo(storage) {
    const storageInfo = document.getElementById('storageInfo');
    if (!storageInfo) return;

    storageInfo.innerHTML = `
        <div class="storage-bar">
            <div class="used" style="width: ${storage.usage_percent}%"></div>
        </div>
        <div class="storage-text">
            Used: ${storage.total_readable} of ${storage.limit_readable} (${storage.usage_percent.toFixed(1)}%)
        </div>
    `;
}

// Logout function
async function logout() {
    try {
        // Get user email for secure session cleanup
        const userEmail = getUserEmailFromToken();
        
        // Get the current refresh token
        const refreshToken = localStorage.getItem('refreshToken');
        
        if (refreshToken) {
            // Call the logout API to revoke the refresh token
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refreshToken }),
            });
        }
        
        // Clear secure session from WASM memory
        if (userEmail) {
            clearSecureSession(userEmail);
        }
        
        // Clear local storage
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        
        // Clear any remaining session context (legacy)
        delete window.arkfileSecurityContext;
        
        // Show auth section
        showAuthSection();
        
        showSuccess('Logged out successfully.');
    } catch (error) {
        console.error('Logout error:', error);
        // Still clear local storage and redirect
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        
        // Try to clear secure session even on error
        const userEmail = getUserEmailFromToken();
        if (userEmail) {
            try {
                clearSecureSession(userEmail);
            } catch (e) {
                console.warn('Failed to clear secure session on logout error:', e);
            }
        }
        
        showAuthSection();
    }
}

// Function to toggle security settings panel
function toggleSecuritySettings() {
    const securityPanel = document.getElementById('security-settings');
    if (securityPanel) {
        securityPanel.classList.toggle('hidden');
    }
}

// Modal utility functions
function createModal(options) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 1000;
    `;

    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';
    modalContent.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 8px;
        max-width: 500px;
        width: 90%;
        max-height: 80vh;
        overflow-y: auto;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    `;

    const title = document.createElement('h3');
    title.style.cssText = `
        margin-top: 0;
        margin-bottom: 15px;
        color: #333;
        text-align: center;
    `;
    title.textContent = options.title;

    const message = document.createElement('div');
    message.style.cssText = `
        margin-bottom: 20px;
        line-height: 1.5;
        color: #666;
        white-space: pre-line;
    `;
    message.textContent = options.message;

    const closeButton = document.createElement('button');
    closeButton.textContent = 'Close';
    closeButton.style.cssText = `
        width: 100%;
        padding: 10px;
        background-color: #007bff;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
    `;
    closeButton.onclick = () => modal.remove();

    modalContent.appendChild(title);
    modalContent.appendChild(message);
    modalContent.appendChild(closeButton);
    modal.appendChild(modalContent);

    // Close modal when clicking outside
    modal.onclick = (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    };

    document.body.appendChild(modal);
    return modal;
}

// Get admin emails from server
let adminEmails = [];
async function fetchAdminEmails() {
    try {
        const response = await fetch('/api/admin-contacts');
        if (response.ok) {
            const data = await response.json();
            adminEmails = data.adminEmails || [];
        }
    } catch (error) {
        console.warn('Could not fetch admin emails:', error);
        adminEmails = ['admin@arkfile.demo']; // Fallback
    }
}

// UI helper functions
function toggleAuthForm() {
    document.getElementById('login-form').classList.toggle('hidden');
    document.getElementById('register-form').classList.toggle('hidden');
}

function showFileSection() {
    document.getElementById('auth-section').classList.add('hidden');
    document.getElementById('file-section').classList.remove('hidden');
}

function showAuthSection() {
    document.getElementById('auth-section').classList.remove('hidden');
    document.getElementById('file-section').classList.add('hidden');
}

function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = message;
    document.body.appendChild(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

function showSuccess(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.textContent = message;
    document.body.appendChild(successDiv);
    setTimeout(() => successDiv.remove(), 5000);
}

// Helper function to extract user email from JWT token
function getUserEmailFromToken() {
    const token = localStorage.getItem('token');
    if (!token) return null;
    
    try {
        // JWT tokens have 3 parts separated by dots
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        
        // Decode the payload (middle part)
        const payload = JSON.parse(atob(parts[1]));
        return payload.email || null;
    } catch (error) {
        console.error('Error extracting email from token:', error);
        return null;
    }
}

// Password confirmation validation function
function updatePasswordConfirmationStatus(password, confirmPassword) {
    const statusElement = document.getElementById('password-match-status');
    if (!statusElement) return;

    // Use the Go-WASM function for validation
    if (!wasmReady) {
        statusElement.textContent = 'Validation not ready...';
        statusElement.className = 'match-status empty';
        return;
    }

    const validation = validatePasswordConfirmation(password, confirmPassword);
    statusElement.textContent = validation.message;
    statusElement.className = `match-status ${validation.status}`;
}

// Event listeners
window.addEventListener('load', async () => {
    // Check if we have a token, but validate it before showing the file interface
    const token = localStorage.getItem('token');
    if (token) {
        try {
            // Validate the token by making a simple API call
            const response = await fetch('/api/files', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });
            
            if (response.ok) {
                // Token is valid, show the file section and load files
                showFileSection();
                const data = await response.json();
                displayFiles(data);
            } else {
                // Token is invalid, clear storage and show auth
                console.warn('Stored token is invalid, clearing and showing auth');
                localStorage.removeItem('token');
                localStorage.removeItem('refreshToken');
                delete window.arkfileSecurityContext;
                showAuthSection();
                
                // Show a user-friendly message
                showError('Your session has expired. Please log in again.');
            }
        } catch (error) {
            // Network error or other issue, clear storage and show auth
            console.error('Error validating token:', error);
            localStorage.removeItem('token');
            localStorage.removeItem('refreshToken');
            delete window.arkfileSecurityContext;
            showAuthSection();
        }
    } else {
        // No token, show auth section
        showAuthSection();
    }
    
    // Set up password type toggle handling
    const passwordTypeRadios = document.querySelectorAll('input[name="passwordType"]');
    const customPasswordSection = document.getElementById('customPasswordSection');
    const filePassword = document.getElementById('filePassword');
    
    passwordTypeRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            const useCustomPassword = e.target.value === 'custom';
            customPasswordSection.classList.toggle('hidden', !useCustomPassword);
            if (!useCustomPassword) {
                filePassword.value = ''; // Clear password field when switching to account password
            }
        });
    });

    // Setup password strength monitoring for registration
    const registerPassword = document.getElementById('register-password');
    const registerPasswordConfirm = document.getElementById('register-password-confirm');
    const registerContainer = document.querySelector('.register-form .password-section');
    if (registerPassword && registerContainer) {
        registerPassword.addEventListener('input', (e) => {
            securityUtils.updatePasswordStrengthUI(e.target.value, registerContainer);
            // Also update confirmation status when main password changes
            if (registerPasswordConfirm.value) {
                updatePasswordConfirmationStatus(registerPassword.value, registerPasswordConfirm.value);
            }
        });
    }

    // Setup password confirmation monitoring
    if (registerPasswordConfirm) {
        registerPasswordConfirm.addEventListener('input', (e) => {
            updatePasswordConfirmationStatus(registerPassword.value, e.target.value);
        });
    }

    // Setup password strength monitoring for file upload
    if (filePassword && customPasswordSection) {
        filePassword.addEventListener('input', (e) => {
            securityUtils.updatePasswordStrengthUI(e.target.value, customPasswordSection);
        });
    }
});

// TOTP Setup Functions
async function generateTOTPSetup() {
    if (!window.registrationData) {
        showError('Registration data not found. Please restart registration.');
        return;
    }

    try {
        const response = await fetch('/api/totp/setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${window.registrationData.tempToken}`
            },
            body: JSON.stringify({ 
                sessionKey: window.registrationData.sessionKey 
            })
        });

        if (response.ok) {
            const data = await response.json();
            
            // Store TOTP setup data
            window.totpSetupData = data;
            
            // Show QR code
            const qrDisplay = document.getElementById('qr-code-display');
            qrDisplay.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(data.qrCodeUrl)}" alt="TOTP QR Code">`;
            
            // Show manual entry code
            document.getElementById('manual-entry-code').textContent = data.manualEntry;
            
            // Show backup codes
            const backupList = document.getElementById('backup-codes-list');
            backupList.innerHTML = '';
            data.backupCodes.forEach(code => {
                const li = document.createElement('li');
                li.textContent = code;
                backupList.appendChild(li);
            });
            
            // Show sections
            document.getElementById('qr-code-section').classList.remove('hidden');
            document.getElementById('backup-codes-section').classList.remove('hidden');
            
            // Enable verification button and add event listener
            const verifyButton = document.getElementById('verify-totp-btn');
            verifyButton.disabled = false;
            
            // Add event listener for TOTP input
            const totpInput = document.getElementById('totp-verify-code');
            totpInput.addEventListener('input', function() {
                this.value = this.value.replace(/[^0-9]/g, '');
                verifyButton.disabled = this.value.length !== 6;
            });
            
            // Add Enter key support
            totpInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && this.value.length === 6) {
                    verifyTOTPSetup();
                }
            });
            
            showSuccess('TOTP setup generated! Scan the QR code and enter the verification code.');
            
        } else {
            const errorData = await response.json().catch(() => ({}));
            showError(`TOTP setup failed: ${errorData.message || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('TOTP setup error:', error);
        showError('Failed to generate TOTP setup.');
    }
}

async function verifyTOTPSetup() {
    const code = document.getElementById('totp-verify-code').value;
    
    if (!code || code.length !== 6) {
        showError('Please enter a 6-digit verification code.');
        return;
    }

    if (!window.registrationData || !window.totpSetupData) {
        showError('Setup data not found. Please restart the process.');
        return;
    }

    try {
        const response = await fetch('/api/totp/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${window.registrationData.tempToken}`
            },
            body: JSON.stringify({ 
                code: code,
                sessionKey: window.registrationData.sessionKey 
            })
        });

        if (response.ok) {
            showSuccess('TOTP verification successful! Your registration is complete.');
            
            // Show completion message
            await showRegistrationComplete();
            
        } else {
            const errorData = await response.json().catch(() => ({}));
            showError(`TOTP verification failed: ${errorData.message || 'Invalid code'}`);
        }
    } catch (error) {
        console.error('TOTP verification error:', error);
        showError('Failed to verify TOTP code.');
    }
}

async function showRegistrationComplete() {
    // Fetch admin emails for contact info
    await fetchAdminEmails();
    
    const adminContactList = adminEmails.length > 0 
        ? adminEmails.join('\n• ') 
        : 'admin@arkfile.demo';
        
    createModal({
        title: "Registration Complete!",
        message: `🎉 Your account has been successfully created with ${window.registrationData.authMethod} and TOTP 2FA!

📋 Next Steps:
• An administrator must approve your account before you can log in
• You will receive an email notification when approved
• This usually takes 1-2 business days

🔐 Security Features Enabled:
• OPAQUE password authentication
• Two-factor authentication (TOTP)
• Encrypted file storage

📧 Need help or want to check your status?
Contact an administrator:
• ${adminContactList}

💡 Tip: Include your registered email address (${window.registrationData.email}) when contacting support.

⚠️ Important: Make sure you've saved your backup codes in a secure location!`
    });
    
    // Clear registration data
    delete window.registrationData;
    delete window.totpSetupData;
    
    // Return to login form
    setTimeout(() => {
        document.getElementById('totp-setup-form').classList.add('hidden');
        document.getElementById('login-form').classList.remove('hidden');
        document.getElementById('register-form').classList.add('hidden');
    }, 3000);
}

function downloadBackupCodes() {
    if (!window.totpSetupData || !window.totpSetupData.backupCodes) {
        showError('Backup codes not available.');
        return;
    }
    
    const codes = window.totpSetupData.backupCodes;
    const content = `Arkfile TOTP Backup Codes
Generated: ${new Date().toISOString()}
Account: ${window.registrationData.email}

⚠️ IMPORTANT: Keep these codes secure and confidential!
⚠️ Each code can only be used once.
⚠️ Use these codes if you lose access to your authenticator app.

Backup Codes:
${codes.map((code, index) => `${index + 1}. ${code}`).join('\n')}

Instructions:
1. Store these codes in a secure location (password manager, encrypted file, etc.)
2. Never share these codes with anyone
3. If you use a backup code, generate new ones immediately
4. Contact an administrator if you lose both your authenticator and backup codes

Support Contact: ${adminEmails.join(', ')}`;
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `arkfile-backup-codes-${window.registrationData.email}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    showSuccess('Backup codes downloaded successfully!');
}

function cancelRegistration() {
    createModal({
        title: "Cancel Registration?",
        message: "Are you sure you want to cancel the registration process? Your account will not be created and you'll need to start over."
    });
    
    // Add custom buttons to modal
    const modal = document.querySelector('.modal-overlay');
    const modalContent = modal.querySelector('.modal-content');
    const closeButton = modalContent.querySelector('button');
    
    closeButton.textContent = 'Keep Setting Up';
    
    const cancelButton = document.createElement('button');
    cancelButton.textContent = 'Yes, Cancel Registration';
    cancelButton.style.cssText = `
        width: 100%;
        padding: 10px;
        background-color: #dc3545;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        margin-top: 10px;
    `;
    cancelButton.onclick = () => {
        // Clear registration data
        delete window.registrationData;
        delete window.totpSetupData;
        
        // Return to login form
        document.getElementById('totp-setup-form').classList.add('hidden');
        document.getElementById('login-form').classList.remove('hidden');
        document.getElementById('register-form').classList.add('hidden');
        
        modal.remove();
        showSuccess('Registration cancelled.');
    };
    
    modalContent.appendChild(cancelButton);
}

// Handle TOTP flow during login
function handleTOTPFlow(data) {
    // Store the partial login data
    window.totpLoginData = {
        partialToken: data.partialToken,
        email: data.email
    };
    
    // Show TOTP input
    const totpModal = createModal({
        title: "Two-Factor Authentication",
        message: "Please enter your 6-digit TOTP code from your authenticator app:"
    });
    
    // Replace the close button with TOTP input form
    const modalContent = totpModal.querySelector('.modal-content');
    const closeButton = modalContent.querySelector('button');
    closeButton.remove();
    
    const totpForm = document.createElement('div');
    totpForm.innerHTML = `
        <input type="text" id="totp-login-code" maxlength="6" placeholder="000000" style="
            width: 100%;
            padding: 10px;
            font-size: 18px;
            text-align: center;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 15px;
            letter-spacing: 0.2em;
        ">
        <button id="verify-totp-login" disabled style="
            width: 100%;
            padding: 10px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-bottom: 10px;
        ">Verify</button>
        <button onclick="this.closest('.modal-overlay').remove(); delete window.totpLoginData;" style="
            width: 100%;
            padding: 10px;
            background-color: #6c757d;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        ">Cancel</button>
    `;
    
    modalContent.appendChild(totpForm);
    
    // Add event listeners
    const totpInput = document.getElementById('totp-login-code');
    const verifyButton = document.getElementById('verify-totp-login');
    
    totpInput.addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
        verifyButton.disabled = this.value.length !== 6;
    });
    
    totpInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && this.value.length === 6) {
            verifyTOTPLogin();
        }
    });
    
    verifyButton.addEventListener('click', verifyTOTPLogin);
    
    // Focus the input
    setTimeout(() => totpInput.focus(), 100);
}

async function verifyTOTPLogin() {
    const code = document.getElementById('totp-login-code').value;
    
    if (!code || code.length !== 6) {
        showError('Please enter a 6-digit code.');
        return;
    }
    
    if (!window.totpLoginData) {
        showError('Login session expired. Please try again.');
        return;
    }
    
    try {
        showProgress('Verifying TOTP...');
        
        const response = await fetch('/api/opaque/login-totp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                partialToken: window.totpLoginData.partialToken,
                totpCode: code
            }),
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Complete authentication
            localStorage.setItem('token', data.token);
            localStorage.setItem('refreshToken', data.refreshToken);
            
            // Store session context
            window.arkfileSecurityContext = {
                sessionKey: data.sessionKey,
                authMethod: 'OPAQUE',
                expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
            };
            
            // Clean up
            delete window.totpLoginData;
            document.querySelector('.modal-overlay').remove();
            
            hideProgress();
            showSuccess('Login successful');
            showFileSection();
            loadFiles();
        } else {
            hideProgress();
            const errorData = await response.json().catch(() => ({}));
            showError(errorData.message || 'TOTP verification failed');
        }
    } catch (error) {
        hideProgress();
        console.error('TOTP verification error:', error);
        showError('TOTP verification failed');
    }
}

// Check session validity periodically
setInterval(() => {
    const securityContext = window.arkfileSecurityContext;
    if (securityContext && Date.now() > securityContext.expiresAt) {
        delete window.arkfileSecurityContext;
    }
}, 60000); // Check every minute
