// multi-key-encryption.js - Support for multi-key encryption in Arkfile
// Provides functions to work with the dual-key encryption system

// Initialize WASM
async function ensureWasmReady() {
    if (!window.wasmReady) {
        await initWasm();
    }
}

// Upload a file with multi-key encryption
async function uploadFileWithMultiKey(file, options) {
    await ensureWasmReady();
    
    const {
        useAccountPassword = true,  
        customPassword = null,
        passwordHint = '',
        onProgress = () => {},
        onComplete = () => {},
        onError = (err) => console.error(err)
    } = options;
    
    try {
        // Initialize chunked uploader
        const uploader = new ChunkedUploader({
            chunkSize: 16 * 1024 * 1024, // 16MB chunks
            onProgress,
            onComplete,
            onError
        });
        
        // Prepare password options
        const passwordOptions = {
            type: useAccountPassword ? 'account' : 'custom',
            password: useAccountPassword ? 
                window.arkfileSecurityContext?.sessionKey : 
                customPassword,
            hint: passwordHint
        };
        
        // Multi-key flag to indicate this is a multi-key encrypted file
        passwordOptions.multiKey = true;
        
        // Initialize upload
        await uploader.initialize(file, passwordOptions);
        
        // Start chunked upload
        const result = await uploader.start({
            concurrency: 3 // Number of concurrent uploads
        });
        
        return result;
    } catch (error) {
        onError(error);
        throw error;
    }
}

// Add a sharing key to an existing file
async function addSharingKey(filename, customPassword, keyLabel = "Sharing Key", passwordHint = "") {
    await ensureWasmReady();
    
    // Validate password complexity
    const validation = securityUtils.validatePassword(customPassword);
    if (!validation.valid) {
        throw new Error(validation.message);
    }
    
    // Check session
    const securityContext = window.arkfileSecurityContext;
    if (!securityContext || Date.now() > securityContext.expiresAt) {
        throw new Error('Your session has expired. Please log in again.');
    }
    
    // Get the encrypted file
    const response = await fetch(`/api/files/${filename}`, {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    });
    
    if (!response.ok) {
        throw new Error('Failed to retrieve file data');
    }
    
    const data = await response.json();
    
    // Generate a unique key ID
    const keyId = `share-${Date.now()}`;
    
    // Determine if this is already a multi-key file or needs conversion
    let updatedEncryptedData;
    
    if (data.multiKey) {
        // Already a multi-key file, just add a new key
        updatedEncryptedData = addKeyToEncryptedFile(
            data.data, 
            securityContext.sessionKey,
            customPassword,
            keyId
        );
    } else {
        // First-time conversion from single-key to multi-key
        // 1. Decrypt with current key
        const decryptedData = decryptFile(data.data, securityContext.sessionKey);
        
        // 2. Convert base64 to binary
        const binary = atob(decryptedData);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        
        // 3. Re-encrypt with multi-key format (both keys)
        const additionalKeys = [{ 
            password: customPassword, 
            id: keyId 
        }];
        
        updatedEncryptedData = encryptFileMultiKey(
            bytes, 
            securityContext.sessionKey,
            "account",
            additionalKeys
        );
    }
    
    // Save the updated file encryption
    const updateResponse = await fetch(`/api/files/${filename}/update-encryption`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            encryptedData: updatedEncryptedData,
            newKeyId: keyId,
            keyLabel: keyLabel,
            passwordHint: passwordHint
        })
    });
    
    if (!updateResponse.ok) {
        throw new Error('Failed to update file encryption');
    }
    
    return { 
        success: true, 
        keyId: keyId,
        password: customPassword
    };
}

// Create a share link after adding a sharing key
async function createShareLink(filename, customPassword, keyLabel = "Share Access", passwordHint = "", expiresAfterHours = 0) {
    try {
        // First add a sharing key if a custom password is provided
        if (customPassword) {
            await addSharingKey(filename, customPassword, keyLabel, passwordHint);
        }
        
        // Now create the actual share link
        const shareResponse = await fetch('/api/share', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fileId: filename,
                passwordProtected: false,  // No additional password on share link
                expiresAfterHours: expiresAfterHours
            })
        });
        
        if (!shareResponse.ok) {
            throw new Error('Failed to create share link');
        }
        
        const shareData = await shareResponse.json();
        
        return {
            success: true,
            shareUrl: shareData.shareUrl,
            password: customPassword  // Return so it can be displayed to user
        };
    } catch (error) {
        console.error('Share creation error:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// List keys for a file
async function listFileKeys(filename) {
    const response = await fetch(`/api/files/${filename}/keys`, {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    });
    
    if (!response.ok) {
        throw new Error('Failed to retrieve file keys');
    }
    
    return response.json();
}

// Remove a key from a file
async function removeFileKey(filename, keyId) {
    const response = await fetch(`/api/files/${filename}/keys/${keyId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    });
    
    if (!response.ok) {
        throw new Error('Failed to remove key');
    }
    
    return response.json();
}

// Update key details like label or password hint
async function updateKeyDetails(filename, keyId, updates) {
    const response = await fetch(`/api/files/${filename}/keys/${keyId}`, {
        method: 'PATCH',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(updates)
    });
    
    if (!response.ok) {
        throw new Error('Failed to update key details');
    }
    
    return response.json();
}

// Register these functions globally
window.arkfileEncryption = {
    uploadFileWithMultiKey,
    addSharingKey,
    createShareLink,
    listFileKeys,
    removeFileKey,
    updateKeyDetails
};

// Enhance the downloader to support multi-key files
const originalDownloadFile = window.downloadFile;
window.downloadFile = async function(filename, hint, expectedHash, passwordType, isMultiKey) {
    await ensureWasmReady();
    
    if (hint) {
        alert(`Password Hint: ${hint}`);
    }

    let password;
    
    if (passwordType === 'account') {
        // For account-encrypted files, use the session key
        const securityContext = window.arkfileSecurityContext;
        
        if (!securityContext || Date.now() > securityContext.expiresAt) {
            alert('Your session has expired. Please log in again to decrypt account-encrypted files.');
            return;
        }
        
        password = securityContext.sessionKey;
    } else {
        // For custom password-encrypted files
        password = prompt('Enter the file password:');
        if (!password) return;
    }

    try {
        const response = await fetch(`/api/download/${filename}`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
        });

        if (!response.ok) {
            alert('Failed to download file.');
            return;
        }

        const data = await response.json();
        
        // Use appropriate decryption function based on file type
        let decryptedData;
        if (isMultiKey) {
            decryptedData = decryptFileMultiKey(data.data, password);
        } else {
            decryptedData = decryptFile(data.data, password);
        }

        if (typeof decryptedData === 'string' && decryptedData.startsWith('Failed')) {
            alert('Incorrect password or corrupted file.');
            return;
        }

        // Convert base64 to Uint8Array for hash verification
        const decryptedBytes = Uint8Array.from(atob(decryptedData), c => c.charCodeAt(0));
        
        // Verify file integrity
        const calculatedHash = calculateSHA256(decryptedBytes);
        if (calculatedHash !== expectedHash) {
            alert('File integrity check failed. The file may be corrupted.');
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
    } catch (error) {
        alert('An error occurred during file download: ' + error.message);
    }
};
