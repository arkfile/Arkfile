/**
 * File Upload Module
 * 
 * Handles chunked file uploads with client-side encryption.
 * Matches the Go CLI implementation for cross-platform compatibility.
 * 
 * Upload Flow:
 * 1. Resolve account key (from cache, provided key, or password derivation)
 * 2. Generate random FEK (File Encryption Key)
 * 3. Encrypt metadata (filename, SHA256) with account key
 * 4. Encrypt FEK with appropriate KEK (account or custom derived)
 * 5. Encrypt file chunks with FEK using AES-256-GCM
 * 6. Upload chunks to server via chunked upload API
 * 
 * Key design: Metadata is ALWAYS encrypted with the account-derived key,
 * regardless of password type. The password type only governs FEK encryption.
 * This keeps file lists readable without requiring custom passwords.
 */

import {
  randomBytes,
  encryptAESGCM,
  generateIV,
  hash256,
  toBase64,
  toHex,
  secureWipe,
  concatBytes,
} from '../crypto/primitives.js';
import {
  deriveFileEncryptionKey,
  deriveFileEncryptionKeyWithCache,
  getCachedAccountKey,
  isAccountKeyCached,
  isAccountKeyLocked,
  type PasswordContext,
  type CacheDurationHours,
} from '../crypto/file-encryption.js';
import { promptForAccountKeyPassword } from '../ui/password-modal.js';
import {
  KEY_SIZES,
  getChunkingParams,
} from '../crypto/constants.js';
import { showError, showSuccess, showInfo } from '../ui/messages.js';
import { checkDuplicate, addDigest } from '../utils/digest-cache.js';

// ============================================================================
// Types
// ============================================================================

export interface UploadOptions {
  /** Pre-derived account key for metadata encryption (skips derivation if provided) */
  accountKey?: Uint8Array;
  /** Account password — used to derive account key if not provided or cached */
  accountPassword?: string;
  /** Username for salt derivation and API context */
  username: string;
  /** 'account' or 'custom' — governs FEK encryption key */
  passwordType: PasswordContext;
  /** Custom password — required when passwordType === 'custom' (derives custom KEK) */
  customPassword?: string;
  /** Optional hint for custom passwords (stored unencrypted) */
  passwordHint?: string;
  /** Progress callback */
  onProgress?: (progress: UploadProgress) => void;
}

export interface UploadProgress {
  /** Current phase of upload */
  phase: 'deriving-key' | 'encrypting' | 'uploading' | 'completing';
  /** Percentage complete (0-100) */
  percent: number;
  /** Current chunk being processed */
  currentChunk?: number;
  /** Total number of chunks */
  totalChunks?: number;
  /** Bytes uploaded so far */
  bytesUploaded?: number;
  /** Total bytes to upload */
  totalBytes?: number;
}

export interface UploadResult {
  /** Server-assigned file ID */
  fileId: string;
  /** Storage ID (for verification) */
  storageId: string;
  /** SHA256 hash of encrypted file (server-calculated) */
  encryptedFileSha256: string;
  /** Storage usage info */
  storage: {
    totalBytes: number;
    limitBytes: number;
    availableBytes: number;
  };
}

interface UploadSession {
  sessionId: string;
  fileId: string;
  chunkSize: number;
  totalChunks: number;
  expiresAt: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Gets the authentication token from storage
 */
function getAuthToken(): string | null {
  return sessionStorage.getItem('arkfile.sessionToken') || 
         localStorage.getItem('arkfile.sessionToken');
}

/**
 * Makes an authenticated API request
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getAuthToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${token}`);
  
  if (options.body && !(options.body instanceof FormData) && !(options.body instanceof Blob)) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage: string;
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.message || errorJson.error || errorText;
    } catch {
      errorMessage = errorText;
    }
    throw new Error(`API error (${response.status}): ${errorMessage}`);
  }

  return response.json();
}

/**
 * Encrypts data with AES-256-GCM (no AAD for file data)
 * Returns: [nonce (12)][ciphertext][tag (16)]
 */
async function encryptChunk(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const result = await encryptAESGCM({
    data,
    key,
    // No AAD for file chunks - matches Go implementation
  });
  
  // Combine: [nonce][ciphertext][tag]
  return concatBytes(result.iv, result.ciphertext, result.tag);
}

/**
 * Encrypts metadata (filename or SHA256) with AES-256-GCM
 * Returns separate nonce and ciphertext+tag for API format
 * 
 * NOTE: Metadata is always encrypted with the account-derived key,
 * not the FEK. This matches the Go CLI implementation.
 */
async function encryptMetadata(
  data: string,
  key: Uint8Array
): Promise<{ encrypted: string; nonce: string }> {
  const dataBytes = new TextEncoder().encode(data);
  
  const result = await encryptAESGCM({
    data: dataBytes,
    key,
    // No AAD for metadata - matches Go implementation
  });
  
  // Combine ciphertext and tag
  const encryptedWithTag = concatBytes(result.ciphertext, result.tag);
  
  return {
    encrypted: toBase64(encryptedWithTag),
    nonce: toBase64(result.iv),
  };
}

/**
 * Creates the 2-byte envelope header
 * Format: [version (1 byte)][keyType (1 byte)]
 * Values loaded from chunking config (single source of truth)
 */
function createEnvelopeHeader(envelopeVersion: number, keyType: number): Uint8Array {
  return new Uint8Array([envelopeVersion, keyType]);
}

/**
 * Resolves the account key from the available sources.
 * Priority: provided key > cached key > derive from password
 */
async function resolveAccountKey(
  options: Pick<UploadOptions, 'accountKey' | 'accountPassword' | 'username'>
): Promise<Uint8Array> {
  const { accountKey, accountPassword, username } = options;

  // 1. Use provided key directly
  if (accountKey && accountKey.length === KEY_SIZES.FILE_ENCRYPTION_KEY) {
    return accountKey;
  }

  // 2. Check cache
  if (isAccountKeyCached(username) && !isAccountKeyLocked()) {
    const cached = getCachedAccountKey(username);
    if (cached) {
      return cached;
    }
  }

  // 3. Derive from password
  if (accountPassword) {
    return deriveFileEncryptionKey(accountPassword, username, 'account');
  }

  throw new Error('Account key required: provide accountKey, ensure key is cached, or provide accountPassword');
}

// ============================================================================
// Main Upload Function
// ============================================================================

/**
 * Uploads a file with client-side encryption
 * 
 * Single entry point for all file uploads. Handles both account and custom
 * password types. Metadata is always encrypted with the account key.
 * 
 * @param file - The file to upload
 * @param options - Upload options
 * @returns Upload result with file ID and storage info
 */
export async function uploadFile(
  file: File,
  options: UploadOptions
): Promise<UploadResult> {
  const { username, passwordType, customPassword, passwordHint, onProgress } = options;

  // Validate inputs
  if (!file) {
    throw new Error('No file provided');
  }
  if (!username) {
    throw new Error('Username is required');
  }
  if (passwordType !== 'account' && passwordType !== 'custom') {
    throw new Error('Invalid password type: must be "account" or "custom"');
  }
  if (passwordType === 'custom' && !customPassword) {
    throw new Error('Custom password is required when passwordType is "custom"');
  }

  const reportProgress = (progress: UploadProgress) => {
    if (onProgress) {
      onProgress(progress);
    }
  };

  try {
    // Load chunking config from single source of truth
    const chunkCfg = await getChunkingParams();
    const CHUNK_SIZE = chunkCfg.plaintextChunkSizeBytes;
    const nonceSize = chunkCfg.aesGcm.nonceSizeBytes;
    const tagSize = chunkCfg.aesGcm.tagSizeBytes;
    const envelopeVersion = chunkCfg.envelope.version;
    const keyTypeVal = passwordType === 'account'
      ? chunkCfg.envelope.keyTypes.account
      : chunkCfg.envelope.keyTypes.custom;

    // ================================================================
    // Step 1: Resolve keys
    // ================================================================
    reportProgress({ phase: 'deriving-key', percent: 0 });

    // Account key — always needed for metadata encryption
    const accountKey = await resolveAccountKey(options);

    // FEK encryption key — depends on password type
    let fekEncryptionKey: Uint8Array;
    if (passwordType === 'account') {
      fekEncryptionKey = accountKey;
    } else {
      // Custom: derive separate key from custom password
      fekEncryptionKey = await deriveFileEncryptionKey(customPassword!, username, 'custom');
    }

    // ================================================================
    // Step 2: Generate FEK and prepare encryption
    // ================================================================
    reportProgress({ phase: 'encrypting', percent: 5 });

    // Generate random FEK (File Encryption Key)
    const fek = randomBytes(KEY_SIZES.FILE_ENCRYPTION_KEY);

    // Calculate SHA256 of plaintext file
    const fileBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuffer);
    const plaintextHash = hash256(fileBytes);
    const plaintextHashHex = toHex(plaintextHash);

    // ----------------------------------------------------------------
    // Deduplication check: abort early if file already exists
    // ----------------------------------------------------------------
    const existingFileId = checkDuplicate(plaintextHashHex);
    if (existingFileId) {
      secureWipe(fek);
      throw new Error(
        `Duplicate file detected (already uploaded as ${existingFileId}). ` +
        'Delete the existing copy before uploading again.'
      );
    }

    // Encrypt metadata with ACCOUNT key (always, regardless of password type)
    const encryptedFilename = await encryptMetadata(file.name, accountKey);
    const encryptedSha256 = await encryptMetadata(plaintextHashHex, accountKey);

    // Encrypt FEK with the appropriate KEK
    const encryptedFekResult = await encryptAESGCM({
      data: fek,
      key: fekEncryptionKey,
      // No AAD for FEK encryption - matches Go implementation
    });

    // Prepend 2-byte envelope header to encrypted FEK
    // Format: [version(1)][keyType(1)][nonce(12)][ciphertext][tag(16)]
    // This matches crypto.EncryptFEK() in Go
    const envelopeHeader = createEnvelopeHeader(envelopeVersion, keyTypeVal);
    const encryptedFek = concatBytes(
      envelopeHeader,
      encryptedFekResult.iv,
      encryptedFekResult.ciphertext,
      encryptedFekResult.tag
    );

    reportProgress({ phase: 'encrypting', percent: 10 });

    // ================================================================
    // Step 3: Encrypt file chunks
    // ================================================================
    const totalChunks = Math.ceil(fileBytes.length / CHUNK_SIZE);
    const encryptedChunks: Uint8Array[] = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileBytes.length);
      const chunk = fileBytes.slice(start, end);

      // Encrypt chunk with FEK
      const encryptedChunk = await encryptChunk(chunk, fek);

      // For chunk 0, prepend the envelope header
      if (i === 0) {
        const chunkEnvelope = createEnvelopeHeader(envelopeVersion, keyTypeVal);
        encryptedChunks.push(concatBytes(chunkEnvelope, encryptedChunk));
      } else {
        encryptedChunks.push(encryptedChunk);
      }

      const encryptPercent = 10 + Math.floor((i + 1) / totalChunks * 40);
      reportProgress({
        phase: 'encrypting',
        percent: encryptPercent,
        currentChunk: i + 1,
        totalChunks,
      });
    }

    // Calculate total encrypted size
    const totalEncryptedSize = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);

    // Clean up sensitive key material
    secureWipe(fek);
    if (passwordType === 'custom') {
      secureWipe(fekEncryptionKey);
    }

    reportProgress({ phase: 'encrypting', percent: 50 });

    // ================================================================
    // Step 4: Create upload session
    // ================================================================
    reportProgress({ phase: 'uploading', percent: 50 });

    const session = await apiRequest<UploadSession>('/api/uploads/init', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_filename: encryptedFilename.encrypted,
        filename_nonce: encryptedFilename.nonce,
        encrypted_sha256sum: encryptedSha256.encrypted,
        sha256sum_nonce: encryptedSha256.nonce,
        encrypted_fek: toBase64(encryptedFek),
        total_size: totalEncryptedSize,
        chunk_size: CHUNK_SIZE + nonceSize + tagSize + chunkCfg.envelope.headerSizeBytes,
        password_hint: passwordHint || '',
        password_type: passwordType,
      }),
    });

    // ================================================================
    // Step 5: Upload chunks
    // ================================================================
    let bytesUploaded = 0;

    for (let i = 0; i < encryptedChunks.length; i++) {
      const chunk = encryptedChunks[i];
      
      // Calculate chunk hash for verification
      const chunkHash = toHex(hash256(chunk));

      // Upload chunk as raw binary with hash header
      const chunkBuffer = chunk.buffer.slice(
        chunk.byteOffset,
        chunk.byteOffset + chunk.byteLength
      ) as ArrayBuffer;
      
      await apiRequest(`/api/uploads/${session.sessionId}/chunks/${i}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Chunk-Hash': chunkHash,
        },
        body: new Blob([chunkBuffer]),
      });

      bytesUploaded += chunk.length;
      const uploadPercent = 50 + Math.floor((i + 1) / encryptedChunks.length * 40);
      reportProgress({
        phase: 'uploading',
        percent: uploadPercent,
        currentChunk: i + 1,
        totalChunks: encryptedChunks.length,
        bytesUploaded,
        totalBytes: totalEncryptedSize,
      });
    }

    // ================================================================
    // Step 6: Complete upload
    // ================================================================
    reportProgress({ phase: 'completing', percent: 90 });

    const result = await apiRequest<{
      message: string;
      file_id: string;
      storage_id: string;
      encrypted_file_sha256: string;
      storage: {
        total_bytes: number;
        limit_bytes: number;
        available_bytes: number;
      };
    }>(`/api/uploads/${session.sessionId}/complete`, {
      method: 'POST',
    });

    reportProgress({ phase: 'completing', percent: 100 });

    // Update digest cache so subsequent uploads in this session are deduped
    addDigest(result.file_id, plaintextHashHex);

    return {
      fileId: result.file_id,
      storageId: result.storage_id,
      encryptedFileSha256: result.encrypted_file_sha256,
      storage: {
        totalBytes: result.storage.total_bytes,
        limitBytes: result.storage.limit_bytes,
        availableBytes: result.storage.available_bytes,
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Upload failed';
    throw new Error(message);
  }
}

// ============================================================================
// UI Integration
// ============================================================================

/**
 * Handles file upload from the UI
 * This is the main entry point called from the HTML page
 * 
 * For 'account' password type:
 * - First checks if Account Key is cached and not locked
 * - If cached, uses it directly (no password prompt needed)
 * - If not cached or locked, prompts for password
 * 
 * For 'custom' password type:
 * - Always requires the custom password input
 * - Also needs the account key (from cache or prompt) for metadata encryption
 */
export async function handleFileUpload(): Promise<void> {
  // Get file input — HTML uses id="fileInput"
  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showError('Please select a file to upload');
    return;
  }

  const file = fileInput.files[0];

  // Get username from session
  const username = sessionStorage.getItem('arkfile.username') || 
                   localStorage.getItem('arkfile.username');
  if (!username) {
    showError('Not logged in. Please log in first.');
    return;
  }

  // Get password type — HTML uses radio buttons named "passwordType"
  const passwordTypeRadio = document.querySelector<HTMLInputElement>('input[name="passwordType"]:checked');
  const passwordType = (passwordTypeRadio?.value || 'account') as PasswordContext;

  // Get password hint — HTML uses id="passwordHint"
  const hintInput = document.getElementById('passwordHint') as HTMLInputElement | null;
  const passwordHint = hintInput?.value || '';

  // Get progress elements
  const progressBar = document.getElementById('upload-progress') as HTMLProgressElement | null;
  const progressText = document.getElementById('upload-progress-text') as HTMLElement | null;
  // Upload button — HTML uses id="upload-file-btn"
  const uploadButton = document.getElementById('upload-file-btn') as HTMLButtonElement | null;

  // Build upload options
  const uploadOptions: UploadOptions = {
    username,
    passwordType,
    passwordHint,
  };

  // Resolve account key / password (always needed for metadata)
  if (isAccountKeyCached(username) && !isAccountKeyLocked()) {
    // Account key is cached — use it directly
    const cachedKey = getCachedAccountKey(username);
    if (cachedKey) {
      uploadOptions.accountKey = cachedKey;
    }
  }

  if (!uploadOptions.accountKey) {
    // Need to prompt for account password
    const passwordInput = document.getElementById('upload-password') as HTMLInputElement | null;
    let accountPassword = passwordInput?.value;

    if (!accountPassword) {
      // Show password modal
      const result = await promptForAccountKeyPassword();
      if (!result) {
        // User cancelled
        return;
      }
      accountPassword = result.password;

      // If user chose to remember, derive and cache the key
      if (result.cacheDuration) {
        const derivedKey = await deriveFileEncryptionKeyWithCache(
          accountPassword, username, 'account', result.cacheDuration
        );
        uploadOptions.accountKey = derivedKey;
      }
    }

    // If we still don't have a derived key, pass the password for derivation
    if (!uploadOptions.accountKey) {
      uploadOptions.accountPassword = accountPassword;
    }
  }

  // For custom password type, get the custom password — HTML uses id="filePassword"
  if (passwordType === 'custom') {
    const customPasswordInput = document.getElementById('filePassword') as HTMLInputElement | null;
    const customPassword = customPasswordInput?.value;
    if (!customPassword) {
      showError('Please enter your custom password for file encryption');
      return;
    }
    uploadOptions.customPassword = customPassword;
  }

  // Disable upload button during upload
  if (uploadButton) {
    uploadButton.disabled = true;
  }

  try {
    showInfo(`Uploading ${file.name}...`);

    uploadOptions.onProgress = (progress) => {
      if (progressBar) {
        progressBar.value = progress.percent;
      }
      if (progressText) {
        let text = `${progress.phase}: ${progress.percent}%`;
        if (progress.currentChunk && progress.totalChunks) {
          text += ` (chunk ${progress.currentChunk}/${progress.totalChunks})`;
        }
        progressText.textContent = text;
      }
    };

    const result = await uploadFile(file, uploadOptions);
    showSuccess(`File uploaded successfully! File ID: ${result.fileId}`);

    // Clear the form
    if (fileInput) fileInput.value = '';
    const customPasswordInput = document.getElementById('filePassword') as HTMLInputElement | null;
    if (customPasswordInput) customPasswordInput.value = '';
    if (hintInput) hintInput.value = '';
    if (progressBar) progressBar.value = 0;
    if (progressText) progressText.textContent = '';

    // Refresh file list if available
    const refreshButton = document.getElementById('refresh-files');
    if (refreshButton) {
      refreshButton.click();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Upload failed';
    showError(message);
  } finally {
    if (uploadButton) {
      uploadButton.disabled = false;
    }
  }
}

// ============================================================================
// Exports
// ============================================================================

export const upload = {
  uploadFile,
  handleFileUpload,
};
