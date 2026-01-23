/**
 * File Upload Module
 * 
 * Handles chunked file uploads with client-side encryption.
 * Matches the Go CLI implementation for cross-platform compatibility.
 * 
 * Upload Flow:
 * 1. Generate random FEK (File Encryption Key)
 * 2. Encrypt file chunks with FEK using AES-256-GCM
 * 3. Encrypt metadata (filename, SHA256) with FEK
 * 4. Encrypt FEK with user's password-derived key (Argon2id)
 * 5. Upload chunks to server via multipart upload API
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
} from '../crypto/file-encryption.js';
import { promptForAccountKeyPassword } from '../ui/password-modal.js';
import {
  KEY_SIZES,
  DEFAULT_CHUNK_SIZE_BYTES,
  AES_GCM_NONCE_SIZE,
  AES_GCM_TAG_SIZE,
} from '../crypto/constants.js';
import { showError, showSuccess, showInfo } from '../ui/messages.js';

// ============================================================================
// Types
// ============================================================================

export interface UploadOptions {
  /** Password for encrypting the FEK */
  password: string;
  /** Username for deterministic salt derivation */
  username: string;
  /** Password type: 'account' or 'custom' */
  passwordType: PasswordContext;
  /** Optional password hint (stored unencrypted) */
  passwordHint?: string;
  /** Progress callback */
  onProgress?: (progress: UploadProgress) => void;
}

/**
 * Options for uploading with a pre-derived key (from cache)
 */
export interface UploadWithKeyOptions {
  /** Pre-derived key encryption key (KEK) */
  key: Uint8Array;
  /** Username for API context */
  username: string;
  /** Password type: 'account' or 'custom' */
  passwordType: PasswordContext;
  /** Optional password hint (stored unencrypted) */
  passwordHint?: string;
  /** Progress callback */
  onProgress?: (progress: UploadProgress) => void;
}

export interface UploadProgress {
  /** Current phase of upload */
  phase: 'encrypting' | 'uploading' | 'completing';
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
// Constants
// ============================================================================

/** Chunk size for encryption (16 MiB plaintext) - matches server */
const CHUNK_SIZE = DEFAULT_CHUNK_SIZE_BYTES;

/** Envelope version byte */
const ENVELOPE_VERSION = 0x01;

/** Envelope type: AES-256-GCM */
const ENVELOPE_TYPE_AES_GCM = 0x01;

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
 * Creates the 2-byte envelope header for chunk 0
 * Format: [version (1 byte)][type (1 byte)]
 */
function createEnvelopeHeader(): Uint8Array {
  return new Uint8Array([ENVELOPE_VERSION, ENVELOPE_TYPE_AES_GCM]);
}

// ============================================================================
// Main Upload Function
// ============================================================================

/**
 * Uploads a file with client-side encryption
 * 
 * @param file - The file to upload
 * @param options - Upload options including password and username
 * @returns Upload result with file ID and storage info
 */
export async function uploadFile(
  file: File,
  options: UploadOptions
): Promise<UploadResult> {
  const { password, username, passwordType, passwordHint, onProgress } = options;

  // Validate inputs
  if (!file) {
    throw new Error('No file provided');
  }
  if (!password) {
    throw new Error('Password is required');
  }
  if (!username) {
    throw new Error('Username is required');
  }
  if (passwordType !== 'account' && passwordType !== 'custom') {
    throw new Error('Invalid password type');
  }

  const reportProgress = (progress: UploadProgress) => {
    if (onProgress) {
      onProgress(progress);
    }
  };

  try {
    // Phase 1: Generate keys and prepare encryption
    reportProgress({ phase: 'encrypting', percent: 0 });

    // Generate random FEK (File Encryption Key)
    const fek = randomBytes(KEY_SIZES.FILE_ENCRYPTION_KEY);

    // Derive user's key encryption key from password
    const kek = await deriveFileEncryptionKey(password, username, passwordType);

    // Calculate SHA256 of plaintext file
    const fileBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuffer);
    const plaintextHash = hash256(fileBytes);
    const plaintextHashHex = toHex(plaintextHash);

    // Encrypt metadata
    const encryptedFilename = await encryptMetadata(file.name, fek);
    const encryptedSha256 = await encryptMetadata(plaintextHashHex, fek);

    // Encrypt FEK with user's KEK
    const encryptedFekResult = await encryptAESGCM({
      data: fek,
      key: kek,
      // No AAD for FEK encryption - matches Go implementation
    });
    const encryptedFek = concatBytes(
      encryptedFekResult.iv,
      encryptedFekResult.ciphertext,
      encryptedFekResult.tag
    );

    reportProgress({ phase: 'encrypting', percent: 10 });

    // Phase 2: Encrypt file chunks
    const totalChunks = Math.ceil(fileBytes.length / CHUNK_SIZE);
    const encryptedChunks: Uint8Array[] = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileBytes.length);
      const chunk = fileBytes.slice(start, end);

      // Encrypt chunk
      const encryptedChunk = await encryptChunk(chunk, fek);

      // For chunk 0, prepend the envelope header
      if (i === 0) {
        const envelope = createEnvelopeHeader();
        encryptedChunks.push(concatBytes(envelope, encryptedChunk));
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

    // Clean up FEK from memory (KEK is cached, so we don't wipe it)
    secureWipe(fek);

    reportProgress({ phase: 'encrypting', percent: 50 });

    // Phase 3: Create upload session
    reportProgress({ phase: 'uploading', percent: 50 });

    const session = await apiRequest<UploadSession>('/api/upload/init', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_filename: encryptedFilename.encrypted,
        filename_nonce: encryptedFilename.nonce,
        encrypted_sha256sum: encryptedSha256.encrypted,
        sha256sum_nonce: encryptedSha256.nonce,
        encrypted_fek: toBase64(encryptedFek),
        total_size: totalEncryptedSize,
        chunk_size: CHUNK_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE + 2, // Include overhead
        password_hint: passwordHint || '',
        password_type: passwordType,
      }),
    });

    // Phase 4: Upload chunks
    let bytesUploaded = 0;

    for (let i = 0; i < encryptedChunks.length; i++) {
      const chunk = encryptedChunks[i];
      
      // Calculate chunk hash for verification
      const chunkHash = toHex(hash256(chunk));

      // Upload chunk (convert to ArrayBuffer for fetch API compatibility)
      const chunkBuffer = chunk.buffer.slice(
        chunk.byteOffset,
        chunk.byteOffset + chunk.byteLength
      ) as ArrayBuffer;
      
      await apiRequest(`/api/upload/${session.sessionId}/chunk/${i}`, {
        method: 'PUT',
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

    // Phase 5: Complete upload
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
    }>(`/api/upload/${session.sessionId}/complete`, {
      method: 'POST',
    });

    reportProgress({ phase: 'completing', percent: 100 });

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

/**
 * Uploads a file with a pre-derived key (from cache)
 * 
 * This is used when the Account Key is already cached, avoiding
 * the need to re-derive the key from password.
 * 
 * @param file - The file to upload
 * @param options - Upload options including the pre-derived key
 * @returns Upload result with file ID and storage info
 */
export async function uploadFileWithKey(
  file: File,
  options: UploadWithKeyOptions
): Promise<UploadResult> {
  const { key, username, passwordType, passwordHint, onProgress } = options;

  // Validate inputs
  if (!file) {
    throw new Error('No file provided');
  }
  if (!key || key.length !== KEY_SIZES.FILE_ENCRYPTION_KEY) {
    throw new Error('Invalid key');
  }
  if (!username) {
    throw new Error('Username is required');
  }
  if (passwordType !== 'account' && passwordType !== 'custom') {
    throw new Error('Invalid password type');
  }

  const reportProgress = (progress: UploadProgress) => {
    if (onProgress) {
      onProgress(progress);
    }
  };

  try {
    // Phase 1: Generate FEK and prepare encryption
    reportProgress({ phase: 'encrypting', percent: 0 });

    // Generate random FEK (File Encryption Key)
    const fek = randomBytes(KEY_SIZES.FILE_ENCRYPTION_KEY);

    // Use the provided key as KEK (already derived)
    const kek = key;

    // Calculate SHA256 of plaintext file
    const fileBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuffer);
    const plaintextHash = hash256(fileBytes);
    const plaintextHashHex = toHex(plaintextHash);

    // Encrypt metadata
    const encryptedFilename = await encryptMetadata(file.name, fek);
    const encryptedSha256 = await encryptMetadata(plaintextHashHex, fek);

    // Encrypt FEK with user's KEK
    const encryptedFekResult = await encryptAESGCM({
      data: fek,
      key: kek,
    });
    const encryptedFek = concatBytes(
      encryptedFekResult.iv,
      encryptedFekResult.ciphertext,
      encryptedFekResult.tag
    );

    reportProgress({ phase: 'encrypting', percent: 10 });

    // Phase 2: Encrypt file chunks
    const totalChunks = Math.ceil(fileBytes.length / CHUNK_SIZE);
    const encryptedChunks: Uint8Array[] = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, fileBytes.length);
      const chunk = fileBytes.slice(start, end);

      // Encrypt chunk
      const encryptedChunk = await encryptChunk(chunk, fek);

      // For chunk 0, prepend the envelope header
      if (i === 0) {
        const envelope = createEnvelopeHeader();
        encryptedChunks.push(concatBytes(envelope, encryptedChunk));
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

    // Clean up FEK from memory
    secureWipe(fek);

    reportProgress({ phase: 'encrypting', percent: 50 });

    // Phase 3: Create upload session
    reportProgress({ phase: 'uploading', percent: 50 });

    const session = await apiRequest<UploadSession>('/api/upload/init', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_filename: encryptedFilename.encrypted,
        filename_nonce: encryptedFilename.nonce,
        encrypted_sha256sum: encryptedSha256.encrypted,
        sha256sum_nonce: encryptedSha256.nonce,
        encrypted_fek: toBase64(encryptedFek),
        total_size: totalEncryptedSize,
        chunk_size: CHUNK_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE + 2,
        password_hint: passwordHint || '',
        password_type: passwordType,
      }),
    });

    // Phase 4: Upload chunks
    let bytesUploaded = 0;

    for (let i = 0; i < encryptedChunks.length; i++) {
      const chunk = encryptedChunks[i];
      
      const chunkHash = toHex(hash256(chunk));

      const chunkBuffer = chunk.buffer.slice(
        chunk.byteOffset,
        chunk.byteOffset + chunk.byteLength
      ) as ArrayBuffer;
      
      await apiRequest(`/api/upload/${session.sessionId}/chunk/${i}`, {
        method: 'PUT',
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

    // Phase 5: Complete upload
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
    }>(`/api/upload/${session.sessionId}/complete`, {
      method: 'POST',
    });

    reportProgress({ phase: 'completing', percent: 100 });

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
 * - Always requires password input (custom passwords are not cached)
 */
export async function handleFileUpload(): Promise<void> {
  // Get file input
  const fileInput = document.getElementById('file-input') as HTMLInputElement | null;
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

  // Get password type
  const passwordTypeSelect = document.getElementById('password-type') as HTMLSelectElement | null;
  const passwordType = (passwordTypeSelect?.value || 'account') as PasswordContext;

  // Get password hint
  const hintInput = document.getElementById('password-hint') as HTMLInputElement | null;
  const passwordHint = hintInput?.value || '';

  // Get progress elements
  const progressBar = document.getElementById('upload-progress') as HTMLProgressElement | null;
  const progressText = document.getElementById('upload-progress-text') as HTMLElement | null;
  const uploadButton = document.getElementById('upload-button') as HTMLButtonElement | null;

  // Determine password based on password type and cache status
  let password: string | undefined;
  let useCachedKey = false;

  if (passwordType === 'account') {
    // Check if Account Key is cached and not locked
    if (isAccountKeyCached(username) && !isAccountKeyLocked()) {
      // Account Key is available - no password needed
      useCachedKey = true;
      password = ''; // Will use cached key directly
    } else {
      // Need to prompt for password
      const passwordInput = document.getElementById('upload-password') as HTMLInputElement | null;
      password = passwordInput?.value;
      
      if (!password) {
        // Show password modal if no password in input field
        const result = await promptForAccountKeyPassword();
        if (!result) {
          // User cancelled
          return;
        }
        password = result.password;
        
        // If user chose to remember, derive and cache the key
        if (result.cacheDuration) {
          await deriveFileEncryptionKeyWithCache(password, username, 'account', result.cacheDuration);
        }
      }
    }
  } else {
    // Custom password - always required from input
    const passwordInput = document.getElementById('upload-password') as HTMLInputElement | null;
    password = passwordInput?.value;
    if (!password) {
      showError('Please enter your custom password');
      return;
    }
  }

  // Disable upload button during upload
  if (uploadButton) {
    uploadButton.disabled = true;
  }

  try {
    showInfo(`Uploading ${file.name}...`);

    // If using cached key, we need to handle this differently
    // The uploadFile function expects a password, but we can pass a dummy
    // and override the key derivation
    if (useCachedKey && passwordType === 'account') {
      // Get the cached key directly
      const cachedKey = getCachedAccountKey(username);
      if (!cachedKey) {
        throw new Error('Account Key cache expired. Please try again.');
      }
      
      // Use the cached key version of upload
      const result = await uploadFileWithKey(file, {
        key: cachedKey,
        username,
        passwordType,
        passwordHint,
        onProgress: (progress) => {
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
        },
      });

      showSuccess(`File uploaded successfully! File ID: ${result.fileId}`);
    } else {
      // Use password-based upload
      const result = await uploadFile(file, {
        password: password!,
        username,
        passwordType,
        passwordHint,
        onProgress: (progress) => {
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
        },
      });

      showSuccess(`File uploaded successfully! File ID: ${result.fileId}`);
    }

    // Clear the form
    if (fileInput) fileInput.value = '';
    const passwordInput = document.getElementById('upload-password') as HTMLInputElement | null;
    if (passwordInput) passwordInput.value = '';
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
