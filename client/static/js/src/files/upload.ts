/**
 * File Upload Module
 * 
 * Handles chunked file uploads with client-side encryption.
 * Matches the Go CLI implementation for cross-platform compatibility.
 * 
 * Upload Flow (streaming, constant memory):
 * 1. Resolve account key (from cache, provided key, or password derivation)
 * 2. Generate random FEK (File Encryption Key)
 * 3. Compute SHA-256 of plaintext file via streaming (one chunk at a time)
 * 4. Encrypt metadata (filename, SHA256) with account key
 * 5. Calculate total encrypted size mathematically (no file read needed)
 * 6. Init upload session with server
 * 7. For each chunk: read from disk, encrypt with FEK, upload, release
 * 8. Complete upload
 * 
 * Peak memory: ~32 MB (one plaintext chunk + one encrypted chunk),
 * constant regardless of file size. Mirrors the Go CLI pattern exactly.
 * 
 * Key design: Metadata is ALWAYS encrypted with the account-derived key,
 * regardless of password type. The password type only governs FEK encryption.
 * This keeps file lists readable without requiring custom passwords.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  randomBytes,
  encryptAESGCM,
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
  getChunkingParams,
} from '../crypto/constants.js';
import { showError, showSuccess } from '../ui/messages.js';
import { showProgress, updateProgress, hideProgress } from '../ui/progress.js';
import { checkDuplicate, addDigest } from '../utils/digest-cache.js';
import { getToken, getUsernameFromToken } from '../utils/auth.js';
import { loadFiles } from './list.js';

// ============================================================================
// Types
// ============================================================================

export interface UploadOptions {
  /** Pre-derived account key for metadata encryption (skips derivation if provided) */
  accountKey?: Uint8Array;
  /** Account password -- used to derive account key if not provided or cached */
  accountPassword?: string;
  /** Username for salt derivation and API context */
  username: string;
  /** 'account' or 'custom' -- governs FEK encryption key */
  passwordType: PasswordContext;
  /** Custom password -- required when passwordType === 'custom' (derives custom KEK) */
  customPassword?: string;
  /** Optional hint for custom passwords (stored unencrypted) */
  passwordHint?: string;
  /** Progress callback */
  onProgress?: (progress: UploadProgress) => void;
}

export interface UploadProgress {
  /** Current phase of upload */
  phase: 'deriving-key' | 'hashing' | 'encrypting' | 'uploading' | 'completing';
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
  session_id: string;
  file_id: string;
  chunk_size: number;
  total_chunks: number;
  expires_at: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Makes an authenticated API request
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
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
    const cached = await getCachedAccountKey(username, getToken() ?? undefined);
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

/**
 * Computes SHA-256 of a File using streaming reads.
 * Reads one chunk at a time via file.slice(), never loading the whole file.
 * Mirrors Go CLI's computeStreamingSHA256(). Peak memory: ~chunkSize bytes.
 */
async function computeStreamingSHA256(
  file: File,
  chunkSize: number,
  onProgress?: (bytesHashed: number, totalBytes: number) => void
): Promise<string> {
  const hasher = sha256.create();
  let offset = 0;

  while (offset < file.size) {
    const end = Math.min(offset + chunkSize, file.size);
    const slice = file.slice(offset, end);
    const buffer = await slice.arrayBuffer();
    hasher.update(new Uint8Array(buffer));
    offset = end;

    if (onProgress) {
      onProgress(offset, file.size);
    }
  }

  // Handle empty files (0-byte)
  if (file.size === 0) {
    hasher.update(new Uint8Array(0));
  }

  return toHex(hasher.digest());
}

/**
 * Calculates total encrypted size deterministically from plaintext file size.
 * Pure math -- no file reading needed. Mirrors Go CLI's calculateTotalEncryptedSize().
 * 
 * Each chunk gets: nonce (12) + ciphertext (same as plaintext) + tag (16) = +28 bytes overhead
 * Chunk 0 also gets a 2-byte envelope header prepended.
 */
function calculateTotalEncryptedSize(
  plaintextSize: number,
  chunkSize: number,
  overhead: number,
  headerSize: number
): number {
  if (plaintextSize === 0) {
    // Even empty files get one chunk with overhead + header
    return headerSize + overhead;
  }

  const numFullChunks = Math.floor(plaintextSize / chunkSize);
  const lastChunkPlaintext = plaintextSize % chunkSize;

  if (lastChunkPlaintext === 0) {
    // All chunks are full
    return numFullChunks * (chunkSize + overhead) + headerSize;
  }

  // Full chunks + partial last chunk
  return numFullChunks * (chunkSize + overhead) + (lastChunkPlaintext + overhead) + headerSize;
}

// ============================================================================
// Main Upload Function
// ============================================================================

/**
 * Uploads a file with client-side encryption using streaming.
 * 
 * Single entry point for all file uploads. Handles both account and custom
 * password types. Metadata is always encrypted with the account key.
 * 
 * Mirrors the Go CLI upload pattern: streaming SHA-256 hash, then
 * one-chunk-at-a-time encrypt+upload loop. Peak memory ~32 MB regardless
 * of file size.
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
    const aesGcmOverhead = nonceSize + tagSize; // 12 + 16 = 28
    const envelopeVersion = chunkCfg.envelope.version;
    const envelopeHeaderSize = chunkCfg.envelope.headerSizeBytes;
    const keyTypeVal = passwordType === 'account'
      ? chunkCfg.envelope.keyTypes.account
      : chunkCfg.envelope.keyTypes.custom;

    // ================================================================
    // Step 1: Resolve keys
    // ================================================================
    reportProgress({ phase: 'deriving-key', percent: 0 });

    // Account key -- always needed for metadata encryption
    const accountKey = await resolveAccountKey(options);

    // FEK encryption key -- depends on password type
    let fekEncryptionKey: Uint8Array;
    if (passwordType === 'account') {
      fekEncryptionKey = accountKey;
    } else {
      // Custom: derive separate key from custom password
      fekEncryptionKey = await deriveFileEncryptionKey(customPassword!, username, 'custom');
    }

    // ================================================================
    // Step 2: Generate FEK
    // ================================================================
    reportProgress({ phase: 'deriving-key', percent: 3 });

    // Generate random FEK (File Encryption Key)
    const fek = randomBytes(KEY_SIZES.FILE_ENCRYPTION_KEY);

    // ================================================================
    // Step 3: Streaming SHA-256 of plaintext file
    // Reads file one chunk at a time -- never loads whole file into memory.
    // Mirrors Go CLI's computeStreamingSHA256().
    // ================================================================
    reportProgress({ phase: 'hashing', percent: 5 });

    const plaintextHashHex = await computeStreamingSHA256(file, CHUNK_SIZE, (bytesHashed, totalBytes) => {
      // Hash phase: 5% to 15%
      const hashPercent = 5 + Math.floor((bytesHashed / totalBytes) * 10);
      reportProgress({ phase: 'hashing', percent: hashPercent });
    });

    // ================================================================
    // Step 4: Deduplication check
    // ================================================================
    const existingFileId = checkDuplicate(plaintextHashHex);
    if (existingFileId) {
      secureWipe(fek);
      throw new Error(
        `Duplicate file detected (already uploaded as ${existingFileId}). ` +
        'Delete the existing copy before uploading again.'
      );
    }

    // ================================================================
    // Step 5: Encrypt metadata with ACCOUNT key (always, regardless of password type)
    // ================================================================
    reportProgress({ phase: 'encrypting', percent: 16 });

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

    // ================================================================
    // Step 6: Calculate total encrypted size mathematically
    // No need to encrypt all chunks first -- mirrors Go CLI's calculateTotalEncryptedSize()
    // ================================================================
    const totalEncryptedSize = calculateTotalEncryptedSize(
      file.size, CHUNK_SIZE, aesGcmOverhead, envelopeHeaderSize
    );
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));

    // ================================================================
    // Step 7: Create upload session
    // ================================================================
    reportProgress({ phase: 'uploading', percent: 18 });

    const session = await apiRequest<UploadSession>('/api/uploads/init', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_filename: encryptedFilename.encrypted,
        filename_nonce: encryptedFilename.nonce,
        encrypted_sha256sum: encryptedSha256.encrypted,
        sha256sum_nonce: encryptedSha256.nonce,
        encrypted_fek: toBase64(encryptedFek),
        total_size: totalEncryptedSize,
        chunk_size: CHUNK_SIZE,
        password_hint: passwordHint || '',
        password_type: passwordType,
      }),
    });

    // ================================================================
    // Step 8: Streaming encrypt-and-upload loop
    // For each chunk: read from disk, encrypt, upload, release.
    // Only one plaintext chunk + one encrypted chunk in memory at a time.
    // Mirrors Go CLI's doChunkedUpload().
    // ================================================================
    let bytesUploaded = 0;

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);

      // Read ONE chunk from disk via File.slice() -- no full-file load
      const sliceBlob = file.slice(start, end);
      const chunkBuffer = await sliceBlob.arrayBuffer();
      const plaintext = new Uint8Array(chunkBuffer);

      // Encrypt chunk with FEK
      const encryptedChunk = await encryptChunk(plaintext, fek);

      // For chunk 0, prepend the envelope header
      let chunkToUpload: Uint8Array;
      if (i === 0) {
        const chunkEnvelope = createEnvelopeHeader(envelopeVersion, keyTypeVal);
        chunkToUpload = concatBytes(chunkEnvelope, encryptedChunk);
      } else {
        chunkToUpload = encryptedChunk;
      }

      // Calculate chunk hash for server verification
      const chunkHash = toHex(hash256(chunkToUpload));

      // Upload chunk as raw binary with hash header
      const uploadBuffer = chunkToUpload.buffer.slice(
        chunkToUpload.byteOffset,
        chunkToUpload.byteOffset + chunkToUpload.byteLength
      ) as ArrayBuffer;

      await apiRequest(`/api/uploads/${session.session_id}/chunks/${i}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Chunk-Hash': chunkHash,
        },
        body: new Blob([uploadBuffer]),
      });

      // plaintext, encryptedChunk, chunkToUpload all go out of scope here
      // and become eligible for GC

      bytesUploaded += chunkToUpload.length;
      // Upload phase: 20% to 95%
      const uploadPercent = 20 + Math.floor((i + 1) / totalChunks * 75);
      reportProgress({
        phase: 'uploading',
        percent: uploadPercent,
        currentChunk: i + 1,
        totalChunks,
        bytesUploaded,
        totalBytes: totalEncryptedSize,
      });
    }

    // Clean up sensitive key material
    secureWipe(fek);
    if (passwordType === 'custom') {
      secureWipe(fekEncryptionKey);
    }

    // ================================================================
    // Step 9: Complete upload
    // ================================================================
    reportProgress({ phase: 'completing', percent: 96 });

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
    }>(`/api/uploads/${session.session_id}/complete`, {
      method: 'POST',
    });

    reportProgress({ phase: 'completing', percent: 100 });

    // Update digest cache so subsequent uploads in this session are deduped
    addDigest(result.file_id, plaintextHashHex);

    console.log(`[upload] File uploaded successfully: file_id=${result.file_id}, session_id=${session.session_id}`);

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
  // Get file input -- HTML uses id="fileInput"
  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showError('Please select a file to upload');
    return;
  }

  const file = fileInput.files[0];

  // Get username from JWT token (shared auth module)
  const username = getUsernameFromToken();
  if (!username) {
    showError('Not logged in. Please log in first.');
    return;
  }

  // Get password type -- HTML uses radio buttons named "passwordType"
  const passwordTypeRadio = document.querySelector<HTMLInputElement>('input[name="passwordType"]:checked');
  const passwordType = (passwordTypeRadio?.value || 'account') as PasswordContext;

  // Get password hint -- HTML uses id="passwordHint"
  const hintInput = document.getElementById('passwordHint') as HTMLInputElement | null;
  const passwordHint = hintInput?.value || '';

  // Get progress elements
  const progressBar = document.getElementById('upload-progress') as HTMLProgressElement | null;
  const progressText = document.getElementById('upload-progress-text') as HTMLElement | null;
  // Upload button -- HTML uses id="upload-file-btn"
  const uploadButton = document.getElementById('upload-file-btn') as HTMLButtonElement | null;

  // Build upload options
  const uploadOptions: UploadOptions = {
    username,
    passwordType,
    passwordHint,
  };

  // Resolve account key / password (always needed for metadata)
  if (isAccountKeyCached(username) && !isAccountKeyLocked()) {
    // Account key is cached -- use it directly
    const cachedKey = await getCachedAccountKey(username, getToken() ?? undefined);
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
        showProgress({
          title: 'Deriving Account Key',
          message: 'Running Argon2id key derivation -- this may take a few seconds...',
          indeterminate: true,
        });
        const derivedKey = await deriveFileEncryptionKeyWithCache(
          accountPassword, username, 'account', getToken() ?? undefined, result.cacheDuration
        );
        hideProgress();
        uploadOptions.accountKey = derivedKey;
      }
    }

    // If we still don't have a derived key, pass the password for derivation
    if (!uploadOptions.accountKey) {
      uploadOptions.accountPassword = accountPassword;
    }
  }

  // For custom password type, get the custom password -- HTML uses id="filePassword"
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

  // Show ProgressManager overlay for upload
  showProgress({
    title: 'Uploading File',
    message: file.name,
    indeterminate: true,
  });

  try {
    uploadOptions.onProgress = (progress) => {
      // Update ProgressManager overlay
      const phaseLabels: Record<string, string> = {
        'deriving-key': 'Deriving encryption key...',
        'hashing': 'Computing file hash...',
        'encrypting': 'Encrypting metadata...',
        'uploading': 'Uploading...',
        'completing': 'Finalizing...',
      };
      const phaseMessage = phaseLabels[progress.phase] || progress.phase;
      let message = phaseMessage;
      if (progress.currentChunk && progress.totalChunks) {
        message += ` (chunk ${progress.currentChunk}/${progress.totalChunks})`;
      }
      updateProgress({
        title: 'Uploading File',
        message,
        percentage: progress.percent,
        stage: progress.phase,
      });

      // Also update legacy DOM elements if present
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

    hideProgress();
    showSuccess(`File uploaded successfully! File ID: ${result.fileId}`);

    // Clear the form
    if (fileInput) fileInput.value = '';
    // Reset custom file input label
    const fileInputLabel = document.getElementById('fileInputLabel');
    const fileInputName = document.getElementById('fileInputName');
    if (fileInputLabel) fileInputLabel.classList.remove('has-file');
    if (fileInputName) fileInputName.textContent = '';
    const customPasswordInput = document.getElementById('filePassword') as HTMLInputElement | null;
    if (customPasswordInput) customPasswordInput.value = '';
    if (hintInput) hintInput.value = '';
    if (progressBar) progressBar.value = 0;
    if (progressText) progressText.textContent = '';

    // Refresh file list after successful upload
    await loadFiles();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Upload failed';
    updateProgress({ error: message });
    setTimeout(() => hideProgress(), 3000);
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
