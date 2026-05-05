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
import {
  getToken,
  getUsernameFromToken,
  getTokenExpiry,
  refreshToken as doRefreshToken,
} from '../utils/auth.js';
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
  phase: 'deriving-key' | 'hashing' | 'encrypting' | 'init-session' | 'uploading' | 'completing';
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
// Auth helpers (preemptive refresh + 401-refresh-retry)
// ============================================================================

/**
 * Refresh threshold for the per-file token check. If the JWT has fewer than
 * this many seconds remaining when we are about to upload another file, we
 * refresh proactively. Default JWT lifetime is 30 minutes, so 5 minutes is
 * a comfortable buffer for any single in-flight chunk.
 */
const TOKEN_REFRESH_THRESHOLD_SECONDS = 5 * 60;

/**
 * AuthExpiredError signals that the user's session is no longer usable
 * (refresh failed or refresh token rejected). Always fatal: the batch loop
 * stops immediately and the UI surfaces a "session expired" message.
 */
export class AuthExpiredError extends Error {
  constructor(message = 'Session expired. Please log in again.') {
    super(message);
    this.name = 'AuthExpiredError';
  }
}

/**
 * QuotaExceededError signals the user has run out of storage. Fatal because
 * every subsequent file in the batch will hit the same wall.
 */
export class QuotaExceededError extends Error {
  constructor(message = 'Storage limit would be exceeded.') {
    super(message);
    this.name = 'QuotaExceededError';
  }
}

/**
 * AccountDisabledError signals the account is no longer approved or has
 * been disabled. Fatal -- nothing in the batch will succeed.
 */
export class AccountDisabledError extends Error {
  constructor(message = 'Account is not approved or has been disabled.') {
    super(message);
    this.name = 'AccountDisabledError';
  }
}

/**
 * TooManyInProgressUploadsError mirrors the server's stable error code
 * 'too_many_in_progress_uploads' (HTTP 429). Fatal for the current batch
 * loop -- the user must cancel an existing session before any of the
 * remaining files can start.
 */
export class TooManyInProgressUploadsError extends Error {
  constructor(message = 'Too many uploads already in progress. Cancel one or wait for it to complete.') {
    super(message);
    this.name = 'TooManyInProgressUploadsError';
  }
}

/**
 * Decides whether an error should abort an entire batch (fatal) or be
 * recorded against a single file and skipped past (non-fatal).
 *
 * This is the seed of the standing pattern described in
 * docs/wip/general-enhancements.md item 11.
 */
export function isFatalUploadError(err: unknown): boolean {
  if (err instanceof AuthExpiredError) return true;
  if (err instanceof QuotaExceededError) return true;
  if (err instanceof AccountDisabledError) return true;
  if (err instanceof TooManyInProgressUploadsError) return true;
  return false;
}

/**
 * Refresh the JWT preemptively if it has fewer than `thresholdSeconds`
 * remaining. Throws AuthExpiredError if no token is present or the refresh
 * call fails (refresh token also expired or revoked).
 *
 * Safe to call repeatedly between files in a batch.
 */
async function ensureFreshToken(thresholdSeconds = TOKEN_REFRESH_THRESHOLD_SECONDS): Promise<void> {
  const token = getToken();
  if (!token) {
    throw new AuthExpiredError('Not authenticated');
  }

  const expiry = getTokenExpiry();
  if (!expiry) {
    // Token unparseable -- treat as expired and try to refresh
    const ok = await doRefreshToken();
    if (!ok) {
      throw new AuthExpiredError();
    }
    return;
  }

  const remainingSeconds = (expiry.getTime() - Date.now()) / 1000;
  if (remainingSeconds < thresholdSeconds) {
    console.log(`[upload] JWT has ${remainingSeconds.toFixed(0)}s remaining; refreshing preemptively.`);
    const ok = await doRefreshToken();
    if (!ok) {
      throw new AuthExpiredError();
    }
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Makes an authenticated API request. On 401, attempts a single refresh and
 * retries the request once before giving up. On 429 with the stable error
 * code 'too_many_in_progress_uploads', throws TooManyInProgressUploadsError
 * so callers can classify it as a fatal batch-aborting condition.
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const performFetch = async (): Promise<Response> => {
    const token = getToken();
    if (!token) {
      throw new AuthExpiredError('Not authenticated');
    }

    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${token}`);

    if (options.body && !(options.body instanceof FormData) && !(options.body instanceof Blob)) {
      headers.set('Content-Type', 'application/json');
    }

    return fetch(endpoint, {
      ...options,
      headers,
    });
  };

  let response = await performFetch();

  // 401: try a single refresh-and-retry. If still 401 after refresh, treat as fatal.
  if (response.status === 401) {
    const refreshed = await doRefreshToken();
    if (!refreshed) {
      throw new AuthExpiredError();
    }
    response = await performFetch();
    if (response.status === 401) {
      throw new AuthExpiredError();
    }
  }

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage: string;
    let errorCode: string | undefined;
    try {
      const errorJson = JSON.parse(errorText);
      errorMessage = errorJson.message || errorJson.error || errorText;
      errorCode = typeof errorJson.error === 'string' ? errorJson.error : undefined;
    } catch {
      errorMessage = errorText;
    }

    // Classify based on stable error codes / status.
    if (response.status === 429 && errorCode === 'too_many_in_progress_uploads') {
      throw new TooManyInProgressUploadsError(errorMessage);
    }
    if (response.status === 403) {
      const lower = errorMessage.toLowerCase();
      if (lower.includes('storage limit') || lower.includes('quota')) {
        throw new QuotaExceededError(errorMessage);
      }
      if (lower.includes('pending approval') || lower.includes('disabled')) {
        throw new AccountDisabledError(errorMessage);
      }
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
    const uploadStart = performance.now();
    const logTiming = (step: string, startTime: number) => {
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
      const total = ((performance.now() - uploadStart) / 1000).toFixed(2);
      console.log(`[upload] ${step} (${elapsed}s, total: ${total}s)`);
    };

    // Privacy-safe filename for logging: first char + extension only
    const safeFileName = (name: string): string => {
      const dot = name.lastIndexOf('.');
      if (dot > 0) {
        return name[0] + '[...]' + name.substring(dot);
      }
      return name[0] + '[...]';
    };
    const logName = safeFileName(file.name);

    // Load chunking config from single source of truth
    let stepStart = performance.now();
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
    logTiming('Config loaded', stepStart);

    console.log(`[upload] File: ${logName}, size: ${(file.size / 1024 / 1024).toFixed(1)} MB, chunk size: ${(CHUNK_SIZE / 1024 / 1024).toFixed(0)} MB`);

    // ================================================================
    // Step 1: Resolve keys
    // ================================================================
    reportProgress({ phase: 'deriving-key', percent: 0 });
    stepStart = performance.now();

    // Account key -- always needed for metadata encryption
    const accountKey = await resolveAccountKey(options);
    logTiming('Step 1: Account key resolved', stepStart);

    // FEK encryption key -- depends on password type
    let fekEncryptionKey: Uint8Array;
    if (passwordType === 'account') {
      fekEncryptionKey = accountKey;
    } else {
      stepStart = performance.now();
      // Custom: derive separate key from custom password
      fekEncryptionKey = await deriveFileEncryptionKey(customPassword!, username, 'custom');
      logTiming('Step 1b: Custom key derived', stepStart);
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
    stepStart = performance.now();
    console.log(`[upload] Step 3: Starting streaming SHA-256 hash of ${(file.size / 1024 / 1024).toFixed(1)} MB...`);

    const plaintextHashHex = await computeStreamingSHA256(file, CHUNK_SIZE, (bytesHashed, totalBytes) => {
      // Hash phase: 5% to 15%
      const hashPercent = 5 + Math.floor((bytesHashed / totalBytes) * 10);
      reportProgress({ phase: 'hashing', percent: hashPercent });
    });
    logTiming(`Step 3: SHA-256 hash complete (${plaintextHashHex.substring(0, 8)}...)`, stepStart);

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
    stepStart = performance.now();

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
    logTiming('Step 5: Metadata encrypted', stepStart);

    // ================================================================
    // Step 6: Calculate total encrypted size mathematically
    // No need to encrypt all chunks first -- mirrors Go CLI's calculateTotalEncryptedSize()
    // ================================================================
    const totalEncryptedSize = calculateTotalEncryptedSize(
      file.size, CHUNK_SIZE, aesGcmOverhead, envelopeHeaderSize
    );
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    console.log(`[upload] Step 6: Total encrypted size: ${(totalEncryptedSize / 1024 / 1024).toFixed(1)} MB, chunks: ${totalChunks}`);

    // ================================================================
    // Step 7: Create upload session
    // ================================================================
    reportProgress({ phase: 'init-session', percent: 18 });
    stepStart = performance.now();
    console.log('[upload] Step 7: Initializing upload session...');

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
    logTiming(`Step 7: Upload session created (${session.session_id})`, stepStart);

    // ================================================================
    // Step 8: Streaming encrypt-and-upload loop
    // For each chunk: read from disk, encrypt, upload, release.
    // Only one plaintext chunk + one encrypted chunk in memory at a time.
    // Mirrors Go CLI's doChunkedUpload().
    // ================================================================
    let bytesUploaded = 0;

    for (let i = 0; i < totalChunks; i++) {
      const chunkStart = performance.now();
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);
      const chunkSizeMB = ((end - start) / 1024 / 1024).toFixed(1);

      // Report progress at the START of each chunk (before read/encrypt/upload)
      reportProgress({
        phase: 'uploading',
        percent: 20 + Math.floor(i / totalChunks * 75),
        currentChunk: i + 1,
        totalChunks,
        bytesUploaded,
        totalBytes: totalEncryptedSize,
      });

      // Read ONE chunk from disk via File.slice() -- no full-file load
      let subStart = performance.now();
      const sliceBlob = file.slice(start, end);
      const chunkBuffer = await sliceBlob.arrayBuffer();
      const plaintext = new Uint8Array(chunkBuffer);
      const readTime = ((performance.now() - subStart) / 1000).toFixed(2);

      // Encrypt chunk with FEK
      subStart = performance.now();
      const encryptedChunk = await encryptChunk(plaintext, fek);
      const encryptTime = ((performance.now() - subStart) / 1000).toFixed(2);

      // For chunk 0, prepend the envelope header
      let chunkToUpload: Uint8Array;
      if (i === 0) {
        const chunkEnvelope = createEnvelopeHeader(envelopeVersion, keyTypeVal);
        chunkToUpload = concatBytes(chunkEnvelope, encryptedChunk);
      } else {
        chunkToUpload = encryptedChunk;
      }

      // Calculate chunk hash for server verification
      subStart = performance.now();
      const chunkHash = toHex(hash256(chunkToUpload));
      const hashTime = ((performance.now() - subStart) / 1000).toFixed(2);

      // Upload chunk as raw binary with hash header
      const uploadBuffer = chunkToUpload.buffer.slice(
        chunkToUpload.byteOffset,
        chunkToUpload.byteOffset + chunkToUpload.byteLength
      ) as ArrayBuffer;

      subStart = performance.now();
      await apiRequest(`/api/uploads/${session.session_id}/chunks/${i}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Chunk-Hash': chunkHash,
        },
        body: new Blob([uploadBuffer]),
      });
      const uploadTime = ((performance.now() - subStart) / 1000).toFixed(2);

      // plaintext, encryptedChunk, chunkToUpload all go out of scope here
      // and become eligible for GC

      bytesUploaded += chunkToUpload.length;
      const chunkTotal = ((performance.now() - chunkStart) / 1000).toFixed(2);
      console.log(`[upload] Chunk ${i + 1}/${totalChunks} (${chunkSizeMB} MB): read=${readTime}s encrypt=${encryptTime}s hash=${hashTime}s upload=${uploadTime}s total=${chunkTotal}s`);

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
    stepStart = performance.now();

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

    logTiming(`Step 9: Upload finalized (file_id: ${result.file_id})`, stepStart);
    reportProgress({ phase: 'completing', percent: 100 });

    // Update digest cache so subsequent uploads in this session are deduped
    addDigest(result.file_id, plaintextHashHex);

    const totalTime = ((performance.now() - uploadStart) / 1000).toFixed(2);
    console.log(`[upload] SUCCESS: ${logName} (${(file.size / 1024 / 1024).toFixed(1)} MB) uploaded in ${totalTime}s, file_id=${result.file_id}`);

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
    // Preserve typed errors so the batch loop can classify them correctly.
    // Wrapping in new Error() would erase the AuthExpiredError /
    // TooManyInProgressUploadsError / etc. discriminator.
    if (isFatalUploadError(error)) {
      throw error;
    }
    const message = error instanceof Error ? error.message : 'Upload failed';
    throw new Error(message);
  }
}

// ============================================================================
// Batch (multi-file) upload
// ============================================================================

/**
 * Per-file outcome in a batch upload.
 */
export interface BatchUploadFileOutcome {
  /** The original filename */
  name: string;
  /** Server-assigned file ID, present only on success */
  fileId?: string;
  /** Reason this file did not succeed (skipped or failed). Empty on success. */
  reason?: string;
}

/**
 * Aggregate result of a batch upload.
 */
export interface BatchUploadResult {
  succeeded: BatchUploadFileOutcome[];
  failed: BatchUploadFileOutcome[];
  skipped: BatchUploadFileOutcome[];
  /** When set, the batch aborted early on a fatal condition. */
  fatal?: { name: string; reason: string };
}

/**
 * Per-file callback for the batch loop. Receives an immutable snapshot of
 * progress against the *current* file plus an index pointer for batch-level
 * UI updates ("Uploading file 2 of 5: foo.pdf").
 */
export interface BatchUploadProgress extends UploadProgress {
  /** 1-based index of the file currently being uploaded */
  fileIndex: number;
  /** Total number of files in the batch */
  totalFiles: number;
  /** Plain filename of the current file */
  fileName: string;
}

export interface BatchUploadOptions extends Omit<UploadOptions, 'onProgress'> {
  /** Optional progress callback for batch + per-file updates */
  onProgress?: (progress: BatchUploadProgress) => void;
}

/**
 * Upload an array of files sequentially using the existing per-file
 * pipeline. The account key (and custom password / hint) are resolved
 * once at the top and reused for every file.
 *
 * Continues past per-file failures (recorded in `failed[]`) and aborts
 * the batch on fatal conditions (auth expired, quota, account disabled,
 * server cap exceeded). Files after a fatal abort are recorded as
 * skipped[].
 *
 * Sequential by design -- never parallel. See AGENTS.md (mobile/3GB-RAM
 * use case) and docs/wip/general-enhancements.md item 10.
 */
export async function uploadFiles(
  files: File[],
  options: BatchUploadOptions
): Promise<BatchUploadResult> {
  const result: BatchUploadResult = {
    succeeded: [],
    failed: [],
    skipped: [],
  };

  if (files.length === 0) {
    return result;
  }

  // Resolve the account key once for the entire batch. If this fails, the
  // batch cannot continue at all -- no file would have a way to encrypt its
  // metadata. Surface as a synchronous throw rather than per-file failures.
  const accountKey = await resolveAccountKey(options);

  // Capture the per-file pieces explicitly to construct UploadOptions with
  // exactOptionalPropertyTypes-friendly typing (no `undefined` assigned to
  // optional fields).
  const batchOnProgress = options.onProgress;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const fileIndex = i + 1;

    // Preemptively refresh the JWT if it is about to expire. A long batch
    // can outlive a 30-minute JWT, and we do not want to fail mid-chunk
    // when we could have rolled the token between files cheaply.
    try {
      await ensureFreshToken();
    } catch (err) {
      // Refresh failed -- session is gone. Mark the rest of the batch as
      // skipped and propagate the fatal reason.
      const reason = err instanceof Error ? err.message : 'Session expired';
      result.fatal = { name: file.name, reason };
      result.skipped.push({ name: file.name, reason: 'Session expired before upload' });
      for (let j = i + 1; j < files.length; j++) {
        result.skipped.push({ name: files[j].name, reason: 'Session expired earlier in batch' });
      }
      return result;
    }

    // Build per-file options, attaching a wrapper progress callback that
    // injects batch-level context (fileIndex / totalFiles / fileName).
    const fileOptions: UploadOptions = {
      username: options.username,
      passwordType: options.passwordType,
      accountKey,
    };
    if (options.customPassword !== undefined) {
      fileOptions.customPassword = options.customPassword;
    }
    if (options.passwordHint !== undefined) {
      fileOptions.passwordHint = options.passwordHint;
    }
    if (batchOnProgress) {
      fileOptions.onProgress = (progress) => {
        batchOnProgress({
          ...progress,
          fileIndex,
          totalFiles: files.length,
          fileName: file.name,
        });
      };
    }

    try {
      const r = await uploadFile(file, fileOptions);
      result.succeeded.push({ name: file.name, fileId: r.fileId });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      if (isFatalUploadError(err)) {
        // Stop the batch, mark current file as failed, mark remaining as skipped.
        result.fatal = { name: file.name, reason: message };
        result.failed.push({ name: file.name, reason: message });
        for (let j = i + 1; j < files.length; j++) {
          result.skipped.push({ name: files[j].name, reason: 'Aborted after fatal error' });
        }
        return result;
      }

      // Non-fatal: record and continue.
      result.failed.push({ name: file.name, reason: message });
    }
  }

  return result;
}

// ============================================================================
// UI Integration
// ============================================================================

/**
 * Handles file upload from the UI. Supports single-file and multi-file
 * (sequential) batch uploads driven from the same DOM controls.
 *
 * For 'account' password type:
 * - First checks if Account Key is cached and not locked
 * - If cached, uses it directly (no password prompt needed)
 * - If not cached or locked, prompts for password
 *
 * For 'custom' password type:
 * - Always requires the custom password input
 * - The same custom password is applied to every file in the batch
 * - Also needs the account key (from cache or prompt) for metadata encryption
 *
 * Multi-file behavior:
 * - Files are uploaded one at a time, sequentially. Sequential by design --
 *   keeps memory bounded for the constrained-device case (mobile/3GB-RAM
 *   uploading several large files) and matches the per-file server pipeline.
 * - One password prompt for the entire batch. One hint for the entire batch.
 * - Per-file failures are recorded and the loop continues. Fatal errors
 *   (auth expired, quota, account disabled, server cap) abort the batch
 *   immediately; remaining files are reported as skipped.
 * - JWT freshness is checked between files and refreshed proactively if
 *   the access token is within 5 minutes of expiry.
 */
export async function handleFileUpload(): Promise<void> {
  // Get file input -- HTML uses id="fileInput"
  const fileInput = document.getElementById('fileInput') as HTMLInputElement | null;
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showError('Please select one or more files to upload');
    return;
  }

  // Snapshot the FileList into a stable array. The DOM FileList can change
  // out from under us if the user picks new files mid-batch.
  const filesToUpload: File[] = Array.from(fileInput.files);
  const fileCount = filesToUpload.length;

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

  // Upload button -- HTML uses id="upload-file-btn"
  const uploadButton = document.getElementById('upload-file-btn') as HTMLButtonElement | null;

  // Build batch options. Optional fields are added conditionally to play
  // well with exactOptionalPropertyTypes.
  const batchOptions: BatchUploadOptions = {
    username,
    passwordType,
  };
  if (passwordHint) {
    batchOptions.passwordHint = passwordHint;
  }

  // Resolve account key / password once for the whole batch.
  if (isAccountKeyCached(username) && !isAccountKeyLocked()) {
    const cachedKey = await getCachedAccountKey(username, getToken() ?? undefined);
    if (cachedKey) {
      batchOptions.accountKey = cachedKey;
    }
  }

  if (!batchOptions.accountKey) {
    // Need to prompt for the account password.
    const passwordInput = document.getElementById('upload-password') as HTMLInputElement | null;
    let accountPassword = passwordInput?.value || '';

    if (!accountPassword) {
      const result = await promptForAccountKeyPassword();
      if (!result) {
        // User cancelled
        return;
      }
      accountPassword = result.password;

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
        batchOptions.accountKey = derivedKey;
      }
    }

    if (!batchOptions.accountKey) {
      batchOptions.accountPassword = accountPassword;
    }
  }

  // Custom password applies to all files in the batch (single password,
  // single hint). Confirmed UX: the user multi-selecting expects one
  // password prompt for the lot, not N prompts.
  if (passwordType === 'custom') {
    const customPasswordInput = document.getElementById('filePassword') as HTMLInputElement | null;
    const customPassword = customPasswordInput?.value || '';
    if (!customPassword) {
      showError('Please enter your custom password for file encryption');
      return;
    }
    batchOptions.customPassword = customPassword;
  }

  // Disable upload button during the entire batch.
  if (uploadButton) {
    uploadButton.disabled = true;
  }

  const phaseLabels: Record<string, string> = {
    'deriving-key': 'Deriving encryption key...',
    'hashing': 'Computing file hash...',
    'encrypting': 'Encrypting metadata...',
    'init-session': 'Initializing upload session...',
    'uploading': 'Uploading...',
    'completing': 'Finalizing...',
  };

  const batchTitle = fileCount === 1 ? 'Uploading File' : `Uploading ${fileCount} Files`;
  showProgress({
    title: batchTitle,
    message: filesToUpload[0].name,
    indeterminate: true,
  });

  // Wire batch-aware progress callback. Composes "file 2 of 5: foo.pdf"
  // with the per-file phase + chunk + percent that the underlying
  // uploadFile() emits.
  batchOptions.onProgress = (progress) => {
    const phaseMessage = phaseLabels[progress.phase] || progress.phase;
    let message = phaseMessage;
    if (fileCount > 1) {
      message = `File ${progress.fileIndex} of ${progress.totalFiles}: ${progress.fileName} -- ${phaseMessage}`;
    } else {
      message = `${progress.fileName}: ${phaseMessage}`;
    }
    if (progress.currentChunk && progress.totalChunks) {
      message += ` (chunk ${progress.currentChunk}/${progress.totalChunks})`;
    }
    updateProgress({
      title: batchTitle,
      message,
      percentage: progress.percent,
      stage: progress.phase,
    });
  };

  try {
    const batchResult = await uploadFiles(filesToUpload, batchOptions);

    hideProgress();

    // Build a clear summary message. Single-file batches keep the simple
    // "File uploaded successfully" message that today's UX expects.
    if (fileCount === 1) {
      if (batchResult.succeeded.length === 1) {
        showSuccess(`File uploaded successfully! File ID: ${batchResult.succeeded[0].fileId}`);
      } else if (batchResult.failed.length === 1) {
        showError(`Upload failed: ${batchResult.failed[0].reason}`);
      } else if (batchResult.fatal) {
        showError(`Upload failed: ${batchResult.fatal.reason}`);
      }
    } else {
      const ok = batchResult.succeeded.length;
      const failed = batchResult.failed.length;
      const skipped = batchResult.skipped.length;
      let summary = `${ok} of ${fileCount} files uploaded.`;
      if (failed > 0) {
        const samples = batchResult.failed
          .slice(0, 3)
          .map((f) => `${f.name}: ${f.reason}`)
          .join('; ');
        summary += ` ${failed} failed (${samples}${batchResult.failed.length > 3 ? '; ...' : ''}).`;
      }
      if (skipped > 0) {
        summary += ` ${skipped} skipped.`;
      }
      if (batchResult.fatal) {
        summary += ` Aborted: ${batchResult.fatal.reason}`;
      }
      if (failed === 0 && skipped === 0 && !batchResult.fatal) {
        showSuccess(summary);
      } else if (ok > 0) {
        // Partial success -- show as success-with-warning.
        showSuccess(summary);
      } else {
        showError(summary);
      }
    }

    // Clear the form regardless of outcome (matches single-file behavior).
    if (fileInput) fileInput.value = '';
    const fileInputLabel = document.getElementById('fileInputLabel');
    const fileInputName = document.getElementById('fileInputName');
    if (fileInputLabel) fileInputLabel.classList.remove('has-file');
    if (fileInputName) fileInputName.textContent = '';
    const customPasswordInput = document.getElementById('filePassword') as HTMLInputElement | null;
    if (customPasswordInput) customPasswordInput.value = '';
    if (hintInput) hintInput.value = '';

    // Refresh file list once at the end of the batch.
    if (batchResult.succeeded.length > 0) {
      await loadFiles();
    }
  } catch (error) {
    // Errors that escape uploadFiles() (e.g. failed initial account-key
    // resolution) are shown directly. Per-file errors are summarized above.
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
