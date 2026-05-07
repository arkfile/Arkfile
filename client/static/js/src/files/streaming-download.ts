/**
 * Streaming Download Manager for Chunked File Downloads
 *
 * Handles downloading files in chunks with:
 * - Progress tracking
 * - Retry logic with exponential backoff
 * - Client-side decryption
 * - Memory-efficient streaming via incremental Blob construction
 *
 * LARGE FILE SUPPORT
 * ------------------
 * Files > ~1 GB cannot be held entirely in a single JS ArrayBuffer/Uint8Array
 * because the browser's per-context heap limit is typically 2-4 GB. This
 * module avoids the OOM crash by:
 *
 *   - Yielding ONE decrypted chunk at a time from an async generator
 *   - Appending each chunk to an incrementally-built Blob via
 *     `new Blob([existingBlob, chunkData])`
 *   - The browser keeps Blob parts in its internal Blob store (off the JS
 *     heap), so memory pressure stays bounded to a single chunk (~16 MiB)
 *
 * After the last chunk is appended, the Blob is exposed via
 * URL.createObjectURL and the caller triggers a normal browser download
 * with an <a download> anchor click. The file saves to the user's
 * default Downloads folder via the standard browser download pipeline.
 *
 * LOGGING
 * -------
 * All internal stages are logged to console.log with a prefix of
 * `[arkfile-download]` or `[arkfile-share]`. Logs do NOT include filenames,
 * keys, or any potentially private data — only stages, chunk counts, byte
 * counts, durations, and status codes.
 */

import { AESGCMDecryptor } from '../crypto/aes-gcm';
import { getChunkingParams, type ChunkingConfig } from '../crypto/constants';
import { downloadChunkWithRetry, RetryConfig } from './retry-handler';
import { showProgress, updateProgress, hideProgress } from '../ui/progress';

const LOG_PREFIX_FILE = '[arkfile-download]';
const LOG_PREFIX_SHARE = '[arkfile-share]';

/**
 * Metadata returned from the /meta endpoint (snake_case matches JSON response)
 */
export interface ChunkedDownloadMetadata {
  file_id: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  password_hint: string;
  password_type: string;
  size_bytes: number;
  chunk_size: number;
  total_chunks: number;
  chunk_count: number;
  chunk_size_bytes: number;
  encrypted_file_sha256: boolean;
}

/**
 * Progress callback for download operations
 */
export interface DownloadProgressCallback {
  (progress: {
    stage: 'metadata' | 'downloading' | 'decrypting' | 'complete' | 'error';
    currentChunk: number;
    totalChunks: number;
    bytesDownloaded: number;
    totalBytes: number;
    percentage: number;
    speed?: number | undefined; // bytes per second
    remainingTime?: number | undefined; // seconds
    error?: string | undefined;
  }): void;
}

/**
 * Options for streaming download
 */
export interface StreamingDownloadOptions {
  /** Authorization token for authenticated downloads */
  authToken?: string;
  /** Download token for share downloads */
  downloadToken?: string;
  /** Account key for metadata decryption (owner downloads only) */
  accountKey?: Uint8Array;
  /** Retry configuration */
  retryConfig?: Partial<RetryConfig>;
  /** Progress callback */
  onProgress?: DownloadProgressCallback;
  /** Show built-in progress UI */
  showProgressUI?: boolean;
  /** AbortController for cancellation */
  abortController?: AbortController;
}

/**
 * Result of a streaming download.
 *
 * On success, `blobUrl` contains the createObjectURL string that the caller
 * uses to trigger a browser download via `triggerBrowserDownloadFromUrl()`.
 * The caller is responsible for calling `URL.revokeObjectURL(blobUrl)` after
 * the download has been triggered (usually in a setTimeout to give the
 * browser time to start the download).
 */
export interface StreamingDownloadResult {
  success: boolean;
  filename?: string | undefined;
  sha256sum?: string | undefined;
  error?: string | undefined;
  /** Object URL for the assembled Blob; trigger via triggerBrowserDownloadFromUrl. */
  blobUrl?: string | undefined;
}

/**
 * Streaming Download Manager
 *
 * Manages chunked file downloads with decryption, progress tracking, and retry logic.
 */
export class StreamingDownloadManager {
  private baseUrl: string;
  private options: StreamingDownloadOptions;
  private startTime: number = 0;
  private bytesDownloaded: number = 0;
  private chunkingConfig: ChunkingConfig | null = null;

  constructor(baseUrl: string = '', options: StreamingDownloadOptions = {}) {
    this.baseUrl = baseUrl;
    this.options = {
      showProgressUI: true,
      ...options,
    };
  }

  /**
   * Ensure chunking config is loaded from single source of truth
   */
  private async ensureConfig(): Promise<ChunkingConfig> {
    if (!this.chunkingConfig) {
      this.chunkingConfig = await getChunkingParams();
    }
    return this.chunkingConfig;
  }

  /** AES-GCM overhead (nonce + tag) from config */
  private get aesGcmOverhead(): number {
    if (!this.chunkingConfig) throw new Error('Chunking config not loaded');
    return this.chunkingConfig.aesGcm.nonceSizeBytes + this.chunkingConfig.aesGcm.tagSizeBytes;
  }

  /**
   * Download a file using chunked download with decryption (owner downloads).
   */
  async downloadFile(fileId: string, fek: Uint8Array): Promise<StreamingDownloadResult> {
    const t0 = Date.now();
    console.log(`${LOG_PREFIX_FILE} Starting owner download (fileId hash=${shortHash(fileId)})`);

    try {
      await this.ensureConfig();

      if (this.options.showProgressUI) {
        showProgress({ title: 'Downloading File', message: 'Fetching file metadata...', indeterminate: true });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      // 1. Fetch download metadata
      const tMeta = Date.now();
      const metadata = await this.fetchMetadata(fileId);
      console.log(`${LOG_PREFIX_FILE} Metadata fetched in ${Date.now() - tMeta}ms (total_chunks=${metadata.total_chunks}, size_bytes=${metadata.size_bytes}, password_type=${metadata.password_type})`);

      // 2. Decrypt filename and sha256sum using ACCOUNT KEY (not FEK!)
      const metadataKey = this.options.accountKey;
      if (!metadataKey) throw new Error('Account key required for metadata decryption (owner download)');

      const tDecMeta = Date.now();
      const filename = await this.decryptMetadataField(metadata.encrypted_filename, metadata.filename_nonce, metadataKey);
      const sha256sum = await this.decryptMetadataField(metadata.encrypted_sha256sum, metadata.sha256sum_nonce, metadataKey);
      console.log(`${LOG_PREFIX_FILE} Metadata decrypted in ${Date.now() - tDecMeta}ms`);

      // 3. Stream-decrypt all chunks into a Blob
      const tStream = Date.now();
      const blobUrl = await this.streamDecryptedChunksToBlob(
        this.makeFileChunkGenerator(fileId, metadata, fek),
        metadata.total_chunks,
        LOG_PREFIX_FILE,
      );
      console.log(`${LOG_PREFIX_FILE} Blob assembled in ${Date.now() - tStream}ms; total elapsed ${Date.now() - t0}ms`);

      this.reportProgress('complete', metadata.total_chunks, metadata.total_chunks, metadata.size_bytes, metadata.size_bytes);

      if (this.options.showProgressUI) hideProgress();

      console.log(`${LOG_PREFIX_FILE} Download complete: chunks=${metadata.total_chunks}, bytes_decrypted=${metadata.size_bytes}, total_ms=${Date.now() - t0}`);

      return { success: true, filename, sha256sum, blobUrl };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Download failed';
      console.error(`${LOG_PREFIX_FILE} Download failed at ${Date.now() - t0}ms:`, errorMessage);

      this.reportProgress('error', 0, 0, 0, 0, errorMessage);

      if (this.options.showProgressUI) {
        updateProgress({ error: errorMessage });
        setTimeout(() => hideProgress(), 3000);
      }

      return { success: false, error: errorMessage };
    }
  }

  /**
   * Download a shared file using chunked download with decryption.
   *
   * Share recipients do NOT have the owner's account key, so server-side
   * encrypted metadata cannot be decrypted here. Filename/sha256 come from
   * the ShareEnvelope (decrypted by the caller using the share password).
   */
  async downloadSharedFile(
    shareId: string,
    fek: Uint8Array,
    shareMetadata?: { filename?: string | undefined; sha256?: string | undefined },
  ): Promise<StreamingDownloadResult> {
    const t0 = Date.now();
    console.log(`${LOG_PREFIX_SHARE} Starting shared download (shareId hash=${shortHash(shareId)})`);

    try {
      if (this.options.showProgressUI) {
        showProgress({ title: 'Downloading Shared File', message: 'Fetching file metadata...', indeterminate: true });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      const tMeta = Date.now();
      const metadata = await this.fetchShareMetadata(shareId);
      console.log(`${LOG_PREFIX_SHARE} Metadata fetched in ${Date.now() - tMeta}ms (chunk_count=${metadata.chunk_count}, size_bytes=${metadata.size_bytes})`);

      const filename = shareMetadata?.filename;
      const sha256sum = shareMetadata?.sha256;

      const tStream = Date.now();
      const blobUrl = await this.streamDecryptedChunksToBlob(
        this.makeShareChunkGenerator(shareId, metadata, fek),
        metadata.chunk_count,
        LOG_PREFIX_SHARE,
      );
      console.log(`${LOG_PREFIX_SHARE} Blob assembled in ${Date.now() - tStream}ms; total elapsed ${Date.now() - t0}ms`);

      this.reportProgress('complete', metadata.chunk_count, metadata.chunk_count, metadata.size_bytes, metadata.size_bytes);

      if (this.options.showProgressUI) hideProgress();

      console.log(`${LOG_PREFIX_SHARE} Download complete: chunks=${metadata.chunk_count}, bytes_decrypted=${metadata.size_bytes}, total_ms=${Date.now() - t0}`);

      return { success: true, filename, sha256sum, blobUrl };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Download failed';
      console.error(`${LOG_PREFIX_SHARE} Download failed at ${Date.now() - t0}ms:`, errorMessage);

      this.reportProgress('error', 0, 0, 0, 0, errorMessage);

      if (this.options.showProgressUI) {
        updateProgress({ error: errorMessage });
        setTimeout(() => hideProgress(), 3000);
      }

      return { success: false, error: errorMessage };
    }
  }

  /**
   * Async generator that downloads and decrypts file chunks one at a time.
   *
   * Chunk format:
   *   - Chunk 0: [version (1 byte)][keyType (1 byte)][nonce (12 B)][ciphertext][tag (16 B)]
   *   - Chunks 1+:                  [nonce (12 B)][ciphertext][tag (16 B)]
   * The 2-byte envelope header is stripped from chunk 0 before AES-GCM decrypt.
   */
  private async *makeFileChunkGenerator(
    fileId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array,
  ): AsyncGenerator<Uint8Array> {
    const config = await this.ensureConfig();
    const envelopeHeaderSize = config.envelope.headerSizeBytes;
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);

    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const headers: Record<string, string> = {};
    if (this.options.authToken) headers['Authorization'] = `Bearer ${this.options.authToken}`;

    for (let chunkIndex = 0; chunkIndex < metadata.total_chunks; chunkIndex++) {
      if (this.options.abortController?.signal.aborted) throw new Error('Download cancelled');

      const tFetch = Date.now();
      const encryptedChunk = await downloadChunkWithRetry(
        `${this.baseUrl}/api/files/${fileId}/chunks/${chunkIndex}`,
        headers,
        this.options.retryConfig,
        (attempt, error, delay) => {
          console.log(`${LOG_PREFIX_FILE} Chunk ${chunkIndex} retry ${attempt} after ${delay}ms: ${error.message}`);
        },
      );
      const fetchMs = Date.now() - tFetch;

      let chunkData = encryptedChunk;
      if (chunkIndex === 0) {
        if (encryptedChunk.length < envelopeHeaderSize) {
          throw new Error(`Chunk 0 too short: expected at least ${envelopeHeaderSize} bytes for envelope, got ${encryptedChunk.length}`);
        }
        const version = encryptedChunk[0];
        if (version !== 0x01) {
          throw new Error(`Unsupported envelope version on chunk 0: 0x${version.toString(16).padStart(2, '0')} (expected 0x01)`);
        }
        chunkData = encryptedChunk.slice(envelopeHeaderSize);
      }

      const tDec = Date.now();
      const decryptedChunk = await decryptor.decryptChunk(chunkData);
      const decMs = Date.now() - tDec;

      this.bytesDownloaded += encryptedChunk.length;

      // Log every chunk for the first 3, then every ~10% of total chunks
      const logInterval = Math.max(1, Math.floor(metadata.total_chunks / 10));
      if (chunkIndex < 3 || chunkIndex % logInterval === 0 || chunkIndex === metadata.total_chunks - 1) {
        console.log(
          `${LOG_PREFIX_FILE} Chunk ${chunkIndex + 1}/${metadata.total_chunks}: fetch=${fetchMs}ms, decrypt=${decMs}ms, total_bytes=${this.bytesDownloaded}`,
        );
      }

      this.reportProgress('downloading', chunkIndex + 1, metadata.total_chunks, this.bytesDownloaded, this.calculateTotalEncryptedSize(metadata));

      if (this.options.showProgressUI) {
        const percentage = ((chunkIndex + 1) / metadata.total_chunks) * 100;
        const speed = this.calculateSpeed();
        const remaining = this.calculateRemainingTime(metadata.total_chunks - chunkIndex - 1, speed, metadata.chunk_size_bytes);
        updateProgress({
          title: 'Downloading File',
          message: `Chunk ${chunkIndex + 1} of ${metadata.total_chunks}`,
          percentage,
          speed,
          remainingTime: remaining,
        });
      }

      yield decryptedChunk;
    }
  }

  /**
   * Async generator that downloads and decrypts shared file chunks one at a time.
   */
  private async *makeShareChunkGenerator(
    shareId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array,
  ): AsyncGenerator<Uint8Array> {
    const config = await this.ensureConfig();
    const envelopeHeaderSize = config.envelope.headerSizeBytes;
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);

    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const headers: Record<string, string> = {};
    if (this.options.downloadToken) headers['X-Download-Token'] = this.options.downloadToken;

    for (let chunkIndex = 0; chunkIndex < metadata.chunk_count; chunkIndex++) {
      if (this.options.abortController?.signal.aborted) throw new Error('Download cancelled');

      const tFetch = Date.now();
      const encryptedChunk = await downloadChunkWithRetry(
        `${this.baseUrl}/api/public/shares/${shareId}/chunks/${chunkIndex}`,
        headers,
        this.options.retryConfig,
        (attempt, error, delay) => {
          console.log(`${LOG_PREFIX_SHARE} Chunk ${chunkIndex} retry ${attempt} after ${delay}ms: ${error.message}`);
        },
      );
      const fetchMs = Date.now() - tFetch;

      let chunkData = encryptedChunk;
      if (chunkIndex === 0) {
        if (encryptedChunk.length < envelopeHeaderSize) {
          throw new Error(`Share chunk 0 too short: expected at least ${envelopeHeaderSize} bytes, got ${encryptedChunk.length}`);
        }
        const version = encryptedChunk[0];
        if (version !== 0x01) {
          throw new Error(`Unsupported envelope version on share chunk 0: 0x${version.toString(16).padStart(2, '0')} (expected 0x01)`);
        }
        chunkData = encryptedChunk.slice(envelopeHeaderSize);
      }

      const tDec = Date.now();
      const decryptedChunk = await decryptor.decryptChunk(chunkData);
      const decMs = Date.now() - tDec;

      this.bytesDownloaded += encryptedChunk.length;

      const logInterval = Math.max(1, Math.floor(metadata.chunk_count / 10));
      if (chunkIndex < 3 || chunkIndex % logInterval === 0 || chunkIndex === metadata.chunk_count - 1) {
        console.log(
          `${LOG_PREFIX_SHARE} Chunk ${chunkIndex + 1}/${metadata.chunk_count}: fetch=${fetchMs}ms, decrypt=${decMs}ms, total_bytes=${this.bytesDownloaded}`,
        );
      }

      this.reportProgress('downloading', chunkIndex + 1, metadata.chunk_count, this.bytesDownloaded, this.calculateTotalEncryptedSize(metadata));

      if (this.options.showProgressUI) {
        const percentage = ((chunkIndex + 1) / metadata.chunk_count) * 100;
        const speed = this.calculateSpeed();
        const remaining = this.calculateRemainingTime(metadata.chunk_count - chunkIndex - 1, speed, metadata.chunk_size_bytes);
        updateProgress({
          title: 'Downloading Shared File',
          message: `Chunk ${chunkIndex + 1} of ${metadata.chunk_count}`,
          percentage,
          speed,
          remainingTime: remaining,
        });
      }

      yield decryptedChunk;
    }
  }

  /**
   * Stream decrypted chunks into an incrementally-built Blob and return its URL.
   *
   * Uses `new Blob([existingBlob, chunk])` per chunk so the browser keeps each
   * chunk in its internal Blob store (off the JS heap). Peak heap usage is
   * bounded to one chunk (~16 MiB) regardless of total file size.
   */
  private async streamDecryptedChunksToBlob(
    chunks: AsyncGenerator<Uint8Array>,
    totalChunks: number,
    logPrefix: string,
  ): Promise<string> {
    let blob = new Blob([]);
    let chunkIndex = 0;
    for await (const chunk of chunks) {
      // slice(0) gives a concrete ArrayBuffer-backed Uint8Array, satisfying BlobPart typing
      blob = new Blob([blob, chunk.slice(0)]);
      chunkIndex++;
      // Log Blob growth at 25/50/75/100% milestones
      const pctMilestones = [Math.floor(totalChunks * 0.25), Math.floor(totalChunks * 0.5), Math.floor(totalChunks * 0.75), totalChunks];
      if (pctMilestones.includes(chunkIndex)) {
        console.log(`${logPrefix} Blob accumulation milestone: ${chunkIndex}/${totalChunks} chunks appended (~${blob.size} bytes total)`);
      }
    }
    const url = URL.createObjectURL(blob);
    console.log(`${logPrefix} Blob URL created (${blob.size} bytes)`);
    return url;
  }

  /** Fetch download metadata for a file */
  private async fetchMetadata(fileId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.options.authToken) headers['Authorization'] = `Bearer ${this.options.authToken}`;
    const response = await fetch(`${this.baseUrl}/api/files/${fileId}/meta`, { method: 'GET', headers });
    if (!response.ok) {
      console.error(`${LOG_PREFIX_FILE} Metadata fetch failed: HTTP ${response.status} ${response.statusText}`);
      throw new Error(`Failed to fetch metadata: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  /** Fetch download metadata for a shared file */
  private async fetchShareMetadata(shareId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.options.downloadToken) headers['X-Download-Token'] = this.options.downloadToken;
    const response = await fetch(`${this.baseUrl}/api/public/shares/${shareId}/metadata`, { method: 'GET', headers });
    if (!response.ok) {
      console.error(`${LOG_PREFIX_SHARE} Metadata fetch failed: HTTP ${response.status} ${response.statusText}`);
      throw new Error(`Failed to fetch share metadata: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  /**
   * Decrypt a metadata field (filename or sha256sum).
   *
   * Metadata is encrypted with the account key (Argon2id derived), NOT the FEK.
   * Server stores [nonce] separately from [ciphertext + auth_tag]; we reassemble.
   */
  private async decryptMetadataField(encryptedBase64: string, nonceBase64: string, key: Uint8Array): Promise<string> {
    const encrypted = this.base64ToBytes(encryptedBase64);
    const nonce = this.base64ToBytes(nonceBase64);
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce, 0);
    combined.set(encrypted, nonce.length);
    const decryptor = await AESGCMDecryptor.fromRawKey(key);
    const decrypted = await decryptor.decryptChunk(combined);
    return new TextDecoder().decode(decrypted);
  }

  private calculateTotalEncryptedSize(metadata: ChunkedDownloadMetadata): number {
    return metadata.size_bytes + (metadata.total_chunks * this.aesGcmOverhead);
  }

  private calculateSpeed(): number {
    const elapsedMs = Date.now() - this.startTime;
    if (elapsedMs === 0) return 0;
    return Math.round((this.bytesDownloaded / elapsedMs) * 1000);
  }

  private calculateRemainingTime(remainingChunks: number, speed: number, chunkSize: number): number {
    if (speed === 0) return 0;
    const remainingBytes = remainingChunks * (chunkSize + this.aesGcmOverhead);
    return Math.round(remainingBytes / speed);
  }

  private reportProgress(
    stage: 'metadata' | 'downloading' | 'decrypting' | 'complete' | 'error',
    currentChunk: number,
    totalChunks: number,
    bytesDownloaded: number,
    totalBytes: number,
    error?: string,
  ): void {
    if (this.options.onProgress) {
      const percentage = totalChunks > 0 ? (currentChunk / totalChunks) * 100 : 0;
      this.options.onProgress({
        stage,
        currentChunk,
        totalChunks,
        bytesDownloaded,
        totalBytes,
        percentage,
        speed: this.calculateSpeed(),
        remainingTime: stage === 'downloading' ? this.calculateRemainingTime(
          totalChunks - currentChunk,
          this.calculateSpeed(),
          this.chunkingConfig!.plaintextChunkSizeBytes,
        ) : undefined,
        error,
      });
    }
  }

  private base64ToBytes(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
    return bytes;
  }
}

/** Convenience function to download a file with chunked download (owner) */
export async function downloadFileChunked(
  fileId: string,
  fek: Uint8Array,
  authToken: string,
  options: Partial<StreamingDownloadOptions> = {},
): Promise<StreamingDownloadResult> {
  const manager = new StreamingDownloadManager('', { authToken, ...options });
  return manager.downloadFile(fileId, fek);
}

/** Convenience function to download a shared file with chunked download */
export async function downloadSharedFileChunked(
  shareId: string,
  fek: Uint8Array,
  downloadToken: string,
  shareMetadata?: { filename?: string | undefined; sha256?: string | undefined },
  options: Partial<StreamingDownloadOptions> = {},
): Promise<StreamingDownloadResult> {
  const manager = new StreamingDownloadManager('', { downloadToken, ...options });
  return manager.downloadSharedFile(shareId, fek, shareMetadata);
}

/**
 * Trigger a browser download from a Blob URL produced by the streaming manager.
 * Creates an <a download> anchor, clicks it, then revokes the URL after a delay.
 * Saves to the user's default Downloads folder via the standard browser pipeline.
 */
export function triggerBrowserDownloadFromUrl(blobUrl: string, filename: string): void {
  console.log(`[arkfile-download] Triggering browser download anchor (filename_len=${filename.length})`);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(blobUrl);
    console.log('[arkfile-download] Blob URL revoked');
  }, 1000);
}

/**
 * Trigger browser download of decrypted data (legacy single-buffer path).
 *
 * @deprecated For new code, prefer the streaming path via downloadFileChunked /
 *   downloadSharedFileChunked which returns a blobUrl. This function creates a
 *   full in-memory copy and will OOM for files > ~1 GB.
 */
export function triggerBrowserDownload(data: Uint8Array, filename: string, contentType: string = 'application/octet-stream'): void {
  const dataCopy = new Uint8Array(data);
  const blob = new Blob([dataCopy.buffer], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
}

/** Compute a short non-cryptographic hash of an ID for log correlation (no PII) */
function shortHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, '0').slice(0, 8);
}
