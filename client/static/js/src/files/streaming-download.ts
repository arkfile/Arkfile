/**
 * Streaming Download Manager for Chunked File Downloads
 *
 * Handles downloading files in chunks with:
 *   - Progress tracking
 *   - Retry logic with exponential backoff
 *   - Client-side AES-GCM decryption
 *   - Service Worker streaming (preferred path) for unbounded file sizes
 *   - Incremental Blob fallback when SW is unavailable or cannot initialize
 *     before any generator output has been consumed
 *
 * Service Worker streaming (preferred / canonical for large files)
 * ---------------------------------------------------------------
 * On modern browsers (Chromium, Firefox 100+, Safari 16.4+, Tor Browser 12+),
 * the page hands the decrypted-byte stream to a same-origin Service Worker
 * which responds to a synthetic /sw-download/<uuid> URL with a streaming
 * Response (Content-Disposition: attachment). The browser's download manager
 * then writes the bytes directly to disk with no Blob accumulation.
 *
 * - Peak heap usage: ~one plaintext chunk at a time
 * - File size limit: no Arkfile-imposed cap (browser streams to disk)
 * - SHA-256: computed inline as bytes flow; mismatch may be known only after
 *   the OS download manager has already saved bytes. Same post-write class of
 *   limit as CLI computeStreamingSHA256 on the output path and offline
 *   decrypt-blob. Per-chunk AES-GCM still authenticates each chunk during
 *   decrypt. Callers must never claim unqualified success on mismatch.
 *
 * Blob fallback (retain; no Arkfile size cap)
 * -------------------------------------------
 * Used when the SW is unavailable, or when SW init fails before any generator
 * consumption (e.g. synchronous DataCloneError on postMessage transfer).
 * Do NOT fall back after ack timeout or mid-stream failure: the generator may
 * already be drained and a partial browser download may exist.
 *
 * - Retains the complete plaintext in browser Blob storage before trigger
 * - No Arkfile-imposed file size limit; browser memory/storage may still fail
 * - SHA-256 is verified before triggerBrowserDownloadFromUrl; on mismatch the
 *   Blob URL must be revoked and download must not be triggered
 *
 * Privacy logging
 * ---------------
 * Logs use prefixes [arkfile-download] / [arkfile-share]. Logs do NOT include
 * filenames, keys, hash digest values, or any potentially private data — only
 * stages, chunk counts, byte counts, durations, and status codes.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { AESGCMDecryptor } from '../crypto/aes-gcm';
import { getChunkingParams, type ChunkingConfig } from '../crypto/constants';
import { downloadChunkWithRetry, RetryConfig } from './retry-handler';
import { showProgress, updateProgress, hideProgress } from '../ui/progress';
import {
  isSwAvailable,
  swStreamDownload,
  type SwStreamDownloadCompletion,
} from './sw-streaming-download';
import {
  buildChunkAAD,
  AAD_FIELD_FILENAME,
  AAD_FIELD_SHA256,
} from '../crypto/aad';
import { decryptMetadataField } from '../crypto/metadata-helpers';
import { debugLog } from '../utils/debug-log.js';

const LOG_PREFIX_FILE = '[arkfile-download]';
const LOG_PREFIX_SHARE = '[arkfile-share]';

/**
 * Metadata returned from the /meta endpoint (snake_case matches JSON response).
 *
 * `owner_username` is required for owner-side metadata decryption
 * because the metadata-field AAD binds (file_id, field_label, owner_username).
 * Anonymous share recipients do not decrypt the server-side metadata fields
 * (filename/sha256 come from the ShareEnvelope), so for share metadata the
 * field may be omitted by the server.
 */
export interface ChunkedDownloadMetadata {
  file_id: string;
  owner_username?: string;
  encrypted_filename: string;
  filename_nonce: string;
  encrypted_sha256sum: string;
  sha256sum_nonce: string;
  encrypted_fek: string;
  encrypted_password_hint?: string;
  password_hint_nonce?: string;
  password_type: string;
  size_bytes: number;
  chunk_size: number;
  total_chunks: number;
  chunk_count: number;
  chunk_size_bytes: number;
  encrypted_file_sha256: boolean;
}

/** Hash verification outcome (mirrors sw-streaming-download). */
export type HashVerification = 'skipped' | 'match' | 'mismatch' | 'unavailable';

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
    speed?: number | undefined;
    remainingTime?: number | undefined;
    error?: string | undefined;
  }): void;
}

/**
 * Options for streaming download
 */
export interface StreamingDownloadOptions {
  /** Authorization token for authenticated downloads */
  authToken?: string;
  /** Required for share downloads: short-lived ticket holder. The manager sends
   *  X-Share-Ticket per request and calls refresh() on 403 to re-issue.
   *  Static X-Download-Token is not accepted; the envelope download token is
   *  used only to obtain tickets via the ticket API. */
  shareTicket?: { get: () => Promise<string>; refresh: () => Promise<string> };
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
 * On the SW streaming path (preferred), `streamedViaSw` is true and the
 * browser's download manager has been handed the bytes directly. No blobUrl
 * is produced. `hashVerification` reports the outcome of in-flight SHA-256
 * verification (often post-write relative to disk).
 *
 * On the Blob fallback path, `blobUrl` contains the createObjectURL string.
 * The caller must check `hashVerification` BEFORE triggerBrowserDownloadFromUrl.
 * On mismatch, revoke the Blob URL and do not trigger or claim success.
 * `hashVerification` reports the incremental end-of-file SHA-256 check.
 */
export interface StreamingDownloadResult {
  success: boolean;
  filename?: string | undefined;
  /** Expected SHA-256 (hex) sourced from envelope/metadata. */
  sha256sum?: string | undefined;
  error?: string | undefined;
  /** True if the SW streaming path was used. */
  streamedViaSw?: boolean | undefined;
  /** SHA-256 verification outcome (both SW and Blob fallback paths). */
  hashVerification?: HashVerification | undefined;
  /** Computed SHA-256 hex when hashing ran (match or mismatch). */
  computedSha256Hex?: string | undefined;
  /** Object URL for the assembled Blob; present only on the Blob fallback path. */
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

  /** Ensure chunking config is loaded from single source of truth */
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

  /** Download a file using chunked download with decryption (owner downloads). */
  async downloadFile(fileId: string, fek: Uint8Array): Promise<StreamingDownloadResult> {
    const t0 = Date.now();
    debugLog(`${LOG_PREFIX_FILE} Starting owner download (fileId hash=${shortHash(fileId)})`);

    try {
      await this.ensureConfig();

      if (this.options.showProgressUI) {
        showProgress({ title: 'Downloading File', message: 'Fetching file metadata...', indeterminate: true });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      // 1. Fetch download metadata
      const tMeta = Date.now();
      const metadata = await this.fetchMetadata(fileId);
      debugLog(`${LOG_PREFIX_FILE} Metadata fetched in ${Date.now() - tMeta}ms (total_chunks=${metadata.total_chunks}, size_bytes=${metadata.size_bytes}, password_type=${metadata.password_type})`);

      // 2. Decrypt filename and sha256sum using ACCOUNT KEY (not FEK).
      // metadata-field AAD requires (file_id, field_label, owner_username).
      const metadataKey = this.options.accountKey;
      if (!metadataKey) throw new Error('Account key required for metadata decryption (owner download)');
      if (!metadata.owner_username) {
        throw new Error('Server metadata missing owner_username (required for metadata AAD)');
      }

      const tDecMeta = Date.now();
      const filename = await decryptMetadataField(
        metadata.encrypted_filename, metadata.filename_nonce, metadataKey,
        metadata.file_id, AAD_FIELD_FILENAME, metadata.owner_username,
      );
      const sha256sum = await decryptMetadataField(
        metadata.encrypted_sha256sum, metadata.sha256sum_nonce, metadataKey,
        metadata.file_id, AAD_FIELD_SHA256, metadata.owner_username,
      );
      debugLog(`${LOG_PREFIX_FILE} Metadata decrypted in ${Date.now() - tDecMeta}ms`);

      // 3. Stream-decrypt chunks via SW (preferred) or Blob fallback
      const tStream = Date.now();
      const streamResult = await this.streamDecryptedChunks(
        () => this.makeFileChunkGenerator(fileId, metadata, fek),
        metadata.total_chunks,
        metadata.size_bytes,
        filename,
        sha256sum,
        LOG_PREFIX_FILE,
      );

      this.reportProgress('complete', metadata.total_chunks, metadata.total_chunks, metadata.size_bytes, metadata.size_bytes);

      if (this.options.showProgressUI) hideProgress();

      debugLog(`${LOG_PREFIX_FILE} Download complete: chunks=${metadata.total_chunks}, bytes_decrypted=${metadata.size_bytes}, total_ms=${Date.now() - t0}, sw_path=${streamResult.streamedViaSw === true}, hash_verification=${streamResult.hashVerification ?? 'n/a'}`);

      return {
        success: true,
        filename,
        sha256sum,
        ...(streamResult.streamedViaSw !== undefined ? { streamedViaSw: streamResult.streamedViaSw } : {}),
        ...(streamResult.hashVerification !== undefined ? { hashVerification: streamResult.hashVerification } : {}),
        ...(streamResult.computedSha256Hex !== undefined ? { computedSha256Hex: streamResult.computedSha256Hex } : {}),
        ...(streamResult.blobUrl !== undefined ? { blobUrl: streamResult.blobUrl } : {}),
      };
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
    debugLog(`${LOG_PREFIX_SHARE} Starting shared download (shareId hash=${shortHash(shareId)})`);

    try {
      await this.ensureConfig();

      if (this.options.showProgressUI) {
        showProgress({ title: 'Downloading Shared File', message: 'Fetching file metadata...', indeterminate: true });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      const tMeta = Date.now();
      const metadata = await this.fetchShareMetadata(shareId);
      debugLog(`${LOG_PREFIX_SHARE} Metadata fetched in ${Date.now() - tMeta}ms (chunk_count=${metadata.chunk_count}, size_bytes=${metadata.size_bytes})`);

      const filename = shareMetadata?.filename ?? 'shared-file';
      const sha256sum = shareMetadata?.sha256;

      const tStream = Date.now();
      const streamResult = await this.streamDecryptedChunks(
        () => this.makeShareChunkGenerator(shareId, metadata, fek),
        metadata.chunk_count,
        metadata.size_bytes,
        filename,
        sha256sum,
        LOG_PREFIX_SHARE,
      );

      this.reportProgress('complete', metadata.chunk_count, metadata.chunk_count, metadata.size_bytes, metadata.size_bytes);

      if (this.options.showProgressUI) hideProgress();

      debugLog(`${LOG_PREFIX_SHARE} Download complete: chunks=${metadata.chunk_count}, bytes_decrypted=${metadata.size_bytes}, total_ms=${Date.now() - t0}, sw_path=${streamResult.streamedViaSw === true}, hash_verification=${streamResult.hashVerification ?? 'n/a'}`);

      return {
        success: true,
        filename,
        ...(sha256sum !== undefined ? { sha256sum } : {}),
        ...(streamResult.streamedViaSw !== undefined ? { streamedViaSw: streamResult.streamedViaSw } : {}),
        ...(streamResult.hashVerification !== undefined ? { hashVerification: streamResult.hashVerification } : {}),
        ...(streamResult.computedSha256Hex !== undefined ? { computedSha256Hex: streamResult.computedSha256Hex } : {}),
        ...(streamResult.blobUrl !== undefined ? { blobUrl: streamResult.blobUrl } : {}),
      };
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
   * Uniform chunk layout, no chunk-0 envelope
   * header. Each chunk is [nonce(12)][ciphertext][tag(16)] and decrypts
   * under per-chunk AAD = BuildChunkAAD(file_id, chunkIndex, totalChunks).
   */
  private async *makeFileChunkGenerator(
    fileId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array,
  ): AsyncGenerator<Uint8Array> {
    await this.ensureConfig();
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);

    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const headers: Record<string, string> = {};
    if (this.options.authToken) headers['Authorization'] = `Bearer ${this.options.authToken}`;

    const totalChunks = metadata.total_chunks;

    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      if (this.options.abortController?.signal.aborted) throw new Error('Download cancelled');

      const tFetch = Date.now();
      const encryptedChunk = await downloadChunkWithRetry(
        `${this.baseUrl}/api/files/${fileId}/chunks/${chunkIndex}`,
        headers,
        this.options.retryConfig,
        (attempt, error, delay) => {
          debugLog(`${LOG_PREFIX_FILE} Chunk ${chunkIndex} retry ${attempt} after ${delay}ms: ${error.message}`);
        },
      );
      const fetchMs = Date.now() - tFetch;

      const aad = buildChunkAAD(
        metadata.file_id, BigInt(chunkIndex), BigInt(totalChunks),
      );

      const tDec = Date.now();
      const decryptedChunk = await decryptor.decryptChunk(encryptedChunk, aad);
      const decMs = Date.now() - tDec;

      this.bytesDownloaded += encryptedChunk.length;

      const logInterval = Math.max(1, Math.floor(metadata.total_chunks / 10));
      if (chunkIndex < 3 || chunkIndex % logInterval === 0 || chunkIndex === metadata.total_chunks - 1) {
        debugLog(
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
   *
   * Chunk AAD is built from the underlying file_id (which the
   * server returns in share metadata), NOT the share_id. Owner uploads
   * and recipient downloads thus produce/consume the same AAD bytes.
   */
  private async *makeShareChunkGenerator(
    shareId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array,
  ): AsyncGenerator<Uint8Array> {
    await this.ensureConfig();
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);

    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const totalChunks = metadata.chunk_count;

    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
      if (this.options.abortController?.signal.aborted) throw new Error('Download cancelled');

      const tFetch = Date.now();
      const encryptedChunk = await this.fetchShareChunkWithTicketRefresh(shareId, chunkIndex, totalChunks);
      const fetchMs = Date.now() - tFetch;

      const aad = buildChunkAAD(
        metadata.file_id, BigInt(chunkIndex), BigInt(totalChunks),
      );

      const tDec = Date.now();
      const decryptedChunk = await decryptor.decryptChunk(encryptedChunk, aad);
      const decMs = Date.now() - tDec;

      this.bytesDownloaded += encryptedChunk.length;

      const logInterval = Math.max(1, Math.floor(metadata.chunk_count / 10));
      if (chunkIndex < 3 || chunkIndex % logInterval === 0 || chunkIndex === metadata.chunk_count - 1) {
        debugLog(
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
   * Stream decrypted chunks to the browser's download manager (SW path) or to
   * an in-memory Blob (fallback path).
   *
   * `chunksFactory` produces a fresh async generator. SW and Blob paths each
   * call it once so a failed SW transfer that closes the first generator cannot
   * leave Blob fallback with a drained iterator.
   *
   * SW path: hands the generator stream to the SW, which serves it as a
   * Content-Disposition: attachment Response. Hashes plaintext as it streams
   * past for SHA-256 verification (when an expected hash is provided).
   * Whole-file mismatch may be reported only after bytes are on disk.
   *
   * Blob fallback: incrementally builds a Blob via `new Blob([existingBlob, chunk])`
   * to keep data in the browser's internal Blob store off the JS heap, while
   * hashing each plaintext chunk so the whole-file SHA-256 can be verified
   * before trigger. Returns a blob URL the caller can hand to
   * triggerBrowserDownloadFromUrl() only after checking hashVerification.
   *
   * Fallback eligibility: only when SW init fails before generator consumption
   * is known to have started (e.g. DataCloneError on postMessage). Ack timeout
   * and mid-stream errors must not fall back (uncertain / drained state).
   */
  private async streamDecryptedChunks(
    chunksFactory: () => AsyncGenerator<Uint8Array>,
    totalChunks: number,
    contentLength: number,
    filename: string,
    expectedSha256Hex: string | undefined,
    logPrefix: string,
  ): Promise<{
    streamedViaSw?: boolean;
    hashVerification?: HashVerification;
    computedSha256Hex?: string;
    blobUrl?: string;
  }> {
    if (isSwAvailable()) {
      debugLog(`${logPrefix} Using SW streaming download path`);
      try {
        const swResult = await swStreamDownload({
          contentLength,
          filename,
          chunks: chunksFactory(),
          ...(this.options.abortController ? { signal: this.options.abortController.signal } : {}),
          ...(expectedSha256Hex && expectedSha256Hex.length === 64 ? { expectedSha256Hex } : {}),
        });

        // Wait for the actual stream to drain so we know the hash result and
        // bytes-streamed before returning. The browser's download manager and
        // the SW's stream consumption proceed in parallel with this wait.
        const completion: SwStreamDownloadCompletion = await swResult.completion;
        debugLog(`${logPrefix} SW stream completed: ok=${completion.ok}, bytes_streamed=${completion.bytesStreamed}, hash_verification=${completion.hashVerification}`);
        if (!completion.ok && completion.error) {
          // Mid-stream failure: a partial file may already be in Downloads.
          const base = completion.error.message || 'Download interrupted';
          throw new Error(
            `${base}. A partial file may already be in your downloads folder; delete it if incomplete.`,
          );
        }
        return {
          streamedViaSw: true,
          hashVerification: completion.hashVerification,
          ...(completion.computedSha256Hex
            ? { computedSha256Hex: completion.computedSha256Hex }
            : {}),
        };
      } catch (err: unknown) {
        if (isSafeSwToBlobFallback(err)) {
          console.warn(
            `${logPrefix} SW stream transfer failed before generator consumption; falling back to Blob path. Error: ${describeErr(err)}`,
          );
          // Proceed to Blob fallback with a FRESH generator below.
        } else {
          throw err instanceof Error ? err : new Error(String(err));
        }
      }
    }

    // Blob fallback path
    //
    // Hash the decrypted plaintext incrementally as each chunk arrives so the
    // whole-file SHA-256 can be verified before triggerBrowserDownloadFromUrl.
    // There is no Arkfile-imposed size cap; the browser may still fail to
    // allocate or retain the full Blob. Hashing one chunk at a time adds no
    // extra peak memory. A mismatch is reported via hashVerification — callers
    // must revoke the URL and must not trigger download or claim success.
    debugLog(`${logPrefix} Using Blob fallback path (SW unavailable or pre-transfer init failure)`);
    const chunks = chunksFactory();
    const wantHash = typeof expectedSha256Hex === 'string' && expectedSha256Hex.length === 64;
    const hasher = wantHash ? sha256.create() : null;
    let blob = new Blob([]);
    let chunkIndex = 0;
    try {
      for await (const chunk of chunks) {
        if (hasher) hasher.update(chunk);
        // slice(0) gives a concrete ArrayBuffer-backed Uint8Array, satisfying BlobPart typing
        blob = new Blob([blob, chunk.slice(0)]);
        chunkIndex++;
        const pctMilestones = [Math.floor(totalChunks * 0.25), Math.floor(totalChunks * 0.5), Math.floor(totalChunks * 0.75), totalChunks];
        if (pctMilestones.includes(chunkIndex)) {
          debugLog(`${logPrefix} Blob accumulation milestone: ${chunkIndex}/${totalChunks} chunks appended (~${blob.size} bytes total)`);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/quota|memory|allocation|out of memory/i.test(msg)) {
        throw new Error(
          'Browser could not allocate or retain the full decrypted file in memory. Retry with Service Worker streaming available, or use the arkfile-client CLI.',
        );
      }
      throw err instanceof Error ? err : new Error(msg);
    }
    const url = URL.createObjectURL(blob);
    debugLog(`${logPrefix} Blob URL created (${blob.size} bytes)`);

    let hashVerification: HashVerification = 'skipped';
    let computedSha256Hex: string | undefined;
    if (hasher && expectedSha256Hex) {
      computedSha256Hex = bytesToHex(hasher.digest());
      hashVerification = constantTimeHexEqual(computedSha256Hex, expectedSha256Hex) ? 'match' : 'mismatch';
      if (hashVerification === 'mismatch') {
        // No digest values, no filename in the log (privacy), matching the SW path.
        console.warn(`${logPrefix} SHA-256 verification FAILED for downloaded file (computed digest does not match expected)`);
      }
    }
    return {
      blobUrl: url,
      hashVerification,
      ...(computedSha256Hex !== undefined ? { computedSha256Hex } : {}),
    };
  }

  /** Fetch download metadata for a file */
  private async fetchMetadata(fileId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.options.authToken) headers['Authorization'] = `Bearer ${this.options.authToken}`;
    const response = await fetch(`${this.baseUrl}/api/files/${fileId}/meta`, {
      method: 'GET',
      headers,
      credentials: 'include',
    });
    if (!response.ok) {
      console.error(`${LOG_PREFIX_FILE} Metadata fetch failed: HTTP ${response.status} ${response.statusText}`);
      throw new Error(`Failed to fetch metadata: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  /** Fetch download metadata for a shared file */
  private async fetchShareMetadata(shareId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    await this.applyShareAuthHeader(headers);
    const response = await fetch(`${this.baseUrl}/api/public/shares/${shareId}/metadata`, { method: 'GET', headers });
    if (response.ok) return response.json();

    // On 403, the ticket may have expired mid-session; refresh once and retry.
    if (response.status === 403 && this.options.shareTicket) {
      await this.options.shareTicket.refresh();
      const retryHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      await this.applyShareAuthHeader(retryHeaders);
      const retry = await fetch(`${this.baseUrl}/api/public/shares/${shareId}/metadata`, { method: 'GET', headers: retryHeaders });
      if (retry.ok) return retry.json();
      console.error(`${LOG_PREFIX_SHARE} Metadata fetch failed after ticket refresh: HTTP ${retry.status} ${retry.statusText}`);
      throw new Error(`Failed to fetch share metadata: ${retry.status} ${retry.statusText}`);
    }
    console.error(`${LOG_PREFIX_SHARE} Metadata fetch failed: HTTP ${response.status} ${response.statusText}`);
    throw new Error(`Failed to fetch share metadata: ${response.status} ${response.statusText}`);
  }

  /**
   * Build share auth headers with a short-lived X-Share-Ticket only.
   * Ticket-provider failure fails closed; never sends X-Download-Token.
   */
  private async applyShareAuthHeader(headers: Record<string, string>): Promise<void> {
    if (!this.options.shareTicket) {
      throw new Error(
        'Share download requires a short-lived share ticket. Re-enter the share password and try again.',
      );
    }
    try {
      headers['X-Share-Ticket'] = await this.options.shareTicket.get();
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      console.error(`${LOG_PREFIX_SHARE} Ticket provider failed (fail closed):`, err);
      throw new Error(
        `Failed to obtain share download ticket: ${detail}. Re-enter the share password and try again.`,
      );
    }
  }

  /**
   * Fetch a single encrypted share chunk, transparently refreshing the
   * short-lived download ticket if the server returns 403 mid-download. The
   * retry helper does not retry 403 by design (it is not a transient error in
   * general), so we intercept it here specifically for ticket expiry.
   */
  private async fetchShareChunkWithTicketRefresh(
    shareId: string,
    chunkIndex: number,
    totalChunks: number,
  ): Promise<Uint8Array> {
    const url = `${this.baseUrl}/api/public/shares/${shareId}/chunks/${chunkIndex}`;
    const doFetch = async (): Promise<Response> => {
      const headers: Record<string, string> = {};
      await this.applyShareAuthHeader(headers);
      return fetch(url, { headers });
    };

    let response = await doFetch();
    if (response.status === 403 && this.options.shareTicket) {
      debugLog(`${LOG_PREFIX_SHARE} Chunk ${chunkIndex} got 403; refreshing share ticket and retrying once.`);
      await this.options.shareTicket.refresh();
      response = await doFetch();
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText} fetching chunk ${chunkIndex + 1}/${totalChunks}`);
    }
    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  }

  private calculateTotalEncryptedSize(metadata: ChunkedDownloadMetadata): number {
    // size_bytes is already the encrypted-stream length (pre-padding).
    return metadata.size_bytes;
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

}

/** Convenience function to download a file with chunked download (owner) */
export async function downloadFileChunked(
  fileId: string,
  fek: Uint8Array,
  authToken: string | null,
  options: Partial<StreamingDownloadOptions> = {},
): Promise<StreamingDownloadResult> {
  const managerOpts: Partial<StreamingDownloadOptions> = { ...options };
  if (authToken) managerOpts.authToken = authToken;
  const manager = new StreamingDownloadManager('', managerOpts);
  return manager.downloadFile(fileId, fek);
}

/**
 * Download a shared file using a short-lived download ticket only.
 * The holder issues and refreshes the ticket; the manager sends X-Share-Ticket
 * per chunk and refreshes on 403. Never sends a static X-Download-Token.
 */
export async function downloadSharedFileWithTicket(
  shareId: string,
  fek: Uint8Array,
  shareTicket: { get: () => Promise<string>; refresh: () => Promise<string> },
  shareMetadata?: { filename?: string | undefined; sha256?: string | undefined },
  options: Partial<StreamingDownloadOptions> = {},
): Promise<StreamingDownloadResult> {
  const manager = new StreamingDownloadManager('', { shareTicket, ...options });
  return manager.downloadSharedFile(shareId, fek, shareMetadata);
}

/**
 * Trigger a browser download from a Blob URL produced by the streaming manager.
 * Used only on the Blob fallback path (when SW is unavailable or pre-transfer
 * init failed). Callers MUST check hashVerification first; on mismatch revoke
 * the URL without calling this function.
 * Creates an <a download> anchor, clicks it, then revokes the URL after a delay.
 */
export function triggerBrowserDownloadFromUrl(blobUrl: string, filename: string): void {
  debugLog(`[arkfile-download] Triggering browser download anchor from blob URL (filename_len=${filename.length})`);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    if (a.parentNode) document.body.removeChild(a);
    URL.revokeObjectURL(blobUrl);
    debugLog('[arkfile-download] Blob URL revoked');
  }, 1000);
}

/**
 * True when an SW failure is known to have happened before any generator output
 * was consumed, so Blob fallback with the same generator is safe.
 *
 * Ack timeout is excluded: the ReadableStream may already have been transferred
 * to the Service Worker, so reusing the generator can yield a truncated file.
 * Mid-stream decrypt/transport errors are also excluded.
 */
export function isSafeSwToBlobFallback(err: unknown): boolean {
  const errName = String((err as { name?: string } | null)?.name || '');
  const errMsg = String((err as { message?: string } | null)?.message || '');

  if (/ack timeout/i.test(errMsg)) {
    return false;
  }
  // Partial-download messaging from mid-stream failures must not fall back.
  if (/partial file may already/i.test(errMsg)) {
    return false;
  }

  return (
    errName === 'DataCloneError' ||
    /clone/i.test(errMsg) ||
    /duplicate/i.test(errMsg) ||
    /cannot be transferred/i.test(errMsg) ||
    (/transfer/i.test(errMsg) && !/after/i.test(errMsg))
  );
}

function describeErr(err: unknown): string {
  const name = String((err as { name?: string } | null)?.name || '');
  const msg = String((err as { message?: string } | null)?.message || err);
  return name ? `${name} - ${msg}` : msg;
}

/** Compute a short non-cryptographic hash of an ID for log correlation (no PII) */
function shortHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, '0').slice(0, 8);
}

/** Lowercase hex encoding of a byte array. */
function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Constant-time hex string comparison (mirrors sw-streaming-download). Both
 * inputs are lowercased; unequal lengths are immediately not-equal but still
 * fully scanned to avoid timing leaks.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  const aLow = a.toLowerCase();
  const bLow = b.toLowerCase();
  const len = Math.max(aLow.length, bLow.length);
  let diff = aLow.length ^ bLow.length;
  for (let i = 0; i < len; i++) {
    const ac = i < aLow.length ? aLow.charCodeAt(i) : 0;
    const bc = i < bLow.length ? bLow.charCodeAt(i) : 0;
    diff |= ac ^ bc;
  }
  return diff === 0;
}
