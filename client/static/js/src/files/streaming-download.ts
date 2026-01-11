/**
 * Streaming Download Manager for Chunked File Downloads
 * 
 * Handles downloading files in chunks with:
 * - Progress tracking
 * - Retry logic with exponential backoff
 * - Resume capability
 * - Client-side decryption
 */

import { AESGCMDecryptor } from '../crypto/aes-gcm';
import { AES_GCM_OVERHEAD, DEFAULT_CHUNK_SIZE_BYTES } from '../crypto/constants';
import { downloadChunkWithRetry, RetryConfig } from './retry-handler';
import { showProgress, updateProgress, hideProgress } from '../ui/progress';

/**
 * Metadata returned from the download metadata endpoint
 */
export interface ChunkedDownloadMetadata {
  fileId: string;
  storageId: string;
  encryptedFilename: string;
  filenameNonce: string;
  encryptedSha256sum: string;
  sha256sumNonce: string;
  sizeBytes: number;
  totalChunks: number;
  chunkSizeBytes: number;
  contentType: string;
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
 * Result of a streaming download
 */
export interface StreamingDownloadResult {
  success: boolean;
  data?: Uint8Array;
  filename?: string;
  sha256sum?: string;
  error?: string;
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

  constructor(baseUrl: string = '', options: StreamingDownloadOptions = {}) {
    this.baseUrl = baseUrl;
    this.options = {
      showProgressUI: true,
      ...options,
    };
  }

  /**
   * Download a file using chunked download with decryption
   * 
   * @param fileId - The file ID to download
   * @param fek - The File Encryption Key (32 bytes)
   * @returns Promise resolving to the download result
   */
  async downloadFile(fileId: string, fek: Uint8Array): Promise<StreamingDownloadResult> {
    try {
      // Show progress UI if enabled
      if (this.options.showProgressUI) {
        showProgress({
          title: 'Downloading File',
          message: 'Fetching file metadata...',
          indeterminate: true,
        });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      // 1. Fetch download metadata
      const metadata = await this.fetchMetadata(fileId);
      
      // 2. Download and decrypt all chunks
      const decryptedData = await this.downloadAndDecryptChunks(
        fileId,
        metadata,
        fek
      );

      // 3. Decrypt filename and sha256sum using FEK
      const filename = await this.decryptMetadataField(
        metadata.encryptedFilename,
        metadata.filenameNonce,
        fek
      );
      
      const sha256sum = await this.decryptMetadataField(
        metadata.encryptedSha256sum,
        metadata.sha256sumNonce,
        fek
      );

      this.reportProgress('complete', metadata.totalChunks, metadata.totalChunks, metadata.sizeBytes, metadata.sizeBytes);

      if (this.options.showProgressUI) {
        hideProgress();
      }

      return {
        success: true,
        data: decryptedData,
        filename,
        sha256sum,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Download failed';
      
      this.reportProgress('error', 0, 0, 0, 0, errorMessage);
      
      if (this.options.showProgressUI) {
        updateProgress({ error: errorMessage });
        // Keep error visible for a moment
        setTimeout(() => hideProgress(), 3000);
      }

      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Download a shared file using chunked download with decryption
   * 
   * @param shareId - The share ID
   * @param fek - The File Encryption Key (32 bytes)
   * @returns Promise resolving to the download result
   */
  async downloadSharedFile(shareId: string, fek: Uint8Array): Promise<StreamingDownloadResult> {
    try {
      if (this.options.showProgressUI) {
        showProgress({
          title: 'Downloading Shared File',
          message: 'Fetching file metadata...',
          indeterminate: true,
        });
      }

      this.reportProgress('metadata', 0, 0, 0, 0);

      // 1. Fetch share download metadata
      const metadata = await this.fetchShareMetadata(shareId);
      
      // 2. Download and decrypt all chunks
      const decryptedData = await this.downloadAndDecryptShareChunks(
        shareId,
        metadata,
        fek
      );

      // 3. Decrypt filename and sha256sum using FEK
      const filename = await this.decryptMetadataField(
        metadata.encryptedFilename,
        metadata.filenameNonce,
        fek
      );
      
      const sha256sum = await this.decryptMetadataField(
        metadata.encryptedSha256sum,
        metadata.sha256sumNonce,
        fek
      );

      this.reportProgress('complete', metadata.totalChunks, metadata.totalChunks, metadata.sizeBytes, metadata.sizeBytes);

      if (this.options.showProgressUI) {
        hideProgress();
      }

      return {
        success: true,
        data: decryptedData,
        filename,
        sha256sum,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Download failed';
      
      this.reportProgress('error', 0, 0, 0, 0, errorMessage);
      
      if (this.options.showProgressUI) {
        updateProgress({ error: errorMessage });
        setTimeout(() => hideProgress(), 3000);
      }

      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Fetch download metadata for a file
   */
  private async fetchMetadata(fileId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (this.options.authToken) {
      headers['Authorization'] = `Bearer ${this.options.authToken}`;
    }

    const response = await fetch(`${this.baseUrl}/api/files/${fileId}/metadata`, {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch metadata: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Fetch download metadata for a shared file
   */
  private async fetchShareMetadata(shareId: string): Promise<ChunkedDownloadMetadata> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    if (this.options.downloadToken) {
      headers['X-Download-Token'] = this.options.downloadToken;
    }

    const response = await fetch(`${this.baseUrl}/api/shares/${shareId}/metadata`, {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch share metadata: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Download and decrypt all chunks for a file
   */
  private async downloadAndDecryptChunks(
    fileId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array
  ): Promise<Uint8Array> {
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);
    const decryptedChunks: Uint8Array[] = [];
    
    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const headers: Record<string, string> = {};
    if (this.options.authToken) {
      headers['Authorization'] = `Bearer ${this.options.authToken}`;
    }

    for (let chunkIndex = 0; chunkIndex < metadata.totalChunks; chunkIndex++) {
      // Check for cancellation
      if (this.options.abortController?.signal.aborted) {
        throw new Error('Download cancelled');
      }

      // Download chunk with retry
      const encryptedChunk = await downloadChunkWithRetry(
        `${this.baseUrl}/api/files/${fileId}/chunks/${chunkIndex}`,
        headers,
        this.options.retryConfig,
        (attempt, error, delay) => {
          console.log(`Chunk ${chunkIndex}: Retry ${attempt} after ${delay}ms - ${error.message}`);
        }
      );

      // Decrypt chunk
      const decryptedChunk = await decryptor.decryptChunk(encryptedChunk);
      decryptedChunks.push(decryptedChunk);

      // Update progress
      this.bytesDownloaded += encryptedChunk.length;
      this.reportProgress(
        'downloading',
        chunkIndex + 1,
        metadata.totalChunks,
        this.bytesDownloaded,
        this.calculateTotalEncryptedSize(metadata)
      );

      // Update UI
      if (this.options.showProgressUI) {
        const percentage = ((chunkIndex + 1) / metadata.totalChunks) * 100;
        const speed = this.calculateSpeed();
        const remaining = this.calculateRemainingTime(metadata.totalChunks - chunkIndex - 1, speed, metadata.chunkSizeBytes);
        
        updateProgress({
          title: 'Downloading File',
          message: `Chunk ${chunkIndex + 1} of ${metadata.totalChunks}`,
          percentage,
          speed,
          remainingTime: remaining,
        });
      }
    }

    // Combine all decrypted chunks
    return this.combineChunks(decryptedChunks);
  }

  /**
   * Download and decrypt all chunks for a shared file
   */
  private async downloadAndDecryptShareChunks(
    shareId: string,
    metadata: ChunkedDownloadMetadata,
    fek: Uint8Array
  ): Promise<Uint8Array> {
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);
    const decryptedChunks: Uint8Array[] = [];
    
    this.startTime = Date.now();
    this.bytesDownloaded = 0;

    const headers: Record<string, string> = {};
    if (this.options.downloadToken) {
      headers['X-Download-Token'] = this.options.downloadToken;
    }

    for (let chunkIndex = 0; chunkIndex < metadata.totalChunks; chunkIndex++) {
      // Check for cancellation
      if (this.options.abortController?.signal.aborted) {
        throw new Error('Download cancelled');
      }

      // Download chunk with retry
      const encryptedChunk = await downloadChunkWithRetry(
        `${this.baseUrl}/api/shares/${shareId}/chunks/${chunkIndex}`,
        headers,
        this.options.retryConfig,
        (attempt, error, delay) => {
          console.log(`Share chunk ${chunkIndex}: Retry ${attempt} after ${delay}ms - ${error.message}`);
        }
      );

      // Decrypt chunk
      const decryptedChunk = await decryptor.decryptChunk(encryptedChunk);
      decryptedChunks.push(decryptedChunk);

      // Update progress
      this.bytesDownloaded += encryptedChunk.length;
      this.reportProgress(
        'downloading',
        chunkIndex + 1,
        metadata.totalChunks,
        this.bytesDownloaded,
        this.calculateTotalEncryptedSize(metadata)
      );

      // Update UI
      if (this.options.showProgressUI) {
        const percentage = ((chunkIndex + 1) / metadata.totalChunks) * 100;
        const speed = this.calculateSpeed();
        const remaining = this.calculateRemainingTime(metadata.totalChunks - chunkIndex - 1, speed, metadata.chunkSizeBytes);
        
        updateProgress({
          title: 'Downloading Shared File',
          message: `Chunk ${chunkIndex + 1} of ${metadata.totalChunks}`,
          percentage,
          speed,
          remainingTime: remaining,
        });
      }
    }

    // Combine all decrypted chunks
    return this.combineChunks(decryptedChunks);
  }

  /**
   * Decrypt a metadata field (filename or sha256sum)
   */
  private async decryptMetadataField(
    encryptedBase64: string,
    nonceBase64: string,
    fek: Uint8Array
  ): Promise<string> {
    // Import from primitives for base64 decoding
    const encrypted = this.base64ToBytes(encryptedBase64);
    const nonce = this.base64ToBytes(nonceBase64);
    
    // Combine nonce + ciphertext for decryption
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce, 0);
    combined.set(encrypted, nonce.length);
    
    const decryptor = await AESGCMDecryptor.fromRawKey(fek);
    const decrypted = await decryptor.decryptChunk(combined);
    
    return new TextDecoder().decode(decrypted);
  }

  /**
   * Combine multiple chunks into a single Uint8Array
   */
  private combineChunks(chunks: Uint8Array[]): Uint8Array {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    
    return result;
  }

  /**
   * Calculate total encrypted size from metadata
   */
  private calculateTotalEncryptedSize(metadata: ChunkedDownloadMetadata): number {
    // Each chunk has AES-GCM overhead
    return metadata.sizeBytes + (metadata.totalChunks * AES_GCM_OVERHEAD);
  }

  /**
   * Calculate current download speed in bytes per second
   */
  private calculateSpeed(): number {
    const elapsedMs = Date.now() - this.startTime;
    if (elapsedMs === 0) return 0;
    return Math.round((this.bytesDownloaded / elapsedMs) * 1000);
  }

  /**
   * Calculate remaining time in seconds
   */
  private calculateRemainingTime(remainingChunks: number, speed: number, chunkSize: number): number {
    if (speed === 0) return 0;
    const remainingBytes = remainingChunks * (chunkSize + AES_GCM_OVERHEAD);
    return Math.round(remainingBytes / speed);
  }

  /**
   * Report progress to callback
   */
  private reportProgress(
    stage: 'metadata' | 'downloading' | 'decrypting' | 'complete' | 'error',
    currentChunk: number,
    totalChunks: number,
    bytesDownloaded: number,
    totalBytes: number,
    error?: string
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
          DEFAULT_CHUNK_SIZE_BYTES
        ) : undefined,
        error,
      });
    }
  }

  /**
   * Convert base64 string to Uint8Array
   */
  private base64ToBytes(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Convenience function to download a file with chunked download
 */
export async function downloadFileChunked(
  fileId: string,
  fek: Uint8Array,
  authToken: string,
  options: Partial<StreamingDownloadOptions> = {}
): Promise<StreamingDownloadResult> {
  const manager = new StreamingDownloadManager('', {
    authToken,
    ...options,
  });
  return manager.downloadFile(fileId, fek);
}

/**
 * Convenience function to download a shared file with chunked download
 */
export async function downloadSharedFileChunked(
  shareId: string,
  fek: Uint8Array,
  downloadToken: string,
  options: Partial<StreamingDownloadOptions> = {}
): Promise<StreamingDownloadResult> {
  const manager = new StreamingDownloadManager('', {
    downloadToken,
    ...options,
  });
  return manager.downloadSharedFile(shareId, fek);
}

/**
 * Trigger browser download of decrypted data
 */
export function triggerBrowserDownload(data: Uint8Array, filename: string, contentType: string = 'application/octet-stream'): void {
  // Create a copy to ensure proper ArrayBuffer type
  const dataCopy = new Uint8Array(data);
  const blob = new Blob([dataCopy.buffer], { type: contentType });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  
  // Cleanup
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
