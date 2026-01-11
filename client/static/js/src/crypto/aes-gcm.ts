/**
 * AES-GCM Decryption Module for Chunked Downloads
 * 
 * Provides streaming decryption of AES-256-GCM encrypted chunks using the Web Crypto API.
 * Each chunk is independently encrypted with its own nonce, allowing for parallel
 * decryption and resume capability.
 * 
 * Chunk format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
 */

import { AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, AES_GCM_OVERHEAD } from './constants';

/**
 * AES-GCM Decryptor for streaming chunk decryption
 * 
 * Uses Web Crypto API for hardware-accelerated decryption where available.
 * Each chunk is self-contained with its own nonce and authentication tag.
 */
export class AESGCMDecryptor {
  private key: CryptoKey;

  private constructor(key: CryptoKey) {
    this.key = key;
  }

  /**
   * Create a decryptor from a raw 256-bit key
   * 
   * @param keyBytes - 32-byte AES-256 key
   * @returns Promise resolving to an AESGCMDecryptor instance
   * @throws Error if key length is invalid
   */
  static async fromRawKey(keyBytes: Uint8Array): Promise<AESGCMDecryptor> {
    if (keyBytes.length !== 32) {
      throw new Error(`Invalid key length: expected 32 bytes, got ${keyBytes.length}`);
    }

    // Create a new Uint8Array copy to ensure we have a proper ArrayBuffer
    const keyCopy = new Uint8Array(keyBytes);
    
    const key = await crypto.subtle.importKey(
      'raw',
      keyCopy,
      { name: 'AES-GCM', length: 256 },
      false, // not extractable
      ['decrypt']
    );

    return new AESGCMDecryptor(key);
  }

  /**
   * Decrypt a single encrypted chunk
   * 
   * Input format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
   * The Web Crypto API expects the tag to be appended to the ciphertext.
   * 
   * @param encryptedChunk - The encrypted chunk data
   * @returns Promise resolving to the decrypted plaintext
   * @throws Error if chunk is too small or decryption fails
   */
  async decryptChunk(encryptedChunk: Uint8Array): Promise<Uint8Array> {
    if (encryptedChunk.length < AES_GCM_OVERHEAD) {
      throw new Error(`Encrypted chunk too small: expected at least ${AES_GCM_OVERHEAD} bytes, got ${encryptedChunk.length}`);
    }

    // Extract nonce (first 12 bytes)
    const nonce = encryptedChunk.slice(0, AES_GCM_NONCE_SIZE);
    
    // Extract ciphertext + tag (remaining bytes)
    // Web Crypto expects ciphertext with tag appended
    const ciphertextWithTag = encryptedChunk.slice(AES_GCM_NONCE_SIZE);

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          tagLength: AES_GCM_TAG_SIZE * 8, // in bits
        },
        this.key,
        ciphertextWithTag
      );

      return new Uint8Array(decrypted);
    } catch (error) {
      throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decrypt multiple chunks in sequence
   * 
   * @param chunks - Array of encrypted chunks
   * @param onProgress - Optional callback for progress updates
   * @returns Promise resolving to array of decrypted chunks
   */
  async decryptChunks(
    chunks: Uint8Array[],
    onProgress?: (completed: number, total: number) => void
  ): Promise<Uint8Array[]> {
    const decryptedChunks: Uint8Array[] = [];
    
    for (let i = 0; i < chunks.length; i++) {
      const decrypted = await this.decryptChunk(chunks[i]);
      decryptedChunks.push(decrypted);
      
      if (onProgress) {
        onProgress(i + 1, chunks.length);
      }
    }
    
    return decryptedChunks;
  }
}

/**
 * Decrypt a single chunk using a raw key (convenience function)
 * 
 * @param encryptedChunk - The encrypted chunk data
 * @param key - 32-byte AES-256 key
 * @returns Promise resolving to the decrypted plaintext
 */
export async function decryptChunk(encryptedChunk: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const decryptor = await AESGCMDecryptor.fromRawKey(key);
  return decryptor.decryptChunk(encryptedChunk);
}

/**
 * Verify that a chunk can be decrypted (authentication check)
 * 
 * @param encryptedChunk - The encrypted chunk data
 * @param key - 32-byte AES-256 key
 * @returns Promise resolving to true if chunk is valid, false otherwise
 */
export async function verifyChunk(encryptedChunk: Uint8Array, key: Uint8Array): Promise<boolean> {
  try {
    await decryptChunk(encryptedChunk, key);
    return true;
  } catch {
    return false;
  }
}
