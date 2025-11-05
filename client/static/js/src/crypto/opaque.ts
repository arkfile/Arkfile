/**
 * OPAQUE Protocol Implementation using libopaque.js WASM
 * 
 * This module provides a clean TypeScript wrapper around the libopaque.js WASM library.
 * It implements the OPAQUE asymmetric password-authenticated key exchange protocol.
 * 
 * Key Features:
 * - Zero-knowledge password authentication
 * - Multi-step registration and login flows
 * - Export key derivation for session management
 * - Compatible with libopaque C library on server side
 * 
 * IMPORTANT: This is ONLY for authentication. File encryption uses separate Argon2id system.
 */

import { CryptoError, OpaqueRegistrationError, OpaqueAuthenticationError } from './errors.js';

// Type definitions for libopaque.js module
interface LibOpaqueModule {
  ready: Promise<void>;
  
  // Configuration constants
  NotPackaged: number;
  InSecEnv: number;
  
  // Utility functions
  hexToUint8Array(hex: string): Uint8Array;
  uint8ArrayToHex(arr: Uint8Array): string;
  
  // Registration flow
  createRegistrationRequest(params: { pwdU: string }): {
    M: Uint8Array;
    sec: Uint8Array;
  };
  
  finalizeRequest(params: {
    sec: Uint8Array;
    pub: Uint8Array;
    cfg: OpaqueConfig;
    ids: { idS: string; idU: string };
  }): {
    rec: Uint8Array;
    export_key: Uint8Array;
  };
  
  // Authentication flow
  createCredentialRequest(params: { pwdU: string }): {
    pub: Uint8Array;
    sec: Uint8Array;
  };
  
  recoverCredentials(params: {
    resp: Uint8Array;
    sec: Uint8Array;
    pkS: Uint8Array | null;
    cfg: OpaqueConfig;
    infos: OpaqueInfos;
    ids: { idS: string; idU: string };
  }): {
    authU: Uint8Array;
    export_key: Uint8Array;
    sk: Uint8Array;
  };
}

interface OpaqueConfig {
  skU: number;
  pkU: number;
  pkS: number;
  idS: number;
  idU: number;
}

interface OpaqueInfos {
  info: Uint8Array | null;
  einfo: Uint8Array | null;
}

// Registration flow types
export interface RegistrationInitRequest {
  username: string;
  password: string;
}

export interface RegistrationInitResponse {
  requestData: string; // hex-encoded M
  clientSecret: string; // hex-encoded sec (stored in sessionStorage)
}

export interface RegistrationFinalizeRequest {
  username: string;
  serverResponse: string; // hex-encoded pub from server
  clientSecret: string; // hex-encoded sec from sessionStorage
}

export interface RegistrationFinalizeResponse {
  record: string; // hex-encoded rec to send to server
  exportKey: Uint8Array; // for session key derivation
}

// Authentication flow types
export interface LoginInitRequest {
  username: string;
  password: string;
}

export interface LoginInitResponse {
  requestData: string; // hex-encoded pub
  clientSecret: string; // hex-encoded sec (stored in sessionStorage)
}

export interface LoginFinalizeRequest {
  username: string;
  serverResponse: string; // hex-encoded resp from server
  serverPublicKey: string | null; // hex-encoded pkS (if NotPackaged)
  clientSecret: string; // hex-encoded sec from sessionStorage
}

export interface LoginFinalizeResponse {
  authData: string; // hex-encoded authU to send to server
  exportKey: Uint8Array; // for session key derivation
  sessionKey: Uint8Array; // derived from export_key
}

/**
 * OPAQUE Client
 * 
 * Provides high-level API for OPAQUE protocol operations.
 */
export class OpaqueClient {
  private module: LibOpaqueModule | null = null;
  private config: OpaqueConfig;
  private infos: OpaqueInfos;
  private readonly serverId = 'server';
  
  constructor() {
    // Configuration matching server setup
    this.config = {
      skU: 0, // Will be set to NotPackaged after module loads
      pkU: 0, // Will be set to NotPackaged after module loads
      pkS: 1, // Will be set to InSecEnv after module loads
      idS: 0, // Will be set to NotPackaged after module loads
      idU: 0, // Will be set to NotPackaged after module loads
    };
    
    this.infos = {
      info: null,
      einfo: null,
    };
  }
  
  /**
   * Initialize the OPAQUE module
   * Must be called before any other operations
   */
  async initialize(): Promise<void> {
    try {
      // Load libopaque.js module
      // @ts-ignore - libopaque is loaded as a global script
      if (typeof libopaque === 'undefined') {
        throw new CryptoError(
          'libopaque.js not loaded. Include <script src="/js/libopaque.js"></script> in HTML.',
          'INITIALIZATION_FAILED'
        );
      }
      
      // @ts-ignore
      this.module = libopaque;
      
      if (this.module && this.module.ready) {
        await this.module.ready;
      }
      
      // Set config values using module constants
      if (this.module) {
        this.config.skU = this.module.NotPackaged;
        this.config.pkU = this.module.NotPackaged;
        this.config.pkS = this.module.InSecEnv;
        this.config.idS = this.module.NotPackaged;
        this.config.idU = this.module.NotPackaged;
      }
      
    } catch (error) {
      throw new CryptoError(
        `Failed to initialize OPAQUE: ${error instanceof Error ? error.message : String(error)}`,
        'INITIALIZATION_FAILED'
      );
    }
  }
  
  /**
   * Start registration flow (step 1)
   * Client creates registration request
   */
  async startRegistration(params: RegistrationInitRequest): Promise<RegistrationInitResponse> {
    if (!this.module) {
      throw new CryptoError('OPAQUE module not initialized', 'INITIALIZATION_FAILED');
    }
    
    try {
      const { username, password } = params;
      
      // Create registration request
      const request = this.module.createRegistrationRequest({ pwdU: password });
      
      // Convert to hex for transmission and storage
      const requestData = this.module.uint8ArrayToHex(request.M);
      const clientSecret = this.module.uint8ArrayToHex(request.sec);
      
      return {
        requestData,
        clientSecret,
      };
    } catch (error) {
      throw new OpaqueRegistrationError(
        `Registration init failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  
  /**
   * Finalize registration flow (step 2)
   * Client processes server response and creates user record
   */
  async finalizeRegistration(params: RegistrationFinalizeRequest): Promise<RegistrationFinalizeResponse> {
    if (!this.module) {
      throw new CryptoError('OPAQUE module not initialized', 'INITIALIZATION_FAILED');
    }
    
    try {
      const { username, serverResponse, clientSecret } = params;
      
      // Convert from hex
      const pub = this.module.hexToUint8Array(serverResponse);
      const sec = this.module.hexToUint8Array(clientSecret);
      
      // Finalize registration
      const result = this.module.finalizeRequest({
        sec,
        pub,
        cfg: this.config,
        ids: { idS: this.serverId, idU: username },
      });
      
      // Convert record to hex for transmission
      const record = this.module.uint8ArrayToHex(result.rec);
      
      return {
        record,
        exportKey: result.export_key,
      };
    } catch (error) {
      throw new OpaqueRegistrationError(
        `Registration finalize failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  
  /**
   * Start login flow (step 1)
   * Client creates credential request
   */
  async startLogin(params: LoginInitRequest): Promise<LoginInitResponse> {
    if (!this.module) {
      throw new CryptoError('OPAQUE module not initialized', 'INITIALIZATION_FAILED');
    }
    
    try {
      const { username, password } = params;
      
      // Create credential request
      const request = this.module.createCredentialRequest({ pwdU: password });
      
      // Convert to hex for transmission and storage
      const requestData = this.module.uint8ArrayToHex(request.pub);
      const clientSecret = this.module.uint8ArrayToHex(request.sec);
      
      return {
        requestData,
        clientSecret,
      };
    } catch (error) {
      throw new OpaqueAuthenticationError(
        `Login init failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  
  /**
   * Finalize login flow (step 2)
   * Client recovers credentials and creates auth token
   */
  async finalizeLogin(params: LoginFinalizeRequest): Promise<LoginFinalizeResponse> {
    if (!this.module) {
      throw new CryptoError('OPAQUE module not initialized', 'INITIALIZATION_FAILED');
    }
    
    try {
      const { username, serverResponse, serverPublicKey, clientSecret } = params;
      
      // Convert from hex
      const resp = this.module.hexToUint8Array(serverResponse);
      const sec = this.module.hexToUint8Array(clientSecret);
      const pkS = serverPublicKey ? this.module.hexToUint8Array(serverPublicKey) : null;
      
      // Recover credentials
      const credentials = this.module.recoverCredentials({
        resp,
        sec,
        pkS,
        cfg: this.config,
        infos: this.infos,
        ids: { idS: this.serverId, idU: username },
      });
      
      // Convert authU to hex for transmission
      const authData = this.module.uint8ArrayToHex(credentials.authU);
      
      // Derive session key from export key (simple hash for now)
      const sessionKey = await this.deriveSessionKey(credentials.export_key);
      
      return {
        authData,
        exportKey: credentials.export_key,
        sessionKey,
      };
    } catch (error) {
      throw new OpaqueAuthenticationError(
        `Login finalize failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
  
  /**
   * Derive session key from OPAQUE export key
   * Uses SHA-256 hash of export key
   */
  private async deriveSessionKey(exportKey: Uint8Array): Promise<Uint8Array> {
    try {
      // Create a proper ArrayBuffer copy to avoid SharedArrayBuffer issues
      const buffer = exportKey.buffer.slice(exportKey.byteOffset, exportKey.byteOffset + exportKey.byteLength) as ArrayBuffer;
      const hash = await crypto.subtle.digest('SHA-256', buffer);
      return new Uint8Array(hash);
    } catch (error) {
      throw new CryptoError(
        `Session key derivation failed: ${error instanceof Error ? error.message : String(error)}`,
        'KEY_DERIVATION_FAILED'
      );
    }
  }
}

// Singleton instance
let opaqueClient: OpaqueClient | null = null;

/**
 * Get or create OPAQUE client instance
 */
export async function getOpaqueClient(): Promise<OpaqueClient> {
  if (!opaqueClient) {
    opaqueClient = new OpaqueClient();
    await opaqueClient.initialize();
  }
  return opaqueClient;
}

/**
 * Helper function to store client secret in sessionStorage
 */
export function storeClientSecret(key: string, secret: string): void {
  try {
    sessionStorage.setItem(`opaque_${key}`, secret);
  } catch (error) {
    throw new CryptoError(
      'Failed to store client secret',
      'STORAGE_ERROR'
    );
  }
}

/**
 * Helper function to retrieve client secret from sessionStorage
 */
export function retrieveClientSecret(key: string): string | null {
  try {
    return sessionStorage.getItem(`opaque_${key}`);
  } catch (error) {
    throw new CryptoError(
      'Failed to retrieve client secret',
      'STORAGE_ERROR'
    );
  }
}

/**
 * Helper function to clear client secret from sessionStorage
 */
export function clearClientSecret(key: string): void {
  try {
    sessionStorage.removeItem(`opaque_${key}`);
  } catch (error) {
    // Non-critical error, just log it
    console.warn('Failed to clear client secret:', error);
  }
}
