/**
 * WASM initialization and management utilities
 * Types are available globally via wasm.d.ts declarations
 */

export class WASMManager {
  private static instance: WASMManager;
  private wasmReady: boolean = false;
  private initPromise: Promise<void> | null = null;

  private constructor() {}

  public static getInstance(): WASMManager {
    if (!WASMManager.instance) {
      WASMManager.instance = new WASMManager();
    }
    return WASMManager.instance;
  }

  public async initWasm(): Promise<void> {
    if (this.wasmReady) {
      return Promise.resolve();
    }

    if (this.initPromise) {
      return this.initPromise;
    }

    this.initPromise = this.performWasmInit();
    return this.initPromise;
  }

  private async performWasmInit(): Promise<void> {
    try {
      // @ts-ignore - Go WASM runtime is loaded via script tag
      const go = new Go();
      const result = await WebAssembly.instantiateStreaming(
        fetch("/main.wasm"),
        go.importObject
      );
      go.run(result.instance);
      this.wasmReady = true;
      console.log('WASM initialized successfully');
    } catch (err) {
      console.error('Failed to load WASM:', err);
      throw new Error(`WASM initialization failed: ${err}`);
    }
  }

  public isReady(): boolean {
    return this.wasmReady;
  }

  public async ensureReady(): Promise<void> {
    if (!this.wasmReady) {
      await this.initWasm();
    }
  }

  // Wrapper functions for WASM functions with error handling
  public async validatePasswordComplexity(password: string): Promise<PasswordValidationResult> {
    await this.ensureReady();
    try {
      return (window as any).validatePasswordComplexity(password);
    } catch (error) {
      console.error('WASM password validation error:', error);
      return {
        valid: false,
        score: 0,
        message: 'Password validation failed. Please try again.',
        requirements: [],
        missing: ['Password validation service unavailable']
      };
    }
  }

  public async validatePasswordConfirmation(password: string, confirm: string): Promise<PasswordConfirmationResult> {
    await this.ensureReady();
    try {
      return (window as any).validatePasswordConfirmation(password, confirm);
    } catch (error) {
      console.error('WASM password confirmation error:', error);
      return {
        match: false,
        message: 'Password confirmation failed. Please try again.',
        status: 'error'
      };
    }
  }

  // Removed deprecated OPAQUE export-based methods
  // Now using HTTP-based OPAQUE authentication methods below

  public async validateSecureSession(userEmail: string): Promise<SessionValidationResult> {
    await this.ensureReady();
    try {
      return (window as any).validateSecureSession(userEmail);
    } catch (error) {
      console.error('WASM session validation error:', error);
      return {
        valid: false,
        error: `Session validation failed: ${error}`
      };
    }
  }

  public async encryptFileWithSecureSession(fileData: Uint8Array, userEmail: string): Promise<FileEncryptionResult> {
    await this.ensureReady();
    try {
      return (window as any).encryptFileWithSecureSession(fileData, userEmail);
    } catch (error) {
      console.error('WASM file encryption error:', error);
      return {
        success: false,
        error: `File encryption failed: ${error}`
      };
    }
  }

  public async decryptFileWithSecureSession(encryptedData: string, userEmail: string): Promise<FileDecryptionResult> {
    await this.ensureReady();
    try {
      return (window as any).decryptFileWithSecureSession(encryptedData, userEmail);
    } catch (error) {
      console.error('WASM file decryption error:', error);
      return {
        success: false,
        error: `File decryption failed: ${error}`
      };
    }
  }

  public async encryptFile(fileData: Uint8Array, password: string): Promise<string> {
    await this.ensureReady();
    try {
      return (window as any).encryptFile(fileData, password);
    } catch (error) {
      console.error('WASM file encryption error:', error);
      throw new Error(`File encryption failed: ${error}`);
    }
  }

  public async decryptFile(encryptedData: string, password: string): Promise<string | Uint8Array> {
    await this.ensureReady();
    try {
      return (window as any).decryptFile(encryptedData, password);
    } catch (error) {
      console.error('WASM file decryption error:', error);
      return 'Failed to decrypt data';
    }
  }

  public async calculateSHA256(fileData: Uint8Array): Promise<string> {
    await this.ensureReady();
    try {
      return (window as any).calculateSHA256(fileData);
    } catch (error) {
      console.error('WASM SHA256 calculation error:', error);
      throw new Error(`SHA256 calculation failed: ${error}`);
    }
  }

  public async validateTOTPCode(code: string, userEmail: string): Promise<TOTPValidationResult> {
    await this.ensureReady();
    try {
      return (window as any).validateTOTPCodeWASM(code, userEmail);
    } catch (error) {
      console.error('WASM TOTP validation error:', error);
      return {
        valid: false,
        error: `TOTP validation failed: ${error}`
      };
    }
  }

  public async generateTOTPSetupData(userEmail: string): Promise<TOTPSetupResult> {
    await this.ensureReady();
    try {
      return (window as any).generateTOTPSetupDataWASM(userEmail);
    } catch (error) {
      console.error('WASM TOTP setup generation error:', error);
      return {
        success: false,
        error: `TOTP setup generation failed: ${error}`
      };
    }
  }

  public async verifyTOTPSetup(code: string, secret: string, userEmail: string): Promise<TOTPValidationResult> {
    await this.ensureReady();
    try {
      return (window as any).verifyTOTPSetupWASM(code, secret, userEmail);
    } catch (error) {
      console.error('WASM TOTP setup verification error:', error);
      return {
        valid: false,
        error: `TOTP setup verification failed: ${error}`
      };
    }
  }

  public async checkOpaqueHealth(): Promise<{ wasmReady: boolean; timestamp: number; opaqueReady: boolean }> {
    await this.ensureReady();
    try {
      return (window as any).opaqueHealthCheck();
    } catch (error) {
      console.error('WASM OPAQUE health check error:', error);
      return {
        wasmReady: false,
        timestamp: Date.now(),
        opaqueReady: false
      };
    }
  }

  // HTTP-based OPAQUE authentication methods
  public async performOpaqueLogin(username: string, password: string): Promise<{ success: boolean; promise?: Promise<Response>; error?: string; message?: string }> {
    await this.ensureReady();
    try {
      return (window as any).performOpaqueLogin(username, password);
    } catch (error) {
      console.error('WASM OPAQUE login error:', error);
      return {
        success: false,
        error: `OPAQUE login failed: ${error}`
      };
    }
  }

  public async performOpaqueRegister(username: string, password: string, email?: string): Promise<{ success: boolean; promise?: Promise<Response>; error?: string; message?: string }> {
    await this.ensureReady();
    try {
      return (window as any).performOpaqueRegister(username, password, email);
    } catch (error) {
      console.error('WASM OPAQUE registration error:', error);
      return {
        success: false,
        error: `OPAQUE registration failed: ${error}`
      };
    }
  }

  public async createSecureSessionFromKey(sessionKey: string, username: string): Promise<{ success: boolean; message?: string; error?: string }> {
    await this.ensureReady();
    try {
      return (window as any).createSecureSession(sessionKey, username);
    } catch (error) {
      console.error('WASM secure session creation error:', error);
      return {
        success: false,
        error: `Secure session creation failed: ${error}`
      };
    }
  }

  public async clearSecureSessionForUser(username: string): Promise<{ success: boolean; message?: string; error?: string }> {
    await this.ensureReady();
    try {
      return (window as any).clearSecureSession(username);
    } catch (error) {
      console.error('WASM secure session clearing error:', error);
      return {
        success: false,
        error: `Secure session clearing failed: ${error}`
      };
    }
  }
}

// Export singleton instance
export const wasmManager = WASMManager.getInstance();
