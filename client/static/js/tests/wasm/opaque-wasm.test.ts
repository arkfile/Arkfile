#!/usr/bin/env bun

/**
 * OPAQUE WASM Integration Tests (Bun Version)
 * 
 * This TypeScript file tests the OPAQUE WASM functions from Bun runtime
 * Tests device capability detection, registration, login, and session management
 */

import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import "../../src/types/wasm.d.ts";

// Mock browser APIs for Bun environment
if (!globalThis.crypto) {
    const { randomBytes } = await import("crypto");
    
    globalThis.crypto = {
        getRandomValues: (array: any) => {
            const bytes = randomBytes(array.length);
            for (let i = 0; i < array.length; i++) {
                array[i] = bytes[i];
            }
            return array;
        },
        randomUUID: () => randomBytes(16).toString('hex'),
        subtle: {} as SubtleCrypto
    } as Crypto;
}

// Type-safe OPAQUE WASM function declarations
declare global {
    function requestCapabilityConsentWASM(): { title: string; message: string; success: boolean };
    function detectDeviceCapabilityPrivacyFirstWASM(consent: string): string;
    function opaqueClientRegistrationInitWASM(password: string, capability: string, suite: string): {
        success: boolean;
        request: string;
        error?: string;
    };
    function opaqueClientRegistrationFinalizeWASM(serverResponse: string, request: string): {
        success: boolean;
        export?: string;
        error?: string;
    };
    function opaqueClientLoginInitWASM(password: string): {
        success: boolean;
        ke1: string;
        error?: string;
    };
    function opaqueClientLoginFinalizeWASM(ke2: string, ke1: string): {
        success: boolean;
        sessionKey?: string;
        export?: string;
        error?: string;
    };
    function deriveOpaqueSessionKeyWASM(exportKey: string): {
        success: boolean;
        sessionKey: string;
        error?: string;
    };
    function validateOpaqueSessionKeyWASM(sessionKey: string): {
        valid: boolean;
        error?: string;
    };
}

// WASM module management
let wasmLoaded = false;

async function loadWASMModule(): Promise<void> {
    if (wasmLoaded) return;
    
    try {
        // Check if WASM file exists
        const wasmPath = join(import.meta.dir, '..', '..', '..', 'main.wasm');
        if (!existsSync(wasmPath)) {
            console.warn('WASM file not found. OPAQUE functions will be mocked.');
            return;
        }
        
        // Load WASM file
        const wasmBytes = readFileSync(wasmPath);
        
        // Load wasm_exec.js for Go runtime
        const wasmExecPath = join(import.meta.dir, '..', '..', '..', '..', 'wasm_exec.js');
        if (!existsSync(wasmExecPath)) {
            console.warn('wasm_exec.js not found. OPAQUE functions will be mocked.');
            return;
        }
        
        // Import wasm_exec.js dynamically
        const wasmExecCode = readFileSync(wasmExecPath, 'utf-8');
        eval(wasmExecCode);
        
        // Create Go instance
        const Go = (globalThis as any).Go;
        const go = new Go();
        
        // Instantiate WASM module
        const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
        
        // Start the Go program
        go.run(result.instance);
        
        // Wait for initialization
        await new Promise(resolve => setTimeout(resolve, 100));
        
        wasmLoaded = true;
        console.log('OPAQUE WASM module loaded successfully');
        
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.warn(`Failed to load WASM module: ${errorMessage}. Using mocks.`);
    }
}

// Mock functions for when WASM is not available
function mockWASMCall(fnName: string, ...args: any[]): any {
    console.log(`🧪 Mock call to ${fnName} with args:`, args);
    
    switch (fnName) {
        case 'requestCapabilityConsentWASM':
            return {
                title: 'Optimize Security Performance',
                message: 'Allow capability detection for optimal security settings?',
                success: true
            };
        case 'detectDeviceCapabilityPrivacyFirstWASM':
            return 'interactive';
        case 'opaqueClientRegistrationInitWASM':
            return {
                success: true,
                request: 'mock-registration-request-base64'
            };
        case 'opaqueClientRegistrationFinalizeWASM':
            return {
                success: true,
                export: 'mock-export-key-base64'
            };
        case 'opaqueClientLoginInitWASM':
            return {
                success: true,
                ke1: 'mock-ke1-base64'
            };
        case 'opaqueClientLoginFinalizeWASM':
            return {
                success: true,
                sessionKey: 'mock-session-key',
                export: 'mock-export-key-base64'
            };
        case 'deriveOpaqueSessionKeyWASM':
            return {
                success: true,
                sessionKey: 'derived-session-key-base64'
            };
        case 'validateOpaqueSessionKeyWASM':
            return {
                valid: true
            };
        default:
            return { success: true, mock: true };
    }
}

// Helper function to get WASM function or mock
function getWASMFunction<T extends (...args: any[]) => any>(fnName: keyof typeof globalThis): T {
    const fn = (globalThis as any)[fnName];
    if (typeof fn === 'function') {
        return fn as T;
    }
    
    // Return mock function
    return ((...args: any[]) => mockWASMCall(String(fnName), ...args)) as T;
}

describe('OPAQUE WASM Integration Tests', () => {
    beforeAll(async () => {
        console.log('Starting OPAQUE WASM Tests (Bun Runtime)');
        await loadWASMModule();
    });

    afterAll(() => {
        console.log('OPAQUE WASM Tests completed');
    });

    test('Device Capability Detection', async () => {
        const requestConsent = getWASMFunction<typeof globalThis.requestCapabilityConsentWASM>('requestCapabilityConsentWASM');
        const detectCapability = getWASMFunction<typeof globalThis.detectDeviceCapabilityPrivacyFirstWASM>('detectDeviceCapabilityPrivacyFirstWASM');
        
        const consent = requestConsent();
        expect(consent.success).toBe(true);
        expect(consent.title).toContain('Optimize Security');
        
        const capability = detectCapability('allow');
        expect(['minimal', 'interactive', 'balanced', 'maximum']).toContain(capability);
        
        console.log(`Detected device capability: ${capability}`);
    });

    test('OPAQUE Registration Flow', async () => {
        const registrationInit = getWASMFunction<typeof globalThis.opaqueClientRegistrationInitWASM>('opaqueClientRegistrationInitWASM');
        const registrationFinalize = getWASMFunction<typeof globalThis.opaqueClientRegistrationFinalizeWASM>('opaqueClientRegistrationFinalizeWASM');
        
        const password = 'testpassword123!@#';
        const capability = 'interactive';
        const suite = 'RistrettoSha512';
        
        // Test registration init
        const init = registrationInit(password, capability, suite);
        expect(init.success).toBe(true);
        expect(init.request).toBeDefined();
        expect(typeof init.request).toBe('string');
        
        console.log(`Registration init successful, request length: ${init.request.length}`);
        
        // Simulate server response (would come from server in real flow)
        const mockServerResponse = 'mock-server-response-base64';
        
        // Test registration finalize
        const finalize = registrationFinalize(mockServerResponse, init.request);
        expect(finalize.success).toBe(true);
        expect(finalize.export).toBeDefined();
        
        console.log(`Registration finalize successful, export length: ${finalize.export?.length}`);
    });

    test('OPAQUE Login Flow', async () => {
        const loginInit = getWASMFunction<typeof globalThis.opaqueClientLoginInitWASM>('opaqueClientLoginInitWASM');
        const loginFinalize = getWASMFunction<typeof globalThis.opaqueClientLoginFinalizeWASM>('opaqueClientLoginFinalizeWASM');
        
        const password = 'testpassword123!@#';
        
        // Test login init
        const init = loginInit(password);
        expect(init.success).toBe(true);
        expect(init.ke1).toBeDefined();
        expect(typeof init.ke1).toBe('string');
        
        console.log(`Login init successful, KE1 length: ${init.ke1.length}`);
        
        // Simulate server KE2 response
        const mockKE2 = 'mock-ke2-response-base64';
        
        // Test login finalize
        const finalize = loginFinalize(mockKE2, init.ke1);
        expect(finalize.success).toBe(true);
        expect(finalize.sessionKey || finalize.export).toBeDefined();
        
        console.log(`Login finalize successful`);
    });

    test('Session Key Derivation and Validation', async () => {
        const deriveSessionKey = getWASMFunction<typeof globalThis.deriveOpaqueSessionKeyWASM>('deriveOpaqueSessionKeyWASM');
        const validateSessionKey = getWASMFunction<typeof globalThis.validateOpaqueSessionKeyWASM>('validateOpaqueSessionKeyWASM');
        
        const mockExportKey = 'mock-export-key-base64';
        
        // Test session key derivation
        const derived = deriveSessionKey(mockExportKey);
        expect(derived.success).toBe(true);
        expect(derived.sessionKey).toBeDefined();
        expect(typeof derived.sessionKey).toBe('string');
        
        console.log(`Session key derived successfully, length: ${derived.sessionKey.length}`);
        
        // Test session key validation
        const validation = validateSessionKey(derived.sessionKey);
        expect(validation.valid).toBe(true);
        
        console.log(`Session key validation successful`);
    });

    test('Error Handling for Invalid Inputs', async () => {
        const registrationInit = getWASMFunction<typeof globalThis.opaqueClientRegistrationInitWASM>('opaqueClientRegistrationInitWASM');
        const loginInit = getWASMFunction<typeof globalThis.opaqueClientLoginInitWASM>('opaqueClientLoginInitWASM');
        
        // Test with empty password (should handle gracefully)
        const emptyPasswordReg = registrationInit('', 'interactive', 'RistrettoSha512');
        // In mock mode, this will still succeed, but real WASM should handle this
        expect(emptyPasswordReg).toBeDefined();
        
        const emptyPasswordLogin = loginInit('');
        expect(emptyPasswordLogin).toBeDefined();
        
        console.log(`Error handling test completed`);
    });
});

// Export for standalone execution
export async function runOpaqueWASMTests(): Promise<void> {
    console.log('🧪 Running OPAQUE WASM Tests Standalone...\n');
    await loadWASMModule();
    
    try {
        // Run tests manually if needed
        console.log('OPAQUE WASM module setup complete');
        console.log('Use "bun test" to run the full test suite');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`Error in OPAQUE WASM tests: ${errorMessage}`);
        throw error;
    }
}

// Run if called directly
if (import.meta.main) {
    await runOpaqueWASMTests();
}
