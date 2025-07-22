#!/usr/bin/env bun

/**
 * WASM Test Runner for Arkfile Client (Bun Version)
 * 
 * This Bun TypeScript script loads and executes the compiled WASM module
 * to run client-side cryptographic tests in a modern runtime environment.
 */

import { readFileSync, existsSync } from "fs";
import { join } from "path";

// Import Bun's built-in test framework
import { test, expect, describe } from "bun:test";

// Global test state
interface TestResult {
    name: string;
    failed: boolean;
    logs: string[];
}

let testResults: TestResult[] = [];
let currentTest: TestContext | null = null;

// Test context interface
export interface TestContext {
    name: string;
    failed: boolean;
    logs: string[];
    error(msg: string): void;
    log(msg: string): void;
    skip(msg: string): void;
}

// Mock browser APIs for Bun environment
declare global {
    // WASM function declarations
    function encryptFile(data: Uint8Array, password: string, keyType: string): string;
    function decryptFile(data: string, password: string): string;
    function generateSalt(): string;
    function deriveSessionKey(password: string, salt: string): string;
    function encryptFileMultiKey(
        data: Uint8Array, 
        primaryPassword: string, 
        keyType: string, 
        additionalKeys: { password: string; id: string }[]
    ): string;
    function decryptFileMultiKey(encrypted: string, password: string): string;
}

// Enhanced crypto mocking for Bun
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
        subtle: {} as SubtleCrypto // Placeholder - not used in tests
    } as Crypto;
}

// Test framework implementation
export class TestRunner {
    private testResults: TestResult[] = [];
    
    async runTest(testName: string, testFunc: (t: TestContext) => Promise<void> | void): Promise<boolean> {
        const t: TestContext = {
            name: testName,
            failed: false,
            logs: [],
            error(msg: string) {
                this.failed = true;
                this.logs.push(`ERROR: ${msg}`);
                console.error(`❌ ${this.name}: ${msg}`);
            },
            log(msg: string) {
                this.logs.push(`LOG: ${msg}`);
                console.log(`📝 ${this.name}: ${msg}`);
            },
            skip(msg: string) {
                this.logs.push(`SKIP: ${msg}`);
                console.log(`⏭️ ${this.name}: SKIPPED - ${msg}`);
            }
        };
        
        currentTest = t;
        
        try {
            console.log(`🧪 Running ${testName}...`);
            await testFunc(t);
            if (!t.failed) {
                console.log(`✅ ${testName} PASSED`);
            }
        } catch (error) {
            t.failed = true;
            const errorMessage = error instanceof Error ? error.message : String(error);
            t.logs.push(`PANIC: ${errorMessage}`);
            console.error(`💥 ${testName} PANICKED: ${errorMessage}`);
        }
        
        this.testResults.push(t);
        currentTest = null;
        return !t.failed;
    }
    
    async runWasmTests(): Promise<void> {
        console.log('🚀 Starting Arkfile WASM Tests (Bun Runtime)\n');
        
        try {
            // Check if WASM file exists
            const wasmPath = join(import.meta.dir, '..', '..', '..', 'static', 'main.wasm');
            if (!existsSync(wasmPath)) {
                console.error('❌ WASM file not found. Please build first with:');
                console.error('   cd client && GOOS=js GOARCH=wasm go build -o static/main.wasm .');
                process.exit(1);
            }
            
            // Load WASM file
            const wasmBytes = readFileSync(wasmPath);
            
            // Load wasm_exec.js for Go runtime
            const wasmExecPath = join(import.meta.dir, '..', '..', '..', 'wasm_exec.js');
            if (!existsSync(wasmExecPath)) {
                console.error('❌ wasm_exec.js not found');
                process.exit(1);
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
            
            // Check if WASM functions are available
            if (typeof globalThis.encryptFile === 'undefined') {
                console.error('❌ WASM functions not available. Module may not have loaded correctly.');
                process.exit(1);
            }
            
            console.log('✅ WASM module loaded successfully\n');
            
            // Debug: List available WASM functions
            console.log('🔍 Available WASM functions:');
            const wasmFunctions = Object.keys(globalThis).filter(key => 
                typeof (globalThis as any)[key] === 'function' && 
                (key.startsWith('encrypt') || key.startsWith('decrypt') || 
                 key.startsWith('derive') || key.startsWith('generate'))
            );
            wasmFunctions.forEach(func => console.log(`  - ${func}`));
            console.log();
            
            // Run tests
            let passed = 0;
            let failed = 0;
            
            console.log('📋 Running TypeScript integration tests...\n');
            
            // Test 1: Basic encryption/decryption
            if (await this.runTest('TestBasicEncryptionDecryption', this.testBasicEncryption)) {
                passed++;
            } else {
                failed++;
            }
            
            // Test 2: Salt generation
            if (await this.runTest('TestSaltGeneration', this.testSaltGeneration)) {
                passed++;
            } else {
                failed++;
            }
            
            // Test 3: Session key derivation
            if (await this.runTest('TestSessionKeyDerivation', this.testSessionKeyDerivation)) {
                passed++;
            } else {
                failed++;
            }
            
            // Test 4: Multi-key encryption (if available)
            if (typeof globalThis.encryptFileMultiKey === 'undefined' || 
                typeof globalThis.decryptFileMultiKey === 'undefined') {
                console.log('⏭️  TestMultiKeyEncryption SKIPPED - Multi-key functions not implemented yet');
            } else {
                if (await this.runTest('TestMultiKeyEncryption', this.testMultiKeyEncryption)) {
                    passed++;
                } else {
                    failed++;
                }
            }
            
            // Test 5: Wrong password handling
            if (await this.runTest('TestWrongPasswordHandling', this.testWrongPassword)) {
                passed++;
            } else {
                failed++;
            }
            
            // Print summary
            console.log('\n📊 Test Summary:');
            console.log(`✅ Passed: ${passed}`);
            console.log(`❌ Failed: ${failed}`);
            console.log(`📋 Total:  ${passed + failed}`);
            
            if (failed > 0) {
                console.log('\n💡 Some tests failed. Check the output above for details.');
                process.exit(1);
            } else {
                console.log('\n🎉 All tests passed!');
                process.exit(0);
            }
            
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.error(`💥 Error running tests: ${errorMessage}`);
            if (error instanceof Error && error.stack) {
                console.error(error.stack);
            }
            process.exit(1);
        }
    }
    
    private testBasicEncryption = (): void => {
        const testData = new Uint8Array([1, 2, 3, 4, 5]);
        const password = "testpassword123!";
        
        const encrypted = globalThis.encryptFile(testData, password, "custom");
        if (typeof encrypted !== 'string') {
            throw new Error('Encryption did not return a string');
        }
        
        const decrypted = globalThis.decryptFile(encrypted, password);
        if (typeof decrypted !== 'string') {
            throw new Error('Decryption did not return a string');
        }
        
        // Convert back to compare
        const decryptedBytes = Uint8Array.from(atob(decrypted), c => c.charCodeAt(0));
        if (decryptedBytes.length !== testData.length) {
            throw new Error('Decrypted data length mismatch');
        }
        
        for (let i = 0; i < testData.length; i++) {
            if (decryptedBytes[i] !== testData[i]) {
                throw new Error(`Decrypted data mismatch at index ${i}`);
            }
        }
    };
    
    private testSaltGeneration = (): void => {
        const salt1 = globalThis.generateSalt();
        const salt2 = globalThis.generateSalt();
        
        if (typeof salt1 !== 'string' || typeof salt2 !== 'string') {
            throw new Error('Salt generation did not return strings');
        }
        
        if (salt1 === salt2) {
            throw new Error('Salt generation is not producing unique values');
        }
        
        // Decode and check length (should be 32 bytes = 44 base64 chars with padding)
        const decodedSalt = atob(salt1);
        if (decodedSalt.length !== 32) {
            throw new Error(`Salt length incorrect: expected 32, got ${decodedSalt.length}`);
        }
    };
    
    private testSessionKeyDerivation = (): void => {
        const password = "userpassword123!";
        const salt = globalThis.generateSalt();
        
        const sessionKey1 = globalThis.deriveSessionKey(password, salt);
        const sessionKey2 = globalThis.deriveSessionKey(password, salt);
        
        if (typeof sessionKey1 !== 'string' || typeof sessionKey2 !== 'string') {
            throw new Error('Session key derivation did not return strings');
        }
        
        if (sessionKey1 !== sessionKey2) {
            throw new Error('Session key derivation is not deterministic');
        }
        
        // Test with different salt
        const salt2 = globalThis.generateSalt();
        const sessionKey3 = globalThis.deriveSessionKey(password, salt2);
        
        if (sessionKey1 === sessionKey3) {
            throw new Error('Different salts should produce different session keys');
        }
    };
    
    private testMultiKeyEncryption = (): void => {
        const testData = new Uint8Array([10, 20, 30, 40, 50]);
        const primaryPassword = "primary123!";
        const additionalPassword = "additional123!";
        
        // Create additional keys array structure
        const additionalKeys = [
            { password: additionalPassword, id: "share1" }
        ];
        
        console.log(`    🔍 Encrypting with primary: "${primaryPassword}", additional: "${additionalPassword}"`);
        
        const encrypted = globalThis.encryptFileMultiKey(testData, primaryPassword, "custom", additionalKeys);
        if (typeof encrypted !== 'string') {
            throw new Error('Multi-key encryption did not return a string');
        }
        
        console.log('    ✅ Multi-key encryption successful');
        
        // Test decryption with primary password
        console.log('    🔍 Attempting decryption with primary password...');
        const decrypted1 = globalThis.decryptFileMultiKey(encrypted, primaryPassword);
        console.log(`    📝 Primary decryption result: ${typeof decrypted1} - ${decrypted1?.substring(0, 50)}...`);
        
        if (typeof decrypted1 !== 'string' || decrypted1.startsWith('Failed')) {
            throw new Error(`Multi-key decryption with primary password failed: ${decrypted1}`);
        }
        
        // Test decryption with additional password
        console.log('    🔍 Attempting decryption with additional password...');
        const decrypted2 = globalThis.decryptFileMultiKey(encrypted, additionalPassword);
        console.log(`    📝 Additional decryption result: ${typeof decrypted2} - ${decrypted2?.substring(0, 50)}...`);
        
        if (typeof decrypted2 !== 'string' || decrypted2.startsWith('Failed')) {
            throw new Error(`Multi-key decryption with additional password failed: ${decrypted2}`);
        }
        
        // Both should decrypt to the same data
        if (decrypted1 !== decrypted2) {
            throw new Error('Multi-key decryption results do not match');
        }
    };
    
    private testWrongPassword = (): void => {
        const testData = new Uint8Array([5, 4, 3, 2, 1]);
        const correctPassword = "correct123!";
        const wrongPassword = "wrong123!";
        
        const encrypted = globalThis.encryptFile(testData, correctPassword, "custom");
        const decrypted = globalThis.decryptFile(encrypted, wrongPassword);
        
        if (typeof decrypted !== 'string' || !decrypted.includes('Failed')) {
            throw new Error('Wrong password should fail to decrypt');
        }
    };
}

// Export for use in other test files
export const testRunner = new TestRunner();

// Run if called directly
if (import.meta.main) {
    await testRunner.runWasmTests();
}
