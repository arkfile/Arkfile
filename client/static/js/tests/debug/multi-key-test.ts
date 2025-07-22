#!/usr/bin/env bun

/**
 * Debug-focused test runner for multi-key encryption issue (Bun Version)
 * Runs only the failing test with extensive debugging output
 */

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

// Type-safe WASM function declarations
declare global {
    function encryptFileMultiKey(
        data: Uint8Array, 
        primaryPassword: string, 
        keyType: string, 
        additionalKeys: { password: string; id: string }[]
    ): string;
    function decryptFileMultiKey(encrypted: string, password: string): string;
}

// Load and run WASM tests
async function runDebugTest(): Promise<void> {
    console.log('🔍 Debug Multi-Key Encryption Test (Bun Runtime)\n');
    
    try {
        // Check if WASM file exists
        const wasmPath = join(import.meta.dir, '..', '..', '..', 'static', 'main.wasm');
        if (!existsSync(wasmPath)) {
            console.error('❌ WASM file not found. Please build first.');
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
        if (typeof globalThis.encryptFileMultiKey === 'undefined') {
            console.error('❌ Multi-key WASM functions not available.');
            process.exit(1);
        }
        
        console.log('✅ WASM module loaded successfully\n');
        
        // Run the multi-key encryption test with extensive debugging
        console.log('🧪 Running Debug Multi-Key Encryption Test...\n');
        
        const testData = new Uint8Array([10, 20, 30, 40, 50]);
        const primaryPassword = "primary123!";
        const additionalPassword = "additional123!";
        
        console.log(`📝 Test data: [${Array.from(testData).join(', ')}]`);
        console.log(`📝 Primary password: "${primaryPassword}"`);
        console.log(`📝 Additional password: "${additionalPassword}"`);
        console.log();
        
        // Create additional keys array structure
        const additionalKeys: { password: string; id: string }[] = [
            { password: additionalPassword, id: "share1" }
        ];
        
        console.log('📝 Additional keys structure:', JSON.stringify(additionalKeys, null, 2));
        console.log();
        
        // Step 1: Encrypt with multi-key
        console.log('🔐 Step 1: Encrypting with multi-key...');
        const encrypted = globalThis.encryptFileMultiKey(testData, primaryPassword, "custom", additionalKeys);
        
        if (typeof encrypted !== 'string') {
            console.error('❌ Multi-key encryption did not return a string');
            console.error('   Returned:', typeof encrypted, encrypted);
            process.exit(1);
        }
        
        console.log('✅ Multi-key encryption successful');
        console.log(`📝 Encrypted result length: ${encrypted.length} characters`);
        console.log(`📝 Encrypted result (first 100 chars): ${encrypted.substring(0, 100)}...`);
        console.log();
        
        // Step 2: Analyze the encrypted data structure
        console.log('🔍 Step 2: Analyzing encrypted data structure...');
        const encryptedBuffer = Buffer.from(encrypted, 'base64');
        console.log(`📝 Encrypted data length: ${encryptedBuffer.length} bytes`);
        console.log(`📝 Version byte: 0x${encryptedBuffer[0].toString(16).padStart(2, '0')}`);
        console.log(`📝 Number of keys: ${encryptedBuffer[1]}`);
        console.log(`📝 First few bytes: [${Array.from(encryptedBuffer.slice(0, 20)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);
        console.log();
        
        // Step 3: Try decryption with primary password
        console.log('🔓 Step 3: Attempting decryption with primary password...');
        const decrypted1 = globalThis.decryptFileMultiKey(encrypted, primaryPassword);
        
        console.log(`📝 Decryption result type: ${typeof decrypted1}`);
        console.log(`📝 Decryption result (first 200 chars): ${decrypted1.substring(0, 200)}`);
        
        if (typeof decrypted1 !== 'string' || decrypted1.startsWith('Failed')) {
            console.error('❌ Multi-key decryption with primary password failed');
            console.error('   Full error:', decrypted1);
            
            // Let's also try with the additional password to see if it's a key-specific issue
            console.log('\n🔍 Trying with additional password for comparison...');
            const decrypted2 = globalThis.decryptFileMultiKey(encrypted, additionalPassword);
            console.log(`📝 Additional password result: ${decrypted2.substring(0, 200)}`);
            
            process.exit(1);
        }
        
        console.log('✅ Primary password decryption successful!');
        
        // Step 4: Verify decrypted data matches original
        console.log('\n🔍 Step 4: Verifying decrypted data...');
        const decryptedBuffer = Buffer.from(decrypted1, 'base64');
        const originalBuffer = Buffer.from(testData);
        
        console.log(`📝 Original data: [${Array.from(originalBuffer).join(', ')}]`);
        console.log(`📝 Decrypted data: [${Array.from(decryptedBuffer).join(', ')}]`);
        
        if (Buffer.compare(originalBuffer, decryptedBuffer) === 0) {
            console.log('✅ Data verification successful!');
        } else {
            console.error('❌ Decrypted data does not match original');
            process.exit(1);
        }
        
        console.log('\n🎉 Multi-key encryption test passed!');
        
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`💥 Error running debug test: ${errorMessage}`);
        if (error instanceof Error && error.stack) {
            console.error(error.stack);
        }
        process.exit(1);
    }
}

// Export for use in other test files
export { runDebugTest };

// Run if called directly
if (import.meta.main) {
    await runDebugTest();
}
