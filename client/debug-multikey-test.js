#!/usr/bin/env node

/**
 * Debug-focused test runner for multi-key encryption issue
 * Runs only the failing test with extensive debugging output
 */

const fs = require('fs');
const path = require('path');

// Load the Go WASM runtime
require('./wasm_exec.js');

// Mock browser APIs for Node.js environment
global.crypto = require('crypto').webcrypto || {
    getRandomValues: (array) => {
        const nodeBytes = require('crypto').randomBytes(array.length);
        for (let i = 0; i < array.length; i++) {
            array[i] = nodeBytes[i];
        }
        return array;
    }
};

// Load and run WASM tests
async function runDebugTest() {
    console.log('🔍 Debug Multi-Key Encryption Test\n');
    
    try {
        // Check if WASM file exists
        const wasmPath = path.join(__dirname, 'static', 'main.wasm');
        if (!fs.existsSync(wasmPath)) {
            console.error('❌ WASM file not found. Please build first.');
            process.exit(1);
        }
        
        // Load WASM file
        const wasmBytes = fs.readFileSync(wasmPath);
        
        // Create Go instance
        const go = new Go();
        
        // Create a promise that resolves when WASM is ready
        const wasmReady = new Promise((resolve) => {
            const originalExit = go.exit;
            go.exit = (code) => {
                console.log(`Go program exited with code ${code}`);
                resolve();
            };
        });
        
        // Instantiate WASM module
        const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
        
        // Start the Go program
        go.run(result.instance);
        
        // Wait a moment for initialization
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Check if WASM functions are available
        if (typeof global.encryptFileMultiKey === 'undefined') {
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
        const additionalKeys = [
            { password: additionalPassword, id: "share1" }
        ];
        
        console.log('📝 Additional keys structure:', JSON.stringify(additionalKeys, null, 2));
        console.log();
        
        // Step 1: Encrypt with multi-key
        console.log('🔐 Step 1: Encrypting with multi-key...');
        const encrypted = global.encryptFileMultiKey(testData, primaryPassword, "custom", additionalKeys);
        
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
        const encryptedBytes = Buffer.from(encrypted, 'base64');
        console.log(`📝 Encrypted data length: ${encryptedBytes.length} bytes`);
        console.log(`📝 Version byte: 0x${encryptedBytes[0].toString(16).padStart(2, '0')}`);
        console.log(`📝 Number of keys: ${encryptedBytes[1]}`);
        console.log(`📝 First few bytes: [${Array.from(encryptedBytes.slice(0, 20)).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);
        console.log();
        
        // Step 3: Try decryption with primary password
        console.log('🔓 Step 3: Attempting decryption with primary password...');
        const decrypted1 = global.decryptFileMultiKey(encrypted, primaryPassword);
        
        console.log(`📝 Decryption result type: ${typeof decrypted1}`);
        console.log(`📝 Decryption result (first 200 chars): ${decrypted1.substring(0, 200)}`);
        
        if (typeof decrypted1 !== 'string' || decrypted1.startsWith('Failed')) {
            console.error('❌ Multi-key decryption with primary password failed');
            console.error('   Full error:', decrypted1);
            
            // Let's also try with the additional password to see if it's a key-specific issue
            console.log('\n🔍 Trying with additional password for comparison...');
            const decrypted2 = global.decryptFileMultiKey(encrypted, additionalPassword);
            console.log(`📝 Additional password result: ${decrypted2.substring(0, 200)}`);
            
            process.exit(1);
        }
        
        console.log('✅ Primary password decryption successful!');
        
        // Step 4: Verify decrypted data matches original
        console.log('\n🔍 Step 4: Verifying decrypted data...');
        const decryptedBytes = Buffer.from(decrypted1, 'base64');
        const originalBytes = Buffer.from(testData);
        
        console.log(`📝 Original data: [${Array.from(originalBytes).join(', ')}]`);
        console.log(`📝 Decrypted data: [${Array.from(decryptedBytes).join(', ')}]`);
        
        if (Buffer.compare(originalBytes, decryptedBytes) === 0) {
            console.log('✅ Data verification successful!');
        } else {
            console.error('❌ Decrypted data does not match original');
            process.exit(1);
        }
        
        console.log('\n🎉 Multi-key encryption test passed!');
        
    } catch (error) {
        console.error(`💥 Error running debug test: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    runDebugTest();
}

module.exports = { runDebugTest };
