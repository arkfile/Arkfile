#!/usr/bin/env node

/**
 * WASM Test Runner for Arkfile Client
 * 
 * This Node.js script loads and executes the compiled WASM module
 * to run client-side cryptographic tests in a JavaScript environment.
 */

const fs = require('fs');
const path = require('path');

// Load the Go WASM runtime
require('./wasm_exec.js');

// Global test state
let testResults = [];
let currentTest = null;

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

// Mock console methods for test output
const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn
};

// Test framework mock
global.testing = {
    T: class {
        constructor(name) {
            this.name = name;
            this.failed = false;
            this.logs = [];
        }
        
        Error(msg) {
            this.failed = true;
            this.logs.push(`ERROR: ${msg}`);
            console.error(`❌ ${this.name}: ${msg}`);
        }
        
        Errorf(format, ...args) {
            const msg = format.replace(/%[sdv]/g, () => args.shift());
            this.Error(msg);
        }
        
        Fatal(msg) {
            this.Error(msg);
            throw new Error(`Fatal: ${msg}`);
        }
        
        Fatalf(format, ...args) {
            const msg = format.replace(/%[sdv]/g, () => args.shift());
            this.Fatal(msg);
        }
        
        Log(msg) {
            this.logs.push(`LOG: ${msg}`);
            console.log(`📝 ${this.name}: ${msg}`);
        }
        
        Logf(format, ...args) {
            const msg = format.replace(/%[sdv]/g, () => args.shift());
            this.Log(msg);
        }
        
        Skip(msg) {
            this.logs.push(`SKIP: ${msg}`);
            console.log(`⏭️  ${this.name}: SKIPPED - ${msg}`);
        }
    }
};

// Test runner functions
function runTest(testName, testFunc) {
    const t = new testing.T(testName);
    currentTest = t;
    
    try {
        console.log(`🧪 Running ${testName}...`);
        testFunc(t);
        if (!t.failed) {
            console.log(`✅ ${testName} PASSED`);
        }
    } catch (error) {
        t.failed = true;
        t.logs.push(`PANIC: ${error.message}`);
        console.error(`💥 ${testName} PANICKED: ${error.message}`);
    }
    
    testResults.push(t);
    currentTest = null;
    return !t.failed;
}

// Load and run WASM tests
async function runWasmTests() {
    console.log('🚀 Starting Arkfile WASM Tests\n');
    
    try {
        // Check if WASM file exists
        const wasmPath = path.join(__dirname, 'static', 'main.wasm');
        if (!fs.existsSync(wasmPath)) {
            console.error('❌ WASM file not found. Please build first with:');
            console.error('   cd client && GOOS=js GOARCH=wasm go build -o static/main.wasm .');
            process.exit(1);
        }
        
        // Load WASM file
        const wasmBytes = fs.readFileSync(wasmPath);
        
        // Create Go instance
        const go = new Go();
        
        // Create a promise that resolves when WASM is ready
        const wasmReady = new Promise((resolve) => {
            // Override the Go exit function to prevent process termination
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
        if (typeof global.encryptFile === 'undefined') {
            console.error('❌ WASM functions not available. Module may not have loaded correctly.');
            process.exit(1);
        }
        
        console.log('✅ WASM module loaded successfully\n');
        
        // Debug: List available WASM functions
        console.log('🔍 Available WASM functions:');
        const wasmFunctions = Object.keys(global).filter(key => 
            typeof global[key] === 'function' && 
            (key.startsWith('encrypt') || key.startsWith('decrypt') || key.startsWith('derive') || key.startsWith('generate'))
        );
        wasmFunctions.forEach(func => console.log(`  - ${func}`));
        console.log();
        
        // Run tests (these would be defined in the WASM module)
        let passed = 0;
        let failed = 0;
        
        // We can't directly call Go test functions from JS, but we can test the exposed functions
        console.log('📋 Running JavaScript integration tests...\n');
        
        // Test 1: Basic encryption/decryption
        const testBasicEncryption = () => {
            const testData = new Uint8Array([1, 2, 3, 4, 5]);
            const password = "testpassword123!";
            
            const encrypted = global.encryptFile(testData, password, "custom");
            if (typeof encrypted !== 'string') {
                throw new Error('Encryption did not return a string');
            }
            
            const decrypted = global.decryptFile(encrypted, password);
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
        
        if (runTest('TestBasicEncryptionDecryption', testBasicEncryption)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 2: Salt generation
        const testSaltGeneration = () => {
            const salt1 = global.generateSalt();
            const salt2 = global.generateSalt();
            
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
        
        if (runTest('TestSaltGeneration', testSaltGeneration)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 3: Session key derivation
        const testSessionKeyDerivation = () => {
            const password = "userpassword123!";
            const salt = global.generateSalt();
            
            const sessionKey1 = global.deriveSessionKey(password, salt);
            const sessionKey2 = global.deriveSessionKey(password, salt);
            
            if (typeof sessionKey1 !== 'string' || typeof sessionKey2 !== 'string') {
                throw new Error('Session key derivation did not return strings');
            }
            
            if (sessionKey1 !== sessionKey2) {
                throw new Error('Session key derivation is not deterministic');
            }
            
            // Test with different salt
            const salt2 = global.generateSalt();
            const sessionKey3 = global.deriveSessionKey(password, salt2);
            
            if (sessionKey1 === sessionKey3) {
                throw new Error('Different salts should produce different session keys');
            }
        };
        
        if (runTest('TestSessionKeyDerivation', testSessionKeyDerivation)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 4: Multi-key encryption (if available)
        const testMultiKeyEncryption = () => {
            // Check if multi-key functions are available
            if (typeof global.encryptFileMultiKey === 'undefined' || typeof global.decryptFileMultiKey === 'undefined') {
                throw new Error('Multi-key functions not available - test skipped');
            }
            
            const testData = new Uint8Array([10, 20, 30, 40, 50]);
            const primaryPassword = "primary123!";
            const additionalPassword = "additional123!";
            
            // Create additional keys array structure
            const additionalKeys = [
                { password: additionalPassword, id: "share1" }
            ];
            
            console.log(`    🔍 Encrypting with primary: "${primaryPassword}", additional: "${additionalPassword}"`);
            
            const encrypted = global.encryptFileMultiKey(testData, primaryPassword, "custom", additionalKeys);
            if (typeof encrypted !== 'string') {
                throw new Error('Multi-key encryption did not return a string');
            }
            
            console.log('    ✅ Multi-key encryption successful');
            
            // Test decryption with primary password
            console.log('    🔍 Attempting decryption with primary password...');
            const decrypted1 = global.decryptFileMultiKey(encrypted, primaryPassword);
            console.log(`    📝 Primary decryption result: ${typeof decrypted1} - ${decrypted1?.substring(0, 50)}...`);
            
            if (typeof decrypted1 !== 'string' || decrypted1.startsWith('Failed')) {
                throw new Error(`Multi-key decryption with primary password failed: ${decrypted1}`);
            }
            
            // Test decryption with additional password
            console.log('    🔍 Attempting decryption with additional password...');
            const decrypted2 = global.decryptFileMultiKey(encrypted, additionalPassword);
            console.log(`    📝 Additional decryption result: ${typeof decrypted2} - ${decrypted2?.substring(0, 50)}...`);
            
            if (typeof decrypted2 !== 'string' || decrypted2.startsWith('Failed')) {
                throw new Error(`Multi-key decryption with additional password failed: ${decrypted2}`);
            }
            
            // Both should decrypt to the same data
            if (decrypted1 !== decrypted2) {
                throw new Error('Multi-key decryption results do not match');
            }
        };
        
        // Check if multi-key functions are available before running the test
        if (typeof global.encryptFileMultiKey === 'undefined' || typeof global.decryptFileMultiKey === 'undefined') {
            console.log('⏭️  TestMultiKeyEncryption SKIPPED - Multi-key functions not implemented yet');
        } else {
            if (runTest('TestMultiKeyEncryption', testMultiKeyEncryption)) {
                passed++;
            } else {
                failed++;
            }
        }
        
        // Test 5: Wrong password handling
        const testWrongPassword = () => {
            const testData = new Uint8Array([5, 4, 3, 2, 1]);
            const correctPassword = "correct123!";
            const wrongPassword = "wrong123!";
            
            const encrypted = global.encryptFile(testData, correctPassword, "custom");
            const decrypted = global.decryptFile(encrypted, wrongPassword);
            
            if (typeof decrypted !== 'string' || !decrypted.includes('Failed')) {
                throw new Error('Wrong password should fail to decrypt');
            }
        };
        
        if (runTest('TestWrongPasswordHandling', testWrongPassword)) {
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
        console.error(`💥 Error running tests: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    runWasmTests();
}

module.exports = { runWasmTests };
