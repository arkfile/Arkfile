#!/usr/bin/env node

/**
 * Additional test runner for password-related WASM functions
 * Tests the new salt-based password hashing functions
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
    
    return !t.failed;
}

// Load and run password function tests
async function runPasswordTests() {
    console.log('🔐 Starting Arkfile Password Function Tests\n');
    
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
        
        // Check if password WASM functions are available
        const passwordFunctions = ['hashPasswordArgon2ID', 'generatePasswordSalt', 'validatePasswordComplexity'];
        const missingFunctions = passwordFunctions.filter(func => typeof global[func] === 'undefined');
        
        if (missingFunctions.length > 0) {
            console.error(`❌ Missing password WASM functions: ${missingFunctions.join(', ')}`);
            process.exit(1);
        }
        
        console.log('✅ Password WASM functions loaded successfully\n');
        
        // List available password functions
        console.log('🔍 Available password functions:');
        passwordFunctions.forEach(func => console.log(`  - ${func}`));
        console.log();
        
        let passed = 0;
        let failed = 0;
        
        // Test 1: Password salt generation
        const testPasswordSaltGeneration = () => {
            const salt1 = global.generatePasswordSalt();
            const salt2 = global.generatePasswordSalt();
            
            if (typeof salt1 !== 'string' || typeof salt2 !== 'string') {
                throw new Error('Password salt generation did not return strings');
            }
            
            if (salt1 === salt2) {
                throw new Error('Password salt generation is not producing unique values');
            }
            
            // Decode and check length (should be 32 bytes for Argon2ID)
            const decodedSalt = Buffer.from(salt1, 'base64');
            if (decodedSalt.length !== 32) {
                throw new Error(`Password salt length incorrect: expected 32, got ${decodedSalt.length}`);
            }
            
            console.log(`    📝 Generated salt length: ${decodedSalt.length} bytes`);
            console.log(`    📝 Base64 salt length: ${salt1.length} characters`);
        };
        
        if (runTest('TestPasswordSaltGeneration', testPasswordSaltGeneration)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 2: Argon2ID password hashing
        const testArgon2IDPasswordHashing = () => {
            const password = "TestPassword123!@#";
            const salt = global.generatePasswordSalt();
            
            const hash1 = global.hashPasswordArgon2ID(password, salt);
            const hash2 = global.hashPasswordArgon2ID(password, salt);
            
            if (typeof hash1 !== 'string' || typeof hash2 !== 'string') {
                throw new Error('Password hashing did not return strings');
            }
            
            if (hash1 !== hash2) {
                throw new Error('Password hashing is not deterministic with same salt');
            }
            
            // Test with different salt
            const salt2 = global.generatePasswordSalt();
            const hash3 = global.hashPasswordArgon2ID(password, salt2);
            
            if (hash1 === hash3) {
                throw new Error('Different salts should produce different hashes');
            }
            
            // Test with different password
            const password2 = "DifferentPassword123!@#";
            const hash4 = global.hashPasswordArgon2ID(password2, salt);
            
            if (hash1 === hash4) {
                throw new Error('Different passwords should produce different hashes');
            }
            
            // Decode and check hash length (should be 32 bytes for Argon2ID)
            const decodedHash = Buffer.from(hash1, 'base64');
            if (decodedHash.length !== 32) {
                throw new Error(`Hash length incorrect: expected 32, got ${decodedHash.length}`);
            }
            
            console.log(`    📝 Generated hash length: ${decodedHash.length} bytes`);
            console.log(`    📝 Base64 hash length: ${hash1.length} characters`);
        };
        
        if (runTest('TestArgon2IDPasswordHashing', testArgon2IDPasswordHashing)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 3: Password complexity validation
        const testPasswordComplexityValidation = () => {
            // Test valid password
            const validPassword = "ValidPassword123!@#";
            const validResult = global.validatePasswordComplexity(validPassword);
            
            if (typeof validResult !== 'object' || validResult.valid !== true) {
                throw new Error(`Valid password should pass validation: ${JSON.stringify(validResult)}`);
            }
            
            console.log(`    📝 Valid password result: ${JSON.stringify(validResult)}`);
            
            // Test invalid passwords
            const invalidPasswords = [
                "short",                    // Too short
                "nouppercase123!",         // No uppercase
                "NOLOWERCASE123!",         // No lowercase
                "NoNumbersInThisPassword!@#",  // No numbers (long enough)
                "NoSpecialChars123",       // No special characters
                "ValidPassword123"         // Missing special character
            ];
            
            for (const invalidPassword of invalidPasswords) {
                const result = global.validatePasswordComplexity(invalidPassword);
                if (typeof result !== 'object' || result.valid !== false) {
                    throw new Error(`Invalid password "${invalidPassword}" should fail validation: ${JSON.stringify(result)}`);
                }
                console.log(`    📝 Invalid password "${invalidPassword}": ${result.message}`);
            }
        };
        
        if (runTest('TestPasswordComplexityValidation', testPasswordComplexityValidation)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 4: Session key derivation consistency
        const testSessionKeyConsistency = () => {
            const password = "UserPassword123!@#";
            const salt = global.generatePasswordSalt();
            
            // Derive session key
            const sessionKey1 = global.deriveSessionKey(password, salt);
            const sessionKey2 = global.deriveSessionKey(password, salt);
            
            if (sessionKey1 !== sessionKey2) {
                throw new Error('Session key derivation should be deterministic');
            }
            
            // Compare with direct password hashing
            const directHash = global.hashPasswordArgon2ID(password, salt);
            
            // Test domain separation: session keys should be different from password hashes
            if (sessionKey1 === directHash) {
                throw new Error('Session key should be different from direct password hash (domain separation)');
            }
            
            console.log(`    📝 Session key length: ${sessionKey1.length} characters`);
            console.log(`    📝 Direct hash length: ${directHash.length} characters`);
            console.log(`    📝 Session key and direct hash are different: ${sessionKey1 !== directHash}`);
        };
        
        if (runTest('TestSessionKeyConsistency', testSessionKeyConsistency)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 5: Integration test - encrypt with session key
        const testSessionKeyEncryption = () => {
            const password = "UserPassword123!@#";
            const salt = global.generatePasswordSalt();
            const testData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
            
            // Derive session key
            const sessionKey = global.deriveSessionKey(password, salt);
            
            // Encrypt with session key (account type)
            const encrypted = global.encryptFile(testData, sessionKey, "account");
            if (typeof encrypted !== 'string') {
                throw new Error('Session key encryption failed');
            }
            
            // Decrypt with session key
            const decrypted = global.decryptFile(encrypted, sessionKey);
            if (typeof decrypted !== 'string' || decrypted.startsWith('Failed')) {
                throw new Error(`Session key decryption failed: ${decrypted}`);
            }
            
            // Verify data integrity
            const decryptedBytes = Buffer.from(decrypted, 'base64');
            const originalBytes = Buffer.from(testData);
            
            if (Buffer.compare(originalBytes, decryptedBytes) !== 0) {
                throw new Error('Decrypted data does not match original');
            }
            
            console.log(`    📝 Encrypted with session key successfully`);
            console.log(`    📝 Data integrity verified`);
        };
        
        if (runTest('TestSessionKeyEncryption', testSessionKeyEncryption)) {
            passed++;
        } else {
            failed++;
        }
        
        // Print summary
        console.log('\n📊 Password Function Test Summary:');
        console.log(`✅ Passed: ${passed}`);
        console.log(`❌ Failed: ${failed}`);
        console.log(`📋 Total:  ${passed + failed}`);
        
        if (failed > 0) {
            console.log('\n💡 Some password function tests failed. Check the output above for details.');
            process.exit(1);
        } else {
            console.log('\n🎉 All password function tests passed!');
            process.exit(0);
        }
        
    } catch (error) {
        console.error(`💥 Error running password tests: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    runPasswordTests();
}

module.exports = { runPasswordTests };
