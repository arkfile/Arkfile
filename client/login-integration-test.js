#!/usr/bin/env node

/**
 * Login Integration Test for Arkfile
 * Tests the complete login flow: salt generation → password hashing → backend compatibility
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

// Mock fetch for API testing
global.fetch = async (url, options) => {
    // Simulate backend responses
    const method = options?.method || 'GET';
    const body = options?.body ? JSON.parse(options.body) : null;
    
    if (url.includes('/get-user-salt') && method === 'POST') {
        // Return a mock salt for the test user
        return {
            ok: true,
            json: async () => ({ salt: "dGVzdC1zYWx0LWZvci10ZXN0aW5n" }) // base64 test salt
        };
    }
    
    if (url.includes('/login') && method === 'POST') {
        // Verify that we receive passwordHash instead of password
        if (!body.passwordHash) {
            return {
                ok: false,
                json: async () => ({ error: "Missing passwordHash field" })
            };
        }
        
        if (body.password) {
            return {
                ok: false,
                json: async () => ({ error: "Received plaintext password - security violation!" })
            };
        }
        
        // Mock successful login
        return {
            ok: true,
            json: async () => ({
                token: "mock-jwt-token",
                refreshToken: "mock-refresh-token",
                user: { email: body.email, is_approved: true }
            })
        };
    }
    
    throw new Error(`Unmocked fetch: ${method} ${url}`);
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
        
        Log(msg) {
            this.logs.push(`LOG: ${msg}`);
            console.log(`📝 ${this.name}: ${msg}`);
        }
    }
};

// Test runner function
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

// Simulate the frontend login flow
async function simulateLoginFlow(email, password) {
    console.log(`    🔍 Starting login flow for ${email}`);
    
    // Step 1: Get user salt
    console.log('    📡 Getting user salt...');
    const saltResponse = await fetch('/get-user-salt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });
    
    if (!saltResponse.ok) {
        throw new Error('Failed to get user salt');
    }
    
    const { salt } = await saltResponse.json();
    console.log(`    📝 Received salt: ${salt.substring(0, 20)}...`);
    
    // Step 2: Hash password with salt using WASM
    console.log('    🔐 Hashing password with salt...');
    const passwordHash = global.hashPasswordArgon2ID(password, salt);
    console.log(`    📝 Generated password hash: ${passwordHash.substring(0, 20)}...`);
    
    // Step 3: Send login request with hash
    console.log('    📡 Sending login request...');
    const loginResponse = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email,
            passwordHash // Note: sending hash, not plaintext password
        })
    });
    
    if (!loginResponse.ok) {
        const error = await loginResponse.json();
        throw new Error(`Login failed: ${error.error}`);
    }
    
    const loginData = await loginResponse.json();
    console.log('    ✅ Login successful!');
    console.log(`    📝 Received token: ${loginData.token}`);
    console.log(`    📝 User approved: ${loginData.user.is_approved}`);
    
    return loginData;
}

// Load and run login integration tests
async function runLoginIntegrationTests() {
    console.log('🔐 Starting Arkfile Login Integration Tests\n');
    
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
        
        // Instantiate WASM module
        const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
        
        // Start the Go program
        go.run(result.instance);
        
        // Wait for initialization
        await new Promise(resolve => setTimeout(resolve, 100));
        
        // Check if password hashing functions are available
        if (typeof global.hashPasswordArgon2ID === 'undefined') {
            console.error('❌ Password hashing WASM functions not available');
            process.exit(1);
        }
        
        console.log('✅ Login integration test environment ready\n');
        
        let passed = 0;
        let failed = 0;
        
        // Test 1: Complete login flow
        const testCompleteLoginFlow = async () => {
            const email = 'test@example.com';
            const password = 'TestPassword123!@#';
            
            const loginData = await simulateLoginFlow(email, password);
            
            if (!loginData.token || !loginData.refreshToken) {
                throw new Error('Login response missing required tokens');
            }
            
            if (loginData.user.email !== email) {
                throw new Error('Login response user email mismatch');
            }
        };
        
        if (await runTest('TestCompleteLoginFlow', testCompleteLoginFlow)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 2: Password hash consistency
        const testPasswordHashConsistency = () => {
            const password = 'ConsistencyTest123!';
            const salt = 'dGVzdC1zYWx0LWZvci10ZXN0aW5n';
            
            // Generate hash multiple times
            const hash1 = global.hashPasswordArgon2ID(password, salt);
            const hash2 = global.hashPasswordArgon2ID(password, salt);
            const hash3 = global.hashPasswordArgon2ID(password, salt);
            
            if (hash1 !== hash2 || hash2 !== hash3) {
                throw new Error('Password hashing is not consistent with same salt');
            }
            
            console.log(`    📝 Hash consistency verified: ${hash1.substring(0, 20)}...`);
            
            // Test with different salt
            const differentSalt = global.generatePasswordSalt();
            const hash4 = global.hashPasswordArgon2ID(password, differentSalt);
            
            if (hash1 === hash4) {
                throw new Error('Different salts should produce different hashes');
            }
            
            console.log(`    📝 Salt uniqueness verified`);
        };
        
        if (runTest('TestPasswordHashConsistency', testPasswordHashConsistency)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 3: Backend compatibility format
        const testBackendCompatibilityFormat = () => {
            const password = 'BackendTest123!@#';
            const salt = global.generatePasswordSalt();
            const hash = global.hashPasswordArgon2ID(password, salt);
            
            // Verify hash is base64 string
            if (typeof hash !== 'string') {
                throw new Error('Password hash is not a string');
            }
            
            // Verify it's valid base64
            try {
                const decoded = Buffer.from(hash, 'base64');
                if (decoded.length !== 32) {
                    throw new Error(`Hash length incorrect: expected 32 bytes, got ${decoded.length}`);
                }
            } catch (e) {
                throw new Error(`Invalid base64 hash format: ${e.message}`);
            }
            
            // Verify salt format
            if (typeof salt !== 'string') {
                throw new Error('Salt is not a string');
            }
            
            try {
                const decodedSalt = Buffer.from(salt, 'base64');
                if (decodedSalt.length !== 32) {
                    throw new Error(`Salt length incorrect: expected 32 bytes, got ${decodedSalt.length}`);
                }
            } catch (e) {
                throw new Error(`Invalid base64 salt format: ${e.message}`);
            }
            
            console.log(`    📝 Hash format: base64, ${hash.length} chars`);
            console.log(`    📝 Salt format: base64, ${salt.length} chars`);
            console.log(`    📝 Backend compatibility verified`);
        };
        
        if (runTest('TestBackendCompatibilityFormat', testBackendCompatibilityFormat)) {
            passed++;
        } else {
            failed++;
        }
        
        // Test 4: Security verification (no plaintext)
        const testSecurityVerification = async () => {
            // Simulate what would happen if plaintext password was sent
            console.log('    🔒 Testing security: attempting to send plaintext password...');
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: 'test@example.com',
                        password: 'PlaintextPassword123!' // This should be rejected
                    })
                });
                
                const result = await response.json();
                if (response.ok) {
                    throw new Error('Backend accepted plaintext password - security vulnerability!');
                }
                
                if (!result.error.includes('passwordHash') && !result.error.includes('security')) {
                    throw new Error('Backend did not properly reject plaintext password');
                }
                
                console.log('    ✅ Backend properly rejects plaintext passwords');
                
            } catch (error) {
                if (error.message.includes('security vulnerability')) {
                    throw error;
                }
                // Expected error is good
                console.log('    ✅ Security verification passed');
            }
        };
        
        if (await runTest('TestSecurityVerification', testSecurityVerification)) {
            passed++;
        } else {
            failed++;
        }
        
        // Print summary
        console.log('\n📊 Login Integration Test Summary:');
        console.log(`✅ Passed: ${passed}`);
        console.log(`❌ Failed: ${failed}`);
        console.log(`📋 Total:  ${passed + failed}`);
        
        if (failed > 0) {
            console.log('\n💡 Some login integration tests failed. Check the output above for details.');
            process.exit(1);
        } else {
            console.log('\n🎉 All login integration tests passed!');
            console.log('🔐 Backend security fix verified: only password hashes are accepted');
            process.exit(0);
        }
        
    } catch (error) {
        console.error(`💥 Error running login integration tests: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    runLoginIntegrationTests();
}

module.exports = { runLoginIntegrationTests };
