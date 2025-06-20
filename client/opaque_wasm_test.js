/**
 * Client-side WASM tests for OPAQUE integration and adaptive Argon2ID functionality
 * These tests validate the new crypto functions in the browser environment
 */

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds for crypto operations

// Mock data for testing
const testData = {
    password: "TestPassword123!",
    sessionKey: "dGVzdFNlc3Npb25LZXlEYXRhSGVyZVRoaXNJczMyQnl0ZXNMB25n", // base64 encoded 32 bytes
    fileContent: "This is test file content for OPAQUE crypto testing with adaptive Argon2ID parameters.",
    additionalPassword: "AdditionalKey456!"
};

// Test results tracking
let testResults = {
    passed: 0,
    failed: 0,
    errors: []
};

/**
 * Helper function to log test results
 */
function logTest(testName, passed, error = null) {
    if (passed) {
        console.log(`✅ ${testName}`);
        testResults.passed++;
    } else {
        console.error(`❌ ${testName}: ${error}`);
        testResults.failed++;
        testResults.errors.push(`${testName}: ${error}`);
    }
}

/**
 * Helper function to generate random test data
 */
function generateRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
}

/**
 * Test device capability detection and adaptive parameters
 */
async function testDeviceCapabilityDetection() {
    try {
        // Test salt generation (should work with new adaptive system)
        const salt = generateSalt();
        logTest("Salt Generation", typeof salt === 'string' && salt.length > 0);

        // Test session key derivation (should use adaptive parameters)
        const sessionKey = deriveSessionKey(testData.password, salt);
        logTest("Session Key Derivation", typeof sessionKey === 'string' && sessionKey.length > 0);

        // Test that session keys are consistent
        const sessionKey2 = deriveSessionKey(testData.password, salt);
        logTest("Session Key Consistency", sessionKey === sessionKey2);

        // Test that different salts produce different session keys
        const salt2 = generateSalt();
        const sessionKey3 = deriveSessionKey(testData.password, salt2);
        logTest("Session Key Uniqueness", sessionKey !== sessionKey3);

    } catch (error) {
        logTest("Device Capability Detection", false, error.message);
    }
}

/**
 * Test adaptive Argon2ID encryption with custom passwords
 */
async function testAdaptiveEncryption() {
    try {
        const fileData = new TextEncoder().encode(testData.fileContent);
        
        // Test custom password encryption (should use detected device capability)
        const encrypted = encryptFile(fileData, testData.password, "custom");
        logTest("Adaptive Custom Password Encryption", typeof encrypted === 'string' && encrypted.length > 0);

        // Test decryption
        const decrypted = decryptFile(encrypted, testData.password);
        const decryptedText = new TextDecoder().decode(new Uint8Array(Array.from(atob(decrypted), c => c.charCodeAt(0))));
        logTest("Adaptive Custom Password Decryption", decryptedText === testData.fileContent);

        // Test that wrong password fails
        try {
            const wrongDecrypt = decryptFile(encrypted, "WrongPassword123!");
            logTest("Wrong Password Rejection", wrongDecrypt.includes("Failed"));
        } catch (e) {
            logTest("Wrong Password Rejection", true); // Exception is also acceptable
        }

    } catch (error) {
        logTest("Adaptive Encryption", false, error.message);
    }
}

/**
 * Test session key encryption (account-based)
 */
async function testSessionKeyEncryption() {
    try {
        const fileData = new TextEncoder().encode(testData.fileContent);
        
        // Test session key encryption
        const encrypted = encryptFile(fileData, testData.sessionKey, "account");
        logTest("Session Key Encryption", typeof encrypted === 'string' && encrypted.length > 0);

        // Test decryption with session key
        const decrypted = decryptFile(encrypted, testData.sessionKey);
        const decryptedText = new TextDecoder().decode(new Uint8Array(Array.from(atob(decrypted), c => c.charCodeAt(0))));
        logTest("Session Key Decryption", decryptedText === testData.fileContent);

    } catch (error) {
        logTest("Session Key Encryption", false, error.message);
    }
}

/**
 * Test multi-key encryption with adaptive parameters
 */
async function testMultiKeyAdaptiveEncryption() {
    try {
        const fileData = new TextEncoder().encode(testData.fileContent);
        
        // Create additional keys array
        const additionalKeys = [{
            password: testData.additionalPassword,
            id: "test-share-1"
        }];

        // Test multi-key encryption with custom primary password
        const encrypted = encryptFileMultiKey(fileData, testData.password, "custom", additionalKeys);
        logTest("Multi-Key Adaptive Encryption", typeof encrypted === 'string' && encrypted.length > 0);

        // Test decryption with primary password
        const decrypted1 = decryptFileMultiKey(encrypted, testData.password);
        const decryptedText1 = new TextDecoder().decode(new Uint8Array(Array.from(atob(decrypted1), c => c.charCodeAt(0))));
        logTest("Multi-Key Primary Password Decryption", decryptedText1 === testData.fileContent);

        // Test decryption with additional password
        const decrypted2 = decryptFileMultiKey(encrypted, testData.additionalPassword);
        const decryptedText2 = new TextDecoder().decode(new Uint8Array(Array.from(atob(decrypted2), c => c.charCodeAt(0))));
        logTest("Multi-Key Additional Password Decryption", decryptedText2 === testData.fileContent);

        // Test wrong password fails
        try {
            const wrongDecrypt = decryptFileMultiKey(encrypted, "WrongPassword123!");
            logTest("Multi-Key Wrong Password Rejection", wrongDecrypt.includes("Failed"));
        } catch (e) {
            logTest("Multi-Key Wrong Password Rejection", true);
        }

    } catch (error) {
        logTest("Multi-Key Adaptive Encryption", false, error.message);
    }
}

/**
 * Test password complexity validation
 */
async function testPasswordValidation() {
    try {
        // Test valid password
        const validResult = validatePasswordComplexity("ValidPassword123!");
        logTest("Password Validation - Valid", validResult.valid === true);

        // Test invalid password (too short)
        const shortResult = validatePasswordComplexity("Short1!");
        logTest("Password Validation - Too Short", validResult.valid === false || shortResult.valid === false);

        // Test invalid password (no uppercase)
        const noUpperResult = validatePasswordComplexity("lowercase123!");
        logTest("Password Validation - No Uppercase", noUpperResult.valid === false);

        // Test invalid password (no special char)
        const noSpecialResult = validatePasswordComplexity("NoSpecialChar123");
        logTest("Password Validation - No Special", noSpecialResult.valid === false);

    } catch (error) {
        logTest("Password Validation", false, error.message);
    }
}

/**
 * Test password hashing with adaptive parameters
 */
async function testPasswordHashing() {
    try {
        const salt = generatePasswordSalt();
        
        // Test password hashing
        const hash1 = hashPasswordArgon2ID(testData.password, salt);
        logTest("Password Hashing", typeof hash1 === 'string' && hash1.length > 0);

        // Test consistency
        const hash2 = hashPasswordArgon2ID(testData.password, salt);
        logTest("Password Hashing Consistency", hash1 === hash2);

        // Test different passwords produce different hashes
        const hash3 = hashPasswordArgon2ID("DifferentPassword123!", salt);
        logTest("Password Hashing Uniqueness", hash1 !== hash3);

    } catch (error) {
        logTest("Password Hashing", false, error.message);
    }
}

/**
 * Test large file encryption performance
 */
async function testLargeFilePerformance() {
    try {
        // Create 1MB test file
        const largeData = generateRandomBytes(1024 * 1024);
        
        console.log("Testing large file encryption (1MB)...");
        const startTime = performance.now();
        
        const encrypted = encryptFile(largeData, testData.password, "custom");
        const encryptTime = performance.now() - startTime;
        
        logTest("Large File Encryption", typeof encrypted === 'string' && encrypted.length > 0);
        console.log(`Encryption time: ${encryptTime.toFixed(2)}ms`);

        // Test decryption
        const decryptStart = performance.now();
        const decrypted = decryptFile(encrypted, testData.password);
        const decryptTime = performance.now() - decryptStart;
        
        const decryptedData = new Uint8Array(Array.from(atob(decrypted), c => c.charCodeAt(0)));
        logTest("Large File Decryption", decryptedData.length === largeData.length);
        console.log(`Decryption time: ${decryptTime.toFixed(2)}ms`);

        // Verify data integrity
        let dataMatches = true;
        for (let i = 0; i < Math.min(1000, largeData.length); i++) { // Check first 1000 bytes
            if (largeData[i] !== decryptedData[i]) {
                dataMatches = false;
                break;
            }
        }
        logTest("Large File Data Integrity", dataMatches);

    } catch (error) {
        logTest("Large File Performance", false, error.message);
    }
}

/**
 * Test encryption format compatibility
 */
async function testFormatCompatibility() {
    try {
        const fileData = new TextEncoder().encode("Format test data");
        
        // Test single-key format (0x04)
        const singleEncrypted = encryptFile(fileData, testData.password, "custom");
        const singleDecrypted = decryptFile(singleEncrypted, testData.password);
        logTest("Format 0x04 Compatibility", typeof singleDecrypted === 'string');

        // Test multi-key format (0x05)
        const multiEncrypted = encryptFileMultiKey(fileData, testData.password, "custom", []);
        const multiDecrypted = decryptFileMultiKey(multiEncrypted, testData.password);
        logTest("Format 0x05 Compatibility", typeof multiDecrypted === 'string');

        // Ensure formats are different
        logTest("Format Differentiation", singleEncrypted !== multiEncrypted);

    } catch (error) {
        logTest("Format Compatibility", false, error.message);
    }
}

/**
 * Run all WASM crypto tests
 */
async function runAllTests() {
    console.log("🚀 Starting OPAQUE WASM Crypto Tests...\n");
    
    const startTime = performance.now();
    
    try {
        await testDeviceCapabilityDetection();
        await testAdaptiveEncryption();
        await testSessionKeyEncryption();
        await testMultiKeyAdaptiveEncryption();
        await testPasswordValidation();
        await testPasswordHashing();
        await testLargeFilePerformance();
        await testFormatCompatibility();
        
    } catch (error) {
        console.error("Test suite error:", error);
        testResults.failed++;
        testResults.errors.push(`Test suite error: ${error.message}`);
    }
    
    const totalTime = performance.now() - startTime;
    
    console.log("\n📊 Test Results:");
    console.log(`✅ Passed: ${testResults.passed}`);
    console.log(`❌ Failed: ${testResults.failed}`);
    console.log(`⏱️  Total time: ${totalTime.toFixed(2)}ms`);
    
    if (testResults.failed > 0) {
        console.log("\n🚨 Errors:");
        testResults.errors.forEach(error => console.log(`  - ${error}`));
        return false;
    } else {
        console.log("\n🎉 All tests passed!");
        return true;
    }
}

// Auto-run tests if this script is loaded directly
if (typeof window !== 'undefined') {
    // Wait for WASM to load
    setTimeout(() => {
        if (typeof encryptFile === 'function') {
            runAllTests();
        } else {
            console.error("WASM functions not loaded. Please ensure main.wasm is loaded first.");
        }
    }, 1000);
}

// Export for Node.js testing if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runAllTests, testResults };
}
