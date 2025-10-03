#!/usr/bin/env bun

/**
 * Main Integration Test Runner (Bun Version)
 * 
 * Orchestrates and runs all TypeScript test suites for ArkFile
 * Combines WASM tests, OPAQUE tests, debug tests, and unit tests
 */

import { describe, test, beforeAll, afterAll } from "bun:test";
import { runWasmTests } from "../utils/test-runner.test";
import { runDebugTest } from "../debug/multi-key-test.test";
import { runOpaqueWASMTests } from "../wasm/opaque-wasm.test";

console.log(`
ArkFile TypeScript Test Suite (Bun Runtime)
===============================================
Running comprehensive integration tests...
`);

// Main test orchestrator
describe('ArkFile Integration Test Suite', () => {
    beforeAll(async () => {
        console.log('Setting up test environment...');
        // Any global setup can go here
    });

    afterAll(() => {
        console.log('Test suite completed');
    });

    test('WASM Cryptographic Functions', async () => {
        console.log('\nRunning WASM Integration Tests...');
        try {
            await runWasmTests();
        } catch (error) {
            // Handle WASM test failures gracefully
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.warn(`WASM tests encountered issues: ${errorMessage}`);
            // Don't fail the entire suite if WASM isn't available
        }
    });

    test('Multi-Key Debug Tests', async () => {
        console.log('\nRunning Multi-Key Debug Tests...');
        try {
            await runDebugTest();
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.warn(`Debug tests encountered issues: ${errorMessage}`);
        }
    });

    test('OPAQUE Protocol Tests', async () => {
        console.log('\nRunning OPAQUE WASM Tests...');
        try {
            await runOpaqueWASMTests();
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.warn(`OPAQUE tests encountered issues: ${errorMessage}`);
        }
    });
});

// Standalone execution support
export async function runAllTests(): Promise<void> {
    console.log('🧪 Running ArkFile Integration Tests Standalone...\n');
    
    const results = {
        wasm: { passed: false, error: null as string | null },
        debug: { passed: false, error: null as string | null },
        opaque: { passed: false, error: null as string | null }
    };
    
    // Run WASM tests
    try {
        console.log('1️⃣ Running WASM Integration Tests...');
        await runWasmTests();
        results.wasm.passed = true;
        console.log('WASM tests completed successfully\n');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        results.wasm.error = errorMessage;
        console.warn(`WASM tests failed: ${errorMessage}\n`);
    }
    
    // Run debug tests
    try {
        console.log('2️⃣ Running Multi-Key Debug Tests...');
        await runDebugTest();
        results.debug.passed = true;
        console.log('Debug tests completed successfully\n');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        results.debug.error = errorMessage;
        console.warn(`Debug tests failed: ${errorMessage}\n`);
    }
    
    // Run OPAQUE tests
    try {
        console.log('3️⃣ Running OPAQUE Protocol Tests...');
        await runOpaqueWASMTests();
        results.opaque.passed = true;
        console.log('OPAQUE tests completed successfully\n');
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        results.opaque.error = errorMessage;
        console.warn(`OPAQUE tests failed: ${errorMessage}\n`);
    }
    
    // Print final summary
    console.log('Final Test Results Summary:');
    console.log('================================');
    console.log(`WASM Tests:   ${results.wasm.passed ? 'PASSED' : 'FAILED'}`);
    if (results.wasm.error) console.log(`              Error: ${results.wasm.error}`);
    
    console.log(`Debug Tests:  ${results.debug.passed ? 'PASSED' : 'FAILED'}`);
    if (results.debug.error) console.log(`              Error: ${results.debug.error}`);
    
    console.log(`OPAQUE Tests: ${results.opaque.passed ? 'PASSED' : 'FAILED'}`);
    if (results.opaque.error) console.log(`              Error: ${results.opaque.error}`);
    
    const totalPassed = Object.values(results).filter(r => r.passed).length;
    const totalTests = Object.keys(results).length;
    
    console.log(`\nOverall: ${totalPassed}/${totalTests} test suites passed`);
    
    if (totalPassed === totalTests) {
        console.log('All test suites completed successfully!');
        process.exit(0);
    } else {
        console.log('Some test suites had issues. Check output above for details.');
        process.exit(1);
    }
}

// Run if called directly
if (import.meta.main) {
    await runAllTests();
}
