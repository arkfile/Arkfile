#!/usr/bin/env bun

/**
 * File Encryption WASM Integration Tests (Bun Version)
 *
 * This test suite validates the password-based file encryption, decryption,
 * and metadata handling functions exposed by the Go WASM module. It ensures
 * that the client-side encryption logic is consistent and secure.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import "../../src/types/wasm.d.ts";

// Mock browser APIs for non-browser environment
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
        subtle: {} as SubtleCrypto,
    } as Crypto;
}

// Type-safe declarations for all WASM functions under test
declare global {
    function storePasswordForUser(username: string, password_string: string): { success: boolean, message: string };
    function clearPasswordForUser(username: string): { success: boolean, message: string };
    function calculateSHA256(data: Uint8Array): string;

    function encryptFilePassword(
        fileData: Uint8Array,
        username: string,
        keyType: "account" | "custom",
        customPassword?: string
    ): { success: boolean, data: string, error?: string };

    function decryptFilePassword(
        encryptedData: string,
        username: string,
        customPassword?: string
    ): { success: boolean, data: string, error?: string };
    
    function encryptFileChunkedPassword(
        fileData: Uint8Array,
        username: string,
        keyType: "account" | "custom",
        chunkSize: number,
        customPassword?: string
    ): {
        success: boolean,
        envelope?: string,
        chunks?: { data: string, hash: string, size: number }[],
        totalChunks?: number,
        error?: string
    };

    function decryptFileChunkedPassword(
        encryptedData: string,
        username: string,
        customPassword?: string
    ): { success: boolean, data: string, error?: string };

    function encryptFileMetadata(
        filename: string,
        sha256sum: string,
        username: string
    ): {
        success: boolean,
        filenameNonce?: string,
        encryptedFilename?: string,
        sha256Nonce?: string,
        encryptedSha256sum?: string,
        error?: string
    };

    function decryptFileMetadata(
        filenameNonce: string,
        encryptedFilename: string,
        sha256Nonce: string,
        encryptedSha256sum: string,
        username: string
    ): { success: boolean, filename?: string, sha256sum?: string, error?: string };
}


// WASM module management_
let wasmLoaded = false;
async function loadWASMModule(): Promise<void> {
    if (wasmLoaded) return;
    try {
        const wasmPath = join(__dirname, '..', '..', '..', 'main.wasm');
        if (!existsSync(wasmPath)) {
            console.warn('WASM file not found, tests will be skipped.');
            return;
        }

        const wasmExecPath = join(__dirname, '..', '..', '..', '..', 'wasm_exec.js');
        if (!existsSync(wasmExecPath)) {
            console.warn('wasm_exec.js not found, tests will be skipped.');
            return;
        }

        const wasmBytes = readFileSync(wasmPath);
        const wasmExecCode = readFileSync(wasmExecPath, 'utf-8');
        eval(wasmExecCode);

        const go = new (globalThis as any).Go();
        const result = await WebAssembly.instantiate(wasmBytes, go.importObject);
        go.run(result.instance);

        await new Promise(resolve => setTimeout(resolve, 100)); // Short delay for init
        wasmLoaded = true;
        console.log("Go WASM Module Loaded Successfully");
    } catch (e) {
        console.error("Failed to load WASM module:", e);
    }
}

// Helper to get a WASM function or a mock if WASM fails to load.
function getWASMFunction<T extends (...args: any[]) => any>(fnName: keyof typeof globalThis): T {
    const fn = (globalThis as any)[fnName];
    if (typeof fn === 'function') {
        return fn as T;
    }
    // Return a mock function that reports an error if WASM isn't loaded
    return ((...args: any[]) => {
        return { success: false, error: `WASM function '${String(fnName)}' is not available.` };
    }) as T;
}


describe("File Encryption WASM Tests", () => {
    const username = "test-user";
    const accountPassword = "secure-account-password-123!";
    const customPassword = "extra-secure-custom-password-456$";
    const fileContent = "This is a secret file for testing purposes.";
    const fileData = new TextEncoder().encode(fileContent);

    beforeAll(async () => {
        console.log("Starting File Encryption WASM Tests...");
        await loadWASMModule();

        if (wasmLoaded) {
            const storePass = getWASMFunction<typeof globalThis.storePasswordForUser>('storePasswordForUser');
            const result = storePass(username, accountPassword);
            expect(result.success).toBe(true);
        }
    });

    afterAll(() => {
        if (wasmLoaded) {
            const clearPass = getWASMFunction<typeof globalThis.clearPasswordForUser>('clearPasswordForUser');
            clearPass(username);
        }
        console.log("File Encryption WASM Tests Completed.");
    });

    /**
     * Test single-chunk file encryption and decryption.
     */
    test("should correctly encrypt and decrypt a file with an account password", () => {
        if (!wasmLoaded) {
            console.warn("WASM module not loaded, skipping test.");
            return;
        }

        const encrypt = getWASMFunction<typeof globalThis.encryptFilePassword>('encryptFilePassword');
        const decrypt = getWASMFunction<typeof globalThis.decryptFilePassword>('decryptFilePassword');

        // Encrypt with account password
        const encResult = encrypt(fileData, username, "account");
        expect(encResult.success).toBe(true);
        expect(encResult.data).toBeString();

        // Decrypt and verify
        const decResult = decrypt(encResult.data, username);
        expect(decResult.success).toBe(true);
        const decryptedContent = new TextDecoder().decode(Buffer.from(decResult.data, 'base64'));
        expect(decryptedContent).toBe(fileContent);
    });

    test("should correctly encrypt and decrypt a file with a custom password", () => {
        if (!wasmLoaded) return;
        const encrypt = getWASMFunction<typeof globalThis.encryptFilePassword>('encryptFilePassword');
        const decrypt = getWASMFunction<typeof globalThis.decryptFilePassword>('decryptFilePassword');
        
        // Encrypt with custom password
        const encResult = encrypt(fileData, username, "custom", customPassword);
        expect(encResult.success).toBe(true);
        expect(encResult.data).toBeString();

        // Decrypt and verify
        const decResult = decrypt(encResult.data, username, customPassword);
        expect(decResult.success).toBe(true);
        const decryptedContent = new TextDecoder().decode(Buffer.from(decResult.data, 'base64'));
        expect(decryptedContent).toBe(fileContent);
    });

    /**
     * Test chunked file encryption and decryption.
     */
    test("should correctly encrypt and decrypt a chunked file with an account password", () => {
        if (!wasmLoaded) return;
        const encrypt = getWASMFunction<typeof globalThis.encryptFileChunkedPassword>('encryptFileChunkedPassword');
        const decrypt = getWASMFunction<typeof globalThis.decryptFileChunkedPassword>('decryptFileChunkedPassword');
        const chunkSize = 16;
        
        const encResult = encrypt(fileData, username, "account", chunkSize);
        expect(encResult.success).toBe(true);
        expect(encResult.chunks?.length).toBeGreaterThan(1);
        
        // Reassemble the file from chunks for decryption
        const envelope = Buffer.from(encResult.envelope!, 'base64');
        const encryptedChunks = encResult.chunks!.map(chunk => Buffer.from(chunk.data, 'base64'));
        const reassembledData = Buffer.concat([envelope, ...encryptedChunks]);
        
        const decResult = decrypt(reassembledData.toString('base64'), username);
        expect(decResult.success).toBe(true);
        
        const decryptedContent = new TextDecoder().decode(Buffer.from(decResult.data, 'base64'));
        expect(decryptedContent).toBe(fileContent);
    });


    /**
     * Test metadata encryption and decryption.
     */
    test("should correctly encrypt and decrypt file metadata", () => {
        if (!wasmLoaded) return;
        const encryptMeta = getWASMFunction<typeof globalThis.encryptFileMetadata>('encryptFileMetadata');
        const decryptMeta = getWASMFunction<typeof globalThis.decryptFileMetadata>('decryptFileMetadata');
        const sha256 = getWASMFunction<typeof globalThis.calculateSHA256>('calculateSHA256');

        const filename = "test-document.txt";
        const sha256sum = sha256(fileData);

        const encResult = encryptMeta(filename, sha256sum, username);
        expect(encResult.success).toBe(true);

        const decResult = decryptMeta(
            encResult.filenameNonce!,
            encResult.encryptedFilename!,
            encResult.sha256Nonce!,
            encResult.encryptedSha256sum!,
            username
        );

        expect(decResult.success).toBe(true);
        expect(decResult.filename).toBe(filename);
        expect(decResult.sha256sum).toBe(sha256sum);
    });

    /**
     * Test failure cases.
     */
    test("should fail decryption with the wrong password", () => {
        if (!wasmLoaded) return;
        const encrypt = getWASMFunction<typeof globalThis.encryptFilePassword>('encryptFilePassword');
        const decrypt = getWASMFunction<typeof globalThis.decryptFilePassword>('decryptFilePassword');

        const encResult = encrypt(fileData, username, "custom", customPassword);
        expect(encResult.success).toBe(true);

        // Attempt decryption with wrong password
        const decResult = decrypt(encResult.data, username, "wrong-password");
        expect(decResult.success).toBe(false);
        expect(decResult.error).toContain("Failed to decrypt");
    });
});
