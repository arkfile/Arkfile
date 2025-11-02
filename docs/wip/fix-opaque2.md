# Zero-Knowledge OPAQUE Implementation - Comprehensive Refactoring Plan v2

**Status**: Planning Phase - Enhanced with Critical Security Findings  
**Priority**: CRITICAL - Security Architecture Overhaul Required  
**Complexity**: High - Multi-layer refactoring with protocol compliance

---

> ## ⚠️ MANDATORY: READ BEFORE ANY WORK
> 
> **ALL AGENTIC CODING AGENTS MUST READ `docs/AGENTS.md` BEFORE STARTING OR CONTINUING ANY WORK ON THIS PROJECT.**
>
> This document contains critical project guidelines, coding standards, architectural principles, and security requirements that are MANDATORY for all contributors.
>
> **PROJECT STATUS**: This is a **GREENFIELD APPLICATION** with **NO PRODUCTION DEPLOYMENTS**. We can implement the correct zero-knowledge OPAQUE protocol directly without backward compatibility concerns.

---

## CRITICAL PRIORITY RANKING

### 🔴 PRIORITY 1: PROTOCOL-BREAKING ISSUES (Must Fix First)

1. **Server Key Generation is Fundamentally Broken** ⚠️ CRITICAL
   - **Location**: `auth/opaque.go` - `generateOPAQUEServerKeys()`
   - **Problem**: Using random bytes instead of proper cryptographic key derivation
   - **Impact**: Breaks OPAQUE protocol, authentication will fail or be insecure
   - **Fix**: Use libsodium's `crypto_scalarmult_base()` to derive public key from private key

2. **CGO in Browser WASM is Not Viable** ⚠️ CRITICAL
   - **Location**: `crypto/wasm_shim.go` - All WASM exports
   - **Problem**: Go's WASM target does not support CGO to native C in browser
   - **Impact**: Current architecture cannot work in browser
   - **Fix**: Compile libopaque to WebAssembly via Emscripten OR use Rust OPAQUE implementation

3. **Missing OPRF Seed Usage** ⚠️ CRITICAL
   - **Location**: `auth/opaque.go` - Server keys structure
   - **Problem**: OPRF seed generated but never used in protocol
   - **Impact**: Password hashing may not be truly oblivious, could leak information
   - **Fix**: Pass OPRF seed to libopaque's registration and authentication functions

### 🟠 PRIORITY 2: SECURITY-CRITICAL ISSUES

4. **Export Key vs Session Key Semantic Confusion** ⚠️ HIGH
   - **Location**: `auth/opaque_wrapper.c`, throughout codebase
   - **Problem**: Function parameters named `session_key` but return `export_key`
   - **Impact**: Incorrect key usage, potential session replay vulnerabilities
   - **Fix**: Clarify semantics, separate export_key (deterministic) from session_key (ephemeral)

5. **Simplified Identity Structure Weakens Security** ⚠️ HIGH
   - **Location**: `auth/opaque_wrapper.c` - All functions
   - **Problem**: Hardcoded generic identities ("user", "server") for all users
   - **Impact**: Violates protocol design, enables cross-user attacks
   - **Fix**: Use actual usernames and server identifiers in Opaque_Ids structure

6. **Missing Channel/Context Binding** ⚠️ HIGH
   - **Location**: All CGO prototypes
   - **Problem**: No IdU/IdS or context inputs to prevent unknown key-share attacks
   - **Impact**: Protocol vulnerable to mix-up attacks
   - **Fix**: Add explicit parameters for IdU, IdS, and context; verify consistently

7. **Export Key Storage Policy Too Weak** ⚠️ HIGH
   - **Location**: `client/static/js/src/utils/wasm.ts`
   - **Problem**: sessionStorage exposes export_key to XSS attacks
   - **Impact**: Complete compromise of zero-knowledge properties
   - **Fix**: Keep export_key in-memory only, never in Web Storage

### 🟡 PRIORITY 3: IMPLEMENTATION GAPS

8. **Server-Side State Encryption Unspecified**
   - **Location**: `database/database.go` - `encryptServerSecret()`
   - **Problem**: No specification of algorithm, master key source, or rotation
   - **Impact**: Operational risk, potential key compromise
   - **Fix**: Specify XChaCha20-Poly1305 with systemd-credentials master key

9. **Incomplete Export Key Validation**
   - **Location**: `models/user.go` - `ValidateOPAQUEExportKey()`
   - **Problem**: Only checks length and not-all-zeros
   - **Impact**: Could accept low-entropy or malformed keys
   - **Fix**: Add entropy check, proper derivation verification

10. **TOTP Design Conflicts with Zero-Knowledge Goals**
    - **Location**: TOTP integration throughout
    - **Problem**: Unclear whether TOTP uses server-managed keys or export_key binding
    - **Impact**: Ambiguous zero-knowledge claims
    - **Fix**: Choose server-managed TOTP with per-user derivation (recommended)

---

## Executive Summary

This document outlines the complete refactoring plan to migrate from the current **broken** "OPAQUE-inspired" password storage implementation to a **true zero-knowledge OPAQUE protocol implementation** that is RFC-compliant, secure, and privacy-preserving.

### Current State: FUNDAMENTALLY BROKEN

The existing implementation has **critical security flaws**:

1. **Passwords sent to server in plaintext** - Defeats zero-knowledge entirely
2. **Server keys generated incorrectly** - Random bytes instead of proper derivation
3. **WASM architecture impossible** - CGO doesn't work in browser WASM
4. **OPRF seed unused** - Protocol not truly oblivious
5. **Generic identities** - All users share same protocol identity
6. **No context binding** - Vulnerable to mix-up attacks

### Target State: RFC-Compliant Zero-Knowledge OPAQUE

The refactored system will ensure:

- ✅ **Passwords NEVER leave the client** (not even once)
- ✅ **Server cannot decrypt user files**
- ✅ **Server cannot see original filenames**
- ✅ **Proper cryptographic key derivation**
- ✅ **RFC-compliant OPAQUE protocol**
- ✅ **Browser-compatible WASM architecture**
- ✅ **Per-user identity binding**
- ✅ **Context-bound protocol execution**

### Key Architectural Principles

> **⚠️ CRITICAL: NO CUSTOM CRYPTO**
>
> - **NEVER** roll our own crypto
> - **ALWAYS** use battle-tested libraries: libopaque (C), libsodium
> - **NO** JavaScript/TypeScript for cryptographic operations
> - **JS/TS for UI elements ONLY**
> - **Avoid JavaScript as much as possible**

### Validation Strategy

**Primary validation tool**: `scripts/testing/test-app-curl.sh` must work completely end-to-end.

All Go CLI utilities must be updated in parallel with the core implementation. The browser client is secondary but must share the same crypto core (via WASM or API calls).

---

## PHASE 0: COMPLETE REMOVAL OF BROKEN CODE

> **⚠️ GREENFIELD STATUS**: This is a greenfield application with NO production deployments. We will completely remove all broken OPAQUE code and implement the correct protocol from scratch.

### 0.1 Files to Remove/Rewrite Completely

**Remove these broken implementations**:
- [ ] `auth/opaque.go` - `generateOPAQUEServerKeys()` (broken key generation)
- [ ] `auth/opaque_wrapper.c` - All one-step functions (wrong architecture)
- [ ] `handlers/auth.go` - `OpaqueRegister()`, `OpaqueLogin()` (send passwords to server)
- [ ] `client/static/js/src/auth/register.ts` - Current registration flow
- [ ] `client/static/js/src/auth/login.ts` - Current login flow

**Mark as deprecated in route config**:
```go
// handlers/route_config.go
// REMOVED - INSECURE: Sent password to server
// api.POST("/auth/opaque/register", OpaqueRegister)
// api.POST("/auth/opaque/login", OpaqueLogin)
```

### 0.2 Database Cleanup

**Remove conflicting tables**:
```sql
-- Remove if exists (check schema first)
DROP TABLE IF EXISTS old_opaque_user_data;
```

**Standardize on single source of truth**:
- `opaque_password_records` table with `record_type` enum:
  - `'account'` - User account authentication (one per user)
  - `'file'` - File-specific passwords (multiple per user)
  - `'share'` - Share-specific passwords (multiple per user)

### 0.3 Removal Checklist

- [ ] Remove all functions that accept plaintext passwords from server
- [ ] Remove all one-step OPAQUE functions
- [ ] Remove broken server key generation
- [ ] Remove CGO-based WASM exports (won't work in browser)
- [ ] Remove sessionStorage usage for export_key
- [ ] Remove generic "user"/"server" identity strings
- [ ] Remove any custom crypto implementations
- [ ] Remove any JavaScript crypto operations

---

## PHASE 1: CORRECT SERVER KEY GENERATION

### 1.1 Fix Server Key Generation (CRITICAL)

**Location**: `auth/opaque.go`

**Current (BROKEN)**:
```go
// WRONG - Random bytes have no cryptographic relationship
serverPrivateKey := crypto.GenerateRandomBytes(serverPrivateKeySize)
serverPublicKey := crypto.GenerateRandomBytes(serverPublicKeySize)
```

**Correct Implementation**:
```go
// Generate server private key (32 bytes for Curve25519)
serverPrivateKey := make([]byte, 32)
if _, err := rand.Read(serverPrivateKey); err != nil {
    return nil, fmt.Errorf("failed to generate server private key: %w", err)
}

// Derive server public key using scalar multiplication
// This MUST be mathematically derived from the private key
serverPublicKey := make([]byte, 32)
if err := derivePublicKey(serverPublicKey, serverPrivateKey); err != nil {
    return nil, fmt.Errorf("failed to derive server public key: %w", err)
}

// Generate OPRF seed (used in OPAQUE protocol)
oprfSeed := make([]byte, 32)
if _, err := rand.Read(oprfSeed); err != nil {
    return nil, fmt.Errorf("failed to generate OPRF seed: %w", err)
}
```

**Add CGO wrapper for key derivation**:
```go
// auth/opaque_cgo.go

/*
#include <sodium.h>

int derive_public_key(uint8_t *public_key, const uint8_t *private_key) {
    return crypto_scalarmult_base(public_key, private_key);
}
*/
import "C"

func derivePublicKey(publicKey, privateKey []byte) error {
    if len(publicKey) != 32 || len(privateKey) != 32 {
        return fmt.Errorf("invalid key sizes")
    }
    
    ret := C.derive_public_key(
        (*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
        (*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
    )
    
    if ret != 0 {
        return fmt.Errorf("key derivation failed: %d", ret)
    }
    
    return nil
}
```

### 1.2 Server Key Storage and Rotation

**Master Key Provisioning** (via systemd-credentials):

```go
// config/security_config.go

// LoadServerMasterKey loads the master key for encrypting server secrets
func LoadServerMasterKey() ([]byte, error) {
    // Preferred: systemd-credentials
    if key, err := loadFromSystemdCredentials("arkfile-master-key"); err == nil {
        return key, nil
    }
    
    // Fallback: environment variable (development only)
    if keyB64 := os.Getenv("ARKFILE_MASTER_KEY"); keyB64 != "" {
        return base64.StdEncoding.DecodeString(keyB64)
    }
    
    return nil, fmt.Errorf("no master key found")
}

func loadFromSystemdCredentials(name string) ([]byte, error) {
    // Read from /run/credentials/arkfile.service/<name>
    path := fmt.Sprintf("/run/credentials/arkfile.service/%s", name)
    return os.ReadFile(path)
}
```

**Encryption of Server Secrets**:

```go
// crypto/server_secrets.go

// EncryptServerSecret encrypts server secrets (rsec, ssec) for database storage
func EncryptServerSecret(plaintext, masterKey []byte, sessionID, username string) ([]byte, error) {
    // Use XChaCha20-Poly1305 for encryption
    aead, err := chacha20poly1305.NewX(masterKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }
    
    // Generate random nonce (24 bytes for XChaCha20)
    nonce := make([]byte, chacha20poly1305.NonceSizeX)
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    // Additional authenticated data (AAD)
    aad := []byte(fmt.Sprintf("session:%s:user:%s", sessionID, username))
    
    // Encrypt
    ciphertext := aead.Seal(nil, nonce, plaintext, aad)
    
    // Return nonce || ciphertext
    result := append(nonce, ciphertext...)
    return result, nil
}

// DecryptServerSecret decrypts server secrets from database
func DecryptServerSecret(encrypted, masterKey []byte, sessionID, username string) ([]byte, error) {
    if len(encrypted) < chacha20poly1305.NonceSizeX {
        return nil, fmt.Errorf("ciphertext too short")
    }
    
    // Split nonce and ciphertext
    nonce := encrypted[:chacha20poly1305.NonceSizeX]
    ciphertext := encrypted[chacha20poly1305.NonceSizeX:]
    
    // Create cipher
    aead, err := chacha20poly1305.NewX(masterKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }
    
    // Additional authenticated data (AAD)
    aad := []byte(fmt.Sprintf("session:%s:user:%s", sessionID, username))
    
    // Decrypt
    plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }
    
    return plaintext, nil
}
```

**Key Rotation Policy**:

```markdown
## Server Key Rotation

**WARNING**: Rotating server keys invalidates ALL existing user registrations.

**Rotation Procedure**:
1. Schedule maintenance window
2. Export all user data
3. Generate new server keys
4. Force all users to re-register
5. Update documentation

**Rotation Frequency**: Only on security breach or major version upgrade.
```

### 1.3 OPRF Seed Integration

**Update C wrapper to use OPRF seed**:

```c
// auth/opaque_wrapper.h

// Registration with OPRF seed
int arkfile_opaque_create_registration_response_with_seed(
    const uint8_t *M,
    const uint8_t *server_private_key,
    const uint8_t *oprf_seed,
    uint8_t *rsec,
    uint8_t *rpub
);

// Authentication with OPRF seed
int arkfile_opaque_create_credential_response_with_seed(
    const uint8_t *pub,
    const uint8_t *rec,
    const uint8_t *oprf_seed,
    uint8_t *resp,
    uint8_t *sk,
    uint8_t *authU
);
```

**Update Go wrappers**:

```go
// auth/opaque_cgo.go

func libopaqueCreateRegistrationResponse(M, serverPrivateKey, oprfSeed []byte) ([]byte, []byte, error) {
    rsec := make([]byte, OPAQUE_REGISTER_SECRET_LEN)
    rpub := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)
    
    ret := C.arkfile_opaque_create_registration_response_with_seed(
        (*C.uint8_t)(unsafe.Pointer(&M[0])),
        (*C.uint8_t)(unsafe.Pointer(&serverPrivateKey[0])),
        (*C.uint8_t)(unsafe.Pointer(&oprfSeed[0])),
        (*C.uint8_t)(unsafe.Pointer(&rsec[0])),
        (*C.uint8_t)(unsafe.Pointer(&rpub[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("registration response failed: %d", ret)
    }
    
    return rsec, rpub, nil
}
```

---

## PHASE 2: BROWSER-COMPATIBLE WASM ARCHITECTURE

### 2.1 The CGO Problem

**Current Architecture (BROKEN)**:
```
Go (crypto/wasm_shim.go) --CGO--> libopaque.so --X--> Browser WASM
                                                   ❌ CGO not supported in browser WASM
```

**Solution Options**:

#### Option A: Emscripten (Recommended)
```
libopaque (C) --Emscripten--> libopaque.wasm + glue.js
                              ↓
TypeScript --calls--> WASM exports --runs in--> Browser
```

#### Option B: Rust OPAQUE
```
opaque-ke (Rust) --wasm-pack--> opaque_wasm.wasm
                                ↓
TypeScript --calls--> WASM exports --runs in--> Browser
```

### 2.2 Emscripten Build Configuration (Option A - Recommended)

**Create build script**: `scripts/setup/build-libopaque-wasm.sh`

```bash
#!/bin/bash
set -e

echo "Building libopaque for WebAssembly..."

# Install Emscripten if not present
if ! command -v emcc &> /dev/null; then
    echo "Installing Emscripten..."
    git clone https://github.com/emscripten-core/emsdk.git /tmp/emsdk
    cd /tmp/emsdk
    ./emsdk install latest
    ./emsdk activate latest
    source ./emsdk_env.sh
fi

# Build libsodium for WASM first
cd /tmp
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
./autogen.sh
emconfigure ./configure --disable-shared
emmake make
emmake make install

# Build libopaque for WASM
cd /tmp
git clone https://github.com/stef/libopaque.git
cd libopaque
emmake make

# Create WASM module with exported functions
emcc -O3 \
    -s WASM=1 \
    -s EXPORTED_FUNCTIONS='["_opaque_CreateRegistrationRequest", "_opaque_FinalizeRequest", "_opaque_CreateCredentialRequest", "_opaque_RecoverCredentials"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='createOpaqueModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -I/tmp/libsodium/src/libsodium/include \
    -L/tmp/libsodium/src/libsodium/.libs \
    -lopaque -lsodium \
    -o client/static/js/lib/opaque.js

echo "WASM build complete: client/static/js/lib/opaque.js"
echo "WASM binary: client/static/js/lib/opaque.wasm"
```

### 2.3 TypeScript WASM Interface

**Create WASM module wrapper**: `client/static/js/src/crypto/opaque-wasm.ts`

```typescript
// Type definitions for Emscripten module
interface OpaqueModule {
    ccall: (
        name: string,
        returnType: string,
        argTypes: string[],
        args: any[]
    ) => any;
    
    _malloc: (size: number) => number;
    _free: (ptr: number) => void;
    HEAPU8: Uint8Array;
}

let opaqueModule: OpaqueModule | null = null;

// Load WASM module
export async function initOpaqueWasm(): Promise<void> {
    if (opaqueModule) return;
    
    // @ts-ignore - Emscripten generated module
    const createOpaqueModule = (await import('../lib/opaque.js')).default;
    opaqueModule = await createOpaqueModule();
}

// Helper to allocate and copy bytes to WASM memory
function allocateBytes(bytes: Uint8Array): number {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    const ptr = opaqueModule._malloc(bytes.length);
    opaqueModule.HEAPU8.set(bytes, ptr);
    return ptr;
}

// Helper to read bytes from WASM memory
function readBytes(ptr: number, length: number): Uint8Array {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    return new Uint8Array(opaqueModule.HEAPU8.buffer, ptr, length);
}

// Helper to securely zero memory
function secureZero(ptr: number, length: number): void {
    if (!opaqueModule) return;
    
    for (let i = 0; i < length; i++) {
        opaqueModule.HEAPU8[ptr + i] = 0;
    }
}

// Registration Step 1: Create registration request
export async function createRegistrationRequest(
    password: Uint8Array
): Promise<{ usrCtx: Uint8Array; M: Uint8Array }> {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    const passwordPtr = allocateBytes(password);
    const usrCtxPtr = opaqueModule._malloc(128); // OPAQUE_USER_SESSION_SECRET_LEN
    const MPtr = opaqueModule._malloc(32); // crypto_core_ristretto255_BYTES
    
    try {
        const ret = opaqueModule.ccall(
            'opaque_CreateRegistrationRequest',
            'number',
            ['number', 'number', 'number', 'number'],
            [passwordPtr, password.length, usrCtxPtr, MPtr]
        );
        
        if (ret !== 0) {
            throw new Error(`Registration request failed: ${ret}`);
        }
        
        const usrCtx = new Uint8Array(readBytes(usrCtxPtr, 128));
        const M = new Uint8Array(readBytes(MPtr, 32));
        
        return { usrCtx, M };
        
    } finally {
        // Securely zero password from WASM memory
        secureZero(passwordPtr, password.length);
        opaqueModule._free(passwordPtr);
        opaqueModule._free(usrCtxPtr);
        opaqueModule._free(MPtr);
    }
}

// Registration Step 2: Finalize registration
export async function finalizeRegistration(
    usrCtx: Uint8Array,
    rpub: Uint8Array
): Promise<{ recU: Uint8Array; exportKey: Uint8Array }> {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    const usrCtxPtr = allocateBytes(usrCtx);
    const rpubPtr = allocateBytes(rpub);
    const recUPtr = opaqueModule._malloc(192); // OPAQUE_REGISTRATION_RECORD_LEN
    const exportKeyPtr = opaqueModule._malloc(64); // crypto_hash_sha512_BYTES
    
    try {
        const ret = opaqueModule.ccall(
            'opaque_FinalizeRequest',
            'number',
            ['number', 'number', 'number', 'number'],
            [usrCtxPtr, rpubPtr, recUPtr, exportKeyPtr]
        );
        
        if (ret !== 0) {
            throw new Error(`Finalize request failed: ${ret}`);
        }
        
        const recU = new Uint8Array(readBytes(recUPtr, 192));
        const exportKey = new Uint8Array(readBytes(exportKeyPtr, 64));
        
        return { recU, exportKey };
        
    } finally {
        // Securely zero sensitive data
        secureZero(usrCtxPtr, usrCtx.length);
        secureZero(exportKeyPtr, 64);
        opaqueModule._free(usrCtxPtr);
        opaqueModule._free(rpubPtr);
        opaqueModule._free(recUPtr);
        opaqueModule._free(exportKeyPtr);
    }
}

// Authentication Step 1: Create credential request
export async function createCredentialRequest(
    password: Uint8Array
): Promise<{ sec: Uint8Array; pub: Uint8Array }> {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    const passwordPtr = allocateBytes(password);
    const secPtr = opaqueModule._malloc(128); // OPAQUE_USER_SESSION_SECRET_LEN
    const pubPtr = opaqueModule._malloc(32); // OPAQUE_USER_SESSION_PUBLIC_LEN
    
    try {
        const ret = opaqueModule.ccall(
            'opaque_CreateCredentialRequest',
            'number',
            ['number', 'number', 'number', 'number'],
            [passwordPtr, password.length, secPtr, pubPtr]
        );
        
        if (ret !== 0) {
            throw new Error(`Credential request failed: ${ret}`);
        }
        
        const sec = new Uint8Array(readBytes(secPtr, 128));
        const pub = new Uint8Array(readBytes(pubPtr, 32));
        
        return { sec, pub };
        
    } finally {
        // Securely zero password from WASM memory
        secureZero(passwordPtr, password.length);
        opaqueModule._free(passwordPtr);
        opaqueModule._free(secPtr);
        opaqueModule._free(pubPtr);
    }
}

// Authentication Step 2: Recover credentials
export async function recoverCredentials(
    resp: Uint8Array,
    sec: Uint8Array
): Promise<{ sk: Uint8Array; authU: Uint8Array; exportKey: Uint8Array }> {
    if (!opaqueModule) throw new Error('WASM not initialized');
    
    const respPtr = allocateBytes(resp);
    const secPtr = allocateBytes(sec);
    const skPtr = opaqueModule._malloc(64); // OPAQUE_SHARED_SECRETBYTES
    const authUPtr = opaqueModule._malloc(64); // crypto_auth_hmacsha512_BYTES
    const exportKeyPtr = opaqueModule._malloc(64); // crypto_hash_sha512_BYTES
    
    try {
        const ret = opaqueModule.ccall(
            'opaque_RecoverCredentials',
            'number',
            ['number', 'number', 'number', 'number', 'number'],
            [respPtr, secPtr, skPtr, authUPtr, exportKeyPtr]
        );
        
        if (ret !== 0) {
            throw new Error(`Recover credentials failed: ${ret}`);
        }
        
        const sk = new Uint8Array(readBytes(skPtr, 64));
        const authU = new Uint8Array(readBytes(authUPtr, 64));
        const exportKey = new Uint8Array(readBytes(exportKeyPtr, 64));
        
        return { sk, authU, exportKey };
        
    } finally {
        // Securely zero sensitive data
        secureZero(secPtr, sec.length);
        secureZero(skPtr, 64);
        secureZero(exportKeyPtr, 64);
        opaqueModule._free(respPtr);
        opaqueModule._free(secPtr);
        opaqueModule._free(skPtr);
        opaqueModule._free(authUPtr);
        opaqueModule._free(exportKeyPtr);
    }
}
```

### 2.4 Memory Hygiene at JS Boundary

**Password input handling**: `client/static/js/src/utils/password-input.ts`

```typescript
// Secure password input handling
export function getPasswordSecurely(inputElement: HTMLInputElement): Uint8Array {
    // Get password value
    const password = inputElement.value;
    
    // Convert to Uint8Array immediately
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    
    // Clear input field immediately
    inputElement.value = '';
    inputElement.form?.reset();
    
    // Return bytes (caller must zero after use)
    return passwordBytes;
}

// Securely zero Uint8Array
export function secureZeroBytes(bytes: Uint8Array): void {
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
    }
}

// Never log sensitive data
export function sanitizeForLogging(obj: any): any {
    const sanitized = { ...obj };
    const sensitiveKeys = ['password', 'export_key', 'session_key', 'secret', 'token'];
    
    for (const key of Object.keys(sanitized)) {
        if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
            sanitized[key] = '[REDACTED]';
        }
    }
    
    return sanitized;
}
```

---

## PHASE 3: IDENTITY AND CONTEXT BINDING

### 3.1 Opaque_Ids Structure

**Update C wrapper**: `auth/opaque_wrapper.c`

```c
// Create proper identity structure
Opaque_Ids create_opaque_ids(const char *username, const char *server_id) {
    Opaque_Ids ids;
    
    // Client identity (username)
    ids.idU_len = strlen(username);
    ids.idU = (uint8_t*)username;
    
    // Server identity (e.g., "Arkfile v1")
    ids.idS_len = strlen(server_id);
    ids.idS = (uint8_t*)server_id;
    
    return ids;
}

// Updated registration response with proper IDs
int arkfile_opaque_create_registration_response_v2(
    const uint8_t *M,
    const uint8_t *server_private_key,
    const uint8_t *oprf_seed,
    const char *username,
    const char *server_id,
    uint8_t *rsec,
    uint8_t *rpub
) {
    Opaque_Ids ids = create_opaque_ids(username, server_id);
    
    return opaque_CreateRegistrationResponse(
        M,
        server_private_key,
        oprf_seed,
        &ids,
        rsec,
        rpub
    );
}
```

**Update Go wrappers**: `auth/opaque_cgo.go`

```go
func libopaqueCreateRegistrationResponseV2(
    M, serverPrivateKey, oprfSeed []byte,
    username, serverID string,
) ([]byte, []byte, error) {
    rsec := make([]byte, OPAQUE_REGISTER_SECRET_LEN)
    rpub := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)
    
    cUsername := C.CString(username)
    defer C.free(unsafe.Pointer(cUsername))
    
    cServerID := C.CString(serverID)
    defer C.free(unsafe.Pointer(cServerID))
    
    ret := C.arkfile_opaque_create_registration_response_v2(
        (*C.uint8_t)(unsafe.Pointer(&M[0])),
        (*C.uint8_t)(unsafe.Pointer(&serverPrivateKey[0])),
        (*C.uint8_t)(unsafe.Pointer(&oprfSeed[0])),
        cUsername,
        cServerID,
        (*C.uint8_t)(unsafe.Pointer(&rsec[0])),
        (*C.uint8_t)(unsafe.Pointer(&rpub[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("registration response failed: %d", ret)
    }
    
    return rsec, rpub, nil
}
```

### 3.2 Context Binding

**Define application context**: `auth/constants.go`

```go
package auth

const (
    // Server identity for OPAQUE protocol
    ServerIdentity = "Arkfile v1.0"
    
    // Application context for OPAQUE
    ApplicationContext = "arkfile.secure.vault"
    
    // API version for context binding
    APIVersion = "v1"
)

// GetOPAQUEContext returns the full context string for OPAQUE operations
func GetOPAQUEContext() string {
    return fmt.Sprintf("%s:%s", ApplicationContext, APIVersion)
}
```

**Use in all OPAQUE operations**:

```go
// In handlers/auth.go

func OpaqueRegisterStep1(c echo.Context) error {
    // ... validation ...
    
    // Create registration response with proper identity and context
    rsec, rpub, err := provider.CreateRegistrationResponseV2(
        M,
        serverPrivateKey,
        oprfSeed,
        request.Username,        // Client identity
        auth.ServerIdentity,     // Server identity
    )
    
    // ... rest of handler ...
}
```

---

## PHASE 4: EXPORT KEY LIFECYCLE AND STORAGE

### 4.1 In-Memory Only Storage (Zero-Knowledge Compliant)

**Create secure key manager**: `client/static/js/src/crypto/key-manager.ts`

```typescript
// In-memory key storage (never persisted)
class SecureKeyManager {
    private exportKey: Uint8Array | null = null;
    private keyTimestamp: number = 0;
    private readonly KEY_LIFETIME_MS = 30 * 60 * 1000; // 30 minutes
    
    // Store export key in memory
    storeExportKey(key: Uint8Array): void {
        // Clear any existing key
        this.clearExportKey();
        
        // Store new key
        this.exportKey = new Uint8Array(key);
        this.keyTimestamp = Date.now();
        
        // Set up automatic cleanup
        setTimeout(() => this.clearExportKey(), this.KEY_LIFETIME_MS);
    }
    
    // Retrieve export key (with expiry check)
    getExportKey(): Uint8Array | null {
        if (!this.exportKey) return null;
        
        // Check if expired
        if (Date.now() - this.keyTimestamp > this.KEY_LIFETIME_MS) {
            this.clearExportKey();
            return null;
        }
        
        return this.exportKey;
    }
    
    // Securely clear export key
    clearExportKey(): void {
        if (this.exportKey) {
            // Zero out memory
            for (let i = 0; i < this.exportKey.length; i++) {
                this.exportKey[i] = 0;
            }
            this.exportKey = null;
        }
        this.keyTimestamp = 0;
    }
    
    // Check if key is available
    hasExportKey(): boolean {
        return this.getExportKey() !== null;
    }
}

// Singleton instance
const keyManager = new SecureKeyManager();

// Clear on page unload
window.addEventListener('beforeunload', () => {
    keyManager.clearExportKey();
});

// Clear on visibility change (tab switch)
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Optional: clear key when tab is hidden for security
        // keyManager.clearExportKey();
    }
});

export default keyManager;
```

### 4.2 Key Derivation Schedule

**Define key derivation contexts**: `client/static/js/src/crypto/key-derivation.ts`

```typescript
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

// Key derivation contexts (domain separation)
const KDF_CONTEXTS = {
    FILE_ENCRYPTION: 'arkfile.file.encryption.v1',
    METADATA_ENCRYPTION: 'arkfile.metadata.encryption.v1',
    SESSION_AUTH: 'arkfile.session.auth.v1',
    TOTP_BINDING: 'arkfile.totp.binding.v1',
} as const;

// Derive file encryption key from export key
export function deriveFileEncryptionKey(
    exportKey: Uint8Array,
    fileID: string
): Uint8Array {
    const info = new TextEncoder().encode(
        `${KDF_CONTEXTS.FILE_ENCRYPTION}:${fileID}`
    );
    
    return hkdf(sha256, exportKey, undefined, info, 32);
}

// Derive metadata encryption key from export key
export function deriveMetadataKey(
    exportKey: Uint8Array,
    username: string
): Uint8Array {
    const info = new TextEncoder().encode(
        `${KDF_CONTEXTS.METADATA_ENCRYPTION}:${username}`
    );
    
    return hkdf(sha256, exportKey, undefined, info, 32);
}

// Derive session authentication material (never sent to server)
export function deriveSessionAuth(
    exportKey: Uint8Array,
    sessionID: string
): Uint8Array {
    const info = new TextEncoder().encode(
        `${KDF_CONTEXTS.SESSION_AUTH}:${sessionID}`
    );
    
    return hkdf(sha256, exportKey, undefined, info, 32);
}

// Note: TOTP binding is optional and conflicts with zero-knowledge goals
// Recommended: Use server-managed TOTP instead
```

### 4.3 Export Key Validation

**Enhanced validation**: `models/user.go`

```go
// ValidateOPAQUEExportKey validates export key with comprehensive checks
func (u *User) ValidateOPAQUEExportKey(exportKey []byte) error {
    // Check length (OPAQUE export keys are 64 bytes)
    if len(exportKey) != 64 {
        return fmt.Errorf("OPAQUE export key must be exactly 64 bytes, got %d", len(exportKey))
    }
    
    // Check not all zeros
    allZero := true
    for _, b := range exportKey {
        if b != 0 {
            allZero = false
            break
        }
    }
    if allZero {
        return fmt.Errorf("OPAQUE export key cannot be all zeros")
    }
    
    // Check entropy (basic check - at least 50% of bits should be set)
    setBits := 0
    for _, b := range exportKey {
        setBits += bits.OnesCount8(b)
    }
    totalBits := len(exportKey) * 8
    if float64(setBits)/float64(totalBits) < 0.4 || float64(setBits)/float64(totalBits) > 0.6 {
        return fmt.Errorf("OPAQUE export key has suspicious entropy")
    }
    
    return nil
}
```

---

## PHASE 5: TOTP INTEGRATION (SERVER-MANAGED)

### 5.1 TOTP Design Decision

**Recommended Approach**: Server-managed TOTP with per-user derivation

**Rationale**:
- Maintains zero-knowledge for passwords and files
- Operationally robust (no client-side TOTP secret management)
- Standard 2FA implementation
- Does NOT require sending export_key to server

**Alternative (NOT Recommended)**: Export key-bound TOTP
- Requires sending export_key to server (violates zero-knowledge)
- Complex client-side TOTP verification
- Operational challenges

### 5.2 Server-Managed TOTP Implementation

**TOTP master key derivation**: `auth/totp.go`

```go
// DeriveTOTPKey derives a per-user TOTP key from server master key
func DeriveTOTPKey(masterKey []byte, username string) ([]byte, error) {
    // Use HKDF to derive per-user TOTP key
    info := []byte(fmt.Sprintf("arkfile.totp.v1:%s", username))
    
    hkdf := hkdf.New(sha256.New, masterKey, nil, info)
    
    totpKey := make([]byte, 32)
    if _, err := hkdf.Read(totpKey); err != nil {
        return nil, fmt.Errorf("failed to derive TOTP key: %w", err)
    }
    
    return totpKey, nil
}

// EncryptTOTPSecret encrypts TOTP secret for database storage
func EncryptTOTPSecret(secret, totpKey []byte) ([]byte, error) {
    // Use XChaCha20-Poly1305
    aead, err := chacha20poly1305.NewX(totpKey)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }
    
    nonce := make([]byte, chacha20poly1305.NonceSizeX)
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    ciphertext := aead.Seal(nil, nonce, secret, nil)
    
    // Return nonce || ciphertext
    return append(nonce, ciphertext...), nil
}
```

**Update TOTP storage**: `database/unified_schema.sql`

```sql
-- TOTP secrets table (server-managed)
CREATE TABLE IF NOT EXISTS totp_secrets (
    username TEXT PRIMARY KEY,
    encrypted_secret BLOB NOT NULL,
    backup_codes TEXT NOT NULL, -- JSON array of encrypted backup codes
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    is_enabled BOOLEAN DEFAULT 1,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
```

### 5.3 TOTP Flow Integration

**After OPAQUE authentication completes**:

```typescript
// client/static/js/src/auth/login.ts

async function handleLogin(event: Event): Promise<void> {
    // ... OPAQUE authentication steps 1 & 2 ...
    
    // Store export key in memory (NOT sessionStorage)
    keyManager.storeExportKey(step2Result.exportKey);
    
    // Store temp token for TOTP
    sessionStorage.setItem('temp_token', step2Data.temp_token);
    
    // Redirect to TOTP verification
    window.location.href = '/totp-verify.html';
}
```

**TOTP verification does NOT use export_key**:

```typescript
// client/static/js/src/auth/totp-verify.ts

async function verifyTOTP(code: string): Promise<void> {
    const tempToken = sessionStorage.getItem('temp_token');
    
    const response = await fetch('/api/totp/verify', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${tempToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code })
    });
    
    if (!response.ok) {
        throw new Error('TOTP verification failed');
    }
    
    const data = await response.json();
    
    // Store final tokens
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    
    // Clear temp token
    sessionStorage.removeItem('temp_token');
    
    // Export key remains in memory for file operations
    // (retrieved via keyManager.getExportKey())
}
```

---

## PHASE 6: API ENDPOINTS WITH VALIDATION

### 6.1 Input Validation and Size Checks

**Create validation middleware**: `handlers/opaque_validation.go`

```go
package handlers

import (
    "encoding/base64"
    "fmt"
    "net/http"
    
    "github.com/labstack/echo/v4"
)

// OPAQUE message size constants
const (
    MaxRegistrationRequestSize  = 64   // M size
    MaxRegistrationResponseSize = 128  // rpub size
    MaxRegistrationRecordSize   = 256  // recU size
    MaxCredentialRequestSize    = 64   // pub size
    MaxCredentialResponseSize   = 256  // resp size
    MaxAuthTokenSize            = 128  // authU size
)

// ValidateBase64Size validates base64 input and checks decoded size
func ValidateBase64Size(b64Input string, maxSize int, fieldName string) ([]byte, error) {
    // Decode base64
    decoded, err := base64.StdEncoding.DecodeString(b64Input)
    if err != nil {
        return nil, fmt.Errorf("%s: invalid base64 encoding", fieldName)
    }
    
    // Check size
    if len(decoded) > maxSize {
        return nil, fmt.Errorf("%s: size %d exceeds maximum %d", fieldName, len(decoded), maxSize)
    }
    
    if len(decoded) == 0 {
        return nil, fmt.Errorf("%s: cannot be empty", fieldName)
    }
    
    return decoded, nil
}

// ValidateSessionID validates session ID format
func ValidateSessionID(sessionID string) error {
    if len(sessionID) != 32 {
        return fmt.Errorf("invalid session ID length")
    }
    
    // Check if alphanumeric
    for _, c := range sessionID {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            return fmt.Errorf("invalid session ID format")
        }
    }
    
    return nil
}
```

### 6.2 Registration Endpoints with Validation

**Step 1 with validation**: `handlers/auth.go`

```go
func OpaqueRegisterStep1(c echo.Context) error {
    var request OpaqueRegisterStep1Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Validate username
    if err := utils.ValidateUsername(request.Username); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid username: "+err.Error())
    }
    
    // Validate M (registration request from client)
    M, err := ValidateBase64Size(request.M, MaxRegistrationRequestSize, "M")
    if err != nil {
        logging.ErrorLogger.Printf("Invalid M from %s: %v", request.Username, err)
        return echo.NewHTTPError(http.StatusBadRequest, err.Error())
    }
    
    // Check if user already exists
    _, err = models.GetUserByUsername(database.DB, request.Username)
    if err == nil {
        return echo.NewHTTPError(http.StatusConflict, "Username already registered")
    }
    
    // Get server keys
    provider := auth.GetOPAQUEProvider()
    _, serverPrivateKey, oprfSeed, err := provider.GetServerKeysWithSeed()
    if err != nil {
        logging.ErrorLogger.Printf("Failed to get server keys: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
    }
    
    // Create registration response with proper identity binding
    rsec, rpub, err := provider.CreateRegistrationResponseV2(
        M,
        serverPrivateKey,
        oprfSeed,
        request.Username,
        auth.ServerIdentity,
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to create registration response: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Generate cryptographically random session ID
    sessionID := crypto.GenerateRandomString(32)
    
    // Encrypt and store server secret (rsec)
    masterKey, err := config.LoadServerMasterKey()
    if err != nil {
        logging.ErrorLogger.Printf("Failed to load master key: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
    }
    
    encryptedRsec, err := crypto.EncryptServerSecret(rsec, masterKey, sessionID, request.Username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to encrypt server secret: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Store session with 5-minute expiry
    expiresAt := time.Now().Add(5 * time.Minute)
    if err := database.StoreOPAQUESession(database.DB, sessionID, request.Username, "registration", encryptedRsec, expiresAt); err != nil {
        logging.ErrorLogger.Printf("Failed to store OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Clear sensitive data from memory
    crypto.SecureZeroBytes(rsec)
    crypto.SecureZeroBytes(masterKey)
    
    logging.InfoLogger.Printf("OPAQUE registration step 1 completed for: %s", request.Username)
    
    return c.JSON(http.StatusOK, OpaqueRegisterStep1Response{
        SessionID: sessionID,
        Rpub:      base64.StdEncoding.EncodeToString(rpub),
    })
}
```

**Step 2 with validation**:

```go
func OpaqueRegisterStep2(c echo.Context) error {
    var request OpaqueRegisterStep2Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Validate session ID
    if err := ValidateSessionID(request.SessionID); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid session ID")
    }
    
    // Validate recU (registration record from client)
    recU, err := ValidateBase64Size(request.RecU, MaxRegistrationRecordSize, "recU")
    if err != nil {
        logging.ErrorLogger.Printf("Invalid recU: %v", err)
        return echo.NewHTTPError(http.StatusBadRequest, err.Error())
    }
    
    // Retrieve and decrypt session
    masterKey, err := config.LoadServerMasterKey()
    if err != nil {
        logging.ErrorLogger.Printf("Failed to load master key: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
    }
    defer crypto.SecureZeroBytes(masterKey)
    
    username, protocolType, encryptedRsec, err := database.GetOPAQUESessionEncrypted(database.DB, request.SessionID)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to retrieve OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid or expired session")
    }
    
    if protocolType != "registration" {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid session type")
    }
    
    // Decrypt rsec
    rsec, err := crypto.DecryptServerSecret(encryptedRsec, masterKey, request.SessionID, username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to decrypt server secret: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Session decryption failed")
    }
    defer crypto.SecureZeroBytes(rsec)
    
    // Complete registration
    provider := auth.GetOPAQUEProvider()
    rec, err := provider.StoreUserRecord(rsec, recU)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to store user record: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Store in database (transaction for atomicity)
    tx, err := database.DB.Begin()
    if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
    }
    defer tx.Rollback()
    
    // Create user record
    var emailPtr *string
    if request.Email != "" {
        emailPtr = &request.Email
    }
    
    user, err := models.CreateUser(tx, username, emailPtr)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to create user: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Store OPAQUE record
    _, err = tx.Exec(`
        INSERT INTO opaque_password_records 
        (record_type, record_identifier, opaque_user_record, associated_username, is_active)
        VALUES (?, ?, ?, ?, ?)`,
        "account", username, rec, username, true)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to store OPAQUE record: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Commit transaction
    if err := tx.Commit(); err != nil {
        logging.ErrorLogger.Printf("Failed to commit transaction: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Delete session (one-time use)
    database.DeleteOPAQUESession(database.DB, request.SessionID)
    
    // Generate temporary token for TOTP setup
    tempToken, err := auth.GenerateTemporaryTOTPToken(username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to generate temporary TOTP token: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration succeeded but setup token creation failed")
    }
    
    database.LogUserAction(username, "registered with zero-knowledge OPAQUE", "")
    logging.InfoLogger.Printf("Zero-knowledge OPAQUE registration completed for: %s", username)
    
    return c.JSON(http.StatusCreated, OpaqueRegisterStep2Response{
        Message:           "Registration successful. TOTP setup required.",
        RequiresTOTPSetup: true,
        TempToken:         tempToken,
    })
}
```

### 6.3 Rate Limiting

**Add rate limiting middleware**: `handlers/rate_limiting.go`

```go
// OPAQUERateLimiter implements strict rate limiting for OPAQUE endpoints
func OPAQUERateLimiter() echo.MiddlewareFunc {
    // Per-IP rate limiting
    ipLimiter := rate.NewLimiter(rate.Every(time.Minute), 10) // 10 requests per minute
    
    // Per-username rate limiting (for step 2)
    userLimiters := make(map[string]*rate.Limiter)
    var mu sync.Mutex
    
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // Get client IP
            ip := c.RealIP()
            
            // Check IP rate limit
            if !ipLimiter.Allow() {
                return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded")
            }
            
            // For step 2, also check per-username limit
            if strings.Contains(c.Path(), "step2") {
                var request struct {
                    SessionID string `json:"session_id"`
                }
                if err := c.Bind(&request); err == nil {
                    // Get username from session
                    username, _, _, err := database.GetOPAQUESessionEncrypted(database.DB, request.SessionID)
                    if err == nil {
                        mu.Lock()
                        limiter, exists := userLimiters[username]
                        if !exists {
                            limiter = rate.NewLimiter(rate.Every(time.Minute), 5)
                            userLimiters[username] = limiter
                        }
                        mu.Unlock()
                        
                        if !limiter.Allow() {
                            return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded for user")
                        }
                    }
                }
            }
            
            return next(c)
        }
    }
}
```

---

## PHASE 7: CLI TOOLS AND TEST SCRIPT UPDATES

### 7.1 CLI Client Updates

**Update CLI to use multi-step protocol**: `cmd/arkfile-client/main.go`

```go
func registerCommand() error {
    username := promptUsername()
    password := promptPassword()
    
    fmt.Println("Starting zero-knowledge OPAQUE registration...")
    
    // Step 1: Create registration request (client-side)
    usrCtx, M, err := auth.CreateRegistrationRequest([]byte(password))
    if err != nil {
        return fmt.Errorf("failed to create registration request: %w", err)
    }
    defer crypto.SecureZeroBytes(usrCtx)
    
    // Send M to server
    step1Req := map[string]string{
        "username": username,
        "m":        base64.StdEncoding.EncodeToString(M),
    }
    
    step1Resp, err := sendRequest("POST", "/api/auth/opaque/register/step1", step1Req)
    if err != nil {
        return fmt.Errorf("registration step 1 failed: %w", err)
    }
    
    sessionID := step1Resp["session_id"].(string)
    rpubB64 := step1Resp["rpub"].(string)
    rpub, _ := base64.StdEncoding.DecodeString(rpubB64)
    
    fmt.Println("Finalizing registration...")
    
    // Step 2: Finalize registration (client-side)
    recU, exportKey, err := auth.FinalizeRegistration(usrCtx, rpub)
    if err != nil {
        return fmt.Errorf("failed to finalize registration: %w", err)
    }
    defer crypto.SecureZeroBytes(exportKey)
    
    // Send recU to server
    step2Req := map[string]string{
        "session_id": sessionID,
        "rec_u":      base64.StdEncoding.EncodeToString(recU),
    }
    
    step2Resp, err := sendRequest("POST", "/api/auth/opaque/register/step2", step2Req)
    if err != nil {
        return fmt.Errorf("registration step 2 failed: %w", err)
    }
    
    fmt.Println("✓ Registration successful!")
    fmt.Println("Temp token:", step2Resp["temp_token"])
    fmt.Println("\nNext step: Complete TOTP setup")
    fmt.Println("Export key (keep secure):", base64.StdEncoding.EncodeToString(exportKey))
    
    return nil
}

func loginCommand() error {
    username := promptUsername()
    password := promptPassword()
    
    fmt.Println("Starting zero-knowledge OPAQUE authentication...")
    
    // Step 1: Create credential request (client-side)
    sec, pub, err := auth.CreateCredentialRequest([]byte(password))
    if err != nil {
        return fmt.Errorf("failed to create credential request: %w", err)
    }
    defer crypto.SecureZeroBytes(sec)
    
    // Send pub to server
    step1Req := map[string]string{
        "username": username,
        "pub":      base64.StdEncoding.EncodeToString(pub),
    }
    
    step1Resp, err := sendRequest("POST", "/api/auth/opaque/login/step1", step1Req)
    if err != nil {
        return fmt.Errorf("authentication step 1 failed: %w", err)
    }
    
    sessionID := step1Resp["session_id"].(string)
    respB64 := step1Resp["resp"].(string)
    resp, _ := base64.StdEncoding.DecodeString(respB64)
    
    fmt.Println("Recovering credentials...")
    
    // Step 2: Recover credentials (client-side)
    sk, authU, exportKey, err := auth.RecoverCredentials(resp, sec)
    if err != nil {
        return fmt.Errorf("failed to recover credentials: %w", err)
    }
    defer crypto.SecureZeroBytes(sk)
    defer crypto.SecureZeroBytes(exportKey)
    
    // Send authU to server
    step2Req := map[string]string{
        "session_id": sessionID,
        "auth_u":     base64.StdEncoding.EncodeToString(authU),
    }
    
    step2Resp, err := sendRequest("POST", "/api/auth/opaque/login/step2", step2Req)
    if err != nil {
        return fmt.Errorf("authentication step 2 failed: %w", err)
    }
    
    fmt.Println("✓ Authentication successful!")
    fmt.Println("Temp token:", step2Resp["temp_token"])
    fmt.Println("\nNext step: Enter TOTP code")
    fmt.Println("Export key (keep secure):", base64.StdEncoding.EncodeToString(exportKey))
    
    return nil
}
```

### 7.2 Test Script Updates

**Update test-app-curl.sh**: `scripts/testing/test-app-curl.sh`

```bash
#!/bin/bash
set -e

echo "==================================="
echo "Arkfile Zero-Knowledge OPAQUE Test"
echo "==================================="

# Configuration
API_URL="${API_URL:-http://localhost:8080}"
TEST_USERNAME="zktest_$(date +%s)"
TEST_PASSWORD="TestPassword123!@#"

echo ""
echo "Test Configuration:"
echo "  API URL: $API_URL"
echo "  Username: $TEST_USERNAME"
echo ""

# Function to generate mock OPAQUE messages (for testing without real crypto)
# In production, these would come from actual WASM/Go crypto
generate_mock_M() {
    # Generate 32 bytes of random data, base64 encode
    openssl rand -base64 32
}

generate_mock_recU() {
    # Generate 192 bytes of random data, base64 encode
    openssl rand -base64 192
}

generate_mock_pub() {
    # Generate 32 bytes of random data, base64 encode
    openssl rand -base64 32
}

generate_mock_authU() {
    # Generate 64 bytes of random data, base64 encode
    openssl rand -base64 64
}

echo "=== Test 1: OPAQUE Registration ==="
echo ""

# Step 1: Create registration request
echo "Step 1: Sending registration request..."
M=$(generate_mock_M)

STEP1_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/opaque/register/step1" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USERNAME\",\"m\":\"$M\"}")

echo "Response: $STEP1_RESPONSE"

# Extract session_id and rpub
SESSION_ID=$(echo "$STEP1_RESPONSE" | jq -r '.session_id')
RPUB=$(echo "$STEP1_RESPONSE" | jq -r '.rpub')

if [ "$SESSION_ID" == "null" ] || [ -z "$SESSION_ID" ]; then
    echo "❌ Registration step 1 failed: No session_id"
    exit 1
fi

echo "✓ Session ID: $SESSION_ID"
echo ""

# Step 2: Finalize registration
echo "Step 2: Finalizing registration..."
REC_U=$(generate_mock_recU)

STEP2_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/opaque/register/step2" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$SESSION_ID\",\"rec_u\":\"$REC_U\"}")

echo "Response: $STEP2_RESPONSE"

TEMP_TOKEN=$(echo "$STEP2_RESPONSE" | jq -r '.temp_token')

if [ "$TEMP_TOKEN" == "null" ] || [ -z "$TEMP_TOKEN" ]; then
    echo "❌ Registration step 2 failed: No temp_token"
    exit 1
fi

echo "✓ Registration successful!"
echo "✓ Temp token: $TEMP_TOKEN"
echo ""

echo "=== Test 2: OPAQUE Authentication ==="
echo ""

# Step 1: Create credential request
echo "Step 1: Sending credential request..."
PUB=$(generate_mock_pub)

AUTH_STEP1_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/opaque/login/step1" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USERNAME\",\"pub\":\"$PUB\"}")

echo "Response: $AUTH_STEP1_RESPONSE"

AUTH_SESSION_ID=$(echo "$AUTH_STEP1_RESPONSE" | jq -r '.session_id')
RESP=$(echo "$AUTH_STEP1_RESPONSE" | jq -r '.resp')

if [ "$AUTH_SESSION_ID" == "null" ] || [ -z "$AUTH_SESSION_ID" ]; then
    echo "❌ Authentication step 1 failed: No session_id"
    exit 1
fi

echo "✓ Auth Session ID: $AUTH_SESSION_ID"
echo ""

# Step 2: Complete authentication
echo "Step 2: Completing authentication..."
AUTH_U=$(generate_mock_authU)

AUTH_STEP2_RESPONSE=$(curl -s -X POST "$API_URL/api/auth/opaque/login/step2" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$AUTH_SESSION_ID\",\"auth_u\":\"$AUTH_U\"}")

echo "Response: $AUTH_STEP2_RESPONSE"

AUTH_TEMP_TOKEN=$(echo "$AUTH_STEP2_RESPONSE" | jq -r '.temp_token')

if [ "$AUTH_TEMP_TOKEN" == "null" ] || [ -z "$AUTH_TEMP_TOKEN" ]; then
    echo "❌ Authentication step 2 failed: No temp_token"
    exit 1
fi

echo "✓ Authentication successful!"
echo "✓ Auth Temp token: $AUTH_TEMP_TOKEN"
echo ""

echo "=== Test 3: TOTP Setup ==="
echo ""

# Note: TOTP setup requires real implementation
# This is a placeholder for the full flow

echo "TOTP setup would follow here..."
echo "(Requires QR code generation and verification)"
echo ""

echo "==================================="
echo "✓ All tests passed!"
echo "==================================="
echo ""
echo "Summary:"
echo "  ✓ OPAQUE registration (2 steps)"
echo "  ✓ OPAQUE authentication (2 steps)"
echo "  ⚠ TOTP setup (manual verification required)"
echo ""
echo "Next steps:"
echo "  1. Complete TOTP setup manually"
echo "  2. Test file upload/download with export key"
echo "  3. Verify zero-knowledge properties"
```

---

## PHASE 8: SECURITY HARDENING

### 8.1 XSS Protection

**Content Security Policy**: `main.go`

```go
// Add CSP middleware
func CSPMiddleware() echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            c.Response().Header().Set("Content-Security-Policy",
                "default-src 'self'; "+
                "script-src 'self'; "+
                "style-src 'self' 'unsafe-inline'; "+
                "img-src 'self' data:; "+
                "font-src 'self'; "+
                "connect-src 'self'; "+
                "frame-ancestors 'none'; "+
                "base-uri 'self'; "+
                "form-action 'self'")
            
            c.Response().Header().Set("X-Content-Type-Options", "nosniff")
            c.Response().Header().Set("X-Frame-Options", "DENY")
            c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
            c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
            
            // COOP/COEP for WASM isolation
            c.Response().Header().Set("Cross-Origin-Opener-Policy", "same-origin")
            c.Response().Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
            
            return next(c)
        }
    }
}

// Apply in main
e.Use(CSPMiddleware())
```

### 8.2 Logging Policy

**Sanitized logging**: `logging/security_events.go`

```go
// SanitizeForLogging removes sensitive data from log messages
func SanitizeForLogging(data map[string]interface{}) map[string]interface{} {
    sanitized := make(map[string]interface{})
    
    sensitiveKeys := []string{
        "password", "export_key", "session_key", "secret",
        "token", "m", "pub", "resp", "auth_u", "rec_u",
        "rpub", "rsec", "ssec", "oprf_seed",
    }
    
    for key, value := range data {
        keyLower := strings.ToLower(key)
        isSensitive := false
        
        for _, sk := range sensitiveKeys {
            if strings.Contains(keyLower, sk) {
                isSensitive = true
                break
            }
        }
        
        if isSensitive {
            sanitized[key] = "[REDACTED]"
        } else {
            sanitized[key] = value
        }
    }
    
    return sanitized
}

// LogSecurityEvent logs security-relevant events without sensitive data
func LogSecurityEvent(eventType, username, details string) {
    sanitizedDetails := SanitizeForLogging(map[string]interface{}{
        "details": details,
    })
    
    InfoLogger.Printf("SECURITY EVENT: type=%s user=%s details=%v",
        eventType, username, sanitizedDetails)
}
```

### 8.3 Timing Attack Mitigation

**Constant-time comparisons**: `auth/opaque.go`

```go
import "crypto/subtle"

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}

// Use in authentication verification
func (p *RealOPAQUEProvider) UserAuth(authUServer, authUClient []byte) error {
    if len(authUServer) != len(authUClient) {
        return fmt.Errorf("authentication failed")
    }
    
    // Constant-time comparison to prevent timing attacks
    if !ConstantTimeCompare(authUServer, authUClient) {
        return fmt.Errorf("authentication failed")
    }
    
    return nil
}
```

---

## PHASE 9: TESTING AND VALIDATION

### 9.1 Unit Tests

**Test server key generation**: `auth/opaque_test.go`

```go
func TestServerKeyGeneration(t *testing.T) {
    // Generate server keys
    privateKey := make([]byte, 32)
    _, err := rand.Read(privateKey)
    require.NoError(t, err)
    
    // Derive public key
    publicKey := make([]byte, 32)
    err = derivePublicKey(publicKey, privateKey)
    require.NoError(t, err)
    
    // Verify public key is not all zeros
    allZero := true
    for _, b := range publicKey {
        if b != 0 {
            allZero = false
            break
        }
    }
    assert.False(t, allZero, "Public key should not be all zeros")
    
    // Verify public key is deterministic
    publicKey2 := make([]byte, 32)
    err = derivePublicKey(publicKey2, privateKey)
    require.NoError(t, err)
    assert.Equal(t, publicKey, publicKey2, "Public key derivation should be deterministic")
}
```

**Test export key validation**: `models/user_test.go`

```go
func TestExportKeyValidation(t *testing.T) {
    user := &User{Username: "test"}
    
    // Test valid export key
    validKey := make([]byte, 64)
    rand.Read(validKey)
    err := user.ValidateOPAQUEExportKey(validKey)
    assert.NoError(t, err)
    
    // Test wrong length
    shortKey := make([]byte, 32)
    err = user.ValidateOPAQUEExportKey(shortKey)
    assert.Error(t, err)
    
    // Test all zeros
    zeroKey := make([]byte, 64)
    err = user.ValidateOPAQUEExportKey(zeroKey)
    assert.Error(t, err)
    
    // Test low entropy
    lowEntropyKey := make([]byte, 64)
    // Fill with pattern
    for i := range lowEntropyKey {
        lowEntropyKey[i] = byte(i % 2)
    }
    err = user.ValidateOPAQUEExportKey(lowEntropyKey)
    assert.Error(t, err)
}
```

### 9.2 Integration Tests

**Test full registration flow**: `handlers/auth_test.go`

```go
func TestZeroKnowledgeOPAQUERegistration(t *testing.T) {
    // Setup test server
    e := setupTestServer(t)
    defer teardownTestServer(t)
    
    username := "zktest_" + generateRandomString(8)
    
    // Step 1: Create registration request
    M := generateMockM()
    step1Req := map[string]interface{}{
        "username": username,
        "m":        base64.StdEncoding.EncodeToString(M),
    }
    
    step1Resp := testRequest(t, e, "POST", "/api/auth/opaque/register/step1", step1Req)
    assert.Equal(t, http.StatusOK, step1Resp.Code)
    
    var step1Data map[string]interface{}
    json.Unmarshal(step1Resp.Body.Bytes(), &step1Data)
    
    sessionID := step1Data["session_id"].(string)
    assert.NotEmpty(t, sessionID)
    assert.Len(t, sessionID, 32)
    
    // Step 2: Finalize registration
    recU := generateMockRecU()
    step2Req := map[string]interface{}{
        "session_id": sessionID,
        "rec_u":      base64.StdEncoding.EncodeToString(recU),
    }
    
    step2Resp := testRequest(t, e, "POST", "/api/auth/opaque/register/step2", step2Req)
    assert.Equal(t, http.StatusCreated, step2Resp.Code)
    
    var step2Data map[string]interface{}
    json.Unmarshal(step2Resp.Body.Bytes(), &step2Data)
    
    tempToken := step2Data["temp_token"].(string)
    assert.NotEmpty(t, tempToken)
    
    // Verify user was created
    user, err := models.GetUserByUsername(database.DB, username)
    assert.NoError(t, err)
    assert.Equal(t, username, user.Username)
    
    // Verify OPAQUE record was stored
    var count int
    err = database.DB.QueryRow(`
        SELECT COUNT(*) FROM opaque_password_records 
        WHERE record_type = 'account' AND record_identifier = ?`,
        username).Scan(&count)
    assert.NoError(t, err)
    assert.Equal(t, 1, count)
    
    // Verify session was deleted (one-time use)
    _, _, _, err = database.GetOPAQUESessionEncrypted(database.DB, sessionID)
    assert.Error(t, err)
}
```

### 9.3 Zero-Knowledge Verification Checklist

After implementation, verify these critical properties:

**Password Handling**:
- [ ] Password sent ZERO times to server (not even once)
- [ ] Password stored only in WASM memory
- [ ] Password cleared from memory after use
- [ ] No password in localStorage
- [ ] No password in sessionStorage
- [ ] No password in cookies
- [ ] No password in URL parameters
- [ ] No password in HTTP headers (except during OPAQUE protocol steps where it's never plaintext)

**File Encryption**:
- [ ] All encryption happens client-side in WASM
- [ ] Only encrypted data sent to server
- [ ] Server cannot decrypt files
- [ ] Server cannot see original filenames
- [ ] Server cannot access file content
- [ ] Export key never sent to server
- [ ] File encryption keys derived from export key client-side

**Protocol Compliance**:
- [ ] Server public key properly derived from private key
- [ ] OPRF seed used in all OPAQUE operations
- [ ] Per-user identities (IdU) used in protocol
- [ ] Server identity (IdS) consistent across operations
- [ ] Context binding prevents mix-up attacks
- [ ] Session IDs are cryptographically random
- [ ] Sessions expire after 5 minutes
- [ ] Sessions are one-time use only

**Key Management**:
- [ ] Export key stored in-memory only (not Web Storage)
- [ ] Export key cleared on logout
- [ ] Export key cleared on tab close
- [ ] Server secrets encrypted at rest
- [ ] Master key loaded from systemd-credentials
- [ ] All sensitive data zeroed after use

**Security Hardening**:
- [ ] CSP headers prevent XSS
- [ ] COOP/COEP headers for WASM isolation
- [ ] Rate limiting on all OPAQUE endpoints
- [ ] Input validation on all base64 inputs
- [ ] Size checks prevent buffer overflows
- [ ] Constant-time comparisons for auth tokens
- [ ] No sensitive data in logs
- [ ] Timing attack mitigations in place

---

## PHASE 10: DOCUMENTATION UPDATES

### 10.1 API Documentation

**Update docs/api.md** with new endpoints:

```markdown
## Zero-Knowledge OPAQUE Authentication

### Registration

#### POST /api/auth/opaque/register/step1

**Description**: Initiates OPAQUE registration (client sends M, receives rpub)

**Request**:
```json
{
  "username": "user.name",
  "email": "user@example.com",
  "m": "base64_encoded_registration_request"
}
```

**Response**:
```json
{
  "session_id": "32_char_random_string",
  "rpub": "base64_encoded_registration_response"
}
```

#### POST /api/auth/opaque/register/step2

**Description**: Completes OPAQUE registration (client sends recU)

**Request**:
```json
{
  "session_id": "32_char_random_string",
  "rec_u": "base64_encoded_registration_record"
}
```

**Response**:
```json
{
  "message": "Registration successful. TOTP setup required.",
  "requires_totp_setup": true,
  "temp_token": "jwt_token_for_totp_setup"
}
```

### Authentication

#### POST /api/auth/opaque/login/step1

**Description**: Initiates OPAQUE authentication (client sends pub, receives resp)

**Request**:
```json
{
  "username": "user.name",
  "pub": "base64_encoded_credential_request"
}
```

**Response**:
```json
{
  "session_id": "32_char_random_string",
  "resp": "base64_encoded_credential_response"
}
```

#### POST /api/auth/opaque/login/step2

**Description**: Completes OPAQUE authentication (client sends authU)

**Request**:
```json
{
  "session_id": "32_char_random_string",
  "auth_u": "base64_encoded_auth_token"
}
```

**Response**:
```json
{
  "requires_totp": true,
  "temp_token": "jwt_token_for_totp_verification",
  "message": "OPAQUE authentication successful. TOTP code required."
}
```
```

### 10.2 Security Documentation

**Update docs/security.md**:

```markdown
## Zero-Knowledge Architecture

Arkfile implements true zero-knowledge OPAQUE authentication, ensuring:

1. **Passwords never leave the client device**
   - All password operations happen in WASM
   - Server never sees plaintext passwords
   - OPAQUE protocol ensures zero-knowledge proof

2. **Server cannot decrypt user files**
   - File encryption keys derived from export key (client-side only)
   - Export key never transmitted to server
   - Server stores only encrypted file data

3. **Server cannot see original filenames**
   - Filenames encrypted client-side before upload
   - Metadata encryption uses keys derived from export key

4. **RFC-compliant OPAQUE implementation**
   - Proper server key derivation (not random bytes)
   - OPRF seed used in all operations
   - Per-user identity binding
   - Context binding prevents mix-up attacks

## Cryptographic Guarantees

### Key Derivation

```
Server Keys:
  server_private_key (32 bytes random)
  server_public_key = crypto_scalarmult_base(server_private_key)
  oprf_seed (32 bytes random)

Client Keys (never sent to server):
  export_key (64 bytes from OPAQUE)
  file_encryption_key = HKDF(export_key, "file:" + file_id)
  metadata_key = HKDF(export_key, "metadata:" + username)
```

### OPAQUE Protocol Flow

**Registration**:
1. Client: Creates registration request (M) from password
2. Server: Creates registration response (rpub) using server keys
3. Client: Finalizes registration (recU) and derives export_key
4. Server: Stores user record (rec)

**Authentication**:
1. Client: Creates credential request (pub) from password
2. Server: Creates credential response (resp) using stored record
3. Client: Recovers credentials (authU) and derives export_key
4. Server: Verifies authentication token

**Key Properties**:
- Password never transmitted
- Export key deterministic (same password = same export_key)
- Server cannot derive export_key from stored data
- Zero-knowledge proof of password knowledge
```

---

## IMPLEMENTATION TIMELINE

### Week 1-2: Foundation (CRITICAL)
- [ ] Fix server key generation (Priority 1)
- [ ] Implement Emscripten WASM build (Priority 1)
- [ ] Add OPRF seed usage (Priority 1)
- [ ] Implement identity and context binding (Priority 2)
- [ ] Remove all broken code (Phase 0)

### Week 3: Backend Infrastructure
- [ ] Implement server secret encryption
- [ ] Add session management with proper cleanup
- [ ] Implement validation middleware
- [ ] Add rate limiting
- [ ] Update database schema

### Week 4: WASM and Client
- [ ] Complete WASM module with Emscripten
- [ ] Implement TypeScript WASM interface
- [ ] Create secure key manager (in-memory only)
- [ ] Implement password input handling
- [ ] Add key derivation functions

### Week 5: API Endpoints
- [ ] Implement registration endpoints (step 1 & 2)
- [ ] Implement authentication endpoints (step 1 & 2)
- [ ] Add comprehensive input validation
- [ ] Implement TOTP integration (server-managed)
- [ ] Add security headers and CSP

### Week 6: CLI and Testing
- [ ] Update CLI client for multi-step protocol
- [ ] Update test-app-curl.sh script
- [ ] Write unit tests for all components
- [ ] Write integration tests for full flows
- [ ] Perform security audit

### Week 7: Documentation and Hardening
- [ ] Update API documentation
- [ ] Update security documentation
- [ ] Add deployment guide
- [ ] Implement logging sanitization
- [ ] Add timing attack mitigations

### Week 8: Final Testing and Deployment
- [ ] Complete zero-knowledge verification checklist
- [ ] Perform penetration testing
- [ ] Load testing and performance optimization
- [ ] Final security review
- [ ] Deploy to production

---

## SUCCESS CRITERIA

### Functional Requirements
- [ ] Registration flow works end-to-end (2 steps)
- [ ] Authentication flow works end-to-end (2 steps)
- [ ] TOTP setup and verification works
- [ ] File upload/download with encryption works
- [ ] CLI tools work with new protocol
- [ ] Browser client works with WASM
- [ ] test-app-curl.sh passes all tests

### Security Requirements
- [ ] Password NEVER transmitted to server (verified)
- [ ] Export key NEVER transmitted to server (verified)
- [ ] Server cannot decrypt files (verified)
- [ ] Server cannot see filenames (verified)
- [ ] OPAQUE protocol RFC-compliant (verified)
- [ ] All crypto uses libopaque/libsodium (no custom crypto)
- [ ] XSS protections in place (CSP, headers)
- [ ] Rate limiting prevents abuse
- [ ] Timing attacks mitigated
- [ ] All sensitive data zeroed after use

### Performance Requirements
- [ ] Registration completes in < 2 seconds
- [ ] Authentication completes in < 2 seconds
- [ ] WASM module loads in < 500ms
- [ ] File encryption/decryption acceptable performance
- [ ] No memory leaks in WASM operations

### Documentation Requirements
- [ ] API documentation complete and accurate
- [ ] Security documentation explains zero-knowledge properties
- [ ] Setup guide updated for new protocol
- [ ] AGENTS.md reflects new architecture
- [ ] Code comments explain critical security decisions

---

## RISK MITIGATION

### Risk: WASM Build Complexity
**Mitigation**: 
- Use well-documented Emscripten toolchain
- Test WASM module independently before integration
- Have fallback plan (server-side crypto with API calls)

### Risk: Performance Issues
**Mitigation**:
- Benchmark each OPAQUE step
- Optimize WASM module size
- Use Web Workers for heavy crypto operations
- Implement progressive loading

### Risk: Browser Compatibility
**Mitigation**:
- Test on all major browsers (Chrome, Firefox, Safari, Edge)
- Provide fallback for older browsers
- Document minimum browser requirements

### Risk: Key Management Complexity
**Mitigation**:
- Keep export key in-memory only (simplest approach)
- Clear documentation on key lifecycle
- Automatic cleanup on logout/tab close

---

## CONCLUSION

This comprehensive refactoring plan transforms Arkfile from a broken "OPAQUE-inspired" system to a **true zero-knowledge, RFC-compliant OPAQUE authentication system**. 

### Key Achievements

1. **Fixes all critical security flaws**:
   - Proper server key generation
   - Browser-compatible WASM architecture
   - OPRF seed integration
   - Identity and context binding

2. **Ensures true zero-knowledge**:
   - Passwords never leave client
   - Export keys never transmitted
   - Server cannot decrypt files
   - Server cannot see filenames

3. **RFC-compliant implementation**:
   - Multi-step OPAQUE protocol
   - Proper cryptographic primitives
   - No custom crypto (libopaque/libsodium only)

4. **Production-ready security**:
   - XSS protections
   - Rate limiting
   - Timing attack mitigations
   - Comprehensive logging (sanitized)

### Next Steps

1. **Review this plan thoroughly**
2. **Prioritize Phase 0 (removal) and Phase 1 (server keys)**
3. **Choose WASM toolchain (Emscripten recommended)**
4. **Begin implementation following the timeline**
5. **Test continuously with test-app-curl.sh**

**Remember**: This is a greenfield application. We can implement the correct protocol from scratch without backward compatibility concerns. Let's build it right the first time.

---

> **⚠️ FINAL REMINDER**
>
> **ALL AGENTIC CODING AGENTS MUST READ `docs/AGENTS.md` BEFORE STARTING ANY WORK.**
>
> This document provides the foundation, but AGENTS.md contains critical project-specific guidelines that must be followed.
