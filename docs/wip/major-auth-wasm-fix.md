# Major Authentication and WASM Refactor Plan

## Overview

This document outlines the comprehensive refactor to fix fundamental security issues in the Arkfile authentication system and remove WASM complexity. The current implementation violates zero-knowledge principles by sending plaintext passwords to the server. This refactor will establish proper zero-knowledge authentication using TypeScript OPAQUE in the browser and fix the CLI implementation.

## Critical Security Issue

The current implementation in `auth/opaque_wrapper.c` function `arkfile_opaque_authenticate_user` runs the entire OPAQUE protocol server-side, including client operations. This means:
- The server receives plaintext passwords
- Zero-knowledge property is completely violated
- Security is equivalent to basic password hashing
- Server compromise exposes all passwords

This must be fixed immediately.

## Goals

1. Remove Go WASM entirely from the project
2. Implement proper TypeScript OPAQUE in browser using `@cloudflare/opaque-ts`
3. Fix Go CLI OPAQUE to use proper client-server message exchange
4. Maintain server-side Go + libopaque implementation
5. Achieve actual zero-knowledge authentication
6. Establish stable TypeScript crypto patterns for future features

## Cryptographic Strategy

### Overview

This refactor establishes a comprehensive, modern cryptographic architecture using native browser APIs and well-audited TypeScript libraries while removing WASM complexity.

### Three-Tier Password System

#### 1. Account-Based Authentication (OPAQUE → HKDF)

**Flow:**
- User authenticates via OPAQUE protocol
- OPAQUE provides high-entropy export key (32 bytes)
- Use Web Crypto API's HKDF to derive file encryption keys
- No Argon2id needed (export key is already high-entropy)

**Implementation:**
```typescript
// After OPAQUE authentication
const exportKey = await opaqueClient.finishAuthentication(serverResponse);

// Import as CryptoKey for Web Crypto API
const baseKey = await crypto.subtle.importKey(
  'raw',
  exportKey,
  { name: 'HKDF' },
  false,
  ['deriveKey', 'deriveBits']
);

// Derive file encryption key
const fileKey = await crypto.subtle.deriveKey(
  {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(32), // Per-file salt
    info: new TextEncoder().encode('arkfile-file-encryption')
  },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);
```

**Rationale:**
- OPAQUE export key = 256 bits of entropy
- HKDF is designed for deriving keys from high-entropy sources
- Web Crypto API native = fast, audited, no dependencies
- Proper cryptographic separation: authentication vs encryption

#### 2. Custom File Passwords (Argon2id)

**Flow:**
- User provides custom password for specific file
- Use `@noble/hashes` Argon2id implementation
- Derive key encryption key (KEK)
- KEK wraps randomly-generated file encryption key (FEK)

**Parameters (Maintained from Current Implementation):**
```typescript
const ARGON2_PARAMS = {
  time: 8,        // iterations
  mem: 262144,    // 256 MB (256 * 1024 KB)
  parallelism: 4, // threads
  outputLen: 32   // 32 bytes
};
```

**Implementation:**
```typescript
import { argon2id } from '@noble/hashes/argon2';

async function deriveCustomFileKey(
  password: string,
  username: string
): Promise<Uint8Array> {
  // Generate deterministic salt (matches Go implementation)
  const saltInput = `arkfile-custom-key-salt:${username}`;
  const salt = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(saltInput)
  );
  
  // Derive key using Argon2id
  const key = argon2id(
    new TextEncoder().encode(password),
    new Uint8Array(salt),
    {
      t: ARGON2_PARAMS.time,
      m: ARGON2_PARAMS.mem,
      p: ARGON2_PARAMS.parallelism,
      dkLen: ARGON2_PARAMS.outputLen
    }
  );
  
  return key;
}
```

**Rationale:**
- Custom passwords are user-chosen (potentially weak)
- Argon2id provides memory-hard protection
- 256MB memory cost makes brute-force expensive
- Matches Go implementation parameters

#### 3. Share Passwords (Argon2id)

**Flow:**
- User creates share with password
- Use `@noble/hashes` Argon2id implementation
- Derive key encryption key (KEK)
- KEK wraps file encryption key for anonymous access

**Parameters (Same as Custom File Passwords):**
```typescript
const ARGON2_PARAMS = {
  time: 8,
  mem: 262144,
  parallelism: 4,
  outputLen: 32
};
```

**Implementation:**
```typescript
async function deriveShareKey(
  password: string,
  username: string
): Promise<Uint8Array> {
  // Generate deterministic salt (matches Go implementation)
  const saltInput = `arkfile-share-key-salt:${username}`;
  const salt = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(saltInput)
  );
  
  // Derive key using Argon2id
  const key = argon2id(
    new TextEncoder().encode(password),
    new Uint8Array(salt),
    {
      t: ARGON2_PARAMS.time,
      m: ARGON2_PARAMS.mem,
      p: ARGON2_PARAMS.parallelism,
      dkLen: ARGON2_PARAMS.outputLen
    }
  );
  
  return key;
}
```

**Rationale:**
- Share passwords enable anonymous access
- Must be strong enough to protect shared files
- Argon2id provides necessary protection
- Matches Go implementation parameters

### Web Crypto API Usage

#### File Encryption (AES-GCM)

**Implementation:**
```typescript
async function encryptFile(
  data: Uint8Array,
  key: CryptoKey
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  // Generate random nonce (12 bytes for AES-GCM)
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      tagLength: 128 // 16-byte authentication tag
    },
    key,
    data
  );
  
  return {
    ciphertext: new Uint8Array(ciphertext),
    nonce
  };
}

async function decryptFile(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      tagLength: 128
    },
    key,
    ciphertext
  );
  
  return new Uint8Array(plaintext);
}
```

**Rationale:**
- AES-GCM provides authenticated encryption
- Web Crypto API native = hardware acceleration
- 12-byte nonce is standard for AES-GCM
- 128-bit tag provides strong authentication

#### Key Import/Export

**Implementation:**
```typescript
// Import raw key material as CryptoKey
async function importKey(
  keyMaterial: Uint8Array,
  algorithm: 'AES-GCM' | 'HKDF'
): Promise<CryptoKey> {
  const usages = algorithm === 'AES-GCM' 
    ? ['encrypt', 'decrypt'] 
    : ['deriveKey', 'deriveBits'];
    
  return await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: algorithm },
    false, // not extractable
    usages
  );
}

// Export CryptoKey to raw bytes (when needed)
async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const exported = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(exported);
}
```

### Password Complexity Requirements

**Maintained from Current Implementation:**

All password validation logic remains unchanged:
- Minimum length requirements
- Character class requirements
- Complexity scoring
- User feedback

**Files:**
- `crypto/password_validation.go` - Server-side validation (unchanged)
- `client/static/js/src/auth/*` - Client-side validation (unchanged)

The cryptographic changes only affect how passwords are processed after validation, not the validation rules themselves.

### TypeScript Crypto Module Structure

**File: `client/static/js/src/crypto/primitives.ts`**
```typescript
// Core cryptographic primitives
export class CryptoPrimitives {
  // AES-GCM encryption/decryption
  static async encrypt(data: Uint8Array, key: CryptoKey): Promise<EncryptedData>
  static async decrypt(encrypted: EncryptedData, key: CryptoKey): Promise<Uint8Array>
  
  // Key derivation
  static async deriveHKDF(baseKey: Uint8Array, info: string): Promise<CryptoKey>
  static async deriveArgon2id(password: string, salt: Uint8Array): Promise<Uint8Array>
  
  // Key management
  static async importKey(material: Uint8Array, algorithm: string): Promise<CryptoKey>
  static async exportKey(key: CryptoKey): Promise<Uint8Array>
}
```

**File: `client/static/js/src/crypto/file-encryption.ts`**
```typescript
// High-level file encryption operations
export class FileEncryption {
  // Account-based encryption (OPAQUE export key)
  static async encryptWithAccountKey(file: File, exportKey: Uint8Array): Promise<EncryptedFile>
  static async decryptWithAccountKey(encrypted: EncryptedFile, exportKey: Uint8Array): Promise<File>
  
  // Custom password encryption
  static async encryptWithCustomPassword(file: File, password: string, username: string): Promise<EncryptedFile>
  static async decryptWithCustomPassword(encrypted: EncryptedFile, password: string, username: string): Promise<File>
  
  // Share password encryption
  static async encryptForSharing(file: File, password: string, username: string): Promise<EncryptedFile>
  static async decryptSharedFile(encrypted: EncryptedFile, password: string): Promise<File>
}
```

**File: `client/static/js/src/crypto/types.ts`**
```typescript
// Type definitions for crypto operations
export interface EncryptedData {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  tag?: Uint8Array; // For AES-GCM, included in ciphertext
}

export interface EncryptedFile {
  metadata: FileMetadata;
  data: EncryptedData;
  keyType: 'account' | 'custom' | 'share';
}

export interface FileMetadata {
  filename: string;
  size: number;
  mimeType: string;
  uploadedAt: Date;
}

export const ARGON2_PARAMS = {
  time: 8,
  mem: 262144,
  parallelism: 4,
  outputLen: 32
} as const;
```

### Error Handling Patterns

**Cryptographic Errors:**
```typescript
export class CryptoError extends Error {
  constructor(
    message: string,
    public readonly operation: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}

// Usage
try {
  const key = await deriveKey(password, salt);
} catch (error) {
  throw new CryptoError(
    'Key derivation failed',
    'deriveArgon2id',
    error as Error
  );
}
```

**User-Facing Errors:**
```typescript
export function handleCryptoError(error: Error): string {
  if (error instanceof CryptoError) {
    switch (error.operation) {
      case 'decrypt':
        return 'Incorrect password or corrupted file';
      case 'encrypt':
        return 'Encryption failed. Please try again';
      case 'deriveKey':
        return 'Password processing failed';
      default:
        return 'Cryptographic operation failed';
    }
  }
  return 'An unexpected error occurred';
}
```

### Dependencies

**Add to `client/static/js/package.json`:**
```json
{
  "dependencies": {
    "@cloudflare/opaque-ts": "^0.1.0",
    "@noble/hashes": "^1.3.3"
  }
}
```

**Installation:**
```bash
cd client/static/js
bun add @cloudflare/opaque-ts @noble/hashes
```

**Rationale:**
- `@cloudflare/opaque-ts`: Battle-tested OPAQUE implementation
- `@noble/hashes`: Pure TypeScript, well-audited, supports Argon2id
- Both maintained by respected cryptography experts
- No WASM dependencies
- Small bundle sizes

## Database Schema Changes

### Overview

Clean separation between OPAQUE (account authentication) and Argon2id (file/share passwords) with minimal salt storage.

### Design Principles

1. **No Critical Password Salts for Account Authentication**
   - OPAQUE handles all salt/randomness internally
   - Server never sees or stores password-derived salts

2. **Minimal Salt Storage for File Operations**
   - Share passwords: Random salts (necessary for Argon2id)
   - Custom file passwords: Deterministic salts (no storage needed)

3. **Clear Table Separation**
   - One table per authentication mechanism
   - No mixing of OPAQUE and Argon2id records

### Tables to Modify

#### 1. Simplify `opaque_user_data`

**Current Purpose:** Mixed OPAQUE storage
**New Purpose:** Account authentication only

**Keep:**
```sql
CREATE TABLE IF NOT EXISTS opaque_user_data (
    username TEXT PRIMARY KEY,
    serialized_record BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);
```

**Changes:**
- Remove any file-related fields if present
- Focus solely on account authentication

#### 2. Delete `opaque_password_records`

**Reason:** This table currently mixes OPAQUE and other password types, creating confusion.

**Action:** Drop table entirely
```sql
DROP TABLE IF EXISTS opaque_password_records;
```

**Replacement:** Separate tables for each use case (see below)

### Tables to Create

#### 3. New `file_custom_passwords` Table

**Purpose:** Track custom file passwords (Argon2id-based)

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS file_custom_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    owner_username TEXT NOT NULL,
    key_label TEXT NOT NULL,              -- User-friendly name like "Work Password"
    password_hint TEXT,                   -- Optional hint
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE,
    UNIQUE(file_id, key_label)            -- Each file can have multiple custom passwords
);

CREATE INDEX IF NOT EXISTS idx_file_custom_passwords_file 
    ON file_custom_passwords(file_id);
CREATE INDEX IF NOT EXISTS idx_file_custom_passwords_owner 
    ON file_custom_passwords(owner_username);
CREATE INDEX IF NOT EXISTS idx_file_custom_passwords_active 
    ON file_custom_passwords(is_active);
```

**Key Points:**
- **No salt column** - uses deterministic salt from username
- Stores metadata only (label, hint, timestamps)
- Never stores actual password or derived keys
- Follows same `owner_username` pattern as `file_metadata`

**Salt Derivation (Client-Side):**
```typescript
// Deterministic salt - no storage needed
const saltInput = `arkfile-custom-key-salt:${username}`;
const salt = await crypto.subtle.digest(
  'SHA-256',
  new TextEncoder().encode(saltInput)
);
```

### Tables to Keep Unchanged

#### 4. `file_share_keys` - Already Correct

**Purpose:** Anonymous file sharing with password protection

**Current Schema:**
```sql
CREATE TABLE IF NOT EXISTS file_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,
    file_id TEXT NOT NULL,
    owner_username TEXT NOT NULL,
    salt TEXT NOT NULL,                   -- Random salt for each share (necessary)
    encrypted_fek TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (owner_username) REFERENCES users(username) ON DELETE CASCADE
);
```

**Why Keep Salt:**
- Share passwords need random salts (not deterministic)
- Each share is independent and anonymous
- Salt is not secret - safe to store

#### 5. `file_metadata` - No Changes

**Current Schema:**
```sql
CREATE TABLE IF NOT EXISTS file_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id VARCHAR(36) UNIQUE NOT NULL,
    storage_id VARCHAR(36) UNIQUE NOT NULL,
    owner_username TEXT NOT NULL,
    -- ... other fields ...
    FOREIGN KEY (owner_username) REFERENCES users(username)
);
```

**Why No Changes:**
- Already uses `owner_username` foreign key pattern
- Consistent with new `file_custom_passwords` table

### Salt Storage Summary

| Password Type | Mechanism | Salt Storage | Rationale |
|--------------|-----------|--------------|-----------|
| Account Password | OPAQUE | None | Handled internally by OPAQUE protocol |
| Custom File Password | Argon2id | None | Deterministic from username |
| Share Password | Argon2id | Random (stored) | Each share needs unique random salt |

### Migration Strategy

Since this is a greenfield application with no current deployments:

1. Update `database/unified_schema.sql` with new schema
2. Drop `opaque_password_records` table
3. Create `file_custom_passwords` table
4. Update Go models to use new tables
5. No data migration needed

### Security Benefits

1. **Minimal Attack Surface**
   - Only one table stores salts (`file_share_keys`)
   - Account authentication has zero stored salts

2. **Clear Separation**
   - Each authentication mechanism has dedicated table
   - No confusion between OPAQUE and Argon2id

3. **Audit Trail**
   - `last_used_at` tracks password usage
   - `is_active` allows soft deletion

4. **Scalability**
   - Each file can have multiple custom passwords
   - Each password has user-friendly label

## Coding Standards

- Use Bun exclusively (no npm/pnpm/yarn)
- Zero emojis in all code and documentation
- Clear, technical language
- Comprehensive error handling
- Security-first approach

## Implementation Phases

### Phase 1: Remove WASM Infrastructure

#### Files to Delete
- `crypto/wasm_shim.go`
- `client/static/js/src/types/wasm.d.ts`
- `client/static/js/src/utils/wasm.ts`
- `client/static/js/src/auth/register.ts` (will be rewritten)
- `scripts/testing/test-wasm.sh`
- Any WASM build artifacts

#### Files to Modify
- `client/static/js/package.json` - Remove WASM-related dependencies
- `tsconfig.json` - Remove WASM-related compiler options
- `scripts/setup/build.sh` - Remove WASM build steps
- `.gitignore` - Remove WASM artifact patterns
- `client/static/index.html` - Remove WASM loading code

#### Build System Changes
- Remove TinyGo installation requirements
- Remove WASM compilation steps from build scripts
- Simplify TypeScript build to pure browser JavaScript
- Update deployment scripts to exclude WASM artifacts

### Phase 2: Implement TypeScript OPAQUE in Browser

#### Install Dependencies
```bash
cd client/static/js
bun add @cloudflare/opaque-ts
```

#### Create New TypeScript Modules

**File: `client/static/js/src/auth/opaque-client.ts`**
- Wrapper around `@cloudflare/opaque-ts`
- Registration flow (client-side only)
- Authentication flow (client-side only)
- Export key derivation
- Error handling

**File: `client/static/js/src/auth/opaque-types.ts`**
- TypeScript interfaces for OPAQUE messages
- Registration request/response types
- Authentication request/response types
- Server configuration types

**File: `client/static/js/src/auth/register.ts`** (rewrite)
- User registration UI logic
- Call OPAQUE client for registration request
- Send request to server
- Process server response
- Finalize registration locally
- Derive encryption keys from export key

**File: `client/static/js/src/auth/login.ts`** (major refactor)
- User login UI logic
- Call OPAQUE client for credential request
- Send request to server
- Process server response
- Recover credentials locally
- Derive session keys from export key
- Handle TOTP flow

#### API Endpoints (Server-Side)

**Registration Flow:**
1. `POST /auth/register/init` - Client sends registration request
2. Server responds with registration response
3. Client finalizes locally, sends final record
4. `POST /auth/register/finalize` - Server stores user record

**Authentication Flow:**
1. `POST /auth/login/init` - Client sends credential request
2. Server responds with credential response
3. Client recovers credentials locally
4. `POST /auth/login/finalize` - Client sends authentication proof
5. Server validates and issues JWT

### Phase 3: Fix Go CLI OPAQUE Implementation

#### Current Problem
The CLI currently sends passwords to the server in `cmd/arkfile-client/main.go`. This must be changed to proper client-server message exchange.

#### New CLI Flow

**File: `auth/opaque_client.go`** (new)
- Client-side OPAQUE operations using libopaque
- Registration request creation
- Registration finalization
- Credential request creation
- Credential recovery
- Proper separation from server operations

**File: `auth/opaque_wrapper.c`** (major refactor)
- Remove `arkfile_opaque_authenticate_user` (broken function)
- Remove `arkfile_opaque_register_user` (broken function)
- Keep only proper client and server operation functions
- Add clear comments about client vs server operations

**File: `cmd/arkfile-client/main.go`** (refactor)
- Registration: Create request locally, send to server, finalize locally
- Authentication: Create request locally, send to server, recover locally
- Never send plaintext password to server
- Proper error handling for network failures

#### CLI API Client

**File: `client/api_client.go`** (new or refactor existing)
- HTTP client for API calls
- Registration endpoints
- Authentication endpoints
- Proper request/response handling
- TLS verification

### Phase 4: Server-Side Implementation

#### Keep Existing
- `auth/opaque.go` - High-level interface (modify for new flow)
- `auth/opaque_cgo.go` - CGO bindings (modify for server-only ops)
- Server key management
- Database operations

#### Modify for New Flow

**File: `handlers/auth.go`**

New handlers:
- `POST /auth/register/init` - Process registration request, return response
- `POST /auth/register/finalize` - Store user record
- `POST /auth/login/init` - Process credential request, return response
- `POST /auth/login/finalize` - Validate authentication, issue JWT

Replace existing:
- Old single-step registration endpoint
- Old single-step login endpoint

**File: `auth/opaque.go`**

New functions:
- `CreateRegistrationResponse(request []byte) (response []byte, error)`
- `StoreUserRecord(username string, record []byte) error`
- `CreateCredentialResponse(username string, request []byte) (response []byte, error)`
- `ValidateAuthentication(username string, proof []byte) (bool, error)`

### Phase 5: Testing Strategy

#### Unit Tests

**Browser OPAQUE Tests:**
- Test registration flow with mock server responses
- Test authentication flow with mock server responses
- Test error handling
- Test key derivation

**CLI OPAQUE Tests:**
- Test registration request creation
- Test credential request creation
- Test response processing
- Test error handling

**Server OPAQUE Tests:**
- Test registration response creation
- Test credential response creation
- Test authentication validation
- Test database operations

#### Integration Tests

**End-to-End Registration:**
1. Browser creates registration request
2. Server processes and responds
3. Browser finalizes and sends record
4. Server stores record
5. Verify user can authenticate

**End-to-End Authentication:**
1. Browser creates credential request
2. Server processes and responds
3. Browser recovers credentials
4. Browser sends authentication proof
5. Server validates and issues JWT
6. Verify JWT works for API calls

**CLI Integration:**
1. CLI creates registration request
2. Server processes and responds
3. CLI finalizes and sends record
4. Server stores record
5. CLI authenticates successfully
6. Verify CLI can perform file operations

#### Security Tests

**Zero-Knowledge Verification:**
- Capture all network traffic during registration
- Verify password never appears in plaintext
- Capture all network traffic during authentication
- Verify password never appears in plaintext
- Test with compromised server (mock)
- Verify server cannot derive password from stored data

**Cryptographic Validation:**
- Verify export keys are deterministic (same password = same key)
- Verify session keys are random (different each time)
- Verify authentication fails with wrong password
- Verify authentication fails with tampered messages

### Phase 6: Deployment Strategy

#### Database Changes
No schema changes required - OPAQUE user records use the same database structure.

#### Deployment Steps
1. Deploy new server code
2. Deploy new browser client
3. Deploy new CLI binary
4. Test end-to-end flows
5. Monitor for errors

### Phase 7: Documentation Updates

#### Files to Update
- `docs/setup.md` - Remove WASM setup steps
- `docs/api.md` - Document new API endpoints
- `docs/security.md` - Explain zero-knowledge properties
- `README.md` - Update architecture description

#### New Documentation
- `docs/opaque-protocol.md` - Explain OPAQUE implementation
- `docs/testing-guide.md` - How to verify security properties

## File Modification Checklist

### Files to Delete
- [ ] `crypto/wasm_shim.go`
- [ ] `client/static/js/src/types/wasm.d.ts`
- [ ] `client/static/js/src/utils/wasm.ts`
- [ ] `client/static/js/src/auth/register.ts` (will recreate)
- [ ] `scripts/testing/test-wasm.sh`

### Files to Create
- [ ] `client/static/js/src/auth/opaque-client.ts`
- [ ] `client/static/js/src/auth/opaque-types.ts`
- [ ] `auth/opaque_client.go`
- [ ] `client/api_client.go`
- [ ] `docs/opaque-protocol.md`
- [ ] `docs/testing-guide.md`

### Files to Modify
- [ ] `client/static/js/package.json`
- [ ] `tsconfig.json`
- [ ] `scripts/setup/build.sh`
- [ ] `.gitignore`
- [ ] `client/static/index.html`
- [ ] `client/static/js/src/auth/login.ts`
- [ ] `auth/opaque_wrapper.c`
- [ ] `auth/opaque_wrapper.h`
- [ ] `auth/opaque.go`
- [ ] `auth/opaque_cgo.go`
- [ ] `handlers/auth.go`
- [ ] `cmd/arkfile-client/main.go`
- [ ] `docs/setup.md`
- [ ] `docs/api.md`
- [ ] `docs/security.md`
- [ ] `README.md`

## Implementation Order

1. Phase 1: Remove WASM (cleanup)
2. Phase 2: Implement TypeScript OPAQUE (browser)
3. Phase 4: Update server handlers (server)
4. Phase 3: Fix CLI OPAQUE (CLI)
5. Phase 5: Testing (verification)
6. Phase 6: Migration (deployment)
7. Phase 7: Documentation (finalization)

## Success Criteria

- [ ] No WASM files remain in project
- [ ] Browser never sends plaintext passwords
- [ ] CLI never sends plaintext passwords
- [ ] Server never receives plaintext passwords
- [ ] All tests pass
- [ ] Zero-knowledge property verified
- [ ] Documentation complete

## Risks and Mitigations

**Risk:** Cryptographic implementation errors
**Mitigation:** Use battle-tested libraries, comprehensive testing

**Risk:** Performance degradation
**Mitigation:** Benchmark before/after, optimize if needed

**Risk:** Integration complexity
**Mitigation:** Clear documentation, phased implementation

## Changelog Format

After modifying each file, append to this document:

### Implementation Log

- `docs/wip/major-auth-wasm-fix.md` - Added comprehensive cryptographic strategy section detailing Web Crypto API usage, three-tier password system (OPAQUE→HKDF for account passwords, Argon2id for custom/share passwords), TypeScript module structure, error handling patterns; removed all backward compatibility and migration references (greenfield app)
- `docs/wip/major-auth-wasm-fix.md` - Added database schema changes section: new `file_custom_passwords` table for custom file passwords (Argon2id, no salt storage), simplified `opaque_user_data` for account auth only, deleted `opaque_password_records` table, documented salt storage strategy (OPAQUE: none, custom passwords: deterministic, share passwords: random)

### WASM Removal Progress

**Phase 1 Complete: WASM Infrastructure Removed**

Files deleted:
- `crypto/wasm_shim.go` - Go WASM shim for password validation
- `client/static/js/src/types/wasm.d.ts` - WASM TypeScript type definitions
- `client/static/js/src/utils/wasm.ts` - WASM loader utility
- `client/static/js/src/utils/auth-wasm.ts` - WASM authentication wrapper
- `scripts/testing/test-wasm.sh` - WASM test script
- `client/static/main.wasm` - Compiled WASM binary
- `client/static/wasm_exec.js` - Go WASM runtime

Files modified:
- `client/static/js/package.json` - Removed WASM-related scripts and dependencies
- `tsconfig.json` - Removed WASM compiler options and type references
- `scripts/setup/build.sh` - Removed WASM build steps and verification
- `.gitignore` - Removed WASM artifact patterns
- `handlers/route_config.go` - Removed WASM file serving routes
- `scripts/testing/test-typescript.sh` - Removed WASM test execution
- `client/static/index.html` - Removed WASM loading script tags
- `client/static/shared.html` - Removed WASM loading script tags
- `client/static/file-share.html` - Removed WASM loading script tags
- `client/static/chunked-upload.html` - Removed WASM loading script tags

TypeScript files cleaned:
- `client/static/js/src/auth/login.ts` - Removed WASM imports
- `client/static/js/src/auth/totp.ts` - Removed WASM imports
- `client/static/js/src/files/list.ts` - Removed WASM imports
- `client/static/js/src/files/download.ts` - Removed WASM imports
- `client/static/js/src/files/share-integration.ts` - Removed WASM imports
- `client/static/js/src/app.ts` - Added missing register.ts import

Status:
- All WASM source files removed from project
- All WASM references removed from build system
- All WASM imports removed from TypeScript code
- Build system no longer compiles or deploys WASM
- HTML files no longer load WASM runtime
- TypeScript compilation verified working without WASM

Next steps:
- Implement TypeScript OPAQUE client using @cloudflare/opaque-ts
- Create new registration/login flows with proper client-server message exchange
- Update server handlers for new OPAQUE protocol flow
- Fix CLI OPAQUE implementation
