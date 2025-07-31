# Arkfile OPAQUE Security Architecture - Implementation Plan

## I. Security & Privacy Assumptions

### Core Security Model

**Zero-Knowledge Server Principle**: The Arkfile server operates under strict zero-knowledge assumptions where cryptographic secrets never exist in server memory or storage in recoverable form.

### Data Classification & Security Matrix

| Data Type | Storage Location | Server Visibility | Database Compromise Impact | Network Compromise Impact |
|-----------|------------------|-------------------|---------------------------|--------------------------|
| **Account Passwords** | Never stored | Never seen | No impact | No impact |
| **OPAQUE Export Keys** | Never stored | Never seen | No impact | No impact |
| **Session Keys** | Never stored | Never seen | No impact | No impact |
| **Share Passwords** | Never stored | Never seen | No impact | Argon2id crack required |
| **File Encryption Keys (FEKs)** | Never stored raw | Never seen | Requires session/share crack | No impact |
| **Share Salts** | Database (BLOB) | Visible (random) | No cryptographic value | No impact |
| **Encrypted FEKs** | Database (BLOB) | Visible (encrypted) | Requires password crack | No impact |
| **File Metadata** | Database | Visible | Filenames/sizes exposed | Metadata exposed |
| **Encrypted File Blobs** | S3/MinIO | Opaque binary | No decryption possible | No decryption possible |

### Password Type Security Model

**Account Passwords (OPAQUE-Only)**:
- **Flow**: User Password → OPAQUE Authentication → Export Key → HKDF → Session Key
- **Server Knowledge**: None (OPAQUE protocol ensures zero knowledge)
- **Attack Resistance**: Complete (no offline attacks possible)
- **Compromise Impact**: Zero (export keys cannot be derived from stored data)

**Share Passwords (Argon2id-Based)**:
- **Flow**: Share Password → Argon2id (client-side) → Share Key → FEK Decryption
- **Server Knowledge**: Salt + Encrypted FEK only
- **Attack Resistance**: Strong (128MB memory requirement, 18+ char passwords)
- **Compromise Impact**: Controlled (offline attacks limited to shared files only)

### Transmission Security Guarantees

| Operation | Client → Server | Server → Client | Zero-Knowledge Properties |
|-----------|-----------------|-----------------|--------------------------|
| **Registration** | Email + OPAQUE Registration Data | OPAQUE Record Confirmation | ✅ Server never sees password |
| **Login** | Email + OPAQUE Authentication | JWT + OPAQUE Export Key | ✅ Server never sees password |
| **File Upload** | Encrypted Blob + Metadata | Storage Confirmation | ✅ Server never sees file content |
| **Share Creation** | Salt + Encrypted FEK | Crypto-Secure Share URL | ✅ Server never sees share password |
| **Share Access** | POST with Password (Request Body) | Salt + Encrypted FEK | ✅ Anonymous access, request body security, EntityID-based rate limiting |

### Database Compromise Threat Model

**Complete Database Breach Scenario**:
- **Account-Only Files**: ✅ **PERFECTLY SECURE** - No decryption possible (depend on OPAQUE export keys never stored)
- **Shared Files**: ⚠️ **CONTROLLED RISK** - Vulnerable to offline Argon2id attacks against share passwords
- **User Accounts**: ✅ **PERFECTLY SECURE** - No password recovery possible (OPAQUE records unusable without protocol)
- **System Metadata**: ❌ **EXPOSED** - Filenames, sizes, upload dates, user emails visible

**Attack Economics (Shared Files)**:
- **Weak Share Passwords** (<20 chars): $10K-50K GPU investment, weeks to crack
- **Strong Share Passwords** (20+ chars): $100K+ specialized hardware, months-years timeframe
- **Economic Threshold**: Makes attacks unfeasible for most threat actors

### Privacy Assumptions

**Server-Side Privacy**:
- **Account Authentication**: Server sees only OPAQUE protocol messages (cryptographically opaque)
- **File Content**: Server stores encrypted blobs indistinguishable from random data
- **Share Access**: Server provides encrypted data to anonymous users without identity verification
- **Access Patterns**: Limited metadata (timestamps, access counts) - no content correlation possible

**Client-Side Privacy**:
- **Cryptographic Operations**: All key derivation and file encryption/decryption occurs in browser
- **Share Password Transmission**: Only via secure HTTPS headers, never logged or stored
- **Anonymous Access**: Share recipients require no account creation or identity disclosure

## II. System Architecture Overview

### Unified OPAQUE Authentication Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│ User Password   │ -> │ OPAQUE           │ -> │ Export Key         │
│ (Account/Custom)│    │ Authentication   │    │ (64 bytes)         │
└─────────────────┘    └──────────────────┘    └────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ HKDF Derivation    │
                                               │ (Domain Separated) │
                                               └────────────────────┘
                                                          │
                        ┌─────────────────────────────────┼─────────────────────────────────┐
                        ▼                                 ▼                                 ▼
              ┌─────────────────┐               ┌─────────────────┐               ┌─────────────────┐
              │ File Keys       │               │ JWT Signing     │               │ TOTP Secrets    │
              │ (Account/Custom)│               │ Keys            │               │ (MFA)           │
              └─────────────────┘               └─────────────────┘               └─────────────────┘
```

**IMPORTANT: All authenticated user operations use OPAQUE-derived keys:**
- **Account Password Files**: Standard user password → OPAQUE → HKDF("ARKFILE_SESSION_KEY") → File Key
- **Custom Password Files**: User-chosen password → OPAQUE → HKDF("ARKFILE_CUSTOM_KEY") → File Key

### Anonymous Share Access Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│ Share Password  │ -> │ Argon2id         │ -> │ Share Key          │
│ (18+ chars)     │    │ (128MB, 4 iter)  │    │ (32 bytes)         │
└─────────────────┘    └──────────────────┘    └────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ FEK Decryption     │
                                               │ (AES-GCM)          │
                                               └────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ File Decryption    │
                                               │ (Client-Side)      │
                                               └────────────────────┘
```

### Threat Model & Attack Surface

**Attack Vectors Eliminated**:
- ✅ **Offline Password Attacks** (account passwords) - OPAQUE prevents this entirely
- ✅ **Server-Side Key Extraction** - No recoverable keys stored server-side
- ✅ **Database Password Harvesting** - No password hashes or derivatives stored
- ✅ **Man-in-the-Middle** - OPAQUE protocol provides mutual authentication

**Remaining Attack Surface**:
- ⚠️ **Share Password Dictionary Attacks** - Limited to shared files only, Argon2id-protected
- ⚠️ **Client-Side Compromise** - Individual user impact only, no lateral movement
- ⚠️ **Metadata Exposure** - Filenames and access patterns visible in database
- ⚠️ **Social Engineering** - Share passwords transmitted out-of-band vulnerable to interception

**Risk Mitigation Strategy**:
- **Controlled Exposure**: Only opt-in shared files vulnerable to cryptographic attacks
- **Strong Parameters**: Argon2id with 128MB memory makes attacks expensive
- **Economic Disincentive**: Attack costs exceed value for most use cases
- **Perfect Forward Secrecy**: Account-only files remain secure even under worst-case scenarios

## III. Implementation Status & Roadmap

### Completed Implementation (✅)

**Phase 1: Database Schema Purge**
- Eliminated `password_hash` and `password_salt` fields from users table
- Updated all SQL operations to exclude legacy authentication fields
- **Status**: ✅ COMPLETE - Database layer fully clean

**Phase 2: Authentication System Elimination**
- Deleted `auth/password.go` entirely (Argon2ID functions)
- Removed all Argon2ID configuration from `config/config.go`
- Eliminated environment variable handling for Argon2ID parameters
- **Status**: ✅ COMPLETE - Single OPAQUE authentication path

**Phase 3: Model Layer Migration**
- Implemented `CreateUserWithOPAQUE()` for atomic user registration
- Added comprehensive User model OPAQUE lifecycle methods
- Created user-centric authentication API with transaction safety
- **Status**: ✅ COMPLETE - User model fully OPAQUE-integrated

**Phase 4A: Test Schema Cleanup**
- Deleted `auth/password_test.go` (17 obsolete test functions)
- Removed 121+ legacy password field references from test mocks  
- Updated test schema to match cleaned database
- **Status**: ✅ COMPLETE - Test infrastructure clean

**Phase 4B: Mock-Based OPAQUE Testing**
- Implemented complete `OPAQUEProvider` interface abstraction
- Created full mock OPAQUE implementation with deterministic behavior
- Built comprehensive test framework with 176 passing tests
- Added build tag support for mock vs real provider switching
- **Status**: ✅ COMPLETE - Full test coverage with mock framework

**Phase 5A: Server-Side OPAQUE Export Key Integration**
- Enhanced `models/user.go` with export key management methods
- Updated authentication handlers to derive session keys from OPAQUE export keys
- Implemented HKDF-based key derivation with proper domain separation
- Added secure memory management for export keys
- **Status**: ✅ COMPLETE - Server provides OPAQUE export keys to clients

### Remaining Work (🎯)

**Phase 5B: Client-Side Migration - ✅ COMPLETE**
- **Target**: Eliminate ALL Argon2ID from authenticated user operations (account AND custom passwords)
- **Files Modified**:
  - `client/main.go` - ✅ Complete rewrite for OPAQUE-only operations with export key handling
  - `crypto/wasm_shim.go` - ✅ Clean OPAQUE-only WASM functions, removed Argon2ID device detection
  - `crypto/kdf.go` - ✅ DELETED ENTIRELY (all functions moved to share-specific implementations)
- **Success Criteria**: ✅ All authenticated file encryption uses OPAQUE export keys (account and custom passwords)
- **Validation**: ✅ New encryption format with versions 0x01 (account) and 0x02 (custom), both OPAQUE-based
- **Status**: ✅ COMPLETE - All builds pass, zero Argon2ID in authenticated operations

**Phase 5C: Crypto System Cleanup - ✅ COMPLETE**
- **Target**: Remove all Argon2ID references from crypto system
- **Files Modified**:
  - `crypto/kdf.go` - ✅ DELETED ENTIRELY
  - `crypto/envelope.go` - ✅ Created new OPAQUE-only envelope system (versions 0x01/0x02)
  - `crypto/capability_negotiation.go` - ✅ DELETED ENTIRELY (device capability detection removed)
  - `crypto/crypto_test.go` - ✅ DELETED ENTIRELY (contained Argon2ID tests)
- **Success Criteria**: ✅ Zero Argon2ID references in authenticated operations
- **Validation**: ✅ Clean compilation, all builds pass (standard, mock, WASM)
- **Status**: ✅ COMPLETE - Pure OPAQUE architecture achieved

**Phase 5D: ELIMINATED - No Backwards Compatibility**
- **Target**: Fresh start with new encryption formats
- **Implementation**: New versions 0x01 (account OPAQUE) and 0x02 (custom OPAQUE)
- **No Legacy Support**: Clean break from old Argon2id-based formats
- **Greenfield Advantage**: No migration complexity needed

**Phase 5E: Share System Security Hardening - HIGH PRIORITY**
- **Target**: Implement comprehensive security protections for share system
- **Files to Modify**:
  - Create `database/share_rate_limiting.sql` - Rate limiting table schema
  - `handlers/file_shares.go` - Secure ID generation and rate limiting
  - `handlers/middleware.go` - EntityID-based rate limiting implementation
  - Client-side enhanced password validation with entropy scoring
- **Security Enhancements**:
  - Enhanced password validation (entropy scoring, dictionary checking)
  - EntityID-based rate limiting with exponential backoff
  - Crypto-secure 256-bit share identifiers
  - Request body password transmission (POST instead of headers)
  - 2-second minimum response time (timing attack mitigation)
  - Rate limiting for 404 responses (share enumeration protection)
- **Success Criteria**: All 6 security improvements implemented and tested
- **Validation**: Rate limiting tests, timing attack tests, secure ID entropy tests, password validation tests

**Phase 5F: Frontend Security & TypeScript Migration - MEDIUM PRIORITY**
- **Target**: Secure frontend and migrate to TypeScript-based architecture
- **Files to Modify**:
  - `client/static/file-share.html` - Move inline JavaScript to TypeScript modules
  - `client/static/index.html` - Refactor inline onclick handlers to addEventListener patterns
  - Create `client/static/css/file-share.css` - Move inline CSS to external files
  - `handlers/middleware.go` - Add CSP headers for web security
  - TypeScript build process - Generate SRI hashes for static assets
- **Frontend Security Enhancements**:
  - Content Security Policy (CSP) headers to prevent XSS attacks
  - Subresource Integrity (SRI) hashes for JavaScript/CSS integrity
  - Elimination of inline scripts and styles for CSP compliance
  - Migration of raw JavaScript to TypeScript modules (aligns with Go/WASM preference)
  - Event handler refactoring from onclick attributes to addEventListener patterns
- **Success Criteria**: CSP-compliant frontend with TypeScript-based architecture
- **Validation**: CSP policy validation, SRI hash verification, TypeScript build success

**Phase 6: Configuration & Documentation Cleanup - LOW PRIORITY**
- **Target**: Remove all Argon2ID configuration options
- **Files**: `config/config.go`, documentation files
- **Update**: Environment variables, setup guides, API documentation

### Success Criteria Matrix

| Metric | Current Status | Target | Validation Method |
|--------|---------------|---------|-------------------|
| **Argon2ID References (Account Auth)** | 0 server-side ✅ | 0 system-wide | `grep -r "Argon2" --exclude-dir=vendor` |
| **Test Suite Status** | 176/176 passing ✅ | Maintained | `go test -tags=mock ./...` |
| **Build Compatibility** | Mock + Real ✅ | Maintained | Both build modes succeed |
| **OPAQUE Export Key Usage** | Server-side ✅ | Client-side | File encryption uses export keys |
| **Share Password Strength** | Basic (18+ chars) | Entropy-validated | Client-side complexity scoring |
| **Rate Limiting** | None | EntityID-based | Exponential backoff per (ShareID, EntityID) |
| **Share ID Security** | UUIDv4 (122-bit) | Crypto-secure (256-bit) | Cryptographically random generation |
| **Password Transmission** | HTTP headers | Request body | POST with JSON body |
| **Timing Attack Protection** | None | 2-second minimum | Constant response times for all share access |
| **Share Enumeration Protection** | None | Rate limited | 404 responses subject to same rate limiting |
| **Content Security Policy** | None | Strict CSP | CSP headers prevent XSS attacks |
| **Subresource Integrity** | None | SRI hashes | Static assets have integrity verification |
| **Frontend Architecture** | Raw JavaScript | TypeScript modules | Inline scripts moved to TypeScript |
| **New File Formats** | N/A | 0x01, 0x02 | Clean OPAQUE-based encryption versions |

## IV. Share System Technical Specification

### Complete End-to-End Share Flow

**File Upload Process**:
1. User authenticates via OPAQUE → receives export key
2. Client derives session key: `HKDF(export_key, "ARKFILE_SESSION_KEY")`
3. Client generates random FEK, encrypts file: `AES-GCM(file, FEK)`
4. Client encrypts FEK: `AES-GCM(FEK, session_key)`
5. Encrypted file blob uploaded to S3, encrypted FEK stored in database

**Share Creation Process**:
1. Owner provides 18+ character share password
2. Client generates 32-byte random salt
3. Client derives share key: `Argon2id(share_password, salt, 128MB, 4 iter, 4 threads)`
4. Client downloads and decrypts FEK using owner's session key
5. Client encrypts FEK with share key: `AES-GCM(FEK, share_key)`
6. Client uploads salt + encrypted_FEK_share to server → receives share URL

**Anonymous Access Process**:
1. Visitor receives share URL + password out-of-band
2. Visitor enters share password → client downloads salt + encrypted_FEK_share
3. Client derives share key: `Argon2id(share_password, salt, 128MB, 4 iter, 4 threads)`
4. Client decrypts FEK: `AES-GCM_decrypt(encrypted_FEK_share, share_key)`
5. Client downloads encrypted file blob from S3
6. Client decrypts file: `AES-GCM_decrypt(encrypted_file, FEK)`

### Database Schema Extensions

```sql
-- New table for share access management
CREATE TABLE file_share_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL UNIQUE,        -- 256-bit crypto-secure identifier
    file_id INTEGER NOT NULL,
    salt BLOB NOT NULL,                    -- 32-byte random salt for Argon2id
    encrypted_fek BLOB NOT NULL,           -- FEK encrypted with Argon2id-derived share key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,                   -- Optional expiration
    access_count INTEGER DEFAULT 0,       -- Usage tracking
    last_accessed DATETIME,               -- Last access timestamp
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- New table for EntityID-based rate limiting
CREATE TABLE share_access_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,               -- Anonymous EntityID from logging system
    failed_count INTEGER DEFAULT 0,       -- Number of failed attempts
    last_failed_attempt DATETIME,         -- Timestamp of last failure
    next_allowed_attempt DATETIME,        -- When next attempt is allowed (exponential backoff)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(share_id, entity_id)
);

CREATE INDEX idx_file_share_keys_share_id ON file_share_keys(share_id);
CREATE INDEX idx_file_share_keys_file_id ON file_share_keys(file_id);
CREATE INDEX idx_file_share_keys_expires_at ON file_share_keys(expires_at);
CREATE INDEX idx_share_access_attempts_share_entity ON share_access_attempts(share_id, entity_id);
CREATE INDEX idx_share_access_attempts_next_allowed ON share_access_attempts(next_allowed_attempt);
```

### API Specification

**Create Share Access: `POST /api/files/{fileId}/share`**
```json
Request:
{
  "salt": "base64-encoded-32-byte-salt",
  "encrypted_fek": "base64-encoded-encrypted-fek",
  "expires_in_days": 30,
  "max_access_count": 100
}

Response:
{
  "success": true,
  "share_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "share_url": "https://arkfile.example.com/share/f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "expires_at": "2025-08-30T16:21:48Z"
}
```

**Access Shared File: `POST /api/share/{shareId}`**
```json
Request:
{
  "password": "MyVacation2025PhotosForFamily!"
}

Response (Success):
{
  "success": true,
  "salt": "base64-encoded-32-byte-salt",
  "encrypted_fek": "base64-encoded-encrypted-fek",
  "file_info": {
    "filename": "joeyphotos.zip",
    "size": 15728640,
    "content_type": "application/zip"
  },
  "download_url": "https://storage.example.com/files/uuid-blob-name"
}

Response (Rate Limited):
{
  "success": false,
  "error": "rate_limited",
  "retry_after": 30,
  "message": "Too many failed attempts. Try again in 30 seconds."
}

Response (Invalid Password):
{
  "success": false,
  "error": "invalid_password",
  "message": "Incorrect share password."
}
```

### Client-Side Implementation Requirements

**WASM Functions for Share Access**:
```javascript
// Argon2id derivation with production parameters
function deriveShareKey(sharePassword, salt) {
    return argon2id({
        password: sharePassword,
        salt: salt,
        memory: 128 * 1024,      // 128MB memory (ASIC-resistant)
        iterations: 4,           // 4 iterations (balanced security/performance)
        parallelism: 4,          // 4 threads (multi-core utilization)
        hashLength: 32           // 32-byte output (AES-256 key size)
    });
}

// Enhanced password validation with entropy scoring
function validateSharePassword(password) {
    const entropy = calculatePasswordEntropy(password);
    const complexity = scorePasswordComplexity(password);
    
    if (password.length < 18) {
        throw new Error("Password must be at least 18 characters long");
    }
    
    if (entropy < 65) {
        throw new Error("Password entropy too low - use more varied characters");
    }
    
    if (complexity.score < 3) {
        throw new Error("Password too predictable - avoid common patterns");
    }
    
    return { 
        valid: true, 
        strength: complexity.score,
        entropy: entropy,
        feedback: complexity.feedback
    };
}

// Entropy calculation using zxcvbn-style scoring
function calculatePasswordEntropy(password) {
    // Character set size estimation
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    
    // Basic entropy: log2(charset^length)
    return Math.log2(Math.pow(charsetSize, password.length));
}

// Advanced complexity scoring (0-4 scale)
function scorePasswordComplexity(password) {
    let score = 0;
    let feedback = [];
    
    // Length scoring
    if (password.length >= 20) score += 1;
    else feedback.push("Consider using 20+ characters");
    
    // Character variety
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
    else feedback.push("Mix uppercase and lowercase letters");
    
    if (/[0-9]/.test(password)) score += 0.5;
    else feedback.push("Include numbers");
    
    if (/[^a-zA-Z0-9]/.test(password)) score += 0.5;
    else feedback.push("Include special characters");
    
    // Pattern detection
    if (!/(.)\1{2,}/.test(password)) score += 1; // No repeated chars
    else feedback.push("Avoid repeated characters");
    
    return { score: Math.min(4, score), feedback };
}
```

**Server-Side Handler Requirements**:
```go
// handlers/file_shares.go - Core implementation
func (h *Handler) CreateFileShare(w http.ResponseWriter, r *http.Request) {
    // Validate file ownership (prevent unauthorized sharing)
    // Parse client-provided salt + encrypted_fek
    // Store in file_share_keys table
    // Return share URL (server never sees share password)
}

func (h *Handler) AccessSharedFile(w http.ResponseWriter, r *http.Request) {
    // Extract share password from HTTP header
    // Retrieve salt + encrypted_fek from database
    // Return data for client-side Argon2id derivation
    // Update access tracking (optional)
}
```

### Security Analysis: Share System

**Security Benefits**:
- **Zero-Knowledge Server**: Server never processes share passwords in plaintext
- **ASIC-Resistant Protection**: 128MB Argon2id memory requirement makes specialized hardware attacks prohibitively expensive
- **Anonymous Access**: No account creation required for recipients
- **Domain Separation**: Share keys cryptographically isolated from account authentication
- **Perfect Forward Secrecy**: Account-only files remain secure even if share passwords compromised

**Security Trade-offs**:
- **Offline Attack Surface**: Shared files vulnerable to dictionary attacks if database compromised
- **Password Dependency**: Security limited by user behavior in choosing share passwords
- **Computational Burden**: 128MB memory requirement may impact low-end devices

**Risk Assessment**:
- **Weak Share Passwords** (<20 chars): Crackable with $10K-50K GPU investment over weeks
- **Strong Share Passwords** (20+ chars): Requires $100K+ specialized hardware, months-years timeframe
- **Economic Threshold**: Attack costs exceed value for most threat scenarios

**Mitigation Strategy**:
- **18+ Character Minimum**: Enforced complexity requirements
- **User Education**: Guidance on creating strong share passwords
- **Optional Expiration**: Time-limited share access
- **Access Monitoring**: Track usage patterns for anomaly detection

## V. AI-Friendly Development Guide

`NOTE: Greenfield Status. There are no current deployments of this app and no current users. No need for backwards compability.`

### Phase 5B Implementation Roadmap

**Priority 1: Client-Side Argon2ID Elimination**

**File: `client/main.go`**
- **Functions to DELETE**:
  - `deriveKeyArgon2ID()` - Remove entirely
  - `deriveKeyWithDeviceCapability()` - Remove entirely
  - `deriveSessionKey()` - Replace with OPAQUE export key approach
  - `detectDeviceCapability()` - Remove entirely
  - `getProfileForCapability()` - Remove entirely
  - All `ArgonProfile` structs and constants

- **Functions to ADD/MODIFY**:
  - `receiveOPAQUEExportKey()` - Process export key from server authentication
  - `deriveSessionKeyFromExport()` - Use HKDF instead of Argon2ID
  - Update `encryptFile()` to use OPAQUE-derived session keys
  - Update `decryptFile()` to handle OPAQUE-based decryption

**File: `crypto/wasm_shim.go`**
- **Functions to REMOVE**:
  - `DetectDeviceCapabilityWASM()` - Remove device capability detection
  - `BenchmarkArgonProfileWASM()` - Remove Argon2ID profiling
  - `adaptiveArgon2IDJS()` - Remove adaptive Argon2ID functions
  - All device capability detection utilities

- **Functions to ENHANCE**:
  - `createSecureSessionFromOpaqueExportJS()` - Already implemented, verify integration
  - `encryptFileWithSecureSessionJS()` - Ensure proper HKDF usage
  - `decryptFileWithSecureSessionJS()` - Verify OPAQUE session key handling

**Validation Commands**:
```bash
# Verify no Argon2ID in client code (account authentication)
grep -r "Argon2" client/ --exclude="*share*"  # Should return only share-related functions

# Verify compilation
go build ./client

# Verify WASM build
GOOS=js GOARCH=wasm go build ./client
```

**Priority 2: Crypto System Cleanup**

**File: `crypto/kdf.go` - DELETE ENTIRELY**
```bash
# Verification before deletion
grep -l "crypto/kdf" **/*.go  # Check what files import this
rm crypto/kdf.go              # Delete after confirming no dependencies
```

**File: `crypto/envelope.go`**
- **Remove**: All `DeriveKeyArgon2ID()` function calls
- **Replace**: With `crypto.DeriveSessionKey()` and HKDF approaches
- **Update**: Key derivation to use OPAQUE export keys exclusively

**Validation Commands**:
```bash
# Verify no Argon2ID references in crypto system
grep -r "Argon2" crypto/ --exclude="*share*"  # Should return empty

# Verify clean compilation
go build ./crypto

# Run crypto tests
go test ./crypto
```

**Priority 3: Legacy File Format Support**

**Implementation Strategy**:
- **Maintain**: Decryption support for existing formats (0x04, 0x05)
- **Add**: New format 0x06 = Pure OPAQUE-derived keys
- **Migration**: Progressive re-encryption (user-initiated)

**Version Handling**:
```go
// client/main.go - decryptFile() enhancement
func decryptFile(encryptedData, password string) interface{} {
    version := data[0]
    switch version {
    case 0x04, 0x05:
        // Legacy: Maintain existing Argon2ID decryption for backward compatibility
        return decryptLegacyFormat(data, password)
    case 0x06:
        // New: Pure OPAQUE-derived session key
        return decryptOPAQUEFormat(data, password)
    default:
        return "Unsupported encryption version"
    }
}
```

### Test Strategy & Validation

**Mock Testing (Development)**:
```bash
# Run full test suite with mocks
OPAQUE_MOCK_MODE=true go test -tags=mock ./...

# Verify 176 tests still pass
echo $?  # Should return 0 (success)
```

**Build Validation**:
```bash
# Standard build (production)
go build ./...

# Mock build (development)
OPAQUE_MOCK_MODE=true go build -tags=mock ./...

# WASM build (client-side)
GOOS=js GOARCH=wasm go build ./client
```

**Integration Testing**:
```bash
# End-to-end authentication flow
./scripts/testing/test-auth-curl.sh

# File upload/download testing
./scripts/testing/test-only.sh

# Performance validation
./scripts/testing/performance-benchmark.sh
```

### Success Validation Checklist

**Phase 5B Completion Criteria**:
- [ ] Zero Argon2ID references in account authentication flows
- [ ] All file encryption uses OPAQUE export keys for account-based operations
- [ ] Share system uses Argon2id only for anonymous access
- [ ] Existing encrypted files remain decryptable
- [ ] All 176 tests continue passing
- [ ] Both standard and mock builds succeed
- [ ] WASM build generates successfully

**Validation Commands**:
```bash
# 1. Argon2ID Reference Check (Account Auth Only)
grep -r "Argon2" --exclude-dir=vendor --exclude="*share*" . | grep -v "share"
# Expected: Only share-related references remain

# 2. Test Suite Validation  
OPAQUE_MOCK_MODE=true go test -tags=mock ./... | grep -E "(PASS|FAIL)"
# Expected: All tests PASS, none FAIL

# 3. Build Compatibility
go build ./... && echo "Standard build: SUCCESS"
OPAQUE_MOCK_MODE=true go build -tags=mock ./... && echo "Mock build: SUCCESS"
GOOS=js GOARCH=wasm go build ./client && echo "WASM build: SUCCESS"

# 4. OPAQUE Export Key Usage Verification
grep -r "export.*key" handlers/ models/ | grep -i opaque
# Expected: Export key handling in authentication flows

# 5. Session Key Derivation Check
grep -r "DeriveSessionKey" crypto/ handlers/ client/
# Expected: HKDF-based derivation, no Argon2ID
```

### File Modification Summary

**Files to MODIFY**:
- `client/main.go` - Major refactoring (remove Argon2ID, add OPAQUE session key handling)
- `crypto/wasm_shim.go` - Clean up Argon2ID WASM functions
- `crypto/envelope.go` - Replace Argon2ID calls with HKDF approaches

**Files to DELETE**:
- `crypto/kdf.go` - Remove entirely (all Argon2ID key derivation functions)

**Files to CREATE**:
- `handlers/file_shares.go` - Share system API handlers (if not exists)
- Database migration script for `file_share_keys` table

**Files to TEST**:
- All modified files require comprehensive testing
- Integration tests for OPAQUE export key → session key → file encryption flow
- Backward compatibility tests for existing encrypted files

### Development Workflow

**Recommended Implementation Order**:
1. **Implement OPAQUE session key handling** in `client/main.go` (without removing Argon2ID yet)
2. **Test dual functionality** to ensure OPAQUE path works correctly
3. **Remove Argon2ID functions** from account authentication flows
4. **Clean up crypto system** (delete `crypto/kdf.go`, update `crypto/envelope.go`)
5. **Implement share system** (separate from account authentication)
6. **Comprehensive testing** of all flows
7. **Documentation update** and final validation

**Risk Mitigation**:
- **Incremental Changes**: Implement OPAQUE path before removing Argon2ID
- **Comprehensive Testing**: Verify each change with full test suite
- **Backward Compatibility**: Maintain existing file decryption throughout
- **Build Validation**: Ensure both mock and real builds succeed at each step

### Phase 5E Implementation Roadmap

**Priority 1: Enhanced Password Validation & Rate Limiting**

**Implementation Steps**:
- Integrate entropy scoring validation into client-side password forms
- Implement EntityID-based rate limiting middleware
- Add 2-second minimum response time enforcement
- Extend rate limiting to 404 responses

**Validation Commands**:
```bash
# Test enhanced password validation
curl -X POST /api/share/test-share-id \
  -H "Content-Type: application/json" \
  -d '{"password":"weakpass"}' # Should return entropy error

# Test rate limiting functionality
for i in {1..5}; do
  curl -X POST /api/share/test-share-id \
    -H "Content-Type: application/json" \
    -d '{"password":"wrong-password"}'
  sleep 1
done # Should eventually return 429 rate limited

# Test timing attack mitigation
time curl -X POST /api/share/invalid-share-id \
  -H "Content-Type: application/json" \
  -d '{"password":"any-password"}' # Should take minimum 2 seconds

# Verify secure share ID generation
grep -r "uuid.New" handlers/file_shares.go # Should return empty
grep -r "crypto/rand" handlers/file_shares.go # Should show secure generation
```

### Phase 5F Implementation Roadmap

**Priority 1: Frontend Security Architecture**

**CSP Implementation**:
```go
// handlers/middleware.go - CSP headers
func CSPMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        csp := "default-src 'self'; " +
               "script-src 'self'; " +
               "style-src 'self'; " +
               "img-src 'self'; " +
               "connect-src 'self'; " +
               "font-src 'self'; " +
               "object-src 'none'; " +
               "base-uri 'self'; " +
               "form-action 'self'"
        w.Header().Set("Content-Security-Policy", csp)
        next.ServeHTTP(w, r)
    })
}
```

**SRI Hash Generation**:
```bash
# Generate SRI hashes for static assets
find client/static -name "*.js" -o -name "*.css" | while read file; do
    hash=$(openssl dgst -sha384 -binary "$file" | openssl base64 -A)
    echo "$file: sha384-$hash"
done
```

**TypeScript Migration Steps**:
- Move `file-share.html` inline JavaScript to `client/static/js/src/file-share.ts`
- Refactor onclick handlers to TypeScript event listeners
- Move inline CSS to `client/static/css/file-share.css`
- Update HTML templates to reference external files with SRI hashes

**Validation Commands**:
```bash
# Verify CSP compliance
curl -I http://localhost:8080/ | grep -i "content-security-policy"
# Expected: CSP header present

# Test CSP blocking of inline scripts
# Should see CSP violations in browser console for any remaining inline scripts

# Verify SRI hashes
grep -r "integrity=" client/static/*.html
# Expected: All external scripts/styles have integrity attributes

# Verify TypeScript compilation
cd client/static/js && npm run build
# Expected: Clean TypeScript compilation with no errors

# Test frontend functionality
./scripts/testing/test-typescript.sh
# Expected: All frontend tests pass with new TypeScript architecture
```

**Phase 5E & 5F Success Criteria**:
- [ ] All 6 share system security improvements implemented
- [ ] 2-second minimum response time enforced for all share access
- [ ] EntityID-based rate limiting functional with exponential backoff
- [ ] 404 responses subject to same rate limiting as valid requests
- [ ] Enhanced password validation with entropy scoring active
- [ ] CSP headers prevent XSS attacks (verified with security scanner)
- [ ] SRI hashes protect static asset integrity
- [ ] All inline scripts moved to TypeScript modules
- [ ] All inline styles moved to external CSS files
- [ ] Frontend functionality maintained after migration

---

## Conclusion

This document provides a comprehensive roadmap for completing the Arkfile OPAQUE security architecture implementation. The security assumptions are clearly defined upfront, the implementation status is documented, and the remaining work is broken down into actionable phases with specific validation criteria.

**Key Achievements to Date**:
- ✅ Complete server-side OPAQUE integration (176 passing tests)
- ✅ Zero-knowledge database schema (no password storage)
- ✅ Comprehensive mock testing framework
- ✅ Server-side export key provision to clients
- ✅ **Phase 5B COMPLETE**: Pure OPAQUE client-side implementation
- ✅ **Phase 5C COMPLETE**: Complete crypto system cleanup

**Phase 5B/5C Implementation Results (July 31, 2025)**:
- **Files Deleted**: `crypto/kdf.go`, `crypto/crypto_test.go`, `crypto/capability_negotiation.go`
- **Files Created**: `crypto/share_kdf.go` (isolated Argon2ID), `crypto/envelope.go` (OPAQUE-only)
- **Client Rewrite**: Complete `client/main.go` migration to OPAQUE export keys
- **WASM Cleanup**: `crypto/wasm_shim.go` now OPAQUE-only for authenticated operations
- **Build Status**: All builds pass (standard, mock, WASM)
- **Argon2ID References**: Only 8 documentation comments remain (all appropriate)
- **New File Formats**: 0x01 (OPAQUE account), 0x02 (OPAQUE custom) implemented
- **Share System**: Completely isolated in `crypto/share_kdf.go` for anonymous access only

**Remaining High-Priority Work**:
- 🎯 **Phase 5E**: Share system security hardening (rate limiting, entropy validation)
- 🎯 **Phase 5F**: Frontend security & TypeScript migration
- 📋 **Phase 6**: Configuration & documentation cleanup

The document is structured for both security expert review and AI-assisted development, providing clear validation criteria and implementation guidance for completing the transition to a pure OPAQUE architecture.
