# OPAQUE Security Architecture Cleanup Plan

## Executive Summary & Context

This document outlines the comprehensive cleanup required to complete the OPAQUE password system unification in Arkfile. The foundational OPAQUE implementation work (Phases 1-3 from the original analysis) has been successfully completed, establishing:

- ✅ **Secure server key generation** using cryptographically random values
- ✅ **OPAQUE password manager** with unified authentication system
- ✅ **Share authentication migration** from Argon2ID to OPAQUE
- ✅ **File key OPAQUE integration** for custom file passwords

**Current State**: The OPAQUE foundation is solid and functional, but significant legacy code contamination remains that conflicts with the OPAQUE-only architecture goal.

**Context**: This is a greenfield implementation with no existing users, no current deployments, and no backwards compatibility requirements. This allows for aggressive cleanup without migration concerns.

## Critical Issues Assessment

Based on comprehensive codebase analysis, the following critical issues prevent achieving a pure OPAQUE-only architecture:

### **Database Schema Contamination**
**File**: `database/database.go`
- `password_hash TEXT NOT NULL` - Legacy field that shouldn't exist in OPAQUE-only system
- `password_salt TEXT` - Unused Argon2ID remnant field
- Outdated comments referencing "backwards compatibility" inappropriate for greenfield

### **Test Infrastructure Contamination**
**Scope**: 132+ references across multiple test files
- `handlers/auth_test.go` - Extensive SQL mocks expecting password_hash/password_salt
- `handlers/admin_test.go` - All user queries include legacy authentication fields
- `handlers/files_test.go` - User retrieval mocks with password_hash/password_salt
- `handlers/uploads_test.go` - Multiple test cases expecting legacy fields
- `models/user_test.go` - Tests specifically validating password_hash storage

**Impact**: All tests expect legacy authentication patterns instead of OPAQUE workflow

### **Parallel Argon2ID Authentication System**
**File**: `auth/password.go`
- Complete Argon2ID implementation (`HashPassword`, `VerifyPassword` functions)
- Direct conflict with OPAQUE-only architecture goal
- Creates dual authentication paths that should not exist

**Dependencies**: 113+ references to Argon2ID across:
- `config/config.go` - ServerArgon2ID and ClientArgon2ID configuration
- `crypto/kdf.go` - Argon2ID key derivation functions
- `client/main.go` - Client-side Argon2ID encryption
- Multiple WASM and crypto utility files

### **Model Layer Issues**
**File**: `models/user.go`
- `CreateUser()` function uses `password_hash` placeholder in INSERT statements
- Should integrate directly with OPAQUE authentication system
- Comments reference "OPAQUE_AUTH_PLACEHOLDER" anti-pattern

### **Client-Side Legacy Architecture**
**Files**: `client/main.go`, `crypto/kdf.go`, various WASM files
- Client-side Argon2ID key derivation for file encryption
- Password-based key generation instead of OPAQUE export key approach
- Dual client/server key derivation systems

## Architecture Target State

The final architecture must achieve complete OPAQUE unification:

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│ User Password   │ -> │ OPAQUE           │ -> │ Export Key         │
│ (Any Type)      │    │ Authentication   │    │ (64 bytes)         │
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
              │ Account File    │               │ Custom File     │               │ Share Access    │
              │ Encryption Keys │               │ Encryption Keys │               │ Keys            │
              └─────────────────┘               └─────────────────┘               └─────────────────┘
```

### **Core Principles**:
- **Single Authentication Path**: All passwords flow through OPAQUE
- **Export Key Foundation**: All cryptographic operations derive from OPAQUE export keys
- **Zero Argon2ID**: No Argon2ID references anywhere in the system
- **Domain Separation**: Different HKDF info strings prevent key reuse across contexts

## Cleanup Implementation Plan

### **Phase 1: Database Schema Purge**

**Objective**: Eliminate all legacy authentication fields from database schema

**Target Files**:
- `database/database.go` - Main schema definition
- `database/schema_extensions.sql` - Remove outdated comments

**Actions**:
- Remove `password_hash TEXT NOT NULL` from users table
- Remove `password_salt TEXT` from users table  
- Remove inappropriate "backwards compatibility" comments
- Update schema to rely entirely on `opaque_password_records` table for authentication
- Verify foreign key relationships work properly

**Expected Impact**: This will immediately break all contaminated tests (desired outcome)

### **Phase 2: Authentication System Elimination**

**Objective**: Remove complete Argon2ID authentication system

**Target Files**:
- `auth/password.go` - DELETE ENTIRE FILE
- `go.mod` - Remove golang.org/x/crypto/argon2 dependency
- `config/config.go` - Remove ServerArgon2ID and ClientArgon2ID configuration
- All files importing deleted functions

**Actions**:
- Delete `auth/password.go` (HashPassword, VerifyPassword, parseEncodedHash functions)
- Remove `golang.org/x/crypto/argon2` from go.mod using `go mod edit -droprequire`
- Remove Argon2ID configuration options from config structs
- Update all imports that reference deleted functions
- Remove environment variable handling for Argon2ID parameters

**Expected Impact**: Compilation will fail until all references are updated (forcing comprehensive cleanup)

### **Phase 3: Model Layer Migration**

**Objective**: Update user model to work with OPAQUE-only authentication

**Target Files**:
- `models/user.go` - Update CreateUser and GetUserByEmail functions
- `models/user_test.go` - Remove password_hash validation tests

**Actions**:
- Modify `CreateUser()` to work without password_hash field
- Update user struct and queries to remove password_hash/password_salt references
- Integrate properly with existing OPAQUE infrastructure
- Remove "OPAQUE_AUTH_PLACEHOLDER" anti-pattern
- Add proper OPAQUE user record linking

### **Phase 4: Test Infrastructure Overhaul**

**Objective**: Fix all 132+ test references to use OPAQUE authentication patterns

**Target Files**:
- `handlers/auth_test.go` - Update authentication workflow tests
- `handlers/admin_test.go` - Fix all admin user authentication tests
- `handlers/files_test.go` - Update file access authentication tests
- `handlers/uploads_test.go` - Fix upload authentication tests
- `models/user_test.go` - Replace password_hash tests with OPAQUE tests

**Actions**:
- Remove all SQL mock expectations for password_hash/password_salt fields
- Create new test patterns for OPAQUE registration/authentication workflow
- Update user creation tests to use OPAQUE registration
- Implement OPAQUE-based test helpers and utilities
- Verify all handler tests pass with OPAQUE-only authentication

### **Phase 5: Client-Side File Encryption Migration**

**Objective**: Replace client-side Argon2ID with OPAQUE export key approach

**Target Files**:
- `client/main.go` - Remove client-side Argon2ID key derivation
- `crypto/kdf.go` - DELETE FILE (all Argon2ID key derivation functions)
- `crypto/envelope.go` - Update encryption formats
- Various WASM files - Remove Argon2ID JavaScript exports

**Actions**:
- Remove all `DeriveKeyArgon2ID()` function calls
- Delete client-side password-based key derivation
- Remove browser device capability detection for Argon2ID
- Implement OPAQUE export key → HKDF derivation for all file encryption
- Update client to receive file keys from server after OPAQUE authentication
- Remove legacy encryption format versions that use Argon2ID

### **Phase 6: Configuration & Documentation Cleanup**

**Objective**: Remove all Argon2ID configuration and update documentation

**Target Files**:
- `config/config.go` - Remove all Argon2ID configuration structs
- Various documentation files - Update to reflect OPAQUE-only approach
- Environment variable examples - Remove Argon2ID parameters

**Actions**:
- Remove all Argon2ID configuration options from config structs
- Update API documentation to reflect OPAQUE-only approach
- Remove environment variable handling for Argon2ID parameters
- Update setup documentation to remove Argon2ID references
- Document single OPAQUE-based authentication flow

## Implementation Details

### **Database Schema Changes**

**Current Users Table** (to be modified):
```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- REMOVE
    password_salt TEXT,                   -- REMOVE  
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- ... other fields remain
);
```

**Target Users Table**:
```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- ... other fields remain
    -- Authentication handled by opaque_password_records table
);
```

### **Authentication Flow Changes**

**Current Flow** (to be eliminated):
```go
// REMOVE: auth/password.go
hash, err := HashPassword(password)
isValid := VerifyPassword(password, storedHash)
```

**Target Flow** (already implemented):
```go
// USE: auth/opaque_unified.go
opm := auth.NewOPAQUEPasswordManager()
exportKey, err := opm.AuthenticatePassword(recordIdentifier, password)
fileKey := crypto.DeriveFileEncryptionKey(exportKey, fileID, userEmail)
```

### **File Encryption Changes**

**Current Flow** (to be eliminated):
```go
// REMOVE: Client-side Argon2ID derivation
fileKey := argon2.IDKey(password, salt, time, memory, threads, 32)
```

**Target Flow**:
```go
// Server: OPAQUE authentication → export key → file key
exportKey := opaqueAuth.GetExportKey()
fileKey := crypto.DeriveFileEncryptionKey(exportKey, fileID, userEmail)

// Client: Receives file key after OPAQUE authentication
fileKey := receivedFromServerAfterAuth()
```

## Success Criteria

### **Quantitative Metrics**:
- **Argon2ID References**: 0/113 remaining (currently 113)
- **password_hash/password_salt References**: 0/132+ remaining (currently 132+)
- **Compilation**: Clean build with no legacy authentication code
- **Test Coverage**: All tests pass with OPAQUE-only authentication

### **Qualitative Achievements**:
- **Single Authentication System**: All passwords flow through OPAQUE
- **Export Key Utilization**: All cryptographic operations use OPAQUE export keys
- **Memory Safety**: Proper cleanup with `defer crypto.SecureZeroBytes()`
- **Zero-Knowledge Server**: Server never sees plaintext passwords
- **Attack Resistance**: Offline dictionary attacks prevented across all authentication

### **Architecture Verification**:
- No dual authentication paths remain
- No client-side password-based key derivation
- All file encryption uses OPAQUE-derived keys
- Database schema contains no legacy authentication fields
- Configuration contains no Argon2ID options

## Progress Tracking Section

*Progress updates will be appended here as work is completed*

---

**Document Version**: 1.0  
**Created**: 2025-01-29  
**Last Updated**: 2025-01-29  
**Greenfield Status**: Confirmed - No existing users, deployments, or backwards compatibility requirements
