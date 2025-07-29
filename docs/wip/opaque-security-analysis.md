# OPAQUE Authentication Security Analysis and Hardening Recommendations

## Executive Summary

This document provides a comprehensive security analysis of Arkfile's OPAQUE authentication implementation and presents actionable recommendations to strengthen security and privacy protections. The analysis identifies several areas for improvement while acknowledging the solid cryptographic foundation already in place.

## Current Implementation Analysis

### OPAQUE Library Configuration

**Current Setup:**
- **Library**: libopaque by stef (https://github.com/stef/libopaque)
- **Underlying Crypto**: libsodium with ristretto255 curve
- **Key Size**: 32 bytes (256-bit) for all keys
- **OPRF Implementation**: Based on ristretto255 scalar operations
- **Authentication Flow**: Simplified one-step registration and authentication

**Strengths:**
- ✅ Uses ristretto255 curve (highly secure, immune to small subgroup attacks)
- ✅ Based on libsodium (well-audited cryptographic library)
- ✅ Implements proper OPAQUE protocol with password-authenticated key exchange
- ✅ Secure memory handling with cleanup of sensitive data
- ✅ Proper OPRF (Oblivious Pseudorandom Function) implementation

### Current Security Configuration

**Key Management:**
```c
// Current key sizes and algorithms
#define OPAQUE_SHARED_SECRETBYTES 64        // 512-bit shared secrets
#define OPAQUE_USER_RECORD_LEN 256          // User record storage
#define OPAQUE_ENVELOPE_NONCEBYTES 32       // 256-bit nonces
crypto_core_ristretto255_SCALARBYTES        // 32-byte scalars
crypto_scalarmult_SCALARBYTES               // 32-byte key material
crypto_auth_hmacsha512_BYTES                // 64-byte HMAC-SHA512
```

**Protocol Configuration:**
- **Identity Structure**: Simple "user"/"server" identifiers
- **Context String**: "arkfile_auth" for domain separation
- **Export Key**: SHA-512 derived key for additional encryption
- **Server Keys**: Minimal configuration with placeholder implementation

## Security Vulnerabilities and Concerns

### 1. Server Key Management (CRITICAL)

**Current Issue:**
```go
// From auth/opaque.go - SetupServerKeys function
serverID := "arkfile-server"
_, err = db.Exec(`
    INSERT INTO opaque_server_keys (id, server_secret_key, server_public_key, oprf_seed)
    VALUES (1, ?, ?, ?)`,
    hex.EncodeToString([]byte(serverID)), // Using serverID as secret key!
    hex.EncodeToString([]byte(serverID)), // Using serverID as public key!
    hex.EncodeToString([]byte(serverID)), // Using serverID as OPRF seed!
)
```

**Security Impact:** CRITICAL - The current implementation stores the same string value as the server secret key, public key, and OPRF seed. This completely undermines the security of the OPAQUE protocol.

**Recommendation:** Implement proper cryptographic key generation using libsodium's secure random number generation.

### 2. Identity Configuration (MEDIUM)

**Current Issue:**
```c
// From auth/opaque_wrapper.c
Opaque_Ids ids = {
    .idU_len = 4,
    .idU = (uint8_t*)"user",    // Generic identifier
    .idS_len = 6,
    .idS = (uint8_t*)"server"   // Generic identifier
};
```

**Security Impact:** MEDIUM - Generic identities reduce the cryptographic binding and make the protocol less resistant to certain attack scenarios.

**Recommendation:** Use domain-specific identities that include server domain and user email addresses.

### 3. Context Configuration (LOW)

**Current Issue:**
```c
const uint8_t context[] = "arkfile_auth";
const uint16_t context_len = sizeof(context) - 1;
```

**Security Impact:** LOW - While functional, the context string could be more specific to provide better domain separation.

**Recommendation:** Use more specific context strings that include protocol version and application details.

### 4. Export Key Handling (MEDIUM)

**Current Issue:**
```go
// From auth/opaque.go - RegisterUser function
exportKey, err := libopaqueRegisterUser(passwordBytes)
if err != nil {
    return fmt.Errorf("libopaque registration failed: %w", err)
}
// Clear the export key for security (we don't store it)
crypto.SecureZeroBytes(exportKey)
```

**Security Impact:** MEDIUM - The export key is generated but immediately discarded, missing opportunities for additional security features.

**Recommendation:** Utilize export keys for additional encryption/authentication of user data.

## Hardening Recommendations

### 1. Implement Proper Server Key Generation

**Replace the current placeholder implementation:**

```go
// New implementation for auth/opaque.go
func generateOPAQUEServerKeys() (*OPAQUEServerKeys, error) {
    // Generate cryptographically secure server keypair
    serverPrivateKey := make([]byte, crypto_scalarmult_SCALARBYTES) // 32 bytes
    serverPublicKey := make([]byte, crypto_scalarmult_BYTES)        // 32 bytes
    oprfSeed := make([]byte, crypto_core_ristretto255_SCALARBYTES)  // 32 bytes
    
    // Use libsodium's secure random number generation
    if _, err := rand.Read(serverPrivateKey); err != nil {
        return nil, fmt.Errorf("failed to generate server private key: %w", err)
    }
    
    if _, err := rand.Read(oprfSeed); err != nil {
        return nil, fmt.Errorf("failed to generate OPRF seed: %w", err)
    }
    
    // Derive public key from private key using scalar multiplication
    // This requires calling into libsodium via CGO
    if err := derivePublicKey(serverPrivateKey, serverPublicKey); err != nil {
        return nil, fmt.Errorf("failed to derive public key: %w", err)
    }
    
    return &OPAQUEServerKeys{
        ServerPrivateKey: serverPrivateKey,
        ServerPublicKey:  serverPublicKey,
        OPRFSeed:        oprfSeed,
        CreatedAt:       time.Now(),
    }, nil
}
```

### 2. Enhanced Identity Configuration

**Implement domain-specific identities:**

```c
// Enhanced opaque_wrapper.c identity configuration
int arkfile_create_ids(const char* user_email, const char* server_domain, Opaque_Ids* ids) {
    // Allocate memory for enhanced identities
    size_t user_len = strlen(user_email);
    size_t server_len = strlen(server_domain);
    
    ids->idU = malloc(user_len);
    ids->idS = malloc(server_len);
    
    if (!ids->idU || !ids->idS) {
        return -1; // Memory allocation failed
    }
    
    memcpy(ids->idU, user_email, user_len);
    memcpy(ids->idS, server_domain, server_len);
    
    ids->idU_len = user_len;
    ids->idS_len = server_len;
    
    return 0;
}
```

### 3. Enhanced Context Strings

**Implement versioned, domain-specific contexts:**

```c
// Enhanced context generation
int arkfile_create_context(const char* operation, uint8_t** context, uint16_t* context_len) {
    const char* app_name = "arkfile";
    const char* version = "v1.0";
    const char* domain = "file-sharing";
    
    // Format: "arkfile/v1.0/file-sharing/{operation}"
    size_t total_len = strlen(app_name) + strlen(version) + strlen(domain) + 
                       strlen(operation) + 4; // For separators
    
    *context = malloc(total_len);
    if (!*context) return -1;
    
    snprintf((char*)*context, total_len, "%s/%s/%s/%s", 
             app_name, version, domain, operation);
    
    *context_len = total_len - 1; // Exclude null terminator
    return 0;
}
```

### 4. Export Key Utilization

**Implement secure export key handling:**

```go
// Enhanced export key handling in auth/opaque.go
type ExportKeyManager struct {
    userEmail string
    exportKey []byte
}

func (ekm *ExportKeyManager) DeriveEncryptionKey() ([]byte, error) {
    // Use HKDF to derive specific-purpose keys from export key
    salt := []byte("arkfile-file-encryption")
    info := []byte(fmt.Sprintf("user:%s:file-key", ekm.userEmail))
    
    return hkdf.Expand(sha256.New, ekm.exportKey, info, 32), nil
}

func (ekm *ExportKeyManager) DeriveAuthenticationKey() ([]byte, error) {
    salt := []byte("arkfile-auth-binding")
    info := []byte(fmt.Sprintf("user:%s:auth-key", ekm.userEmail))
    
    return hkdf.Expand(sha256.New, ekm.exportKey, info, 32), nil
}

func (ekm *ExportKeyManager) SecureCleanup() {
    crypto.SecureZeroBytes(ekm.exportKey)
}
```

### 5. Enhanced Parameter Configuration

**Strengthen cryptographic parameters:**

```c
// Enhanced opaque_wrapper.h with stronger parameters
#define ARKFILE_OPAQUE_CONTEXT_VERSION "arkfile/v1.0/auth"
#define ARKFILE_OPAQUE_SALT_SIZE 32        // 256-bit salts
#define ARKFILE_OPAQUE_NONCE_SIZE 32       // 256-bit nonces
#define ARKFILE_SERVER_DOMAIN "arkfile.local" // Configurable server domain

// Enhanced server configuration structure
typedef struct {
    uint8_t server_private_key[crypto_scalarmult_SCALARBYTES];
    uint8_t server_public_key[crypto_scalarmult_BYTES];
    uint8_t oprf_seed[crypto_core_ristretto255_SCALARBYTES];
    uint8_t domain_separator[64];
    uint32_t key_version;
    time_t created_at;
    time_t expires_at;
} arkfile_server_config_t;
```

### 6. Database Schema Hardening

**Enhanced database schema for OPAQUE keys:**

```sql
-- Enhanced OPAQUE server keys table
CREATE TABLE IF NOT EXISTS opaque_server_keys (
    id INTEGER PRIMARY KEY,
    server_private_key BLOB NOT NULL,           -- 32 bytes, encrypted at rest
    server_public_key BLOB NOT NULL,            -- 32 bytes
    oprf_seed BLOB NOT NULL,                    -- 32 bytes, encrypted at rest
    domain_separator TEXT NOT NULL,             -- Server domain
    key_version INTEGER NOT NULL DEFAULT 1,     -- For key rotation
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,                        -- For key rotation scheduling
    is_active BOOLEAN DEFAULT TRUE,
    key_derivation_info JSON,                   -- Metadata for key derivation
    UNIQUE(key_version, is_active)              -- Ensure only one active key per version
);

-- Enhanced OPAQUE user data table with metadata
CREATE TABLE IF NOT EXISTS opaque_user_data (
    user_email TEXT PRIMARY KEY,
    serialized_record BLOB NOT NULL,            -- OPAQUE user record
    server_key_version INTEGER NOT NULL,        -- Track which server key was used
    registration_timestamp DATETIME NOT NULL,
    last_auth_timestamp DATETIME,
    auth_failure_count INTEGER DEFAULT 0,
    record_version INTEGER DEFAULT 1,
    metadata JSON,                              -- Additional security metadata
    FOREIGN KEY (user_email) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY (server_key_version) REFERENCES opaque_server_keys(key_version)
);

-- Indexes for performance and security queries
CREATE INDEX IF NOT EXISTS idx_opaque_server_keys_version ON opaque_server_keys(key_version, is_active);
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_key_version ON opaque_user_data(server_key_version);
CREATE INDEX IF NOT EXISTS idx_opaque_user_data_auth_failures ON opaque_user_data(auth_failure_count, last_auth_timestamp);
```

### 7. Security Monitoring and Alerting

**Implement OPAQUE-specific security monitoring:**

```go
// Security monitoring for OPAQUE authentication
type OPAQUESecurityMonitor struct {
    logger *logging.SecurityLogger
    alerts chan SecurityAlert
}

func (osm *OPAQUESecurityMonitor) MonitorAuthenticationAttempt(email string, success bool, metadata map[string]interface{}) {
    event := SecurityEvent{
        Type:        "opaque_authentication",
        UserEmail:   email,
        Success:     success,
        Timestamp:   time.Now(),
        Metadata:    metadata,
    }
    
    // Check for suspicious patterns
    if !success {
        osm.trackFailedAuthentication(email)
    }
    
    // Log security event
    osm.logger.LogSecurityEvent(event)
}

func (osm *OPAQUESecurityMonitor) trackFailedAuthentication(email string) {
    // Implement rate limiting and alerting for failed authentications
    failures := osm.getRecentFailures(email, time.Hour)
    
    if failures > 5 {
        alert := SecurityAlert{
            Type:      "excessive_auth_failures",
            Severity:  "HIGH",
            UserEmail: email,
            Message:   fmt.Sprintf("User %s has %d failed authentication attempts in the last hour", email, failures),
        }
        
        select {
        case osm.alerts <- alert:
        default:
            // Alert channel full, log directly
            osm.logger.LogSecurityAlert(alert)
        }
    }
}
```

## Privacy Enhancements

### 1. Zero-Knowledge Proofs Integration

**Consider integrating zero-knowledge proofs for enhanced privacy:**

```go
// Privacy-preserving authentication metadata
type PrivateAuthMetadata struct {
    TimingResistantAuth bool   // Constant-time authentication
    ZKProofValidation  bool    // Zero-knowledge proof of password knowledge
    MetadataBlinding   bool    // Blind authentication metadata
}
```

### 2. Differential Privacy for Authentication Logs

**Implement differential privacy for authentication analytics:**

```go
// Differential privacy for authentication statistics
type DifferentialPrivacyManager struct {
    epsilon float64  // Privacy budget
    delta   float64  // Privacy parameter
}

func (dpm *DifferentialPrivacyManager) GetNoisy AuthenticationStats(timeWindow time.Duration) AuthStats {
    realStats := dpm.getRealStats(timeWindow)
    
    // Add calibrated Laplace noise to preserve privacy
    noise := dpm.generateLaplaceNoise(1.0 / dpm.epsilon)
    
    return AuthStats{
        TotalAttempts:    realStats.TotalAttempts + int(noise),
        SuccessfulAuths: realStats.SuccessfulAuths + int(noise),
        FailedAuths:     realStats.FailedAuths + int(noise),
    }
}
```

## Implementation Priority and Timeline

### Phase 1: Critical Security Fixes (Week 1-2)
1. **CRITICAL**: Implement proper server key generation
2. **CRITICAL**: Fix placeholder key storage implementation
3. **HIGH**: Add proper key validation and integrity checks
4. **HIGH**: Implement secure key rotation infrastructure

### Phase 2: Protocol Hardening (Week 3-4)
1. **MEDIUM**: Enhance identity configuration with domain-specific IDs
2. **MEDIUM**: Implement export key utilization for additional encryption
3. **MEDIUM**: Add enhanced context strings with versioning
4. **MEDIUM**: Implement comprehensive security monitoring

### Phase 3: Advanced Features (Week 5-6)
1. **LOW**: Add zero-knowledge proof integration
2. **LOW**: Implement differential privacy for analytics
3. **LOW**: Add advanced key rotation scheduling
4. **LOW**: Performance optimization and benchmarking

---

# OPAQUE Password System Migration Plan

## Overview

This section outlines the comprehensive migration plan to eliminate Argon2ID password hashing and consolidate all password authentication around OPAQUE. This migration will unify account passwords, custom file passwords, and share link passwords under a single, cryptographically superior authentication system.

## Current Password System Issues

### Critical Problems Identified

1. **Missing JavaScript Security Libraries**
   - HTML files reference `/js/security.js` and `/js/multi-key-encryption.js` that return 404 errors
   - Client-side password hashing functionality is broken
   - No fallback or server-side password processing

2. **Inconsistent Password Storage**
   - Account passwords: OPAQUE (good)
   - Custom file passwords: Client-side only (good)
   - Share link passwords: Argon2ID hashes with salts (inconsistent)

3. **Weak Share ID Generation**
   - Current `generateShareID()` uses 16 random bytes + hex encoding
   - Should use collision-resistant UUIDs (UUIDv4 or UUIDv7)

4. **Underutilized OPAQUE Export Keys**
   - Export keys generated during authentication but immediately discarded
   - Missing opportunity for unified file encryption key derivation

### Legacy JavaScript References to Remove

```html
<!-- Remove these broken references from HTML files: -->
<script src="/js/security.js"></script>                    <!-- 404 error -->
<script src="/js/multi-key-encryption.js"></script>        <!-- 404 error -->
<script src="/js/chunked-uploader.js"></script>           <!-- 404 error -->
<script src="/js/chunked-downloader.js"></script>         <!-- 404 error -->
<script src="/js/chunked-upload-ui.js"></script>          <!-- 404 error -->
```

All functionality should be in the compiled TypeScript: `/js/dist/app.js`

## OPAQUE-Unified Password Architecture

### Core Principle

**Single Cryptographic Framework:**
```
All Passwords → OPAQUE Authentication → Export Keys → File Encryption Keys
```

### Three Password Types, One System

#### 1. Account Passwords (Already OPAQUE)
```go
// Current: Already using OPAQUE ✅
User Account Password → OPAQUE Auth → Export Key → Account File Encryption Keys
```

#### 2. Custom File Passwords (Migrate to OPAQUE)
```go
// New: Each custom password becomes its own OPAQUE registration
Custom File Password → OPAQUE Registration → Export Key → File-Specific Encryption Key

func RegisterCustomFilePassword(userEmail, fileID, customPassword string) error {
    // Create unique OPAQUE user ID for this file password
    opaqueUserID := fmt.Sprintf("%s:file:%s", userEmail, fileID)
    
    // Register custom password with OPAQUE
    userRecord, exportKey, err := libopaqueRegisterUser([]byte(customPassword))
    if err != nil {
        return err
    }
    
    // Derive file encryption key from export key
    fileEncryptionKey := deriveFileEncryptionKey(exportKey, fileID, userEmail)
    
    // Store OPAQUE record and derived key
    return storeCustomFileOPAQUERecord(fileID, opaqueUserID, userRecord, fileEncryptionKey)
}
```

#### 3. Share Link Passwords (Migrate to OPAQUE)
```go
// New: Share passwords become anonymous OPAQUE registrations
Share Password → OPAQUE Registration → Export Key → File Access Key

func CreatePasswordProtectedShare(fileID, sharePassword string) (string, error) {
    shareID := uuid.New().String() // ✅ Use proper UUID instead of random bytes
    
    // Register share password with OPAQUE (anonymous registration)
    userRecord, exportKey, err := libopaqueRegisterUser([]byte(sharePassword))
    if err != nil {
        return "", err
    }
    
    // Derive file access key from export key
    fileAccessKey := deriveShareAccessKey(exportKey, shareID, fileID)
    
    // Store OPAQUE record for anonymous access
    return shareID, storeShareOPAQUERecord(shareID, userRecord, fileAccessKey)
}
```

## Database Schema Migration

### New OPAQUE-Unified Schema

```sql
-- Replace current password hash tables with unified OPAQUE records
CREATE TABLE IF NOT EXISTS opaque_password_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_type TEXT NOT NULL,              -- 'account', 'file_custom', 'share'
    record_identifier TEXT NOT NULL UNIQUE, -- email, 'user:file:filename', 'share:shareID'
    opaque_user_record BLOB NOT NULL,       -- OPAQUE registration data
    associated_file_id TEXT,                -- NULL for account, filename for file/share
    associated_user_email TEXT,             -- User who created this record
    key_label TEXT,                         -- Human-readable label
    password_hint_encrypted BLOB,           -- Encrypted with export key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Indexes for fast lookups
    UNIQUE(record_type, record_identifier),
    INDEX idx_opaque_records_type (record_type),
    INDEX idx_opaque_records_file (associated_file_id),
    INDEX idx_opaque_records_user (associated_user_email)
);

-- Derived keys table (encrypted file keys derived from OPAQUE export keys)
CREATE TABLE IF NOT EXISTS derived_file_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    opaque_record_id INTEGER NOT NULL,
    file_id TEXT NOT NULL,
    encrypted_file_key BLOB NOT NULL,       -- File key encrypted with derived KEK
    key_derivation_info JSON NOT NULL,      -- HKDF parameters and context
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (opaque_record_id) REFERENCES opaque_password_records(id) ON DELETE CASCADE,
    UNIQUE(opaque_record_id, file_id)
);

-- Replace file_shares table
CREATE TABLE IF NOT EXISTS file_shares_v2 (
    id TEXT PRIMARY KEY,                    -- UUIDv4 share ID
    file_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    opaque_record_id INTEGER,               -- NULL if not password protected
    share_type TEXT NOT NULL DEFAULT 'public', -- 'public', 'password_protected'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    last_accessed DATETIME,
    access_count INTEGER DEFAULT 0,
    
    FOREIGN KEY (opaque_record_id) REFERENCES opaque_password_records(id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES file_metadata(filename),
    FOREIGN KEY (owner_email) REFERENCES users(email)
);

-- Migration tracking
CREATE TABLE IF NOT EXISTS password_migration_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    migration_type TEXT NOT NULL,           -- 'argon2id_to_opaque', 'share_password', etc.
    old_record_id TEXT,
    new_record_id INTEGER,
    user_email TEXT,
    migrated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    migration_status TEXT DEFAULT 'completed', -- 'pending', 'completed', 'failed'
    notes TEXT,
    
    FOREIGN KEY (new_record_id) REFERENCES opaque_password_records(id)
);
```

### Database Migration Steps

```sql
-- Step 1: Create new tables
-- (See schema above)

-- Step 2: Migrate existing share data (Argon2ID → OPAQUE will require user re-entry)
INSERT INTO password_migration_log (migration_type, old_record_id, user_email, migration_status, notes)
SELECT 'share_password_requires_reset', id, owner_email, 'pending', 
       'Share passwords using Argon2ID must be reset by users'
FROM file_shares;

-- Step 3: Create public shares for non-password protected shares
INSERT INTO file_shares_v2 (id, file_id, owner_email, share_type)
SELECT id, file_id, owner_email, 'public'
FROM file_shares 
WHERE is_password_protected = FALSE;

-- Step 4: Mark password-protected shares for user migration
INSERT INTO file_shares_v2 (id, file_id, owner_email, share_type)
SELECT id, file_id, owner_email, 'password_migration_required'
FROM file_shares 
WHERE is_password_protected = TRUE;

-- Step 5: Drop old tables after migration confirmation
-- DROP TABLE file_shares;
-- DROP TABLE file_encryption_keys; (if using separate custom password storage)
```

## Implementation Plan

### Phase 1: Infrastructure & Cleanup (Week 1-2)

#### 1.1 Fix Share ID Generation
```go
// handlers/file_shares.go - Replace generateShareID()
func generateShareID() string {
    return uuid.New().String() // Collision-resistant UUIDv4
}
```

#### 1.2 Remove Broken JavaScript References
Update HTML files to remove 404-causing script references:

**Files to update:**
- `client/static/shared.html`
- `client/static/file-share.html`  
- `client/static/chunked-upload.html`
- `client/static/index.html` (verify current references)

**Remove these lines:**
```html
<script src="/js/security.js"></script>
<script src="/js/multi-key-encryption.js"></script>
<script src="/js/chunked-uploader.js"></script>
<script src="/js/chunked-downloader.js"></script>
<script src="/js/chunked-upload-ui.js"></script>
```

#### 1.3 Implement OPAQUE Password Record Management
```go
// New file: auth/opaque_unified.go

type OPAQUEPasswordManager struct {
    db *sql.DB
}

type PasswordRecord struct {
    ID                 int
    RecordType         string    // 'account', 'file_custom', 'share'
    RecordIdentifier   string    // Unique identifier for this password
    OpaqueUserRecord   []byte    // OPAQUE registration data
    AssociatedFileID   *string   // Optional file association
    AssociatedUserEmail *string  // User who created this record
    KeyLabel           *string   // Human-readable label
    PasswordHintEncrypted []byte // Encrypted hint
    CreatedAt          time.Time
    LastUsedAt         *time.Time
    IsActive           bool
}

func (opm *OPAQUEPasswordManager) RegisterCustomFilePassword(
    userEmail, fileID, password, keyLabel, passwordHint string) error {
    
    recordIdentifier := fmt.Sprintf("%s:file:%s", userEmail, fileID)
    
    // Register with OPAQUE
    userRecord, exportKey, err := libopaqueRegisterUser([]byte(password))
    if err != nil {
        return fmt.Errorf("OPAQUE registration failed: %w", err)
    }
    defer crypto.SecureZeroBytes(exportKey) // Clean up export key
    
    // Encrypt password hint with export key if provided
    var encryptedHint []byte
    if passwordHint != "" {
        encryptedHint, err = encryptPasswordHint(passwordHint, exportKey)
        if err != nil {
            return fmt.Errorf("failed to encrypt password hint: %w", err)
        }
    }
    
    // Store OPAQUE record
    _, err = opm.db.Exec(`
        INSERT INTO opaque_password_records 
        (record_type, record_identifier, opaque_user_record, associated_file_id, 
         associated_user_email, key_label, password_hint_encrypted)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        "file_custom", recordIdentifier, userRecord, fileID, userEmail, keyLabel, encryptedHint)
    
    return err
}

func (opm *OPAQUEPasswordManager) RegisterSharePassword(
    shareID, fileID, ownerEmail, password string) error {
    
    recordIdentifier := fmt.Sprintf("share:%s", shareID)
    
    // Register with OPAQUE (anonymous)
    userRecord, exportKey, err := libopaqueRegisterUser([]byte(password))
    if err != nil {
        return fmt.Errorf("OPAQUE registration failed: %w", err)
    }
    defer crypto.SecureZeroBytes(exportKey)
    
    // Store OPAQUE record
    _, err = opm.db.Exec(`
        INSERT INTO opaque_password_records 
        (record_type, record_identifier, opaque_user_record, associated_file_id, associated_user_email)
        VALUES (?, ?, ?, ?, ?)`,
        "share", recordIdentifier, userRecord, fileID, ownerEmail)
    
    return err
}

func (opm *OPAQUEPasswordManager) AuthenticatePassword(
    recordIdentifier, password string) ([]byte, error) {
    
    // Get OPAQUE user record
    var userRecord []byte
    err := opm.db.QueryRow(`
        SELECT opaque_user_record FROM opaque_password_records 
        WHERE record_identifier = ? AND is_active = TRUE`,
        recordIdentifier).Scan(&userRecord)
    
    if err != nil {
        return nil, fmt.Errorf("password record not found: %w", err)
    }
    
    // Authenticate with OPAQUE
    exportKey, err := libopaqueAuthenticateUser([]byte(password), userRecord)
    if err != nil {
        return nil, fmt.Errorf("OPAQUE authentication failed: %w", err)
    }
    
    // Update last used timestamp
    _, _ = opm.db.Exec(`
        UPDATE opaque_password_records 
        SET last_used_at = CURRENT_TIMESTAMP 
        WHERE record_identifier = ?`, recordIdentifier)
    
    return exportKey, nil
}
```

#### 1.4 Export Key Derivation System
```go
// New file: crypto/key_derivation.go

// Standardized key derivation from OPAQUE export keys
func DeriveFileEncryptionKey(exportKey []byte, fileID, userEmail string) ([]byte, error) {
    info := fmt.Sprintf("arkfile-file-encryption:%s:%s", userEmail, fileID)
    return hkdf.Expand(sha256.New, exportKey, []byte(info), 32), nil
}

func DeriveShareAccessKey(exportKey []byte, shareID, fileID string) ([]byte, error) {
    info := fmt.Sprintf("arkfile-share-access:%s:%s", shareID, fileID)
    return hkdf.Expand(sha256.New, exportKey, []byte(info), 32), nil
}

func DerivePasswordHintKey(exportKey []byte, recordIdentifier string) ([]byte, error) {
    info := fmt.Sprintf("arkfile-hint-encryption:%s", recordIdentifier)
    return hkdf.Expand(sha256.New, exportKey, []byte(info), 32), nil
}

// Password hint encryption/decryption
func encryptPasswordHint(hint string, exportKey []byte) ([]byte, error) {
    hintKey, err := DerivePasswordHintKey(exportKey, "hint")
    if err != nil {
        return nil, err
    }
    
    // Use AES-GCM for hint encryption
    return crypto.EncryptAESGCM([]byte(hint), hintKey)
}

func decryptPasswordHint(encryptedHint, exportKey []byte) (string, error) {
    hintKey, err := DerivePasswordHintKey(exportKey, "hint")
    if err != nil {
        return "", err
    }
    
    decrypted, err := crypto.DecryptAESGCM(encryptedHint, hintKey)
    if err != nil {
        return "", err
    }
    
    return string(decrypted), nil
}
```

### Phase 2: OPAQUE Share Link Implementation (Week 3-4)

#### 2.1 Anonymous Share Authentication
```go
// handlers/file_shares.go - New OPAQUE-based share creation

func ShareFile(c echo.Context) error {
    email := auth.GetEmailFromToken(c)
    
    var request struct {
        FileID            string `json:"fileId"`
        PasswordProtected bool   `json:"passwordProtected"`
        SharePassword     string `json:"sharePassword,omitempty"`
        ExpiresAfterHours int    `json:"expiresAfterHours"`
    }
    
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
    }
    
    // Validate file ownership
    var ownerEmail string
    err := database.DB.QueryRow(
        "SELECT owner_email FROM file_metadata WHERE filename = ?",
        request.FileID,
    ).Scan(&ownerEmail)
    
    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "File not found")
    } else if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
    }
    
    if ownerEmail != email {
        return echo.NewHTTPError(http.StatusForbidden, "Not authorized to share this file")
    }
    
    // Generate collision-resistant share ID
    shareID := uuid.New().String()
    
    // Calculate expiration time
    var expiresAt *time.Time
    if request.ExpiresAfterHours > 0 {
        expiry := time.Now().Add(time.Duration(request.ExpiresAfterHours) * time.Hour)
        expiresAt = &expiry
    }
    
    var opaqueRecordID *int
    
    // Handle password-protected shares
    if request.PasswordProtected && request.SharePassword != "" {
        // Initialize OPAQUE password manager
        opm := &OPAQUEPasswordManager{db: database.DB}
        
        // Register share password with OPAQUE
        err = opm.RegisterSharePassword(shareID, request.FileID, email, request.SharePassword)
        if err != nil {
            logging.ErrorLogger.Printf("Failed to register share password: %v", err)
            return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create password-protected share")
        }
        
        // Get the record ID for the foreign key
        var recordID int
        err = database.DB.QueryRow(`
            SELECT id FROM opaque_password_records 
            WHERE record_identifier = ?`,
            fmt.Sprintf("share:%s", shareID)).Scan(&recordID)
        
        if err != nil {
            return echo.NewHTTPError(http.StatusInternalServerError, "Failed to link share password")
        }
        
        opaqueRecordID = &recordID
    }
    
    // Create share record
    shareType := "public"
    if request.PasswordProtected {
        shareType = "password_protected"
    }
    
    _, err = database.DB.Exec(`
        INSERT INTO file_shares_v2 (id, file_id, owner_email, opaque_record_id, share_type, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)`,
        shareID, request.FileID, email, opaqueRecordID, shareType, expiresAt)
    
    if err != nil {
        logging.ErrorLogger.Printf("Failed to create share record: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create share")
    }
    
    // Build share URL
    baseURL := getBaseURL(c)
    shareURL := fmt.Sprintf("%s/shared/%s", baseURL, shareID)
    
    logging.InfoLogger.Printf("File shared: %s by %s, share ID: %s", request.FileID, email, shareID)
    
    return c.JSON(http.StatusOK, map[string]interface{}{
        "shareId":             shareID,
        "shareUrl":            shareURL,
        "isPasswordProtected": request.PasswordProtected,
        "expiresAt":           expiresAt,
        "createdAt":           time.Now(),
    })
}

// Anonymous share access with OPAQUE authentication
func AuthenticateShare(c echo.Context) error {
    shareID := c.Param("id")
    
    var request struct {
        Password string `json:"password"`
    }
    
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
    }
    
    // Validate share exists and get details
    var share struct {
        FileID          string
        OwnerEmail      string
        OpaqueRecordID  *int
        ShareType       string
        ExpiresAt       *time.Time
    }
    
    err := database.DB.QueryRow(`
        SELECT file_id, owner_email, opaque_record_id, share_type, expires_at
        FROM file_shares_v2 
        WHERE id = ?`, shareID).Scan(
            &share.FileID, 
            &share.OwnerEmail, 
            &share.OpaqueRecordID, 
            &share.ShareType,
            &share.ExpiresAt)
    
    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "Share not found")
    } else if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
    }
    
    // Check if share has expired
    if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
        return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
    }
    
    // If not password protected, allow access
    if share.ShareType == "public" {
        return c.JSON(http.StatusOK, map[string]string{
            "message": "Access granted",
        })
    }
    
    // For password-protected shares, authenticate with OPAQUE
    if share.OpaqueRecordID == nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Share configuration error")
    }
    
    // Initialize OPAQUE password manager
    opm := &OPAQUEPasswordManager{db: database.DB}
    
    // Authenticate share password
    recordIdentifier := fmt.Sprintf("share:%s", shareID)
    exportKey, err := opm.AuthenticatePassword(recordIdentifier, request.Password)
    if err != nil {
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid password")
    }
    defer crypto.SecureZeroBytes(exportKey) // Clean up
    
    // Update access tracking
    _, _ = database.DB.Exec(`
        UPDATE file_shares_v2 
        SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 
        WHERE id = ?`, shareID)
    
    logging.InfoLogger.Printf("Share authentication successful: %s", shareID)
    
    return c.JSON(http.StatusOK, map[string]string{
        "message": "Authentication successful",
    })
}

// Download shared file with OPAQUE key derivation
func DownloadSharedFile(c echo.Context) error {
    shareID := c.Param("id")
    
    // Get share details
    var share struct {
        FileID          string
        OwnerEmail      string
        OpaqueRecordID  *int
        ShareType       string
        ExpiresAt       *time.Time
    }
    
    err := database.DB.QueryRow(`
        SELECT file_id, owner_email, opaque_record_id, share_type, expires_at
        FROM file_shares_v2 
        WHERE id = ?`, shareID).Scan(
            &share.FileID, 
            &share.OwnerEmail, 
            &share.OpaqueRecordID, 
            &share.ShareType,
            &share.ExpiresAt)
    
    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "Share not found")
    } else if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Database error")
    }
    
    // Check expiration
    if share.ExpiresAt != nil && time.Now().After(*share.ExpiresAt) {
        return echo.NewHTTPError(http.StatusForbidden, "Share link has expired")
    }
    
    // Get file metadata
    var fileMetadata struct {
        Filename     string
        SHA256Sum    string
        PasswordHint string
        MultiKey     bool
        Size         int64
    }
    
    err = database.DB.QueryRow(`
        SELECT filename, sha256sum, password_hint, multi_key, size_bytes
        FROM file_metadata WHERE filename = ?`,
        share.FileID).Scan(
            &fileMetadata.Filename,
            &fileMetadata.SHA256Sum,
            &fileMetadata.PasswordHint,
            &fileMetadata.MultiKey,
            &fileMetadata.Size)
    
    if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "File metadata error")
    }
    
    // Get encrypted file from storage
    object, err := storage.Provider.GetObject(
        c.Request().Context(),
        share.FileID,
        minio.GetObjectOptions{},
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to retrieve shared file from storage: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve file")
    }
    defer object.Close()
    
    data, err := io.ReadAll(object)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to read shared file: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to read file")
    }
    
    // Update access tracking
    _, _ = database.DB.Exec(`
        UPDATE file_shares_v2 
        SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1 
        WHERE id = ?`, shareID)
    
    logging.InfoLogger.Printf("Downloaded shared file: %s, file: %s", shareID, share.FileID)
    
    // Return encrypted file data with metadata
    return c.JSON(http.StatusOK, map[string]interface{}{
        "data":              string(data),
        "filename":          fileMetadata.Filename,
        "sha256sum":         fileMetadata.SHA256Sum,
        "passwordHint":      fileMetadata.PasswordHint,
        "isMultiKey":        fileMetadata.MultiKey,
        "size":              fileMetadata.Size,
        "shareType":         share.ShareType,
        "requiresPassword":  share.ShareType == "password_protected",
    })
}
```

#### 2.2 TypeScript Client OPAQUE Integration
```typescript
// client/static/js/src/utils/opaque-client.ts

export class OPAQUEClient {
    private wasmInstance: any;
    
    constructor() {
        // Initialize WebAssembly OPAQUE implementation
        this.initializeWasm();
    }
    
    private async initializeWasm(): Promise<void> {
        // Load OPAQUE WebAssembly module
        // This should be compiled from the same libopaque library
        if (typeof window !== 'undefined' && (window as any).libopaqueWasm) {
            this.wasmInstance = (window as any).libopaqueWasm;
        } else {
            throw new Error('OPAQUE WebAssembly module not loaded');
        }
    }
    
    async registerPassword(password: string): Promise<{userRecord: Uint8Array, exportKey: Uint8Array}> {
        if (!this.wasmInstance) {
            throw new Error('OPAQUE client not initialized');
        }
        
        // Use WebAssembly OPAQUE registration
        const result = await this.wasmInstance.registerUser(password);
        
        return {
            userRecord: new Uint8Array(result.userRecord),
            exportKey: new Uint8Array(result.exportKey)
        };
    }
    
    async authenticatePassword(password: string, userRecord: Uint8Array): Promise<Uint8Array> {
        if (!this.wasmInstance) {
            throw new Error('OPAQUE client not initialized');
        }
        
        // Use WebAssembly OPAQUE authentication
        const result = await this.wasmInstance.authenticateUser(password, userRecord);
        
        return new Uint8Array(result.exportKey);
    }
    
    // Key derivation functions matching Go implementation
    deriveFileEncryptionKey(exportKey: Uint8Array, fileID: string, userEmail: string): Uint8Array {
        const info = `arkfile-file-encryption:${userEmail}:${fileID}`;
        return this.hkdfExpand(exportKey, new TextEncoder().encode(info), 32);
    }
    
    deriveShareAccessKey(exportKey: Uint8Array, shareID: string, fileID: string): Uint8Array {
        const info = `arkfile-share-access:${shareID}:${fileID}`;
        return this.hkdfExpand(exportKey, new TextEncoder().encode(info), 32);
    }
    
    private hkdfExpand(key: Uint8Array, info: Uint8Array, length: number): Uint8Array {
        // HKDF-Expand implementation using Web Crypto API
        // This should match the Go implementation exactly
        return crypto.subtle.deriveBits({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: info
        }, key, length * 8).then(bits => new Uint8Array(bits));
    }
}

// Global OPAQUE client instance
export const opaqueClient = new OPAQUEClient();
```

#### 2.3 Client-Side Share Password Handling
```typescript
// client/static/js/src/files/share.ts

import { opaqueClient } from '../utils/opaque-client';
import { showError, showSuccess } from '../ui/messages';

export class ShareManager {
    
    async accessPasswordProtectedShare(shareID: string, password: string): Promise<any> {
        try {
            // First, authenticate the share password with OPAQUE
            const authResponse = await fetch(`/api/shared/${shareID}/auth`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password })
            });
            
            if (!authResponse.ok) {
                throw new Error('Invalid password');
            }
            
            // If authentication successful, download the file
            const fileResponse = await fetch(`/api/shared/${shareID}/download`);
            
            if (!fileResponse.ok) {
                throw new Error('Failed to download file');
            }
            
            const fileData = await fileResponse.json();
            
            // For password-protected shares, we may need to derive the decryption key
            // from the OPAQUE export key if the file uses custom encryption
            if (fileData.requiresPassword && fileData.isMultiKey) {
                // Get OPAQUE user record for this share
                const recordResponse = await fetch(`/api/shared/${shareID}/opaque-record`);
                const recordData = await recordResponse.json();
                
                // Authenticate to get export key
                const exportKey = await opaqueClient.authenticatePassword(
                    password, 
                    new Uint8Array(recordData.opaqueUserRecord)
                );
                
                // Derive file access key
                const fileAccessKey = opaqueClient.deriveShareAccessKey(
                    exportKey, 
                    shareID, 
                    fileData.filename
                );
                
                // Decrypt file with derived key
                const decryptedData = await this.decryptFileData(fileData.data, fileAccessKey);
                
                return {
                    ...fileData,
                    data: decryptedData
                };
            }
            
            return fileData;
            
        } catch (error) {
            showError(`Failed to access shared file: ${error.message}`);
            throw error;
        }
    }
    
    private async decryptFileData(encryptedData: string, key: Uint8Array): Promise<string> {
        // Implement AES-GCM decryption matching server-side implementation
        // This should use Web Crypto API for browser compatibility
        const decoder = new TextDecoder();
        const encoder = new TextEncoder();
        
        // Convert base64 encrypted data to bytes
        const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
        
        // Extract nonce (first 12 bytes) and ciphertext
        const nonce = encryptedBytes.slice(0, 12);
        const ciphertext = encryptedBytes.slice(12);
        
        // Import key for decryption
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const decryptedBytes = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            cryptoKey,
            ciphertext
        );
        
        return decoder.decode(decryptedBytes);
    }
}

export const shareManager = new ShareManager();
```

### Phase 3: Custom File Password Migration (Week 5-6)

#### 3.1 Custom File Password OPAQUE Implementation
```go
// handlers/file_keys.go - Migrate to OPAQUE-based custom passwords

func UpdateEncryption(c echo.Context) error {
    email := auth.GetEmailFromToken(c)
    filename := c.Param("filename")
    
    // Check file ownership
    var ownerEmail string
    err := database.DB.QueryRow(
        "SELECT owner_email FROM file_metadata WHERE filename = ?",
        filename,
    ).Scan(&ownerEmail)
    
    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "File not found")
    } else if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
    }
    
    if ownerEmail != email {
        return echo.NewHTTPError(http.StatusForbidden, "Not authorized to modify this file")
    }
    
    var request struct {
        CustomPassword   string `json:"customPassword"`
        KeyLabel         string `json:"keyLabel"`
        PasswordHint     string `json:"passwordHint"`
        EncryptedData    string `json:"encryptedData"`
    }
    
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
    }
    
    // Initialize OPAQUE password manager
    opm := &OPAQUEPasswordManager{db: database.DB}
    
    // Register custom file password with OPAQUE
    err = opm.RegisterCustomFilePassword(
        email, 
        filename, 
        request.CustomPassword,
        request.KeyLabel,
        request.PasswordHint,
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to register custom file password: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to add custom password")
    }
    
    // Update file in storage with new encrypted data
    reader := strings.NewReader(request.EncryptedData)
    _, err = storage.Provider.PutObject(
        c.Request().Context(),
        filename,
        reader,
        int64(len(request.EncryptedData)),
        minio.PutObjectOptions{ContentType: "application/octet-stream"},
    )
    
    if err != nil {
        logging.ErrorLogger.Printf("Failed to update file in storage: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update file")
    }
    
    // Mark file as multi-key enabled
    _, err = database.DB.Exec(
        "UPDATE file_metadata SET multi_key = TRUE WHERE filename = ?",
        filename,
    )
    if err != nil {
        logging.ErrorLogger.Printf("Failed to update file metadata: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update file metadata")
    }
    
    logging.InfoLogger.Printf("Custom file password added: %s by %s", filename, email)
    
    return c.JSON(http.StatusOK, map[string]interface{}{
        "message": "Custom password added successfully",
        "keyLabel": request.KeyLabel,
    })
}

// List all OPAQUE password records for a file
func ListKeys(c echo.Context) error {
    email := auth.GetEmailFromToken(c)
    filename := c.Param("filename")
    
    // Check file ownership
    var ownerEmail string
    err := database.DB.QueryRow(
        "SELECT owner_email FROM file_metadata WHERE filename = ?",
        filename,
    ).Scan(&ownerEmail)
    
    if err == sql.ErrNoRows {
        return echo.NewHTTPError(http.StatusNotFound, "File not found")
    } else if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Error checking file ownership")
    }
    
    if ownerEmail != email {
        return echo.NewHTTPError(http.StatusForbidden, "Not authorized to access this file's keys")
    }
    
    // Get all OPAQUE password records for this file
    rows, err := database.DB.Query(`
        SELECT record_type, key_label, created_at, last_used_at
        FROM opaque_password_records 
        WHERE (record_type = 'account' AND associated_user_email = ?) 
           OR (record_type = 'file_custom' AND associated_file_id = ? AND associated_user_email = ?)
        ORDER BY record_type, created_at ASC`,
        email, filename, email)
    
    if err != nil {
        logging.ErrorLogger.Printf("Error querying password records: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Error retrieving password records")
    }
    defer rows.Close()
    
    var keys []map[string]interface{}
    for rows.Next() {
        var recordType, keyLabel string
        var createdAt string
        var lastUsedAt sql.NullString
        
        err := rows.Scan(&recordType, &keyLabel, &createdAt, &lastUsedAt)
        if err != nil {
            logging.ErrorLogger.Printf("Error scanning password record: %v", err)
            continue
        }
        
        keyInfo := map[string]interface{}{
            "keyType":   recordType,
            "keyLabel":  keyLabel,
            "createdAt": createdAt,
            "isPrimary": recordType == "account",
        }
        
        if lastUsedAt.Valid {
            keyInfo["lastUsedAt"] = lastUsedAt.String
        }
        
        keys = append(keys, keyInfo)
    }
    
    if err = rows.Err(); err != nil {
        logging.ErrorLogger.Printf("Error iterating password records: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Error processing password records")
    }
    
    return c.JSON(http.StatusOK, map[string]interface{}{
        "keys": keys,
        "isMultiKey": len(keys) > 1,
    })
}
```

#### 3.2 Remove Argon2ID Dependencies
```go
// Remove from crypto/kdf.go - Mark for deletion
// This entire file can be removed after migration

// Remove from go.mod dependencies:
// golang.org/x/crypto/argon2

// Update imports across codebase to remove:
// "golang.org/x/crypto/argon2"

// Files to update:
// - handlers/file_shares.go (remove Argon2ID verification)
// - handlers/auth.go (if any Argon2ID usage remains)
// - Any remaining password hash verification code
```

#### 3.3 Clean Up HTML JavaScript References
```html
<!-- client/static/shared.html - Remove broken script references -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shared File Access</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <!-- Page content remains the same -->
    
    <!-- WebAssembly loader -->
    <script src="/wasm_exec.js"></script>
    
    <!-- REMOVE these broken references: -->
    <!-- <script src="/js/security.js"></script> -->
    
    <!-- Keep only the compiled TypeScript -->
    <script src="/js/dist/app.js"></script>
    
    <!-- Inline JavaScript remains for page-specific functionality -->
    <script>
        // Keep existing inline functionality
        // All security functions should now be in compiled TypeScript
    </script>
</body>
</html>
```

### Phase 4: Testing & Validation (Week 7-8)

#### 4.1 OPAQUE Integration Tests
```go
// New file: auth/opaque_unified_test.go

func TestOPAQUEPasswordManager_CustomFilePassword(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer db.Close()
    
    opm := &OPAQUEPasswordManager{db: db}
    
    // Test custom file password registration
    err := opm.RegisterCustomFilePassword(
        "user@example.com",
        "test-file.txt",
        "SecureFilePassword123!",
        "Test Key",
        "My secure hint",
    )
    
    assert.NoError(t, err)
    
    // Test authentication
    recordIdentifier := "user@example.com:file:test-file.txt"
    exportKey, err := opm.AuthenticatePassword(recordIdentifier, "SecureFilePassword123!")
    
    assert.NoError(t, err)
    assert.Equal(t, 64, len(exportKey)) // OPAQUE export key should be 64 bytes
    
    // Test key derivation
    fileKey, err := DeriveFileEncryptionKey(exportKey, "test-file.txt", "user@example.com")
    assert.NoError(t, err)
    assert.Equal(t, 32, len(fileKey)) // Derived key should be 32 bytes
    
    // Test wrong password
    _, err = opm.AuthenticatePassword(recordIdentifier, "WrongPassword")
    assert.Error(t, err)
}

func TestOPAQUEPasswordManager_SharePassword(t *testing.T) {
    db := setupTestDB(t)
    defer db.Close()
    
    opm := &OPAQUEPasswordManager{db: db}
    
    shareID := uuid.New().String()
    
    // Test share password registration
    err := opm.RegisterSharePassword(
        shareID,
        "shared-file.pdf",
        "owner@example.com",
        "SharePassword456!",
    )
    
    assert.NoError(t, err)
    
    // Test authentication
    recordIdentifier := fmt.Sprintf("share:%s", shareID)
    exportKey, err := opm.AuthenticatePassword(recordIdentifier, "SharePassword456!")
    
    assert.NoError(t, err)
    assert.Equal(t, 64, len(exportKey))
    
    // Test share access key derivation
    accessKey, err := DeriveShareAccessKey(exportKey, shareID, "shared-file.pdf")
    assert.NoError(t, err)
    assert.Equal(t, 32, len(accessKey))
}

func TestKeyDerivationConsistency(t *testing.T) {
    // Test that key derivation is consistent
    exportKey := make([]byte, 64)
    rand.Read(exportKey)
    
    fileID := "test-consistency.txt"
    userEmail := "user@example.com"
    
    // Derive the same key multiple times
    key1, err := DeriveFileEncryptionKey(exportKey, fileID, userEmail)
    assert.NoError(t, err)
    
    key2, err := DeriveFileEncryptionKey(exportKey, fileID, userEmail)
    assert.NoError(t, err)
    
    // Keys should be identical
    assert.Equal(t, key1, key2)
    
    // Different inputs should produce different keys
    key3, err := DeriveFileEncryptionKey(exportKey, "different-file.txt", userEmail)
    assert.NoError(t, err)
    
    assert.NotEqual(t, key1, key3)
}
```

#### 4.2 Migration Validation Scripts
```bash
#!/bin/bash
# scripts/testing/validate-opaque-migration.sh

echo "🔍 Validating OPAQUE Password Migration..."

# Check for broken JavaScript references
echo "Checking for broken JavaScript references..."
BROKEN_REFS=$(grep -r "security\.js\|multi-key-encryption\.js\|chunked-uploader\.js" client/static/*.html || true)

if [ -n "$BROKEN_REFS" ]; then
    echo "❌ Found broken JavaScript references:"
    echo "$BROKEN_REFS"
