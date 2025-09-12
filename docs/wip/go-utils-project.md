# Arkfile Go Utilities and Advanced Tooling

## Overview

This document outlines advanced Go-based tooling and utilities for the Arkfile secure file vault system. These tools provide comprehensive administrative capabilities, client tooling, and enhanced testing frameworks, all designed around the principle of strict separation between OPAQUE authentication and Argon2ID password-based file encryption.

## Architecture Overview

### Tool Ecosystem Design

The Go utilities maintain separation of concerns while enabling secure integration:

**cryptocli** (Offline Cryptographic Tool):
- File operations: generate, encrypt, decrypt with **password-derived (Argon2ID) keys**.
- No network communication capabilities.
- Pure cryptographic operations using `libopaque` (for OPAQUE authentication related tasks if any, but not for file encryption).
- Commands: `generate-test-file`, `encrypt-password`, `decrypt-password`

**arkfile-client** (Server Communication Tool):
- Authenticated server communication over TLS 1.3 (localhost and remote).
- OPAQUE authentication flows and session management.
- File upload/download operations and share creation, using **password-derived (Argon2ID) keys for file encryption**.
- Commands: `login`, `upload`, `download`, `list-files`, `create-share`

**arkfile-setup** (Administrative Installation Tool):
- Cross-platform system installation and configuration.
- Cryptographic key generation using static binaries.
- Service configuration and state management.
- Reinstall strategies (soft, hard, complete, selective).

**arkfile-admin** (Maintenance and Monitoring Tool):
- System health monitoring and diagnostics.
- Comprehensive key rotation (OPAQUE, JWT, TLS).
- Backup and restore operations with encryption.
- Performance monitoring and security auditing.

### Integration Pattern

Tools integrate through secure, well-defined patterns:
1. `arkfile-client` performs OPAQUE authentication, handling session keys internally for server communication.
2. `cryptocli` performs offline file encryption/decryption using **passwords (and Argon2ID)**, with no reliance on OPAQUE export keys for this purpose.
3. `arkfile-client` handles all network communication with encrypted payloads (encrypted using password-derived keys).
4. Administrative tools coordinate system operations using consistent static binaries.

## Phase 4: Basic Client Tools (Weeks 4-5)

### 4.1 arkfile-client Implementation

#### Core Architecture

**File: `cmd/arkfile-client/main.go`**

```go
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
)

const (
	Version = "1.0.0-static"
	Usage = `arkfile-client - Secure file sharing client with OPAQUE authentication and Argon2ID file encryption

USAGE:
    arkfile-client [global options] command [command options] [arguments...]

COMMANDS:
    login         Authenticate with arkfile server
    upload        Upload file to server
    download      Download file from server  
    list-files    List available files
    create-share  Create anonymous share link
    version       Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL (default: https://localhost:4443)
    --config FILE       Configuration file path
    --tls-insecure      Skip TLS certificate verification (localhost only)
    --tls-min-version   Minimum TLS version: 1.2 or 1.3 (default: 1.3)
    --username USER     Username for authentication
    --help, -h          Show help

EXAMPLES:
    arkfile-client login --username alice
    arkfile-client upload --file document.pdf
    arkfile-client download --file document.pdf --output ./downloads/
    arkfile-client --server-url https://files.example.com login --username alice
    arkfile-client create-share --file document.pdf --password sharepass123
`
)

type ClientConfig struct {
	ServerURL     string `json:"server_url"`
	Username      string `json:"username"`
	TLSInsecure   bool   `json:"tls_insecure"`
	TLSMinVersion uint16 `json:"tls_min_version"`
	TokenFile     string `json:"token_file"`
	ConfigFile    string `json:"config_file"`
}
```

#### Authentication Implementation

**OPAQUE Authentication (No Export Keys for File Encryption):**

```go
func performOPAQUEAuthentication(client *http.Client, config *ClientConfig) (*AuthSession, error) {
	// Step 1: OPAQUE registration check
	regCheckResp, err := client.Get(config.ServerURL + "/auth/opaque/check-user/" + username)
	if err != nil {
		return nil, fmt.Errorf("failed to check user registration: %v", err)
	}
	
	// Step 2: OPAQUE authentication flow using static libopaque
	authResp, err := performOPAQUELogin(client, config.ServerURL, username, passwordBytes)
	if err != nil {
		return nil, fmt.Errorf("OPAQUE authentication failed: %v", err)
	}
	
	// Step 3: Handle TOTP if required
	if authResp.RequiresTOTP {
		totpCode, err := getTOTPCode()
		if err != nil {
			return nil, err
		}
		
		authResp, err = completeTOTPAuthentication(client, config.ServerURL, authResp.SessionID, totpCode)
		if err != nil {
			return nil, fmt.Errorf("TOTP authentication failed: %v", err)
		}
	}
	
	// Step 4: Authentication complete; no OPAQUE key export for file encryption.
	// OPAQUE Export Keys are for server-side use only.
	session := &AuthSession{
		Username:     username,
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
		ServerURL:    config.ServerURL,
	}
	
	return session, nil
}
```

#### File Operations Implementation

**Chunked Upload with Progress Tracking (Files encrypted with Argon2ID password-derived keys):**

```go
func handleUploadCommand(client *http.Client, config *ClientConfig, args []string) error {
	// Parse upload options
	opts, err := parseUploadArgs(args)
	if err != nil {
		return err
	}
	
	// Load authentication session
	session, err := loadAuthSession(getSessionFilePath())
	if err != nil {
		return err
	}
	
	// Step 1: Initialize chunked upload session
	uploadSession, err := initializeUploadSession(client, session, opts, fileInfo)
	if err != nil {
		return fmt.Errorf("failed to initialize upload: %v", err)
	}
	
	// Step 2: Upload file in chunks with progress
	if err := uploadFileInChunks(client, session, uploadSession, opts); err != nil {
		return fmt.Errorf("upload failed: %v", err)
	}
	
	// Step 3: Complete upload transaction
	if err := completeUploadSession(client, session, uploadSession); err != nil {
		return fmt.Errorf("failed to complete upload: %v", err)
	}
	
	fmt.Printf("✅ Upload completed successfully\n")
	fmt.Printf("File ID: %s\n", uploadSession.FileID)
	
	return nil
}
```

### 4.2 Enhanced cryptocli Integration

#### Password-Based Argon2ID File Encryption

```go
// Generate deterministic test files with integrity hashes
cryptocli generate-test-file --size 100MB --pattern sequential --output test.dat --hash-output test.hash

// Encrypt files using password-derived (Argon2ID) keys
cryptocli encrypt-password --input test.dat --output test.enc --username alice

// Chunked encryption for large file upload preparation (using password-derived keys)
cryptocli encrypt-password-chunked --input test.dat --output-dir chunks/ --username alice --manifest manifest.json

// Decrypt files using password-derived (Argon2ID) keys
cryptocli decrypt-password --input test.enc --output decrypted.dat --username alice
```

#### Share-Based Decryption

```go
// Decrypt files accessed through anonymous sharing
cryptocli decrypt-share-file --input shared.enc --output shared-decrypted.dat --share-password <password> --salt <hex>

// Validate share key derivation using Argon2id
cryptocli derive-share-key --password <password> --salt <hex> --output share-key.hex
```

## Phase 5: Administrative Tools (Weeks 6-7)

### 5.1 arkfile-setup Implementation

#### Cross-Platform Installation Management

**File: `cmd/arkfile-setup/main.go`**

```go
const (
	Usage = `arkfile-setup - System installation and configuration management

USAGE:
    arkfile-setup [global options] command [command options] [arguments...]

COMMANDS:
    install       Fresh installation of Arkfile system
    reinstall     Reinstall system with various strategies
    status        Check current installation status
    update        Update existing installation
    uninstall     Remove Arkfile system
    validate      Validate installation integrity

GLOBAL OPTIONS:
    --base-dir DIR     Installation base directory (default: /opt/arkfile)
    --config FILE      Configuration file path
    --force            Force operations without confirmation
    --verbose, -v      Verbose output
    --help, -h         Show help

EXAMPLES:
    arkfile-setup install --fresh
    arkfile-setup reinstall --strategy soft
    arkfile-setup status --detailed
    arkfile-setup validate --fix-issues
`
)
```

#### Platform Detection and Dependency Management

```go
func detectPlatformAndInstallDeps(config *SetupConfig, opts *InstallOptions) (*PlatformInfo, error) {
	platform := &PlatformInfo{OS: runtime.GOOS}
	
	switch runtime.GOOS {
	case "linux":
		// Detect Linux distribution
		if _, err := os.Stat("/etc/alpine-release"); err == nil {
			platform.Distribution = "alpine"
			platform.PackageManager = "apk"
			platform.LibC = "musl"
		} else if _, err := os.Stat("/etc/debian_version"); err == nil {
			platform.Distribution = "debian" 
			platform.PackageManager = "apt"
			platform.LibC = "glibc"
		} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
			platform.Distribution = "redhat"
			platform.PackageManager = "dnf"
			platform.LibC = "glibc"
		}
	case "freebsd":
		platform.Distribution = "freebsd"
		platform.PackageManager = "pkg"
	case "openbsd":
		platform.Distribution = "openbsd"
		platform.PackageManager = "pkg_add"
	}
	
	// Install dependencies if not skipping
	if !opts.SkipDeps {
		if err := installSystemDependencies(config, platform); err != nil {
			return nil, err
		}
	}
	
	return platform, nil
}
```

#### Reinstall Strategies

```go
func executeCompleteReinstall(config *SetupConfig, opts *ReinstallOptions, state *InstallationState) error {
	fmt.Printf("💣 Complete Reinstall: Full system rebuild with optional data preservation\n")
	
	var dataBackupDir string
	
	// Optionally preserve user data
	if opts.PreserveData {
		dataBackupDir = filepath.Join(config.BaseDir, ".complete-backup")
		dataDirs := []string{filepath.Join(config.BaseDir, "data")}
		
		if err := preserveDirectories(dataDirs, dataBackupDir); err != nil {
			return fmt.Errorf("failed to preserve user data: %v", err)
		}
		fmt.Printf("📦 User data preserved\n")
	}
	
	// Stop services and remove installation
	if err := stopAllServices(config); err != nil {
		return fmt.Errorf("failed to stop services: %v", err)
	}
	
	if err := os.RemoveAll(config.BaseDir); err != nil {
		return fmt.Errorf("failed to remove installation: %v", err)
	}
	
	// Perform fresh installation
	// ... (full installation process)
	
	// Restore user data if preserved
	if opts.PreserveData && dataBackupDir != "" {
		// ... (restoration process)
	}
	
	return nil
}
```

### 5.2 arkfile-admin Implementation (Hybrid Network/Local Architecture)

#### Current Implementation Status

**arkfile-admin** is implemented as a **hybrid network/local admin tool** that combines:

1. **Network-based commands** - Use admin API (localhost-only via AdminMiddleware)
2. **Local commands** - Direct system access for operations without server endpoints yet

#### Usage and Command Architecture

**File: `cmd/arkfile-admin/main.go`**

```go
const (
	Usage = `arkfile-admin - Hybrid network/local admin tool for arkfile server management

USAGE:
    arkfile-admin [global options] command [command options] [arguments...]

NETWORK COMMANDS (Admin API - localhost only):
    login             Admin login via OPAQUE+TOTP authentication
    logout            Clear admin session
    list-users        List all users (dev-test env only)
    approve-user      Approve user account (dev-test env only)
    set-storage       Set user storage limit (via credits API)

LOCAL COMMANDS (Direct system access - server endpoints not yet available):
    backup            Create system backup (local implementation)
    restore           Restore from backup (local implementation)
    monitor           Performance monitoring (local implementation)
    audit             Security audit (local implementation)
    key-rotation      Rotate cryptographic keys (local implementation)
    health-check      System health check (local implementation)
    system-status     System status overview (local implementation)

EXAMPLES:
    # Network-based admin operations:
    arkfile-admin login --username admin
    arkfile-admin list-users
    arkfile-admin approve-user --username alice
    
    # Local system operations:
    arkfile-admin backup --output backup.tar.gz
    arkfile-admin health-check --detailed
    arkfile-admin key-rotation --type jwt
`
)
```

#### Network Commands (Available Now)

**Admin Authentication Flow:**
- Uses existing AdminMiddleware (localhost-only access)
- OPAQUE + TOTP authentication via `/api/admin/login`
- Session management with JWT tokens
- Rate limiting (10 requests/minute)
- Complete audit logging via security events

**User Management Commands (Dev-Test Environment):**
- `list-users` → Maps to existing admin endpoints when `ADMIN_DEV_TEST_API_ENABLED=true`
- `approve-user` → Uses `/api/admin/dev-test/user/:username/approve` 
- `set-storage` → Uses existing admin credits/storage management endpoints

#### Local Commands (Placeholder Implementation)

**Current Status:** Local commands display clear warnings and return errors indicating server endpoints needed.

Example output:
```bash
$ arkfile-admin backup --output backup.tar.gz
⚠️  Using local implementation - server endpoint not yet available
🔄 Creating system backup...
Output file: backup.tar.gz
Base directory: /opt/arkfile
⚠️  Backup functionality requires server endpoint implementation
Would backup: config files, keys, database, user data
ERROR: backup endpoint not yet implemented on server
```

#### Security Model

**AdminMiddleware Security Features:**
1. **Localhost-only access** - `clientIP.IsLoopback()` enforcement
2. **Rate limiting** - 10 requests/minute via EntityID system
3. **JWT authentication** - Valid admin JWT token required
4. **Admin privileges** - `user.HasAdminPrivileges()` check
5. **Production protection** - Blocks dev admin accounts in production
6. **Audit logging** - All admin actions logged without IP for privacy

#### Required Server Endpoints (To Be Implemented)

**Missing Production Admin Endpoints:**
```
GET  /api/admin/users                    - List all users (production)
PATCH /api/admin/users/:username         - Update user properties (production)  
DELETE /api/admin/users/:username        - Delete user (production)
GET  /api/admin/system/status            - System metrics and status
GET  /api/admin/system/health            - Health check with component status
POST /api/admin/system/rotate-keys       - Key rotation operations
POST /api/admin/system/backup            - Create system backup
POST /api/admin/system/restore           - Restore from backup
GET  /api/admin/system/monitor           - Performance monitoring data
GET  /api/admin/system/audit             - Security audit information
GET  /api/admin/stats                    - System statistics
GET  /api/admin/activity                 - Activity logs
```

**Available Endpoints:**
```
✅ POST /api/admin/login                         - Admin authentication
✅ GET  /api/admin/credits                       - Credits management
✅ GET  /api/admin/credits/:username             - User credits
✅ POST /api/admin/credits/:username             - Adjust credits
✅ PUT  /api/admin/credits/:username             - Set credits
✅ POST /api/admin/dev-test/user/cleanup         - Test user cleanup (dev-test)
✅ POST /api/admin/dev-test/user/:username/approve - Approve user (dev-test)
✅ GET  /api/admin/dev-test/user/:username/status  - User status (dev-test)
✅ GET  /api/admin/dev-test/totp/decrypt-check/:username - TOTP diagnostics (dev-test)
```

#### Migration Strategy

**Phase 1: Current State (Complete)**
- ✅ Hybrid arkfile-admin implemented
- ✅ Network commands use existing admin API
- ✅ Local commands show clear "not implemented" warnings
- ✅ AdminMiddleware enforces localhost-only security

**Phase 2: Server Endpoint Implementation**
- Implement missing `/api/admin/system/*` endpoints
- Add production user management endpoints  
- Update arkfile-admin command routing as endpoints become available

**Phase 3: Production Deployment**
- Disable dev-test endpoints in production (`ADMIN_DEV_TEST_API_ENABLED=false`)
- Use production admin endpoints for all operations
- Full network-based admin functionality

#### Comprehensive Key Rotation System

**Production-Ready OPAQUE Key Rotation:**

```go
func (kr *OPAQUEKeyRotation) executeDualKeyTransition(opts *KeyRotationOptions) error {
	kr.logger.Log("Starting dual-key transition for OPAQUE keys")
	
	// Step 1: Generate new OPAQUE server keys using static libopaque
	newPublicKey, newPrivateKey, err := kr.generateNewOPAQUEKeys()
	if err != nil {
		return fmt.Errorf("new key generation failed: %v", err)
	}
	
	// Step 2: Update database schema to support multiple key versions
	if err := kr.updateSchemaForMultipleKeys(); err != nil {
		return fmt.Errorf("schema update failed: %v", err)
	}
	
	// Step 3: Store new keys alongside existing keys
	if err := kr.storeKeysWithVersion(newPublicKey, newPrivateKey, 2); err != nil {
		return fmt.Errorf("key storage failed: %v", err)
	}
	
	// Step 4: Update application to support both key versions
	if err := kr.updateApplicationForDualKeys(); err != nil {
		return fmt.Errorf("application update failed: %v", err)
	}
	
	// Step 5: Monitor user migration progress
	if err := kr.trackUserMigrationProgress(); err != nil {
		return fmt.Errorf("migration tracking setup failed: %v", err)
	}
	
	kr.logger.Log("Dual-key transition completed - both keys active")
	return nil
}
```

#### Backup and Restore Operations

**Encrypted Backup Creation:**

```go
func (bm *BackupManager) CreateBackup(opts *BackupOptions, manifest *BackupManifest) error {
	// Create backup file with optional encryption
	backupFile, err := os.Create(opts.OutputPath)
	if err != nil {
		return fmt.Errorf("cannot create backup file: %v", err)
	}
	defer backupFile.Close()
	
	var writer io.Writer = backupFile
	
	// Add encryption if requested
	if opts.Encrypt {
		encryptedWriter, err := bm.createEncryptedWriter(writer)
		if err != nil {
			return fmt.Errorf("encryption setup failed: %v", err)
		}
		writer = encryptedWriter
	}
	
	// Add compression
	if opts.Compression == "gzip" {
		gzipWriter := gzip.NewWriter(writer)
		defer gzipWriter.Close()
		writer = gzipWriter
	}
	
	// Create tar archive and backup components
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()
	
	// Backup each component
	if opts.IncludeKeys {
		if err := bm.backupDirectory(tarWriter, "keys", filepath.Join(bm.baseDir, "keys")); err != nil {
			return fmt.Errorf("keys backup failed: %v", err)
		}
	}
	
	// ... (additional component backups)
	
	return nil
}
```

## Phase 6: Enhanced Integration Testing (Weeks 8-9)

### 6.1 Go-Based Integration Testing Framework

#### Comprehensive Test Suite Implementation

**File: `cmd/integration-test/main.go`**

```go
const (
	Usage = `integration-test - Comprehensive static binary integration testing

USAGE:
    integration-test [global options] command [command options]

COMMANDS:
    full-suite     Run complete integration test suite
    auth-flow      Test authentication workflows
    file-ops       Test file operation workflows  
    share-ops      Test anonymous sharing workflows
    admin-ops      Test administrative operations
    benchmark      Performance benchmarking tests

EXAMPLES:
    integration-test full-suite --verbose --performance
    integration-test auth-flow --test-user alice --server-url https://localhost:4443
    integration-test benchmark --file-size 100MB --performance
`
)
```

#### Authentication Flow Testing

```go
func (suite *IntegrationTestSuite) runAuthenticationFlowTests() error {
	fmt.Printf("📋 Phase 2: Authentication Flow Testing\n")
	
	// Test 1: OPAQUE Registration and Authentication
	suite.runTest("OPAQUE Authentication Flow", func() error {
		return suite.testOPAQUEAuthentication()
	})
	
	// Test 2: TOTP Setup and Validation
	suite.runTest("TOTP Two-Factor Authentication", func() error {
		return suite.testTOTPAuthentication()
	})
	
	// Test 3: Session Management
	suite.runTest("JWT Session Management", func() error {
		return suite.testSessionManagement()
	})
	
	// Test 4: File Encryption Key Derivation (Password and Argon2ID)
	suite.runTest("Password-Based File Encryption Key Derivation", func() error {
		return suite.testPasswordBasedFileEncryptionKeyDerivation()
	})
	
	fmt.Printf("✅ Authentication flows validated\n\n")
	return nil
}
```

#### File Operations Testing

```go
func (suite *IntegrationTestSuite) runFileOperationTests() error {
	fmt.Printf("📋 Phase 3: File Operation Testing\n")
	
	// Test 1: Large File Generation
	suite.runTest("Test File Generation (100MB)", func() error {
		return suite.generateTestFile()
	})
	
	// Test 2: File Encryption with Password-Derived Keys (Argon2ID)
	suite.runTest("Password-Derived File Encryption (Argon2ID)", func() error {
		return suite.testFileEncryption()
	})
	
	// Test 3: Chunked File Upload
	suite.runTest("Chunked File Upload (100MB)", func() error {
		return suite.testChunkedUpload()
	})
	
	// Test 4: File Download and Decryption
	suite.runTest("Authenticated File Download", func() error {
		return suite.testFileDownload()
	})
	
	// Test 5: End-to-End Integrity Verification
	suite.runTest("Complete Integrity Verification", func() error {
		return suite.testIntegrityVerification()
	})
	
	fmt.Printf("✅ File operations validated\n\n")
	return nil
}
```

### 6.2 Enhanced test-app-curl.sh Integration

#### Go Tools Integration Testing

```bash
phase_file_operations_go_tools() {
    phase "FILE OPERATIONS WITH GO TOOLS"
    
    local timer_start
    [ "$PERFORMANCE_MODE" = true ] && timer_start=$(start_timer)
    
    # Ensure Go tools are built with static linking
    build_go_tools_static
    
    # Export authentication data for Go tools (no OPAQUE export keys for file encryption)
    export_auth_data_for_go_tools
    
    # Step 1: Generate 100MB test file with cryptocli
    generate_large_test_file_with_cryptocli
    
    # Step 2: Authenticate with arkfile-client (no OPAQUE export key for file encryption)
    authenticate_with_arkfile_client
    
    # Step 3: Encrypt file using password-derived (Argon2ID) keys
    encrypt_test_file_with_password_based_keys
    
    # Step 4: Upload encrypted file using chunked operations
    upload_chunked_file_with_arkfile_client
    
    # Step 5: Verify file in listing and validate metadata
    verify_uploaded_file_metadata
    
    # Step 6: Download and decrypt file for integrity verification
    download_and_decrypt_complete_workflow
    
    # Step 7: Verify perfect integrity through complete cycle
    verify_complete_file_integrity
    
    # Step 8: Performance benchmarking and metrics
    benchmark_file_operations_performance
    
    success "File operations testing completed with Go tools"
    
    if [ "$PERFORMANCE_MODE" = true ]; then
        local duration=$(end_timer "$timer_start")
        info "File operations completed in: $duration"
    fi
}
```

## Shell Script to Go Conversion Analysis

### Recommended Conversions (High Value)

**1. Build and Setup Scripts → Go Tools**
- `scripts/setup/build-libopaque.sh` → **Go program (`cmd/build-libopaque/main.go`)**
  - Benefits: Better error handling, cross-platform detection, structured configuration
  - Implementation: Full platform detection and dependency management in Go

**2. Administrative Operations → Integrated Go Tools**
- `scripts/setup/03-setup-opaque-keys.sh` → **Integrate into arkfile-setup**
- `scripts/setup/04-setup-jwt-keys.sh` → **Integrate into arkfile-setup**
- `scripts/maintenance/rotate-opaque-keys.sh` → **Integrate into arkfile-admin**
- `scripts/maintenance/rotate-jwt-keys.sh` → **Integrate into arkfile-admin**
- Benefits: Consistent cryptographic operations, better key management

**3. Integration Testing Orchestration → Go Framework**
- Test orchestration functions in `test-app-curl.sh` → **Go integration test framework**
- Benefits: Structured reporting, better error handling, cross-platform consistency

### Keep as Shell Scripts (System Integration)

**4. System Service Management (Keep in Shell)**
- `scripts/setup/00-setup-foundation.sh` - System user/group creation
- `scripts/setup/01-setup-users.sh` - User management  
- `scripts/setup/02-setup-directories.sh` - Directory structure
- `scripts/setup/07-setup-minio.sh` - External service setup
- `scripts/setup/08-setup-rqlite.sh` - External service setup
- **Reason**: Heavy system integration, package managers, root privileges

**5. Development and Deployment Scripts (Keep in Shell)**
- `scripts/dev-reset.sh` - Development environment reset
- `scripts/quick-start.sh` - Quick development startup
- `scripts/setup/deploy.sh` - Production deployment
- `scripts/testing/test-app-curl.sh` - **Keep as shell orchestrator**
- **Reason**: Excellent for coordinating multiple tools and services

### Hybrid Integration Strategy

**Enhanced Shell Orchestration with Go Tools:**

```bash
# Shell script orchestrates, Go tools execute:
./scripts/setup/build.sh
  ├── build-libopaque (Go tool)
  ├── Static binary compilation
  └── ./arkfile-setup validate --installation

# Instead of pure shell:
./scripts/maintenance/rotate-opaque-keys.sh

# Use Go tool with shell wrapper:
./arkfile-admin rotate-keys --opaque --strategy dual-key --confirm
```

## Implementation Timeline (Phases 4-9)

### Week 4: Basic Client Implementation
- **Days 1-3**: Implement arkfile-client core functionality (login, upload, download)
- **Days 4-5**: Add comprehensive session management and error handling
- **Days 6-7**: Integration testing with existing infrastructure

### Week 5: Client Tool Completion
- **Days 1-3**: Complete file operations with progress tracking
- **Days 4-5**: Implement share creation and management
- **Days 6-7**: End-to-end validation and documentation

### Week 6: Administrative Setup Tool
- **Days 1-3**: Implement arkfile-setup with cross-platform support
- **Days 4-5**: Add installation workflows and state management
- **Days 6-7**: Implement reinstall strategies and validation

### Week 7: Administrative Maintenance Tool
- **Days 1-3**: Implement arkfile-admin with health monitoring
- **Days 4-5**: Add comprehensive key rotation system
- **Days 6-7**: Implement backup/restore and security auditing

### Week 8: Integration and Enhancement
- **Days 1-3**: Cross-tool integration and communication patterns
- **Days 4-5**: Enhanced test-app-curl.sh integration
- **Days 6-7**: Shell script to Go conversion implementation

### Week 9: Comprehensive Testing Framework
- **Days 1-3**: Go-based integration testing framework
- **Days 4-5**: Performance benchmarking and validation
- **Days 6-7**: Final system validation and documentation

## Success Criteria

### Phase 4 Success (Client Tools)
- arkfile-client can authenticate, upload, download files successfully
- Session management works across tool invocations
- Integration with existing dev-reset + test-app-curl.sh workflow
- File encryption uses Argon2ID password-derived keys, not OPAQUE export keys

### Phase 5 Success (Administrative Tools)
- arkfile-setup can perform fresh installations across platforms
- arkfile-admin can rotate keys without breaking functionality
- Backup and restore operations work with encryption
- All tools integrate with static binary architecture

### Phase 6 Success (Enhanced Testing)
- Go-based testing framework validates complete workflows
- Performance benchmarks meet established targets
- Enhanced test-app-curl.sh integration provides comprehensive coverage
- All testing uses authentic server operations, not simulations

### Overall Success
- Complete tool ecosystem working with static binary consistency
- No dependency on mock systems for any operations
- Cross-platform compatibility across all supported systems
- Production-ready administrative and client tooling

## Future Considerations

### Performance Optimization
- Binary size optimization while maintaining functionality
- Memory usage analysis and optimization
- Cross-platform performance characteristics validation

### Enhanced Security Features
- Advanced key rotation strategies
- Comprehensive security auditing capabilities
- Enhanced monitoring and alerting systems

### User Experience Improvements
- Interactive configuration wizards
- Enhanced error messages and troubleshooting guides
- Comprehensive documentation and examples

This advanced tooling framework provides a complete ecosystem for Arkfile operations while maintaining the static binary consistency and security characteristics established in the foundation phase.

---

## IMPLEMENTATION STATUS AND TODOS (Historical - Refer to `docs/wip/encrypt-cleanup.md` for latest encryption status)

The following section contains historical implementation status and todos as of August 14, 2025, and August 16, 2025. For the current status regarding the Argon2ID encryption refactoring and OPAQUE protocol roles, please refer to `docs/wip/encrypt-cleanup.md`.

### ✅ COMPLETED WORK (Historical)

#### Phase 4 - Basic Client Tools (PARTIAL COMPLETION)

**✅ arkfile-client Implementation**
- **File**: `cmd/arkfile-client/main.go` - **COMPLETED AND COMPILED**
- **Status**: Full implementation with comprehensive command structure
- **Features Implemented**:
  - Complete command-line interface with help system
  - OPAQUE authentication with TOTP support
  - File upload/download operations with chunked support
  - Share creation and management
  - Session management with token persistence
  - TLS configuration (1.2/1.3 support)
  - Verbose logging and error handling
  - Cross-platform configuration management
- **Binary Status**: Successfully compiles (arkfile-client binary exists)
- **Static Linking Status**: ⚠️ **NOW STATIC** (confirmed static linking working)

**✅ arkfile-admin Implementation (HYBRID ARCHITECTURE)**
- **File**: `cmd/arkfile-admin/main.go` - **COMPLETED AND COMPILED**
- **Status**: Hybrid network/local implementation fully complete
- **Architecture**: 
  - **Network Commands**: Use existing admin API (localhost-only)
  - **Local Commands**: Show clear warnings + placeholder implementations
- **Network Commands Implemented**:
  - ✅ `login` - Admin OPAQUE+TOTP authentication
  - ✅ `logout` - Session management
  - ✅ `list-users` - User management (dev-test env)
  - ✅ `approve-user` - User approval (dev-test env)
  - ✅ `set-storage` - Credits/storage management
- **Local Commands Implemented** (with proper warning system):
  - ✅ `backup` - Shows "server endpoint not yet available" warning
  - ✅ `restore` - Shows "server endpoint not yet available" warning
  - ✅ `monitor` - Shows "server endpoint not yet available" warning
  - ✅ `audit` - Shows "server endpoint not yet available" warning
  - ✅ `key-rotation` - Shows "server endpoint not yet available" warning
  - ✅ `health-check` - Shows "server endpoint not yet available" warning
  - ✅ `system-status` - Shows "server endpoint not yet available" warning
- **Binary Status**: Successfully compiles (arkfile-admin binary exists)
- **Static Linking Status**: ⚠️ **NOW STATIC** (confirmed static linking working)

### ✅ RESOLVED - CRITICAL ISSUES (Historical)

**TOKEN REFRESH ISSUE SUCCESSFULLY RESOLVED (Historical)**:

The critical refresh token validation failure in testing scripts has been resolved. Both admin authentication and main application testing now pass all phases including token refresh functionality.

**Root Cause Identified and Fixed**:
- **Problem**: RQLite stores timestamps as strings, but Go was trying to scan them directly into `time.Time` types
- **Solution**: Modified `models/refresh_token.go` to scan timestamps as strings first, then parse into `time.Time` with proper error handling
- **Implementation**: Added support for multiple timestamp formats (RFC3339, SQL format) with fallback parsing

**Verification Results**:
```bash
# Both testing scripts now pass completely
./scripts/testing/admin-auth-test.sh       # 6/6 tests passing (including Test 6: Token Refresh) ✅
./scripts/testing/test-app-curl.sh         # 10/10 phases passing (including Phase 7: Session Management) ✅
```

**Database Fix Applied**:
- Updated `ValidateRefreshToken()` function in `models/refresh_token.go`
- Added comprehensive debug logging for token validation troubleshooting
- Implemented sliding window expiry (14-day extension on use)
- Token rotation working correctly (revoke old token on refresh)

### 📋 PHASE 4 REMAINING WORK (Historical)

#### cryptocli Integration Enhancement
- **Status**: ⏳ **PARTIALLY IMPLEMENTED**
- **File**: `cmd/cryptocli/main.go` exists but may need updates for client integration
- **TODO**: Verify OPAQUE export key compatibility with arkfile-client (This task is now irrelevant, as OPAQUE export keys are not used for file encryption.)

#### Client Tool Testing and Validation
- **Status**: ⏳ **NOT YET TESTED**
- **Critical Requirement**: Must test with `sudo dev-reset.sh` + `test-app-curl.sh` workflow
- **Validation Needed**:
  - arkfile-client authentication against running server
  - File upload/download operations
  - Share creation functionality
  - Session persistence and token management

### 📋 PHASE 5 REMAINING WORK (Administrative Tools - Historical)

#### arkfile-admin Server Endpoint Implementation
- **Status**: ⏳ **SERVER ENDPOINTS NOT YET IMPLEMENTED**
- **Required Server Endpoints** (to be added to main server):
  ```
  GET  /api/admin/system/status            - System metrics and status
  GET  /api/admin/system/health            - Health check with component status
  POST /api/admin/system/rotate-keys       - Key rotation operations
  POST /api/admin/system/backup            - Create system backup
  POST /api/admin/system/restore           - Restore from backup
  GET  /api/admin/system/monitor           - Performance monitoring data
  GET  /api/admin/system/audit             - Security audit information
  ```

#### arkfile-setup Implementation
- **File**: `cmd/arkfile-setup/main.go`
- **Scope**: Cross-platform installation and management tool

### 📋 VALIDATION REQUIREMENTS (Historical)

**Success Criteria for Phase 4 Completion**:
- arkfile-client can authenticate and perform file operations
- arkfile-admin network commands work with existing admin API 
- dev-reset + test-app-curl.sh workflow remains intact
- No regressions in existing functionality

### 📋 ARCHITECTURE DECISIONS MADE (Historical)

1. **Hybrid arkfile-admin Approach**: Decided to implement network commands first using existing admin API, with local commands showing clear warnings until server endpoints are implemented
2. **Security Model**: AdminMiddleware enforces localhost-only access for admin operations
3. **Warning System**: Local commands provide clear feedback about missing server endpoints
4. **Session Management**: Both tools use file-based session persistence in user home directory

### 📋 FILES TO MONITOR (Historical)

**Completed and Ready**:
- `cmd/arkfile-client/main.go` - Full implementation, needs testing
- `cmd/arkfile-admin/main.go` - Hybrid implementation, network commands ready
- `docs/wip/go-utils-project.md` - Updated with current status

**Needs Attention**:
- Static linking configuration for Go tools (RESOLVED ✅)
- Server endpoint implementation for arkfile-admin local commands
- Integration testing with existing infrastructure

---

## 🚨 CRITICAL SERVER ENDPOINT GAP ANALYSIS (Historical - August 16, 2025)

### THE BRUTAL TRUTH: MASSIVE ENDPOINT IMPLEMENTATION REQUIRED

After completing comprehensive audit of arkfile-admin expectations vs. actual server implementation, **this is NOT a minimal issue** - it represents a fundamental gap that blocks production admin operations.

### EXISTING MONITORING INFRASTRUCTURE (THE GOOD NEWS)

**DISCOVERY**: The `monitoring/` package contains extensive health monitoring infrastructure:

- **`monitoring/health_endpoints.go`**: Complete `HealthMonitor` with database, key, storage, and system health checks
- **`monitoring/key_health.go`**: Comprehensive `KeyHealthMonitor` with key component monitoring  
- **Existing health endpoints**: `/health`, `/ready`, `/live`, `/metrics`
- **BUT**: These are **NOT wired into the admin API endpoints** that arkfile-admin expects

### MISSING SERVER ENDPOINTS (THE MASSIVE GAP)

**7 Critical Admin Commands with NO Server Endpoints:**

1. **`arkfile-admin backup`** → expects `/api/admin/system/backup` - **MISSING ENTIRELY**
2. **`arkfile-admin restore`** → expects `/api/admin/system/restore` - **MISSING ENTIRELY** 
3. **`arkfile-admin monitor`** → expects `/api/admin/system/monitor` - **MISSING ENTIRELY**
4. **`arkfile-admin audit`** → expects `/api/admin/system/audit` - **MISSING ENTIRELY**
5. **`arkfile-admin system-status`** → expects `/api/admin/system/status` - **MISSING ENTIRELY**
6. **`arkfile-admin key-rotation`** → expects `/api/admin/system/rotate-keys` - **MISSING ENTIRELY**
7. **`arkfile-admin health-check`** → expects `/api/admin/system/health` - **MISSING ENTIRELY**

**Current Status**: All 7 commands show "server endpoint not yet available" warnings and fail with errors.

### WHAT NEEDS IMMEDIATE IMPLEMENTATION

#### Phase 1: Create Missing Admin Handlers (`handlers/admin.go`)
```go
func AdminSystemBackup(c echo.Context) error { /* NEW - complete implementation needed */ }
func AdminSystemRestore(c echo.Context) error { /* NEW - complete implementation needed */ }
func AdminSystemMonitor(c echo.Context) error { /* NEW - bridge to monitoring package */ }
func AdminSystemAudit(c echo.Context) error { /* NEW - complete implementation needed */ }
func AdminSystemStatus(c echo.Context) error { /* NEW - bridge to monitoring package */ }
func AdminSystemRotateKeys(c echo.Context) error { /* NEW - complete implementation needed */ }
func AdminSystemHealth(c echo.Context) error { /* NEW - bridge to monitoring package */ }
```

#### Phase 2: Wire Routes (`handlers/route_config.go`)
**CURRENT STATE**: `handlers/route_config.go` shows:
- Existing admin endpoints: `/api/admin/credits/*` (implemented)
- **Commented placeholder examples** for missing endpoints
- **NO actual routes** for the 7 missing endpoints

**REQUIRED**: All 7 missing routes need to be added to the admin group with proper AdminMiddleware.

#### Phase 3: Bridge Monitoring Infrastructure
**The good news**: Monitoring logic exists but needs admin API wrappers:
- `AdminSystemHealth` → calls `HealthMonitor.HealthHandler`
- `AdminSystemStatus` → calls `HealthMonitor.GetHealthStatus`  
- `AdminSystemMonitor` → calls `KeyHealthMonitor.GetHealthStatus`

#### Phase 4: Implement Missing Logic
**Complete implementations needed for**:
- **Backup/Restore**: Database and file system backup/restore logic
- **Audit**: Security audit and log analysis functionality
- **Key Rotation**: Integration with existing key rotation scripts

### IMPACT ASSESSMENT

**Current State**:
- arkfile-admin shows "server endpoint not yet available" warnings for **7 out of 12 commands**
- **58% of admin functionality is broken**
- Integration testing **cannot validate admin operations**
- Production admin operations are **severely limited**

**Development Effort Required**:
- **Estimated 2-3 weeks of server-side development** before go-integration2.md implementation can begin
- This represents a **blocking dependency** for integration testing

### RECOMMENDATION

**❌ HALT all go-integration2.md planning until this server endpoint gap is closed**

The integration test would be testing a **fundamentally incomplete system**. We cannot validate admin operations that don't exist on the server side.

**✅ PRIORITY**: Implement missing server endpoints as **PHASE 0** before any integration testing work begins.

### FILES REQUIRING IMMEDIATE ATTENTION

1. **`handlers/admin.go`** - Add 7 missing handler functions
2. **`handlers/route_config.go`** - Wire 7 missing admin routes
3. **Bridge existing monitoring infrastructure** - Connect health monitoring to admin endpoints
4. **Implement backup/restore/audit logic** - Complete missing business logic

**BOTTOM LINE**: This is a **massive server-side development effort** that must be completed before arkfile-admin can function as designed and before any meaningful integration testing can occur.

---

## 🎯 ADMIN ENDPOINT ARCHITECTURE PLAN (Historical - August 19, 2025)

### SECURITY FRAMEWORK FOR ALL ADMIN ENDPOINTS

**Base Security Requirements (ALL endpoints)**:
- ✅ Rate limited (10 requests/minute via AdminMiddleware)
- ✅ Require admin privileges (`user.HasAdminPrivileges()`)
- ✅ JWT authentication required
- ✅ Available to localhost only (`AdminMiddleware` enforcement)
- ✅ Security event logging (privacy-preserving)

### ENDPOINT CATEGORIZATION AND IMPLEMENTATION PLAN

#### **Category A: Production Admin Endpoints**
**Route Group**: `/api/admin` with `AdminMiddleware`
**Environment**: Available in all environments (dev, test, production)

**User Management (Move from dev/test to production)**:
- `POST /api/admin/user/:username/approve` - **MIGRATE** from `/api/admin/dev-test/user/:username/approve`
- `GET /api/admin/user/:username/status` - **MIGRATE** from `/api/admin/dev-test/user/:username/status`

**Credits System (Already implemented)**:
- `GET /api/admin/credits` ✅
- `GET /api/admin/credits/:username` ✅ 
- `POST /api/admin/credits/:username` ✅
- `PUT /api/admin/credits/:username` ✅

**System Operations (NEW - Bridge existing monitoring infrastructure)**:
- `GET /api/admin/system/health` - **NEW** - Wire `monitoring/health_endpoints.go`
- `GET /api/admin/audit/security-events` - **NEW** - Expose existing security event logs
- `POST /api/admin/system/backup` - **NEW** - Production-ready backup operations
- `POST /api/admin/system/restore` - **NEW** - Production-ready restore operations  
- `POST /api/admin/system/rotate-keys` - **NEW** - Production-ready key rotation

#### **Category B: Dev/Test Only Endpoints**
**Route Group**: `/api/admin/dev-test` with `ADMIN_DEV_TEST_API_ENABLED` gate
**Environment**: Only when `ADMIN_DEV_TEST_API_ENABLED=true`

**Test/Diagnostic Operations (Keep in dev/test)**:
- `POST /api/admin/dev-test/user/cleanup` - **KEEP** - `AdminCleanupTestUser` (test-specific)
- `GET /api/admin/dev-test/totp/decrypt-check/:username` - **KEEP** - `AdminTOTPDecryptCheck` (diagnostic)

### IMPLEMENTATION STRATEGY

#### **Phase 1: Migrate User Management (Immediate)**
**Action**: Move user management from dev/test to production admin group

**Changes Required**:
1. **`handlers/route_config.go`**: 
   - Remove user management from `devTestAdminGroup`
   - Add to main `adminGroup`
2. **No handler changes needed** - `AdminApproveUser` and `AdminGetUserStatus` already implemented

#### **Phase 2: Wire Existing Monitoring Infrastructure (Quick Win)**
**Action**: Bridge existing monitoring to admin endpoints

**Implementation**:
```go
// handlers/admin.go - NEW functions
func AdminSystemHealth(c echo.Context) error {
    // Bridge to existing monitoring/health_endpoints.go
    return monitoring.HealthMonitor.HealthHandler(c)
}

func AdminSecurityEvents(c echo.Context) error {
    // Expose existing security event logs from logging package
    events, err := logging.GetRecentSecurityEvents(database.DB, 100)
    if err != nil {
        return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve security events")
    }
    return c.JSON(http.StatusOK, events)
}
```

#### **Phase 3: Implement Missing Business Logic (Major Work)**
**Action**: Implement backup, restore, and key rotation logic

**New Implementations Needed**:
- `AdminSystemBackup` - Create system backups (database, keys, config)
- `AdminSystemRestore` - Restore from backups with validation
- `AdminSystemRotateKeys` - Coordinate key rotation operations

#### **Phase 4: Update Route Configuration**
**Action**: Wire all new endpoints in `handlers/route_config.go`

**Changes Required**:
```go
// Production admin endpoints (always available)
adminGroup.POST("/user/:username/approve", AdminApproveUser) // MIGRATED
adminGroup.GET("/user/:username/status", AdminGetUserStatus) // MIGRATED
adminGroup.GET("/system/health", AdminSystemHealth) // NEW
adminGroup.GET("/audit/security-events", AdminSecurityEvents) // NEW
adminGroup.POST("/system/backup", AdminSystemBackup) // NEW
adminGroup.POST("/system/restore", AdminSystemRestore) // NEW
adminGroup.POST("/system/rotate-keys", AdminSystemRotateKeys) // NEW
```

### SECURITY CONSIDERATIONS

#### **Localhost-Only Enforcement**
- All admin endpoints restricted to localhost via `AdminMiddleware`
- `clientIP.IsLoopback()` validation prevents remote access
- Privacy-preserving logging (no IP addresses stored)

#### **Environment-Based Security**
- Production: User management, system operations, monitoring available
- Dev/Test: Additional diagnostic and cleanup operations available
- Clear separation between operational and diagnostic endpoints

#### **Audit Trail**
- All admin operations logged via existing `logging.LogSecurityEvent` system
- Privacy-preserving entity IDs used for rate limiting
- Complete admin action audit trail maintained

### MIGRATION IMPACT

#### **arkfile-admin Command Mapping**
**After Implementation**:
- `arkfile-admin approve-user` → `POST /api/admin/user/:username/approve` ✅
- `arkfile-admin system-status` → `GET /api/admin/user/:username/status` ✅  
- `arkfile-admin health-check` → `GET /api/admin/system/health` ✅
- `arkfile-admin audit` → `GET /api/admin/audit/security-events` ✅
- `arkfile-admin backup` → `POST /api/admin/system/backup` ✅
- `arkfile-admin restore` → `POST /api/admin/system/restore` ✅
- `arkfile-admin key-rotation` → `POST /api/admin/system/rotate-keys` ✅

#### **Testing Integration**
- All admin operations can be validated in integration tests
- Full admin functionality available for production deployment
- Clear separation between production and dev/test endpoints

### SUCCESS CRITERIA

#### **Immediate Goals**
1. **User management available in production** (simple migration)
2. **System health monitoring working** (wire existing infrastructure)
3. **Security audit logs accessible** (expose existing logging)

#### **Complete Implementation**
1. **All 7 missing admin endpoints implemented and tested**
2. **58% functionality gap eliminated**
3. **Production-ready admin operations available**
4. **Clean separation between production and dev/test endpoints**

### DEVELOPMENT EFFORT ESTIMATE

#### **Phase 1-2: Quick Wins (1-2 days)**
- Migrate user management endpoints
- Wire existing monitoring infrastructure
- Update routing configuration

#### **Phase 3: Major Implementation (1-2 weeks)**
- Implement backup/restore logic with encryption
- Implement comprehensive key rotation system
- Add comprehensive error handling and validation

#### **Phase 4: Integration and Testing (3-5 days)**
- Update arkfile-admin command routing
- Integration testing with existing test suite
- Production deployment validation

**TOTAL EFFORT**: 2-3 weeks for complete implementation, but **immediate progress possible** with phased approach focusing on quick wins first.
