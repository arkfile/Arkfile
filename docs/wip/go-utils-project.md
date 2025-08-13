# Arkfile Go Utilities and Advanced Tooling

## Overview

This document outlines advanced Go-based tooling and utilities for the Arkfile secure file vault system. These tools build upon the static linking foundation to provide comprehensive administrative capabilities, client tooling, and enhanced testing frameworks.

## Prerequisites

**Foundation Requirements (Must Be Complete):**
- Static linking implementation complete (see `static-linking.md`)
- Mock system entirely removed
- Basic functionality validated via `sudo dev-reset.sh` + `test-app-curl.sh`
- All existing tests passing consistently with static binaries

**Success Criteria Before Starting:**
- `ldd ./arkfile` shows "not a dynamic executable"
- Zero mock-related files in codebase
- Complete dev-reset → test-app-curl.sh workflow operational

## Architecture Overview

### Tool Ecosystem Design

The Go utilities maintain separation of concerns while enabling secure integration:

**cryptocli** (Offline Cryptographic Tool):
- File operations: generate, encrypt, decrypt with OPAQUE-derived keys
- No network communication capabilities
- Pure cryptographic operations using statically linked libopaque
- Commands: `generate-test-file`, `encrypt-file-opaque`, `decrypt-file-opaque`, `encrypt-chunked-opaque`

**arkfile-client** (Server Communication Tool):
- Authenticated server communication over TLS 1.3 (localhost and remote)
- OPAQUE authentication flows and session management
- File upload/download operations and share creation
- Commands: `login`, `upload`, `download`, `list-files`, `create-share`

**arkfile-setup** (Administrative Installation Tool):
- Cross-platform system installation and configuration
- Cryptographic key generation using static binaries
- Service configuration and state management
- Reinstall strategies (soft, hard, complete, selective)

**arkfile-admin** (Maintenance and Monitoring Tool):
- System health monitoring and diagnostics
- Comprehensive key rotation (OPAQUE, JWT, TLS)
- Backup and restore operations with encryption
- Performance monitoring and security auditing

### Integration Pattern

Tools integrate through secure key handoff patterns:
1. arkfile-client performs OPAQUE authentication and exports session keys as needed
2. cryptocli uses exported keys for offline cryptographic operations
3. arkfile-client handles all network communication with pre-encrypted payloads
4. Administrative tools coordinate system operations using consistent static binaries

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
	Usage = `arkfile-client - Secure file sharing client with OPAQUE authentication

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

**OPAQUE Authentication with Export Keys:**

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
	
	// Step 4: Export OPAQUE key for cryptocli integration
	session := &AuthSession{
		Username:     username,
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
		OPAQUEExport: authResp.OPAQUEExport, // For cryptocli key handoff
		ServerURL:    config.ServerURL,
	}
	
	return session, nil
}
```

#### File Operations Implementation

**Chunked Upload with Progress Tracking:**

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

#### OPAQUE-Integrated Encryption

```go
// Generate deterministic test files with integrity hashes
cryptocli generate-test-file --size 100MB --pattern sequential --output test.dat --hash-output test.hash

// Encrypt files using OPAQUE-derived keys (production compatibility)
cryptocli encrypt-file-opaque --input test.dat --output test.enc --export-key <hex> --username alice --file-id test.dat

// Chunked encryption for large file upload preparation
cryptocli encrypt-chunked-opaque --input test.dat --output-dir chunks/ --export-key <hex> --username alice --manifest manifest.json

// Decrypt files using various key sources
cryptocli decrypt-file-opaque --input test.enc --output decrypted.dat --export-key <hex> --username alice
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

### 5.2 arkfile-admin Implementation

#### System Health Monitoring

**File: `cmd/arkfile-admin/main.go`**

```go
const (
	Usage = `arkfile-admin - System maintenance and monitoring

USAGE:
    arkfile-admin [global options] command [command options] [arguments...]

COMMANDS:
    health        System health monitoring and diagnostics
    rotate-keys   Rotate cryptographic keys (OPAQUE, JWT, TLS)
    backup        Create system backups
    restore       Restore from backups
    audit         Basic security audit
    monitor       Performance monitoring
    status        System status overview

EXAMPLES:
    arkfile-admin health --detailed
    arkfile-admin rotate-keys --opaque --confirm
    arkfile-admin backup --encrypt --output backup.tar.gz
    arkfile-admin monitor --duration 5m
`
)
```

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
	
	// Test 4: Export Key Functionality
	suite.runTest("OPAQUE Export Key Handling", func() error {
		return suite.testExportKeyHandling()
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
	
	// Test 2: File Encryption with OPAQUE Keys
	suite.runTest("OPAQUE-Derived File Encryption", func() error {
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
    
    # Export authentication data for Go tools
    export_auth_data_for_go_tools
    
    # Step 1: Generate 100MB test file with cryptocli
    generate_large_test_file_with_cryptocli
    
    # Step 2: Authenticate with arkfile-client and capture OPAQUE export key
    authenticate_with_arkfile_client_export_key
    
    # Step 3: Encrypt file using authentic OPAQUE export key
    encrypt_test_file_with_opaque_keys
    
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
- OPAQUE export keys work correctly with cryptocli

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
