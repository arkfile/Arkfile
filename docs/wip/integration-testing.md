# Arkfile Integration Testing Framework

## Overview

This document outlines a comprehensive Go-based integration testing framework for the Arkfile secure file vault system. The framework leverages static linking to eliminate mock complexity and provides authentic end-to-end validation through real server interactions. This approach creates specialized Go tools that work together using consistent cryptographic operations, enabling thorough system validation while serving as practical administrative utilities.

**Note**: This document focuses purely on testing methodology and implementation. For architectural decisions regarding static linking and tool design, see `static-linking.md`.

## Testing Philosophy

The integration testing framework eliminates simulation and mocking in favor of authentic server interactions using production-grade cryptographic operations. By leveraging static linking, all testing tools use identical libopaque implementations to the server, ensuring perfect consistency between test and production environments.

### Core Principles

**Authentic Operations**: All tests perform real OPAQUE authentication, genuine file encryption, and actual server API calls using production cryptographic implementations.

**Comprehensive Workflows**: Testing covers complete user journeys from registration through file operations to anonymous sharing, validating every aspect of the user experience.

**Static Binary Consistency**: All testing tools use statically linked binaries, eliminating library dependency issues and ensuring identical cryptographic behavior across test environments.

**Production Readiness**: The testing framework doubles as administrative tooling, providing practical utilities for system management while enabling comprehensive validation.

## Architecture

### Tool Integration Pattern

The testing framework uses four primary tools working in coordination:

**cryptocli** (Static Cryptographic Operations):
- File generation with deterministic patterns for integrity verification
- OPAQUE-derived encryption/decryption using identical server implementations
- Key derivation and management with static libopaque
- Chunked file processing for large file operations

**arkfile-client** (Authenticated Server Communication):
- OPAQUE authentication flows with export key capture
- TLS 1.3 server communication (localhost and remote)
- Chunked file upload/download operations
- Session management and token handling

**arkfile-admin** (Administrative Operations):
- System health monitoring and validation
- User management and database operations
- Performance monitoring and benchmarking
- Cleanup and resource management

**Test Orchestration** (Bash Integration):
- Coordination between Go tools and existing test infrastructure
- Integration with `test-app-curl.sh` for comprehensive validation
- Environment setup and teardown procedures
- Result aggregation and reporting

### Integration Workflow

```
Authentication Phase (arkfile-client):
  Register User → OPAQUE Login → TOTP Setup → Export Keys

File Operations Phase (cryptocli + arkfile-client):
  Generate Test File → Encrypt with OPAQUE Keys → Chunked Upload → Verify Listing

Download Validation Phase (arkfile-client + cryptocli):
  Download Encrypted File → Decrypt with OPAQUE Keys → Verify Integrity

Share Operations Phase (arkfile-client + cryptocli):
  Create Share → Anonymous Access → Share Download → Verify Integrity

Administrative Phase (arkfile-admin):
  System Health Check → Performance Metrics → Resource Cleanup
```

## Implementation Specifications

### Comprehensive Test Suite Architecture

#### Test Suite 1: User Authentication and Setup

**Registration with OPAQUE Protocol**:
- Perform authentic OPAQUE registration using static libopaque
- Handle username-based authentication flows
- Validate server response formats and cryptographic correctness
- Export OPAQUE keys for subsequent cryptographic operations

**TOTP Two-Factor Authentication**:
- Set up TOTP using real cryptographic key generation
- Validate 6-digit TOTP codes with production algorithms
- Test backup code generation and verification
- Handle TOTP authentication during login flows

**Session Management**:
- JWT token acquisition and validation
- Refresh token handling and rotation
- Session key derivation from OPAQUE export keys
- Token expiration and renewal workflows

#### Test Suite 2: Large File Operations

**File Generation and Preparation**:
- Generate deterministic test files (100MB) for integrity verification
- Create SHA-256 hashes for end-to-end integrity validation
- Support multiple file patterns (sequential, repeated, random)
- Memory-efficient generation for large files

**OPAQUE-Integrated Encryption**:
- Derive file encryption keys from OPAQUE export keys
- Perform AES-256-GCM encryption with authentic key derivation
- Create chunked encrypted files for upload operations
- Generate comprehensive manifests for chunk management

**Authenticated Upload Operations**:
- Initialize chunked upload sessions via API
- Upload encrypted chunks with progress tracking
- Complete upload transactions with integrity verification
- Validate server-side file metadata and storage

**Download and Decryption Validation**:
- Download encrypted files using authenticated API calls
- Decrypt files using OPAQUE-derived keys
- Perform SHA-256 integrity verification
- Validate complete encryption/decryption round-trip integrity

#### Test Suite 3: Anonymous Sharing System

**Share Creation with Argon2id**:
- Create share links using production Argon2id parameters
- Re-encrypt file keys for anonymous access
- Generate time-limited share URLs
- Validate database share record creation

**Anonymous Access Testing**:
- Access shared files without authentication
- Validate share password verification and timing protection
- Test rate limiting and security boundaries
- Verify anonymous user privacy protection

**Share Download and Decryption**:
- Download shared files using anonymous access
- Decrypt files using share-derived keys
- Validate integrity through complete sharing workflow
- Test share expiration and access controls

#### Test Suite 4: System Integration and Performance

**Database Operations**:
- Direct database queries for validation and cleanup
- User record management and verification
- File metadata consistency checking
- Share record lifecycle management

**Performance Benchmarking**:
- Measure file upload/download performance (100MB targets)
- Authentication flow timing validation
- Share access timing protection verification
- Memory usage and resource consumption monitoring

**Security Validation**:
- Cryptographic operation correctness verification
- Timing protection validation (minimum response times)
- Rate limiting functionality testing
- Security header and policy validation

## Testing Tool Implementations

### Enhanced cryptocli Commands

#### File Generation and Encryption

```go
// Generate deterministic test files with integrity hashes
cryptocli generate-test-file --size 100MB --pattern sequential --output test.dat --hash-output test.hash

// Encrypt files using OPAQUE-derived keys (production compatibility)
cryptocli encrypt-file-opaque --input test.dat --output test.enc --export-key <hex> --username alice --file-id test.dat

// Chunked encryption for large file upload preparation
cryptocli encrypt-chunked-opaque --input test.dat --output-dir chunks/ --export-key <hex> --username alice --manifest manifest.json

// Decrypt files using various key sources
cryptocli decrypt-file-opaque --input test.enc --output decrypted.dat --export-key <hex> --username alice
cryptocli decrypt-file-opaque --input test.enc --output decrypted.dat --encrypted-fek fek.bin --export-key <hex>
```

#### Share-Based Decryption

```go
// Decrypt files accessed through anonymous sharing
cryptocli decrypt-share-file --input shared.enc --output shared-decrypted.dat --share-password <password> --salt <hex>

// Validate share key derivation using Argon2id
cryptocli derive-share-key --password <password> --salt <hex> --output share-key.hex
```

### Enhanced arkfile-client Commands

#### Authentication and Session Management

```go
// Complete OPAQUE authentication with export key capture
arkfile-client login --username alice --export-opaque-key opaque-export.hex --session-file session.json

// Session validation and token management
arkfile-client validate-session --session-file session.json
arkfile-client refresh-token --session-file session.json
```

#### File Operations

```go
// Upload chunked encrypted files with progress tracking
arkfile-client upload --manifest manifest.json --chunks-dir chunks/ --filename test.dat --progress

// Download files with encrypted FEK export
arkfile-client download --file-id <id> --output encrypted.dat --export-encrypted-fek fek.bin

// List files with detailed metadata
arkfile-client list-files --output-json files.json
```

#### Share Management

```go
// Create anonymous shares with Argon2id password protection
arkfile-client create-share --file-id <id> --password <password> --expires-days 30

// Access shares anonymously (no authentication required)
arkfile-client access-share --share-id <id> --password <password> --output shared.dat
```

### arkfile-admin Integration

#### System Validation

```go
// Comprehensive system health assessment
arkfile-admin health --detailed --output-json health.json

// Database connectivity and integrity validation
arkfile-admin validate-database --check-integrity --repair-minor-issues

// Performance benchmarking with detailed metrics
arkfile-admin benchmark --test-file-size 100MB --concurrent-users 5 --output-json benchmark.json
```

#### Resource Management

```go
// Clean up test data and resources
arkfile-admin cleanup --test-users --temporary-files --verify-cleanup

// User management for testing
arkfile-admin create-test-user --username test-user --auto-approve
arkfile-admin remove-test-user --username test-user --cleanup-files
```

## Test Integration with Existing Infrastructure

### Enhanced test-app-curl.sh Integration

#### Phase 11: Go Tools File Operations

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

#### Phase 12: Anonymous Sharing Operations

```bash
phase_anonymous_sharing_go_tools() {
    phase "ANONYMOUS SHARING WITH GO TOOLS"
    
    # Step 1: Create share using arkfile-client
    create_anonymous_share_with_password
    
    # Step 2: Validate share in database
    validate_share_database_record
    
    # Step 3: Logout authenticated user
    logout_authenticated_session
    
    # Step 4: Access share anonymously
    access_share_anonymously_with_timing_validation
    
    # Step 5: Download shared file without authentication
    download_shared_file_anonymous
    
    # Step 6: Decrypt shared file using Argon2id-derived key
    decrypt_shared_file_with_share_key
    
    # Step 7: Verify integrity through complete sharing workflow
    verify_sharing_workflow_integrity
    
    success "Anonymous sharing testing completed with Go tools"
}
```

### Performance and Security Validation

#### Benchmarking Framework

```bash
benchmark_comprehensive_operations() {
    log "Running comprehensive performance benchmarks..."
    
    # File operation benchmarks
    local upload_start download_start share_start
    
    upload_start=$(date +%s%N)
    upload_chunked_file_with_arkfile_client
    local upload_duration=$(($(date +%s%N) - upload_start))
    
    download_start=$(date +%s%N)
    download_and_decrypt_complete_workflow
    local download_duration=$(($(date +%s%N) - download_start))
    
    share_start=$(date +%s%N)
    access_share_anonymously_with_timing_validation
    local share_duration=$(($(date +%s%N) - share_start))
    
    # Performance validation
    validate_performance_benchmarks "$upload_duration" "$download_duration" "$share_duration"
}

validate_performance_benchmarks() {
    local upload_ns="$1" download_ns="$2" share_ns="$3"
    
    local upload_ms=$((upload_ns / 1000000))
    local download_ms=$((download_ns / 1000000))
    local share_ms=$((share_ns / 1000000))
    
    info "Performance Results:"
    info "  100MB Upload: ${upload_ms}ms"
    info "  100MB Download: ${download_ms}ms" 
    info "  Share Access: ${share_ms}ms"
    
    # Validate against performance targets
    if [ "$upload_ms" -gt 60000 ]; then
        warning "Upload slower than 60s target: ${upload_ms}ms"
    fi
    
    if [ "$download_ms" -gt 20000 ]; then
        warning "Download slower than 20s target: ${download_ms}ms"
    fi
    
    if [ "$share_ms" -lt 900 ] || [ "$share_ms" -gt 1500 ]; then
        warning "Share access timing outside 900-1500ms range: ${share_ms}ms"
    else
        success "Timing protection validated: ${share_ms}ms"
    fi
}
```

#### Security Validation Framework

```bash
validate_security_measures() {
    log "Validating security measures..."
    
    # Cryptographic integrity validation
    validate_cryptographic_integrity
    
    # Timing protection validation
    validate_timing_protection_consistency
    
    # Rate limiting validation
    validate_rate_limiting_functionality
    
    # Anonymous privacy validation
    validate_anonymous_privacy_protection
    
    success "All security measures validated"
}

validate_cryptographic_integrity() {
    log "Validating cryptographic integrity..."
    
    # Compare all file hashes through complete workflow
    local original_hash authenticated_hash anonymous_hash
    
    original_hash=$(cat "$TEMP_DIR/original-file.hash")
    authenticated_hash=$(sha256sum "$TEMP_DIR/authenticated-download.dat" | cut -d' ' -f1)
    anonymous_hash=$(sha256sum "$TEMP_DIR/anonymous-download.dat" | cut -d' ' -f1)
    
    if [ "$original_hash" = "$authenticated_hash" ] && [ "$original_hash" = "$anonymous_hash" ]; then
        success "Perfect cryptographic integrity verified across all workflows"
        info "  Original:        $original_hash"
        info "  Authenticated:   $authenticated_hash" 
        info "  Anonymous:       $anonymous_hash"
        info "  ✅ Triple integrity match"
    else
        error "Cryptographic integrity failure detected"
        error "  Original:        $original_hash"
        error "  Authenticated:   $authenticated_hash"
        error "  Anonymous:       $anonymous_hash"
        return 1
    fi
}
```

## Expected Results and Validation

### Comprehensive Test Output

```
🧪 ARKFILE INTEGRATION TESTING FRAMEWORK
Configuration:
  Server URL: https://localhost:4443
  Test Username: integration.test.user.2025
  Test File Size: 100MB
  Database URL: http://localhost:4001
  Static Binaries: ✅ Verified

📋 Phase 1: User Authentication and Setup
  ✅ OPAQUE Registration (2.1s) - Zero-knowledge authentication
  ✅ Database User Approval (0.3s) - Direct database operation  
  ✅ TOTP Setup and Verification (4.2s) - Real cryptographic keys
  ✅ Complete Login Flow (3.8s) - JWT and refresh tokens
  ✅ Export Key Capture (0.5s) - OPAQUE export key: 64 bytes

📋 Phase 2: Large File Operations
  ✅ Test File Generation (1.2s) - 100MB deterministic content
  ✅ OPAQUE Key Derivation (0.1s) - Static libopaque consistency
  ✅ File Encryption (8.3s) - AES-256-GCM with derived keys
  ✅ Chunked Upload (45.3s) - 100 chunks, 1MB each
  ✅ File Listing Verification (0.8s) - Metadata validation
  ✅ Authenticated Download (12.4s) - Encrypted file retrieval
  ✅ File Decryption (7.9s) - OPAQUE key decryption
  ✅ Integrity Verification (0.9s) - SHA-256 perfect match ✅

📋 Phase 3: Anonymous Sharing System  
  ✅ Share Creation (3.7s) - Argon2id key derivation (128MB, 4 iter)
  ✅ Database Share Validation (0.4s) - Share record verified
  ✅ Session Logout (0.6s) - Authentication cleared
  ✅ Anonymous Share Access (1.8s) - Timing protection: 1,015ms ✅
  ✅ Anonymous Download (15.2s) - No authentication required
  ✅ Share Key Decryption (2.1s) - Argon2id key derivation
  ✅ Anonymous Integrity Check (0.7s) - SHA-256 perfect match ✅

📋 Phase 4: System Integration and Performance
  ✅ Database Operations (1.2s) - Direct queries and cleanup
  ✅ Performance Benchmarks - All targets met ✅
      Upload:   45.3s (target: <60s) ✅
      Download: 12.4s (target: <20s) ✅  
      Share:    1.8s (timing protection: 900-1500ms) ✅
  ✅ Security Validation (0.8s) - All measures active ✅
  ✅ Resource Cleanup (1.5s) - Complete data removal ✅

🎉 ALL INTEGRATION TESTS PASSED

📊 Final Results:
   Total Duration: 2 minutes 47 seconds
   Total Steps: 24 operations
   Success Rate: 100% (24/24) ✅
   
📈 Performance Summary:
   File Operations: 100MB file - Complete cycle in 77 seconds
   Cryptographic: Static libopaque consistency across all operations ✅
   Network: TLS 1.3 connections stable for local and remote servers ✅
   
🔐 Security Validation Summary:
   ✅ OPAQUE zero-knowledge authentication (no password exposure)
   ✅ End-to-end file encryption (AES-256-GCM integrity preserved)
   ✅ Argon2id share protection (128MB memory, production parameters)
   ✅ Timing protection active (1.8s > 900ms minimum)
   ✅ Anonymous privacy maintained (no user data disclosure)
   ✅ Perfect file integrity (SHA-256 triple verification)
   
💾 Data Integrity Report:
   Original file:       104,857,600 bytes (100.0 MB)
   Authenticated cycle: 104,857,600 bytes ✅ Perfect match
   Anonymous cycle:     104,857,600 bytes ✅ Perfect match
   Hash verification:   SHA-256 identical across all workflows ✅
   
✨ SYSTEM VALIDATION: COMPLETE SUCCESS
Arkfile secure file vault fully operational with static binary consistency!

Cleanup completed - all test data securely removed
Detailed logs: /tmp/arkfile-integration-20250813-090000/
```

### Success Criteria

**Complete Workflow Validation**: All 24 test steps complete without errors, demonstrating full system functionality from authentication through file operations to anonymous sharing.

**Cryptographic Integrity**: Perfect SHA-256 hash matches across all workflows (original → authenticated → anonymous), proving zero data corruption through complete encryption/decryption cycles.

**Performance Compliance**: All operations complete within established benchmarks (100MB upload <60s, download <20s, share access 900-1500ms timing protection).

**Security Validation**: All security measures active and functioning correctly, including timing protection, rate limiting, end-to-end encryption, and anonymous privacy protection.

**Static Binary Consistency**: All cryptographic operations use identical static libopaque implementations, eliminating version discrepancies and ensuring perfect test-production parity.

## Implementation Timeline

### Week 1: Core Tool Enhancement
- **Days 1-3**: Enhance cryptocli with OPAQUE integration and large file operations
- **Days 4-5**: Enhance arkfile-client with comprehensive API operations  
- **Days 6-7**: Develop arkfile-admin integration and validation tools

### Week 2: Test Framework Integration
- **Days 1-3**: Integrate Go tools with existing test-app-curl.sh infrastructure
- **Days 4-5**: Implement comprehensive workflow testing (Phases 11-12)
- **Days 6-7**: Develop performance benchmarking and security validation

### Week 3: Validation and Optimization  
- **Days 1-3**: Cross-platform testing and validation
- **Days 4-5**: Performance optimization and security hardening
- **Days 6-7**: Documentation and deployment preparation

This integration testing framework provides comprehensive validation of the Arkfile system using authentic operations and static binary consistency, ensuring production readiness through thorough end-to-end testing.
