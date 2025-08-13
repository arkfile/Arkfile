# Static Linking Implementation Plan

## Executive Summary

This document outlines the migration of Arkfile from dynamic libopaque linking to static linking across all components - server, client tools, and test infrastructure. This architectural change eliminates runtime library dependencies, simplifies deployment, removes mock complexity from testing, and provides a foundation for reliable client tool distribution while maintaining the existing tool separation between cryptocli (offline cryptographic operations) and arkfile-client (authenticated server communication).

## Background and Motivation

### Current Challenges

The existing dynamic linking approach presents several operational and development challenges:

**Runtime Dependencies**: Server deployments require careful libopaque library management across different Linux distributions, creating potential compatibility issues and deployment complexity.

**Testing Complexity**: Extensive mock infrastructure exists throughout the codebase specifically to enable testing without libopaque dependencies. This mock system introduces maintenance overhead, potential behavioral differences between test and production code, and complexity in CI/CD environments.

**Client Distribution**: Distributing client tools (cryptocli, arkfile-client) to end users requires them to install libopaque libraries, creating barriers to adoption and support complexity.

**Development Friction**: New developers must install and configure libopaque libraries before contributing, and development environments can have subtle differences in library versions leading to inconsistent behavior.

### Strategic Benefits of Static Linking

**Deployment Simplification**: Self-contained binaries eliminate library installation requirements for both server deployments and client distributions, reducing operational complexity and support burden.

**Testing Unification**: Removal of mock infrastructure means all tests run against production cryptographic code paths, increasing confidence in test results and eliminating mock/production behavioral discrepancies.

**Client Tool Distribution**: Static binaries enable simple client tool distribution across platforms without library installation requirements, supporting broader user adoption.

**Development Environment Consistency**: All developers work with identical cryptographic implementations, eliminating version-related development issues and simplifying onboarding.

**Version Control**: Pinning to specific libopaque commits ensures identical cryptographic behavior across all environments and deployments.

## Architecture Overview

### Tool Ecosystem Preservation

The static linking migration preserves the established tool architecture while eliminating library dependencies:

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

**arkfile** (Main Server Binary):
- Web server with authentication and file management APIs
- Static linking eliminates server library dependencies
- Simplified deployment across different environments

### Integration Pattern

The tools integrate through secure key handoff patterns:
1. arkfile-client performs OPAQUE authentication and exports account-export and session keys as needed
2. cryptocli uses exported keys for offline cryptographic operations
3. arkfile-client handles all network communication with the offline, pre-encrypted payloads

## Implementation Strategy

### Phase 1: Build System Transformation

#### 1.1 Libopaque Build System
**File: `scripts/setup/build-libopaque.sh`**

Transform the build system to support static linking:

```bash
#!/bin/bash
# Static libopaque build with version pinning

LIBOPAQUE_COMMIT="specific-commit-hash-for-consistency"
LIBOPAQUE_DIR="/opt/arkfile/src/libopaque"

# Clone specific commit for consistency
if [ ! -d "$LIBOPAQUE_DIR" ]; then
    git clone https://github.com/facebook/opaque.git "$LIBOPAQUE_DIR"
    cd "$LIBOPAQUE_DIR"
    git checkout "$LIBOPAQUE_COMMIT"
else
    cd "$LIBOPAQUE_DIR"
    git fetch
    git checkout "$LIBOPAQUE_COMMIT"
fi

# Configure for static library generation
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DCMAKE_INSTALL_PREFIX=/opt/arkfile/lib/libopaque \
      ..

# Build static library
make -j$(nproc)
make install

# Verify static library exists
if [ -f "/opt/arkfile/lib/libopaque/lib/libopaque.a" ]; then
    echo "✅ Static libopaque library built successfully"
    echo "Commit: $LIBOPAQUE_COMMIT"
    echo "Library: /opt/arkfile/lib/libopaque/lib/libopaque.a"
else
    echo "❌ Static library build failed"
    exit 1
fi
```

#### 1.2 Go Build Configuration
**File: `scripts/setup/build.sh`**

Update the main build script for static linking:

```bash
#!/bin/bash
# Static linking build configuration

set -euo pipefail

# Ensure libopaque is built statically
./scripts/setup/build-libopaque.sh

# Static linking environment
export CGO_ENABLED=1
export CGO_LDFLAGS="-L/opt/arkfile/lib/libopaque/lib -lopaque -lstdc++ -lm -static"
export CGO_CPPFLAGS="-I/opt/arkfile/lib/libopaque/include"

# Build main server binary statically
echo "Building arkfile server binary with static linking..."
go build -a -ldflags '-extldflags "-static"' -o arkfile main.go

# Build client tools statically
echo "Building cryptocli with static linking..."
cd cmd/cryptocli
go build -a -ldflags '-extldflags "-static"' -o ../../cryptocli .
cd ../..

echo "Building arkfile-client with static linking..."
cd cmd/arkfile-client  
go build -a -ldflags '-extldflags "-static"' -o ../../arkfile-client .
cd ../..

# Verify static linking
echo "Verifying static binaries..."
if ldd ./arkfile 2>&1 | grep -q "not a dynamic executable"; then
    echo "✅ arkfile: Static binary verified"
else
    echo "❌ arkfile: Dynamic linking detected"
fi

if ldd ./cryptocli 2>&1 | grep -q "not a dynamic executable"; then
    echo "✅ cryptocli: Static binary verified"  
else
    echo "❌ cryptocli: Dynamic linking detected"
fi

if ldd ./arkfile-client 2>&1 | grep -q "not a dynamic executable"; then
    echo "✅ arkfile-client: Static binary verified"
else
    echo "❌ arkfile-client: Dynamic linking detected"
fi

echo "✅ Static linking build completed"
```

### Phase 2: Mock System Removal

#### 2.1 Authentication System Cleanup

**Files to Delete:**
```
auth/opaque_mock.go
auth/opaque_mock_server.go
auth/opaque_password_manager_mock.go
auth/opaque_password_manager_factory_mock.go
auth/mock_only_test.go
```

**File: `auth/opaque_unified.go`** - Remove mock conditionals:

```go
// Remove all build tag conditionals like:
// //go:build !mock

// Remove mock-related imports and conditional logic
// Simplify to single production implementation

package auth

import (
    "context"
    "fmt"
    "github.com/yourdomain/arkfile/logging"
)

// Unified OPAQUE provider - production implementation only
type OPAQUEProvider struct {
    logger *logging.Logger
    // Remove mock field
}

func NewOPAQUEProvider(logger *logging.Logger) *OPAQUEProvider {
    // Remove mock detection logic
    return &OPAQUEProvider{
        logger: logger,
    }
}

// Remove all mock-related methods and conditional implementations
```

**File: `auth/opaque_password_manager_factory.go`** - Simplify to single implementation:

```go
package auth

// Remove mock factory logic
func NewPasswordManagerFactory() PasswordManagerFactory {
    // Always return production implementation
    return &ProductionPasswordManagerFactory{}
}
```

#### 2.2 Test System Updates

**Global Changes:**
- Remove all `//go:build !mock` and `//go:build mock` build tags
- Update all `*_test.go` files to use static binaries
- Remove mock setup and teardown logic from tests

**Example: `auth/opaque_provider_test.go`**:

```go
func TestOPAQUEProvider(t *testing.T) {
    // Remove mock setup
    // Use static binary OPAQUE implementation directly
    
    provider := NewOPAQUEProvider(logging.NewLogger())
    
    // Test against production implementation
    result, err := provider.Register(context.Background(), username, password)
    require.NoError(t, err)
    require.NotNil(t, result)
}
```

### Phase 3: Client Tools Enhancement

#### 3.1 arkfile-client TLS 1.3 Remote Support

**File: `cmd/arkfile-client/main.go`** - Add remote server support:

```go
package main

import (
    "crypto/tls"
    "flag"
    "fmt"
    "net/url"
    "os"
)

type ClientConfig struct {
    ServerURL    string `json:"server_url"`
    Username     string `json:"username"`
    TLSInsecure  bool   `json:"tls_insecure"`  
    TLSMinVersion uint16 `json:"tls_min_version"`
    TokenFile    string `json:"token_file"`
    ConfigFile   string `json:"config_file"`
}

func main() {
    var (
        serverURL    = flag.String("server-url", "https://localhost:4443", "Server URL (supports remote servers)")
        configFile   = flag.String("config", "", "Configuration file path")
        tlsInsecure  = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (localhost only)")
        tlsMinVer    = flag.String("tls-min-version", "1.3", "Minimum TLS version (1.2 or 1.3)")
        username     = flag.String("username", "", "Username for authentication")
    )
    flag.Parse()

    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }

    // Parse and validate server URL
    serverURL, err := url.Parse(*serverURL)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Invalid server URL: %v\n", err)
        os.Exit(1)
    }

    // Validate TLS settings for remote servers
    if serverURL.Hostname() != "localhost" && serverURL.Hostname() != "127.0.0.1" {
        if *tlsInsecure {
            fmt.Fprintf(os.Stderr, "Error: --tls-insecure is not allowed for remote servers\n")
            os.Exit(1)
        }
    }

    config := &ClientConfig{
        ServerURL:     serverURL.String(),
        Username:      *username,
        TLSInsecure:   *tlsInsecure,
        TLSMinVersion: parseTLSVersion(*tlsMinVer),
        ConfigFile:    *configFile,
    }

    client := NewHTTPClient(config)

    switch os.Args[1] {
    case "login":
        err = handleLogin(client, config)
    case "upload":
        err = handleUpload(client, config)
    case "download":
        err = handleDownload(client, config)
    case "list-files":
        err = handleListFiles(client, config)
    case "create-share":
        err = handleCreateShare(client, config)
    default:
        fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
        printUsage()
        os.Exit(1)
    }

    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}

func NewHTTPClient(config *ClientConfig) *http.Client {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: config.TLSInsecure,
        MinVersion:         config.TLSMinVersion,
        // Prefer TLS 1.3 for remote connections
        MaxVersion:         tls.VersionTLS13,
    }

    transport := &http.Transport{
        TLSClientConfig: tlsConfig,
        // Connection optimization for remote servers
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    }

    return &http.Client{
        Transport: transport,
        Timeout:   60 * time.Second, // Longer timeout for remote servers
    }
}

func parseTLSVersion(version string) uint16 {
    switch version {
    case "1.2":
        return tls.VersionTLS12
    case "1.3":
        return tls.VersionTLS13
    default:
        fmt.Fprintf(os.Stderr, "Invalid TLS version: %s (use 1.2 or 1.3)\n", version)
        os.Exit(1)
        return 0
    }
}
```

### Phase 4: Go Utilities Integration

#### 4.1 arkfile-setup Enhancement

**File: `cmd/arkfile-setup/build/static.go`** - Add static build management:

```go
package build

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

type StaticBuilder struct {
    config      *Config
    libopaqueDir string
    logger      *Logger
}

func NewStaticBuilder(config *Config, logger *Logger) *StaticBuilder {
    return &StaticBuilder{
        config:       config,
        libopaqueDir: "/opt/arkfile/src/libopaque",
        logger:       logger,
    }
}

func (sb *StaticBuilder) BuildLibopaque(commitHash string) error {
    sb.logger.Info("Building libopaque statically", "commit", commitHash)
    
    // Clone or update libopaque to specific commit
    if err := sb.ensureLibopaqueSource(commitHash); err != nil {
        return fmt.Errorf("failed to prepare libopaque source: %w", err)
    }
    
    // Build static library
    if err := sb.buildStaticLibrary(); err != nil {
        return fmt.Errorf("failed to build static library: %w", err)
    }
    
    // Verify static library
    if err := sb.verifyStaticLibrary(); err != nil {
        return fmt.Errorf("static library verification failed: %w", err)
    }
    
    sb.logger.Success("Libopaque static build completed")
    return nil
}

func (sb *StaticBuilder) BuildAllBinaries() error {
    sb.logger.Info("Building all binaries with static linking")
    
    binaries := map[string]string{
        "arkfile":        ".",
        "cryptocli":      "cmd/cryptocli",
        "arkfile-client": "cmd/arkfile-client",
    }
    
    // Set static linking environment
    env := append(os.Environ(),
        "CGO_ENABLED=1",
        "CGO_LDFLAGS=-L/opt/arkfile/lib/libopaque/lib -lopaque -lstdc++ -lm -static",
        "CGO_CPPFLAGS=-I/opt/arkfile/lib/libopaque/include",
    )
    
    for binary, path := range binaries {
        sb.logger.Info("Building binary", "name", binary, "path", path)
        
        cmd := exec.Command("go", "build", "-a", "-ldflags", "-extldflags \"-static\"", "-o", binary)
        cmd.Dir = filepath.Join(sb.config.ProjectRoot, path)
        cmd.Env = env
        
        if output, err := cmd.CombinedOutput(); err != nil {
            return fmt.Errorf("failed to build %s: %w\nOutput: %s", binary, err, output)
        }
        
        // Verify static linking
        if err := sb.verifyStaticBinary(filepath.Join(sb.config.ProjectRoot, binary)); err != nil {
            return fmt.Errorf("static linking verification failed for %s: %w", binary, err)
        }
        
        sb.logger.Success("Built binary", "name", binary)
    }
    
    return nil
}

func (sb *StaticBuilder) verifyStaticBinary(binaryPath string) error {
    cmd := exec.Command("ldd", binaryPath)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        // ldd returns error for static binaries, check output
        if strings.Contains(string(output), "not a dynamic executable") {
            return nil // This is expected for static binaries
        }
        return fmt.Errorf("ldd failed: %w", err)
    }
    
    // If ldd succeeded, the binary is dynamic (not what we want)
    return fmt.Errorf("binary is dynamically linked: %s", string(output))
}
```

#### 4.2 arkfile-admin Enhancement

**File: `cmd/arkfile-admin/deployment/static.go`** - Add deployment management:

```go
package deployment

import (
    "fmt"
    "os"
    "path/filepath"
)

type StaticDeployment struct {
    config *Config
    logger *Logger
}

func NewStaticDeployment(config *Config, logger *Logger) *StaticDeployment {
    return &StaticDeployment{
        config: config,
        logger: logger,
    }
}

func (sd *StaticDeployment) DeployStaticBinaries() error {
    sd.logger.Info("Deploying static binaries")
    
    binaries := []string{"arkfile", "cryptocli", "arkfile-client"}
    
    for _, binary := range binaries {
        sourcePath := filepath.Join(sd.config.BuildDir, binary)
        targetPath := filepath.Join(sd.config.BinDir, binary)
        
        if err := sd.deployBinary(sourcePath, targetPath); err != nil {
            return fmt.Errorf("failed to deploy %s: %w", binary, err)
        }
        
        sd.logger.Success("Deployed binary", "name", binary, "path", targetPath)
    }
    
    return nil
}

func (sd *StaticDeployment) ValidateDeployment() error {
    sd.logger.Info("Validating static binary deployment")
    
    binaries := []string{"arkfile", "cryptocli", "arkfile-client"}
    
    for _, binary := range binaries {
        binaryPath := filepath.Join(sd.config.BinDir, binary)
        
        // Check binary exists and is executable
        if err := sd.validateBinary(binaryPath); err != nil {
            return fmt.Errorf("validation failed for %s: %w", binary, err)
        }
        
        // Verify static linking
        if err := sd.verifyStaticLinking(binaryPath); err != nil {
            return fmt.Errorf("static linking verification failed for %s: %w", binary, err)
        }
        
        sd.logger.Success("Validated binary", "name", binary)
    }
    
    return nil
}

func (sd *StaticDeployment) CleanupOldBinaries() error {
    sd.logger.Info("Cleaning up old binary versions")
    
    // Remove old backup binaries older than 30 days
    backupDir := filepath.Join(sd.config.BinDir, "backups")
    
    return sd.cleanupOldBackups(backupDir, 30*24*time.Hour)
}
```

### Phase 5: Testing Infrastructure Update

#### 5.1 Test Script Integration

**File: `scripts/testing/test-app-curl.sh`** - Update for static binaries:

```bash
# Add static binary verification phase
verify_static_binaries() {
    log "Verifying static binary builds..."
    
    local binaries=("./arkfile" "./cryptocli" "./arkfile-client")
    
    for binary in "${binaries[@]}"; do
        if [ ! -f "$binary" ]; then
            error "Binary not found: $binary"
        fi
        
        if ! ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
            error "Binary is not statically linked: $binary"
        fi
        
        success "Verified static binary: $binary"
    done
}

# Update Go tool building phase
build_go_tools() {
    log "Building Go tools with static linking..."
    
    # Use static build script instead of individual builds
    if ! ./scripts/setup/build.sh; then
        error "Static build failed"
    fi
    
    # Verify static binaries
    verify_static_binaries
    
    success "All static Go tools built and verified"
}

# Update file operations phase to use static binaries consistently
phase_file_operations() {
    phase "FILE OPERATIONS WITH STATIC GO TOOLS"
    
    # No mock setup needed - always using production implementation
    build_go_tools
    export_auth_data_for_go_tools
    generate_test_file_with_cryptocli
    authenticate_with_client_tool
    encrypt_test_file_with_opaque
    upload_file_with_client
    verify_file_with_client
    download_and_decrypt_file
    verify_complete_integrity
    cleanup_file_operations_test
    
    success "File operations testing completed with static binaries"
}
```

### Phase 6: Development Workflow Updates

#### 6.1 dev-reset Script Updates

**File: `scripts/dev-reset.sh`** - Update for static binary approach:

```bash
#!/bin/bash
# Development reset with static binary support

set -euo pipefail

# Reset function for static binary environment
reset_static_environment() {
    log "Resetting development environment with static binaries"
    
    # Stop all services
    stop_all_services
    
    # Clean data directories
    clean_data_directories
    
    # Check if libopaque version changed
    local current_commit
    current_commit=$(get_current_libopaque_commit)
    
    if [ "$current_commit" != "$(cat .libopaque-version 2>/dev/null || echo '')" ]; then
        log "Libopaque version changed, rebuilding static binaries"
        rebuild_static_binaries
        echo "$current_commit" > .libopaque-version
    else
        log "Libopaque version unchanged, using existing static binaries"
    fi
    
    # Deploy static binaries
    deploy_static_binaries
    
    # Initialize with test data
    initialize_test_data
    
    success "Development environment reset completed with static binaries"
}

rebuild_static_binaries() {
    log "Rebuilding all static binaries"
    
    # Clean old binaries
    rm -f arkfile cryptocli arkfile-client
    
    # Build with static linking
    ./scripts/setup/build.sh
    
    # Verify static linking
    verify_static_binaries
}

get_current_libopaque_commit() {
    # Get the pinned commit from build script
    grep "LIBOPAQUE_COMMIT=" scripts/setup/build-libopaque.sh | cut -d'"' -f2
}
```

## Migration Timeline

### Phase 1: Foundation (Week 1)
- **Days 1-2**: Update libopaque build system for static compilation
- **Days 3-4**: Modify main build system for static linking
- **Days 5-7**: Test static builds and resolve linking issues

### Phase 2: Mock Removal (Week 2)  
- **Days 1-3**: Remove all mock files and build tags
- **Days 4-5**: Update authentication system for single implementation
- **Days 6-7**: Update all tests to use static binaries

### Phase 3: Client Enhancement (Week 3)
- **Days 1-3**: Add TLS 1.3 remote server support to arkfile-client
- **Days 4-5**: Test client tools with static linking
- **Days 6-7**: Integration testing between cryptocli and arkfile-client

### Phase 4: Tooling Integration (Week 4)
- **Days 1-3**: Enhance arkfile-setup with static build management
- **Days 4-5**: Enhance arkfile-admin with deployment capabilities
- **Days 6-7**: Update development scripts for static binary workflow

### Phase 5: Testing and Documentation (Week 5)
- **Days 1-3**: Update all test scripts for static binary approach
- **Days 4-5**: Comprehensive testing across all environments
- **Days 6-7**: Documentation updates and final validation

## Validation Criteria

### Static Linking Verification
- All binaries pass `ldd` static verification tests
- No runtime library dependencies on any target system
- Binaries work identically across different Linux distributions

### Functional Verification
- All existing tests pass with static binaries
- OPAQUE authentication works identically to dynamic linking
- File operations maintain perfect integrity through static crypto
- Client tools successfully connect to both localhost and remote servers

### Performance Verification
- Static binary startup time acceptable (< 100ms difference)
- Cryptographic operations performance within 5% of dynamic linking
- Memory usage remains within acceptable bounds

### Integration Verification
- arkfile-setup successfully manages static builds
- arkfile-admin properly deploys static binaries
- dev-reset works seamlessly with static binary workflow
- All test scripts pass with static binary implementations

## Risk Mitigation

### Build Complexity
**Risk**: Static linking may increase build complexity and compilation time
**Mitigation**: Comprehensive build scripts with clear error handling and progress reporting

### Binary Size
**Risk**: Static binaries may be significantly larger than dynamic ones
**Mitigation**: Monitor binary sizes and implement compression for distribution if needed

### Platform Compatibility  
**Risk**: Static linking may have platform-specific issues
**Mitigation**: Test on primary target platforms (Alma Linux 10, Debian 13)

## Success Metrics

### Development Experience
- Elimination of environment-specific build issues
- Simplified CI/CD pipeline without library management

### Testing Quality
- 100% removal of mock-related code and build tags
- All tests running against production cryptographic implementations
- Increased confidence in test results due to elimination of mock/production differences

### Operational Benefits
- Simplified server deployment without library dependencies
- Simplified client tool distribution as self-contained binaries
- Reduced support burden from library-related issues

## Conclusion

The migration to static linking represents a significant architectural improvement that addresses current pain points while establishing a more robust foundation for future development. By eliminating mock complexity, simplifying deployment, and enabling seamless client tool distribution, this change positions Arkfile for more reliable operation and broader adoption.

The implementation preserves all existing functionality while providing operational benefits that compound over time. The phased approach ensures minimal disruption to ongoing development while providing incremental validation of the migration's success.
