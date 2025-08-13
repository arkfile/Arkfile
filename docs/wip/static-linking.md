# Static Linking Implementation (Foundation Phase)

## Executive Summary

This document outlines the migration of Arkfile from dynamic libopaque linking to static linking to eliminate deployment complexity and testing inconsistencies. The **primary goal is to maintain all existing functionality while removing library dependencies.**

This is a **foundation phase** focused on core architectural changes. Advanced tooling and client utilities are covered in `go-utils-project.md`.

## Background and Motivation

### Current Challenges

The existing dynamic linking approach presents several operational and development challenges:

**Runtime Dependencies**: Server deployments require careful libopaque library management across different Linux distributions, creating potential compatibility issues and deployment complexity.

**Testing Complexity**: Extensive mock infrastructure exists throughout the codebase specifically to enable testing without libopaque dependencies. This mock system introduces maintenance overhead, potential behavioral differences between test and production code, and complexity in CI/CD environments.

**Development Friction**: New developers must install and configure libopaque libraries before contributing, and development environments can have subtle differences in library versions leading to inconsistent behavior.

### Strategic Benefits of Static Linking

**Deployment Simplification**: Self-contained binaries eliminate library installation requirements, reducing operational complexity and support burden.

**Testing Unification**: Removal of mock infrastructure means all tests run against production cryptographic code paths, increasing confidence in test results and eliminating mock/production behavioral discrepancies.

**Development Environment Consistency**: All developers work with identical cryptographic implementations, eliminating version-related development issues and simplifying onboarding.

## Critical Success Criteria

After each phase completion, the following validation sequence **must pass**:

1. `sudo ./scripts/dev-reset.sh` completes successfully without errors
2. `./scripts/testing/test-app-curl.sh` passes all tests 
3. Built-in admin dev test user can authenticate via web interface
4. All existing functionality remains intact

**Important**: The app should never be "manually rebuilt in-place and then moved to /opt/arkfile/". All builds must go through the standard dev-reset workflow during this project.

## Development Guidelines

- **No manual binary compilation and movement** - Always use dev-reset workflow
- **New bash scripts only if absolutely necessary** for debugging purposes
- **Any new bash scripts must be placed under `scripts/wip/`** only
- **Always validate with dev-reset → test-app-curl.sh** after any changes
- **Incremental validation** - test after each significant change, not just at phase completion

```
NOTES:

please read or re-read all relevant code / files / scripts in the project before beginning work on a new phase or step

please also read in detail the dev-reset script and all scripts and logic it currently uses, and consider how it may need to be updated as we go

we must use dev-reset.sh with sudo every time to rebuild and redeploy the project when making major changes. and we must use test-app-curl.sh to validate that the app is fully running correctly (at least as far as auth/login is concerned)

do not create new bash files during this process, or new documentation files, unless absolutely necessary.
```

## Implementation Phases

### Phase 1: Static Build System ✅ COMPLETED

#### Goal
Create cross-platform static library build system that produces statically linked binaries without breaking existing functionality.

**STATUS: ✅ PHASE 1 COMPLETE AND VALIDATED**
- Static linking fully implemented and working
- All services running with statically-linked binaries
- Authentication system (OPAQUE+TOTP) validated
- Dev-reset workflow enhanced and complete

#### Technical Changes

**1.1 ✅ Enhanced build-libopaque.sh**

**File: `scripts/setup/build-libopaque.sh`** - Complete cross-platform static build system:

```bash
#!/bin/bash
# Cross-platform static library build system

set -e

echo "=== Arkfile Static Library Build System ==="

# Cross-platform system detection
detect_system_and_packages() {
    if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "linux-musl"* ]]; then
        if [ -f /etc/alpine-release ]; then
            OS="alpine"
            PACKAGE_MANAGER="apk"
            INSTALL_CMD="apk add --no-cache"
            SODIUM_PKG="libsodium-dev libsodium-static"
            LIBC="musl"
        elif command -v apt-get >/dev/null; then
            OS="debian"
            PACKAGE_MANAGER="apt"
            INSTALL_CMD="apt-get update && apt-get install -y"
            SODIUM_PKG="libsodium-dev"
            LIBC="glibc"
        elif command -v dnf >/dev/null; then
            OS="alma"
            PACKAGE_MANAGER="dnf"
            INSTALL_CMD="dnf install -y"
            SODIUM_PKG="libsodium-devel"
            LIBC="glibc"
        fi
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        OS="freebsd"
        PACKAGE_MANAGER="pkg"
        INSTALL_CMD="pkg install -y"
        SODIUM_PKG="libsodium"
        LIBC="freebsd-libc"
    elif [[ "$OSTYPE" == "openbsd"* ]]; then
        OS="openbsd"
        PACKAGE_MANAGER="pkg_add"
        INSTALL_CMD="pkg_add"
        SODIUM_PKG="libsodium"
        LIBC="openbsd-libc"
    else
        echo "❌ Unsupported platform: $OSTYPE"
        exit 1
    fi
    
    echo "📋 Detected: $OS ($LIBC) with $PACKAGE_MANAGER"
}

# Go version verification
check_go_version() {
    local required_major=1
    local required_minor=24
    
    if ! command -v go >/dev/null; then
        echo "❌ Go is not installed. Please install Go 1.24+ first."
        exit 1
    fi
    
    local current_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local current_major=$(echo $current_version | cut -d. -f1)
    local current_minor=$(echo $current_version | cut -d. -f2)
    
    if [ "$current_major" -lt "$required_major" ] || 
       ([ "$current_major" -eq "$required_major" ] && [ "$current_minor" -lt "$required_minor" ]); then
        echo "❌ Go version $current_version is too old"
        echo "Required: Go ${required_major}.${required_minor}+ (from go.mod)"
        echo "Please update Go to version 1.24 or later"
        exit 1
    fi
    
    echo "✅ Go version $current_version meets requirements (>= ${required_major}.${required_minor})"
}

# Universal dependency installation
install_dependencies_universal() {
    echo "📦 Installing dependencies on $OS..."
    
    case $PACKAGE_MANAGER in
        apk)
            sudo $INSTALL_CMD libsodium-dev libsodium-static gcc musl-dev make pkgconfig cmake
            ;;
        apt)
            sudo $INSTALL_CMD libsodium-dev build-essential pkg-config cmake
            ;;
        dnf)
            sudo $INSTALL_CMD libsodium-devel gcc make pkgconfig cmake
            ;;
        pkg)
            sudo $INSTALL_CMD libsodium gcc gmake pkgconf cmake
            ;;
        pkg_add)
            sudo $INSTALL_CMD libsodium gcc gmake pkgconf cmake
            ;;
    esac
    
    echo "✅ Dependencies installed for $OS"
}

# Build static libraries in vendor directories
build_static_libraries() {
    echo "🔨 Building static libraries in vendor/ directories..."
    
    # Set universal optimization flags
    export CFLAGS="-O2 -fPIC"
    export LDFLAGS="-static"
    
    # Platform-specific optimizations (not preferences)
    case $LIBC in
        musl)
            # musl allows additional size optimizations
            CFLAGS="$CFLAGS -Os -fomit-frame-pointer"
            ;;
        glibc|freebsd-libc|openbsd-libc)
            # Standard flags work well
            ;;
    esac
    
    # Vendor directories
    OPRF_DIR="vendor/stef/liboprf/src"
    OPAQUE_DIR="vendor/stef/libopaque/src"
    
    # Build liboprf static library
    echo "Building liboprf static library..."
    if [ ! -d "$OPRF_DIR" ]; then
        echo "❌ liboprf source directory not found: $OPRF_DIR"
        echo "Please ensure git submodules are initialized: git submodule update --init --recursive"
        exit 1
    fi
    
    cd "$OPRF_DIR"
    make clean || true
    make CFLAGS="$CFLAGS $(pkg-config --cflags libsodium)" AR=ar ARFLAGS=rcs liboprf.a
    
    # Build libopaque static library
    echo "Building libopaque static library..."
    cd "../../../libopaque/src"
    make clean || true
    make CFLAGS="$CFLAGS -I../../../liboprf/src $(pkg-config --cflags libsodium)" \
         AR=ar ARFLAGS=rcs libopaque.a
    
    # Return to project root
    cd - >/dev/null
    cd - >/dev/null
    
    echo "✅ Static libraries built successfully on $OS"
    
    # Verify libraries exist
    if [ -f "$OPRF_DIR/liboprf.a" ] && [ -f "$OPAQUE_DIR/libopaque.a" ]; then
        echo "📁 Static libraries:"
        ls -la "$OPRF_DIR/liboprf.a" "$OPAQUE_DIR/libopaque.a"
    else
        echo "❌ Static library build verification failed"
        exit 1
    fi
}

# Main execution
main() {
    check_go_version
    detect_system_and_packages
    
    # Check for libsodium availability
    if ! pkg-config --exists libsodium; then
        echo "⚠️  libsodium not found, attempting to install..."
        install_dependencies_universal
    else
        echo "✅ libsodium found: $(pkg-config --modversion libsodium)"
    fi
    
    build_static_libraries
    echo "🎉 Static library build completed successfully!"
}

# Run main function
main "$@"
```

**1.2 Updated CGO Configuration**

**File: `auth/opaque_cgo.go`** - Updated for vendor-based static linking:

```go
//go:build !mock
// +build !mock

package auth

/*
#cgo CFLAGS: -I../../vendor/stef/libopaque/src -I../../vendor/stef/liboprf/src
#cgo pkg-config: libsodium
#cgo LDFLAGS: -L../../vendor/stef/libopaque/src -L../../vendor/stef/liboprf/src
#cgo LDFLAGS: -lopaque -loprf -static
#include "opaque_wrapper.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// libopaqueRegisterUser is a Go wrapper for the one-step registration
func libopaqueRegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
	userRecord := make([]byte, OPAQUE_USER_RECORD_LEN)
	exportKey := make([]byte, OPAQUE_SHARED_SECRETBYTES)

	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	cServerPrivateKey := C.CBytes(serverPrivateKey)
	defer C.free(cServerPrivateKey)

	ret := C.arkfile_opaque_register_user(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(cServerPrivateKey),
		(*C.uint8_t)(unsafe.Pointer(&userRecord[0])),
		(*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
	)

	if ret != 0 {
		return nil, nil, fmt.Errorf("libopaque registration failed: error code %d", ret)
	}

	return userRecord, exportKey, nil
}

// libopaqueAuthenticateUser is a Go wrapper for the one-step authentication
func libopaqueAuthenticateUser(password []byte, userRecord []byte) ([]byte, error) {
	exportKey := make([]byte, OPAQUE_SHARED_SECRETBYTES)

	cPassword := C.CBytes(password)
	defer C.free(cPassword)

	ret := C.arkfile_opaque_authenticate_user(
		(*C.uint8_t)(cPassword),
		C.uint16_t(len(password)),
		(*C.uint8_t)(unsafe.Pointer(&userRecord[0])),
		(*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
	)

	if ret != 0 {
		return nil, fmt.Errorf("libopaque authentication failed: error code %d", ret)
	}

	return exportKey, nil
}
```

**1.3 Build System Integration**

**File: `scripts/setup/build.sh`** - Updated for static linking:

```bash
#!/bin/bash
set -e

# Configuration
APP_NAME="arkfile"
WASM_DIR="client"
BUILD_DIR="build"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_DIR="/opt/arkfile"

# Colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to check Go version requirements from go.mod
check_go_version() {
    local required_version=$(grep '^go [0-9]' go.mod | awk '{print $2}')
    
    if [ -z "$required_version" ]; then
        echo -e "${YELLOW}⚠️  Cannot determine Go version requirement from go.mod${NC}"
        return 0
    fi
    
    local current_version=$(/usr/local/go/bin/go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
    
    if [ -z "$current_version" ]; then
        echo -e "${RED}❌ Cannot determine Go version${NC}"
        exit 1
    fi
    
    # Convert versions to comparable format (remove dots and compare as integers)
    local current_num=$(echo $current_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    local required_num=$(echo $required_version | awk -F. '{printf "%d%02d%02d", $1, $2, $3}')
    
    if [ "$current_num" -lt "$required_num" ]; then
        echo -e "${RED}❌ Go version $current_version is too old${NC}"
        echo -e "${YELLOW}Required: Go $required_version or later (from go.mod)${NC}"
        echo -e "${YELLOW}Current:  Go $current_version${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Go version $current_version meets requirements (>= $required_version)${NC}"
}

# Build static libraries first
build_static_dependencies() {
    echo -e "${YELLOW}Building static dependencies...${NC}"
    
    if ! ./scripts/setup/build-libopaque.sh; then
        echo -e "${RED}❌ Failed to build static dependencies${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Static dependencies built successfully${NC}"
}

# Build Go binaries with static linking
build_go_binaries_static() {
    echo -e "${YELLOW}Building Go binaries with static linking...${NC}"
    
    # Set up static linking environment
    export CGO_ENABLED=1
    export CGO_CFLAGS="-I./vendor/stef/libopaque/src -I./vendor/stef/liboprf/src"
    export CGO_LDFLAGS="-L./vendor/stef/libopaque/src -L./vendor/stef/liboprf/src -lopaque -loprf"
    export CGO_LDFLAGS="$CGO_LDFLAGS $(pkg-config --libs --static libsodium)"
    
    echo "Building arkfile server..."
    /usr/local/go/bin/go build -a -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -extldflags '-static'" -o arkfile .
    
    echo "Building cryptocli..."
    /usr/local/go/bin/go build -a -ldflags '-extldflags "-static"' -o cryptocli ./cmd/cryptocli
    
    echo -e "${GREEN}✅ Go binaries built with static linking${NC}"
}

# Verify static binaries
verify_static_binaries() {
    echo -e "${YELLOW}Verifying static binaries...${NC}"
    
    for binary in arkfile cryptocli; do
        if [ -f "$binary" ]; then
            # Use appropriate verification for platform
            if [[ "$OSTYPE" == "freebsd"* ]] || [[ "$OSTYPE" == "openbsd"* ]]; then
                # BSD systems use different tools
                if file "$binary" | grep -q "statically linked"; then
                    echo -e "${GREEN}✅ $binary: Static binary verified${NC}"
                else
                    echo -e "${RED}❌ $binary: Dynamic linking detected${NC}"
                    exit 1
                fi
            else
                # Linux systems (includes Alpine, Debian, Alma, etc.)
                if ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
                    echo -e "${GREEN}✅ $binary: Static binary verified${NC}"
                else
                    echo -e "${RED}❌ $binary: Dynamic linking detected${NC}"
                    ldd "$binary" 2>&1 || true
                    exit 1
                fi
            fi
        else
            echo -e "${RED}❌ Binary not found: $binary${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}✅ All binaries verified as static${NC}"
}

# Deploy binaries to runtime location
deploy_binaries() {
    echo -e "${YELLOW}Deploying binaries to ${BASE_DIR}/bin...${NC}"
    
    # Create deployment directories
    sudo mkdir -p "${BASE_DIR}/bin"
    
    # Copy static binaries
    sudo cp arkfile cryptocli "${BASE_DIR}/bin/"
    sudo chown -R arkfile:arkfile "${BASE_DIR}/bin/"
    sudo chmod 755 "${BASE_DIR}/bin/"*
    
    echo -e "${GREEN}✅ Binaries deployed to ${BASE_DIR}/bin${NC}"
}

# Main build process
main() {
    echo -e "${GREEN}Building ${APP_NAME} version ${VERSION} with static linking${NC}"
    
    # Preliminary checks
    command -v /usr/local/go/bin/go >/dev/null 2>&1 || { echo -e "${RED}Go is required but not installed.${NC}" >&2; exit 1; }
    check_go_version
    
    # Build static dependencies
    build_static_dependencies
    
    # Build TypeScript frontend (existing process)
    # ... (keep existing TypeScript build process)
    
    # Build WebAssembly (existing process)  
    # ... (keep existing WASM build process)
    
    # Build Go binaries with static linking
    build_go_binaries_static
    
    # Verify static linking
    verify_static_binaries
    
    # Deploy to runtime location
    deploy_binaries
    
    # Create version file
    echo "Creating version file..."
    cat > "${BASE_DIR}/version.json" <<EOF
{
   "version": "${VERSION}",
   "buildTime": "${BUILD_TIME}",
   "staticLinking": true
}
EOF
    
    echo -e "${GREEN}✅ Static linking build completed successfully!${NC}"
    echo "Binaries: ${BASE_DIR}/bin/"
    echo "Version: ${VERSION}"
}

# Execute main function
main "$@"
```

#### Validation Steps ✅ COMPLETED
1. ✅ `sudo ./scripts/dev-reset.sh` - Completes successfully without errors
2. ✅ Binary verification: `ldd ./arkfile` shows "not a dynamic executable" 
3. ✅ `./scripts/testing/test-app-curl.sh` - All authentication tests pass
4. ✅ Admin authentication verified via HTTPS interface (https://localhost:4443)

### Phase 2: Mock System Removal (Week 2)

#### Goal
Eliminate all mock infrastructure and ensure all tests run against production cryptographic code.

#### Technical Changes

**2.1 Remove Mock Files**

Delete these files entirely:
- `auth/opaque_mock.go`
- `auth/opaque_mock_server.go` 
- `auth/opaque_password_manager_mock.go`
- `auth/opaque_password_manager_factory_mock.go`
- `auth/mock_only_test.go`

**2.2 Simplify Authentication Interface**

Update `auth/opaque_interface.go` for static linking only:

```go
package auth

// OPAQUEProvider defines the interface for OPAQUE authentication operations.
// Static linking eliminates the need for mock implementations.
type OPAQUEProvider interface {
	RegisterUser(password []byte, serverPrivateKey []byte) ([]byte, []byte, error)
	AuthenticateUser(password []byte, userRecord []byte) ([]byte, error)
	IsAvailable() bool
	GetServerKeys() ([]byte, []byte, error)
	GenerateServerKeys() ([]byte, []byte, error)
}

// Global provider instance - always uses real implementation with static linking
var provider OPAQUEProvider

// GetOPAQUEProvider returns the static OPAQUE provider.
func GetOPAQUEProvider() OPAQUEProvider {
	if provider == nil {
		provider = NewRealOPAQUEProvider()
	}
	return provider
}
```

**2.3 Update Build Processes**

Update all references:
- Remove LD_LIBRARY_PATH management from scripts
- Update import statements throughout codebase
- Modify test configurations to use static binaries only
- Update `scripts/dev-reset.sh` for static binary workflow

#### Validation Steps
1. Ensure no mock-related files remain in codebase
2. Run `sudo ./scripts/dev-reset.sh` 
3. Verify all tests pass with production crypto: `./scripts/testing/test-app-curl.sh`
4. Confirm no build or runtime errors related to missing mock implementations

### Phase 3: Integration Validation (Week 3)

#### Goal  
Comprehensive validation that static linking implementation maintains all existing functionality and fix any issues discovered.

#### Validation Activities

**3.1 Comprehensive Testing**

- Run full test suite multiple times to ensure consistency
- Test complete user workflows (registration, login, file operations, sharing)
- Verify performance characteristics remain acceptable
- Test across different development environments if available

**3.2 Error Investigation and Fixes**

- Document any behavioral changes discovered
- Fix any broken functionality found during testing
- Ensure error messages and logging remain informative
- Validate security characteristics remain intact

**3.3 Documentation Updates**

- Update any developer documentation affected by static linking changes
- Document new build process requirements
- Update troubleshooting guides for static binary issues

#### Validation Steps
1. Run `sudo ./scripts/dev-reset.sh` - must complete without errors
2. Run `./scripts/testing/test-app-curl.sh` - must pass consistently (try 3-5 runs)
3. Manual testing of key workflows via web interface
4. Performance comparison with previous dynamic linking version (if possible)

## Cross-Platform Support

### Supported Platforms
- **Debian 12/13** (apt, glibc, libsodium-dev)
- **Alma Linux 9/10** (dnf, glibc, libsodium-devel)  
- **Alpine Linux 3.18+** (apk, musl, libsodium-dev + libsodium-static)
- **Ubuntu LTS** (apt, glibc, libsodium-dev)
- **FreeBSD 13+** (pkg, BSD libc, libsodium)
- **OpenBSD 7+** (pkg_add, BSD libc, libsodium)

### Platform-Specific Considerations

**Alpine Linux (musl)**:
- Requires both libsodium-dev and libsodium-static packages
- May need additional size optimizations (-Os -fomit-frame-pointer)

**BSD Systems**:
- Use `file` command instead of `ldd` for static verification
- May require `gmake` instead of `make`
- Package manager differences (pkg vs pkg_add)

## Troubleshooting

### Static Linking Issues

**Linker Errors**:
- Ensure all static libraries built successfully in vendor/ directories
- Verify pkg-config finds libsodium correctly
- Check CGO environment variables are set properly

**Runtime Errors**:
- Verify static binaries with appropriate platform tools
- Ensure no remaining dynamic library references
- Check file permissions and ownership after deployment

**Build Failures**:
- Verify Go version meets go.mod requirements
- Ensure all dependencies installed via package manager
- Check vendor/ directory structure and library files

### Mock Removal Issues

**Test Failures**:
- Verify all mock imports removed from test files
- Ensure OPAQUE provider initialization works correctly  
- Check for remaining mock-specific test configurations

**Interface Changes**:
- Update any code that relied on mock-specific behavior
- Ensure production OPAQUE implementation handles all test cases
- Verify error handling works with real cryptographic operations

## Success Metrics

### Technical Success
- All binaries are statically linked (verified via ldd/file commands)
- Zero mock-related code remains in codebase
- All existing tests pass consistently
- dev-reset + test-app-curl.sh workflow operates without errors

### Operational Success  
- Simplified deployment (no library dependencies)
- Consistent development environment setup
- Increased confidence in test results (no mock discrepancies)
- Identical cryptographic behavior across all environments

## Future Enhancements

Advanced tooling and client utilities planned for future phases are documented in `go-utils-project.md`, including:

- arkfile-client command-line tool
- arkfile-setup administrative installation tool
- arkfile-admin maintenance and monitoring tool
- Enhanced Go-based integration testing framework
- Cross-tool integration patterns

These enhancements will build upon the static linking foundation established in this phase.

## Timeline Summary

**Week 1**: Static build system implementation and validation
**Week 2**: Mock system removal and validation  
**Week 3**: Comprehensive integration validation and fixes

**Total Duration**: 3 weeks for foundation phase
**Extended Features**: See go-utils-project.md for phases 4+
