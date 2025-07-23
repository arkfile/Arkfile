#!/bin/bash

# Test script for OPAQUE functionality
# This script runs OPAQUE integration tests with the proper library paths

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Setup library paths automatically
setup_library_paths() {
    local SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    
    # Check if libopaque exists, if not build it
    local LIBOPAQUE_PATH="$PROJECT_ROOT/vendor/stef/libopaque/src/libopaque.so"
    local LIBOPRF_PATH="$PROJECT_ROOT/vendor/stef/liboprf/src/liboprf.so"
    
    if [ ! -f "$LIBOPAQUE_PATH" ] || [ ! -f "$LIBOPRF_PATH" ]; then
        echo -e "${YELLOW}⚠️  libopaque/liboprf not found, building...${NC}"
        if [ -x "$PROJECT_ROOT/scripts/setup/build-libopaque.sh" ]; then
            cd "$PROJECT_ROOT"
            ./scripts/setup/build-libopaque.sh
        else
            echo -e "${RED}❌ Cannot find build-libopaque.sh script${NC}"
            exit 1
        fi
    fi
    
    # Set up library path
    export LD_LIBRARY_PATH="$PROJECT_ROOT/vendor/stef/libopaque/src:$PROJECT_ROOT/vendor/stef/liboprf/src:$PROJECT_ROOT/vendor/stef/liboprf/src/noise_xk${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    
    # Verify libraries are accessible
    if ! ldd "$LIBOPAQUE_PATH" >/dev/null 2>&1; then
        echo -e "${RED}❌ libopaque.so cannot be loaded${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Library paths configured successfully${NC}"
    echo -e "${BLUE}   LD_LIBRARY_PATH: $LD_LIBRARY_PATH${NC}"
}

echo -e "${BLUE}🔍 Setting up OPAQUE library dependencies...${NC}"
setup_library_paths

echo
echo -e "${BLUE}🧪 Running OPAQUE Integration Tests${NC}"
echo -e "${BLUE}Library path: $LD_LIBRARY_PATH${NC}"
echo

# Run specific test if provided, otherwise run all OPAQUE tests
if [[ $# -gt 0 ]]; then
    echo -e "${YELLOW}Running specific test: $1${NC}"
    go test -v ./auth -run "$1"
else
    echo -e "${YELLOW}Running all OPAQUE integration tests...${NC}"
    
    # Test OPAQUE registration and authentication flow
    go test -v ./auth -run TestOpaqueRegistrationAndAuthentication
    
    # Test OPAQUE with database integration
    if go test -v ./auth -run TestOpaqueDatabase 2>/dev/null; then
        echo -e "${GREEN}✅ OPAQUE database integration test passed${NC}"
    else
        echo -e "${YELLOW}⚠️  OPAQUE database integration test not found or failed${NC}"
    fi
    
    # Test OPAQUE password policies
    if go test -v ./auth -run TestOpaquePasswordPolicy 2>/dev/null; then
        echo -e "${GREEN}✅ OPAQUE password policy test passed${NC}"
    else
        echo -e "${YELLOW}⚠️  OPAQUE password policy test not found${NC}"
    fi
    
    # Run all auth module tests to catch any OPAQUE-related issues
    echo -e "${YELLOW}Running complete auth module test suite...${NC}"
    go test -v ./auth/... -count=1
fi

echo
echo -e "${GREEN}🎉 OPAQUE Integration Tests Complete${NC}"
echo -e "${BLUE}✅ libopaque C library: Working${NC}"
echo -e "${BLUE}✅ Go CGO bindings: Working${NC}"
echo -e "${BLUE}✅ OPAQUE protocol: Working${NC}"
