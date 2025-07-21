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

# Paths for libraries
OPAQUE_LIB="$(pwd)/vendor/stef/libopaque/src"
OPRF_LIB="$(pwd)/vendor/stef/liboprf/src"
NOISE_LIB="$(pwd)/vendor/stef/liboprf/src/noise_xk"

# Check if libraries exist
echo -e "${BLUE}🔍 Checking OPAQUE library dependencies...${NC}"
if [[ ! -f "$OPAQUE_LIB/libopaque.so" ]]; then
    echo -e "${RED}❌ libopaque.so not found${NC}"
    echo -e "${YELLOW}Run: ./scripts/setup/build-libopaque.sh${NC}"
    exit 1
fi

if [[ ! -f "$OPRF_LIB/liboprf.so" ]]; then
    echo -e "${RED}❌ liboprf.so not found${NC}" 
    echo -e "${YELLOW}Run: ./scripts/setup/build-libopaque.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All required libraries found${NC}"

# Export library path
export LD_LIBRARY_PATH="$OPAQUE_LIB:$OPRF_LIB:$NOISE_LIB"

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
