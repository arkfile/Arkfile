#!/bin/bash

# WASM Build and Test Script for Arkfile Client
# This script builds the WASM module and runs tests in Bun

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Building and Testing Arkfile WASM Module${NC}"
echo

# Check if Bun is available
if ! command -v bun &> /dev/null; then
    echo -e "${RED}[X] Bun is not installed or not in PATH${NC}"
    echo "Please install Bun from https://bun.sh to run WASM tests"
    exit 1
fi

BUN_VERSION=$(bun --version)
echo -e "${GREEN}[OK] Bun ${BUN_VERSION} detected for WASM testing${NC}"

# Navigate to client directory
cd client

echo -e "${BLUE}Building WASM module...${NC}"
GOOS=js GOARCH=wasm go build -o static/main.wasm .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[OK] WASM build successful${NC}"
else
    echo -e "${RED}[X] WASM build failed${NC}"
    exit 1
fi

echo
echo -e "${BLUE}🧪 Running WASM tests...${NC}"
echo

# Navigate to TypeScript test directory and run with Bun
cd static/js

# Run Bun test suite
bun test

# Capture exit code
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo
    echo -e "${BLUE}[SECURE] Running WASM integration tests...${NC}"
    echo
    
    # Run WASM integration tests
    bun test tests/wasm/
    
    # Capture WASM test exit code
    WASM_TEST_EXIT_CODE=$?
    
    if [ $WASM_TEST_EXIT_CODE -eq 0 ]; then
        echo
        echo -e "${BLUE}[SECURE] Running integration test suite...${NC}"
        echo
        
        # Run integration tests
        bun test tests/integration/
        
        # Capture integration test exit code
        INTEGRATION_TEST_EXIT_CODE=$?
        
        if [ $INTEGRATION_TEST_EXIT_CODE -eq 0 ]; then
            echo
            echo -e "${GREEN}All WASM tests passed including OPAQUE crypto!${NC}"
            exit 0
        else
            echo -e "${RED}[X] Some integration tests failed${NC}"
            exit $INTEGRATION_TEST_EXIT_CODE
        fi
    else
        echo -e "${RED}[X] Some WASM tests failed${NC}"
        exit $WASM_TEST_EXIT_CODE
    fi
else
    echo
    echo -e "${RED}[X] Some tests failed${NC}"
    exit $TEST_EXIT_CODE
fi
