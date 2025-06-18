#!/bin/bash

# WASM Build and Test Script for Arkfile Client
# This script builds the WASM module and runs tests in Node.js

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Building and Testing Arkfile WASM Module${NC}"
echo

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed or not in PATH${NC}"
    echo "Please install Node.js (version 18+ recommended) to run WASM tests"
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo -e "${YELLOW}⚠️  Warning: Node.js version $NODE_VERSION detected. Version 16+ recommended for better WASM support.${NC}"
fi

# Navigate to client directory
cd client

echo -e "${BLUE}📦 Building WASM module...${NC}"
GOOS=js GOARCH=wasm go build -o static/main.wasm .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ WASM build successful${NC}"
else
    echo -e "${RED}❌ WASM build failed${NC}"
    exit 1
fi

echo
echo -e "${BLUE}🧪 Running WASM tests...${NC}"
echo

# Run the Node.js test runner
node test-runner.js

# Capture exit code
TEST_EXIT_CODE=$?

echo
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}🎉 All WASM tests passed!${NC}"
else
    echo -e "${RED}❌ Some WASM tests failed${NC}"
fi

exit $TEST_EXIT_CODE
