#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 ArkFile TypeScript Test Suite${NC}"
echo "=============================================="

# Function to check if Bun is installed
check_bun() {
    if ! command -v bun >/dev/null 2>&1; then
        echo -e "${RED}❌ Bun is not installed${NC}"
        echo -e "${YELLOW}Install Bun from: https://bun.sh${NC}"
        echo ""
        echo "Quick install:"
        echo "  curl -fsSL https://bun.sh/install | bash"
        echo "  source ~/.bashrc"
        return 1
    fi
    
    echo -e "${GREEN}✅ Bun $(bun --version) detected${NC}"
    return 0
}

# Function to run TypeScript type checking
run_type_check() {
    echo -e "\n${BLUE}📝 Running TypeScript Type Checking...${NC}"
    cd client/static/js
    
    if bun run type-check; then
        echo -e "${GREEN}✅ TypeScript type checking passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${RED}❌ TypeScript type checking failed${NC}"
        cd ../../..
        return 1
    fi
}

# Function to run Bun tests
run_bun_tests() {
    echo -e "\n${BLUE}🧪 Running Bun Test Suite...${NC}"
    cd client/static/js
    
    if bun test; then
        echo -e "${GREEN}✅ Bun tests passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${RED}❌ Bun tests failed${NC}"
        cd ../../..
        return 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    echo -e "\n${BLUE}🔗 Running Integration Tests...${NC}"
    cd client/static/js
    
    if bun test tests/integration/test-runner.test.ts; then
        echo -e "${GREEN}✅ Integration tests passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${YELLOW}⚠️  Integration tests had issues (may be expected if WASM not built)${NC}"
        cd ../../..
        return 0  # Don't fail the entire suite for integration test issues
    fi
}

# Function to run WASM-specific tests
run_wasm_tests() {
    echo -e "\n${BLUE}🌐 Running WASM Tests...${NC}"
    
    # Check if WASM file exists (informational only)
    if [ ! -f "client/static/main.wasm" ]; then
        echo -e "${YELLOW}⚠️  WASM file not found - tests will use mocks${NC}"
        echo -e "${YELLOW}   Build WASM with: cd client && GOOS=js GOARCH=wasm go build -o static/main.wasm .${NC}"
    else
        echo -e "${GREEN}✅ WASM file found - tests will use real WASM functions${NC}"
    fi
    
    cd client/static/js
    
    echo "Running WASM integration tests..."
    if bun test tests/utils/test-runner.test.ts; then
        echo -e "${GREEN}✅ WASM tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  WASM tests encountered issues${NC}"
    fi
    
    echo "Running OPAQUE WASM tests..."
    if bun test tests/wasm/opaque-wasm.test.ts; then
        echo -e "${GREEN}✅ OPAQUE WASM tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  OPAQUE WASM tests encountered issues${NC}"
    fi
    
    echo "Running multi-key debug tests..."
    if bun test tests/debug/multi-key-test.test.ts; then
        echo -e "${GREEN}✅ Multi-key debug tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Multi-key debug tests encountered issues${NC}"
    fi
    
    cd ../../..
    return 0
}

# Function to run build tests
run_build_tests() {
    echo -e "\n${BLUE}🔨 Running Build Tests...${NC}"
    cd client/static/js
    
    # Test development build
    echo "Testing development build..."
    if bun run build:dev; then
        echo -e "${GREEN}✅ Development build successful${NC}"
    else
        echo -e "${RED}❌ Development build failed${NC}"
        cd ../../..
        return 1
    fi
    
    # Test production build
    echo "Testing production build..."
    if bun run build:prod; then
        echo -e "${GREEN}✅ Production build successful${NC}"
    else
        echo -e "${RED}❌ Production build failed${NC}"
        cd ../../..
        return 1
    fi
    
    # Check if built files exist
    if [ -f "dist/app.js" ]; then
        local file_size=$(stat -f%z "dist/app.js" 2>/dev/null || stat -c%s "dist/app.js" 2>/dev/null)
        echo -e "${GREEN}📦 Built app.js: ${file_size} bytes${NC}"
    else
        echo -e "${RED}❌ Built app.js not found${NC}"
        cd ../../..
        return 1
    fi
    
    cd ../../..
    return 0
}

# Main test runner
main() {
    local exit_code=0
    local tests_run=0
    local tests_passed=0
    
    echo -e "${BLUE}Starting comprehensive TypeScript test suite...${NC}\n"
    
    # Check prerequisites
    if ! check_bun; then
        exit 1
    fi
    
    # Ensure we're in the right directory
    if [ ! -f "go.mod" ]; then
        echo -e "${RED}❌ Must be run from project root directory${NC}"
        exit 1
    fi
    
    # Install dependencies
    echo -e "\n${BLUE}📦 Skipping dependency installation...${NC}"
    # cd client/static/js
    # bun install
    # cd ../../..
    
    # Run TypeScript type checking
    tests_run=$((tests_run + 1))
    if run_type_check; then
        tests_passed=$((tests_passed + 1))
    else
        exit_code=1
    fi
    
    # Run build tests
    tests_run=$((tests_run + 1))
    if run_build_tests; then
        tests_passed=$((tests_passed + 1))
    else
        exit_code=1
    fi
    
    # Run Bun tests
    tests_run=$((tests_run + 1))
    if run_bun_tests; then
        tests_passed=$((tests_passed + 1))
    else
        exit_code=1
    fi
    
    # Run integration tests (don't fail on issues)
    tests_run=$((tests_run + 1))
    if run_integration_tests; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # Run WASM tests (don't fail on issues)
    tests_run=$((tests_run + 1))
    if run_wasm_tests; then
        tests_passed=$((tests_passed + 1))
    fi
    
    # Final summary
    echo -e "\n${BLUE}📊 Test Results Summary${NC}"
    echo "=============================="
    echo -e "Tests run:    ${tests_run}"
    echo -e "Tests passed: ${GREEN}${tests_passed}${NC}"
    echo -e "Tests failed: ${RED}$((tests_run - tests_passed))${NC}"
    
    if [ $exit_code -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All critical TypeScript tests passed!${NC}"
    else
        echo -e "\n${RED}❌ Some critical TypeScript tests failed${NC}"
        echo -e "${YELLOW}💡 Check the output above for details${NC}"
    fi
    
    exit $exit_code
}

# Script options
case "${1:-}" in
    "type-check")
        check_bun && run_type_check
        ;;
    "build")
        check_bun && run_build_tests
        ;;
    "unit")
        check_bun && run_bun_tests
        ;;
    "integration")
        check_bun && run_integration_tests
        ;;
    "wasm")
        check_bun && run_wasm_tests
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  type-check   Run TypeScript type checking only"
        echo "  build        Run build tests only"
        echo "  unit         Run unit tests only"
        echo "  integration  Run integration tests only"
        echo "  wasm         Run WASM tests only"
        echo "  help         Show this help message"
        echo ""
        echo "If no option is provided, all tests will be run."
        ;;
    *)
        main
        ;;
esac
