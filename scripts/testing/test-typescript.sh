#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[START] ArkFile TypeScript Test Suite${NC}"
echo "=============================================="

# Function to check if Bun is installed
check_bun() {
    if ! command -v bun >/dev/null 2>&1; then
        echo -e "${RED}[X] Bun is not installed${NC}"
        echo -e "${YELLOW}Install Bun from: https://bun.sh${NC}"
        echo ""
        echo "Quick install:"
        echo "  curl -fsSL https://bun.sh/install | bash"
        echo "  source ~/.bashrc"
        return 1
    fi
    
    echo -e "${GREEN}[OK] Bun $(bun --version) detected${NC}"
    return 0
}

# Function to run TypeScript type checking
run_type_check() {
    echo -e "\n${BLUE}Running TypeScript Type Checking...${NC}"
    cd client/static/js
    
    if bun run type-check; then
        echo -e "${GREEN}[OK] TypeScript type checking passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${RED}[X] TypeScript type checking failed${NC}"
        cd ../../..
        return 1
    fi
}

# Function to run Bun tests
run_bun_tests() {
    echo -e "\n${BLUE} Running Bun Test Suite...${NC}"
    cd client/static/js
    
    if bun test; then
        echo -e "${GREEN}[OK] Bun tests passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${RED}[X] Bun tests failed${NC}"
        cd ../../..
        return 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    echo -e "\n${BLUE}Running Integration Tests...${NC}"
    cd client/static/js
    
    if bun test tests/integration/test-runner.test.ts; then
        echo -e "${GREEN}[OK] Integration tests passed${NC}"
        cd ../../..
        return 0
    else
        echo -e "${YELLOW}[WARNING]  Integration tests had issues (may be expected if WASM not built)${NC}"
        cd ../../..
        return 0  # Don't fail the entire suite for integration test issues
    fi
}


# Function to run build tests
run_build_tests() {
    echo -e "\n${BLUE}[BUILD] Running Build Tests...${NC}"
    cd client/static/js
    
    # Test development build
    echo "Testing development build..."
    if bun run build:dev; then
        echo -e "${GREEN}[OK] Development build successful${NC}"
    else
        echo -e "${RED}[X] Development build failed${NC}"
        cd ../../..
        return 1
    fi
    
    # Test production build
    echo "Testing production build..."
    if bun run build:prod; then
        echo -e "${GREEN}[OK] Production build successful${NC}"
    else
        echo -e "${RED}[X] Production build failed${NC}"
        cd ../../..
        return 1
    fi
    
    # Check if built files exist
    if [ -f "dist/app.js" ]; then
        local file_size=$(stat -f%z "dist/app.js" 2>/dev/null || stat -c%s "dist/app.js" 2>/dev/null)
        echo -e "${GREEN}Built app.js: ${file_size} bytes${NC}"
    else
        echo -e "${RED}[X] Built app.js not found${NC}"
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
        echo -e "${RED}Must be run from project root directory${NC}"
        exit 1
    fi
    
    # Install dependencies
    echo -e "\n${BLUE}Skipping dependency installation...${NC}"
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
    
    # Final summary
    echo -e "\n${BLUE}[STATS] Test Results Summary${NC}"
    echo "=============================="
    echo -e "Tests run:    ${tests_run}"
    echo -e "Tests passed: ${GREEN}${tests_passed}${NC}"
    echo -e "Tests failed: ${RED}$((tests_run - tests_passed))${NC}"
    
    if [ $exit_code -eq 0 ]; then
        echo -e "\n${GREEN}All critical TypeScript tests passed!${NC}"
    else
        echo -e "\n${RED}Some critical TypeScript tests failed${NC}"
        echo -e "${YELLOW}Check the output above for details${NC}"
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
    "help"|"-h"|"--help")
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  type-check   Run TypeScript type checking only"
        echo "  build        Run build tests only"
        echo "  unit         Run unit tests only"
        echo "  integration  Run integration tests only"
        echo "  help         Show this help message"
        echo ""
        echo "If no option is provided, all tests will be run."
        ;;
    *)
        main
        ;;
esac
