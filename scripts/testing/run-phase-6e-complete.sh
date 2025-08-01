#!/bin/bash

# Arkfile Phase 6E: Master Test Runner
# Purpose: Execute complete Phase 6E validation suite
# Security Goal: Comprehensive system integration and security validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_URL="http://localhost:8080"
LOG_DIR="/tmp/arkfile-phase6e-logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo -e "${CYAN}${BOLD}================================================================${NC}"
echo -e "${CYAN}${BOLD}              ARKFILE PHASE 6E VALIDATION SUITE${NC}"
echo -e "${CYAN}${BOLD}         System Integration & Security Validation${NC}"
echo -e "${CYAN}${BOLD}================================================================${NC}"
echo ""
echo "Test execution timestamp: $TIMESTAMP"
echo "Server URL: $SERVER_URL"
echo "Log directory: $LOG_DIR"
echo ""

# Function to setup logging
setup_logging() {
    mkdir -p "$LOG_DIR"
    echo "Created log directory: $LOG_DIR"
    echo ""
}

# Function to check server availability
check_server() {
    echo -e "${BLUE}=== Pre-flight Server Check ===${NC}"
    echo "Checking if Arkfile server is running..."
    
    if ! curl -s "$SERVER_URL" > /dev/null 2>&1; then
        echo -e "${RED}❌ ERROR: Arkfile server not available at $SERVER_URL${NC}"
        echo ""
        echo "Please start the Arkfile server before running Phase 6E tests:"
        echo "  cd /path/to/arkfile"
        echo "  go run main.go"
        echo ""
        echo "Ensure the following are properly configured:"
        echo "  • Database initialized with share system schema"
        echo "  • Rate limiting middleware enabled"
        echo "  • Timing protection middleware active"
        echo "  • OPAQUE authentication system functional"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Server is running and responding${NC}"
    echo ""
}

# Function to run individual test script
run_test_script() {
    local script_name="$1"
    local test_description="$2"
    local script_path="$SCRIPT_DIR/$script_name"
    local log_file="$LOG_DIR/${script_name%.sh}_${TIMESTAMP}.log"
    
    echo -e "${CYAN}${BOLD}=== $test_description ===${NC}"
    echo "Script: $script_name"
    echo "Log file: $log_file"
    echo ""
    
    if [ ! -f "$script_path" ]; then
        echo -e "${RED}❌ ERROR: Test script not found: $script_path${NC}"
        return 1
    fi
    
    if [ ! -x "$script_path" ]; then
        echo -e "${RED}❌ ERROR: Test script not executable: $script_path${NC}"
        echo "Run: chmod +x $script_path"
        return 1
    fi
    
    # Run the test script with logging
    local start_time=$(date +%s)
    
    if "$script_path" 2>&1 | tee "$log_file"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${GREEN}✅ TEST PASSED: $test_description${NC}"
        echo -e "${GREEN}   Duration: ${duration}s${NC}"
        echo -e "${GREEN}   Log saved: $log_file${NC}"
        echo ""
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${RED}❌ TEST FAILED: $test_description${NC}"
        echo -e "${RED}   Duration: ${duration}s${NC}"
        echo -e "${RED}   Log saved: $log_file${NC}"
        echo -e "${RED}   Check log file for detailed error information${NC}"
        echo ""
        return 1
    fi
}

# Function to run Go unit tests
run_go_tests() {
    echo -e "${CYAN}${BOLD}=== Go Unit Tests Validation ===${NC}"
    echo "Running existing Go unit tests to ensure no regressions..."
    echo ""
    
    local log_file="$LOG_DIR/go_unit_tests_${TIMESTAMP}.log"
    local start_time=$(date +%s)
    
    if go test -tags=mock ./... -v 2>&1 | tee "$log_file"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${GREEN}✅ ALL GO UNIT TESTS PASSED${NC}"
        echo -e "${GREEN}   Duration: ${duration}s${NC}"
        echo -e "${GREEN}   Log saved: $log_file${NC}"
        echo ""
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        echo ""
        echo -e "${RED}❌ GO UNIT TESTS FAILED${NC}"
        echo -e "${RED}   Duration: ${duration}s${NC}"
        echo -e "${RED}   Log saved: $log_file${NC}"
        echo ""
        return 1
    fi
}

# Function to generate test report
generate_test_report() {
    local overall_result="$1"
    local report_file="$LOG_DIR/phase6e_test_report_${TIMESTAMP}.txt"
    
    echo -e "${BLUE}=== Generating Test Report ===${NC}"
    
    cat > "$report_file" << EOF
================================================================
ARKFILE PHASE 6E VALIDATION REPORT
================================================================

Test Execution Details:
- Timestamp: $TIMESTAMP
- Server URL: $SERVER_URL
- Overall Result: $overall_result

Test Results Summary:
EOF
    
    # Analyze log files for results
    for log_file in "$LOG_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            local test_name=$(basename "$log_file" .log | sed "s/_${TIMESTAMP}//")
            
            if grep -q "✅.*PASSED" "$log_file"; then
                echo "  ✅ PASSED: $test_name" >> "$report_file"
            elif grep -q "❌.*FAILED" "$log_file"; then
                echo "  ❌ FAILED: $test_name" >> "$report_file"
            else
                echo "  ⚠️  UNCLEAR: $test_name" >> "$report_file"
            fi
        fi
    done
    
    cat >> "$report_file" << EOF

Security Validation Checklist:
- [ ] Timing Protection: 1-second minimum response times
- [ ] Rate Limiting: Exponential backoff working
- [ ] Password Entropy: Weak passwords rejected
- [ ] Share ID Security: Cryptographically secure generation
- [ ] End-to-End Workflow: Complete share lifecycle
- [ ] Attack Resistance: Security measures effective
- [ ] Database Security: No plaintext secrets
- [ ] Performance: System stable under load

Next Steps:
1. Review failed tests (if any) in detail
2. Address any security vulnerabilities discovered
3. Re-run tests after fixes are implemented
4. Consider production deployment readiness

================================================================
EOF
    
    echo "Test report generated: $report_file"
    echo ""
    
    # Display report summary
    echo -e "${YELLOW}=== Test Report Summary ===${NC}"
    grep -E "(✅|❌|⚠️)" "$report_file" || echo "No test results found"
    echo ""
}

# Main test execution
main() {
    local overall_passed=true
    local failed_tests=()
    
    setup_logging
    check_server
    
    echo -e "${CYAN}${BOLD}=== PHASE 6E TEST EXECUTION PLAN ===${NC}"
    echo "The following tests will be executed in sequence:"
    echo "  1. Go Unit Tests (regression check)"
    echo "  2. Timing Protection Validation"
    echo "  3. Rate Limiting Validation"
    echo "  4. Password Validation Testing"
    echo "  5. Complete Share Workflow Testing"
    echo ""
    echo "Each test will be logged separately for detailed analysis."
    echo ""
    
    read -p "Press Enter to begin Phase 6E validation suite..."
    echo ""
    
    # Test 1: Go Unit Tests
    if ! run_go_tests; then
        overall_passed=false
        failed_tests+=("Go Unit Tests")
    fi
    
    # Test 2: Timing Protection
    if ! run_test_script "test-timing-protection.sh" "Timing Protection Validation"; then
        overall_passed=false
        failed_tests+=("Timing Protection")
    fi
    
    # Test 3: Rate Limiting
    if ! run_test_script "test-rate-limiting.sh" "Rate Limiting Validation"; then
        overall_passed=false
        failed_tests+=("Rate Limiting")
    fi
    
    # Test 4: Password Validation
    if ! run_test_script "test-password-validation.sh" "Password Validation Testing"; then
        overall_passed=false
        failed_tests+=("Password Validation")
    fi
    
    # Test 5: Complete Share Workflow
    if ! run_test_script "test-share-workflow-complete.sh" "Complete Share Workflow Testing"; then
        overall_passed=false
        failed_tests+=("Share Workflow")
    fi
    
    # Generate final results
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD}                    PHASE 6E FINAL RESULTS${NC}"
    echo -e "${CYAN}${BOLD}================================================================${NC}"
    echo ""
    
    if [ "$overall_passed" = true ]; then
        echo -e "${GREEN}${BOLD}🎉 ALL PHASE 6E TESTS PASSED! 🎉${NC}"
        echo ""
        echo -e "${GREEN}Security Validation Complete:${NC}"
        echo -e "${GREEN}✅ Timing protection working correctly${NC}"
        echo -e "${GREEN}✅ Rate limiting system functional${NC}"
        echo -e "${GREEN}✅ Password validation enforcing security${NC}"
        echo -e "${GREEN}✅ Share workflow end-to-end operational${NC}"
        echo -e "${GREEN}✅ All security measures validated${NC}"
        echo ""
        echo -e "${GREEN}${BOLD}ARKFILE SHARE SYSTEM IS READY FOR PRODUCTION CONSIDERATION${NC}"
        
        generate_test_report "PASSED"
        exit 0
    else
        echo -e "${RED}${BOLD}❌ PHASE 6E VALIDATION FAILED ❌${NC}"
        echo ""
        echo -e "${RED}Failed Tests (${#failed_tests[@]}):${NC}"
        for test in "${failed_tests[@]}"; do
            echo -e "${RED}  • $test${NC}"
        done
        echo ""
        echo -e "${YELLOW}Required Actions:${NC}"
        echo "1. Review detailed logs in: $LOG_DIR"
        echo "2. Fix identified issues"
        echo "3. Re-run failed tests individually"
        echo "4. Execute complete Phase 6E suite again"
        echo ""
        echo -e "${RED}${BOLD}SYSTEM NOT READY FOR PRODUCTION${NC}"
        
        generate_test_report "FAILED"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "Phase 6E test execution completed."
    echo "All logs preserved in: $LOG_DIR"
}

# Set trap for cleanup
trap cleanup EXIT

# Run the complete test suite
main "$@"
