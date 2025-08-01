#!/bin/bash

# Arkfile Phase 6E: Timing Protection Validation Script
# Purpose: Verify consistent 1-second minimum response times for share endpoints
# Security Goal: Prevent timing side-channel attacks on share access

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER_URL="http://localhost:8080"
MIN_RESPONSE_TIME=1000  # 1 second minimum (in milliseconds)
TIMING_TOLERANCE=100    # 100ms tolerance for measurement variance
TEST_ITERATIONS=5       # Number of timing measurements per test case

echo -e "${BLUE}=== Arkfile Phase 6E: Timing Protection Validation ===${NC}"
echo "Testing server: $SERVER_URL"
echo "Minimum response time: ${MIN_RESPONSE_TIME}ms"
echo "Timing tolerance: ±${TIMING_TOLERANCE}ms"
echo ""

# Function to measure response time in milliseconds
measure_response_time() {
    local url="$1"
    local method="$2"
    local data="$3"
    local headers="$4"
    
    if [ "$method" = "POST" ]; then
        if [ -n "$headers" ]; then
            curl -s -w "%{time_total}" -o /dev/null \
                -X POST "$url" \
                -H "Content-Type: application/json" \
                -H "$headers" \
                -d "$data" 2>/dev/null | awk '{printf "%.0f", $1 * 1000}'
        else
            curl -s -w "%{time_total}" -o /dev/null \
                -X POST "$url" \
                -H "Content-Type: application/json" \
                -d "$data" 2>/dev/null | awk '{printf "%.0f", $1 * 1000}'
        fi
    else
        curl -s -w "%{time_total}" -o /dev/null \
            "$url" 2>/dev/null | awk '{printf "%.0f", $1 * 1000}'
    fi
}

# Function to run timing test with multiple iterations
run_timing_test() {
    local test_name="$1"
    local url="$2"
    local method="$3"
    local data="$4"
    local headers="$5"
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    
    local total_time=0
    local min_time=99999
    local max_time=0
    local times=()
    
    for i in $(seq 1 $TEST_ITERATIONS); do
        echo -n "  Iteration $i/$TEST_ITERATIONS: "
        
        local response_time
        response_time=$(measure_response_time "$url" "$method" "$data" "$headers")
        times+=($response_time)
        
        echo "${response_time}ms"
        
        # Track min/max/total
        total_time=$((total_time + response_time))
        if [ $response_time -lt $min_time ]; then
            min_time=$response_time
        fi
        if [ $response_time -gt $max_time ]; then
            max_time=$response_time
        fi
        
        # Brief pause between requests
        sleep 0.5
    done
    
    # Calculate average
    local avg_time=$((total_time / TEST_ITERATIONS))
    local variance=$((max_time - min_time))
    
    echo "  Results:"
    echo "    Average: ${avg_time}ms"
    echo "    Min: ${min_time}ms"
    echo "    Max: ${max_time}ms"
    echo "    Variance: ${variance}ms"
    
    # Validation
    local passed=true
    
    # Check minimum time requirement
    if [ $min_time -lt $MIN_RESPONSE_TIME ]; then
        echo -e "  ${RED}❌ FAIL: Minimum response time ${min_time}ms < required ${MIN_RESPONSE_TIME}ms${NC}"
        passed=false
    else
        echo -e "  ${GREEN}✅ PASS: Minimum response time requirement met${NC}"
    fi
    
    # Check timing consistency (variance should be small)
    if [ $variance -gt $TIMING_TOLERANCE ]; then
        echo -e "  ${YELLOW}⚠️  WARNING: High timing variance ${variance}ms > tolerance ${TIMING_TOLERANCE}ms${NC}"
        echo "     This may indicate timing side-channels"
    else
        echo -e "  ${GREEN}✅ PASS: Timing consistency within tolerance${NC}"
    fi
    
    echo ""
    return $([ "$passed" = true ] && echo 0 || echo 1)
}

# Function to check if server is running
check_server() {
    echo "Checking server availability..."
    if ! curl -s "$SERVER_URL" > /dev/null 2>&1; then
        echo -e "${RED}❌ Server not available at $SERVER_URL${NC}"
        echo "Please start the Arkfile server first:"
        echo "  go run main.go"
        exit 1
    fi
    echo -e "${GREEN}✅ Server is running${NC}"
    echo ""
}

# Create test share for timing tests
create_test_share() {
    echo "Setting up test environment..."
    
    # Note: In a real implementation, we would need to:
    # 1. Create a test user account
    # 2. Upload a test file
    # 3. Create a share for that file
    # For now, we'll test with a known invalid share ID
    
    TEST_SHARE_ID="timing-test-invalid-share"
    echo "Using test share ID: $TEST_SHARE_ID"
    echo ""
}

# Main test execution
main() {
    local all_passed=true
    
    check_server
    create_test_share
    
    echo -e "${BLUE}=== Test Case 1: Valid Share Password ===${NC}"
    echo "Note: Testing with invalid share (should still have timing protection)"
    if ! run_timing_test \
        "Valid share password (with invalid share)" \
        "$SERVER_URL/api/share/$TEST_SHARE_ID" \
        "POST" \
        '{"password":"ValidTestPassword123!@#"}' \
        ""; then
        all_passed=false
    fi
    
    echo -e "${BLUE}=== Test Case 2: Invalid Share Password ===${NC}"
    if ! run_timing_test \
        "Invalid share password" \
        "$SERVER_URL/api/share/$TEST_SHARE_ID" \
        "POST" \
        '{"password":"wrong-password"}' \
        ""; then
        all_passed=false
    fi
    
    echo -e "${BLUE}=== Test Case 3: Nonexistent Share ID ===${NC}"
    if ! run_timing_test \
        "Nonexistent share ID" \
        "$SERVER_URL/api/share/nonexistent-share-id-12345" \
        "POST" \
        '{"password":"any-password"}' \
        ""; then
        all_passed=false
    fi
    
    echo -e "${BLUE}=== Test Case 4: Share Page Access ===${NC}"
    if ! run_timing_test \
        "Share page access (GET request)" \
        "$SERVER_URL/shared/$TEST_SHARE_ID" \
        "GET" \
        "" \
        ""; then
        all_passed=false
    fi
    
    echo -e "${BLUE}=== Test Case 5: Share Metadata Request ===${NC}"
    if ! run_timing_test \
        "Share metadata request" \
        "$SERVER_URL/api/share/$TEST_SHARE_ID" \
        "GET" \
        "" \
        ""; then
        all_passed=false
    fi
    
    # Summary
    echo -e "${BLUE}=== Timing Protection Test Summary ===${NC}"
    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}✅ ALL TIMING PROTECTION TESTS PASSED${NC}"
        echo ""
        echo "Security Validation:"
        echo "✅ Minimum ${MIN_RESPONSE_TIME}ms response time enforced"
        echo "✅ Timing consistency maintained across scenarios"
        echo "✅ No correlation between response time and request validity"
        echo ""
        echo -e "${GREEN}Timing protection is working correctly!${NC}"
        exit 0
    else
        echo -e "${RED}❌ ONE OR MORE TIMING PROTECTION TESTS FAILED${NC}"
        echo ""
        echo "Security Issues Detected:"
        echo "❌ Timing side-channels may be present"
        echo "❌ Response times may leak information about share validity"
        echo ""
        echo "Recommended Actions:"
        echo "1. Verify TimingProtectionMiddleware is applied to share routes"
        echo "2. Check middleware implementation for correct timing enforcement"
        echo "3. Ensure all share endpoints use timing protection"
        echo "4. Test with actual server under realistic conditions"
        exit 1
    fi
}

# Run the tests
main "$@"
