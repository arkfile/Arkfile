#!/bin/bash

# Arkfile Phase 6E: Password Validation Test Script
# Purpose: Verify entropy checking in share access flow
# Security Goal: Ensure weak passwords are rejected with proper entropy requirements

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MIN_ENTROPY=60  # 60+ bit entropy requirement
MIN_LENGTH=18   # 18+ character minimum

echo -e "${BLUE}=== Arkfile Phase 6E: Password Validation Test ===${NC}"
echo "Testing password entropy validation and pattern detection"
echo "Minimum entropy: ${MIN_ENTROPY} bits"
echo "Minimum length: ${MIN_LENGTH} characters"
echo ""

# Test password sets
declare -a WEAK_PASSWORDS=(
    "password123"
    "123456789012345678"  # Long but no entropy
    "Password1Password1"   # Repeated patterns
    "qwertyuiopasdfghjk"   # Keyboard patterns
    "abcdefghijklmnopqr"   # Sequential characters
    "Password123456789"    # Common + numbers
    "AdminPassword2024"    # Predictable patterns
    "MyPassword2025!!!"    # Weak despite symbols
    "companypassword01"    # Dictionary + numbers
)

declare -a STRONG_PASSWORDS=(
    "MyVacation2025PhotosForFamily!"           # 30 chars, varied - high entropy despite dictionary words
    "Tr0ub4dor&3RainbowCorrectHorse"          # 30 chars, mixed case/symbols - high entropy despite dictionary words
    "X9k#mQ2$vL8&nR5@wP3*zT6!bN4"           # 28 chars, random-like
    "Z8j&hM5$qK9@xV2#yS7*fR4!pL1"           # 28 chars, random-like
    "B3g*tW8$eQ6@rN9#uI5&oL2!mK7"           # 28 chars, random-like
    "D7f&kH4$jM1@xQ8#zV6*cR3!wN9"           # 28 chars, random-like
    "G5s*nL9$rP2@vK8#bM4&tW7!qH1"           # 28 chars, random-like
    "J4h&xQ7$mT3@wR9#fL6*pN2!bK8"           # 28 chars, random-like
    "M2k*vH8$qL5@zN3#rP9&tW4!xM7"           # 28 chars, random-like
    "Q9r&bK4$wH7@pL2#vN8*mQ5!tX3"           # 28 chars, random-like
)

# Function to test Go password validation
test_go_password_validation() {
    echo -e "${YELLOW}=== Testing Go Password Validation Functions ===${NC}"
    echo "Running crypto package password validation tests..."
    echo ""
    
    # Run the existing Go tests
    echo "Executing: go test -tags=mock ./crypto -run TestPasswordValidation -v"
    if go test -tags=mock ./crypto -run TestPasswordValidation -v; then
        echo -e "${GREEN}✅ PASS: Go password validation tests passed${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL: Go password validation tests failed${NC}"
        return 1
    fi
}

# Function to calculate basic entropy (simplified)
calculate_basic_entropy() {
    local password="$1"
    local length=${#password}
    
    # Estimate character set size
    local charset_size=0
    
    if [[ "$password" =~ [a-z] ]]; then
        charset_size=$((charset_size + 26))
    fi
    
    if [[ "$password" =~ [A-Z] ]]; then
        charset_size=$((charset_size + 26))
    fi
    
    if [[ "$password" =~ [0-9] ]]; then
        charset_size=$((charset_size + 10))
    fi
    
    if [[ "$password" =~ [^a-zA-Z0-9] ]]; then
        charset_size=$((charset_size + 32))  # Approximate special chars
    fi
    
    # Basic entropy calculation: log2(charset^length)
    # Using bc for floating point calculation
    if command -v bc > /dev/null 2>&1; then
        echo "scale=2; l($charset_size^$length)/l(2)" | bc -l 2>/dev/null || echo "0"
    else
        # Fallback without bc - rough approximation
        echo $((length * 6))  # Very rough estimate
    fi
}

# Function to detect common patterns
detect_patterns() {
    local password="$1"
    local patterns_found=""
    
    # Check for repeated characters (3 or more)
    if [[ "$password" =~ (.)\1{2,} ]]; then
        patterns_found="${patterns_found}repeated_chars "
    fi
    
    # Check for keyboard patterns
    local keyboard_patterns="qwerty asdfgh zxcvbn 123456 098765"
    for pattern in $keyboard_patterns; do
        if [[ "${password,,}" == *"$pattern"* ]]; then
            patterns_found="${patterns_found}keyboard_pattern "
            break
        fi
    done
    
    # Check for sequential characters
    if [[ "$password" =~ abcd|bcde|cdef|defg|1234|2345|3456|4567|5678|6789 ]]; then
        patterns_found="${patterns_found}sequential "
    fi
    
    # Check for common dictionary words
    local common_words="password admin user login test company secret"
    for word in $common_words; do
        if [[ "${password,,}" == *"$word"* ]]; then
            patterns_found="${patterns_found}dictionary_word "
            break
        fi
    done
    
    echo "$patterns_found"
}

# Function to test password strength using actual Go validation
test_password_strength() {
    local password="$1"
    local expected_result="$2"  # "weak" or "strong"
    local test_name="$3"
    
    echo -e "${BLUE}Testing: $test_name${NC}"
    echo "  Password: '$password'"
    echo "  Length: ${#password} characters"
    echo "  Expected: $expected_result"
    
    # Call the actual Go password validation function
    local json_result
    json_result=$(export LD_LIBRARY_PATH=$(pwd)/vendor/stef/libopaque/src:$(pwd)/vendor/stef/liboprf/src:$(pwd)/vendor/stef/liboprf/src/noise_xk && go run test/test_password_validation.go "$password" 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$json_result" ]; then
        echo -e "  ${RED}❌ FAIL: Could not run Go password validation${NC}"
        return 1
    fi
    
    # Parse JSON result using jq if available, otherwise use basic parsing
    local entropy meets_requirement patterns
    if command -v jq > /dev/null 2>&1; then
        entropy=$(echo "$json_result" | jq -r '.entropy')
        meets_requirement=$(echo "$json_result" | jq -r '.meets_requirement')
        patterns=$(echo "$json_result" | jq -r '.pattern_penalties | join(", ")')
    else
        # Basic JSON parsing without jq
        entropy=$(echo "$json_result" | grep -o '"entropy":[0-9.]*' | cut -d: -f2)
        meets_requirement=$(echo "$json_result" | grep -o '"meets_requirement":[a-z]*' | cut -d: -f2)
        patterns=$(echo "$json_result" | grep -o '"pattern_penalties":\[[^]]*\]' | cut -d: -f2- | tr -d '[]"' | tr ',' ' ')
    fi
    
    echo "  Calculated entropy: ${entropy} bits"
    if [ -n "$patterns" ] && [ "$patterns" != "null" ] && [ "$patterns" != "" ]; then
        echo "  Patterns detected: $patterns"
    else
        echo "  Patterns detected: none"
    fi
    
    # Determine validation result based on meets_requirement
    local validation_result
    if [ "$meets_requirement" = "true" ]; then
        validation_result="strong"
    else
        validation_result="weak"
    fi
    
    echo "  Validation result: $validation_result"
    
    # Compare with expected
    if [ "$validation_result" = "$expected_result" ]; then
        echo -e "  ${GREEN}✅ PASS: Password correctly classified as $expected_result${NC}"
        return 0
    else
        echo -e "  ${RED}❌ FAIL: Expected $expected_result but got $validation_result${NC}"
        return 1
    fi
}

# Function to test frontend integration (placeholder)
test_frontend_integration() {
    echo -e "${YELLOW}=== Testing Frontend Integration ===${NC}"
    echo "Checking TypeScript entropy scoring integration..."
    echo ""
    
    # Check if TypeScript files exist
    local share_crypto_file="client/static/js/src/shares/share-crypto.ts"
    local share_creation_file="client/static/js/src/shares/share-creation.ts"
    
    if [ -f "$share_crypto_file" ] && [ -f "$share_creation_file" ]; then
        echo -e "${GREEN}✅ PASS: TypeScript share modules exist${NC}"
        
        # Check for password validation functions
        if grep -q "validatePassword\|entropy\|complexity" "$share_crypto_file" "$share_creation_file"; then
            echo -e "${GREEN}✅ PASS: Password validation functions found in TypeScript${NC}"
        else
            echo -e "${YELLOW}⚠️  WARNING: Password validation functions not found in TypeScript${NC}"
        fi
        
        # Check TypeScript compilation
        echo "Testing TypeScript compilation..."
        if [ -f "client/static/js/package.json" ]; then
            cd client/static/js
            if npm run build > /dev/null 2>&1; then
                echo -e "${GREEN}✅ PASS: TypeScript compilation successful${NC}"
                cd ../../../
                return 0
            else
                echo -e "${RED}❌ FAIL: TypeScript compilation failed${NC}"
                cd ../../../
                return 1
            fi
        else
            echo -e "${YELLOW}⚠️  WARNING: No package.json found for TypeScript compilation${NC}"
            return 0
        fi
    else
        echo -e "${RED}❌ FAIL: TypeScript share modules not found${NC}"
        return 1
    fi
}

# Main test execution
main() {
    local all_passed=true
    
    echo -e "${BLUE}=== Password Validation Test Suite ===${NC}"
    echo ""
    
    # Test 1: Go password validation functions
    if ! test_go_password_validation; then
        all_passed=false
    fi
    
    echo ""
    
    # Test 2: Weak password detection
    echo -e "${YELLOW}=== Testing Weak Password Detection ===${NC}"
    local weak_test_passed=true
    for i in "${!WEAK_PASSWORDS[@]}"; do
        if ! test_password_strength "${WEAK_PASSWORDS[$i]}" "weak" "Weak Password Test $((i+1))"; then
            weak_test_passed=false
            all_passed=false
        fi
        echo ""
    done
    
    if [ "$weak_test_passed" = true ]; then
        echo -e "${GREEN}✅ All weak password tests passed${NC}"
    else
        echo -e "${RED}❌ Some weak password tests failed${NC}"
    fi
    
    echo ""
    
    # Test 3: Strong password acceptance
    echo -e "${YELLOW}=== Testing Strong Password Acceptance ===${NC}"
    local strong_test_passed=true
    for i in "${!STRONG_PASSWORDS[@]}"; do
        if ! test_password_strength "${STRONG_PASSWORDS[$i]}" "strong" "Strong Password Test $((i+1))"; then
            strong_test_passed=false
            all_passed=false
        fi
        echo ""
    done
    
    if [ "$strong_test_passed" = true ]; then
        echo -e "${GREEN}✅ All strong password tests passed${NC}"
    else
        echo -e "${RED}❌ Some strong password tests failed${NC}"
    fi
    
    echo ""
    
    # Test 4: Frontend integration
    if ! test_frontend_integration; then
        all_passed=false
    fi
    
    echo ""
    
    # Summary
    echo -e "${BLUE}=== Password Validation Test Summary ===${NC}"
    if [ "$all_passed" = true ]; then
        echo -e "${GREEN}✅ ALL PASSWORD VALIDATION TESTS PASSED${NC}"
        echo ""
        echo "Security Validation:"
        echo "✅ Go password validation functions working correctly"
        echo "✅ Weak passwords properly rejected (< ${MIN_ENTROPY} bits entropy)"
        echo "✅ Strong passwords properly accepted (≥ ${MIN_ENTROPY} bits entropy)"
        echo "✅ Pattern detection working for common weak patterns"
        echo "✅ Frontend integration appears functional"
        echo ""
        echo -e "${GREEN}Password validation system is working correctly!${NC}"
        exit 0
    else
        echo -e "${RED}❌ ONE OR MORE PASSWORD VALIDATION TESTS FAILED${NC}"
        echo ""
        echo "Security Issues Detected:"
        echo "❌ Password validation may not be properly enforcing entropy requirements"
        echo "❌ Weak passwords may be accepted, allowing brute force attacks"
        echo "❌ Pattern detection may be insufficient"
        echo ""
        echo "Recommended Actions:"
        echo "1. Review password validation logic in crypto/password_validation.go"
        echo "2. Verify entropy calculation accuracy"
        echo "3. Enhance pattern detection for common weak passwords"
        echo "4. Test frontend password strength feedback"
        echo "5. Ensure client-side validation matches server-side validation"
        exit 1
    fi
}

# Check for required tools
if ! command -v bc > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  WARNING: 'bc' calculator not found. Entropy calculations will be approximate.${NC}"
    echo "Install bc for more accurate entropy calculations: sudo apt-get install bc"
    echo ""
fi

# Run the tests
main "$@"
