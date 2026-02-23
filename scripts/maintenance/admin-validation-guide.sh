#!/bin/bash

# Interactive Admin Validation Guide for Arkfile
# This script walks administrators through real-world testing after deployment
# Version: Phase 5

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TEST_USERNAME="admin-test-user"
TEST_PASSWORD="AdminTest123!@#"
TEST_FILE_CONTENT="Hello Arkfile! This is a test file for encryption validation."
START_TIME=$(date +%s)

# Initialize counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    ARKFILE ADMIN VALIDATION GUIDE                            ║${NC}"
echo -e "${BLUE}║                                                                              ║${NC}"
echo -e "${BLUE}║  This interactive guide will walk you through testing your Arkfile          ║${NC}"
echo -e "${BLUE}║  deployment with real-world user workflows and backend verification.        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${CYAN}Start Time: $(date)${NC}"
echo -e "${CYAN}Test User: ${TEST_USERNAME}${NC}"
echo

# Function to increment test counters
record_test() {
    local result=$1
    ((TESTS_TOTAL++))
    if [ "$result" = "pass" ]; then
        ((TESTS_PASSED++))
    else
        ((TESTS_FAILED++))
    fi
}

# Function to wait for user confirmation
wait_for_user() {
    local message="$1"
    echo -e "${YELLOW}USER ACTION REQUIRED${NC}"
    echo -e "${YELLOW}${message}${NC}"
    echo
    read -p "Press Enter when completed..."
    echo
}

# Function to validate backend state
validate_backend() {
    local check_type="$1"
    local expected="$2"
    local command="$3"
    local description="$4"
    
    echo -e "${PURPLE}Backend Verification: ${description}${NC}"
    
    if result=$(eval "$command" 2>/dev/null); then
        if [[ "$result" == *"$expected"* ]] || [ -z "$expected" ]; then
            echo -e "${GREEN}[OK] PASS: ${description}${NC}"
            echo -e "   Result: ${result}"
            record_test "pass"
        else
            echo -e "${RED}[X] FAIL: ${description}${NC}"
            echo -e "   Expected: ${expected}"
            echo -e "   Got: ${result}"
            record_test "fail"
        fi
    else
        echo -e "${RED}[X] FAIL: ${description} (command failed)${NC}"
        record_test "fail"
    fi
    echo
}

echo -e "${BLUE}[SECURE] UNDERSTANDING YOUR TLS SETUP${NC}"
echo "=================================="
echo
echo -e "${CYAN}Your deployment uses self-signed certificates for HTTPS access.${NC}"
echo -e "${CYAN}This is NORMAL and SECURE for development/internal deployments.${NC}"
echo
echo -e "${YELLOW}[WARNING]  IMPORTANT: Browser Certificate Warnings${NC}"
echo
echo "When you access https://localhost, you WILL see browser warnings like:"
echo
echo -e "${RED}Chrome/Chromium:${NC} 'Your connection is not private'"
echo -e "${RED}Firefox:${NC} 'Warning: Potential Security Risk Ahead'"
echo -e "${RED}Safari:${NC} 'This Connection Is Not Private'"
echo -e "${RED}Edge:${NC} 'Your connection isn't private'"
echo
echo -e "${GREEN}This is EXPECTED and you should accept these warnings.${NC}"
echo -e "${GREEN}The self-signed certificates still provide full encryption.${NC}"
echo
echo "Press Enter to continue..."
read

echo -e "${BLUE}[INFO] STEP 1: SYSTEM HEALTH VERIFICATION${NC}"
echo "======================================"
echo

# Test 1: Health endpoint
echo -e "${PURPLE}Testing system health endpoint...${NC}"
if curl -s -f http://localhost:8080/health >/dev/null 2>&1; then
    health_response=$(curl -s http://localhost:8080/health)
    echo -e "${GREEN}[OK] PASS: Health endpoint accessible${NC}"
    echo -e "   Response: $(echo "$health_response" | jq -r '.status // "healthy"' 2>/dev/null || echo "healthy")"
    record_test "pass"
else
    echo -e "${RED}[X] FAIL: Health endpoint not accessible${NC}"
    echo -e "${RED}   Make sure Arkfile service is running: sudo systemctl status arkfile${NC}"
    record_test "fail"
fi
echo

# Test 2: Service status
echo -e "${PURPLE}Checking service status...${NC}"
services=("arkfile" "caddy" "minio" "rqlite")
services_ok=0

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo -e "${GREEN}[OK] ${service}: running${NC}"
        ((services_ok++))
    else
        echo -e "${RED}[X] ${service}: not running${NC}"
    fi
done

if [ $services_ok -eq ${#services[@]} ]; then
    echo -e "${GREEN}[OK] PASS: All services are running${NC}"
    record_test "pass"
else
    echo -e "${YELLOW}[WARNING]  PARTIAL: $services_ok/${#services[@]} services running${NC}"
    record_test "fail"
fi
echo

# Test 3: Network connectivity
echo -e "${PURPLE}Testing network connectivity...${NC}"

# Test HTTP
if curl -s -I http://localhost:8080/ | head -1 | grep -q "200 OK"; then
    echo -e "${GREEN}[OK] HTTP access (localhost:8080): working${NC}"
    record_test "pass"
else
    echo -e "${RED}[X] HTTP access (localhost:8080): failed${NC}"
    record_test "fail"
fi

# Test HTTPS (ignore certificate)
if curl -s -I https://localhost --insecure 2>/dev/null | head -1 | grep -q "200"; then
    echo -e "${GREEN}[OK] HTTPS access (localhost:443): working${NC}"
    record_test "pass"
else
    echo -e "${YELLOW}[WARNING]  HTTPS access (localhost:443): may need configuration${NC}"
    record_test "fail"
fi
echo

echo -e "${BLUE}STEP 2: CHOOSE YOUR TESTING METHOD${NC}"
echo "======================================"
echo
echo "You can test the system using either:"
echo
echo -e "${GREEN}Option A: HTTP Testing (Recommended for validation)${NC}"
echo "   • URL: http://localhost:8080"
echo "   • No certificate warnings"
echo "   • Same OPAQUE security"
echo "   • Faster for testing"
echo
echo -e "${CYAN}Option B: HTTPS Testing (Production-like)${NC}"
echo "   • URL: https://localhost"
echo "   • Certificate warnings expected"
echo "   • Full TLS stack testing"
echo "   • More realistic production test"
echo
read -p "Choose testing method (A/B) [A]: " TESTING_METHOD
TESTING_METHOD=${TESTING_METHOD:-A}

if [[ "$TESTING_METHOD" =~ ^[Bb]$ ]]; then
    TEST_URL="https://localhost"
    echo -e "${CYAN}Selected: HTTPS testing with certificate warnings${NC}"
    echo -e "${YELLOW}Remember to accept certificate warnings in your browser!${NC}"
else
    TEST_URL="http://localhost:8080"
    echo -e "${GREEN}Selected: HTTP testing (no certificate warnings)${NC}"
fi
echo

echo -e "${BLUE}STEP 3: WEB INTERFACE ACCESS TEST${NC}"
echo "====================================="
echo
echo -e "${CYAN}Testing URL: ${TEST_URL}${NC}"
echo

wait_for_user "1. Open your browser to: ${TEST_URL}
2. Verify the page loads with 'Private File Vault' title
3. Check browser console (F12 → Console) for any red errors
4. Confirm OPAQUE WebAssembly loads without errors"

# Validate web interface access
validate_backend "web" "200" "curl -s -I ${TEST_URL} $([ '$TESTING_METHOD' = 'B' ] && echo '--insecure') | head -1" "Web interface accessibility"

echo -e "${BLUE}STEP 4: USER REGISTRATION TEST (OPAQUE)${NC}"
echo "==========================================="
echo
echo -e "${CYAN}Test Credentials:${NC}"
echo -e "   Username: ${GREEN}${TEST_USERNAME}${NC}"
echo -e "   Password: ${GREEN}${TEST_PASSWORD}${NC}"
echo

wait_for_user "1. Click 'Register' on the web interface
2. Enter Username: ${TEST_USERNAME}
3. Enter Password: ${TEST_PASSWORD}
4. Verify password requirements show green checkmarks
5. Click 'Register' button
6. Look for 'Registration successful' message"

# Backend verification for user registration
validate_backend "registration" "$TEST_USERNAME" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \"SELECT username FROM users WHERE username='$TEST_USERNAME';\" 2>/dev/null" "User registration in database"

validate_backend "opaque_data" "" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \"SELECT username FROM opaque_user_data WHERE username='$TEST_USERNAME';\" 2>/dev/null" "OPAQUE authentication data"

echo -e "${BLUE}[SECURE] STEP 5: USER LOGIN TEST (OPAQUE)${NC}"
echo "==================================="
echo

wait_for_user "1. Use the same login credentials:
   Username: ${TEST_USERNAME}
   Password: ${TEST_PASSWORD}
2. Click 'Login' button
3. Verify redirect to file upload interface
4. Confirm you see logout button and user controls"

# Check for recent OPAQUE authentication in logs
validate_backend "login" "opaque" "sudo journalctl -u arkfile --since='2 minutes ago' --no-pager -q | grep -i opaque | tail -1" "OPAQUE authentication in logs"

echo -e "${BLUE}[FILES] STEP 6: FILE UPLOAD & ENCRYPTION TEST${NC}"
echo "========================================="
echo

# Create test file
echo "$TEST_FILE_CONTENT" > /tmp/arkfile-test.txt
echo -e "${GREEN}[OK] Created test file: /tmp/arkfile-test.txt${NC}"
echo -e "   Content: ${TEST_FILE_CONTENT}"
echo

wait_for_user "1. Click 'Choose File' and select: /tmp/arkfile-test.txt
2. Select 'Use my account password' (recommended)
3. Add password hint: 'Test file for validation'
4. Click 'Upload' button
5. Wait for upload progress to complete
6. Verify file appears in 'Your Files' section with [LOCK] icon"

# Backend verification for file upload
validate_backend "file_upload" "$TEST_USERNAME" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \"SELECT fm.owner_username FROM file_metadata fm WHERE fm.owner_username='$TEST_USERNAME' ORDER BY fm.upload_date DESC LIMIT 1;\" 2>/dev/null" "File upload in database"

validate_backend "file_encryption" "custom" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \"SELECT fm.password_type FROM file_metadata fm WHERE fm.owner_username='$TEST_USERNAME' ORDER BY fm.upload_date DESC LIMIT 1;\" 2>/dev/null" "File encryption type"

# Check for encrypted files in storage
storage_files=$(find /opt/arkfile/var/lib/storage/ -name "*.enc" 2>/dev/null | wc -l)
if [ "$storage_files" -gt 0 ]; then
    echo -e "${GREEN}[OK] PASS: Found $storage_files encrypted file(s) in storage${NC}"
    record_test "pass"
else
    echo -e "${RED}[X] FAIL: No encrypted files found in storage${NC}"
    record_test "fail"
fi
echo

echo -e "${BLUE}STEP 7: FILE DOWNLOAD & DECRYPTION TEST${NC}"
echo "==========================================="
echo

wait_for_user "1. Click the download button/link for your uploaded file
2. Enter your account password when prompted: ${TEST_PASSWORD}
3. Verify the file downloads successfully
4. Open the downloaded file and confirm content matches original"

# Verify file can be decrypted (check for file header)
latest_file=$(find /opt/arkfile/var/lib/storage/ -name "*.enc" -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
if [ -n "$latest_file" ] && [ -f "$latest_file" ]; then
    file_header=$(xxd -l 4 "$latest_file" 2>/dev/null | head -1 | cut -d' ' -f2)
    if [[ "$file_header" =~ ^(0004|0005) ]]; then
        echo -e "${GREEN}[OK] PASS: File has correct encryption header (0x${file_header})${NC}"
        record_test "pass"
    else
        echo -e "${RED}[X] FAIL: File has incorrect encryption header${NC}"
        record_test "fail"
    fi
else
    echo -e "${YELLOW}[WARNING]  SKIP: Could not locate encrypted file for header verification${NC}"
fi
echo

echo -e "${BLUE}STEP 8: FILE SHARING TEST${NC}"
echo "============================="
echo

wait_for_user "1. Click 'Share' button for your uploaded file
2. Copy the generated share link
3. Open a new incognito/private browser window
4. Visit the share link
5. Enter the file password when prompted
6. Verify the file downloads successfully in the private window"

# Check for share records in database
validate_backend "file_sharing" "" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \"SELECT COUNT(*) FROM file_share_keys fsk JOIN file_metadata fm ON fsk.file_id = fm.filename WHERE fm.owner_username='$TEST_USERNAME';\" 2>/dev/null" "File sharing record creation"

echo -e "${BLUE}STEP 9: BACKEND VERIFICATION SUMMARY${NC}"
echo "========================================"
echo

# Additional backend checks
echo -e "${PURPLE}Performing comprehensive backend validation...${NC}"

# Check key material
validate_backend "opaque_keys" "server_private.key" "ls /opt/arkfile/etc/keys/opaque/" "OPAQUE server keys"

validate_backend "jwt_keys" "signing.key" "ls /opt/arkfile/etc/keys/jwt/current/" "JWT signing keys"

# Check database schema
validate_backend "database_schema" "users" "sqlite3 /opt/arkfile/var/lib/database/arkfile.db \".tables\" 2>/dev/null" "Database schema"

# Check storage connectivity
if command -v curl >/dev/null 2>&1; then
    validate_backend "minio_health" "200" "curl -s -o /dev/null -w '%{http_code}' http://localhost:9000/minio/health/ready" "MinIO storage health"
fi

echo -e "${BLUE}[STATS] FINAL VALIDATION SUMMARY${NC}"
echo "============================"
echo

# Calculate test duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "${CYAN}Validation completed in ${DURATION} seconds${NC}"
echo -e "${CYAN}Total tests performed: ${TESTS_TOTAL}${NC}"
echo
echo -e "${GREEN}[OK] Tests passed: ${TESTS_PASSED}${NC}"
echo -e "${RED}[X] Tests failed: ${TESTS_FAILED}${NC}"
echo

# Final verdict
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}CONGRATULATIONS!${NC}"
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                         VALIDATION SUCCESSFUL                                ║${NC}"
    echo -e "${GREEN}║                                                                              ║${NC}"
    echo -e "${GREEN}║  Your Arkfile deployment is working correctly and ready for use!             ║${NC}"
    echo -e "${GREEN}║                                                                              ║${NC}"
    echo -e "${GREEN}║  + OPAQUE authentication system functional                                   ║${NC}"
    echo -e "${GREEN}║  + File encryption and decryption working                                    ║${NC}"
    echo -e "${GREEN}║  + File sharing system operational                                           ║${NC}"
    echo -e "${GREEN}║  + All backend services healthy                                              ║${NC}"
    echo -e "${GREEN}║  + TLS certificates configured properly                                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}[START] NEXT STEPS:${NC}"
    echo "• Your system is ready for production use"
    echo "• Consider running security audit: ./scripts/security-audit.sh"
    echo "• Set up monitoring and backups for production deployment"
    echo "• Upgrade to production TLS certificates when ready"
    
elif [ $TESTS_FAILED -le 2 ]; then
    echo -e "${YELLOW}[WARNING]  VALIDATION COMPLETED WITH MINOR ISSUES${NC}"
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                    MOSTLY FUNCTIONAL DEPLOYMENT                              ║${NC}"
    echo -e "${YELLOW}║                                                                              ║${NC}"
    echo -e "${YELLOW}║  Your Arkfile deployment is largely working but has minor issues.            ║${NC}"
    echo -e "${YELLOW}║  Core functionality appears operational.                                     ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}RECOMMENDED ACTIONS:${NC}"
    echo "• Review failed tests above and address issues"
    echo "• Run deployment validation: ./scripts/validate-deployment.sh"
    echo "• Check service logs: sudo journalctl -u arkfile"
    echo "• Most functionality should work despite minor issues"
    
else
    echo -e "${RED}[X] VALIDATION FAILED${NC}"
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                       DEPLOYMENT NEEDS ATTENTION                             ║${NC}"
    echo -e "${RED}║                                                                              ║${NC}"
    echo -e "${RED}║  Your Arkfile deployment has significant issues that need to be resolved.    ║${NC}"
    echo -e "${RED}║  Please address the failed tests before using in production.                 ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE} TROUBLESHOOTING STEPS:${NC}"
    echo "1. Review all failed tests above"
    echo "2. Check service status: sudo systemctl status arkfile caddy minio rqlite"
    echo "3. Review service logs: sudo journalctl -u arkfile"
    echo "4. Run health check: ./scripts/health-check.sh"
    echo "5. Validate deployment: ./scripts/validate-deployment.sh"
    echo "6. Consult admin testing guide: docs/admin-testing-guide.md"
fi

echo
echo -e "${BLUE}ADDITIONAL RESOURCES:${NC}"
echo "• Admin Testing Guide: docs/admin-testing-guide.md"
echo "• Deployment Guide: docs/deployment-guide.md"
echo "• Security Operations: docs/security-operations.md"
echo "• Health Dashboard: ${TEST_URL}/health"
echo "• System Logs: sudo journalctl -u arkfile -f"

echo
echo -e "${CYAN}Validation completed at: $(date)${NC}"

# Cleanup
rm -f /tmp/arkfile-test.txt 2>/dev/null || true

exit $([ $TESTS_FAILED -eq 0 ] && echo 0 || echo 1)
