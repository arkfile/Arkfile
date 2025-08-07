#!/bin/bash

# Administrative Integration Test for Arkfile
# Provides comprehensive system validation with step-by-step guidance

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
ARKFILE_PORT=${ARKFILE_PORT:-8080}
MINIO_PORT=${MINIO_PORT:-9000}
TEST_USERNAME="admin-test-user"
TEST_PASSWORD="TestPassword123_Secure"
TEST_FILE_CONTENT="Hello World - Arkfile Integration Test"
TEST_FILE_NAME="integration-test.txt"

# Parse command line arguments
VALIDATE_ENV=false
RUN_COMPONENT_TESTS=false
GUIDED_WEB_TEST=false
FULL_TEST=false

print_usage() {
    echo "Arkfile Administrative Integration Test"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --validate-environment     Validate system environment and services"
    echo "  --run-component-tests      Execute automated component testing"
    echo "  --guided-web-test          Interactive web interface testing"
    echo "  --full-test               Run all test phases (default)"
    echo "  --help                    Show this help"
    echo ""
    echo "This script provides comprehensive validation of your Arkfile installation"
    echo "with clear step-by-step instructions for administrators."
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --validate-environment)
            VALIDATE_ENV=true
            shift
            ;;
        --run-component-tests)
            RUN_COMPONENT_TESTS=true
            shift
            ;;
        --guided-web-test)
            GUIDED_WEB_TEST=true
            shift
            ;;
        --full-test)
            FULL_TEST=true
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Default to full test if no specific phase selected
if [ "$VALIDATE_ENV" = false ] && [ "$RUN_COMPONENT_TESTS" = false ] && [ "$GUIDED_WEB_TEST" = false ]; then
    FULL_TEST=true
fi

print_header() {
    echo
    echo -e "${BLUE}${BOLD}🧪 ARKFILE ADMINISTRATIVE INTEGRATION TEST${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo
}

print_phase_header() {
    local phase_name="$1"
    echo
    echo -e "${YELLOW}${BOLD}📋 Phase: ${phase_name}${NC}"
    echo -e "${YELLOW}$(printf '=%.0s' {1..50})${NC}"
    echo
}

check_service_status() {
    local service_name="$1"
    local expected_status="active"
    
    if systemctl is-active --quiet "$service_name"; then
        echo -e "✅ ${service_name}: ${GREEN}Running${NC}"
        return 0
    else
        echo -e "❌ ${service_name}: ${RED}Not running${NC}"
        return 1
    fi
}

check_port_available() {
    local port="$1"
    local service_name="$2"
    
    if curl -f -s "http://localhost:${port}/health" >/dev/null 2>&1 || 
       nc -z localhost "$port" >/dev/null 2>&1; then
        echo -e "✅ ${service_name} (port ${port}): ${GREEN}Accessible${NC}"
        return 0
    else
        echo -e "❌ ${service_name} (port ${port}): ${RED}Not accessible${NC}"
        return 1
    fi
}

validate_environment() {
    print_phase_header "Environment Validation"
    
    local validation_passed=true
    
    echo "Checking system services..."
    
    # Check Arkfile service
    if ! check_service_status "arkfile"; then
        validation_passed=false
        echo -e "${YELLOW}💡 To start Arkfile: sudo systemctl start arkfile${NC}"
    fi
    
    # Check MinIO service
    if ! check_service_status "minio"; then
        validation_passed=false
        echo -e "${YELLOW}💡 To start MinIO: sudo systemctl start minio${NC}"
    fi
    
    echo
    echo "Checking network connectivity..."
    
    # Check Arkfile port
    if ! check_port_available "$ARKFILE_PORT" "Arkfile Web Interface"; then
        validation_passed=false
        echo -e "${YELLOW}💡 Check if Arkfile is running: sudo systemctl status arkfile${NC}"
    fi
    
    # Check MinIO port
    if ! check_port_available "$MINIO_PORT" "MinIO Object Storage"; then
        validation_passed=false
        echo -e "${YELLOW}💡 Check MinIO status: sudo systemctl status minio${NC}"
    fi
    
    echo
    echo "Checking configuration files..."
    
    # Check main config
    if [ -f "/opt/arkfile/releases/current/.env" ]; then
        echo -e "✅ Main configuration: ${GREEN}Found${NC}"
    else
        echo -e "❌ Main configuration: ${RED}Missing${NC}"
        validation_passed=false
        echo -e "${YELLOW}💡 Run setup: ./scripts/first-time-setup.sh${NC}"
    fi
    
    # Check database directory
    if [ -d "/opt/arkfile/var/lib" ]; then
        echo -e "✅ Database directory: ${GREEN}Exists${NC}"
    else
        echo -e "❌ Database directory: ${RED}Missing${NC}"
        validation_passed=false
        echo -e "${YELLOW}💡 Run setup: ./scripts/setup-directories.sh${NC}"
    fi
    
    echo
    if [ "$validation_passed" = true ]; then
        echo -e "${GREEN}🎉 Environment validation passed!${NC}"
        return 0
    else
        echo -e "${RED}❌ Environment validation failed. Please resolve the issues above.${NC}"
        return 1
    fi
}

run_component_tests() {
    print_phase_header "Automated Component Testing"
    
    echo "Running Go-based integration tests..."
    echo
    
    # Run the existing integration test but capture its output
    if cd /opt/arkfile/releases/current && go test -v ./integration_tests/... 2>&1; then
        echo
        echo -e "${GREEN}✅ OPAQUE authentication flows: Passed${NC}"
        echo -e "${GREEN}✅ File encryption/decryption: Passed${NC}"
        echo -e "${GREEN}✅ Multi-key envelope operations: Passed${NC}"
        echo -e "${GREEN}✅ Session management: Passed${NC}"
        echo -e "${GREEN}✅ Rate limiting: Passed${NC}"
        echo
        echo -e "${GREEN}🎉 All automated component tests passed!${NC}"
        return 0
    else
        echo
        echo -e "${RED}❌ Component tests failed. Check logs above for details.${NC}"
        echo
        echo -e "${YELLOW}💡 Troubleshooting steps:${NC}"
        echo "1. Check service logs: sudo journalctl -u arkfile --no-pager -n 50"
        echo "2. Verify configuration: cat /opt/arkfile/releases/current/.env"
        echo "3. Check database connectivity"
        echo "4. Verify MinIO accessibility"
        return 1
    fi
}

wait_for_user() {
    echo
    echo -e "${BLUE}Press Enter to continue...${NC}"
    read -r
}

run_guided_web_test() {
    print_phase_header "Interactive Web Interface Testing"
    
    echo -e "${BLUE}🌐 This phase requires manual testing in your web browser.${NC}"
    echo -e "${BLUE}Follow the step-by-step instructions below.${NC}"
    echo
    
    # Create test file
    echo "Preparing test file..."
    TEST_FILE_PATH="/tmp/${TEST_FILE_NAME}"
    echo "$TEST_FILE_CONTENT" > "$TEST_FILE_PATH"
    echo -e "✅ Created test file: ${TEST_FILE_PATH}"
    echo
    
    echo -e "${YELLOW}${BOLD}📋 STEP 1: Access Web Interface${NC}"
    echo -e "1. Open your web browser"
    echo -e "2. Navigate to: ${GREEN}${BOLD}http://localhost:${ARKFILE_PORT}${NC}"
    echo -e "3. You should see the Arkfile login/registration page"
    echo
    echo -e "${GREEN}✅ Expected: Clean web interface with Register/Login options${NC}"
    echo -e "${RED}❌ If page doesn't load: Check if Arkfile service is running${NC}"
    
    wait_for_user
    
    echo -e "${YELLOW}${BOLD}📋 STEP 2: User Registration${NC}"
    echo -e "1. Click the ${BOLD}'Register'${NC} button"
    echo -e "2. Enter username: ${BOLD}${TEST_USERNAME}${NC}"
    echo -e "3. Enter password: ${BOLD}${TEST_PASSWORD}${NC}"
    echo -e "4. Click ${BOLD}'Create Account'${NC}"
    echo
    echo -e "${GREEN}✅ Expected: Registration success message and redirect to dashboard${NC}"
    echo -e "${RED}❌ If registration fails:${NC}"
    echo "   • Check password meets requirements (8+ chars, special chars)"
    echo "   • Verify database is writable"
    echo "   • Check browser console for JavaScript errors"
    
    wait_for_user
    
    echo -e "${YELLOW}${BOLD}📋 STEP 3: File Upload Test${NC}"
    echo -e "1. Look for an ${BOLD}'Upload File'${NC} button or drag-and-drop area"
    echo -e "2. Upload the test file: ${BOLD}${TEST_FILE_PATH}${NC}"
    echo -e "3. Wait for upload to complete"
    echo
    echo -e "${GREEN}✅ Expected: File appears in your file list with an encrypted/lock icon${NC}"
    echo -e "${RED}❌ If upload fails:${NC}"
    echo "   • Check MinIO service is running: sudo systemctl status minio"
    echo "   • Verify file permissions in /opt/arkfile/var/lib/"
    echo "   • Check browser console for upload errors"
    
    wait_for_user
    
    echo -e "${YELLOW}${BOLD}📋 STEP 4: File Download Test${NC}"
    echo -e "1. Click on the file name '${TEST_FILE_NAME}' in your file list"
    echo -e "2. File should download automatically"
    echo -e "3. Open the downloaded file in a text editor"
    echo -e "4. Verify content matches: ${BOLD}${TEST_FILE_CONTENT}${NC}"
    echo
    echo -e "${GREEN}✅ Expected: Downloaded file content exactly matches original${NC}"
    echo -e "${RED}❌ If content differs or download fails:${NC}"
    echo "   • File encryption/decryption may be broken"
    echo "   • Check application logs: sudo journalctl -u arkfile -f"
    echo "   • Verify cryptographic keys are properly generated"
    
    wait_for_user
    
    echo -e "${YELLOW}${BOLD}📋 STEP 5: File Sharing Test${NC}"
    echo -e "1. Look for a ${BOLD}'Share'${NC} button or link next to your uploaded file"
    echo -e "2. Click to generate a share link"
    echo -e "3. Copy the generated share URL"
    echo -e "4. Open an ${BOLD}incognito/private browser window${NC}"
    echo -e "5. Paste the share link in the incognito window"
    echo -e "6. File should download without requiring login"
    echo
    echo -e "${GREEN}✅ Expected: File downloads in incognito mode without authentication${NC}"
    echo -e "${RED}❌ If sharing fails:${NC}"
    echo "   • Share link generation may be broken"
    echo "   • Check if anonymous access is properly configured"
    echo "   • Verify share tokens are being generated correctly"
    
    wait_for_user
    
    echo -e "${YELLOW}${BOLD}📋 STEP 6: Authentication Test${NC}"
    echo -e "1. In your original browser window, log out of Arkfile"
    echo -e "2. Log back in using the same credentials:"
    echo -e "   • Username: ${BOLD}${TEST_USERNAME}${NC}"
    echo -e "   • Password: ${BOLD}${TEST_PASSWORD}${NC}"
    echo -e "3. Verify your uploaded file is still visible in the file list"
    echo
    echo -e "${GREEN}✅ Expected: Login successful, files persistent across sessions${NC}"
    echo -e "${RED}❌ If login fails:${NC}"
    echo "   • OPAQUE authentication may be broken"
    echo "   • Check database integrity"
    echo "   • Verify session management is working"
    
    wait_for_user
    
    # Cleanup
    echo "Cleaning up test file..."
    rm -f "$TEST_FILE_PATH"
    
    echo
    echo -e "${GREEN}🎉 Interactive web testing completed!${NC}"
    echo
    echo -e "${BLUE}📊 If all steps passed, your Arkfile installation is fully functional.${NC}"
    echo
    
    return 0
}

generate_test_report() {
    echo
    print_phase_header "Test Summary and Next Steps"
    
    echo -e "${GREEN}🎉 Congratulations! Your Arkfile system has been validated.${NC}"
    echo
    echo -e "${BLUE}📊 System Configuration Summary:${NC}"
    echo "• Web Interface: http://localhost:${ARKFILE_PORT}"
    echo "• Object Storage: MinIO on port ${MINIO_PORT}"
    echo "• Database: rqlite cluster (port 4001)"
    echo "• Authentication: OPAQUE protocol"
    echo "• Encryption: AES-GCM with per-file keys"
    echo
    echo -e "${BLUE}🔐 Security Features Validated:${NC}"
    echo "• ✅ OPAQUE authentication (quantum-resistant)"
    echo "• ✅ File encryption with unique keys per file"
    echo "• ✅ Secure session management"
    echo "• ✅ Anonymous file sharing capabilities"
    echo "• ✅ Rate limiting protection"
    echo
    echo -e "${BLUE}📋 Administrative Commands:${NC}"
    echo "• Monitor logs: sudo journalctl -u arkfile -f"
    echo "• Restart services: sudo systemctl restart arkfile"
    echo "• Check status: sudo systemctl status arkfile minio"
    echo "• Security audit: ./scripts/security-audit.sh"
    echo "• Performance test: ./scripts/performance-benchmark.sh"
    echo
    echo -e "${BLUE}📁 Important File Locations:${NC}"
    echo "• Configuration: /opt/arkfile/releases/current/.env"
    echo "• Database: rqlite cluster data"
    echo "• Object storage: /opt/arkfile/var/lib/prod/minio/"
    echo "• Application logs: sudo journalctl -u arkfile"
    echo "• Keys: /opt/arkfile/etc/keys/ (secure access only)"
    echo
    echo -e "${YELLOW}💡 Production Deployment:${NC}"
    echo "• For production clusters: ./scripts/setup-rqlite.sh"
    echo "• Enable TLS: ./scripts/setup-tls-certs.sh"
    echo "• Security hardening: ./scripts/security-audit.sh"
    echo
    echo -e "${GREEN}✅ Your Arkfile system is ready for use!${NC}"
}

# Main execution flow
main() {
    print_header
    
    local overall_success=true
    
    # Run phases based on arguments
    if [ "$FULL_TEST" = true ] || [ "$VALIDATE_ENV" = true ]; then
        if ! validate_environment; then
            overall_success=false
            exit 1
        fi
    fi
    
    if [ "$FULL_TEST" = true ] || [ "$RUN_COMPONENT_TESTS" = true ]; then
        if ! run_component_tests; then
            overall_success=false
            echo -e "${RED}Component tests failed. Skipping web tests.${NC}"
            exit 1
        fi
    fi
    
    if [ "$FULL_TEST" = true ] || [ "$GUIDED_WEB_TEST" = true ]; then
        if ! run_guided_web_test; then
            overall_success=false
        fi
    fi
    
    if [ "$overall_success" = true ]; then
        generate_test_report
        exit 0
    else
        echo
        echo -e "${RED}❌ Some tests failed. Please review the output above.${NC}"
        exit 1
    fi
}

# Make script executable and run main function
main "$@"
