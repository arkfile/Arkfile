#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"
TIMEOUT=30

echo -e "${GREEN}Validating Arkfile deployment...${NC}"

# Global counters
VALIDATIONS_PASSED=0
VALIDATIONS_FAILED=0
VALIDATIONS_WARNING=0

# Function to print validation status
print_validation() {
    local status=$1
    local message=$2
    local details=$3
    
    case $status in
        "PASS")
            echo -e "  ${GREEN}[OK]${NC} ${message}"
            ((VALIDATIONS_PASSED++))
            ;;
        "FAIL")
            echo -e "  ${RED}[X]${NC} ${message}"
            ((VALIDATIONS_FAILED++))
            ;;
        "WARN")
            echo -e "  ${YELLOW}[WARNING]${NC} ${message}"
            ((VALIDATIONS_WARNING++))
            ;;
        "INFO")
            echo -e "  ${BLUE}ℹ${NC} ${message}"
            ;;
    esac
    
    if [ -n "$details" ]; then
        echo "    ${details}"
    fi
}

# Function to validate installation completeness
validate_installation() {
    echo -e "${BLUE}Installation Completeness${NC}"
    echo "========================="
    
    # Check if health check passes
    if sudo ./scripts/health-check.sh >/dev/null 2>&1; then
        print_validation "PASS" "Health check passes"
    else
        print_validation "FAIL" "Health check fails - run './scripts/health-check.sh' for details"
    fi
    
    # Check systemd service status
    if systemctl is-enabled arkfile.service >/dev/null 2>&1; then
        print_validation "PASS" "Service is enabled"
    else
        print_validation "FAIL" "Service is not enabled"
    fi
    
    # Check if all required keys exist
    local required_keys=(
        "$ARKFILE_DIR/etc/keys/opaque/server_private.key"
        "$ARKFILE_DIR/etc/keys/jwt/current/signing.key"
        "$ARKFILE_DIR/etc/keys/tls/ca/ca.crt"
    )
    
    local missing_keys=0
    for key in "${required_keys[@]}"; do
        if [ ! -f "$key" ]; then
            missing_keys=$((missing_keys + 1))
        fi
    done
    
    if [ $missing_keys -eq 0 ]; then
        print_validation "PASS" "All required cryptographic keys present"
    else
        print_validation "FAIL" "$missing_keys required keys missing"
    fi
    
    echo ""
}

# Function to validate service startup
validate_service_startup() {
    echo -e "${BLUE}Service Startup${NC}"
    echo "==============="
    
    # Check if service is currently running
    if systemctl is-active arkfile.service >/dev/null 2>&1; then
        print_validation "INFO" "Service is currently running - stopping for validation test"
        sudo systemctl stop arkfile.service
        sleep 2
    fi
    
    # Start the service
    print_validation "INFO" "Starting arkfile service..."
    if sudo systemctl start arkfile.service; then
        print_validation "PASS" "Service started successfully"
    else
        print_validation "FAIL" "Service failed to start"
        echo ""
        return 1
    fi
    
    # Wait for service to be fully ready
    local wait_count=0
    while [ $wait_count -lt $TIMEOUT ]; do
        if systemctl is-active arkfile.service >/dev/null 2>&1; then
            break
        fi
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    if systemctl is-active arkfile.service >/dev/null 2>&1; then
        print_validation "PASS" "Service is active and running"
    else
        print_validation "FAIL" "Service failed to become active within ${TIMEOUT}s"
        echo ""
        return 1
    fi
    
    # Check service logs for errors
    local error_count=$(sudo journalctl -u arkfile.service --since="1 minute ago" --no-pager -q | grep -i error | wc -l)
    if [ $error_count -eq 0 ]; then
        print_validation "PASS" "No errors in service logs"
    else
        print_validation "WARN" "$error_count errors found in service logs"
    fi
    
    echo ""
}

# Function to validate key loading
validate_key_loading() {
    echo -e "${BLUE}Key Loading${NC}"
    echo "==========="
    
    # Test OPAQUE key accessibility
    if sudo -u $USER test -r "$ARKFILE_DIR/etc/keys/opaque/server_private.key"; then
        print_validation "PASS" "OPAQUE server key is readable by service user"
    else
        print_validation "FAIL" "OPAQUE server key is not accessible"
    fi
    
    # Test JWT key accessibility
    if sudo -u $USER test -r "$ARKFILE_DIR/etc/keys/jwt/current/signing.key"; then
        print_validation "PASS" "JWT signing key is readable by service user"
    else
        print_validation "FAIL" "JWT signing key is not accessible"
    fi
    
    # Test TLS certificate accessibility
    if sudo -u $USER test -r "$ARKFILE_DIR/etc/keys/tls/ca/ca.crt"; then
        print_validation "PASS" "TLS CA certificate is readable by service user"
    else
        print_validation "FAIL" "TLS CA certificate is not accessible"
    fi
    
    # Validate OPAQUE keys (if not placeholder)
    local opaque_key_content=$(sudo -u $USER head -1 "$ARKFILE_DIR/etc/keys/opaque/server_private.key" 2>/dev/null || echo "")
    if [[ "$opaque_key_content" == *"PLACEHOLDER"* ]]; then
        print_validation "WARN" "OPAQUE keys are placeholders - production deployment needs real keys"
    else
        print_validation "PASS" "OPAQUE keys appear to contain real cryptographic material"
    fi
    
    # Validate JWT key format
    if sudo -u $USER openssl pkey -in "$ARKFILE_DIR/etc/keys/jwt/current/signing.key" -noout >/dev/null 2>&1; then
        print_validation "PASS" "JWT signing key format is valid"
    else
        print_validation "FAIL" "JWT signing key format is invalid"
    fi
    
    # Validate TLS certificates
    if sudo -u $USER openssl x509 -in "$ARKFILE_DIR/etc/keys/tls/ca/ca.crt" -noout >/dev/null 2>&1; then
        print_validation "PASS" "TLS CA certificate format is valid"
    else
        print_validation "FAIL" "TLS CA certificate format is invalid"
    fi
    
    echo ""
}

# Function to validate network connectivity
validate_network_connectivity() {
    echo -e "${BLUE}Network Connectivity${NC}"
    echo "===================="
    
    # Get the configured port from environment or default
    local port=${ARKFILE_PORT:-8080}
    local host=${ARKFILE_HOST:-localhost}
    
    print_validation "INFO" "Testing connectivity to ${host}:${port}"
    
    # Wait for service to bind to port
    local wait_count=0
    while [ $wait_count -lt $TIMEOUT ]; do
        if netstat -ln | grep ":${port}" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    # Check if port is listening
    if netstat -ln | grep ":${port}" >/dev/null 2>&1; then
        print_validation "PASS" "Service is listening on port ${port}"
    else
        print_validation "FAIL" "Service is not listening on port ${port}"
        echo ""
        return 1
    fi
    
    # Test HTTP connectivity
    if command -v curl >/dev/null 2>&1; then
        local http_status=$(curl -s -o /dev/null -w "%{http_code}" "http://${host}:${port}/" --connect-timeout 5 || echo "000")
        case $http_status in
            200|301|302|404)
                print_validation "PASS" "HTTP connectivity successful (status: $http_status)"
                ;;
            000)
                print_validation "FAIL" "HTTP connection failed or timed out"
                ;;
            *)
                print_validation "WARN" "HTTP connection returned status: $http_status"
                ;;
        esac
    else
        print_validation "WARN" "curl not available - skipping HTTP connectivity test"
    fi
    
    echo ""
}

# Function to validate database connectivity
validate_database_connectivity() {
    echo -e "${BLUE}Database Connectivity${NC}"
    echo "====================="
    
    # Check if database file exists and is accessible
    local db_path="$ARKFILE_DIR/var/lib/database/arkfile.db"
    if [ -f "$db_path" ]; then
        print_validation "PASS" "Database file exists: $db_path"
        
        # Check database permissions
        local db_owner=$(stat -c "%U:%G" "$db_path")
        if [ "$db_owner" = "$USER:$GROUP" ]; then
            print_validation "PASS" "Database file has correct ownership"
        else
            print_validation "WARN" "Database file ownership: $db_owner (expected: $USER:$GROUP)"
        fi
    else
        print_validation "INFO" "Database file will be created on first use"
    fi
    
    # Test database accessibility by service user
    if sudo -u $USER test -w "$ARKFILE_DIR/var/lib/database"; then
        print_validation "PASS" "Database directory is writable by service user"
    else
        print_validation "FAIL" "Database directory is not writable by service user"
    fi
    
    echo ""
}

# Function to validate security configuration
validate_security_configuration() {
    echo -e "${BLUE}Security Configuration${NC}"
    echo "======================"
    
    # Check file permissions on sensitive directories
    local sensitive_dirs=(
        "$ARKFILE_DIR/etc/keys:700"
        "$ARKFILE_DIR/etc/keys/opaque:700"
        "$ARKFILE_DIR/etc/keys/jwt:700"
        "$ARKFILE_DIR/etc/keys/tls:700"
    )
    
    for dir_spec in "${sensitive_dirs[@]}"; do
        local dir_path=$(echo "$dir_spec" | cut -d: -f1)
        local expected_perms=$(echo "$dir_spec" | cut -d: -f2)
        
        if [ -d "$dir_path" ]; then
            local actual_perms=$(stat -c "%a" "$dir_path")
            if [ "$actual_perms" = "$expected_perms" ]; then
                print_validation "PASS" "Directory $(basename "$dir_path") has secure permissions: $actual_perms"
            else
                print_validation "WARN" "Directory $(basename "$dir_path") permissions: $actual_perms (expected: $expected_perms)"
            fi
        fi
    done
    
    # Check that service user cannot login
    local user_shell=$(getent passwd $USER | cut -d: -f7)
    if [ "$user_shell" = "/sbin/nologin" ]; then
        print_validation "PASS" "Service user login properly disabled"
    else
        print_validation "WARN" "Service user shell: $user_shell (recommended: /sbin/nologin)"
    fi
    
    # Check systemd service security features
    if grep -q "NoNewPrivileges=yes" /etc/systemd/system/arkfile.service; then
        print_validation "PASS" "NoNewPrivileges security feature enabled"
    else
        print_validation "WARN" "NoNewPrivileges security feature not found"
    fi
    
    if grep -q "ProtectSystem=strict" /etc/systemd/system/arkfile.service; then
        print_validation "PASS" "ProtectSystem security feature enabled"
    else
        print_validation "WARN" "ProtectSystem security feature not found"
    fi
    
    echo ""
}

# Function to validate backup capability
validate_backup_capability() {
    echo -e "${BLUE}Backup Capability${NC}"
    echo "=================="
    
    # Check if backup script exists and is executable
    if [ -x "./scripts/backup-keys.sh" ]; then
        print_validation "PASS" "Key backup script is available and executable"
        
        # Test backup creation (dry run)
        print_validation "INFO" "Testing backup creation..."
        if sudo ./scripts/backup-keys.sh >/dev/null 2>&1; then
            print_validation "PASS" "Backup creation test successful"
            
            # Check if backup was created
            local backup_count=$(find "$ARKFILE_DIR/etc/keys/backups" -name "arkfile-keys_*.tar.gz.enc" 2>/dev/null | wc -l)
            if [ $backup_count -gt 0 ]; then
                print_validation "PASS" "$backup_count backup(s) available"
            else
                print_validation "WARN" "No backups found after backup test"
            fi
        else
            print_validation "FAIL" "Backup creation test failed"
        fi
    else
        print_validation "FAIL" "Key backup script not found or not executable"
    fi
    
    echo ""
}

# Function to perform cleanup after validation
cleanup_validation() {
    echo -e "${BLUE}Cleanup${NC}"
    echo "======="
    
    # Service should remain running after successful validation
    if [ $VALIDATIONS_FAILED -eq 0 ]; then
        if systemctl is-active arkfile.service >/dev/null 2>&1; then
            print_validation "INFO" "Service left running for normal operation"
        else
            print_validation "INFO" "Starting service for normal operation"
            sudo systemctl start arkfile.service
        fi
    else
        print_validation "INFO" "Service stopped due to validation failures"
        sudo systemctl stop arkfile.service 2>/dev/null || true
    fi
    
    echo ""
}

# Main validation function
main() {
    echo -e "${GREEN}Arkfile Deployment Validation${NC}"
    echo "============================="
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Host: $(hostname)"
    echo ""
    
    # Run all validations
    validate_installation
    validate_service_startup && {
        validate_key_loading
        validate_network_connectivity
        validate_database_connectivity
        validate_security_configuration
        validate_backup_capability
    }
    
    cleanup_validation
    
    # Summary
    echo -e "${BLUE}Validation Summary${NC}"
    echo "=================="
    echo -e "  ${GREEN}[OK]${NC} Passed: $VALIDATIONS_PASSED"
    echo -e "  ${YELLOW}[WARNING]${NC} Warnings: $VALIDATIONS_WARNING"
    echo -e "  ${RED}[X]${NC} Failed: $VALIDATIONS_FAILED"
    echo ""
    
    # Final verdict
    if [ $VALIDATIONS_FAILED -eq 0 ]; then
        if [ $VALIDATIONS_WARNING -eq 0 ]; then
            echo -e "${GREEN}[OK] DEPLOYMENT VALIDATION PASSED${NC}"
            echo "Arkfile is successfully deployed and ready for production use."
        else
            echo -e "${YELLOW}[WARNING]  DEPLOYMENT VALIDATION PASSED WITH WARNINGS${NC}"
            echo "Arkfile is deployed and functional, but consider addressing warnings."
        fi
        exit 0
    else
        echo -e "${RED}[X] DEPLOYMENT VALIDATION FAILED${NC}"
        echo "Deployment has critical issues that must be resolved."
        echo ""
        echo "Troubleshooting steps:"
        echo "  1. Review failed validations above"
        echo "  2. Check systemd logs: sudo journalctl -u arkfile.service"
        echo "  3. Run health check: sudo ./scripts/health-check.sh -v"
        echo "  4. Verify configuration files and permissions"
        exit 1
    fi
}

# Run main function
main "$@"
