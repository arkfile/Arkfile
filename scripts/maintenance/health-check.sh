#!/bin/bash

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
VERBOSE=false
PRE_INSTALL=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --pre-install)
            PRE_INSTALL=true
            shift
            ;;
        -h|--help)
            echo "Arkfile Health Check Script"
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose     Show detailed output"
            echo "  --pre-install     Run pre-installation checks only"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Global counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Function to print status messages
print_status() {
    local status=$1
    local message=$2
    local details=$3
    
    case $status in
        "PASS")
            echo -e "  ${GREEN}[OK]${NC} ${message}"
            ((CHECKS_PASSED++))
            ;;
        "FAIL")
            echo -e "  ${RED}[X]${NC} ${message}"
            ((CHECKS_FAILED++))
            ;;
        "WARN")
            echo -e "  ${YELLOW}[WARNING]${NC} ${message}"
            ((CHECKS_WARNING++))
            ;;
        "INFO")
            echo -e "  ${BLUE}ℹ${NC} ${message}"
            ;;
    esac
    
    if [ -n "$details" ] && [ "$VERBOSE" = true ]; then
        echo "    ${details}"
    fi
}

# Function to check system requirements
check_system_requirements() {
    echo -e "${BLUE}System Requirements${NC}"
    echo "==================="
    
    # Check OS
    if [ -f /etc/os-release ]; then
        OS_NAME=$(grep '^NAME=' /etc/os-release | cut -d'"' -f2)
        print_status "INFO" "Operating System: ${OS_NAME}"
    else
        print_status "WARN" "Cannot determine operating system"
    fi
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        print_status "FAIL" "Script must be run with sudo privileges"
        return 1
    else
        print_status "PASS" "Running with appropriate privileges"
    fi
    
    # Check required commands
    local required_commands=("openssl" "systemctl" "useradd" "groupadd" "install" "tar" "sha256sum")
    for cmd in "${required_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            print_status "PASS" "Command available: $cmd"
        else
            print_status "FAIL" "Required command missing: $cmd"
        fi
    done
    
    # Check OpenSSL version
    if command -v openssl >/dev/null 2>&1; then
        OPENSSL_VERSION=$(openssl version | cut -d' ' -f2)
        print_status "INFO" "OpenSSL version: ${OPENSSL_VERSION}"
    fi
    
    # Check available disk space
    ROOT_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [ "$ROOT_SPACE" -gt 1048576 ]; then  # 1GB in KB
        print_status "PASS" "Sufficient disk space available"
    else
        print_status "WARN" "Low disk space: $(( ROOT_SPACE / 1024 ))MB available"
    fi
    
    echo ""
}

# Function to check user and group setup
check_user_setup() {
    echo -e "${BLUE}User and Group Setup${NC}"
    echo "==================="
    
    # Check if arkfile group exists
    if getent group "$GROUP" >/dev/null 2>&1; then
        print_status "PASS" "Group '$GROUP' exists"
    else
        if [ "$PRE_INSTALL" = true ]; then
            print_status "INFO" "Group '$GROUP' will be created during installation"
        else
            print_status "FAIL" "Group '$GROUP' does not exist"
        fi
    fi
    
    # Check if arkfile user exists
    if getent passwd "$USER" >/dev/null 2>&1; then
        print_status "PASS" "User '$USER' exists"
        
        # Check user properties
        USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
        USER_SHELL=$(getent passwd "$USER" | cut -d: -f7)
        USER_GROUP=$(id -gn "$USER")
        
        if [ "$USER_HOME" = "$ARKFILE_DIR" ]; then
            print_status "PASS" "User home directory correct: $USER_HOME"
        else
            print_status "WARN" "User home directory: $USER_HOME (expected: $ARKFILE_DIR)"
        fi
        
        if [ "$USER_SHELL" = "/sbin/nologin" ]; then
            print_status "PASS" "User shell properly restricted: $USER_SHELL"
        else
            print_status "WARN" "User shell: $USER_SHELL (recommended: /sbin/nologin)"
        fi
        
        if [ "$USER_GROUP" = "$GROUP" ]; then
            print_status "PASS" "User primary group correct: $USER_GROUP"
        else
            print_status "WARN" "User primary group: $USER_GROUP (expected: $GROUP)"
        fi
    else
        if [ "$PRE_INSTALL" = true ]; then
            print_status "INFO" "User '$USER' will be created during installation"
        else
            print_status "FAIL" "User '$USER' does not exist"
        fi
    fi
    
    echo ""
}

# Function to check directory structure
check_directory_structure() {
    echo -e "${BLUE}Directory Structure${NC}"
    echo "==================="
    
    local directories=(
        "$ARKFILE_DIR:755"
        "$ARKFILE_DIR/bin:755"
        "$ARKFILE_DIR/etc:750"
        "$ARKFILE_DIR/etc/keys:700"
        "$ARKFILE_DIR/etc/keys/opaque:700"
        "$ARKFILE_DIR/etc/keys/jwt:700"
        "$ARKFILE_DIR/etc/keys/tls:700"
        "$ARKFILE_DIR/etc/keys/backups:700"
        "$ARKFILE_DIR/var:750"
        "$ARKFILE_DIR/var/lib:750"
        "$ARKFILE_DIR/var/log:750"
        "$ARKFILE_DIR/var/run:755"
        "$ARKFILE_DIR/webroot:755"
    )
    
    for dir_spec in "${directories[@]}"; do
        local dir_path=$(echo "$dir_spec" | cut -d: -f1)
        local expected_perms=$(echo "$dir_spec" | cut -d: -f2)
        
        if [ -d "$dir_path" ]; then
            local actual_perms=$(stat -c "%a" "$dir_path")
            local owner=$(stat -c "%U:%G" "$dir_path")
            
            if [ "$actual_perms" = "$expected_perms" ]; then
                print_status "PASS" "Directory $(basename "$dir_path"): $actual_perms $owner"
            else
                print_status "WARN" "Directory $(basename "$dir_path"): $actual_perms $owner (expected: $expected_perms)"
            fi
        else
            if [ "$PRE_INSTALL" = true ]; then
                print_status "INFO" "Directory $(basename "$dir_path") will be created"
            else
                print_status "FAIL" "Directory missing: $dir_path"
            fi
        fi
    done
    
    echo ""
}

# Function to check cryptographic keys
check_cryptographic_keys() {
    echo -e "${BLUE}Cryptographic Keys${NC}"
    echo "==================="
    
    # OPAQUE keys
    local opaque_keys=(
        "$ARKFILE_DIR/etc/keys/opaque/server_private.key:600"
        "$ARKFILE_DIR/etc/keys/opaque/server_public.key:644"
        "$ARKFILE_DIR/etc/keys/opaque/oprf_seed.key:600"
    )
    
    for key_spec in "${opaque_keys[@]}"; do
        local key_path=$(echo "$key_spec" | cut -d: -f1)
        local expected_perms=$(echo "$key_spec" | cut -d: -f2)
        local key_name=$(basename "$key_path")
        
        if [ -f "$key_path" ]; then
            local actual_perms=$(stat -c "%a" "$key_path")
            local owner=$(stat -c "%U:%G" "$key_path")
            
            if [ "$actual_perms" = "$expected_perms" ] && [ "$owner" = "$USER:$GROUP" ]; then
                print_status "PASS" "OPAQUE key $key_name: $actual_perms $owner"
            else
                print_status "WARN" "OPAQUE key $key_name: $actual_perms $owner (expected: $expected_perms $USER:$GROUP)"
            fi
        else
            print_status "FAIL" "OPAQUE key missing: $key_name"
        fi
    done
    
    # JWT keys
    local jwt_keys=(
        "$ARKFILE_DIR/etc/keys/jwt/current/signing.key:600"
        "$ARKFILE_DIR/etc/keys/jwt/current/public.key:644"
        "$ARKFILE_DIR/etc/keys/jwt/current/metadata.json:644"
    )
    
    for key_spec in "${jwt_keys[@]}"; do
        local key_path=$(echo "$key_spec" | cut -d: -f1)
        local expected_perms=$(echo "$key_spec" | cut -d: -f2)
        local key_name=$(basename "$key_path")
        
        if [ -f "$key_path" ]; then
            local actual_perms=$(stat -c "%a" "$key_path")
            local owner=$(stat -c "%U:%G" "$key_path")
            
            if [ "$actual_perms" = "$expected_perms" ] && [ "$owner" = "$USER:$GROUP" ]; then
                print_status "PASS" "JWT key $key_name: $actual_perms $owner"
            else
                print_status "WARN" "JWT key $key_name: $actual_perms $owner (expected: $expected_perms $USER:$GROUP)"
            fi
        else
            print_status "FAIL" "JWT key missing: $key_name"
        fi
    done
    
    # TLS certificates
    local tls_certs=(
        "$ARKFILE_DIR/etc/keys/tls/ca/ca.crt:644"
        "$ARKFILE_DIR/etc/keys/tls/ca/ca.key:600"
        "$ARKFILE_DIR/etc/keys/tls/rqlite/server.crt:644"
        "$ARKFILE_DIR/etc/keys/tls/rqlite/server.key:600"
        "$ARKFILE_DIR/etc/keys/tls/minio/server.crt:644"
        "$ARKFILE_DIR/etc/keys/tls/minio/server.key:600"
    )
    
    for cert_spec in "${tls_certs[@]}"; do
        local cert_path=$(echo "$cert_spec" | cut -d: -f1)
        local expected_perms=$(echo "$cert_spec" | cut -d: -f2)
        local cert_name=$(basename "$(dirname "$cert_path")")/$(basename "$cert_path")
        
        if [ -f "$cert_path" ]; then
            local actual_perms=$(stat -c "%a" "$cert_path")
            local owner=$(stat -c "%U:%G" "$cert_path")
            
            if [ "$actual_perms" = "$expected_perms" ] && [ "$owner" = "$USER:$GROUP" ]; then
                print_status "PASS" "TLS cert $cert_name: $actual_perms $owner"
                
                # Check certificate expiration
                if [[ "$cert_path" == *.crt ]]; then
                    if openssl x509 -in "$cert_path" -noout -checkend 2592000 >/dev/null 2>&1; then  # 30 days
                        print_status "PASS" "Certificate $cert_name: Not expiring soon"
                    else
                        print_status "WARN" "Certificate $cert_name: Expires within 30 days"
                    fi
                fi
            else
                print_status "WARN" "TLS cert $cert_name: $actual_perms $owner (expected: $expected_perms $USER:$GROUP)"
            fi
        else
            print_status "FAIL" "TLS certificate missing: $cert_name"
        fi
    done
    
    echo ""
}

# Function to check systemd service
check_systemd_service() {
    echo -e "${BLUE}Systemd Service${NC}"
    echo "================"
    
    local service_file="/etc/systemd/system/arkfile.service"
    
    if [ -f "$service_file" ]; then
        print_status "PASS" "Service file exists: $service_file"
        
        # Check if service is enabled
        if systemctl is-enabled arkfile.service >/dev/null 2>&1; then
            print_status "PASS" "Service is enabled"
        else
            print_status "WARN" "Service is not enabled"
        fi
        
        # Check if service is active (only if not pre-install)
        if [ "$PRE_INSTALL" = false ]; then
            if systemctl is-active arkfile.service >/dev/null 2>&1; then
                print_status "PASS" "Service is active"
            else
                print_status "WARN" "Service is not active"
            fi
        fi
    else
        if [ "$PRE_INSTALL" = true ]; then
            print_status "INFO" "Service file will be installed"
        else
            print_status "FAIL" "Service file missing: $service_file"
        fi
    fi
    
    echo ""
}

# Function to check application binary
check_application_binary() {
    echo -e "${BLUE}Application Binary${NC}"
    echo "=================="
    
    local binary_path="$ARKFILE_DIR/bin/arkfile"
    
    if [ -f "$binary_path" ]; then
        local owner=$(stat -c "%U:%G" "$binary_path")
        local perms=$(stat -c "%a" "$binary_path")
        
        print_status "PASS" "Binary exists: $binary_path"
        print_status "INFO" "Binary permissions: $perms $owner"
        
        # Check if binary is executable
        if [ -x "$binary_path" ]; then
            print_status "PASS" "Binary is executable"
        else
            print_status "FAIL" "Binary is not executable"
        fi
    else
        if [ "$PRE_INSTALL" = true ]; then
            print_status "INFO" "Binary will be installed during deployment"
        else
            print_status "FAIL" "Binary missing: $binary_path"
        fi
    fi
    
    echo ""
}

# Main health check function
main() {
    echo -e "${GREEN}Arkfile Health Check${NC}"
    echo "===================="
    echo "Mode: $([ "$PRE_INSTALL" = true ] && echo "Pre-installation" || echo "Post-installation")"
    echo "Verbose: $([ "$VERBOSE" = true ] && echo "Yes" || echo "No")"
    echo ""
    
    # Run checks
    check_system_requirements
    
    # Skip certain checks in pre-install mode
    if [ "$PRE_INSTALL" = false ]; then
        check_user_setup
        check_directory_structure
        check_cryptographic_keys
        check_application_binary
    else
        check_user_setup
        # Only check if directories can be created
        print_status "INFO" "Directory structure checks skipped in pre-install mode"
        print_status "INFO" "Cryptographic key checks skipped in pre-install mode"
        print_status "INFO" "Application binary checks skipped in pre-install mode"
        echo ""
    fi
    
    check_systemd_service
    
    # Summary
    echo -e "${BLUE}Health Check Summary${NC}"
    echo "==================="
    echo -e "  ${GREEN}[OK]${NC} Passed: $CHECKS_PASSED"
    echo -e "  ${YELLOW}[WARNING]${NC} Warnings: $CHECKS_WARNING"
    echo -e "  ${RED}[X]${NC} Failed: $CHECKS_FAILED"
    echo ""
    
    # Exit code based on failures
    if [ "$CHECKS_FAILED" -gt 0 ]; then
        echo -e "${RED}Health check completed with failures.${NC}"
        if [ "$PRE_INSTALL" = false ]; then
            echo "Please address the failed checks before proceeding."
        fi
        exit 1
    elif [ "$CHECKS_WARNING" -gt 0 ]; then
        echo -e "${YELLOW}Health check completed with warnings.${NC}"
        echo "Consider addressing the warnings for optimal security."
        exit 0
    else
        echo -e "${GREEN}Health check completed successfully!${NC}"
        if [ "$PRE_INSTALL" = true ]; then
            echo "System is ready for Arkfile installation."
        else
            echo "Arkfile installation is healthy and ready for use."
        fi
        exit 0
    fi
}

# Run main function
main "$@"
