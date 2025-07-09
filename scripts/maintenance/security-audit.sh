#!/bin/bash

# security-audit.sh - Comprehensive security audit script for Arkfile
# This script performs a thorough security audit of the Arkfile deployment
# including cryptographic key health, configuration security, and operational readiness

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ARKFILE_USER="arkfile"
ARKFILE_HOME="/opt/arkfile"
KEY_DIR="$ARKFILE_HOME/etc/keys"
TLS_DIR="$ARKFILE_HOME/etc/tls"
CONFIG_DIR="$ARKFILE_HOME/etc"
LOG_DIR="/var/log/arkfile"
AUDIT_LOG="/var/log/arkfile/security-audit.log"

# Audit results
AUDIT_PASSED=0
AUDIT_WARNINGS=0
AUDIT_FAILURES=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$AUDIT_LOG"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$AUDIT_LOG"
    ((AUDIT_PASSED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$AUDIT_LOG"
    ((AUDIT_WARNINGS++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$AUDIT_LOG"
    ((AUDIT_FAILURES++))
}

log_header() {
    echo "" | tee -a "$AUDIT_LOG"
    echo "=================================" | tee -a "$AUDIT_LOG"
    echo "$1" | tee -a "$AUDIT_LOG"
    echo "=================================" | tee -a "$AUDIT_LOG"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_info "Running security audit as root - full system access available"
        return 0
    else
        log_warning "Not running as root - some checks may be limited"
        return 1
    fi
}

# Initialize audit log
init_audit_log() {
    mkdir -p "$(dirname "$AUDIT_LOG")"
    
    # Create audit log header
    cat > "$AUDIT_LOG" << EOF
Arkfile Security Audit Report
============================
Date: $(date)
Host: $(hostname)
User: $(whoami)
Audit Script Version: 1.0

EOF
}

# Check system security basics
audit_system_security() {
    log_header "System Security Audit"
    
    # Check if Arkfile user exists
    if id "$ARKFILE_USER" >/dev/null 2>&1; then
        log_success "Arkfile service user '$ARKFILE_USER' exists"
        
        # Check user shell (should be nologin or false)
        user_shell=$(getent passwd "$ARKFILE_USER" | cut -d: -f7)
        if [[ "$user_shell" == "/sbin/nologin" || "$user_shell" == "/bin/false" || "$user_shell" == "/usr/sbin/nologin" ]]; then
            log_success "Arkfile user has secure shell: $user_shell"
        else
            log_warning "Arkfile user shell should be nologin: $user_shell"
        fi
        
        # Check user home directory
        user_home=$(getent passwd "$ARKFILE_USER" | cut -d: -f6)
        if [[ "$user_home" == "$ARKFILE_HOME" ]]; then
            log_success "Arkfile user home directory is correct: $user_home"
        else
            log_warning "Arkfile user home directory: $user_home (expected: $ARKFILE_HOME)"
        fi
    else
        log_failure "Arkfile service user '$ARKFILE_USER' does not exist"
    fi
    
    # Check directory permissions
    if [[ -d "$ARKFILE_HOME" ]]; then
        dir_perms=$(stat -c "%a" "$ARKFILE_HOME")
        dir_owner=$(stat -c "%U" "$ARKFILE_HOME")
        
        if [[ "$dir_owner" == "$ARKFILE_USER" ]]; then
            log_success "Arkfile home directory owned by correct user: $dir_owner"
        else
            log_failure "Arkfile home directory owned by: $dir_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$dir_perms" == "750" || "$dir_perms" == "700" ]]; then
            log_success "Arkfile home directory has secure permissions: $dir_perms"
        else
            log_warning "Arkfile home directory permissions: $dir_perms (recommended: 750 or 700)"
        fi
    else
        log_failure "Arkfile home directory does not exist: $ARKFILE_HOME"
    fi
    
    # Check if SELinux is enabled
    if command -v getenforce >/dev/null 2>&1; then
        selinux_status=$(getenforce)
        if [[ "$selinux_status" == "Enforcing" ]]; then
            log_success "SELinux is enforcing"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            log_warning "SELinux is in permissive mode (consider enforcing)"
        else
            log_warning "SELinux is disabled"
        fi
    else
        log_info "SELinux not available on this system"
    fi
    
    # Check firewall status
    if systemctl is-active --quiet firewalld; then
        log_success "Firewalld is active"
    elif systemctl is-active --quiet ufw; then
        log_success "UFW firewall is active"
    elif systemctl is-active --quiet iptables; then
        log_success "iptables service is active"
    else
        log_warning "No active firewall service detected"
    fi
}

# Audit cryptographic keys
audit_cryptographic_keys() {
    log_header "Cryptographic Key Audit"
    
    # Check key directory structure
    if [[ -d "$KEY_DIR" ]]; then
        log_success "Key directory exists: $KEY_DIR"
        
        key_dir_perms=$(stat -c "%a" "$KEY_DIR")
        key_dir_owner=$(stat -c "%U" "$KEY_DIR")
        
        if [[ "$key_dir_owner" == "$ARKFILE_USER" ]]; then
            log_success "Key directory owned by correct user: $key_dir_owner"
        else
            log_failure "Key directory owned by: $key_dir_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$key_dir_perms" == "700" ]]; then
            log_success "Key directory has secure permissions: $key_dir_perms"
        else
            log_failure "Key directory permissions: $key_dir_perms (required: 700)"
        fi
    else
        log_failure "Key directory does not exist: $KEY_DIR"
        return
    fi
    
    # Check OPAQUE server keys
    opaque_key_file="$KEY_DIR/opaque/server.key"
    if [[ -f "$opaque_key_file" ]]; then
        log_success "OPAQUE server key file exists"
        
        key_perms=$(stat -c "%a" "$opaque_key_file")
        key_owner=$(stat -c "%U" "$opaque_key_file")
        
        if [[ "$key_owner" == "$ARKFILE_USER" ]]; then
            log_success "OPAQUE server key owned by correct user"
        else
            log_failure "OPAQUE server key owned by: $key_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$key_perms" == "600" ]]; then
            log_success "OPAQUE server key has secure permissions: $key_perms"
        else
            log_failure "OPAQUE server key permissions: $key_perms (required: 600)"
        fi
        
        # Check key age
        key_age_days=$(( ($(date +%s) - $(stat -c %Y "$opaque_key_file")) / 86400 ))
        if [[ $key_age_days -lt 30 ]]; then
            log_success "OPAQUE server key is recent ($key_age_days days old)"
        elif [[ $key_age_days -lt 90 ]]; then
            log_warning "OPAQUE server key is $key_age_days days old (consider rotation)"
        else
            log_failure "OPAQUE server key is $key_age_days days old (rotation overdue)"
        fi
    else
        log_failure "OPAQUE server key file not found: $opaque_key_file"
    fi
    
    # Check JWT signing key
    jwt_key_file="$KEY_DIR/jwt/signing.key"
    if [[ -f "$jwt_key_file" ]]; then
        log_success "JWT signing key file exists"
        
        key_perms=$(stat -c "%a" "$jwt_key_file")
        key_owner=$(stat -c "%U" "$jwt_key_file")
        
        if [[ "$key_owner" == "$ARKFILE_USER" ]]; then
            log_success "JWT signing key owned by correct user"
        else
            log_failure "JWT signing key owned by: $key_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$key_perms" == "600" ]]; then
            log_success "JWT signing key has secure permissions: $key_perms"
        else
            log_failure "JWT signing key permissions: $key_perms (required: 600)"
        fi
        
        # Check key age (JWT keys should be rotated more frequently)
        key_age_days=$(( ($(date +%s) - $(stat -c %Y "$jwt_key_file")) / 86400 ))
        if [[ $key_age_days -lt 7 ]]; then
            log_success "JWT signing key is recent ($key_age_days days old)"
        elif [[ $key_age_days -lt 14 ]]; then
            log_warning "JWT signing key is $key_age_days days old (consider rotation)"
        else
            log_failure "JWT signing key is $key_age_days days old (rotation recommended)"
        fi
    else
        log_failure "JWT signing key file not found: $jwt_key_file"
    fi
    
    # Check Entity ID master secret
    entity_key_file="$KEY_DIR/entity_id/master.key"
    if [[ -f "$entity_key_file" ]]; then
        log_success "Entity ID master secret file exists"
        
        key_perms=$(stat -c "%a" "$entity_key_file")
        key_owner=$(stat -c "%U" "$entity_key_file")
        
        if [[ "$key_owner" == "$ARKFILE_USER" ]]; then
            log_success "Entity ID master secret owned by correct user"
        else
            log_failure "Entity ID master secret owned by: $key_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$key_perms" == "600" ]]; then
            log_success "Entity ID master secret has secure permissions: $key_perms"
        else
            log_failure "Entity ID master secret permissions: $key_perms (required: 600)"
        fi
    else
        log_failure "Entity ID master secret file not found: $entity_key_file"
    fi
}

# Audit TLS certificates
audit_tls_certificates() {
    log_header "TLS Certificate Audit"
    
    if [[ -d "$TLS_DIR" ]]; then
        log_success "TLS directory exists: $TLS_DIR"
        
        tls_dir_perms=$(stat -c "%a" "$TLS_DIR")
        tls_dir_owner=$(stat -c "%U" "$TLS_DIR")
        
        if [[ "$tls_dir_owner" == "$ARKFILE_USER" ]]; then
            log_success "TLS directory owned by correct user: $tls_dir_owner"
        else
            log_failure "TLS directory owned by: $tls_dir_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$tls_dir_perms" == "755" || "$tls_dir_perms" == "750" ]]; then
            log_success "TLS directory has appropriate permissions: $tls_dir_perms"
        else
            log_warning "TLS directory permissions: $tls_dir_perms (recommended: 755 or 750)"
        fi
    else
        log_failure "TLS directory does not exist: $TLS_DIR"
        return
    fi
    
    # Check certificates
    for cert_name in "server" "minio" "rqlite"; do
        cert_file="$TLS_DIR/${cert_name}.crt"
        key_file="$TLS_DIR/${cert_name}.key"
        
        if [[ -f "$cert_file" ]]; then
            log_success "$cert_name certificate exists"
            
            # Check certificate expiry
            if command -v openssl >/dev/null 2>&1; then
                if expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null); then
                    expiry_epoch=$(date -d "${expiry_date#notAfter=}" +%s)
                    days_until_expiry=$(( (expiry_epoch - $(date +%s)) / 86400 ))
                    
                    if [[ $days_until_expiry -gt 30 ]]; then
                        log_success "$cert_name certificate expires in $days_until_expiry days"
                    elif [[ $days_until_expiry -gt 7 ]]; then
                        log_warning "$cert_name certificate expires in $days_until_expiry days"
                    else
                        log_failure "$cert_name certificate expires in $days_until_expiry days (renewal urgent)"
                    fi
                else
                    log_warning "Could not parse $cert_name certificate expiry"
                fi
            else
                log_info "OpenSSL not available - cannot check certificate expiry"
            fi
        else
            log_failure "$cert_name certificate not found: $cert_file"
        fi
        
        if [[ -f "$key_file" ]]; then
            key_perms=$(stat -c "%a" "$key_file")
            key_owner=$(stat -c "%U" "$key_file")
            
            if [[ "$key_owner" == "$ARKFILE_USER" ]]; then
                log_success "$cert_name private key owned by correct user"
            else
                log_failure "$cert_name private key owned by: $key_owner (expected: $ARKFILE_USER)"
            fi
            
            if [[ "$key_perms" == "600" ]]; then
                log_success "$cert_name private key has secure permissions: $key_perms"
            else
                log_failure "$cert_name private key permissions: $key_perms (required: 600)"
            fi
        else
            log_failure "$cert_name private key not found: $key_file"
        fi
    done
}

# Audit service configuration
audit_service_configuration() {
    log_header "Service Configuration Audit"
    
    # Check systemd service files
    for service in "arkfile" "rqlite" "minio"; do
        service_file="/etc/systemd/system/${service}.service"
        if [[ -f "$service_file" ]]; then
            log_success "Systemd service file exists: $service"
            
            # Check service status
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                log_success "Service $service is enabled"
            else
                log_warning "Service $service is not enabled"
            fi
            
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_success "Service $service is active"
            else
                log_warning "Service $service is not active"
            fi
            
            # Check for security settings in service file
            if grep -q "NoNewPrivileges=true" "$service_file"; then
                log_success "Service $service has NoNewPrivileges enabled"
            else
                log_warning "Service $service should have NoNewPrivileges=true"
            fi
            
            if grep -q "PrivateTmp=true" "$service_file"; then
                log_success "Service $service has PrivateTmp enabled"
            else
                log_warning "Service $service should have PrivateTmp=true"
            fi
        else
            log_failure "Systemd service file not found: $service"
        fi
    done
    
    # Check configuration files
    config_file="$CONFIG_DIR/arkfile.conf"
    if [[ -f "$config_file" ]]; then
        log_success "Main configuration file exists"
        
        config_perms=$(stat -c "%a" "$config_file")
        config_owner=$(stat -c "%U" "$config_file")
        
        if [[ "$config_owner" == "$ARKFILE_USER" ]]; then
            log_success "Configuration file owned by correct user"
        else
            log_warning "Configuration file owned by: $config_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$config_perms" == "600" || "$config_perms" == "640" ]]; then
            log_success "Configuration file has secure permissions: $config_perms"
        else
            log_warning "Configuration file permissions: $config_perms (recommended: 600 or 640)"
        fi
        
        # Check for sensitive data in config
        if grep -q "password" "$config_file" 2>/dev/null; then
            log_warning "Configuration file may contain passwords in plaintext"
        fi
        
        if grep -q "secret" "$config_file" 2>/dev/null; then
            log_warning "Configuration file may contain secrets in plaintext"
        fi
    else
        log_warning "Main configuration file not found: $config_file"
    fi
}

# Audit network security
audit_network_security() {
    log_header "Network Security Audit"
    
    # Check listening ports
    if command -v ss >/dev/null 2>&1; then
        log_info "Checking listening ports..."
        
        # Check for HTTPS (should be listening)
        if ss -tlnp | grep -q ":443"; then
            log_success "HTTPS port (443) is listening"
        else
            log_warning "HTTPS port (443) is not listening"
        fi
        
        # Check for HTTP (should NOT be listening in production)
        if ss -tlnp | grep -q ":80"; then
            log_warning "HTTP port (80) is listening (consider HTTPS redirect only)"
        else
            log_success "HTTP port (80) is not listening"
        fi
        
        # Check for database ports (should be restricted)
        for port in "4001" "4002" "9000" "9001"; do
            if ss -tlnp | grep -q ":$port"; then
                log_warning "Database/storage port $port is listening (ensure firewall rules)"
            else
                log_info "Port $port is not listening"
            fi
        done
    else
        log_warning "ss command not available - cannot check listening ports"
    fi
    
    # Check TLS configuration
    if command -v openssl >/dev/null 2>&1; then
        log_info "Checking TLS configuration..."
        
        # This would require the service to be running and accessible
        # In a real audit, we'd test the actual TLS configuration
        log_info "TLS configuration check requires live service testing"
    else
        log_warning "OpenSSL not available - cannot test TLS configuration"
    fi
}

# Audit logging and monitoring
audit_logging_monitoring() {
    log_header "Logging and Monitoring Audit"
    
    # Check log directory
    if [[ -d "$LOG_DIR" ]]; then
        log_success "Log directory exists: $LOG_DIR"
        
        log_dir_perms=$(stat -c "%a" "$LOG_DIR")
        log_dir_owner=$(stat -c "%U" "$LOG_DIR")
        
        if [[ "$log_dir_owner" == "$ARKFILE_USER" ]]; then
            log_success "Log directory owned by correct user"
        else
            log_warning "Log directory owned by: $log_dir_owner (expected: $ARKFILE_USER)"
        fi
        
        if [[ "$log_dir_perms" == "755" || "$log_dir_perms" == "750" ]]; then
            log_success "Log directory has appropriate permissions: $log_dir_perms"
        else
            log_warning "Log directory permissions: $log_dir_perms (recommended: 755 or 750)"
        fi
        
        # Check for log files
        log_files=(
            "$LOG_DIR/arkfile.log"
            "$LOG_DIR/security.log"
            "$LOG_DIR/access.log"
            "$LOG_DIR/error.log"
        )
        
        for log_file in "${log_files[@]}"; do
            if [[ -f "$log_file" ]]; then
                log_success "Log file exists: $(basename "$log_file")"
                
                # Check log file size (warn if very large)
                log_size=$(stat -c "%s" "$log_file")
                log_size_mb=$((log_size / 1024 / 1024))
                
                if [[ $log_size_mb -gt 100 ]]; then
                    log_warning "Log file $(basename "$log_file") is large: ${log_size_mb}MB (consider rotation)"
                elif [[ $log_size_mb -gt 500 ]]; then
                    log_failure "Log file $(basename "$log_file") is very large: ${log_size_mb}MB (requires rotation)"
                fi
            else
                log_info "Log file not found: $(basename "$log_file")"
            fi
        done
    else
        log_failure "Log directory does not exist: $LOG_DIR"
    fi
    
    # Check logrotate configuration
    logrotate_config="/etc/logrotate.d/arkfile"
    if [[ -f "$logrotate_config" ]]; then
        log_success "Logrotate configuration exists"
    else
        log_warning "Logrotate configuration not found (logs may grow indefinitely)"
    fi
    
    # Check journald for systemd services
    for service in "arkfile" "rqlite" "minio"; do
        if journalctl -u "$service" --since "1 day ago" -q --no-pager >/dev/null 2>&1; then
            log_success "Systemd journal available for service: $service"
        else
            log_info "No recent journal entries for service: $service"
        fi
    done
}

# Audit backup and recovery
audit_backup_recovery() {
    log_header "Backup and Recovery Audit"
    
    # Check backup script
    backup_script="$ARKFILE_HOME/scripts/maintenance/backup-keys.sh"
    if [[ -f "$backup_script" ]]; then
        log_success "Backup script exists"
        
        if [[ -x "$backup_script" ]]; then
            log_success "Backup script is executable"
        else
            log_warning "Backup script is not executable"
        fi
    else
        log_failure "Backup script not found: $backup_script"
    fi
    
    # Check for backup location
    backup_dir="/opt/arkfile/backups"
    if [[ -d "$backup_dir" ]]; then
        log_success "Backup directory exists: $backup_dir"
        
        # Check recent backups
        recent_backups=$(find "$backup_dir" -name "*.tar.gz" -mtime -7 | wc -l)
        if [[ $recent_backups -gt 0 ]]; then
            log_success "Found $recent_backups recent backup(s) (within 7 days)"
        else
            log_warning "No recent backups found (within 7 days)"
        fi
    else
        log_warning "Backup directory not found: $backup_dir"
    fi
    
    # Check backup encryption
    if command -v gpg >/dev/null 2>&1; then
        log_success "GPG available for backup encryption"
    else
        log_warning "GPG not available - backups may not be encrypted"
    fi
}

# Generate audit summary
generate_audit_summary() {
    log_header "Audit Summary"
    
    total_checks=$((AUDIT_PASSED + AUDIT_WARNINGS + AUDIT_FAILURES))
    
    log_info "Total checks performed: $total_checks"
    log_info "Passed: $AUDIT_PASSED"
    log_info "Warnings: $AUDIT_WARNINGS"
    log_info "Failures: $AUDIT_FAILURES"
    
    if [[ $AUDIT_FAILURES -eq 0 && $AUDIT_WARNINGS -eq 0 ]]; then
        log_success "Security audit completed successfully - no issues found"
        return 0
    elif [[ $AUDIT_FAILURES -eq 0 ]]; then
        log_warning "Security audit completed with $AUDIT_WARNINGS warning(s)"
        return 1
    else
        log_failure "Security audit completed with $AUDIT_FAILURES failure(s) and $AUDIT_WARNINGS warning(s)"
        return 2
    fi
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Arkfile Security Audit Script

OPTIONS:
    -h, --help          Show this help message
    -q, --quiet         Suppress color output
    -l, --log-only      Only write to log file, no console output
    -f, --full          Perform full audit (default)
    --keys-only         Audit only cryptographic keys
    --network-only      Audit only network security
    --config-only       Audit only configuration

EXAMPLES:
    $0                  # Full security audit
    $0 --keys-only      # Audit only cryptographic keys
    $0 --quiet          # Run audit without color output

EOF
}

# Main execution
main() {
    local audit_type="full"
    local quiet_mode=false
    local log_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -l|--log-only)
                log_only=true
                shift
                ;;
            -f|--full)
                audit_type="full"
                shift
                ;;
            --keys-only)
                audit_type="keys"
                shift
                ;;
            --network-only)
                audit_type="network"
                shift
                ;;
            --config-only)
                audit_type="config"
                shift
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Disable colors if requested
    if [[ "$quiet_mode" == true ]]; then
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        NC=''
    fi
    
    # Initialize audit
    echo "Starting Arkfile Security Audit..."
    init_audit_log
    check_root
    
    # Perform audit based on type
    case $audit_type in
        "full")
            audit_system_security
            audit_cryptographic_keys
            audit_tls_certificates
            audit_service_configuration
            audit_network_security
            audit_logging_monitoring
            audit_backup_recovery
            ;;
        "keys")
            audit_cryptographic_keys
            audit_tls_certificates
            ;;
        "network")
            audit_network_security
            ;;
        "config")
            audit_service_configuration
            ;;
    esac
    
    # Generate summary and exit
    generate_audit_summary
    exit_code=$?
    
    log_info "Audit log saved to: $AUDIT_LOG"
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
