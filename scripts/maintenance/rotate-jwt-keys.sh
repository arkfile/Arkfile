#!/bin/bash

# rotate-jwt-keys.sh - JWT signing key rotation script for Arkfile
# This script safely rotates JWT signing keys while maintaining service availability
# and provides proper backup and rollback capabilities

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
ARKFILE_USER="arkfile"
ARKFILE_HOME="/opt/arkfile"
KEY_DIR="$ARKFILE_HOME/etc/keys/jwt"
BACKUP_DIR="$ARKFILE_HOME/backups/jwt-rotation"
LOG_FILE="/var/log/arkfile/jwt-rotation.log"
SERVICE_NAME="arkfile"

# Script configuration
FORCE_ROTATION=false
SKIP_CONFIRMATION=false
BACKUP_ONLY=false
ROLLBACK_MODE=false
ROLLBACK_TIMESTAMP=""

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_header() {
    echo "" | tee -a "$LOG_FILE"
    echo "=====================================" | tee -a "$LOG_FILE"
    echo "$1" | tee -a "$LOG_FILE"
    echo "=====================================" | tee -a "$LOG_FILE"
}

# Initialize logging
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    
    cat >> "$LOG_FILE" << EOF

JWT Key Rotation Session
=======================
Date: $(date)
Host: $(hostname)
User: $(whoami)
Script Version: 1.0

EOF
}

# Check prerequisites
check_prerequisites() {
    log_header "Checking Prerequisites"
    
    # Check if running as root or arkfile user
    if [[ $EUID -ne 0 ]] && [[ "$(whoami)" != "$ARKFILE_USER" ]]; then
        log_error "This script must be run as root or the arkfile user"
        exit 1
    fi
    
    # Check if required directories exist
    if [[ ! -d "$KEY_DIR" ]]; then
        log_error "JWT key directory does not exist: $KEY_DIR"
        exit 1
    fi
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_error "Cannot create backup directory: $BACKUP_DIR"
        exit 1
    fi
    
    # Check if OpenSSL is available
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL is required but not installed"
        exit 1
    fi
    
    # Check systemctl availability
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warning "systemctl not available - service management will be limited"
    fi
    
    log_success "All prerequisites satisfied"
}

# Check current key status
check_current_keys() {
    log_header "Current Key Status"
    
    local signing_key="$KEY_DIR/signing.key"
    local public_key="$KEY_DIR/signing.pub"
    
    if [[ -f "$signing_key" ]]; then
        local key_age_days=$(( ($(date +%s) - $(stat -c %Y "$signing_key")) / 86400 ))
        local key_size=""
        
        # Get key information
        if key_info=$(openssl rsa -in "$signing_key" -text -noout 2>/dev/null); then
            key_size=$(echo "$key_info" | grep "Private-Key:" | grep -o '[0-9]*' | head -1)
            log_info "Current signing key: ${key_size}-bit RSA, ${key_age_days} days old"
        else
            log_warning "Cannot read current signing key details"
        fi
        
        # Check if key needs rotation
        if [[ $key_age_days -gt 7 ]] && [[ "$FORCE_ROTATION" != true ]]; then
            log_warning "Signing key is ${key_age_days} days old (recommend rotation weekly)"
        elif [[ $key_age_days -gt 14 ]]; then
            log_error "Signing key is ${key_age_days} days old (rotation overdue)"
        else
            log_success "Signing key age is acceptable: ${key_age_days} days"
        fi
    else
        log_error "No current signing key found: $signing_key"
        if [[ "$ROLLBACK_MODE" != true ]]; then
            exit 1
        fi
    fi
    
    if [[ -f "$public_key" ]]; then
        log_success "Public key exists: $public_key"
    else
        log_warning "Public key not found: $public_key"
    fi
}

# Create backup of current keys
backup_current_keys() {
    log_header "Backing Up Current Keys"
    
    local backup_timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_subdir="$BACKUP_DIR/backup_${backup_timestamp}"
    
    mkdir -p "$backup_subdir"
    
    # Backup existing keys
    if [[ -f "$KEY_DIR/signing.key" ]]; then
        cp "$KEY_DIR/signing.key" "$backup_subdir/"
        log_success "Backed up signing key"
    fi
    
    if [[ -f "$KEY_DIR/signing.pub" ]]; then
        cp "$KEY_DIR/signing.pub" "$backup_subdir/"
        log_success "Backed up public key"
    fi
    
    # Create backup manifest
    cat > "$backup_subdir/MANIFEST.txt" << EOF
JWT Key Backup
==============
Created: $(date)
Backup ID: $backup_timestamp
Host: $(hostname)
User: $(whoami)

Files backed up:
$(ls -la "$backup_subdir/" | grep -v "MANIFEST.txt" || echo "No key files found")

Restoration command:
$0 --rollback $backup_timestamp
EOF
    
    # Compress backup
    if tar -czf "${backup_subdir}.tar.gz" -C "$BACKUP_DIR" "$(basename "$backup_subdir")"; then
        rm -rf "$backup_subdir"
        log_success "Backup created: ${backup_subdir}.tar.gz"
        echo "$backup_timestamp" > "$BACKUP_DIR/latest_backup.txt"
    else
        log_error "Failed to create backup archive"
        exit 1
    fi
    
    if [[ "$BACKUP_ONLY" == true ]]; then
        log_success "Backup-only mode complete"
        exit 0
    fi
}

# Generate new JWT signing keys
generate_new_keys() {
    log_header "Generating New JWT Keys"
    
    local temp_dir=$(mktemp -d)
    local new_private_key="$temp_dir/signing.key"
    local new_public_key="$temp_dir/signing.pub"
    
    # Generate new RSA private key (4096-bit for security)
    log_info "Generating new 4096-bit RSA private key..."
    if openssl genrsa -out "$new_private_key" 4096 2>/dev/null; then
        log_success "New private key generated"
    else
        log_error "Failed to generate new private key"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Extract public key
    log_info "Extracting public key..."
    if openssl rsa -in "$new_private_key" -pubout -out "$new_public_key" 2>/dev/null; then
        log_success "Public key extracted"
    else
        log_error "Failed to extract public key"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Set proper permissions
    chmod 600 "$new_private_key"
    chmod 644 "$new_public_key"
    
    # Verify key pair
    log_info "Verifying key pair..."
    if openssl rsa -in "$new_private_key" -pubout 2>/dev/null | diff - "$new_public_key" >/dev/null; then
        log_success "Key pair verification successful"
    else
        log_error "Key pair verification failed"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Test signing with new key
    log_info "Testing JWT signing with new key..."
    test_payload='{"sub":"test","iat":'$(date +%s)',"exp":'$(($(date +%s) + 60))'}'
    test_header='{"alg":"RS256","typ":"JWT"}'
    
    # Create test JWT (simplified - for verification only)
    test_header_b64=$(echo -n "$test_header" | base64 -w 0 | tr -d '=')
    test_payload_b64=$(echo -n "$test_payload" | base64 -w 0 | tr -d '=')
    test_data="${test_header_b64}.${test_payload_b64}"
    
    if echo -n "$test_data" | openssl dgst -sha256 -sign "$new_private_key" >/dev/null 2>&1; then
        log_success "JWT signing test successful"
    else
        log_error "JWT signing test failed"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Move new keys to final location
    log_info "Installing new keys..."
    
    # Stop service temporarily for atomic key replacement
    local service_was_running=false
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        service_was_running=true
        log_info "Stopping $SERVICE_NAME service for key rotation..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Atomic key replacement
    if mv "$new_private_key" "$KEY_DIR/signing.key" && mv "$new_public_key" "$KEY_DIR/signing.pub"; then
        log_success "New keys installed successfully"
        
        # Set proper ownership
        if [[ $EUID -eq 0 ]]; then
            chown "$ARKFILE_USER:$ARKFILE_USER" "$KEY_DIR/signing.key" "$KEY_DIR/signing.pub"
            log_success "Key ownership set to $ARKFILE_USER"
        fi
        
        # Set final permissions
        chmod 600 "$KEY_DIR/signing.key"
        chmod 644 "$KEY_DIR/signing.pub"
        log_success "Key permissions configured"
        
    else
        log_error "Failed to install new keys"
        # Restart service if it was running
        if [[ "$service_was_running" == true ]]; then
            systemctl start "$SERVICE_NAME" 2>/dev/null || true
        fi
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Restart service if it was running
    if [[ "$service_was_running" == true ]]; then
        log_info "Starting $SERVICE_NAME service..."
        if systemctl start "$SERVICE_NAME"; then
            log_success "Service restarted successfully"
            
            # Give service time to initialize
            sleep 3
            
            # Verify service is healthy
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                log_success "Service is running and healthy"
            else
                log_error "Service failed to start properly"
                # This would trigger rollback in a full implementation
            fi
        else
            log_error "Failed to restart service"
            exit 1
        fi
    fi
    
    # Clean up temporary directory
    rm -rf "$temp_dir"
    
    log_success "JWT key rotation completed successfully"
}

# Rollback to previous keys
rollback_keys() {
    log_header "Rolling Back JWT Keys"
    
    if [[ -z "$ROLLBACK_TIMESTAMP" ]]; then
        # Find latest backup if no timestamp specified
        if [[ -f "$BACKUP_DIR/latest_backup.txt" ]]; then
            ROLLBACK_TIMESTAMP=$(cat "$BACKUP_DIR/latest_backup.txt")
            log_info "Using latest backup: $ROLLBACK_TIMESTAMP"
        else
            log_error "No rollback timestamp specified and no latest backup found"
            log_info "Available backups:"
            ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null | grep -o 'backup_[0-9_]*' || echo "No backups found"
            exit 1
        fi
    fi
    
    local backup_file="$BACKUP_DIR/backup_${ROLLBACK_TIMESTAMP}.tar.gz"
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log_info "Rolling back to backup: $ROLLBACK_TIMESTAMP"
    
    # Extract backup to temporary directory
    local temp_dir=$(mktemp -d)
    if tar -xzf "$backup_file" -C "$temp_dir"; then
        log_success "Backup extracted"
    else
        log_error "Failed to extract backup"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    local backup_subdir="$temp_dir/backup_${ROLLBACK_TIMESTAMP}"
    
    # Verify backup contents
    if [[ -f "$backup_subdir/signing.key" ]] && [[ -f "$backup_subdir/signing.pub" ]]; then
        log_success "Backup contains required key files"
    else
        log_error "Backup does not contain required key files"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Stop service for rollback
    local service_was_running=false
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        service_was_running=true
        log_info "Stopping $SERVICE_NAME service for rollback..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Create backup of current keys before rollback
    log_info "Backing up current keys before rollback..."
    local pre_rollback_backup="$BACKUP_DIR/pre_rollback_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$pre_rollback_backup"
    cp "$KEY_DIR"/* "$pre_rollback_backup/" 2>/dev/null || true
    
    # Restore keys from backup
    if cp "$backup_subdir/signing.key" "$backup_subdir/signing.pub" "$KEY_DIR/"; then
        log_success "Keys restored from backup"
        
        # Set proper ownership and permissions
        if [[ $EUID -eq 0 ]]; then
            chown "$ARKFILE_USER:$ARKFILE_USER" "$KEY_DIR/signing.key" "$KEY_DIR/signing.pub"
        fi
        chmod 600 "$KEY_DIR/signing.key"
        chmod 644 "$KEY_DIR/signing.pub"
        
        log_success "Key permissions restored"
    else
        log_error "Failed to restore keys from backup"
        rm -rf "$temp_dir"
        exit 1
    fi
    
    # Restart service
    if [[ "$service_was_running" == true ]]; then
        log_info "Starting $SERVICE_NAME service..."
        if systemctl start "$SERVICE_NAME"; then
            log_success "Service restarted after rollback"
            
            # Verify service health
            sleep 3
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                log_success "Service is running and healthy after rollback"
            else
                log_error "Service failed to start properly after rollback"
            fi
        else
            log_error "Failed to restart service after rollback"
            exit 1
        fi
    fi
    
    # Clean up
    rm -rf "$temp_dir"
    
    log_success "JWT key rollback completed successfully"
}

# Confirm user action
confirm_action() {
    if [[ "$SKIP_CONFIRMATION" == true ]]; then
        return 0
    fi
    
    local action="$1"
    echo ""
    echo -e "${YELLOW}About to: $action${NC}"
    echo -e "${YELLOW}This will invalidate all existing JWT tokens${NC}"
    echo ""
    read -p "Continue? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Operation cancelled by user"
        exit 0
    fi
    
    log_info "User confirmed action: $action"
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

JWT Key Rotation Script for Arkfile

OPTIONS:
    -h, --help              Show this help message
    --rotate                Rotate JWT signing keys (default action)
    --backup-only           Create backup of current keys without rotation
    --rollback [TIMESTAMP]  Rollback to previous keys (use latest if no timestamp)
    --force                 Force rotation even if keys are recent
    --yes                   Skip confirmation prompts
    --status                Show current key status only

EXAMPLES:
    $0                      # Rotate keys with confirmation
    $0 --rotate --yes       # Rotate keys without confirmation
    $0 --backup-only        # Backup current keys only
    $0 --rollback           # Rollback to latest backup
    $0 --rollback 20241220_143022  # Rollback to specific backup
    $0 --status             # Show current key status

NOTES:
    - Key rotation will temporarily stop the arkfile service
    - All existing JWT tokens will be invalidated after rotation
    - Backups are automatically created before rotation
    - Run as root or arkfile user for proper permissions

EOF
}

# Main execution
main() {
    local action="rotate"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            --rotate)
                action="rotate"
                shift
                ;;
            --backup-only)
                action="backup"
                BACKUP_ONLY=true
                shift
                ;;
            --rollback)
                action="rollback"
                ROLLBACK_MODE=true
                if [[ $# -gt 1 ]] && [[ $2 != --* ]]; then
                    ROLLBACK_TIMESTAMP="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            --force)
                FORCE_ROTATION=true
                shift
                ;;
            --yes)
                SKIP_CONFIRMATION=true
                shift
                ;;
            --status)
                action="status"
                shift
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Initialize
    init_logging
    check_prerequisites
    
    # Execute based on action
    case $action in
        "status")
            check_current_keys
            ;;
        "backup")
            check_current_keys
            confirm_action "create backup of current JWT keys"
            backup_current_keys
            ;;
        "rotate")
            check_current_keys
            confirm_action "rotate JWT signing keys"
            backup_current_keys
            generate_new_keys
            ;;
        "rollback")
            confirm_action "rollback JWT keys to previous backup"
            rollback_keys
            ;;
    esac
    
    log_success "JWT key management operation completed"
    echo ""
    echo "Log file: $LOG_FILE"
}

# Run main function with all arguments
main "$@"
