#!/bin/bash

# emergency-procedures.sh - Emergency response procedures for Arkfile security incidents
# This script provides step-by-step guidance for handling various security emergencies
# including compromised keys, suspicious activity, and system breaches

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
KEY_DIR="$ARKFILE_HOME/etc/keys"
TLS_DIR="$ARKFILE_HOME/etc/tls"
LOG_DIR="/var/log/arkfile"
INCIDENT_LOG="/var/log/arkfile/incident-response.log"
BACKUP_DIR="/opt/arkfile/emergency-backups"

# Logging functions
log_emergency() {
    echo -e "${RED}${BOLD}[EMERGENCY]${NC} $1" | tee -a "$INCIDENT_LOG"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" | tee -a "$INCIDENT_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$INCIDENT_LOG"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$INCIDENT_LOG"
}

log_action() {
    echo -e "${GREEN}[ACTION]${NC} $1" | tee -a "$INCIDENT_LOG"
}

log_header() {
    echo "" | tee -a "$INCIDENT_LOG"
    echo "========================================" | tee -a "$INCIDENT_LOG"
    echo "$1" | tee -a "$INCIDENT_LOG"
    echo "========================================" | tee -a "$INCIDENT_LOG"
}

# Initialize incident log
init_incident_log() {
    mkdir -p "$(dirname "$INCIDENT_LOG")"
    mkdir -p "$BACKUP_DIR"
    
    cat > "$INCIDENT_LOG" << EOF
Arkfile Emergency Response Log
=============================
Date: $(date)
Host: $(hostname)
User: $(whoami)
Emergency Response Script Version: 1.0

EOF

    log_emergency "Emergency response procedures initiated"
}

# Confirm critical actions
confirm_action() {
    local action="$1"
    echo ""
    echo -e "${RED}${BOLD}CRITICAL ACTION REQUIRED:${NC}"
    echo -e "${YELLOW}$action${NC}"
    echo ""
    read -p "Type 'CONFIRM' to proceed (or anything else to abort): " confirmation
    
    if [[ "$confirmation" != "CONFIRM" ]]; then
        log_warning "Action aborted by user: $action"
        return 1
    fi
    
    log_action "User confirmed critical action: $action"
    return 0
}

# Emergency service shutdown
emergency_shutdown() {
    log_header "EMERGENCY SERVICE SHUTDOWN"
    
    log_emergency "Performing emergency shutdown of all Arkfile services"
    
    if confirm_action "SHUT DOWN ALL ARKFILE SERVICES - This will make the system unavailable"; then
        # Stop main service
        if systemctl is-active --quiet arkfile; then
            log_action "Stopping arkfile service..."
            systemctl stop arkfile
            log_action "Arkfile service stopped"
        else
            log_info "Arkfile service was not running"
        fi
        
        # Stop supporting services
        for service in "minio" "rqlite"; do
            if systemctl is-active --quiet "$service"; then
                log_action "Stopping $service..."
                systemctl stop "$service"
                log_action "$service stopped"
            else
                log_info "$service was not running"
            fi
        done
        
        # Block network access at firewall level
        if command -v firewall-cmd >/dev/null 2>&1; then
            log_action "Blocking external access via firewalld..."
            firewall-cmd --panic-on 2>/dev/null || true
            log_action "Firewall panic mode activated"
        elif command -v ufw >/dev/null 2>&1; then
            log_action "Denying all incoming connections via ufw..."
            ufw --force reset >/dev/null 2>&1 || true
            ufw --force enable >/dev/null 2>&1 || true
            ufw default deny incoming >/dev/null 2>&1 || true
            log_action "UFW configured to deny all incoming"
        fi
        
        log_emergency "EMERGENCY SHUTDOWN COMPLETE - System is now offline"
        echo ""
        echo -e "${RED}${BOLD}SYSTEM IS NOW OFFLINE${NC}"
        echo -e "${YELLOW}To restore service, use: systemctl start arkfile${NC}"
        echo -e "${YELLOW}To restore network access, disable firewall panic mode${NC}"
    else
        log_warning "Emergency shutdown cancelled"
    fi
}

# Rotate compromised keys
rotate_compromised_keys() {
    log_header "EMERGENCY KEY ROTATION"
    
    log_emergency "Initiating emergency key rotation procedure"
    
    if ! confirm_action "ROTATE ALL CRYPTOGRAPHIC KEYS - This will invalidate all user sessions"; then
        log_warning "Key rotation cancelled"
        return 1
    fi
    
    # Create emergency backup
    backup_timestamp=$(date +"%Y%m%d_%H%M%S")
    emergency_backup_file="$BACKUP_DIR/emergency_backup_${backup_timestamp}.tar.gz"
    
    log_action "Creating emergency backup of current keys..."
    if tar -czf "$emergency_backup_file" -C "$ARKFILE_HOME" etc/ 2>/dev/null; then
        log_action "Emergency backup created: $emergency_backup_file"
    else
        log_critical "Failed to create emergency backup - proceeding anyway"
    fi
    
    # Stop services before key rotation
    log_action "Stopping services for key rotation..."
    systemctl stop arkfile 2>/dev/null || true
    
    # Rotate OPAQUE server keys
    log_action "Rotating OPAQUE server keys..."
    opaque_key_dir="$KEY_DIR/opaque"
    if [[ -d "$opaque_key_dir" ]]; then
        mv "$opaque_key_dir/server.key" "$opaque_key_dir/server.key.compromised.$(date +%s)" 2>/dev/null || true
        
        # Generate new OPAQUE server key
        if [[ -f "$ARKFILE_HOME/scripts/setup-opaque-keys.sh" ]]; then
            bash "$ARKFILE_HOME/scripts/setup-opaque-keys.sh" --force 2>/dev/null || true
            log_action "New OPAQUE server keys generated"
        else
            log_critical "OPAQUE key generation script not found"
        fi
    fi
    
    # Rotate JWT signing keys
    log_action "Rotating JWT signing keys..."
    jwt_key_dir="$KEY_DIR/jwt"
    if [[ -d "$jwt_key_dir" ]]; then
        mv "$jwt_key_dir/signing.key" "$jwt_key_dir/signing.key.compromised.$(date +%s)" 2>/dev/null || true
        
        # Generate new JWT signing key
        if [[ -f "$ARKFILE_HOME/scripts/setup-jwt-keys.sh" ]]; then
            bash "$ARKFILE_HOME/scripts/setup-jwt-keys.sh" --force 2>/dev/null || true
            log_action "New JWT signing keys generated"
        else
            log_critical "JWT key generation script not found"
        fi
    fi
    
    # Rotate Entity ID master secret
    log_action "Rotating Entity ID master secret..."
    entity_key_dir="$KEY_DIR/entity_id"
    if [[ -d "$entity_key_dir" ]]; then
        mv "$entity_key_dir/master.key" "$entity_key_dir/master.key.compromised.$(date +%s)" 2>/dev/null || true
        
        # Generate new Entity ID master secret
        openssl rand -base64 64 > "$entity_key_dir/master.key" 2>/dev/null || true
        chown "$ARKFILE_USER:$ARKFILE_USER" "$entity_key_dir/master.key" 2>/dev/null || true
        chmod 600 "$entity_key_dir/master.key" 2>/dev/null || true
        log_action "New Entity ID master secret generated"
    fi
    
    log_emergency "KEY ROTATION COMPLETE - All cryptographic keys have been rotated"
    log_warning "ALL USER SESSIONS ARE NOW INVALID - Users must re-authenticate"
    log_warning "Rate limiting data has been reset - Monitor for abuse"
    
    echo ""
    echo -e "${RED}${BOLD}KEY ROTATION COMPLETE${NC}"
    echo -e "${YELLOW}All users must re-authenticate${NC}"
    echo -e "${YELLOW}Monitor logs for suspicious re-authentication patterns${NC}"
    echo -e "${YELLOW}Emergency backup saved to: $emergency_backup_file${NC}"
}

# Investigate suspicious activity
investigate_suspicious_activity() {
    log_header "SUSPICIOUS ACTIVITY INVESTIGATION"
    
    log_warning "Initiating investigation of suspicious activity"
    
    # Check recent security events
    log_info "Analyzing recent security events..."
    
    if command -v sqlite3 >/dev/null 2>&1; then
        db_file="$ARKFILE_HOME/data/arkfile.db"
        if [[ -f "$db_file" ]]; then
            log_info "Checking authentication failures in last 24 hours..."
            recent_failures=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM security_events WHERE event_type = 'auth_failure' AND created_at > datetime('now', '-24 hours');" 2>/dev/null || echo "0")
            log_info "Authentication failures in last 24 hours: $recent_failures"
            
            log_info "Checking rate limit violations in last 24 hours..."
            rate_limit_violations=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM security_events WHERE event_type = 'rate_limit_violation' AND created_at > datetime('now', '-24 hours');" 2>/dev/null || echo "0")
            log_info "Rate limit violations in last 24 hours: $rate_limit_violations"
            
            if [[ $recent_failures -gt 50 ]]; then
                log_critical "HIGH NUMBER OF AUTHENTICATION FAILURES DETECTED"
                echo -e "${RED}Consider implementing additional access controls${NC}"
            fi
            
            if [[ $rate_limit_violations -gt 10 ]]; then
                log_critical "HIGH NUMBER OF RATE LIMIT VIOLATIONS DETECTED"
                echo -e "${RED}Possible brute force attack in progress${NC}"
            fi
        else
            log_warning "Database file not accessible for analysis"
        fi
    else
        log_warning "SQLite3 not available - cannot analyze security events database"
    fi
    
    # Check system logs for suspicious patterns
    log_info "Checking system logs for suspicious patterns..."
    
    if [[ -f "$LOG_DIR/security.log" ]]; then
        log_info "Analyzing security log for patterns..."
        
        # Check for repeated failed attempts from same source
        recent_suspicious=$(grep "$(date '+%Y-%m-%d')" "$LOG_DIR/security.log" 2>/dev/null | grep -i "fail\|error\|suspicious" | wc -l || echo "0")
        log_info "Suspicious log entries today: $recent_suspicious"
        
        if [[ $recent_suspicious -gt 20 ]]; then
            log_critical "HIGH NUMBER OF SUSPICIOUS LOG ENTRIES DETECTED"
        fi
    else
        log_warning "Security log not found or not accessible"
    fi
    
    # Check for unusual file access patterns
    log_info "Checking for unusual file access patterns..."
    
    # Look for recently modified key files
    if [[ -d "$KEY_DIR" ]]; then
        recent_key_changes=$(find "$KEY_DIR" -type f -mmin -60 2>/dev/null | wc -l || echo "0")
        log_info "Key files modified in last hour: $recent_key_changes"
        
        if [[ $recent_key_changes -gt 0 ]]; then
            log_critical "KEY FILES HAVE BEEN RECENTLY MODIFIED"
            find "$KEY_DIR" -type f -mmin -60 2>/dev/null | while read -r file; do
                log_critical "Recently modified: $file"
            done
        fi
    fi
    
    # Check process list for suspicious activity
    log_info "Checking for suspicious processes..."
    
    # Look for unusual arkfile processes
    arkfile_processes=$(pgrep -f arkfile | wc -l || echo "0")
    log_info "Arkfile-related processes running: $arkfile_processes"
    
    if [[ $arkfile_processes -gt 5 ]]; then
        log_warning "Unusually high number of arkfile processes detected"
    fi
    
    echo ""
    echo -e "${BLUE}INVESTIGATION SUMMARY:${NC}"
    echo -e "Authentication failures (24h): $recent_failures"
    echo -e "Rate limit violations (24h): $rate_limit_violations"
    echo -e "Suspicious log entries (today): $recent_suspicious"
    echo -e "Recent key file changes (1h): $recent_key_changes"
    echo -e "Arkfile processes running: $arkfile_processes"
    echo ""
    echo -e "${YELLOW}Review the incident log for detailed findings: $INCIDENT_LOG${NC}"
}

# Isolate compromised user account
isolate_user_account() {
    log_header "USER ACCOUNT ISOLATION"
    
    local username=""
    echo ""
    read -p "Enter the username of the compromised user account: " username
    
    if [[ -z "$username" ]]; then
        log_warning "No username provided - isolation cancelled"
        return 1
    fi
    
    log_warning "Initiating isolation procedure for user: $username"
    
    if ! confirm_action "ISOLATE USER ACCOUNT: $username - This will disable the account and revoke all tokens"; then
        log_warning "User isolation cancelled"
        return 1
    fi
    
    # Disable user account in database
    if command -v sqlite3 >/dev/null 2>&1; then
        db_file="$ARKFILE_HOME/data/arkfile.db"
        if [[ -f "$db_file" ]]; then
            log_action "Disabling user account in database..."
            
            # Set user as not approved and add security flag
            sqlite3 "$db_file" "UPDATE users SET is_approved = 0, updated_at = datetime('now') WHERE username = '$username';" 2>/dev/null || true
            
            # Revoke all refresh tokens for the user
            sqlite3 "$db_file" "UPDATE refresh_tokens SET revoked = 1, updated_at = datetime('now') WHERE username = '$username';" 2>/dev/null || true
            
            log_action "User account disabled and all tokens revoked"
            
            # Log security event
            sqlite3 "$db_file" "INSERT INTO security_events (event_type, username, details, created_at) VALUES ('user_isolation', '$username', 'Account isolated due to security incident', datetime('now'));" 2>/dev/null || true
            
            log_action "Security event logged for user isolation"
        else
            log_critical "Database not accessible - manual intervention required"
        fi
    else
        log_critical "SQLite3 not available - cannot modify database"
    fi
    
    # Check for any active sessions or processes
    log_info "Checking for active user sessions..."
    
    log_emergency "USER ACCOUNT ISOLATION COMPLETE"
    log_warning "User $username has been isolated and all tokens revoked"
    
    echo ""
    echo -e "${RED}${BOLD}USER ISOLATION COMPLETE${NC}"
    echo -e "${YELLOW}User: $username${NC}"
    echo -e "${YELLOW}Account disabled and all tokens revoked${NC}"
    echo -e "${YELLOW}Monitor for any continued suspicious activity${NC}"
}

# Reset rate limiting data
reset_rate_limiting() {
    log_header "RATE LIMITING RESET"
    
    log_warning "Initiating rate limiting data reset"
    
    if ! confirm_action "RESET ALL RATE LIMITING DATA - This will clear violation history and penalties"; then
        log_warning "Rate limiting reset cancelled"
        return 1
    fi
    
    # Clear rate limiting tables
    if command -v sqlite3 >/dev/null 2>&1; then
        db_file="$ARKFILE_HOME/data/arkfile.db"
        if [[ -f "$db_file" ]]; then
            log_action "Clearing rate limiting state..."
            sqlite3 "$db_file" "DELETE FROM rate_limit_state;" 2>/dev/null || true
            
            log_action "Clearing entity ID mappings..."
            sqlite3 "$db_file" "DELETE FROM entity_id_mappings;" 2>/dev/null || true
            
            log_action "Rate limiting data cleared"
            
            # Log security event
            sqlite3 "$db_file" "INSERT INTO security_events (event_type, details, created_at) VALUES ('rate_limit_reset', 'Rate limiting data reset during emergency response', datetime('now'));" 2>/dev/null || true
            
            log_action "Security event logged for rate limit reset"
        else
            log_critical "Database not accessible - manual intervention required"
        fi
    else
        log_critical "SQLite3 not available - cannot modify database"
    fi
    
    log_emergency "RATE LIMITING RESET COMPLETE"
    log_warning "All rate limiting history has been cleared"
    log_warning "Monitor for potential abuse after reset"
    
    echo ""
    echo -e "${RED}${BOLD}RATE LIMITING RESET COMPLETE${NC}"
    echo -e "${YELLOW}All rate limiting history cleared${NC}"
    echo -e "${YELLOW}Monitor closely for abuse attempts${NC}"
}

# Create forensic snapshot
create_forensic_snapshot() {
    log_header "FORENSIC SNAPSHOT CREATION"
    
    log_info "Creating forensic snapshot for incident analysis"
    
    snapshot_timestamp=$(date +"%Y%m%d_%H%M%S")
    snapshot_dir="$BACKUP_DIR/forensic_snapshot_${snapshot_timestamp}"
    
    log_action "Creating forensic snapshot directory..."
    mkdir -p "$snapshot_dir"
    
    # Copy system state information
    log_action "Capturing system state..."
    
    # Process list
    ps aux > "$snapshot_dir/processes.txt" 2>/dev/null || true
    
    # Network connections
    ss -tuln > "$snapshot_dir/network_connections.txt" 2>/dev/null || true
    netstat -tuln > "$snapshot_dir/netstat.txt" 2>/dev/null || true
    
    # System logs
    if [[ -d "$LOG_DIR" ]]; then
        log_action "Copying application logs..."
        cp -r "$LOG_DIR" "$snapshot_dir/arkfile_logs/" 2>/dev/null || true
    fi
    
    # System journal for arkfile services
    log_action "Capturing systemd journal..."
    journalctl -u arkfile --since "7 days ago" > "$snapshot_dir/arkfile_journal.log" 2>/dev/null || true
    journalctl -u "minio*" --since "7 days ago" > "$snapshot_dir/minio_journal.log" 2>/dev/null || true
    journalctl -u "rqlite*" --since "7 days ago" > "$snapshot_dir/rqlite_journal.log" 2>/dev/null || true
    
    # Database snapshot (if accessible)
    if [[ -f "$ARKFILE_HOME/data/arkfile.db" ]]; then
        log_action "Creating database snapshot..."
        sqlite3 "$ARKFILE_HOME/data/arkfile.db" ".backup '$snapshot_dir/database_snapshot.db'" 2>/dev/null || true
    fi
    
    # Configuration files
    if [[ -d "$ARKFILE_HOME/etc" ]]; then
        log_action "Copying configuration files..."
        cp -r "$ARKFILE_HOME/etc" "$snapshot_dir/config/" 2>/dev/null || true
        
        # Redact sensitive information from copied configs
        if [[ -d "$snapshot_dir/config/keys" ]]; then
            log_action "Redacting sensitive key material..."
            find "$snapshot_dir/config/keys" -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
        fi
    fi
    
    # System information
    log_action "Capturing system information..."
    uname -a > "$snapshot_dir/system_info.txt" 2>/dev/null || true
    df -h > "$snapshot_dir/disk_usage.txt" 2>/dev/null || true
    free -h > "$snapshot_dir/memory_info.txt" 2>/dev/null || true
    uptime > "$snapshot_dir/uptime.txt" 2>/dev/null || true
    
    # Package versions
    if command -v rpm >/dev/null 2>&1; then
        rpm -qa | grep -E "(arkfile|golang|sqlite)" > "$snapshot_dir/packages_rpm.txt" 2>/dev/null || true
    elif command -v dpkg >/dev/null 2>&1; then
        dpkg -l | grep -E "(arkfile|golang|sqlite)" > "$snapshot_dir/packages_dpkg.txt" 2>/dev/null || true
    fi
    
    # Create manifest
    log_action "Creating snapshot manifest..."
    cat > "$snapshot_dir/MANIFEST.txt" << EOF
Arkfile Forensic Snapshot
Created: $(date)
Host: $(hostname)
Snapshot ID: $snapshot_timestamp
Emergency Response Version: 1.0

Contents:
- processes.txt: Running processes at time of snapshot
- network_connections.txt: Active network connections
- arkfile_logs/: Application log files
- arkfile_journal.log: Systemd journal for arkfile service
- minio_journal.log: Systemd journal for minio services
- rqlite_journal.log: Systemd journal for rqlite services
- database_snapshot.db: Database snapshot (if accessible)
- config/: Configuration files (sensitive keys redacted)
- system_info.txt: System information
- disk_usage.txt: Disk usage information
- memory_info.txt: Memory information
- uptime.txt: System uptime
- packages_*.txt: Installed packages

NOTE: This snapshot is for forensic analysis purposes.
Sensitive cryptographic material has been redacted.
EOF
    
    # Compress snapshot
    log_action "Compressing forensic snapshot..."
    if tar -czf "${snapshot_dir}.tar.gz" -C "$BACKUP_DIR" "$(basename "$snapshot_dir")" 2>/dev/null; then
        rm -rf "$snapshot_dir"
        log_action "Forensic snapshot created: ${snapshot_dir}.tar.gz"
    else
        log_warning "Failed to compress snapshot - directory preserved: $snapshot_dir"
    fi
    
    log_info "FORENSIC SNAPSHOT COMPLETE"
    echo ""
    echo -e "${GREEN}Forensic snapshot created: ${snapshot_dir}.tar.gz${NC}"
    echo -e "${YELLOW}This snapshot can be used for incident analysis${NC}"
    echo -e "${YELLOW}Sensitive cryptographic material has been redacted${NC}"
}

# Display emergency procedures menu
show_emergency_menu() {
    clear
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        ARKFILE EMERGENCY PROCEDURES                         ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: These procedures are for emergency situations only${NC}"
    echo -e "${YELLOW}⚠️  Some actions are irreversible and will affect all users${NC}"
    echo ""
    echo "Emergency Procedures:"
    echo ""
    echo "1) Emergency Service Shutdown     - Stop all services and block network access"
    echo "2) Rotate Compromised Keys        - Generate new cryptographic keys (breaks sessions)"
    echo "3) Investigate Suspicious Activity - Analyze logs and security events"
    echo "4) Isolate User Account           - Disable compromised user account"
    echo "5) Reset Rate Limiting            - Clear rate limiting data and violations"
    echo "6) Create Forensic Snapshot       - Capture system state for analysis"
    echo ""
    echo "0) Exit"
    echo ""
}

# Display usage information
usage() {
    cat << EOF
Usage: $0 [OPTION]

Arkfile Emergency Response Procedures

OPTIONS:
    -h, --help                  Show this help message
    --shutdown                  Perform emergency service shutdown
    --rotate-keys               Rotate all cryptographic keys
    --investigate               Investigate suspicious activity
    --isolate-user USERNAME     Isolate specific user account
    --reset-rate-limit          Reset rate limiting data
    --forensic-snapshot         Create forensic snapshot
    --menu                      Show interactive emergency menu (default)

EXAMPLES:
    $0                          # Show interactive menu
    $0 --shutdown               # Emergency shutdown
    $0 --investigate            # Investigate suspicious activity
    $0 --isolate-user john.doe.2024
    $0 --forensic-snapshot      # Create forensic snapshot

IMPORTANT:
    - These procedures are for emergency situations only
    - Some actions are irreversible and will affect all users
    - Always create a forensic snapshot before making changes
    - Ensure you have proper authorization before proceeding

EOF
}

# Main execution
main() {
    local action="menu"
    local username=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            --shutdown)
                action="shutdown"
                shift
                ;;
            --rotate-keys)
                action="rotate-keys"
                shift
                ;;
            --investigate)
                action="investigate"
                shift
                ;;
            --isolate-user)
                action="isolate-user"
                username="$2"
                shift 2
                ;;
            --reset-rate-limit)
                action="reset-rate-limit"
                shift
                ;;
            --forensic-snapshot)
                action="forensic-snapshot"
                shift
                ;;
            --menu)
                action="menu"
                shift
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Initialize incident logging
    init_incident_log
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_warning "Not running as root - some operations may fail"
        echo -e "${YELLOW}Warning: Not running as root - some operations may fail${NC}"
        echo "Consider running as root for full emergency capabilities"
        echo ""
    fi
    
    # Execute based on action
    case $action in
        "menu")
            while true; do
                show_emergency_menu
                read -p "Select emergency procedure (0-6): " choice
                
                case $choice in
                    1)
                        emergency_shutdown
                        read -p "Press Enter to continue..."
                        ;;
                    2)
                        rotate_compromised_keys
                        read -p "Press Enter to continue..."
                        ;;
                    3)
                        investigate_suspicious_activity
                        read -p "Press Enter to continue..."
                        ;;
                    4)
                        isolate_user_account
                        read -p "Press Enter to continue..."
                        ;;
                    5)
                        reset_rate_limiting
                        read -p "Press Enter to continue..."
                        ;;
                    6)
                        create_forensic_snapshot
                        read -p "Press Enter to continue..."
                        ;;
                    0)
                        log_info "Emergency procedures session ended"
                        echo "Emergency procedures session ended."
                        echo "Incident log saved to: $INCIDENT_LOG"
                        exit 0
                        ;;
                    *)
                        echo "Invalid choice. Please select 0-6."
                        read -p "Press Enter to continue..."
                        ;;
                esac
            done
            ;;
        "shutdown")
            emergency_shutdown
            ;;
        "rotate-keys")
            rotate_compromised_keys
            ;;
        "investigate")
            investigate_suspicious_activity
            ;;
        "isolate-user")
            if [[ -z "$username" ]]; then
                echo "Error: Username required for isolation"
                echo "Usage: $0 --isolate-user USERNAME"
                exit 1
            fi
            # Use the global isolate_user_account function with the provided username
            isolate_user_account() {
                log_header "USER ACCOUNT ISOLATION"
                log_warning "Initiating isolation procedure for user: $username"
                
                if ! confirm_action "ISOLATE USER ACCOUNT: $username - This will disable the account and revoke all tokens"; then
                    log_warning "User isolation cancelled"
                    return 1
                fi
                
                # Disable user account in database
                if command -v sqlite3 >/dev/null 2>&1; then
                    db_file="$ARKFILE_HOME/data/arkfile.db"
                    if [[ -f "$db_file" ]]; then
                        log_action "Disabling user account in database..."
                        
                        # Set user as not approved and add security flag
                        sqlite3 "$db_file" "UPDATE users SET is_approved = 0, updated_at = datetime('now') WHERE username = '$username';" 2>/dev/null || true
                        
                        # Revoke all refresh tokens for the user
                        sqlite3 "$db_file" "UPDATE refresh_tokens SET revoked = 1, updated_at = datetime('now') WHERE username = '$username';" 2>/dev/null || true
                        
                        log_action "User account disabled and all tokens revoked"
                        
                        # Log security event
                        sqlite3 "$db_file" "INSERT INTO security_events (event_type, username, details, created_at) VALUES ('user_isolation', '$username', 'Account isolated due to security incident', datetime('now'));" 2>/dev/null || true
                        
                        log_action "Security event logged for user isolation"
                    else
                        log_critical "Database not accessible - manual intervention required"
                    fi
                else
                    log_critical "SQLite3 not available - cannot modify database"
                fi
                
                log_emergency "USER ACCOUNT ISOLATION COMPLETE"
                log_warning "User $username has been isolated and all tokens revoked"
                
                echo ""
                echo -e "${RED}${BOLD}USER ISOLATION COMPLETE${NC}"
                echo -e "${YELLOW}User: $username${NC}"
                echo -e "${YELLOW}Account disabled and all tokens revoked${NC}"
                echo -e "${YELLOW}Monitor for any continued suspicious activity${NC}"
            }
            isolate_user_account
            ;;
        "reset-rate-limit")
            reset_rate_limiting
            ;;
        "forensic-snapshot")
            create_forensic_snapshot
            ;;
    esac
    
    log_info "Emergency procedure '$action' completed"
    echo ""
    echo "Incident log saved to: $INCIDENT_LOG"
}

# Run main function with all arguments
main "$@"
