#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARKFILE_DIR="/opt/arkfile"
INTERACTIVE=true
SKIP_CONFIRMATION=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --non-interactive)
            INTERACTIVE=false
            shift
            ;;
        --skip-confirmation)
            SKIP_CONFIRMATION=true
            shift
            ;;
        --domain)
            export ARKFILE_DOMAIN="$2"
            shift 2
            ;;
        -h|--help)
            echo "Arkfile First-Time Setup Script"
            echo "==============================="
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --non-interactive      Run without prompts (use defaults)"
            echo "  --skip-confirmation    Skip final confirmation prompts"
            echo "  --domain DOMAIN        Set domain for TLS certificates"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "This script will:"
            echo "  1. Run pre-installation health checks"
            echo "  2. Create service user and directories"
            echo "  3. Generate all cryptographic keys and certificates"
            echo "  4. Install systemd service files"
            echo "  5. Run post-installation validation"
            echo ""
            echo "Example:"
            echo "  sudo $0 --domain myserver.example.com"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Function to print section headers
print_section() {
    echo ""
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"
}

# Function to print status messages
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "INFO")
            echo -e "  ${BLUE}ℹ${NC} ${message}"
            ;;
        "SUCCESS")
            echo -e "  ${GREEN}✓${NC} ${message}"
            ;;
        "WARNING")
            echo -e "  ${YELLOW}⚠${NC} ${message}"
            ;;
        "ERROR")
            echo -e "  ${RED}✗${NC} ${message}"
            ;;
    esac
}

# Function to prompt for user confirmation
confirm() {
    local message=$1
    local default=${2:-"y"}
    
    if [ "$SKIP_CONFIRMATION" = true ]; then
        return 0
    fi
    
    if [ "$INTERACTIVE" = false ]; then
        return 0
    fi
    
    while true; do
        if [ "$default" = "y" ]; then
            read -p "$message [Y/n]: " yn
            yn=${yn:-y}
        else
            read -p "$message [y/N]: " yn
            yn=${yn:-n}
        fi
        
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Function to run pre-installation checks
run_pre_checks() {
    print_section "Pre-Installation Health Checks"
    
    print_status "INFO" "Running pre-installation validation..."
    
    if [ -x "$SCRIPT_DIR/health-check.sh" ]; then
        if "$SCRIPT_DIR/health-check.sh" --pre-install; then
            print_status "SUCCESS" "Pre-installation checks passed"
        else
            print_status "ERROR" "Pre-installation checks failed"
            echo "Please address the issues above before continuing."
            exit 1
        fi
    else
        print_status "ERROR" "Health check script not found or not executable"
        exit 1
    fi
}

# Function to setup users and directories
setup_infrastructure() {
    print_section "Infrastructure Setup"
    
    # Setup users
    print_status "INFO" "Setting up service user and group..."
    if [ -x "$SCRIPT_DIR/setup-users.sh" ]; then
        "$SCRIPT_DIR/setup-users.sh"
        print_status "SUCCESS" "Service user and group configured"
    else
        print_status "ERROR" "setup-users.sh not found or not executable"
        exit 1
    fi
    
    # Setup directories
    print_status "INFO" "Creating directory structure..."
    if [ -x "$SCRIPT_DIR/setup-directories.sh" ]; then
        "$SCRIPT_DIR/setup-directories.sh"
        print_status "SUCCESS" "Directory structure created"
    else
        print_status "ERROR" "setup-directories.sh not found or not executable"
        exit 1
    fi
}

# Function to generate cryptographic keys
generate_keys() {
    print_section "Cryptographic Key Generation"
    
    # Generate OPAQUE keys
    print_status "INFO" "Generating OPAQUE server keys..."
    if [ -x "$SCRIPT_DIR/setup-opaque-keys.sh" ]; then
        "$SCRIPT_DIR/setup-opaque-keys.sh"
        print_status "SUCCESS" "OPAQUE keys generated"
    else
        print_status "ERROR" "setup-opaque-keys.sh not found or not executable"
        exit 1
    fi
    
    # Generate JWT keys
    print_status "INFO" "Generating JWT signing keys..."
    if [ -x "$SCRIPT_DIR/setup-jwt-keys.sh" ]; then
        "$SCRIPT_DIR/setup-jwt-keys.sh"
        print_status "SUCCESS" "JWT keys generated"
    else
        print_status "ERROR" "setup-jwt-keys.sh not found or not executable"
        exit 1
    fi
    
    # Generate TLS certificates
    print_status "INFO" "Generating TLS certificates..."
    if [ -x "$SCRIPT_DIR/setup-tls-certs.sh" ]; then
        "$SCRIPT_DIR/setup-tls-certs.sh"
        print_status "SUCCESS" "TLS certificates generated"
    else
        print_status "ERROR" "setup-tls-certs.sh not found or not executable"
        exit 1
    fi
}

# Function to install systemd service
install_service() {
    print_section "Systemd Service Installation"
    
    local service_file="$PROJECT_ROOT/systemd/arkfile.service"
    local target_file="/etc/systemd/system/arkfile.service"
    
    if [ -f "$service_file" ]; then
        print_status "INFO" "Installing systemd service file..."
        cp "$service_file" "$target_file"
        chmod 644 "$target_file"
        
        print_status "INFO" "Reloading systemd daemon..."
        systemctl daemon-reload
        
        print_status "INFO" "Enabling arkfile service..."
        systemctl enable arkfile.service
        
        print_status "SUCCESS" "Systemd service installed and enabled"
    else
        print_status "ERROR" "Service file not found: $service_file"
        exit 1
    fi
}

# Function to create initial backup
create_initial_backup() {
    print_section "Initial Key Backup"
    
    print_status "INFO" "Creating initial backup of cryptographic keys..."
    if [ -x "$SCRIPT_DIR/backup-keys.sh" ]; then
        "$SCRIPT_DIR/backup-keys.sh"
        print_status "SUCCESS" "Initial backup created"
    else
        print_status "WARNING" "backup-keys.sh not found - skipping initial backup"
    fi
}

# Function to run post-installation validation
run_validation() {
    print_section "Post-Installation Validation"
    
    print_status "INFO" "Running deployment validation..."
    if [ -x "$SCRIPT_DIR/validate-deployment.sh" ]; then
        if "$SCRIPT_DIR/validate-deployment.sh"; then
            print_status "SUCCESS" "Deployment validation passed"
            return 0
        else
            print_status "WARNING" "Deployment validation had issues"
            return 1
        fi
    else
        print_status "ERROR" "validate-deployment.sh not found or not executable"
        exit 1
    fi
}

# Function to display completion information
display_completion_info() {
    print_section "Setup Complete"
    
    local host=${ARKFILE_HOST:-localhost}
    local port=${ARKFILE_PORT:-8080}
    local domain=${ARKFILE_DOMAIN:-localhost}
    
    echo -e "${GREEN}✅ Arkfile setup completed successfully!${NC}"
    echo ""
    echo "Service Information:"
    echo "  Service: arkfile.service"
    echo "  Status: $(systemctl is-active arkfile.service 2>/dev/null || echo 'inactive')"
    echo "  Enabled: $(systemctl is-enabled arkfile.service 2>/dev/null || echo 'disabled')"
    echo "  URL: http://${host}:${port}/"
    echo ""
    echo "Directory Structure:"
    echo "  Installation: ${ARKFILE_DIR}"
    echo "  Logs: ${ARKFILE_DIR}/var/log/"
    echo "  Keys: ${ARKFILE_DIR}/etc/keys/ (restricted access)"
    echo "  Database: ${ARKFILE_DIR}/var/lib/database/"
    echo ""
    echo "Security Notes:"
    echo "  • OPAQUE keys: Generated (replace placeholders for production)"
    echo "  • JWT keys: Ed25519 cryptographic keys"
    echo "  • TLS certificates: Self-signed for ${domain}"
    echo "  • Service user: arkfile (no login shell)"
    echo "  • Permissions: Restrictive (700/750/755 as appropriate)"
    echo ""
    echo "Management Commands:"
    echo "  Start service: sudo systemctl start arkfile.service"
    echo "  Stop service: sudo systemctl stop arkfile.service"
    echo "  View logs: sudo journalctl -u arkfile.service -f"
    echo "  Health check: sudo $SCRIPT_DIR/health-check.sh"
    echo "  Validation: sudo $SCRIPT_DIR/validate-deployment.sh"
    echo "  Backup keys: sudo $SCRIPT_DIR/backup-keys.sh"
    echo ""
    echo "Next Steps:"
    echo "  1. Build and deploy the Arkfile application binary"
    echo "  2. Configure environment variables in /opt/arkfile/etc/arkfile.env"
    echo "  3. Replace OPAQUE placeholder keys with real keys for production"
    echo "  4. Set up reverse proxy (nginx/Apache) if needed"
    echo "  5. Configure firewall rules for port ${port}"
    echo ""
    echo -e "${YELLOW}Important: Store backup keys securely and separately!${NC}"
}

# Main setup function
main() {
    echo -e "${BOLD}${GREEN}Arkfile First-Time Setup${NC}"
    echo -e "${GREEN}========================${NC}"
    echo "This script will set up a complete Arkfile secure file sharing deployment."
    echo ""
    echo "Setup will include:"
    echo "  • Service user and secure directory structure"
    echo "  • OPAQUE server keys for authentication"
    echo "  • JWT signing keys with Ed25519"
    echo "  • TLS certificates for internal services"
    echo "  • Systemd service configuration"
    echo "  • Security hardening and validation"
    echo ""
    
    if [ "$INTERACTIVE" = true ]; then
        if ! confirm "Continue with Arkfile setup?"; then
            echo "Setup cancelled."
            exit 0
        fi
    fi
    
    # Set domain if not provided
    if [ -z "$ARKFILE_DOMAIN" ]; then
        export ARKFILE_DOMAIN="localhost"
        print_status "INFO" "Using default domain: localhost"
    else
        print_status "INFO" "Using domain: $ARKFILE_DOMAIN"
    fi
    
    # Change to project root for relative paths
    cd "$PROJECT_ROOT"
    
    # Make all scripts executable
    chmod +x "$SCRIPT_DIR"/*.sh
    
    # Run setup steps
    run_pre_checks
    setup_infrastructure
    generate_keys
    install_service
    create_initial_backup
    
    # Run validation and handle results
    if run_validation; then
        display_completion_info
        exit 0
    else
        echo ""
        echo -e "${YELLOW}Setup completed but validation found issues.${NC}"
        echo "Please review the validation output above and address any problems."
        echo ""
        echo "You can re-run validation at any time with:"
        echo "  sudo $SCRIPT_DIR/validate-deployment.sh"
        exit 0
    fi
}

# Run main function with all arguments
main "$@"
