#!/bin/bash

# Arkfile Uninstall Script
# Safely removes Arkfile installation with user confirmation

# Note: Don't use set -e for scanning phase as it can exit on expected conditions
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
ARKFILE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"
BACKUP_DIR="/tmp/arkfile-backup-$(date +%Y%m%d-%H%M%S)"

# Global counters
COMPONENTS_FOUND=0
COMPONENTS_REMOVED=0
COMPONENTS_SKIPPED=0

echo -e "${RED}🗑️  Arkfile Uninstall Script${NC}"
echo -e "${RED}===============================${NC}"
echo
echo -e "${YELLOW}⚠️  WARNING: This script will help you remove Arkfile from your system.${NC}"
echo -e "${YELLOW}You will be prompted before each component is removed.${NC}"
echo
echo -e "${BLUE}Components that may be removed:${NC}"
echo "• Arkfile services (arkfile, minio, rqlite)"
echo "• System user and group (arkfile)"
echo "• Installation directory (/opt/arkfile)"
echo "• Cryptographic keys and certificates"
echo "• Downloaded binaries (MinIO, rqlite)"
echo "• Systemd service files"
echo "• Configuration and log files"
echo
echo -e "${CYAN}A backup of cryptographic keys can be created before removal.${NC}"
echo

# Function to ask yes/no questions
ask_yes_no() {
    local question="$1"
    local default="${2:-n}"
    local response
    
    while true; do
        if [ "$default" = "y" ]; then
            echo -ne "${YELLOW}${question} [Y/n]: ${NC}"
        else
            echo -ne "${YELLOW}${question} [y/N]: ${NC}"
        fi
        
        read -r response
        
        # Use default if empty response
        if [ -z "$response" ]; then
            response="$default"
        fi
        
        case "$response" in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo])
                return 1
                ;;
            *)
                echo -e "${RED}Please answer yes or no.${NC}"
                ;;
        esac
    done
}

# Function to print status messages
print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "FOUND")
            echo -e "  ${BLUE}ℹ${NC} ${message}"
            ((COMPONENTS_FOUND++))
            ;;
        "REMOVED")
            echo -e "  ${GREEN}✓${NC} ${message}"
            ((COMPONENTS_REMOVED++))
            ;;
        "SKIPPED")
            echo -e "  ${YELLOW}⏭${NC} ${message}"
            ((COMPONENTS_SKIPPED++))
            ;;
        "NOT_FOUND")
            echo -e "  ${CYAN}−${NC} ${message}"
            ;;
        "ERROR")
            echo -e "  ${RED}✗${NC} ${message}"
            ;;
    esac
}

# Check if running with appropriate privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ This script must be run with sudo privileges${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Initial system scan
echo -e "${BLUE}🔍 Scanning system for Arkfile components...${NC}"
echo

# Check for services
echo -e "${BLUE}Services:${NC}"
if systemctl list-unit-files | grep -q "arkfile.service"; then
    print_status "FOUND" "arkfile.service found"
else
    print_status "NOT_FOUND" "arkfile.service not found"
fi

if systemctl list-unit-files | grep -q "minio.service"; then
    print_status "FOUND" "minio.service found"
else
    print_status "NOT_FOUND" "minio.service not found"
fi

if systemctl list-unit-files | grep -q "rqlite.service"; then
    print_status "FOUND" "rqlite.service found"
else
    print_status "NOT_FOUND" "rqlite.service not found"
fi

# Check for user and group
echo -e "${BLUE}User/Group:${NC}"
if getent passwd "$USER" >/dev/null 2>&1; then
    print_status "FOUND" "User '$USER' exists"
else
    print_status "NOT_FOUND" "User '$USER' not found"
fi

if getent group "$GROUP" >/dev/null 2>&1; then
    print_status "FOUND" "Group '$GROUP' exists"
else
    print_status "NOT_FOUND" "Group '$GROUP' not found"
fi

# Check for directories
echo -e "${BLUE}Directories:${NC}"
if [ -d "$ARKFILE_DIR" ]; then
    DIR_SIZE=$(du -sh "$ARKFILE_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    print_status "FOUND" "Installation directory: $ARKFILE_DIR ($DIR_SIZE)"
else
    print_status "NOT_FOUND" "Installation directory not found"
fi

# Check for binaries
echo -e "${BLUE}Downloaded Binaries:${NC}"
BINARIES_FOUND=false
for location in "/usr/local/bin/minio" "/opt/minio/bin/minio" "$ARKFILE_DIR/bin/minio"; do
    if [ -f "$location" ]; then
        print_status "FOUND" "MinIO binary: $location"
        BINARIES_FOUND=true
    fi
done

for location in "/usr/local/bin/rqlite" "/usr/local/bin/rqlited" "$ARKFILE_DIR/bin/rqlite" "$ARKFILE_DIR/bin/rqlited"; do
    if [ -f "$location" ]; then
        print_status "FOUND" "rqlite binary: $location"
        BINARIES_FOUND=true
    fi
done

if [ "$BINARIES_FOUND" = false ]; then
    print_status "NOT_FOUND" "No downloaded binaries found"
fi

echo
echo -e "${BLUE}📊 Scan Summary:${NC}"
echo "Components found: $COMPONENTS_FOUND"
echo

if [ $COMPONENTS_FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ No Arkfile components found on system${NC}"
    echo "System appears to be clean already."
    exit 0
fi

echo -e "${YELLOW}Proceeding with interactive removal...${NC}"
echo

# Step 1: Backup cryptographic keys
if [ -d "$ARKFILE_DIR/etc/keys" ]; then
    echo -e "${CYAN}🔐 Cryptographic Keys Backup${NC}"
    echo "====================================="
    echo "Arkfile uses important cryptographic keys for security."
    echo "It's recommended to backup these keys before removal."
    echo
    
    if ask_yes_no "Create backup of cryptographic keys before removal?" "y"; then
        echo -e "${YELLOW}Creating backup directory: $BACKUP_DIR${NC}"
        mkdir -p "$BACKUP_DIR"
        
        echo -e "${YELLOW}Backing up keys...${NC}"
        cp -r "$ARKFILE_DIR/etc/keys" "$BACKUP_DIR/" 2>/dev/null || true
        
        if [ -d "$BACKUP_DIR/keys" ]; then
            print_status "REMOVED" "Keys backed up to: $BACKUP_DIR/keys"
            echo -e "${GREEN}📋 Backup created successfully!${NC}"
            echo "Keys backed up to: $BACKUP_DIR/keys"
            echo "This backup includes:"
            echo "• OPAQUE server keys"
            echo "• JWT signing keys"
            echo "• TLS certificates"
            echo
        else
            print_status "ERROR" "Failed to create key backup"
        fi
    else
        print_status "SKIPPED" "Key backup skipped"
    fi
    echo
fi

# Step 2: Stop and disable services
echo -e "${CYAN}🛑 Service Management${NC}"
echo "===================="

# Check which services are running
SERVICES_TO_STOP=()
if systemctl is-active --quiet arkfile 2>/dev/null; then
    SERVICES_TO_STOP+=("arkfile")
fi
if systemctl is-active --quiet minio 2>/dev/null; then
    SERVICES_TO_STOP+=("minio")
fi
if systemctl is-active --quiet rqlite 2>/dev/null; then
    SERVICES_TO_STOP+=("rqlite")
fi

if [ ${#SERVICES_TO_STOP[@]} -gt 0 ]; then
    echo "Running services found: ${SERVICES_TO_STOP[*]}"
    
    if ask_yes_no "Stop running Arkfile services?"; then
        for service in "${SERVICES_TO_STOP[@]}"; do
            echo -e "${YELLOW}Stopping $service...${NC}"
            systemctl stop "$service" 2>/dev/null || true
            print_status "REMOVED" "Stopped service: $service"
        done
    else
        print_status "SKIPPED" "Services left running"
    fi
else
    print_status "NOT_FOUND" "No running services found"
fi

# Disable services
SERVICES_TO_DISABLE=()
if systemctl is-enabled --quiet arkfile 2>/dev/null; then
    SERVICES_TO_DISABLE+=("arkfile")
fi
if systemctl is-enabled --quiet minio 2>/dev/null; then
    SERVICES_TO_DISABLE+=("minio")
fi
if systemctl is-enabled --quiet rqlite 2>/dev/null; then
    SERVICES_TO_DISABLE+=("rqlite")
fi

if [ ${#SERVICES_TO_DISABLE[@]} -gt 0 ]; then
    echo "Enabled services found: ${SERVICES_TO_DISABLE[*]}"
    
    if ask_yes_no "Disable Arkfile services from auto-start?"; then
        for service in "${SERVICES_TO_DISABLE[@]}"; do
            echo -e "${YELLOW}Disabling $service...${NC}"
            systemctl disable "$service" 2>/dev/null || true
            print_status "REMOVED" "Disabled service: $service"
        done
    else
        print_status "SKIPPED" "Services left enabled"
    fi
else
    print_status "NOT_FOUND" "No enabled services found"
fi
echo

# Step 3: Remove systemd service files
echo -e "${CYAN}📄 Systemd Service Files${NC}"
echo "========================"

SERVICE_FILES=(
    "/etc/systemd/system/arkfile.service"
    "/etc/systemd/system/minio.service"
    "/etc/systemd/system/rqlite.service"
    "/etc/systemd/system/minio"
    "/etc/systemd/system/rqlite"
)

FOUND_SERVICE_FILES=()
for file in "${SERVICE_FILES[@]}"; do
    if [ -f "$file" ]; then
        FOUND_SERVICE_FILES+=("$file")
    fi
done

if [ ${#FOUND_SERVICE_FILES[@]} -gt 0 ]; then
    echo "Service files found:"
    for file in "${FOUND_SERVICE_FILES[@]}"; do
        echo "  • $file"
    done
    
    if ask_yes_no "Remove systemd service files?"; then
        for file in "${FOUND_SERVICE_FILES[@]}"; do
            rm -f "$file"
            print_status "REMOVED" "Removed: $(basename "$file")"
        done
        
        echo -e "${YELLOW}Reloading systemd daemon...${NC}"
        systemctl daemon-reload
        print_status "REMOVED" "Systemd daemon reloaded"
    else
        print_status "SKIPPED" "Service files left in place"
    fi
else
    print_status "NOT_FOUND" "No service files found"
fi
echo

# Step 4: Remove user data and configuration
echo -e "${CYAN}📁 User Data and Configuration${NC}"
echo "=============================="

if [ -d "$ARKFILE_DIR" ]; then
    DIR_SIZE=$(du -sh "$ARKFILE_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    echo "Installation directory: $ARKFILE_DIR ($DIR_SIZE)"
    echo
    echo -e "${RED}⚠️  WARNING: This will delete all uploaded files and databases!${NC}"
    echo "This includes:"
    echo "• User uploaded files"
    echo "• Database content"
    echo "• Configuration files"
    echo "• Log files"
    echo "• Cryptographic keys (unless backed up above)"
    echo
    
    if ask_yes_no "Remove installation directory and all data?"; then
        echo -e "${YELLOW}Removing $ARKFILE_DIR...${NC}"
        rm -rf "$ARKFILE_DIR"
        print_status "REMOVED" "Installation directory removed"
    else
        print_status "SKIPPED" "Installation directory preserved"
    fi
else
    print_status "NOT_FOUND" "Installation directory not found"
fi
echo

# Step 5: Remove system user and group
echo -e "${CYAN}👤 System User and Group${NC}"
echo "========================"

if getent passwd "$USER" >/dev/null 2>&1; then
    USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
    echo "User '$USER' found (home: $USER_HOME)"
    
    if ask_yes_no "Remove system user '$USER'?"; then
        echo -e "${YELLOW}Removing user '$USER'...${NC}"
        userdel -r "$USER" 2>/dev/null || userdel "$USER" 2>/dev/null || true
        print_status "REMOVED" "User '$USER' removed"
    else
        print_status "SKIPPED" "User '$USER' preserved"
    fi
else
    print_status "NOT_FOUND" "User '$USER' not found"
fi

if getent group "$GROUP" >/dev/null 2>&1; then
    echo "Group '$GROUP' found"
    
    if ask_yes_no "Remove system group '$GROUP'?"; then
        echo -e "${YELLOW}Removing group '$GROUP'...${NC}"
        groupdel "$GROUP" 2>/dev/null || true
        print_status "REMOVED" "Group '$GROUP' removed"
    else
        print_status "SKIPPED" "Group '$GROUP' preserved"
    fi
else
    print_status "NOT_FOUND" "Group '$GROUP' not found"
fi
echo

# Step 6: Remove downloaded binaries
echo -e "${CYAN}📦 Downloaded Binaries${NC}"
echo "====================="

BINARY_LOCATIONS=(
    "/usr/local/bin/minio"
    "/usr/local/bin/rqlite"
    "/usr/local/bin/rqlited"
    "/opt/minio/bin/minio"
)

FOUND_BINARIES=()
for location in "${BINARY_LOCATIONS[@]}"; do
    if [ -f "$location" ]; then
        FOUND_BINARIES+=("$location")
    fi
done

if [ ${#FOUND_BINARIES[@]} -gt 0 ]; then
    echo "Downloaded binaries found:"
    for binary in "${FOUND_BINARIES[@]}"; do
        echo "  • $binary"
    done
    
    if ask_yes_no "Remove downloaded binaries?"; then
        for binary in "${FOUND_BINARIES[@]}"; do
            echo -e "${YELLOW}Removing $binary...${NC}"
            rm -f "$binary" 2>/dev/null || true
            print_status "REMOVED" "Removed: $binary"
        done
    else
        print_status "SKIPPED" "Binaries preserved"
    fi
else
    print_status "NOT_FOUND" "No downloaded binaries found"
fi
echo

# Step 7: Clean up temporary files and caches
echo -e "${CYAN}🧹 Temporary Files and Caches${NC}"
echo "============================="

TEMP_LOCATIONS=(
    "/tmp/minio*"
    "/tmp/rqlite*"
    "/tmp/arkfile*"
)

FOUND_TEMP_FILES=false
for pattern in "${TEMP_LOCATIONS[@]}"; do
    if ls $pattern 2>/dev/null | head -1 >/dev/null 2>&1; then
        print_status "FOUND" "Temporary files matching: $pattern"
        FOUND_TEMP_FILES=true
    fi
done

if [ "$FOUND_TEMP_FILES" = true ]; then
    if ask_yes_no "Remove temporary files and build caches?"; then
        for pattern in "${TEMP_LOCATIONS[@]}"; do
            rm -rf $pattern 2>/dev/null || true
        done
        print_status "REMOVED" "Temporary files cleaned up"
    else
        print_status "SKIPPED" "Temporary files preserved"
    fi
else
    print_status "NOT_FOUND" "No temporary files found"
fi

# Clean up any remaining build artifacts in project directory
if [ -f "./arkfile" ] || [ -f "./cryptocli" ] || [ -d "./client/static/wasm/" ]; then
    echo "Build artifacts found in project directory"
    
    if ask_yes_no "Remove build artifacts from project directory?"; then
        rm -f ./arkfile ./cryptocli 2>/dev/null || true
        rm -rf ./client/static/wasm/ 2>/dev/null || true
        print_status "REMOVED" "Project build artifacts cleaned"
    else
        print_status "SKIPPED" "Project build artifacts preserved"
    fi
else
    print_status "NOT_FOUND" "No project build artifacts found"
fi
echo

# Final verification
echo -e "${BLUE}🔍 Final Verification${NC}"
echo "===================="

# Re-scan for any remaining components
REMAINING_COMPONENTS=0

# Check services
if systemctl list-unit-files | grep -q "arkfile.service"; then
    print_status "FOUND" "arkfile.service still present"
    ((REMAINING_COMPONENTS++))
fi

# Check user
if getent passwd "$USER" >/dev/null 2>&1; then
    print_status "FOUND" "User '$USER' still exists"
    ((REMAINING_COMPONENTS++))
fi

# Check directory
if [ -d "$ARKFILE_DIR" ]; then
    print_status "FOUND" "Installation directory still exists"
    ((REMAINING_COMPONENTS++))
fi

if [ $REMAINING_COMPONENTS -eq 0 ]; then
    echo -e "${GREEN}✅ No Arkfile components detected${NC}"
else
    echo -e "${YELLOW}⚠️  $REMAINING_COMPONENTS components still present${NC}"
    echo "This may be intentional based on your choices above."
fi

echo
echo -e "${BLUE}📊 Uninstall Summary${NC}"
echo "===================="
echo "Components found: $COMPONENTS_FOUND"
echo "Components removed: $COMPONENTS_REMOVED"
echo "Components skipped: $COMPONENTS_SKIPPED"
echo "Components remaining: $REMAINING_COMPONENTS"

if [ -d "$BACKUP_DIR/keys" ]; then
    echo
    echo -e "${GREEN}🔐 Key Backup Created${NC}"
    echo "====================="
    echo "Location: $BACKUP_DIR/keys"
    echo "This backup contains your cryptographic keys."
    echo "Store this backup securely if you plan to reinstall Arkfile."
    echo
    echo -e "${YELLOW}⚠️  Remember to delete this backup securely when no longer needed:${NC}"
    echo "sudo rm -rf $BACKUP_DIR"
fi

echo
if [ $COMPONENTS_REMOVED -gt 0 ]; then
    echo -e "${GREEN}✅ Arkfile uninstall completed${NC}"
    echo "Thank you for using Arkfile!"
    
    if [ $REMAINING_COMPONENTS -eq 0 ]; then
        echo -e "${GREEN}System is completely clean.${NC}"
    else
        echo -e "${YELLOW}Some components were preserved based on your choices.${NC}"
    fi
else
    echo -e "${BLUE}ℹ️  No components were removed${NC}"
    echo "All Arkfile components remain on your system."
fi

echo
echo -e "${BLUE}🔄 To reinstall Arkfile:${NC}"
echo "./scripts/quick-start.sh"

exit 0
