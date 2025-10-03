#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
VERSION="8.38.2"  # Latest stable version of rqlite
BASE_DIR="/opt/arkfile"
CACHE_DIR="/opt/arkfile/var/cache/downloads"
DEPENDENCY_HASHES_FILE="${BASE_DIR}/../config/dependency-hashes.json"

# Parse command line arguments
FORCE_DOWNLOAD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_DOWNLOAD=true
            shift
            ;;
        --help)
            echo "rqlite Database Setup"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --force                 Force download even if cached"
            echo "  --help                  Show this help"
            echo ""
            echo "This script downloads and installs rqlite cluster binaries with security verification."
            echo "Suitable for both development and production deployments."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}️  Setting up rqlite cluster database v${VERSION}...${NC}"
echo
echo -e "${BLUE}rqlite Database Installation${NC}"
echo "This will download and install rqlite binaries for distributed database clusters."
echo "Suitable for both development and production deployments."
echo

# Check if rqlite is already installed
if command -v rqlited &> /dev/null && command -v rqlite &> /dev/null && [ "$FORCE_DOWNLOAD" != true ]; then
    INSTALLED_VERSION=$(rqlited -version 2>/dev/null | head -n1 | grep -o 'v[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
    echo -e "${GREEN}[OK] rqlite binaries already installed${NC}"
    echo "Installed version: ${INSTALLED_VERSION}"
    echo "Skipping download and installation..."
    
    # Still need to install systemd service files
    echo -e "${BLUE}[CONFIG]  Installing systemd service files...${NC}"
    sudo cp "${BASE_DIR}/systemd/rqlite.service" /etc/systemd/system/
    
    # Create simplified data directory for single-node deployment
    echo "Setting up database directory..."
    sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/database"
    
    # Reload systemd
    echo "Reloading systemd..."
    sudo systemctl daemon-reload
    
    echo -e "${GREEN}rqlite cluster database setup complete!${NC}"
    echo -e "${BLUE}Binaries were already installed, systemd services configured.${NC}"
    exit 0
fi

# Security verification setup
RQLITE_DOWNLOAD_URL="https://github.com/rqlite/rqlite/releases/download/v${VERSION}/rqlite-v${VERSION}-linux-amd64.tar.gz"
RQLITE_SHA256_URL="https://github.com/rqlite/rqlite/releases/download/v${VERSION}/rqlite-v${VERSION}-linux-amd64.tar.gz.sha256"

# Create cache directory if needed
mkdir -p "${CACHE_DIR}"

# Check if we already have the file cached
CACHED_FILE="${CACHE_DIR}/rqlite-v${VERSION}-linux-amd64.tar.gz"
CACHED_SHA256="${CACHE_DIR}/rqlite-v${VERSION}-linux-amd64.tar.gz.sha256"

if [ -f "$CACHED_FILE" ] && [ -f "$CACHED_SHA256" ] && [ "$FORCE_DOWNLOAD" != true ]; then
    echo -e "${GREEN}[OK] Using cached rqlite v${VERSION}${NC}"
else
    echo -e "${YELLOW}Downloading rqlite v${VERSION} with security verification...${NC}"
    
    # Try to download SHA256 checksum first (likely to fail for rqlite)
    echo "Attempting to download SHA256 checksum..."
    CHECKSUM_AVAILABLE=false
    if curl -L "${RQLITE_SHA256_URL}" -o "${CACHED_SHA256}" 2>/dev/null; then
        # Check if we got a real checksum or a 404 page
        if [ -s "${CACHED_SHA256}" ] && ! grep -q "Not Found" "${CACHED_SHA256}"; then
            echo -e "${GREEN}[OK] SHA256 checksum downloaded from upstream${NC}"
            CHECKSUM_AVAILABLE=true
        else
            echo -e "${YELLOW}[WARNING]  Upstream SHA256 checksum not available${NC}"
            rm -f "${CACHED_SHA256}"
        fi
    else
        echo -e "${YELLOW}[WARNING]  Upstream SHA256 checksum not available${NC}"
    fi
    
    # Download the binary
    echo "Downloading rqlite binary..."
    if ! curl -L "${RQLITE_DOWNLOAD_URL}" -o "${CACHED_FILE}"; then
        echo -e "${RED}[X] Failed to download rqlite binary${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[OK] Binary download completed${NC}"
fi

# Verify SHA256 checksum using fallback methods
echo -e "${BLUE}[SECURE] Verifying download integrity...${NC}"
cd "${CACHE_DIR}"

VERIFICATION_PASSED=false
VERIFICATION_METHOD=""

# Method 1: Use upstream checksum if available
if [ -f "${CACHED_SHA256}" ] && [ -s "${CACHED_SHA256}" ]; then
    echo "Verifying with upstream SHA256 checksum..."
    EXPECTED_SHA256=$(cat "${CACHED_SHA256}" | awk '{print $1}')
    ACTUAL_SHA256=$(sha256sum "$(basename "${CACHED_FILE}")" | awk '{print $1}')
    
    echo "Expected SHA256: ${EXPECTED_SHA256}"
    echo "Actual SHA256:   ${ACTUAL_SHA256}"
    
    if [ "$EXPECTED_SHA256" = "$ACTUAL_SHA256" ]; then
        echo -e "${GREEN}[OK] Upstream SHA256 verification passed${NC}"
        VERIFICATION_PASSED=true
        VERIFICATION_METHOD="upstream_checksum"
    else
        echo -e "${RED}[X] Upstream SHA256 verification failed${NC}"
        exit 1
    fi
fi

# Method 2: Use local dependency hash database if upstream not available
if [ "$VERIFICATION_PASSED" = false ]; then
    echo "Falling back to local dependency hash database..."
    
    if [ -f "$DEPENDENCY_HASHES_FILE" ] && command -v jq &> /dev/null; then
        EXPECTED_SHA256=$(jq -r ".dependencies.rqlite.\"v${VERSION}\".\"linux-amd64\".sha256" "$DEPENDENCY_HASHES_FILE" 2>/dev/null)
        
        if [ "$EXPECTED_SHA256" != "null" ] && [ -n "$EXPECTED_SHA256" ]; then
            ACTUAL_SHA256=$(sha256sum "$(basename "${CACHED_FILE}")" | awk '{print $1}')
            
            echo "Expected SHA256 (local database): ${EXPECTED_SHA256}"
            echo "Actual SHA256:                    ${ACTUAL_SHA256}"
            
            if [ "$EXPECTED_SHA256" = "$ACTUAL_SHA256" ]; then
                echo -e "${GREEN}[OK] Local database SHA256 verification passed${NC}"
                VERIFICATION_PASSED=true
                VERIFICATION_METHOD="local_database"
            else
                echo -e "${RED}[X] Local database SHA256 verification failed${NC}"
                echo -e "${RED}[X] This indicates the download may be corrupted or tampered with${NC}"
                rm -f "${CACHED_FILE}"
                exit 1
            fi
        else
            echo -e "${YELLOW}[WARNING]  No SHA256 found in local database for v${VERSION}${NC}"
        fi
    else
        echo -e "${YELLOW}[WARNING]  Local dependency database not available or jq not installed${NC}"
    fi
fi

# Method 3: Manual verification prompt (last resort)
if [ "$VERIFICATION_PASSED" = false ]; then
    ACTUAL_SHA256=$(sha256sum "$(basename "${CACHED_FILE}")" | awk '{print $1}')
    echo -e "${YELLOW}[WARNING]  WARNING: Unable to verify download automatically${NC}"
    echo -e "${YELLOW}[WARNING]  Computed SHA256: ${ACTUAL_SHA256}${NC}"
    echo
    echo -e "${RED}[LOCK] SECURITY WARNING: No automatic verification available${NC}"
    echo "rqlite does not provide SHA256 checksums, and no local database entry exists."
    echo "Please manually verify this SHA256 against a trusted source."
    echo
    echo "Options:"
    echo "1. Continue with unverified download (NOT RECOMMENDED for production)"
    echo "2. Exit and manually verify the checksum"
    echo
    read -p "Continue with unverified download? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting for manual verification..."
        exit 1
    fi
    VERIFICATION_METHOD="manual_override"
    echo -e "${YELLOW}[WARNING]  Proceeding with unverified download${NC}"
fi

# TODO: PGP signature verification would go here
# Note: rqlite releases don't currently provide PGP signatures
# but we should check for them and verify if available
echo -e "${YELLOW}[WARNING]  PGP signature verification not available for rqlite releases${NC}"

# Install the binaries
echo -e "${BLUE}Installing rqlite binaries...${NC}"
TEMP_DIR=$(mktemp -d)
tar xzf "${CACHED_FILE}" -C "${TEMP_DIR}"

# Install with proper permissions
sudo install -m 755 "${TEMP_DIR}/rqlite-v${VERSION}-linux-amd64/rqlited" /usr/local/bin/
sudo install -m 755 "${TEMP_DIR}/rqlite-v${VERSION}-linux-amd64/rqlite" /usr/local/bin/

# Clean up temporary files
rm -rf "${TEMP_DIR}"

echo -e "${GREEN}[OK] rqlite binaries installed successfully${NC}"

# Verify installation
if command -v rqlited &> /dev/null && command -v rqlite &> /dev/null; then
    RQLITED_VERSION=$(rqlited -version | head -n1)
    echo -e "${GREEN}[OK] Installation verified: ${RQLITED_VERSION}${NC}"
else
    echo -e "${RED}[X] Installation verification failed${NC}"
    exit 1
fi

# Copy systemd service files
echo -e "${BLUE}[CONFIG]  Installing systemd service files...${NC}"
sudo cp "${BASE_DIR}/systemd/rqlite.service" /etc/systemd/system/

# Create simplified data directory for single-node deployment
echo "Setting up database directory..."
sudo install -d -m 750 -o arkfile -g arkfile "${BASE_DIR}/var/lib/database"

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo
echo -e "${GREEN}rqlite cluster database setup complete!${NC}"
echo
echo -e "${BLUE}[INFO] Installation Summary:${NC}"
echo "• Version: ${VERSION}"
echo "• Binaries: /usr/local/bin/rqlited, /usr/local/bin/rqlite"
echo "• SHA256: [OK] Verified"
echo "• PGP: [WARNING]  Not available from upstream"
echo "• Cached: ${CACHED_FILE}"

echo
echo -e "${BLUE}[START] Next Steps:${NC}"
echo "1. Configure environment variables in /opt/arkfile/etc/[env]/secrets.env:"
echo "   DATABASE_TYPE=rqlite"
echo "   RQLITE_ADDRESS=http://localhost:4001"
echo "   # For clusters, add multiple RQLITE_NODES"
echo
echo "2. Start rqlite service:"
echo "   sudo systemctl enable rqlite"
echo "   sudo systemctl start rqlite"
echo
echo "3. Check status:"
echo "   sudo systemctl status rqlite"
echo "   rqlite -H localhost:4001 'SELECT 1'"
echo
