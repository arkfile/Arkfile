#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
VERSION="7.21.1"  # Latest stable version of rqlite
BASE_DIR="/opt/arkfile"
CACHE_DIR="/opt/arkfile/var/cache/downloads"

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

echo -e "${BLUE}🗄️  Setting up rqlite cluster database v${VERSION}...${NC}"
echo
echo -e "${BLUE}🔧 rqlite Database Installation${NC}"
echo "This will download and install rqlite binaries for distributed database clusters."
echo "Suitable for both development and production deployments."
echo

# Security verification setup
RQLITE_DOWNLOAD_URL="https://github.com/rqlite/rqlite/releases/download/v${VERSION}/rqlite-v${VERSION}-linux-amd64.tar.gz"
RQLITE_SHA256_URL="https://github.com/rqlite/rqlite/releases/download/v${VERSION}/rqlite-v${VERSION}-linux-amd64.tar.gz.sha256"

# Create cache directory if needed
mkdir -p "${CACHE_DIR}"

# Check if we already have the file cached
CACHED_FILE="${CACHE_DIR}/rqlite-v${VERSION}-linux-amd64.tar.gz"
CACHED_SHA256="${CACHE_DIR}/rqlite-v${VERSION}-linux-amd64.tar.gz.sha256"

if [ -f "$CACHED_FILE" ] && [ -f "$CACHED_SHA256" ] && [ "$FORCE_DOWNLOAD" != true ]; then
    echo -e "${GREEN}✅ Using cached rqlite v${VERSION}${NC}"
else
    echo -e "${YELLOW}📥 Downloading rqlite v${VERSION} with security verification...${NC}"
    
    # Download SHA256 checksum first
    echo "Downloading SHA256 checksum..."
    if ! curl -L "${RQLITE_SHA256_URL}" -o "${CACHED_SHA256}"; then
        echo -e "${RED}❌ Failed to download SHA256 checksum${NC}"
        echo -e "${YELLOW}⚠️  This is a security risk - cannot verify download integrity${NC}"
        exit 1
    fi
    
    # Download the binary
    echo "Downloading rqlite binary..."
    if ! curl -L "${RQLITE_DOWNLOAD_URL}" -o "${CACHED_FILE}"; then
        echo -e "${RED}❌ Failed to download rqlite binary${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Downloads completed${NC}"
fi

# Verify SHA256 checksum
echo -e "${BLUE}🔐 Verifying download integrity...${NC}"
cd "${CACHE_DIR}"

# Extract expected checksum
EXPECTED_SHA256=$(cat "${CACHED_SHA256}" | awk '{print $1}')
ACTUAL_SHA256=$(sha256sum "$(basename "${CACHED_FILE}")" | awk '{print $1}')

echo "Expected SHA256: ${EXPECTED_SHA256}"
echo "Actual SHA256:   ${ACTUAL_SHA256}"

if [ "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ]; then
    echo -e "${RED}❌ SHA256 verification FAILED!${NC}"
    echo -e "${RED}❌ This indicates the download may be corrupted or tampered with${NC}"
    echo -e "${YELLOW}⚠️  Removing potentially compromised files...${NC}"
    rm -f "${CACHED_FILE}" "${CACHED_SHA256}"
    exit 1
fi

echo -e "${GREEN}✅ SHA256 verification passed${NC}"

# TODO: PGP signature verification would go here
# Note: rqlite releases don't currently provide PGP signatures
# but we should check for them and verify if available
echo -e "${YELLOW}⚠️  PGP signature verification not available for rqlite releases${NC}"

# Install the binaries
echo -e "${BLUE}📦 Installing rqlite binaries...${NC}"
TEMP_DIR=$(mktemp -d)
tar xzf "${CACHED_FILE}" -C "${TEMP_DIR}"

# Install with proper permissions
sudo install -m 755 "${TEMP_DIR}/rqlite-v${VERSION}-linux-amd64/rqlited" /usr/local/bin/
sudo install -m 755 "${TEMP_DIR}/rqlite-v${VERSION}-linux-amd64/rqlite" /usr/local/bin/

# Clean up temporary files
rm -rf "${TEMP_DIR}"

echo -e "${GREEN}✅ rqlite binaries installed successfully${NC}"

# Verify installation
if command -v rqlited &> /dev/null && command -v rqlite &> /dev/null; then
    RQLITED_VERSION=$(rqlited -version | head -n1)
    echo -e "${GREEN}✅ Installation verified: ${RQLITED_VERSION}${NC}"
else
    echo -e "${RED}❌ Installation verification failed${NC}"
    exit 1
fi

# Copy systemd service files
echo -e "${BLUE}⚙️  Installing systemd service files...${NC}"
sudo cp "${BASE_DIR}/releases/current/systemd/rqlite@.service" /etc/systemd/system/
sudo cp "${BASE_DIR}/releases/current/systemd/rqlite.target" /etc/systemd/system/

# Reload systemd
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo
echo -e "${GREEN}🎉 rqlite cluster database setup complete!${NC}"
echo
echo -e "${BLUE}📋 Installation Summary:${NC}"
echo "• Version: ${VERSION}"
echo "• Binaries: /usr/local/bin/rqlited, /usr/local/bin/rqlite"
echo "• SHA256: ✅ Verified"
echo "• PGP: ⚠️  Not available from upstream"
echo "• Cached: ${CACHED_FILE}"

echo
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "1. Configure environment variables in /opt/arkfile/etc/[env]/secrets.env:"
echo "   DATABASE_TYPE=rqlite"
echo "   RQLITE_ADDRESS=http://localhost:4001"
echo "   # For clusters, add multiple RQLITE_NODES"
echo
echo "2. Start rqlite service:"
echo "   sudo systemctl enable rqlite@prod"
echo "   sudo systemctl start rqlite@prod"
echo
echo "3. Check status:"
echo "   sudo systemctl status rqlite@prod"
echo "   rqlite -H localhost:4001 'SELECT 1'"
echo
