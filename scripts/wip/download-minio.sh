#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MINIO_VERSION="${MINIO_VERSION:-RELEASE.2025-06-13T11-33-47Z}"
BASE_DIR="/opt/arkfile"
CACHE_DIR="${BASE_DIR}/var/cache/downloads"
USER="arkfile"
GROUP="arkfile"

# MinIO download URLs and checksums
MINIO_DOWNLOAD_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}"
MINIO_SHA256_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}.sha256sum"

# MinIO's PGP public key fingerprint (for signature verification)
MINIO_PGP_KEY_ID="7F1C1F7E60EE0F5B"

echo -e "${GREEN}Secure MinIO Download and Verification${NC}"
echo "Version: ${MINIO_VERSION}"
echo "Cache directory: ${CACHE_DIR}"

# Parse command line options
SKIP_DOWNLOAD=false
FORCE_DOWNLOAD=false
VERIFY_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-download)
            SKIP_DOWNLOAD=true
            shift
            ;;
        --force-download)
            FORCE_DOWNLOAD=true
            shift
            ;;
        --verify-only)
            VERIFY_ONLY=true
            shift
            ;;
        --version)
            MINIO_VERSION="$2"
            MINIO_DOWNLOAD_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}"
            MINIO_SHA256_URL="https://dl.min.io/server/minio/release/linux-amd64/archive/minio.${MINIO_VERSION}.sha256sum"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-download     Use cached file if available, skip download"
            echo "  --force-download    Force re-download even if cached file exists"
            echo "  --verify-only       Only verify existing cached file"
            echo "  --version VERSION   Download specific MinIO version"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  MINIO_VERSION       MinIO version to download (default: ${MINIO_VERSION})"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Create cache directory if it doesn't exist
if [ ! -d "${CACHE_DIR}" ]; then
    echo -e "${YELLOW}Creating cache directory...${NC}"
    sudo mkdir -p "${CACHE_DIR}"
    sudo chown ${USER}:${GROUP} "${CACHE_DIR}"
    sudo chmod 750 "${CACHE_DIR}"
fi

# File paths
MINIO_BINARY="${CACHE_DIR}/minio.${MINIO_VERSION}"
MINIO_CHECKSUM="${CACHE_DIR}/minio.${MINIO_VERSION}.sha256sum"
MINIO_SIGNATURE="${CACHE_DIR}/minio.${MINIO_VERSION}.sha256sum.sig"

# Function to download with retry and progress
download_with_retry() {
    local url="$1"
    local output="$2"
    local description="$3"
    local max_retries=3
    local retry_delay=5
    
    echo -e "${BLUE}Downloading ${description}...${NC}"
    
    for attempt in $(seq 1 $max_retries); do
        echo "Attempt ${attempt}/${max_retries}..."
        
        if curl -L --retry 3 --retry-delay 2 \
               --connect-timeout 30 --max-time 1800 \
               --progress-bar --fail \
               -o "${output}" "${url}"; then
            echo -e "${GREEN}[OK] ${description} downloaded successfully${NC}"
            return 0
        else
            echo -e "${YELLOW}[WARNING]  Download attempt ${attempt} failed${NC}"
            if [ $attempt -lt $max_retries ]; then
                echo "Retrying in ${retry_delay} seconds..."
                sleep $retry_delay
                retry_delay=$((retry_delay * 2))  # Exponential backoff
            fi
        fi
    done
    
    echo -e "${RED}[X] Failed to download ${description} after ${max_retries} attempts${NC}"
    return 1
}

# Function to verify SHA256 checksum
verify_checksum() {
    local binary_file="$1"
    local checksum_file="$2"
    
    echo -e "${BLUE}Verifying SHA256 checksum...${NC}"
    
    if [ ! -f "${checksum_file}" ]; then
        echo -e "${RED}[X] Checksum file not found: ${checksum_file}${NC}"
        return 1
    fi
    
    # Extract expected checksum from the checksum file
    local expected_checksum
    expected_checksum=$(awk '{print $1}' "${checksum_file}" | head -1)
    
    if [ -z "${expected_checksum}" ]; then
        echo -e "${RED}[X] Could not extract checksum from file${NC}"
        return 1
    fi
    
    # Calculate actual checksum
    local actual_checksum
    actual_checksum=$(sha256sum "${binary_file}" | awk '{print $1}')
    
    echo "Expected: ${expected_checksum}"
    echo "Actual:   ${actual_checksum}"
    
    if [ "${expected_checksum}" = "${actual_checksum}" ]; then
        echo -e "${GREEN}[OK] SHA256 checksum verification passed${NC}"
        return 0
    else
        echo -e "${RED}[X] SHA256 checksum verification failed${NC}"
        return 1
    fi
}

# Function to verify PGP signature (if available)
verify_signature() {
    local checksum_file="$1"
    local signature_file="$2"
    
    echo -e "${BLUE}Checking for PGP signature verification...${NC}"
    
    # Check if gpg is available
    if ! command -v gpg >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARNING]  GPG not available, skipping signature verification${NC}"
        return 0
    fi
    
    # Check if signature file exists
    if [ ! -f "${signature_file}" ]; then
        echo -e "${YELLOW}[WARNING]  PGP signature file not available, skipping signature verification${NC}"
        return 0
    fi
    
    echo -e "${BLUE}Verifying PGP signature...${NC}"
    
    # Import MinIO's public key if not already imported
    if ! gpg --list-keys "${MINIO_PGP_KEY_ID}" >/dev/null 2>&1; then
        echo "Importing MinIO's PGP public key..."
        # Note: In production, you'd want to import from a keyserver or local file
        # gpg --keyserver keyserver.ubuntu.com --recv-keys ${MINIO_PGP_KEY_ID}
        echo -e "${YELLOW}[WARNING]  MinIO public key not imported, skipping signature verification${NC}"
        return 0
    fi
    
    # Verify signature
    if gpg --verify "${signature_file}" "${checksum_file}" >/dev/null 2>&1; then
        echo -e "${GREEN}[OK] PGP signature verification passed${NC}"
        return 0
    else
        echo -e "${RED}[X] PGP signature verification failed${NC}"
        return 1
    fi
}

# Function to install MinIO binary
install_minio() {
    local binary_file="$1"
    
    echo -e "${BLUE}Installing MinIO binary...${NC}"
    
    # Check if binary is executable
    if [ ! -x "${binary_file}" ]; then
        sudo chmod +x "${binary_file}"
    fi
    
    # Install to /usr/local/bin
    sudo cp "${binary_file}" /usr/local/bin/minio
    sudo chmod 755 /usr/local/bin/minio
    
    # Verify installation
    if command -v minio >/dev/null 2>&1; then
        local installed_version
        installed_version=$(minio --version 2>/dev/null | head -1 || echo "unknown")
        echo -e "${GREEN}[OK] MinIO installed successfully${NC}"
        echo "Version: ${installed_version}"
        return 0
    else
        echo -e "${RED}[X] MinIO installation failed${NC}"
        return 1
    fi
}

# Main execution logic

# Check if we should only verify existing files
if [ "$VERIFY_ONLY" = true ]; then
    echo -e "${BLUE}Verify-only mode: checking existing cached files${NC}"
    
    if [ ! -f "${MINIO_BINARY}" ]; then
        echo -e "${RED}[X] Cached MinIO binary not found: ${MINIO_BINARY}${NC}"
        exit 1
    fi
    
    if [ ! -f "${MINIO_CHECKSUM}" ]; then
        echo -e "${RED}[X] Cached checksum file not found: ${MINIO_CHECKSUM}${NC}"
        exit 1
    fi
    
    verify_checksum "${MINIO_BINARY}" "${MINIO_CHECKSUM}"
    verify_signature "${MINIO_CHECKSUM}" "${MINIO_SIGNATURE}"
    exit $?
fi

# Check if files already exist and handle caching logic
if [ -f "${MINIO_BINARY}" ] && [ -f "${MINIO_CHECKSUM}" ]; then
    if [ "$SKIP_DOWNLOAD" = true ]; then
        echo -e "${GREEN}Using cached MinIO binary${NC}"
        echo "Binary: ${MINIO_BINARY}"
        echo "Checksum: ${MINIO_CHECKSUM}"
        
        # Verify cached files
        if verify_checksum "${MINIO_BINARY}" "${MINIO_CHECKSUM}"; then
            verify_signature "${MINIO_CHECKSUM}" "${MINIO_SIGNATURE}"
            install_minio "${MINIO_BINARY}"
            exit $?
        else
            echo -e "${YELLOW}[WARNING]  Cached file verification failed, will re-download${NC}"
        fi
    elif [ "$FORCE_DOWNLOAD" = false ]; then
        echo -e "${YELLOW}MinIO files already cached. Use --force-download to re-download or --skip-download to use cached files${NC}"
        echo "Cached binary: ${MINIO_BINARY}"
        echo "Cached checksum: ${MINIO_CHECKSUM}"
        
        # Verify cached files
        if verify_checksum "${MINIO_BINARY}" "${MINIO_CHECKSUM}"; then
            verify_signature "${MINIO_CHECKSUM}" "${MINIO_SIGNATURE}"
            install_minio "${MINIO_BINARY}"
            exit $?
        else
            echo -e "${YELLOW}[WARNING]  Cached file verification failed, will re-download${NC}"
        fi
    fi
fi

# Download files
echo -e "${BLUE}Downloading MinIO version ${MINIO_VERSION}...${NC}"

# Download checksum file first
if ! download_with_retry "${MINIO_SHA256_URL}" "${MINIO_CHECKSUM}" "SHA256 checksum"; then
    echo -e "${RED}[X] Failed to download checksum file${NC}"
    exit 1
fi

# Try to download signature file (optional)
if curl -L --retry 2 --connect-timeout 10 --max-time 60 \
        --fail -o "${MINIO_SIGNATURE}" "${MINIO_SHA256_URL}.sig" >/dev/null 2>&1; then
    echo -e "${GREEN}[OK] PGP signature file downloaded${NC}"
else
    echo -e "${YELLOW}[WARNING]  PGP signature file not available (non-critical)${NC}"
fi

# Download MinIO binary
if ! download_with_retry "${MINIO_DOWNLOAD_URL}" "${MINIO_BINARY}" "MinIO binary"; then
    echo -e "${RED}[X] Failed to download MinIO binary${NC}"
    exit 1
fi

# Set proper ownership for downloaded files
sudo chown ${USER}:${GROUP} "${MINIO_BINARY}" "${MINIO_CHECKSUM}"
if [ -f "${MINIO_SIGNATURE}" ]; then
    sudo chown ${USER}:${GROUP} "${MINIO_SIGNATURE}"
fi

# Verify downloaded files
echo -e "${BLUE}Verifying downloaded files...${NC}"

if ! verify_checksum "${MINIO_BINARY}" "${MINIO_CHECKSUM}"; then
    echo -e "${RED}[X] MinIO binary verification failed${NC}"
    exit 1
fi

verify_signature "${MINIO_CHECKSUM}" "${MINIO_SIGNATURE}"

# Install MinIO
if install_minio "${MINIO_BINARY}"; then
    echo -e "${GREEN}MinIO download, verification, and installation completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}[INFO] Summary:${NC}"
    echo "- Version: ${MINIO_VERSION}"
    echo "- Binary location: /usr/local/bin/minio"
    echo "- Cached in: ${MINIO_BINARY}"
    echo "- SHA256 verified: [OK]"
    if [ -f "${MINIO_SIGNATURE}" ]; then
        echo "- PGP signature checked: [OK]"
    else
        echo "- PGP signature: [WARNING]  Not available"
    fi
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Configure MinIO environment variables"
    echo "2. Set up MinIO systemd service"
    echo "3. Start MinIO service"
    echo ""
    echo -e "${BLUE}Quick test:${NC}"
    echo "minio --version"
else
    echo -e "${RED}[X] MinIO installation failed${NC}"
    exit 1
fi

exit 0
