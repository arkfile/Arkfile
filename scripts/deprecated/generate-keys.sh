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

echo -e "${GREEN}Arkfile Key Generation Helper${NC}"
echo "============================="
echo ""
echo "This script provides utilities for generating cryptographic keys."
echo "For a complete deployment setup, use first-time-setup.sh instead."
echo ""

# Function to generate a random key
generate_key() {
    openssl rand -hex 32
}

# Function to generate environment configuration
generate_env_config() {
    local env_name=$1
    local output_file=$2
    
    echo "# Arkfile Configuration - ${env_name} Environment"
    echo "# Generated on: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "# Server Configuration"
    echo "PORT=8080"
    echo "HOST=localhost"
    echo "BASE_URL=http://localhost:8080"
    echo ""
    echo "# Database Configuration"
    echo "DB_PATH=${ARKFILE_DIR}/var/lib/database/arkfile.db"
    echo ""
    echo "# Cryptographic Keys"
    echo "JWT_SECRET=$(generate_key)"
    echo ""
    echo "# Storage Configuration (Backblaze B2)"
    echo "BACKBLAZE_ENDPOINT="
    echo "BACKBLAZE_KEY_ID="
    echo "BACKBLAZE_APPLICATION_KEY="
    echo "BACKBLAZE_BUCKET_NAME="
    echo ""
    echo "# Security Configuration"
    echo "REFRESH_TOKEN_EXPIRY_HOURS=168"
    echo "REFRESH_TOKEN_COOKIE_NAME=refreshToken"
    echo "REVOKE_USED_REFRESH_TOKENS=true"
    echo ""
    echo "# Argon2ID Configuration (Server-side for authentication)"
    echo "SERVER_ARGON2ID_TIME=4"
    echo "SERVER_ARGON2ID_MEMORY=131072"
    echo "SERVER_ARGON2ID_THREADS=4"
    echo ""
    echo "# Argon2ID Configuration (Client-side for file encryption)"
    echo "CLIENT_ARGON2ID_TIME=4"
    echo "CLIENT_ARGON2ID_MEMORY=131072"
    echo "CLIENT_ARGON2ID_THREADS=4"
    echo ""
    echo "# Key Management"
    echo "ARKFILE_KEY_DIRECTORY=${ARKFILE_DIR}/etc/keys"
    echo "ARKFILE_USE_SYSTEMD_CREDS=true"
    echo ""
    echo "# Deployment"
    echo "ARKFILE_ENV=${env_name}"
    echo "ARKFILE_DATA_DIRECTORY=${ARKFILE_DIR}/var/lib"
    echo "ARKFILE_LOG_DIRECTORY=${ARKFILE_DIR}/var/log"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  env-config [ENV_NAME]    Generate environment configuration"
    echo "  jwt-secret               Generate a JWT secret"
    echo "  help                     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 env-config production > /opt/arkfile/etc/arkfile.env"
    echo "  $0 jwt-secret"
    echo ""
    echo "Note: For complete deployment setup, use first-time-setup.sh"
}

# Main command handling
case "${1:-help}" in
    "env-config")
        env_name="${2:-production}"
        echo -e "${BLUE}Generating environment configuration for: ${env_name}${NC}" >&2
        echo -e "${YELLOW}Redirect output to save to file:${NC}" >&2
        echo -e "  $0 env-config ${env_name} > /opt/arkfile/etc/arkfile.env" >&2
        echo "" >&2
        generate_env_config "$env_name"
        ;;
    
    "jwt-secret")
        echo -e "${BLUE}Generated JWT Secret:${NC}" >&2
        echo "$(generate_key)"
        ;;
    
    "help"|"--help"|"-h")
        show_usage
        ;;
    
    *)
        echo -e "${RED}Unknown command: $1${NC}" >&2
        echo "" >&2
        show_usage
        exit 1
        ;;
esac
