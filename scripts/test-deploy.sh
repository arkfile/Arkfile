#!/bin/bash

# Arkfile Test Deployment Script
# First-time VPS deployment for a real domain using Caddy + Let's Encrypt + deSEC
# Shared body: scripts/setup/vps-first-deploy.sh

set -e

# ensure standard locations always in path regardless of sudo stripping PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

# Source shared build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/setup/build-config.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration defaults
ARKFILE_DIR="/opt/arkfile"
ARKFILE_USER="arkfile"
ARKFILE_GROUP="arkfile"

# Preserve original user context for Go operations
ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_UID="${SUDO_UID:-$(id -u)}"
ORIGINAL_GID="${SUDO_GID:-$(id -g)}"

source "$SCRIPT_DIR/setup/deploy-common.sh"

# Test profile
VERSION_PREFIX="test"
RQLITE_USERNAME="test-user"
SEAWEED_ACCESS_KEY="arkfile-test"
SEAWEED_BUCKET="arkfile-test"
SEAWEED_PROVIDER_ID="generic-s3:arkfile-test"
SEAWEED_IDENTITY_NAME="arkfile"
CADDYFILE_TEMPLATE="Caddyfile.test"
DEPLOY_KIND_LABEL="Test"
DEPLOY_SCRIPT_NAME="test-deploy.sh"
UPDATE_SCRIPT_HINT="scripts/test-update.sh"
DOMAIN_EXAMPLE="test.arkfile.net"
BANNER_TITLE="ARKFILE TEST DEPLOYMENT"
COMPLETE_TITLE="TEST DEPLOYMENT COMPLETE"
INSTANCE_BLURB="Your Arkfile test instance is running at:"

# shellcheck source=setup/vps-first-deploy.sh
source "$SCRIPT_DIR/setup/vps-first-deploy.sh"
