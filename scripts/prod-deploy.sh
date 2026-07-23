#!/bin/bash

# Arkfile Production Deployment Script
# First-time VPS deployment for a production domain using Caddy + Let's Encrypt + deSEC
# Shared body: scripts/setup/vps-first-deploy.sh

set -e

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

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

# Production profile
VERSION_PREFIX="prod"
RQLITE_USERNAME="arkfile-db"
SEAWEED_ACCESS_KEY="arkfile"
SEAWEED_BUCKET="arkfile"
SEAWEED_PROVIDER_ID="generic-s3:arkfile"
SEAWEED_IDENTITY_NAME="arkfile"
CADDYFILE_TEMPLATE="Caddyfile.prod"
DEPLOY_KIND_LABEL="Production"
DEPLOY_SCRIPT_NAME="prod-deploy.sh"
UPDATE_SCRIPT_HINT="scripts/prod-update.sh"
DOMAIN_EXAMPLE="arkfile.example.com"
BANNER_TITLE="ARKFILE PRODUCTION DEPLOYMENT"
COMPLETE_TITLE="DEPLOYMENT COMPLETE"
INSTANCE_BLURB="Your Arkfile instance is running at:"

# shellcheck source=setup/vps-first-deploy.sh
source "$SCRIPT_DIR/setup/vps-first-deploy.sh"
