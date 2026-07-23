#!/bin/bash

# Arkfile Production Update Script
# Rebuilds and redeploys app binaries and static assets WITHOUT touching data, keys, or config.
# Shared body: scripts/setup/vps-update.sh

set -e

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/setup/build-config.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ARKFILE_DIR="/opt/arkfile"
ARKFILE_USER="arkfile"
ARKFILE_GROUP="arkfile"
SECRETS_ENV="$ARKFILE_DIR/etc/secrets.env"

source "$SCRIPT_DIR/setup/deploy-common.sh"

# Production update profile
UPDATE_KIND_LABEL="Production"
UPDATE_KIND_LABEL_LOWER="production"
UPDATE_SCRIPT_NAME="prod-update.sh"
PRIOR_DEPLOY_SCRIPT="prod-deploy.sh"
CADDYFILE_TEMPLATE="Caddyfile.prod"
BANNER_TITLE="ARKFILE PRODUCTION UPDATE"
COMPLETE_TITLE="PRODUCTION UPDATE COMPLETE"
INSTANCE_PHRASE="production instance"

# shellcheck source=setup/vps-update.sh
source "$SCRIPT_DIR/setup/vps-update.sh"
