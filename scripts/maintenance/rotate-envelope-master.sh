#!/bin/bash
# rotate-envelope-master.sh - envelope master key rotation runbook wrapper
#
# All cryptographic work is performed by arkfile-admin. This script only documents
# and invokes the safe prepare/apply flow. Rotation re-wraps every system_keys row
# under a freshly generated ARKFILE_MASTER_KEY and regenerates the EntityID master.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

MANDATE_FILE="${MANDATE_FILE:-/root/envelope-rotation-mandate.txt}"
BASE_DIR="${BASE_DIR:-/opt/arkfile}"
ADMIN_USER="${ADMIN_USER:-admin}"

usage() {
    cat <<EOF
Usage: sudo $0 [--mandate-file PATH] [--base-dir DIR] [--admin-user USER]

Envelope master key rotation (re-wraps all system_keys rows under a new master).

Steps performed:
  1. arkfile-admin rotate-envelope-master prepare
  2. systemctl stop arkfile
  3. arkfile-admin rotate-envelope-master apply
  4. systemctl start arkfile

Prerequisites:
  - Logged-in admin session: arkfile-admin login --username USER
  - arkfile-admin binary on PATH

Environment overrides:
  MANDATE_FILE   Path for the signed mandate (default: /root/envelope-rotation-mandate.txt)
  BASE_DIR       Arkfile install root (default: /opt/arkfile)
  ADMIN_USER     Admin username for reminders only (default: admin)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mandate-file) MANDATE_FILE="$2"; shift 2 ;;
        --base-dir) BASE_DIR="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage; exit 1 ;;
    esac
done

if ! command -v arkfile-admin >/dev/null 2>&1; then
    echo -e "${RED}ERROR: arkfile-admin not found on PATH${NC}"
    exit 1
fi

echo -e "${BLUE}Envelope Master Key Rotation${NC}"
echo -e "${YELLOW}Ensure you have run: arkfile-admin login --username ${ADMIN_USER}${NC}"
echo

echo -e "${BLUE}[1/4] Issuing rotation mandate...${NC}"
arkfile-admin rotate-envelope-master prepare \
    --mandate-file "$MANDATE_FILE" \
    --confirm

echo -e "${BLUE}[2/4] Stopping arkfile service...${NC}"
systemctl stop arkfile

echo -e "${BLUE}[3/4] Applying rotation (offline re-wrap)...${NC}"
arkfile-admin rotate-envelope-master apply \
    --mandate-file "$MANDATE_FILE" \
    --base-dir "$BASE_DIR" \
    --confirm

echo -e "${BLUE}[4/4] Starting arkfile service...${NC}"
systemctl start arkfile

echo -e "${GREEN}[OK] Envelope master rotation complete.${NC}"
echo "Verify admin login and that the service starts cleanly under the new master."
echo "A new-master recovery copy and a secrets.env backup were written under ${BASE_DIR}/backups/envelope-rotation/."
