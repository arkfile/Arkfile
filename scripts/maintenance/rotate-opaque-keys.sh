#!/bin/bash
# rotate-opaque-keys.sh - OPAQUE server key rotation runbook wrapper
#
# All cryptographic and database work is performed by arkfile-admin. This script
# documents and invokes the recommended atomic rotation flow.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ADMIN_USER="${ADMIN_USER:-admin}"

usage() {
    cat <<EOF
Usage: $0

OPAQUE server key rotation for the whole deployment.

This runs the atomic rotate subcommand, which:
  1. Flags every active account for one-time OPAQUE re-registration
  2. Clears all opaque_user_data rows
  3. Generates fresh OPAQUE server private key and OPRF seed
  4. Reloads the new keys in the running service (no restart required)
  5. Force-logs-out all sessions

ORDER IS LOAD-BEARING. Do not replace OPAQUE server keys before flagging
accounts. The atomic rotate command enforces the correct order.

Prerequisites:
  - Logged-in admin session: arkfile-admin login --username USER
  - arkfile-admin binary on PATH

Environment overrides:
  ADMIN_USER   Admin username for reminders only (default: admin)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -gt 0 ]]; then
    echo -e "${RED}Unknown option: $1${NC}"
    usage
    exit 1
fi

if ! command -v arkfile-admin >/dev/null 2>&1; then
    echo -e "${RED}ERROR: arkfile-admin not found on PATH${NC}"
    exit 1
fi

echo -e "${BLUE}OPAQUE Server Key Rotation${NC}"
echo -e "${YELLOW}Ensure you have run: arkfile-admin login --username ${ADMIN_USER}${NC}"
echo -e "${YELLOW}This flags every account and replaces server keys in one guarded step.${NC}"
echo

echo -e "${BLUE}Running atomic OPAQUE key rotation...${NC}"
arkfile-admin rotate-opaque-keys rotate --confirm

echo -e "${GREEN}[OK] OPAQUE server key rotation complete.${NC}"
echo "Each user will re-register on next login; files, shares, MFA, and settings are preserved."
