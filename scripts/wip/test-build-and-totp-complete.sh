#!/bin/bash
# Test Script for TOTP System Verification
# Path: scripts/wip/test-build-and-totp-complete.sh

# Configuration
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
JS_DIR="client/static/js"
LOG_FILE="/tmp/totp-test-$(date +%s).log"

# Clean startup
> "$LOG_FILE"
echo -e "${YELLOW}=== TOTP System Validation Test ===${NC}"
echo "Detailed logs will be written to: $LOG_FILE"

# Phase 0: Preflight Checks
check_bun_installation() {
  if ! command -v bun &>/dev/null; then
    echo -e "${RED}❌ Bun not found!${NC}" | tee -a "$LOG_FILE"
    echo "Attempt automatic installation? [y/N]"
    read -r answer
    if [ "$answer" = "y" ]; then
      echo "Installing bun..."
      curl -fsSL https://bun.sh/install | bash >> "$LOG_FILE" 2>&1 || {
        echo -e "${RED}Failed to install bun!${NC}" | tee -a "$LOG_FILE"
        exit 1
      }
      export PATH="$HOME/.bun/bin:$PATH"
      source ~/.bashrc
    else
      exit 1
    fi
 fi
}

# Phase 1: TypeScript Build Process
clean_build() {
  echo -e "\n${YELLOW}=== STARTING TYPESCRIPT BUILD ===${NC}" | tee -a "$LOG_FILE"
  
  # Clean previous artifacts
  rm -rf "$JS_DIR/dist"/*
  
  # Run TypeScript build
  cd "$JS_DIR" || exit 1
  echo -e "${YELLOW}Running TypeScript build...${NC}" | tee -a "$LOG_FILE"
  bun install --force >> "$LOG_FILE" 2>&1 && \
  bun run build:prod >> "$LOG_FILE" 2>&1
  
  # Verify artifacts
  if [ -f "$JS_DIR/dist/app.js" ]; then
    js_size=$(du -h "$JS_DIR/dist/app.js" | cut -f1)
    echo -e "${GREEN}✓ Built JS file (${js_size}B)${NC}" | tee -a "$LOG_FILE"
  else
    echo -e "${RED}❌ Build failed - no JS artifacts!${NC}" | tee -a "$LOG_FILE"
    exit 1
  fi
}

# Phase 2: Service Management
service_checks() {
  echo -e "\n${YELLOW}=== SERVICE CHECKS ===${NC}" | tee -a "$LOG_FILE"
  
  # Check service endpoint
  curl_status=$(curl -sI http://localhost:8080/js/dist/app.js | head -1 | cut -d' ' -f2)
  if [ "$curl_status" = "200" ]; then
    echo -e "${GREEN}➜ Service responding on port 8080${NC}" | tee -a "$LOG_FILE"
  else
    echo -e "${RED}❌ Service not responding (HTTP ${curl_status:-000})${NC}" | tee -a "$LOG_FILE"
    echo -e "\nTry restarting service with: \n\
    ${YELLOW}sudo systemctl stop arkfile && sudo systemctl start arkfile${NC}"
    exit 1
  fi
}

# Phase 3: TOTP Workflow Test
test_full_totp_flow() {
  echo -e "\n${YELLOW}=== TESTING TOTP WORKFLOW ===${NC}" | tee -a "$LOG_FILE"

  # Test registration flow
  echo -e "${YELLOW}➜ Testing user registration...${NC}" 
  registration_response=$(curl -sS -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"validpassword"}' \
    http://localhost:8080/api/opaque/register)
  
  if [[ "$registration_response" == *"registration_successful"* ]]; then
    echo -e "${GREEN}✓ User registered successfully${NC}" | tee -a "$LOG_FILE"
  else
    echo -e "${RED}❌ Registration failed: $registration_response${NC}" | tee -a "$LOG_FILE"
    exit 1
  fi

  # Get authentication token
  auth_token=$(curl -sS -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"validpassword"}' \
    http://localhost:8080/api/opaque/login | jq -r .token)
  
  if [ -z "$auth_token" ]; then
    echo -e "${RED}❌ Failed to get auth token${NC}" | tee -a "$LOG_FILE"
    exit 1
  fi

  # Validate TOTP code (use dynamic code for production)
  totp_response=$(curl -sS -H "Authorization: Bearer $auth_token" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","code":"123456"}' \
    http://localhost:8080/api/totp/auth)
  
  if [[ "$totp_response" == *"totp_validated"* ]]; then
    echo -e "${GREEN}✓ TOTP validation succeeded${NC}" | tee -a "$LOG_FILE"
  else
    echo -e "${RED}❌ TOTP validation failed: $totp_response${NC}" | tee -a "$LOG_FILE"
    exit 1
  fi
}

# Main Execution Flow
check_bun_installation
clean_build
service_checks
test_full_totp_flow

echo -e "\n${GREEN}=== TEST COMPLETED SUCCESSFULLY ===${NC}" | tee -a "$LOG_FILE"
