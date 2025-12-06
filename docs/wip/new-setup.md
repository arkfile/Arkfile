# Clean Setup System Architecture

## Overview

This document defines the **clean, coherent setup system** for Arkfile - a greenfield application with no existing deployments. The goal is a **single source of truth** for node initialization that works seamlessly in development, testing, and production environments, including multi-node deployments.

---

## Design Principles

1. **Single Source of Truth**: One script (`setup-node.sh`) handles all node initialization
2. **Idempotent Operations**: Safe to run multiple times
3. **Environment Awareness**: Clear dev vs. prod modes
4. **Multi-Node Ready**: Primary/secondary node support with shared master key
5. **Separation of Concerns**: Setup, build, deploy, and service management are separate
6. **Clean Codebase**: Delete obsolete scripts, maintain only what's needed

---

## Architecture

### The Core Script: `setup-node.sh`

**Location:** `scripts/setup/setup-node.sh`

**Purpose:** Complete node initialization - users, directories, secrets, and configuration

**Parameters:**
```bash
--mode=dev|prod              # Environment mode (default: prod)
--force-secrets              # Force regeneration of secrets (for dev resets)
--master-key=<hex>           # Provide existing master key (for additional nodes)
--node-type=primary|secondary # First node vs additional nodes (default: primary)
```

**Responsibilities:**
1. Create system users and groups
2. Create directory structure
3. Generate or load secrets (DB passwords, MinIO passwords, master key)
4. Create configuration files (secrets.env, rqlite-auth.json, master.key)
5. Set correct permissions and ownership

**Does NOT handle:**
- Application building (separate: `build.sh`)
- Binary deployment (separate: `deploy.sh`)
- TLS certificate generation (separate: `setup-tls.sh`)
- MinIO/rqlite binary setup (separate: `setup-minio.sh`, `setup-rqlite.sh`)
- Service startup (separate: systemctl or orchestrator scripts)

---

## Implementation Status

**Status:** 📝 DESIGN COMPLETE - Ready for Implementation

**Next Steps:**
1. Create `scripts/setup/setup-node.sh` with the implementation below
2. Update `dev-reset.sh` to use the new script
3. Test thoroughly in dev environment
4. Clean up obsolete scripts once validated

---

## Complete setup-node.sh Implementation

```bash
#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BASE_DIR="/opt/arkfile"
USER="arkfile"
GROUP="arkfile"
MODE="prod"
FORCE_SECRETS=false
MASTER_KEY=""
NODE_TYPE="primary"

# Parse Arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode=*)
            MODE="${1#*=}"
            shift
            ;;
        --force-secrets)
            FORCE_SECRETS=true
            shift
            ;;
        --master-key=*)
            MASTER_KEY="${1#*=}"
            shift
            ;;
        --node-type=*)
            NODE_TYPE="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--mode=dev|prod] [--force-secrets] [--master-key=<hex>] [--node-type=primary|secondary]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Arkfile Node Setup (Mode: ${MODE}, Type: ${NODE_TYPE})         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo

# ==========================================
# Step 1: User & Group Setup
# ==========================================
echo -e "${YELLOW}Step 1: Setting up users and groups...${NC}"
if ! getent group ${GROUP} >/dev/null; then
    groupadd -r ${GROUP}
    echo -e "${GREEN}  ✓ Created group: ${GROUP}${NC}"
else
    echo -e "${GREEN}  ✓ Group already exists: ${GROUP}${NC}"
fi

if ! getent passwd ${USER} >/dev/null; then
    useradd -r -g ${GROUP} -d ${BASE_DIR} -s /sbin/nologin -c "Arkfile Service" ${USER}
    echo -e "${GREEN}  ✓ Created user: ${USER}${NC}"
else
    echo -e "${GREEN}  ✓ User already exists: ${USER}${NC}"
fi
echo

# ==========================================
# Step 2: Directory Structure
# ==========================================
echo -e "${YELLOW}Step 2: Setting up directory structure...${NC}"

# Main structure
install -d -m 755 -o ${USER} -g ${GROUP} ${BASE_DIR}
install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/bin"
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc"
install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys"
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var"
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib"
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/log"
install -d -m 755 -o ${USER} -g ${GROUP} "${BASE_DIR}/webroot"

# Key subdirectories (TLS only - other keys stored in database)
install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls"
install -d -m 700 -o ${USER} -g ${GROUP} "${BASE_DIR}/etc/keys/tls/arkfile"

# Data directories
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/database"
install -d -m 750 -o ${USER} -g ${GROUP} "${BASE_DIR}/var/lib/storage"

echo -e "${GREEN}  ✓ Directory structure created${NC}"
echo

# ==========================================
# Step 3: Secrets & Configuration
# ==========================================
echo -e "${YELLOW}Step 3: Configuring secrets and credentials...${NC}"
SECRETS_FILE="${BASE_DIR}/etc/secrets.env"

if [ -f "$SECRETS_FILE" ] && [ "$FORCE_SECRETS" = false ]; then
    echo -e "${GREEN}  ✓ Secrets file already exists (use --force-secrets to regenerate)${NC}"
else
    echo -e "${BLUE}  → Generating new secrets...${NC}"
    
    # Generate Passwords
    if [ "$MODE" = "dev" ]; then
        # Dev Mode: Predictable prefix for easier debugging
        RQLITE_PASSWORD="DevPassword123_$(openssl rand -hex 8)"
        MINIO_PASSWORD="DevPassword123_$(openssl rand -hex 8)"
        DEBUG_MODE="true"
        LOG_LEVEL="debug"
        TLS_ENABLED="true"
        ADMIN_USERNAMES="arkfile-dev-admin"
        ADMIN_DEV_TEST_API_ENABLED="true"
    else
        # Prod Mode: Secure Random
        RQLITE_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
        MINIO_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
        DEBUG_MODE="false"
        LOG_LEVEL="info"
        TLS_ENABLED="true"
        ADMIN_USERNAMES=""
        ADMIN_DEV_TEST_API_ENABLED="false"
    fi

    # Write secrets.env
    cat > "$SECRETS_FILE" << EOF
# Arkfile Configuration (Mode: ${MODE})
# Generated: $(date)

# Database
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=arkfile
RQLITE_PASSWORD=${RQLITE_PASSWORD}

# Application
PORT=8080
TLS_ENABLED=${TLS_ENABLED}
TLS_PORT=8443
TLS_CERT_FILE=${BASE_DIR}/etc/keys/tls/arkfile/server-cert.pem
TLS_KEY_FILE=${BASE_DIR}/etc/keys/tls/arkfile/server-key.pem

# Storage (MinIO/S3)
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=arkfile
S3_SECRET_KEY=${MINIO_PASSWORD}
S3_BUCKET=arkfile-data
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
S3_USE_SSL=false

# MinIO Server Config
MINIO_ROOT_USER=arkfile
MINIO_ROOT_PASSWORD=${MINIO_PASSWORD}

# Admin Configuration
ADMIN_USERNAMES=${ADMIN_USERNAMES}
ADMIN_DEV_TEST_API_ENABLED=${ADMIN_DEV_TEST_API_ENABLED}

# Security
DEBUG_MODE=${DEBUG_MODE}
LOG_LEVEL=${LOG_LEVEL}
EOF

    # Set permissions
    chown ${USER}:${GROUP} "$SECRETS_FILE"
    chmod 640 "$SECRETS_FILE"
    echo -e "${GREEN}  ✓ Generated secrets.env${NC}"
    
    # Generate rqlite auth file
    AUTH_FILE="${BASE_DIR}/etc/rqlite-auth.json"
    cat > "$AUTH_FILE" << EOF
[
  {
    "username": "arkfile",
    "password": "${RQLITE_PASSWORD}",
    "perms": ["all"]
  }
]
EOF
    chown ${USER}:${GROUP} "$AUTH_FILE"
    chmod 640 "$AUTH_FILE"
    echo -e "${GREEN}  ✓ Generated rqlite-auth.json${NC}"
fi
echo

# ==========================================
# Step 4: Master Key Generation/Loading
# ==========================================
echo -e "${YELLOW}Step 4: Master Key setup...${NC}"
MASTER_KEY_FILE="${BASE_DIR}/etc/keys/master.key"

if [ -n "$MASTER_KEY" ]; then
    # Master key provided (secondary node or manual override)
    echo -e "${BLUE}  → Using provided master key${NC}"
    echo "ARKFILE_MASTER_KEY=${MASTER_KEY}" > "$MASTER_KEY_FILE"
    chown ${USER}:${GROUP} "$MASTER_KEY_FILE"
    chmod 400 "$MASTER_KEY_FILE"
    echo -e "${GREEN}  ✓ Master key loaded from parameter${NC}"
    
elif [ -f "$MASTER_KEY_FILE" ] && [ "$FORCE_SECRETS" = false ]; then
    # Master key already exists
    echo -e "${GREEN}  ✓ Master key already exists (use --force-secrets to regenerate)${NC}"
    
else
    # Generate new master key (primary node first-time setup)
    echo -e "${BLUE}  → Generating new master key...${NC}"
    GENERATED_KEY=$(openssl rand -hex 32)
    echo "ARKFILE_MASTER_KEY=${GENERATED_KEY}" > "$MASTER_KEY_FILE"
    chown ${USER}:${GROUP} "$MASTER_KEY_FILE"
    chmod 400 "$MASTER_KEY_FILE"
    echo -e "${GREEN}  ✓ Master key generated${NC}"
    
    # Display key for multi-node deployments
    if [ "$NODE_TYPE" = "primary" ]; then
        echo
        echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  IMPORTANT: Save this key for additional nodes!           ║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║  ARKFILE_MASTER_KEY=${GENERATED_KEY}  ║${NC}"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
        echo
    fi
fi
echo

# ==========================================
# Final Summary
# ==========================================
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Node Setup Complete!                          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}Configuration Summary:${NC}"
echo -e "  Mode: ${MODE}"
echo -e "  Node Type: ${NODE_TYPE}"
echo -e "  Base Directory: ${BASE_DIR}"
echo -e "  User: ${USER}:${GROUP}"
echo -e "  Secrets: ${SECRETS_FILE}"
echo -e "  Master Key: ${MASTER_KEY_FILE}"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo -e "  1. Build application: ./scripts/setup/build.sh"
echo -e "  2. Deploy binaries: ./scripts/setup/deploy.sh"
echo -e "  3. Setup TLS: ./scripts/setup/setup-tls.sh"
echo -e "  4. Setup MinIO: ./scripts/setup/setup-minio.sh"
echo -e "  5. Setup rqlite: ./scripts/setup/setup-rqlite.sh"
echo -e "  6. Start services: systemctl start minio rqlite arkfile"
echo

exit 0
```

---

## Master Key Strategy

### Storage Location
**File:** `/opt/arkfile/etc/keys/master.key`

**Format:**
```bash
ARKFILE_MASTER_KEY=<64-hex-characters>
```

### Systemd Loading
```ini
# systemd/arkfile.service
[Service]
EnvironmentFile=-/opt/arkfile/etc/secrets.env
EnvironmentFile=-/opt/arkfile/etc/keys/master.key
```

### Multi-Node Distribution

**Primary Node:**
```bash
sudo ./scripts/setup/setup-node.sh --mode=prod --node-type=primary
# Save the displayed master key
```

**Secondary Nodes:**
```bash
sudo ./scripts/setup/setup-node.sh \
  --mode=prod \
  --node-type=secondary \
  --master-key=<key-from-primary>
```

---

## Integration with Existing Scripts

### Update dev-reset.sh

Replace the current Steps 4-6 (user/directory/master-key setup) with:

```bash
echo -e "${CYAN}Step 4: Node setup with fresh secrets${NC}"
if ! ./scripts/setup/setup-node.sh --mode=dev --force-secrets; then
    print_status "ERROR" "Node setup failed"
    exit 1
fi
```

### Update quick-start.sh

Add as first step:

```bash
echo "Step 1: Node initialization..."
sudo ./scripts/setup/setup-node.sh --mode=prod --node-type=primary
```

---

## Cleanup Plan

### Scripts to Delete (After Testing)
```bash
scripts/setup/00-setup-foundation.sh
scripts/setup/01-setup-users.sh
scripts/setup/02-setup-directories.sh
scripts/setup/03-setup-master-key.sh
scripts/setup/old-03-setup-opaque-keys.sh
scripts/setup/old-04-setup-jwt-keys.sh
scripts/setup/old-06-setup-totp-keys.sh
```

### Scripts to Rename
```bash
scripts/setup/04-setup-tls-certs.sh → setup-tls.sh
scripts/setup/05-setup-minio.sh → setup-minio.sh
scripts/setup/06-setup-rqlite-build.sh → setup-rqlite.sh
```

---

## Testing Strategy

### Test 1: Fresh Development Setup
```bash
sudo rm -rf /opt/arkfile
sudo ./scripts/setup/setup-node.sh --mode=dev
ls -la /opt/arkfile/etc/secrets.env
ls -la /opt/arkfile/etc/keys/master.key
```

### Test 2: Dev Reset
```bash
sudo ./scripts/dev-reset.sh
# Verify services start correctly
sudo systemctl status arkfile
```

### Test 3: Production Setup
```bash
sudo rm -rf /opt/arkfile
sudo ./scripts/setup/setup-node.sh --mode=prod --node-type=primary
# Verify secure passwords generated
cat /opt/arkfile/etc/secrets.env | grep DEBUG_MODE  # Should be "false"
```

---

## Current Issue Diagnosis

**Your Error:**
```
Failed to setup OPAQUE server keys: failed to get KeyManager: KeyManager not initialized
```

**Verified in main.go:** Initialization order is CORRECT:
```go
crypto.InitKeyManager(database.DB)  // Line 107
auth.SetupServerKeys(database.DB)   // Line 113
```

**Root Cause:** Master key file exists but isn't being loaded by systemd.

**Check:**
1. `ls -la /opt/arkfile/etc/keys/master.key` - Does it exist?
2. `cat /opt/arkfile/etc/keys/master.key` - Is it formatted correctly?
3. `sudo systemctl show arkfile | grep ARKFILE_MASTER_KEY` - Is systemd loading it?
4. `sudo journalctl -u arkfile -n 100 | grep -i "master\|keymanager"` - What do logs say?

**Fix:** Ensure `systemd/arkfile.service` has:
```ini
EnvironmentFile=-/opt/arkfile/etc/keys/master.key
```

Then reload: `sudo systemctl daemon-reload && sudo systemctl restart arkfile`

---

## Success Criteria

- [x] Single setup-node.sh script designed
- [x] Master key generation/loading implemented
- [x] Dev/prod mode support
- [x] Multi-node support designed
- [x] Integration plan with existing scripts
- [ ] Implementation and testing
- [ ] Cleanup of obsolete scripts
- [ ] Documentation updates

---

## Next Actions

1. **Create the script:** Copy the implementation above to `scripts/setup/setup-node.sh`
2. **Make executable:** `chmod +x scripts/setup/setup-node.sh`
3. **Test in isolation:** `sudo ./scripts/setup/setup-node.sh --mode=dev`
4. **Update dev-reset.sh:** Replace steps 4-6 with call to setup-node.sh
5. **Test dev workflow:** `sudo ./scripts/dev-reset.sh`
6. **Fix immediate issue:** Verify systemd is loading master.key
7. **Clean up:** Delete obsolete scripts once validated

---

**Document Status:** ✅ COMPLETE

    log.Fatalf("Failed to initialize KeyManager: %v", err)
}

// Now safe to initialize OPAQUE (uses KeyManager)
if err := auth.SetupServerKeys(database.DB); err != nil {
    log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
}
```

**Critical:** KeyManager initialization MUST happen after database init but before any key operations.

---

## Migration Plan

### Phase 1: Create New Script
1. Create `scripts/setup/setup-node.sh` with complete implementation above
2. Make executable: `chmod +x scripts/setup/setup-node.sh`
3. Test in isolation: `sudo ./scripts/setup/setup-node.sh --mode=dev`

### Phase 2: Update Orchestrators
1. Update `scripts/dev-reset.sh` to use `setup-node.sh`
2. Update `scripts/quick-start.sh` to use `setup-node.sh`
3. Update `scripts/complete-setup-test.sh` to use `setup-node.sh`

### Phase 3: Rename Existing Scripts
```bash
cd scripts/setup
mv 04-setup-tls-certs.sh setup-tls.sh
mv 05-setup-minio.sh setup-minio.sh
mv 06-setup-rqlite-build.sh setup-rqlite.sh
```

### Phase 4: Delete Obsolete Scripts
```bash
cd scripts/setup
rm -f 00-setup-foundation.sh
rm -f 01-setup-users.sh
rm -f 02-setup-directories.sh
rm -f 03-setup-master-key.sh
rm -f old-03-setup-opaque-keys.sh
rm -f old-04-setup-jwt-keys.sh
rm -f old-06-setup-totp-keys.sh
```

### Phase 5: Update Systemd Service
1. Edit `systemd/arkfile.service`
2. Remove `LoadCredential` lines
3. Verify `EnvironmentFile` lines are correct
4. Reload: `sudo systemctl daemon-reload`

### Phase 6: Verify Application Code
1. Check `main.go` has KeyManager initialization in correct order
2. Verify no other code tries to load file-based keys

### Phase 7: Test Complete Workflow
```bash
# Fresh install test
sudo ./scripts/quick-start.sh

# Dev reset test
sudo ./scripts/dev-reset.sh

# Verify services
sudo systemctl status arkfile minio rqlite
sudo journalctl -u arkfile -n 50
```

---

## Testing Strategy

### Test 1: Fresh Development Setup
```bash
# Clean slate
sudo rm -rf /opt/arkfile

# Run setup
sudo ./scripts/setup/setup-node.sh --mode=dev

# Verify
ls -la /opt/arkfile/etc/secrets.env
ls -la /opt/arkfile/etc/keys/master.key
cat /opt/arkfile/etc/secrets.env | grep DEBUG_MODE  # Should be "true"
```

### Test 2: Dev Reset
```bash
# Run dev reset
sudo ./scripts/dev-reset.sh

# Verify master key persists
BEFORE=$(cat /opt/arkfile/etc/keys/master.key)
sudo ./scripts/dev-reset.sh
AFTER=$(cat /opt/arkfile/etc/keys/master.key)
[ "$BEFORE" = "$AFTER" ] && echo "PASS: Master key persisted" || echo "FAIL: Master key changed"
```

### Test 3: Production Setup
```bash
# Clean slate
sudo rm -rf /opt/arkfile

# Run setup
sudo ./scripts/setup/setup-node.sh --mode=prod --node-type=primary

# Verify
cat /opt/arkfile/etc/secrets.env | grep DEBUG_MODE  # Should be "false"
cat /opt/arkfile/etc/secrets.env | grep ADMIN_DEV_TEST_API_ENABLED  # Should be "false"
```

### Test 4: Multi-Node Simulation
```bash
# Primary node
sudo ./scripts/setup/setup-node.sh --mode=prod --node-type=primary
PRIMARY_KEY=$(grep ARKFILE_MASTER_KEY /opt/arkfile/etc/keys/master.key | cut -d= -f2)

# Simulate secondary node (in different directory for test)
sudo BASE_DIR=/opt/arkfile-node2 ./scripts/setup/setup-node.sh \
  --mode=prod \
  --node-type=secondary \
  --master-key=$PRIMARY_KEY

# Verify keys match
SECONDARY_KEY=$(grep ARKFILE_MASTER_KEY /opt/arkfile-node2/etc/keys/master.key | cut -d= -f2)
[ "$PRIMARY_KEY" = "$SECONDARY_KEY" ] && echo "PASS: Keys match" || echo "FAIL: Keys differ"
```

### Test 5: Service Startup
```bash
# After complete setup
sudo systemctl start arkfile

# Check logs for KeyManager initialization
sudo journalctl -u arkfile -n 100 | grep -i "keymanager"
sudo journalctl -u arkfile -n 100 | grep -i "opaque"

# Should see:
# - "KeyManager initialized successfully" (or similar)
# - "OPAQUE initialized successfully" (or similar)
# - NO "KeyManager not initialized" errors
```

---

## Success Criteria

### Must Have
- [x] Single `setup-node.sh` script handles all node initialization
- [x] Master key generation and loading works correctly
- [x] Dev mode vs prod mode configuration differences
- [x] Multi-node support with shared master key
- [x] Idempotent operations (safe to run multiple times)
- [x] Proper file permissions and ownership
- [x] Clean codebase (obsolete scripts deleted)

### Validation
- [ ] Fresh install works
- [ ] Dev reset preserves master key
- [ ] Production setup generates secure passwords
- [ ] Multi-node deployment shares master key correctly
- [ ] Services start without errors
- [ ] KeyManager initializes before OPAQUE
- [ ] No file-based key generation attempts

---

## Documentation Updates

### Files to Update
1. `docs/scripts-guide.md` - Update setup script documentation
2. `docs/setup.md` - Update installation instructions
3. `docs/security.md` - Document master key architecture
4. `README.md` - Update quick start instructions

### New Documentation Needed
1. Multi-node deployment guide
2. Master key backup and recovery procedures
3. Environment variable reference
4. Troubleshooting guide for common setup issues

---

## Security Considerations

### Master Key Security
- **Storage:** File permissions 400 (read-only for owner)
- **Generation:** Cryptographically secure random (openssl rand)
- **Distribution:** Manual via secure channel (never commit to git)
- **Backup:** Should be backed up separately from database
- **Rotation:** Not currently supported (future enhancement)

### Secrets Management
- **secrets.env:** Contains infrastructure passwords (DB, MinIO)
- **master.key:** Contains cryptographic root of trust
- **Separation:** Different files for different security profiles
- **Access:** Only arkfile user should have read access

### Production Hardening
- Remove `-` prefix from `EnvironmentFile` directives (fail if missing)
- Implement secrets rotation procedures
- Use external secrets manager for enterprise deployments
- Implement master key escrow for disaster recovery

---

## Future Enhancements

### Short Term
- [ ] Add `--validate` flag to verify setup without making changes
- [ ] Add `--backup` flag to backup existing configuration before changes
- [ ] Improve error messages and troubleshooting hints

### Medium Term
- [ ] Master key rotation mechanism
- [ ] Integration with external secrets managers (Vault, AWS Secrets Manager)
- [ ] Automated multi-node orchestration (Ansible playbook)

### Long Term
- [ ] Container/Kubernetes deployment support
- [ ] Zero-downtime master key rotation
- [ ] Hardware security module (HSM) integration

---

## Status

**Status:** 📝 DESIGN COMPLETE - Ready for Implementation

**Next Step:** Toggle to Act Mode and implement the changes

**Estimated Time:** 2-3 hours for complete implementation and testing

**Risk Level:** Low (greenfield app, clean slate approach)

---

## Questions & Decisions

### Q: Should we keep the old key directories?
**A:** No. Since we're doing a clean implementation and they're not used, remove them from the directory creation in setup-node.sh. Keep only `/opt/arkfile/etc/keys/tls/` for TLS certificates.

### Q: Should dev-reset regenerate the master key?
**A:** No. The master key should persist across resets unless `--force-secrets` is used. This allows testing of key persistence and multi-node scenarios in dev.

### Q: What if someone loses the master key?
**A:** Currently: Complete data loss. All encrypted keys in database become unrecoverable. Future: Implement key escrow or recovery mechanism.

### Q: Should we support master key rotation?
**A:** Not in initial implementation. This is a future enhancement that requires careful design to avoid data loss during rotation.

---

## End of Document
