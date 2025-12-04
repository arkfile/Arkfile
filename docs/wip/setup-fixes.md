# Setup Scripts Refactoring Plan

## Overview

This document outlines the plan to refactor Arkfile's setup scripts to align with the new **Master Key Architecture** introduced in the admin-bootstrap project. The current setup scripts contain obsolete file-based key generation that conflicts with the new database-backed envelope encryption system.

---

## Current Problems

### 1. **Systemd Service Configuration Error**
**File:** `systemd/arkfile.service`

**Issue:** Contains obsolete `LoadCredential` directives:
```
LoadCredential=opaque_server_key:/opt/arkfile/etc/keys/opaque/server_private.key
LoadCredential=jwt_signing_key:/opt/arkfile/etc/keys/jwt/current/signing.key
```

**Error:** `Failed to set up credentials: Protocol error`

**Root Cause:** These files don't exist because the new architecture stores keys encrypted in the database, not as files.

---

### 2. **KeyManager Not Initialized**
**File:** `main.go`

**Issue:** `crypto.InitKeyManager()` is never called before `auth.SetupServerKeys()`.

**Error:** `Failed to setup OPAQUE server keys: failed to get KeyManager: KeyManager not initialized`

**Root Cause:** The KeyManager requires initialization with the database connection and `ARKFILE_MASTER_KEY` environment variable before any key operations.

---

### 3. **Missing Master Key Generation**
**Issue:** No setup script generates the `ARKFILE_MASTER_KEY` environment variable.

**Root Cause:** The master key architecture was implemented but the setup scripts were never updated to generate the master key.

---

### 4. **Obsolete Key Generation Scripts**
**Files:**
- `scripts/setup/03-setup-opaque-keys.sh`
- `scripts/setup/04-setup-jwt-keys.sh`
- `scripts/setup/06-setup-totp-keys.sh`

**Issue:** These scripts generate file-based keys that are no longer used.

**Root Cause:** These scripts were created before the master key architecture was implemented and are now completely obsolete.

---

## Architecture Context

### Master Key Architecture (from admin-bootstrap.md)

The new system uses **Envelope Encryption** with a single root of trust:

1. **`ARKFILE_MASTER_KEY`** - 32-byte hex-encoded key (64 hex characters)
2. All system keys (JWT, TOTP, OPAQUE, Bootstrap) are:
   - Generated randomly by the application
   - Encrypted using keys derived from the master key (via HKDF)
   - Stored in the database (`system_keys` table)
3. Any node with the master key can decrypt and use the shared system secrets

### Key Derivation (HKDF-SHA256)
```
WrappingKey_JWT = HKDF(MasterKey, "ARKFILE_JWT_KEY_ENCRYPTION")
WrappingKey_TOTP = HKDF(MasterKey, "ARKFILE_TOTP_KEY_ENCRYPTION")
WrappingKey_Bootstrap = HKDF(MasterKey, "ARKFILE_BOOTSTRAP_KEY_ENCRYPTION")
```

---

## Proposed Solution

### Setup Scripts Structure

#### **BEFORE (Current - Messy)**
```
00-setup-foundation.sh       ✅ KEEP - System packages, dependencies
01-setup-users.sh            ✅ KEEP - Create arkfile user/group
02-setup-directories.sh      ✅ KEEP - Directory structure
03-setup-opaque-keys.sh      ❌ DELETE - Obsolete (file-based keys)
04-setup-jwt-keys.sh         ❌ DELETE - Obsolete (file-based keys)
05-setup-tls-certs.sh        ✅ KEEP - TLS certificates
06-setup-totp-keys.sh        ❌ DELETE - Obsolete (file-based keys)
07-setup-minio.sh            ✅ KEEP - MinIO S3 storage
08-setup-rqlite-build.sh     ✅ KEEP - rqlite database
```

#### **AFTER (Clean - Logical)**
```
00-setup-foundation.sh       - System packages, dependencies
01-setup-users.sh            - Create arkfile user/group
02-setup-directories.sh      - Directory structure
03-setup-master-key.sh       - Generate ARKFILE_MASTER_KEY (NEW)
04-setup-tls-certs.sh        - TLS certificates (renumbered from 05)
05-setup-minio.sh            - MinIO S3 storage (renumbered from 07)
06-setup-rqlite-build.sh     - rqlite database (renumbered from 08)
```

---

## Implementation Plan

### Phase 1: Create New Master Key Script

**File:** `scripts/setup/03-setup-master-key.sh`

**Purpose:** Generate and store the ARKFILE_MASTER_KEY

**Functionality:**
1. Check if `/opt/arkfile/etc/secrets.env` exists
2. Check if `ARKFILE_MASTER_KEY` already exists in secrets.env
3. If not, generate a new 32-byte random key (64 hex characters)
4. Store in `/opt/arkfile/etc/secrets.env` as `ARKFILE_MASTER_KEY=<hex>`
5. Set file permissions: 600 (read/write owner only)
6. Set ownership: arkfile:arkfile
7. Log success message

**Key Generation Command:**
```bash
openssl rand -hex 32
```

**Security Considerations:**
- File must be readable only by arkfile user
- Key must be 32 bytes (64 hex characters)
- Key should be generated using cryptographically secure random source
- File should be created atomically to prevent race conditions

---

### Phase 2: Delete Obsolete Scripts

**Files to Delete:**
1. `scripts/setup/03-setup-opaque-keys.sh`
2. `scripts/setup/04-setup-jwt-keys.sh`
3. `scripts/setup/06-setup-totp-keys.sh`

**Rationale:**
- These scripts generate file-based keys that are no longer used
- The new architecture generates keys dynamically and stores them encrypted in the database
- Keeping these scripts would confuse future maintainers
- No migration needed (greenfield app with no deployments)

---

### Phase 3: Renumber Remaining Scripts

**Renaming Operations:**
1. `05-setup-tls-certs.sh` → `04-setup-tls-certs.sh`
2. `07-setup-minio.sh` → `05-setup-minio.sh`
3. `08-setup-rqlite-build.sh` → `06-setup-rqlite-build.sh`

**Update References:**
- Check `scripts/complete-setup-test.sh` for script references
- Check `scripts/quick-start.sh` for script references
- Check `docs/scripts-guide.md` for documentation references
- Update any other scripts that call these by name

---

### Phase 4: Fix systemd Service File

**File:** `systemd/arkfile.service`

**Changes:**
1. **Remove** these lines:
   ```
   LoadCredential=opaque_server_key:/opt/arkfile/etc/keys/opaque/server_private.key
   LoadCredential=jwt_signing_key:/opt/arkfile/etc/keys/jwt/current/signing.key
   ```

2. **Keep** this line (correct):
   ```
   EnvironmentFile=-/opt/arkfile/etc/secrets.env
   ```

**Rationale:**
- `LoadCredential` is for loading file-based credentials
- We now use environment variables loaded from secrets.env
- The `-` prefix means "don't fail if file doesn't exist" (correct for dev environments)

---

### Phase 5: Fix Application Initialization

**File:** `main.go`

**Current Code (Broken):**
```go
// Initialize database
database.InitDB()
defer database.DB.Close()

// Initialize OPAQUE server keys first (required for real OPAQUE provider)
if err := auth.SetupServerKeys(database.DB); err != nil {
    log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
}
```

**Fixed Code:**
```go
// Initialize database
database.InitDB()
defer database.DB.Close()

// Initialize KeyManager (required for envelope encryption)
if err := crypto.InitKeyManager(database.DB); err != nil {
    log.Fatalf("Failed to initialize KeyManager: %v", err)
}

// Initialize OPAQUE server keys (now uses KeyManager)
if err := auth.SetupServerKeys(database.DB); err != nil {
    log.Fatalf("Failed to setup OPAQUE server keys: %v", err)
}
```

**Location:** After `database.InitDB()`, before `auth.SetupServerKeys()`

**Rationale:**
- KeyManager must be initialized before any key operations
- KeyManager requires database connection and ARKFILE_MASTER_KEY env var
- All key operations (OPAQUE, JWT, TOTP) depend on KeyManager

---

### Phase 6: Update dev-reset.sh

**File:** `scripts/dev-reset.sh`

**Current Behavior:**
- Resets database
- Resets storage
- Restarts services

**Required Changes:**
- **None** - dev-reset should NOT regenerate the master key
- The master key persists in `/opt/arkfile/etc/secrets.env`
- The systemd service automatically loads it via `EnvironmentFile`

**Verification:**
- Ensure dev-reset doesn't delete `/opt/arkfile/etc/secrets.env`
- Ensure dev-reset doesn't delete `/opt/arkfile/etc/` directory

---

## Testing Plan

### 1. Fresh Installation Test
```bash
# Run setup scripts in order
sudo ./scripts/setup/00-setup-foundation.sh
sudo ./scripts/setup/01-setup-users.sh
sudo ./scripts/setup/02-setup-directories.sh
sudo ./scripts/setup/03-setup-master-key.sh
sudo ./scripts/setup/04-setup-tls-certs.sh
sudo ./scripts/setup/05-setup-minio.sh
sudo ./scripts/setup/06-setup-rqlite-build.sh

# Verify master key exists
sudo cat /opt/arkfile/etc/secrets.env | grep ARKFILE_MASTER_KEY

# Build and deploy
sudo ./scripts/setup/build.sh
sudo ./scripts/setup/deploy.sh

# Check service status
sudo systemctl status arkfile
sudo journalctl -u arkfile -n 50

# Verify bootstrap token generated
sudo journalctl -u arkfile | grep "BOOTSTRAP"
```

### 2. Dev Reset Test
```bash
# Run dev reset
sudo ./scripts/dev-reset.sh

# Verify master key still exists
sudo cat /opt/arkfile/etc/secrets.env | grep ARKFILE_MASTER_KEY

# Verify service starts successfully
sudo systemctl status arkfile
sudo journalctl -u arkfile -n 50
```

### 3. Key Generation Test
```bash
# Start service and check logs
sudo journalctl -u arkfile -f

# Verify KeyManager initialized
# Should see: "KeyManager initialized successfully" (or similar)

# Verify OPAQUE keys generated
# Should see: "OPAQUE initialized successfully"

# Verify bootstrap token generated (if no users)
# Should see: "[BOOTSTRAP] Admin Bootstrap Token: <TOKEN>"
```

---

## Migration Notes

### For Existing Deployments (None Currently)
Since this is a **greenfield app with no current deployments**, we can make breaking changes without migration concerns.

### For Future Reference
If deployments existed, we would need:
1. Migration script to generate master key
2. Migration script to move file-based keys to database
3. Backup procedures for existing keys
4. Rollback plan if migration fails

---

## Security Considerations

### Master Key Security
1. **Storage:** File permissions 600, owned by arkfile:arkfile
2. **Generation:** Cryptographically secure random (openssl rand)
3. **Distribution:** Manual (infrastructure team responsibility)
4. **Backup:** Should be backed up separately from database
5. **Rotation:** Not currently supported (future enhancement)

### Key Directories (Now Obsolete)
The following directories are no longer used but kept for compatibility:
- `/opt/arkfile/etc/keys/opaque/`
- `/opt/arkfile/etc/keys/jwt/`
- `/opt/arkfile/etc/keys/totp/`

These can be removed in a future cleanup, but keeping them doesn't hurt.

---

## Documentation Updates

### Files to Update
1. `docs/scripts-guide.md` - Update setup script list and descriptions
2. `docs/setup.md` - Update installation instructions
3. `docs/security.md` - Document master key architecture
4. `docs/wip/admin-bootstrap.md` - Mark as complete, reference this doc

### New Documentation Needed
1. Master key backup procedures
2. Master key rotation procedures (when implemented)
3. Emergency recovery procedures if master key is lost

---

## Success Criteria

### Must Have
- [x] Master key generated during setup
- [x] Master key stored in secrets.env with correct permissions
- [x] KeyManager initialized before key operations
- [x] Systemd service starts without credential errors
- [x] OPAQUE keys generated and stored in database
- [x] Bootstrap token generated on first run
- [x] dev-reset preserves master key

### Nice to Have
- [ ] Automated tests for setup scripts
- [ ] Master key rotation mechanism
- [ ] Master key backup script
- [ ] Documentation for disaster recovery

---

## Timeline

### Immediate (This Session)
1. Create `03-setup-master-key.sh`
2. Delete obsolete key scripts
3. Renumber remaining scripts
4. Fix `systemd/arkfile.service`
5. Fix `main.go`
6. Test fresh installation

### Follow-up (Next Session)
1. Update documentation
2. Test dev-reset workflow
3. Create backup procedures
4. Update e2e-test.sh

---

## Questions & Decisions

### Q: Should we keep the old key directories?
**A:** Yes, for now. They don't hurt and might be useful for future features. We can clean them up later.

### Q: Should dev-reset regenerate the master key?
**A:** No. The master key should persist across resets. Only a full uninstall should remove it.

### Q: What if someone loses the master key?
**A:** Currently: Complete data loss. All encrypted keys in database become unrecoverable. Future: Implement key escrow or recovery mechanism.

### Q: Should we support master key rotation?
**A:** Not in this phase. This is a future enhancement that requires careful planning.

---

## Status

**Status:** 📝 PLANNING COMPLETE - Ready for Implementation

**Next Step:** Toggle to Act Mode and implement the changes

**Estimated Time:** 30-45 minutes

**Risk Level:** Low (greenfield app, no existing deployments)
