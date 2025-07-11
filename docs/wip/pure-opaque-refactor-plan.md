# Pure OPAQUE Refactor Plan

## Objective
Refactor from current Argon2id-layered OPAQUE implementation to pure OPAQUE with Context parameter "arkfile-v1" for enhanced security and simplified architecture.

## Security Rationale
- Current implementation creates verification oracle attack vector
- Storing both ServerArgonSalt and HardenedEnvelope in database enables faster password attacks
- Pure OPAQUE provides optimal security without additional attack surfaces
- Context parameter adds domain separation without complexity

## Implementation Plan

### Phase 1: Database Schema Updates
**Files to update:**
- `database/schema_extensions.sql` - Simplify OPAQUE table schema

**Changes:**
- Remove Argon2id hardening fields from opaque_user_data table
- Keep only essential OPAQUE fields: user_email, serialized_record, created_at
- Remove device_profile dependency

### Phase 2: Core OPAQUE Implementation
**Files to update:**
- `auth/opaque.go` - Complete refactor for pure OPAQUE
- `auth/opaque_test.go` - Update all tests

**Key changes:**
- Add Context parameter "arkfile-v1" to OPAQUE configuration
- Remove all Argon2id hardening layers
- Simplify data structures (remove ClientArgonSalt, ServerArgonSalt, HardenedEnvelope, DeviceProfile)
- Remove deviceCapability parameter from all functions
- Use passwords directly with OPAQUE (no pre/post hardening)

### Phase 3: Handler Updates
**Files to update:**
- `handlers/auth.go` - Update registration/login handlers
- `handlers/auth_test.go` - Update handler tests

**Changes:**
- Remove deviceCapability parameter from registration endpoints
- Simplify registration request validation
- Update error handling for simplified flow

### Phase 4: Test Infrastructure
**Files to update:**
- `auth/opaque_test.go` - Comprehensive test rewrite
- `handlers/auth_test.go` - Update integration tests

**Changes:**
- Remove device capability testing
- Focus on pure OPAQUE protocol testing
- Test Context parameter integration
- Verify simplified database schema

### Phase 5: Documentation Updates
**Files to update:**
- `docs/security.md` - Update OPAQUE security documentation
- `docs/api.md` - Update API documentation for simplified endpoints
- `README.md` - Update architecture description

**Changes:**
- Document pure OPAQUE approach
- Remove references to Argon2id layering
- Update security model documentation
- Document Context parameter benefits

### Phase 6: Script and Configuration Updates
**Files to check:**
- `scripts/setup/03-setup-opaque-keys.sh` - Verify OPAQUE setup scripts
- `config/security_config.go` - Remove device capability configurations
- Any other scripts referencing device capabilities

## Implementation Order
1. Update database schema (no migration needed - fresh deployment)
2. Refactor core OPAQUE implementation
3. Update handlers and remove device capability logic
4. Update all tests
5. Update documentation
6. Verify scripts and configurations

## Success Criteria
- All tests pass with pure OPAQUE implementation
- Context parameter "arkfile-v1" properly integrated
- No references to Argon2id hardening in authentication flow
- Simplified API endpoints without device capability parameters
- Clean, maintainable codebase following OPAQUE best practices

## Security Benefits
- Eliminates verification oracle attack vector
- Reduces attack surface by removing additional cryptographic layers
- Maintains OPAQUE's proven security guarantees
- Adds domain separation through Context parameter
- Simplifies security analysis and maintenance
