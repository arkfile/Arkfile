# Admin Bootstrap & Secret Management Architecture

This document outlines the architecture for securely bootstrapping the first admin user and managing system secrets in a distributed environment.

## 1. The Master Key Architecture

To support distributed deployments (e.g., Kubernetes, Podman) without complex file-sharing requirements, Arkfile uses an **Envelope Encryption** strategy rooted in a single environment variable.

### The Root of Trust
*   **`ARKFILE_MASTER_KEY`**: A 32-byte hex-encoded key provided via environment variable to all nodes.
*   **Database Credentials**: `RQLITE_USERNAME` and `RQLITE_PASSWORD` provided via environment variables.

### Envelope Encryption
All other system secrets (JWT signing keys, TOTP master keys, OPAQUE server keys) are:
1.  **Generated Randomly** by the first node that starts up.
2.  **Encrypted** using a key derived from the `ARKFILE_MASTER_KEY`.
3.  **Stored** in the database (`system_keys` table).

This allows any node with the Master Key to decrypt and use the shared system secrets, enabling seamless scaling and rotation.

### Secret Management Matrix

| Secret Type | Source | Storage Location | Encryption Strategy | Distribution |
| :--- | :--- | :--- | :--- | :--- |
| **Master Key** | Env Var | Memory Only | N/A | Manual (Infrastructure) |
| **Database Creds** | Env Var | Memory Only | N/A | Manual (Infrastructure) |
| **JWT Signing Keys** | App Generated | Database | Encrypted w/ Master Key | Automatic (via DB) |
| **TOTP Master Key** | App Generated | Database | Encrypted w/ Master Key | Automatic (via DB) |
| **Entity ID Key** | App Generated | Database | Encrypted w/ Master Key | Automatic (via DB) |
| **OPAQUE Server Keys** | App Generated | Database | Encrypted w/ Master Key | Automatic (via DB) |
| **Bootstrap Token** | App Generated | Database | Encrypted w/ Master Key | Automatic (via DB) |

### Key Derivation (HKDF)
We use HKDF-SHA256 to derive specific *wrapping keys* from the Master Key to ensure domain separation:
*   `WrappingKey_JWT` = `HKDF(MasterKey, "ARKFILE_JWT_KEY_ENCRYPTION")`
*   `WrappingKey_TOTP` = `HKDF(MasterKey, "ARKFILE_TOTP_KEY_ENCRYPTION")`
*   `WrappingKey_Bootstrap` = `HKDF(MasterKey, "ARKFILE_BOOTSTRAP_KEY_ENCRYPTION")`

---

## 2. Database Schema

A new table `system_keys` will store the encrypted secrets.

```sql
CREATE TABLE system_keys (
    key_id TEXT PRIMARY KEY,      -- e.g., "jwt_signing_key_v1", "bootstrap_token"
    key_type TEXT NOT NULL,       -- e.g., "jwt", "totp", "opaque", "bootstrap"
    encrypted_data BLOB NOT NULL, -- The encrypted secret
    nonce BLOB NOT NULL,          -- The nonce used for encryption (AES-GCM)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP          -- Optional (for Bootstrap Token)
);
```

---

## 3. The Bootstrap Protocol

The bootstrap process allows the owner to create the first Admin User without hardcoding credentials.

### Step 1: Token Generation (Server Startup)
1.  Server starts and checks if any users exist in the `users` table.
2.  If **Zero Users**:
    *   Generate a random 32-byte `BootstrapToken`.
    *   Encrypt it using `WrappingKey_Bootstrap`.
    *   Store it in `system_keys` with `key_id="bootstrap_token"`.
    *   **Log the Raw Token** to stdout:
        ```text
        [BOOTSTRAP] No users found. Admin Bootstrap Token: <TOKEN>
        ```

### Step 2: OPAQUE Registration (Client)
The `arkfile-admin bootstrap` command performs an OPAQUE registration, gated by the token.

**A. Registration Init**
*   **Endpoint:** `POST /admin/bootstrap/register-init`
*   **Input:** `{ "bootstrap_token": "...", "username": "admin", "opaque_request": "..." }`
*   **Server Logic:**
    1.  Fetch `bootstrap_token` from DB.
    2.  Decrypt and compare with input.
    3.  If valid, perform OPAQUE OPRF.
*   **Output:** `{ "server_public_key": "...", "credential_response": "..." }`

**B. Registration Finalize**
*   **Endpoint:** `POST /admin/bootstrap/register-finalize`
*   **Input:** `{ "bootstrap_token": "...", "username": "admin", "opaque_record": "..." }`
*   **Server Logic:**
    1.  Verify `bootstrap_token` again.
    2.  Store `opaque_record` in `users` table.
    3.  Set `is_admin = true`.
    4.  **Self-Destruct:** DELETE `bootstrap_token` from `system_keys`.

---

## 4. Implementation Plan

### Phase 1: Master Key Infrastructure
1.  **Database:** Add `system_keys` table to `unified_schema.sql`.
2.  **Crypto:** Create `crypto/key_manager.go` to handle:
    *   Loading `ARKFILE_MASTER_KEY`.
    *   `Encrypt(data, type)` / `Decrypt(data, type)`.
    *   `GetOrGenerateKey(type)` logic.
3.  **Refactor:** Update `auth/keys.go`, `crypto/totp_keys.go`, etc., to use the Key Manager instead of file paths.

### Phase 2: Admin Bootstrap
1.  **Startup Logic:** Implement "Zero User Check" and Token Generation in `main.go` (or a startup handler).
2.  **API:** Implement `/admin/bootstrap/*` endpoints in `handlers/admin_bootstrap.go`.
3.  **CLI:** Implement `arkfile-admin bootstrap` command.

---

## 5. Implementation Status

**Status**: ✅ COMPLETE with SECURITY ENHANCEMENTS

All components have been implemented with additional security measures beyond the original plan:

### Core Features (Implemented)
- ✅ Bootstrap token generation and validation
- ✅ OPAQUE registration endpoints (`/api/bootstrap/register/response`, `/api/bootstrap/register/finalize`)
- ✅ Admin privilege assignment
- ✅ TOTP setup flow integration
- ✅ CLI tool (`arkfile-admin bootstrap`, `setup-totp`, `verify-login`)
- ✅ Master key infrastructure with envelope encryption
- ✅ Database schema (`system_keys` table)

### Security Enhancements (Added)
- ✅ **Localhost-Only Restriction**: Bootstrap endpoints strictly enforce `127.0.0.1` or `::1` access
- ✅ **Force Bootstrap Mechanism**: `ARKFILE_FORCE_BOOTSTRAP=true` allows regeneration of bootstrap token
- ✅ **Proof-of-Life Token Deletion**: Bootstrap token is deleted only after successful admin login (not just registration)
- ✅ **Session Cleanup**: Automatic cleanup of expired bootstrap sessions (5-minute intervals)
- ✅ **Verification Login**: CLI command to verify bootstrap admin can authenticate successfully

### Implementation Files
- `auth/bootstrap.go` - Bootstrap token management and validation
- `handlers/bootstrap.go` - Bootstrap HTTP endpoints
- `handlers/admin_auth.go` - Admin login with proof-of-life token deletion
- `cmd/arkfile-admin/main.go` - CLI commands (bootstrap, verify-login)
- `main.go` - Startup logic for token generation
- `database/unified_schema.sql` - Schema with `system_keys` table

### Security Considerations

#### Why Localhost-Only?
The bootstrap process is intentionally restricted to localhost access because:
1. **Physical Access Requirement**: Only someone with direct server access should bootstrap
2. **Network Attack Prevention**: Prevents remote attackers from intercepting bootstrap tokens
3. **Deployment Security**: Forces proper operational security practices

#### Why Proof-of-Life Deletion?
The bootstrap token is deleted after first successful login (not just registration) because:
1. **Verification**: Ensures the admin account is fully functional before removing the safety net
2. **TOTP Setup**: Allows time for TOTP configuration without rushing
3. **Recovery**: If something goes wrong during setup, the token remains available

#### Force Bootstrap Use Cases
The `ARKFILE_FORCE_BOOTSTRAP=true` environment variable should only be used when:
1. **Lost Admin Access**: All admin accounts are inaccessible
2. **Emergency Recovery**: System needs immediate administrative access
3. **Testing/Development**: Resetting test environments

**WARNING**: Using force bootstrap in production should be logged and audited.

### Bootstrap Workflow

```
1. Server Startup (No Users)
   ↓
2. Generate Bootstrap Token → Log to stdout
   ↓
3. Admin runs: arkfile-admin bootstrap --token <TOKEN>
   ↓
4. OPAQUE Registration (2-step protocol)
   ↓
5. Admin account created (is_admin=1, is_approved=1)
   ↓
6. Admin runs: arkfile-admin setup-totp
   ↓
7. TOTP configured, backup codes generated
   ↓
8. Admin runs: arkfile-admin verify-login
   ↓
9. Successful login → Bootstrap token deleted
   ↓
10. System ready for normal operation
```

### CLI Commands

```bash
# Bootstrap first admin (requires token from server logs)
arkfile-admin bootstrap --token <BOOTSTRAP_TOKEN> --username admin

# Setup two-factor authentication
arkfile-admin setup-totp

# Admin login (triggers bootstrap token deletion on first successful login)
arkfile-admin login --username admin
```

### Testing Checklist

- [ ] Bootstrap token generated on first startup
- [ ] Bootstrap endpoints reject non-localhost requests
- [ ] OPAQUE registration completes successfully
- [ ] Admin user created with correct privileges
- [ ] TOTP setup works correctly
- [ ] Verification login succeeds
- [ ] Bootstrap token deleted after first login
- [ ] Force bootstrap regenerates token
- [ ] Expired sessions cleaned up automatically
- [ ] Second bootstrap attempt fails (no token available)

---

## 6. Future Enhancements

### Potential Improvements
1. **Multi-Admin Bootstrap**: Support for creating multiple admin accounts during initial setup
2. **Bootstrap Token Rotation**: Automatic token rotation after extended periods
3. **Audit Logging**: Enhanced logging of all bootstrap-related activities
4. **Recovery Codes**: Alternative recovery mechanism if bootstrap token is lost
5. **Web UI**: Browser-based bootstrap interface (still localhost-only)

### Security Hardening
1. **Rate Limiting**: Limit bootstrap attempts to prevent brute force
2. **Token Complexity**: Increase token entropy or add checksums
3. **Time-Based Expiration**: Auto-expire bootstrap tokens after 24-48 hours
4. **Notification System**: Alert on bootstrap token generation/usage
