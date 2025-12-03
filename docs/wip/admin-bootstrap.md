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
