# local-deploy.sh: Local/LAN Deployment Plan

## Overview

This document outlines the design for `scripts/local-deploy.sh`, a first-time deployment script for standing up a real, usable Arkfile instance on a local machine or LAN without requiring a domain name or public internet access. It uses self-signed TLS certificates and the admin bootstrap flow (no hardcoded dev credentials).

`local-deploy.sh` sits between `dev-reset.sh` (destructive dev-only cycle) and `test-deploy.sh` (full VPS with real domain + Let's Encrypt):

| Script | Purpose | TLS | Admin | Data | Domain | Target |
|---|---|---|---|---|---|---|
| `dev-reset.sh` | Dev iteration loop | Self-signed | Hardcoded dev-admin | NUKES everything | localhost | Dev machine |
| **`local-deploy.sh`** | **LAN/local deployment** | **Self-signed** | **Admin bootstrap** | **Constructive** | **IP / hostname** | **Any local machine** |
| `test-deploy.sh` | VPS beta deployment | Let's Encrypt (deSEC) | Admin bootstrap | Constructive | e.g. `test.arkfile.net` | VPS |

## Scope and Non-Goals

**In scope:**
- First-time setup of Arkfile on any Linux machine (local, LAN, home server)
- Self-signed TLS certificates (no domain or CA required)
- Admin bootstrap flow (no dev admin seeding, no hardcoded credentials)
- All services running as systemd units under the `arkfile` user
- SeaweedFS as local S3-compatible storage backend (Apache 2.0 license)
- rqlite as database (single-node)
- Accessible via `https://<IP>:8443` or `https://<hostname>:8443`
- No Caddy reverse proxy (Arkfile serves TLS directly)

**Not in scope:**
- Domain names, DNS, or Let's Encrypt certificates (use `test-deploy.sh` for that)
- Caddy reverse proxy setup
- Public internet exposure
- Container/Podman deployment (documented separately in `docs/wip/podman.md`)
- Firewall configuration (user's responsibility for LAN)

## Prerequisites

Before running `local-deploy.sh`, the target machine must have:

1. **OS**: Debian 12+, Ubuntu 22.04+, Alma/Rocky 9+, or Fedora 39+
2. **Hardware**: Minimum 2 vCPU, 4GB RAM, 20GB storage
3. **System packages** (script will verify):
   - Go 1.26+ (from package manager or manual install)
   - gcc, make, cmake, pkg-config, git
   - libsodium-dev (or libsodium-devel on RHEL-family)
   - openssl, curl, ca-certificates
   - Bun (for TypeScript compilation)
4. **The Arkfile repository** cloned to the machine

## CLI Interface

```
Usage: sudo bash scripts/local-deploy.sh [OPTIONS]

Required:
    --admin-username <name>       Admin username for bootstrap (required)

Optional:
    --force-rebuild-all           Force rebuild of ALL C libraries
    --force-rebuild-rqlite        Force rebuild of rqlite
    --bind-address <ip>           IP address to bind to (default: 0.0.0.0)
    --tls-port <port>             TLS port (default: 8443)
    --http-port <port>            HTTP port (default: 8080, redirects to TLS)
    -h, --help                    Show help message
```

## Script Outline

### Step 0: Pre-flight Checks and Configuration

```
- Must be run as root (sudo bash scripts/local-deploy.sh)
- Parse and validate CLI arguments
    - --admin-username is REQUIRED (no default)
    - Validate username format against existing username validator rules:
        - 10-50 characters
        - Allowed characters: letters (a-z, A-Z), numbers (0-9), underscore, hyphen, period, comma
        - Cannot start or end with underscore, hyphen, period, or comma
        - Cannot contain consecutive special characters (.., --, __, ,,)
- Detect OS family (debian/rhel) for package manager context
- Source build-config.sh for shared build paths
- Detect Go binary (find_go_binary from build-config.sh)
- Verify system dependencies are installed
- Check if /opt/arkfile already exists with data
    - If yes: WARN and ask for confirmation (this is a first-time script)
    - If no: proceed
- Display what will be created, ask for confirmation (no NUKE prompt -- constructive)
```

### Step 1: System User and Directory Structure

```
- Run scripts/setup/01-setup-users.sh
    - Creates arkfile user/group
- Run scripts/setup/02-setup-directories.sh
    - Creates /opt/arkfile directory tree
    - Sets ownership to arkfile:arkfile
```

Identical to dev-reset.sh Steps 3-4 (post-build user/directory setup).

### Step 2: Build Application

```
- Preserve original user context (SUDO_USER) for Go operations
- Fix Go file ownership (fix_go_ownership from build-config.sh)
- Check for existing C libraries (skip rebuild if present, unless --force-rebuild-all)
- IMPORTANT: Do NOT set LIBOPAQUE_DEFINES (leave unset/empty)
    - This builds libopaque WASM without -DTRACE, so no cryptographic debug
      dumps appear in the browser console during OPAQUE authentication
    - dev-reset.sh sets LIBOPAQUE_DEFINES="-DTRACE" for development;
      local-deploy.sh must NOT do this
    - If switching from a dev build, use --force-rebuild-all to recompile
      WASM without trace logging (the flag is baked into the WASM binary)
- Force fresh TypeScript rebuild:
    - Remove client/static/js/.buildcache
    - Remove client/static/js/dist/*
- Clean build artifacts (preserve C libraries)
- Run build.sh --build-only as the original user (not root)
- Fix Go ownership after build
- Verify critical build artifacts:
    - BUILD_ROOT/client/static/js/dist/app.js (TypeScript bundle)
    - BUILD_ROOT/client/static/js/libopaque.js (WASM)
    - BUILD_BIN/arkfile (server binary)
    - BUILD_BIN/arkfile-client (CLI client)
    - BUILD_BIN/arkfile-admin (admin CLI)
```

Similar to dev-reset.sh Step 3, but WITHOUT LIBOPAQUE_DEFINES="-DTRACE".

### Step 3: Deploy Build Artifacts

```
- Run scripts/setup/deploy.sh
    - Copies build artifacts to /opt/arkfile
    - Installs systemd service files
    - Sets arkfile:arkfile ownership
    - Reloads systemd daemon
- Verify critical files in /opt/arkfile:
    - /opt/arkfile/bin/arkfile (executable)
    - /opt/arkfile/bin/arkfile-client (executable)
    - /opt/arkfile/bin/arkfile-admin (executable)
    - /opt/arkfile/client/static/js/dist/app.js
    - /opt/arkfile/client/static/js/libopaque.js
```

Identical to dev-reset.sh Step 3 (deploy portion).

### Step 4: Ensure Correct Ownership

```
- chown -R arkfile:arkfile /opt/arkfile
- chmod 700 on all key directories
- Verify no root-owned files in /opt/arkfile
- Create and permission log directory
```

Identical to dev-reset.sh Step 4.

### Step 5: Generate Cryptographic Material

```
- Generate Master Key:
    - Run scripts/setup/03-setup-master-key.sh
    - Verify ARKFILE_MASTER_KEY is in /opt/arkfile/etc/secrets.env
- Generate self-signed TLS certificates:
    - Run scripts/setup/04-setup-tls-certs.sh
    - These certs are used directly by Arkfile (no Caddy in front)
- Set ownership and permissions:
    - chown -R arkfile:arkfile /opt/arkfile
    - chmod 700 on all key directories
- Verify ownership (no root-owned files in /opt/arkfile)
```

Identical to dev-reset.sh Step 6.

### Step 6: Generate secrets.env (Local Deployment Configuration)

This is where `local-deploy.sh` diverges significantly from `dev-reset.sh`.

```
Generate /opt/arkfile/etc/secrets.env with:

    # Local Deployment Configuration
    # Generated: <timestamp>
    # Access: https://<BIND_ADDRESS>:<TLS_PORT>

    # Database Configuration
    DATABASE_TYPE=rqlite
    RQLITE_ADDRESS=http://localhost:4001
    RQLITE_USERNAME=local-user
    RQLITE_PASSWORD=<random: openssl rand -hex 16>

    # Arkfile Application Configuration
    PORT=<HTTP_PORT>
    CORS_ALLOWED_ORIGINS=https://localhost:<TLS_PORT>,https://<LAN_IP>:<TLS_PORT>

    # TLS Configuration (Arkfile serves its own TLS directly)
    TLS_ENABLED=true
    TLS_PORT=<TLS_PORT>
    TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
    TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key

    # Storage Configuration - Generic S3 (local SeaweedFS backend)
    STORAGE_PROVIDER=generic-s3
    S3_ENDPOINT=http://localhost:9332
    S3_ACCESS_KEY=arkfile-local
    S3_SECRET_KEY=<random: openssl rand -hex 16>
    S3_BUCKET=arkfile-local
    S3_REGION=us-east-1
    S3_FORCE_PATH_STYLE=true
    S3_USE_SSL=false

Also generate /opt/arkfile/etc/seaweedfs-s3.json with matching S3 credentials:

    {
      "identities": [
        {
          "name": "arkfile",
          "credentials": [
            {
              "accessKey": "arkfile-local",
              "secretKey": "<same S3_SECRET_KEY from secrets.env>"
            }
          ],
          "actions": ["Admin", "Read", "Write", "List", "Tagging"]
        }
      ]
    }

    # Admin Configuration
    ADMIN_USERNAMES=<admin-username from CLI arg>

    # Admin Bootstrap Mode (true for first-time setup)
    ARKFILE_FORCE_ADMIN_BOOTSTRAP=true

    # CRITICAL: Dev/Test API DISABLED
    ADMIN_DEV_TEST_API_ENABLED=false

    # Local Deployment Settings (NOT development)
    REQUIRE_APPROVAL=false
    ENABLE_REGISTRATION=true
    DEBUG_MODE=false
    LOG_LEVEL=info

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

Key differences from dev-reset.sh secrets.env:
- No hardcoded dev-admin username
- `ARKFILE_FORCE_ADMIN_BOOTSTRAP=true` (admin must be bootstrapped)
- `ADMIN_DEV_TEST_API_ENABLED=false` (no test API)
- `DEBUG_MODE=false`
- `LOG_LEVEL=info` (not debug)
- Prefix `local-` instead of `dev-` for credentials
- All passwords are random (no `DevPassword123_` prefix)

### Step 7: Generate rqlite Auth File

```
Generate /opt/arkfile/etc/rqlite-auth.json:
    [
      {
        "username": "local-user",
        "password": "<same RQLITE_PASSWORD from secrets.env>",
        "perms": ["all"]
      }
    ]

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

### Step 8: Setup SeaweedFS and rqlite

```
- Setup SeaweedFS:
    - Run scripts/setup/05-setup-seaweedfs.sh
    - Verify SeaweedFS binary and configuration

- Setup rqlite:
    - Run scripts/setup/06-setup-rqlite-build.sh [--force if requested]
    - Verify rqlite binary and configuration
```

Identical to dev-reset.sh Step 7.

### Step 9: Start Services (Ordered)

```
- systemctl daemon-reload

A. Start SeaweedFS:
    - systemctl start seaweedfs
    - systemctl enable seaweedfs
    - Verify: systemctl is-active seaweedfs

B. Start rqlite:
    - systemctl start rqlite
    - systemctl enable rqlite
    - Wait for leadership (poll /status for "ready":true, up to 60 seconds)
    - Verify: rqlite is ready and leader

C. Start Arkfile:
    - systemctl start arkfile
    - systemctl enable arkfile
    - Wait for readiness (poll https://localhost:<TLS_PORT>/readyz, up to 30 seconds)
    - Verify: Arkfile responds with "status":"ready"
```

Identical to dev-reset.sh Step 8, minus Caddy.

### Step 10: Health Verification

```
A. Health checks:
    - https://localhost:<TLS_PORT>/readyz returns "status":"ready"
    - https://localhost:<TLS_PORT>/api/config/argon2 returns valid JSON
    - https://localhost:<TLS_PORT>/api/config/password-requirements returns valid JSON
    - https://localhost:<TLS_PORT>/api/config/chunking returns valid JSON

B. Service status verification:
    - seaweedfs: active
    - rqlite: active
    - arkfile: active

C. Ownership verification:
    - No root-owned files in /opt/arkfile
```

Identical to dev-reset.sh Step 9, minus Caddy.

### Step 11: Output Admin Bootstrap Instructions and Access Info

```
Detect the machine's LAN IP address for display purposes.

Output:

    LOCAL DEPLOYMENT COMPLETE
    =========================

    Your Arkfile instance is running at:
      HTTPS: https://localhost:<TLS_PORT>
      HTTPS (LAN): https://<LAN_IP>:<TLS_PORT>
      (Accept self-signed certificate warning in browser)

    Services:
      SeaweedFS: active
      rqlite:    active
      Arkfile:   active

    NEXT: Bootstrap your admin account
    ===================================

    1. Check Arkfile logs for the bootstrap token:
       sudo journalctl -u arkfile | grep BOOTSTRAP

    2. Bootstrap the admin account (from this machine):
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:<TLS_PORT> --tls-insecure \
         bootstrap --token <BOOTSTRAP_TOKEN> --username <ADMIN_USERNAME>

    3. Setup TOTP for the admin account:
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:<TLS_PORT> --tls-insecure \
         setup-totp

    4. Verify admin login:
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:<TLS_PORT> --tls-insecure \
         verify-login --username <ADMIN_USERNAME>

    5. After successful admin login, disable force bootstrap:
       - Edit /opt/arkfile/etc/secrets.env
       - Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=false
       - Restart: sudo systemctl restart arkfile

    6. Access the web interface:
       https://localhost:<TLS_PORT>
       https://<LAN_IP>:<TLS_PORT> (from other devices on your network)
       (Accept the self-signed certificate warning)

    Useful commands:
      View logs:       sudo journalctl -u arkfile -f
      Restart:         sudo systemctl restart arkfile
      Stop all:        sudo systemctl stop arkfile seaweedfs rqlite
      Start all:       sudo systemctl start seaweedfs rqlite arkfile
```

## Differences from dev-reset.sh

| Aspect | dev-reset.sh | local-deploy.sh |
|---|---|---|
| **Purpose** | Local dev iteration (destroy + rebuild) | First-time local/LAN deployment |
| **Data handling** | NUKES all data, keys, database | Never destroys data (constructive only) |
| **TLS** | Self-signed (localhost) | Self-signed (localhost + LAN IP) |
| **Caddy** | Not used | Not used |
| **Domain** | localhost:8443 | localhost:8443 or LAN IP:8443 |
| **Admin account** | arkfile-dev-admin (auto-seeded) | Bootstrap flow (no hardcoded creds) |
| **ADMIN_DEV_TEST_API_ENABLED** | true | false |
| **DEBUG_MODE** | true | false |
| **LOG_LEVEL** | debug | info |
| **WASM trace logging** | LIBOPAQUE_DEFINES="-DTRACE" | Unset (no trace) |
| **REQUIRE_APPROVAL** | false | false (configurable) |
| **CORS_ALLOWED_ORIGINS** | https://localhost:8443 | https://localhost:TLS_PORT,https://LAN_IP:TLS_PORT |
| **Credentials** | Random with `Dev` prefix | Random with `local-` prefix, no dev patterns |
| **Idempotent** | Yes (destructive reset) | No (first-time only) |
| **Reusable sub-scripts** | 01, 02, 03, 04, 05, 06, build.sh, deploy.sh | Same set |

## Differences from test-deploy.sh

| Aspect | local-deploy.sh | test-deploy.sh |
|---|---|---|
| **TLS (public)** | Self-signed | Let's Encrypt via Caddy + deSEC |
| **Caddy** | Not used | Required (reverse proxy, public TLS) |
| **Domain** | IP / hostname | test.arkfile.net (real domain) |
| **Firewall** | Not configured | Optional firewall step |
| **DNS verification** | None | Verifies A record resolves to VPS IP |
| **Caddy build** | N/A | Custom build with xcaddy + deSEC module |
| **Additional CLI args** | --bind-address, --tls-port | --domain, --desec-token |
| **CORS_ALLOWED_ORIGINS** | https://localhost:TLS_PORT,https://LAN_IP:TLS_PORT | https://test.arkfile.net |
| **OS target** | Any supported Linux | VPS (Alma/Rocky/Debian/Ubuntu) |

## Implementation Notes

### Code Reuse from dev-reset.sh

The script should reuse the same patterns and helper functions from dev-reset.sh:
- Source `build-config.sh` for shared build paths and Go helpers
- Use `find_go_binary`, `fix_go_ownership`, `run_go_as_user` from build-config.sh
- Use the same `verify_ownership` function
- Use the same `stop_service_if_running` pattern
- Use the same service startup and health-check polling patterns

The main structural difference is:
1. No NUKE confirmation/countdown
2. CLI argument parsing for `--admin-username` and optional args
3. Different secrets.env generation (production-like settings)
4. Admin bootstrap instructions in output instead of dev-admin info
5. Guard against running on an existing deployment (warn if /opt/arkfile has data)

### Guard Against Re-running

Since this is a first-time script, it should detect if Arkfile is already deployed:
```
- Check if /opt/arkfile/etc/secrets.env exists
- Check if systemctl is-active arkfile returns active
- If either: WARN that this appears to be an existing deployment
- Offer: "Type REINSTALL to wipe and reinstall, or Ctrl+C to abort"
- If REINSTALL: stop services, remove /opt/arkfile data (similar to dev-reset nuke)
- If not: abort with message suggesting systemctl restart or test-update.sh (future)
```

### Future: local-update.sh

A companion `local-update.sh` script will be needed for:
- Pulling latest code
- Rebuilding the application
- Deploying new artifacts
- Restarting services (preserving all data, keys, database)

This mirrors the planned `test-update.sh` for VPS deployments. Both update scripts share the same pattern: rebuild + redeploy + restart, without touching data or secrets.
