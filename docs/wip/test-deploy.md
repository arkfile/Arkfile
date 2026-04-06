# test-deploy.sh: Beta Deployment Plan for test.arkfile.net

## Overview

This document outlines the design for `scripts/test-deploy.sh`, a first-time deployment script for standing up Arkfile on a real VPS with a real domain (`test.arkfile.net`). It is modeled after the battle-tested `dev-reset.sh` (which passes 100% of e2e tests) but adapted for a non-destructive, production-oriented, TLS 1.3-required deployment with Let's Encrypt certificates via Caddy and deSEC DNS challenge.

## Scope and Non-Goals

**In scope:**
- First-time setup of Arkfile on a fresh VPS (Debian/Ubuntu/Alma/Rocky)
- Real domain TLS via Caddy + deSEC DNS-01 challenge (Let's Encrypt)
- Admin bootstrap flow (no dev admin seeding)
- All services running as systemd units under the `arkfile` user
- MinIO as local S3-compatible storage backend (single-node beta)
- rqlite as database (single-node beta)
- Security hardened (no debug mode, no dev test API, proper rate limiting)

**Not in scope (future work):**
- Container/Podman deployment (documented separately in `docs/wip/podman.md`)
- Multi-node rqlite clusters
- External S3 backends (Wasabi, B2, etc.)
- SeaweedFS migration
- Automated CI/CD pipeline

## Prerequisites

Before running `test-deploy.sh`, the target VPS must have:

1. **OS**: Debian 12+, Ubuntu 22.04+, Alma/Rocky 9+, or Fedora 39+
2. **Hardware**: Minimum 2 vCPU, 4GB RAM, 20GB storage
3. **Network**:
   - Ports 80 and 443 open (for Caddy/Let's Encrypt)
   - Port 8443 open (for Arkfile direct TLS -- Caddy proxies to this)
   - DNS A record for `test.arkfile.net` pointing to the VPS IP
4. **System packages** (script will verify/install):
   - Go 1.24+ (from package manager or manual install)
   - gcc, make, cmake, pkg-config, git
   - libsodium-dev (or libsodium-devel on RHEL-family)
   - openssl, curl, ca-certificates
   - Bun (for TypeScript compilation)
5. **Caddy** installed with deSEC DNS module (custom build -- see Section 7)
6. **deSEC API token** for `arkfile.net` DNS management
7. **The Arkfile repository** cloned to the VPS

## Script Outline: test-deploy.sh

### Step 0: Pre-flight Checks and Configuration

```
- Must be run as root (sudo bash scripts/test-deploy.sh)
- Parse CLI arguments:
    --domain <domain>          (required, e.g. "test.arkfile.net")
    --desec-token <token>      (required, deSEC API token)
    --admin-username <name>    (required, production admin username)
    --storage-backend <type>   (optional, default: "local-minio")
    --force-rebuild-all        (optional, rebuild C libraries)
    --force-rebuild-rqlite     (optional, rebuild rqlite)
    -h / --help
- Validate all required arguments are provided
- Detect OS family (debian/rhel/alpine) for package manager
- Source build-config.sh for shared build paths
- Detect Go binary (find_go_binary from build-config.sh)
- Verify system dependencies are installed
- Verify DNS resolution: test that $DOMAIN resolves to this machine's IP
- Verify ports 80, 443 are not already in use by another service
- Confirm with user before proceeding (no NUKE prompt -- this is constructive)
```

### Step 1: System User and Directory Structure

```
- Run scripts/setup/01-setup-users.sh
    - Creates arkfile user/group
    - Creates caddy user/group (if not present)
- Run scripts/setup/02-setup-directories.sh
    - Creates /opt/arkfile directory tree
    - Sets ownership to arkfile:arkfile
    - Creates /var/log/caddy directory for Caddy logs
```

### Step 2: Build Application

```
- Preserve original user context (SUDO_USER) for Go operations
- Fix Go file ownership (fix_go_ownership from build-config.sh)
- Check for existing C libraries (skip rebuild if present, unless --force-rebuild-all)
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

### Step 4: Generate Cryptographic Material

```
- Generate Master Key:
    - Run scripts/setup/03-setup-master-key.sh
    - Verify ARKFILE_MASTER_KEY is in /opt/arkfile/etc/secrets.env
- Generate internal TLS certificates (for inter-service communication):
    - Run scripts/setup/04-setup-tls-certs.sh
    - These are self-signed certs for Arkfile<->rqlite, Arkfile<->MinIO internal TLS
    - Public-facing TLS is handled by Caddy + Let's Encrypt (Step 7)
- Set ownership and permissions:
    - chown -R arkfile:arkfile /opt/arkfile
    - chmod 700 on all key directories
- Verify ownership (no root-owned files in /opt/arkfile)
```

### Step 5: Generate secrets.env (Beta Configuration)

```
Generate /opt/arkfile/etc/secrets.env with:

    # Beta Deployment Configuration
    # Generated: <timestamp>
    # Domain: <DOMAIN>

    # Database Configuration
    DATABASE_TYPE=rqlite
    RQLITE_ADDRESS=http://localhost:4001
    RQLITE_USERNAME=beta-user
    RQLITE_PASSWORD=<random: openssl rand -hex 16>

    # Arkfile Application Configuration
    PORT=8080
    CORS_ALLOWED_ORIGINS=https://<DOMAIN>

    # TLS Configuration (Arkfile serves its own TLS for direct access)
    TLS_ENABLED=true
    TLS_PORT=8443
    TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
    TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key

    # Storage Configuration - Generic S3 (local MinIO backend)
    STORAGE_PROVIDER=generic-s3
    S3_ENDPOINT=http://localhost:9000
    S3_ACCESS_KEY=arkfile-beta
    S3_SECRET_KEY=<random: openssl rand -hex 16>
    S3_BUCKET=arkfile-beta
    S3_REGION=us-east-1
    S3_FORCE_PATH_STYLE=true
    S3_USE_SSL=false

    # MinIO Server Configuration
    MINIO_ROOT_USER=arkfile-beta
    MINIO_ROOT_PASSWORD=<same as S3_SECRET_KEY>
    MINIO_SSE_AUTO_ENCRYPTION=off

    # Admin Configuration
    ADMIN_USERNAMES=<admin-username from CLI arg>

    # Admin Bootstrap Mode (true for first-time setup)
    ARKFILE_FORCE_ADMIN_BOOTSTRAP=true

    # CRITICAL: Dev/Test API DISABLED for beta
    ADMIN_DEV_TEST_API_ENABLED=false

    # Beta Settings (NOT development)
    REQUIRE_APPROVAL=true
    ENABLE_REGISTRATION=true
    DEBUG_MODE=false
    LOG_LEVEL=info

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

### Step 6: Generate rqlite Auth File

```
Generate /opt/arkfile/etc/rqlite-auth.json:
    [
      {
        "username": "beta-user",
        "password": "<same RQLITE_PASSWORD from secrets.env>",
        "perms": ["all"]
      }
    ]

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

### Step 7: Setup Caddy with deSEC DNS Challenge

This is the major new component vs. dev-reset.sh.

```
Decision: Bare-metal Caddy vs. Container Caddy

For beta, use bare-metal Caddy with custom build (simpler, matches
the rest of the bare-metal systemd setup). Container deployment is
a separate future effort (docs/wip/podman.md).

A. Build custom Caddy with deSEC module:
    - Use xcaddy to build Caddy with github.com/caddy-dns/desec
    - Install to /usr/local/bin/caddy
    - (Or: download pre-built if available)

B. Generate Caddyfile for test.arkfile.net:
    - Write to /etc/caddy/Caddyfile
    - Content (see "Caddyfile for Beta" section below)

C. Configure Caddy systemd service:
    - Create caddy user/group if not present
    - Create /var/lib/caddy, /var/log/caddy, /etc/caddy directories
    - Install systemd/caddy.service (updated for deSEC token)
    - Set DESEC_TOKEN in caddy service environment or env file

D. Verify Caddy can resolve the domain via DNS-01 challenge
```

#### Caddyfile for Beta (test.arkfile.net)

```caddy
{
    email admin@arkfile.net

    servers {
        protocols h1 h2 h3
        strict_sni_host
    }
}

test.arkfile.net {
    tls {
        dns desec {
            token {$DESEC_TOKEN}
        }
        protocols tls1.3
        key_type p384
    }

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        X-Content-Type-Options "nosniff"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' data: blob:;"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    reverse_proxy localhost:8443 {
        transport http {
            tls
            tls_insecure_skip_verify
        }
        health_uri /readyz
        health_interval 30s
        health_timeout 10s
        health_status 200
    }

    encode gzip

    log {
        output file /var/log/caddy/test-access.log
        format json
    }

    handle_errors {
        respond "{http.error.status_code} {http.error.status_text}"
    }
}
```

Key design decisions for the Caddyfile:
- Caddy handles public TLS termination (Let's Encrypt via deSEC DNS-01)
- Caddy proxies to Arkfile's own TLS on port 8443 (double encryption in transit)
- `tls_insecure_skip_verify` is used because Arkfile uses self-signed internal certs
- Health check uses `/readyz` (the current correct endpoint)
- TLS 1.3 only, P-384 keys, strong security headers
- No HTTP redirect block needed -- Caddy auto-redirects HTTP->HTTPS by default

### Step 8: Setup MinIO

```
- Run scripts/setup/05-setup-minio.sh
    - Downloads/configures MinIO binary
    - Creates MinIO data directories
    - Installs MinIO systemd service
    - Sets ownership to arkfile:arkfile
```

### Step 9: Setup rqlite

```
- Run scripts/setup/06-setup-rqlite-build.sh [--force if requested]
    - Builds rqlite from source (Go, no CGO needed)
    - Installs rqlite binary
    - Installs rqlite systemd service
```

### Step 10: Start Services (Ordered)

```
- systemctl daemon-reload

A. Start MinIO:
    - systemctl start minio
    - systemctl enable minio
    - Verify: systemctl is-active minio

B. Start rqlite:
    - systemctl start rqlite
    - systemctl enable rqlite
    - Wait for leadership (poll /status for "ready":true, up to 60 seconds)
    - Verify: rqlite is ready and leader

C. Start Arkfile:
    - systemctl start arkfile
    - systemctl enable arkfile
    - Wait for readiness (poll https://localhost:8443/readyz, up to 30 seconds)
    - Verify: Arkfile responds with "status":"ready"

D. Start Caddy:
    - systemctl start caddy
    - systemctl enable caddy
    - Wait for certificate acquisition (may take 30-60 seconds for DNS-01)
    - Verify: curl https://test.arkfile.net/readyz returns "status":"ready"
```

### Step 11: Health Verification

```
A. Internal health checks:
    - https://localhost:8443/readyz returns "status":"ready"
    - https://localhost:8443/api/config/argon2 returns valid JSON
    - https://localhost:8443/api/config/password-requirements returns valid JSON
    - https://localhost:8443/api/config/chunking returns valid JSON

B. External/public health checks:
    - https://test.arkfile.net/readyz returns "status":"ready"
    - TLS certificate is valid (not self-signed, issued by Let's Encrypt)
    - TLS 1.3 is enforced (test with openssl s_client)

C. Service status verification:
    - minio: active
    - rqlite: active
    - arkfile: active
    - caddy: active

D. Ownership verification:
    - No root-owned files in /opt/arkfile
```

### Step 12: Admin Bootstrap Instructions

```
After all services are running, output instructions for admin bootstrap:

    1. Check Arkfile logs for the bootstrap token:
       sudo journalctl -u arkfile | grep BOOTSTRAP

    2. Bootstrap the admin account (from the VPS, localhost only):
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:8443 --tls-insecure \
         bootstrap --token <BOOTSTRAP_TOKEN> --username <ADMIN_USERNAME>

    3. Setup TOTP for the admin account:
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:8443 --tls-insecure \
         setup-totp

    4. Verify admin login:
       /opt/arkfile/bin/arkfile-admin \
         --server-url https://localhost:8443 --tls-insecure \
         verify-login --username <ADMIN_USERNAME>

    5. After successful admin login, disable force bootstrap:
       - Edit /opt/arkfile/etc/secrets.env
       - Set ARKFILE_FORCE_ADMIN_BOOTSTRAP=false
       - Restart: sudo systemctl restart arkfile

    6. Access the web interface:
       https://test.arkfile.net
```

## Differences from dev-reset.sh

| Aspect | dev-reset.sh | test-deploy.sh |
|---|---|---|
| **Purpose** | Local dev iteration (destroy + rebuild) | First-time beta deployment |
| **Data handling** | NUKES all data, keys, database | Never destroys data (constructive only) |
| **TLS (public)** | Self-signed (localhost) | Let's Encrypt via Caddy + deSEC |
| **TLS (internal)** | Self-signed | Self-signed (same) |
| **Caddy** | Not used | Required (reverse proxy, public TLS) |
| **Domain** | localhost:8443 | test.arkfile.net (real domain) |
| **Admin account** | arkfile-dev-admin (auto-seeded) | Bootstrap flow (secure, no hardcoded creds) |
| **ADMIN_DEV_TEST_API_ENABLED** | true | false |
| **DEBUG_MODE** | true | false |
| **LOG_LEVEL** | debug | info |
| **REQUIRE_APPROVAL** | false | true |
| **CORS_ALLOWED_ORIGINS** | https://localhost:8443 | https://test.arkfile.net |
| **Credentials** | Random (dev prefix) | Random (beta prefix) |
| **Idempotent** | Yes (destructive reset) | No (first-time only; use separate update script) |

## Open Questions and Decisions Needed

### 1. Caddy Build Strategy
How should the custom Caddy with deSEC module be obtained?
- **Option A**: Script builds it on the VPS using `xcaddy` (requires Go, which we already have)
- **Option B**: Pre-build and host a binary somewhere
- **Option C**: Use Podman to build it in a container, extract the binary

Recommendation: **Option A** -- `xcaddy` is simple and Go is already a prerequisite.

### 2. Arkfile Internal TLS vs. Caddy-Only TLS
Currently Arkfile serves its own TLS on 8443 with self-signed certs. Caddy then proxies to it. Two options:
- **Option A (current plan)**: Keep Arkfile's internal TLS. Caddy uses `tls_insecure_skip_verify` to talk to it. Double encryption in transit.
- **Option B**: Disable Arkfile's internal TLS, have Caddy proxy to plain HTTP on 8080. Simpler, but internal traffic is unencrypted.

Recommendation: **Option A** -- defense in depth. The app enforces TLS 1.3 internally, and Caddy handles the public-facing cert. If someone bypasses Caddy, Arkfile still requires TLS.

### 3. Firewall Configuration
Should the script configure firewall rules (ufw/firewalld)?
- Close all ports except 22 (SSH), 80, 443
- Port 8443 should NOT be publicly accessible (Caddy proxies to it internally)
- Ports 4001 (rqlite), 9000 (MinIO) should NOT be publicly accessible

Recommendation: Yes, add a firewall step. Keep it optional with a `--skip-firewall` flag.

### 4. Storage Backend for Beta
- **MinIO local** (current plan): Simple, all data on the VPS
- **External S3** (Wasabi/B2): Data stored externally, VPS is stateless for files

Recommendation: Start with MinIO local for simplicity. Add external S3 support as a future `--storage-backend` option.

### 5. Backup Strategy
Beta data will be real (even if limited). Need at minimum:
- rqlite database backup (cron job)
- Master key backup (manual, offline)
- MinIO data backup (optional for beta)

Recommendation: Document manual backup procedures in the output. Automate in a future iteration.

### 6. Update/Redeploy Script
`test-deploy.sh` is for first-time setup. A separate `test-update.sh` (or `beta-update.sh`) will be needed for:
- Pull latest code
- Rebuild
- Deploy new artifacts
- Restart services (preserving data)

This mirrors how `dev-reset.sh` handles rebuilds but without the NUKE step.

## Cleanup: What Else Should Change

### Delete quick-start.sh
`scripts/quick-start.sh` is stale and broken (references non-existent scripts `07-setup-minio.sh` and `08-setup-rqlite-build.sh`, missing TLS, missing Master Key, wrong storage config, wrong CORS, wrong health endpoint). It should be deleted from the repository.

### Update 00-setup-foundation.sh
Its "NEXT STEP" output still references `quick-start.sh` and the non-existent `07-setup-minio.sh` / `08-setup-rqlite-build.sh`. Update to reference `dev-reset.sh` for local dev or `test-deploy.sh` for beta deployment.

### Update setup.md
Multiple stale references:
- Method 1 references `quick-start.sh` and `http://localhost:8080` (plain HTTP)
- Method 2 references non-existent `integration-test.sh`
- Method 3 references `00-setup-foundation.sh` with old script numbers
- Production setup references `scripts/deprecated/first-time-setup.sh`
- Health checks reference `http://localhost:8080/health` instead of `https://localhost:8443/readyz`
- Multiple sections describe HTTP-only access patterns
- Registration example uses email format `admin@test.local` which is invalid for current username validation

### Update Caddyfile (production)
The production `Caddyfile` references `{$PROD_PORT}` and `{$TEST_PORT}` env vars and has cross-environment failover logic. For the beta this is overkill. The beta Caddyfile should be a standalone, simple config for just `test.arkfile.net`.

### Update systemd/caddy.service
The current service file references `arkfile@prod.service` and `arkfile@test.service` (template units) which don't exist. For beta, simplify to depend on `arkfile.service`.

## Implementation Priority

1. Write `scripts/test-deploy.sh` following this plan
2. Delete `scripts/quick-start.sh`
3. Create `Caddyfile.beta` for test.arkfile.net
4. Update `systemd/caddy.service` for beta (or create `systemd/caddy-beta.service`)
5. Update `scripts/setup/00-setup-foundation.sh` references
6. Update `docs/setup.md` to reflect current state
7. Test on a fresh VPS with `test.arkfile.net` DNS configured
8. Document admin bootstrap walkthrough with real output
