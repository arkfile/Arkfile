# test-deploy.sh: Test Deployment Plan for test.arkfile.net

## Overview

This document outlines the design for `scripts/test-deploy.sh`, a first-time deployment script for standing up Arkfile on a real VPS with a real domain (e.g. `test.arkfile.net`). It is modeled after the battle-tested `dev-reset.sh` (which passes 100% of e2e tests) but adapted for a non-destructive, production-oriented, TLS 1.3-required deployment with Let's Encrypt certificates via Caddy and deSEC DNS challenge.

## Scope and Non-Goals

**In scope:**
- First-time setup of Arkfile on a fresh VPS (Debian/Ubuntu/Alma/Rocky)
- Real domain TLS via Caddy + deSEC DNS-01 challenge (Let's Encrypt)
- Admin bootstrap flow (no dev admin seeding)
- All services running as systemd units under the `arkfile` user
- SeaweedFS as local S3-compatible storage backend (single-node, Apache 2.0 license)
- rqlite as database (single-node)
- Security hardened (no debug mode, no dev test API, proper rate limiting)

**Not in scope (future work):**
- Container/Podman deployment (documented separately in `docs/wip/podman.md`)
- Multi-node rqlite clusters
- External S3 backends (Wasabi, B2, etc.)
- Automated CI/CD pipeline

## Prerequisites

Before running `test-deploy.sh`, the target VPS must have:

1. **OS**: Debian 12+, Ubuntu 22.04+, Alma/Rocky 9+, or Fedora 39+ (primary supported targets)
   Note: Scripts detect OS family (debian/rhel) and use appropriate package managers and
   firewall tools. FreeBSD, OpenBSD, and Alpine are stretch goals for future adaptation;
   OS-specific logic in scripts is commented to aid future BSD/Alpine porting.
2. **Hardware**: Minimum 2 vCPU, 4GB RAM, 20GB storage
3. **Network**:
   - Port 443 open (for Caddy to serve HTTPS to users)
   - Port 80 is OPTIONAL (only for Caddy's automatic HTTP-to-HTTPS redirect; the deSEC DNS-01 challenge does NOT use port 80 -- it validates via DNS TXT records, so port 80 can remain closed)
   - Port 8443 should NOT be publicly accessible (Caddy proxies to it internally on localhost)
   - DNS A record for the intended domain, e.g. `test.arkfile.net`, pointing to the VPS IP
4. **System packages** (script will verify/install):
   - Go 1.26+ (from package manager or manual install)
   - gcc, make, cmake, pkg-config, git
   - libsodium-dev (or libsodium-devel on RHEL-family)
   - openssl, curl, ca-certificates
   - Bun (for TypeScript compilation)
5. **Caddy** installed with deSEC DNS module (custom build -- see Section 7)
6. **deSEC API token** for primary domain, e.g. `arkfile.net`, DNS management (see "About deSEC" below)
7. **The Arkfile repository** cloned to the VPS

### About deSEC

deSEC (desec.io) is a free, privacy-focused DNS hosting service run by deSEC e.V., a German non-profit based in Berlin, operational since ~2019 and used by privacy-oriented projects and infrastructure providers. If deSEC ever went away, the Caddy DNS challenge plugin is modular -- swapping to any of the ~30+ supported providers (Cloudflare, Route53, Porkbun, Gandi, etc.) requires rebuilding Caddy with a different `caddy-dns/*` module and changing 2-3 lines in the Caddyfile, a ~15 minute migration. Alternatively, you can fall back to HTTP-01 challenge (requires port 80) or bring your own certs via certbot.

### Multi-VPS / Multi-Provider

deSEC is a standalone DNS hosting service, not tied to any VPS provider. You point your registrar's nameservers to deSEC, and deSEC manages all DNS records centrally. You can then point `test.arkfile.net` to VPS-A (provider 1) and `arkfile.net` to VPS-B (provider 2) -- each VPS runs its own Caddy with the same deSEC API token and independently obtains its own Let's Encrypt certificate via DNS-01.

### Pre-VPS Setup: deSEC + DNS Configuration

Complete these steps before running `test-deploy.sh`:

1. Create a deSEC account at desec.io (free)
2. Add your domain (e.g. `arkfile.net`) to deSEC -- this gives you deSEC nameservers
3. Point your registrar's nameservers to deSEC's nameservers (`ns1.desec.io`, `ns2.desec.org`)
   -- this is done at wherever you registered/bought the domain, not at deSEC or Contabo
4. Create an A record in deSEC: `test.arkfile.net` -> your VPS public IP address
5. Generate a deSEC API token in the deSEC dashboard (Settings -> Tokens)
6. Wait for DNS propagation (usually 15 min to a few hours depending on registrar TTL)
7. Verify from the VPS: `dig test.arkfile.net` should return your VPS IP

The deSEC token is a high-value secret -- it has write access to your DNS records. Keep it offline
when not in use. The script stores it in `/opt/arkfile/etc/caddy-env` (owned by `caddy:arkfile`,
mode 640), which is referenced by the Caddy systemd service via `EnvironmentFile`. Do not embed
it in the Caddyfile or commit it to version control.

## Script Outline: test-deploy.sh

### Step 0: Pre-flight Checks and Configuration

```
- Must be run as root (sudo bash scripts/test-deploy.sh)
- Parse CLI arguments:
    --domain <domain>          (required, e.g. "test.arkfile.net")
    --desec-token <token>      (required, deSEC API token)
    --admin-username <name>    (required, production admin username)
    --storage-backend <type>   (optional, default: "local-seaweedfs")
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

### Step 1: Firewall Configuration

Mandatory for all VPS deployments. Opens only the ports required for public operation.

```
- Detect active firewall tool:
    - RHEL-family (Alma/Rocky/Fedora): firewalld
    - Debian-family (Debian/Ubuntu): ufw

- If firewalld:
    - firewall-cmd --permanent --set-default-zone=drop
    - firewall-cmd --permanent --add-service=ssh
    - firewall-cmd --permanent --add-service=http
    - firewall-cmd --permanent --add-service=https
    - firewall-cmd --reload
    - Verify: firewall-cmd --list-all

- If ufw:
    - ufw default deny incoming
    - ufw default allow outgoing
    - ufw allow 22/tcp (SSH)
    - ufw allow 80/tcp (HTTP redirect)
    - ufw allow 443/tcp (HTTPS)
    - ufw --force enable
    - Verify: ufw status verbose

- If neither found: warn and continue (firewall may be managed externally)

Ports that must NOT be publicly accessible:
    - 8443 (Arkfile internal TLS -- Caddy proxies to this on localhost only)
    - 4001 (rqlite HTTP API -- localhost only)
    - 9332 (SeaweedFS S3 gateway -- localhost only)
```

### Step 2: System User and Directory Structure

```
- Run scripts/setup/01-setup-users.sh
    - Creates arkfile user/group
    - Creates caddy user/group (if not present)
- Run scripts/setup/02-setup-directories.sh
    - Creates /opt/arkfile directory tree
    - Sets ownership to arkfile:arkfile
    - Creates /var/log/caddy directory for Caddy logs
```

### Step 3: Build Application

```
- Preserve original user context (SUDO_USER) for Go operations
- Fix Go file ownership (fix_go_ownership from build-config.sh)
- Check for existing C libraries (skip rebuild if present, unless --force-rebuild-all)
- IMPORTANT: Do NOT set LIBOPAQUE_DEFINES (leave unset/empty)
    - This builds libopaque WASM without -DTRACE, so no cryptographic debug
      dumps appear in the browser console during OPAQUE authentication
    - dev-reset.sh sets LIBOPAQUE_DEFINES="-DTRACE" for development;
      test-deploy.sh must NOT do this
    - If the VPS was previously used for dev builds, use --force-rebuild-all
      to recompile WASM without trace logging (the flag is baked into the
      WASM binary at compile time)
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

### Step 4: Deploy Build Artifacts

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

### Step 5: Generate Cryptographic Material

```
- Generate Master Key:
    - Run scripts/setup/03-setup-master-key.sh
    - Verify ARKFILE_MASTER_KEY is in /opt/arkfile/etc/secrets.env
- Generate internal TLS certificates (for inter-service communication):
    - Run scripts/setup/04-setup-tls-certs.sh
    - These are self-signed certs for Arkfile<->rqlite internal TLS
    - Public-facing TLS is handled by Caddy + Let's Encrypt (Step 8)
- Set ownership and permissions:
    - chown -R arkfile:arkfile /opt/arkfile
    - chmod 700 on all key directories
- Verify ownership (no root-owned files in /opt/arkfile)
```

### Step 6: Generate secrets.env (Test Configuration)

```
Generate /opt/arkfile/etc/secrets.env with:

    # Test Deployment Configuration
    # Generated: <timestamp>
    # Domain: <DOMAIN>

    # Database Configuration
    DATABASE_TYPE=rqlite
    RQLITE_ADDRESS=http://localhost:4001
    RQLITE_USERNAME=test-user
    RQLITE_PASSWORD=<random: openssl rand -hex 16>

    # Arkfile Application Configuration
    PORT=8080
    CORS_ALLOWED_ORIGINS=https://<DOMAIN>

    # TLS Configuration (Arkfile serves its own TLS for direct access)
    TLS_ENABLED=true
    TLS_PORT=8443
    TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
    TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key

    # Storage Configuration - Generic S3 (local SeaweedFS backend)
    STORAGE_PROVIDER=generic-s3
    S3_ENDPOINT=http://localhost:9332
    S3_ACCESS_KEY=arkfile-test
    S3_SECRET_KEY=<random: openssl rand -hex 16>
    S3_BUCKET=arkfile-test
    S3_REGION=us-east-1
    S3_FORCE_PATH_STYLE=true
    S3_USE_SSL=false

Also generate /opt/arkfile/etc/seaweedfs-s3.json with S3 credentials
(see docs/wip/swfs-now.md for format)

    # Admin Configuration
    ADMIN_USERNAMES=<admin-username from CLI arg>

    # Admin Bootstrap Mode (true for first-time setup)
    ARKFILE_FORCE_ADMIN_BOOTSTRAP=true

    # CRITICAL: Dev/Test API DISABLED for test deployments
    ADMIN_DEV_TEST_API_ENABLED=false

    # Test Settings (NOT development)
    REQUIRE_APPROVAL=true
    ENABLE_REGISTRATION=true
    DEBUG_MODE=false
    LOG_LEVEL=info

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

### Step 7: Generate rqlite Auth File

```
Generate /opt/arkfile/etc/rqlite-auth.json:
    [
      {
        "username": "test-user",
        "password": "<same RQLITE_PASSWORD from secrets.env>",
        "perms": ["all"]
      }
    ]

- Set ownership: arkfile:arkfile
- Set permissions: 640
```

### Step 8: Setup Caddy with deSEC DNS Challenge

This is the major new component vs. dev-reset.sh.

```
Decision: Bare-metal Caddy vs. Container Caddy

For test, use bare-metal Caddy with custom build (simpler, matches the rest of the bare-metal systemd setup). Container deployment is a separate future effort (docs/wip/podman.md).

A. Build custom Caddy with deSEC module:
    - Install xcaddy: go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
      (Go is already a prerequisite, so no additional toolchain needed)
    - Build: xcaddy build --with github.com/caddy-dns/desec
    - Install to /usr/local/bin/caddy
    - Verify: /usr/local/bin/caddy version (should show caddy with desec module)

B. Generate Caddyfile from Caddyfile.test template:
    - Caddyfile.test is maintained in the repo root as a reusable template
      with {DOMAIN} placeholder
    - script substitutes actual domain via sed and writes to /etc/caddy/Caddyfile
    - Content (see "Caddyfile for Test Deployment" section below)

C. Configure Caddy systemd service and token storage:
    - Create caddy user/group if not present
    - Create /var/lib/caddy, /var/log/caddy, /etc/caddy directories
    - Store deSEC token in /opt/arkfile/etc/caddy-env:
        DESEC_TOKEN=<token from --desec-token CLI arg>
      Ownership: caddy:arkfile, permissions: 640
      (Follows the same secrets-in-files pattern as secrets.env and rqlite-auth.json.
      caddy user can read it; arkfile group access for operational convenience.)
    - Install systemd/caddy.service with:
        EnvironmentFile=/opt/arkfile/etc/caddy-env
        After=network-online.target (NOT After=arkfile.service;
        Caddy health-checks Arkfile independently via /readyz)
    - systemctl daemon-reload

D. SELinux configuration (RHEL-family only):
    - Detect: SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
    - If enforcing:
        - setsebool -P httpd_can_network_connect 1
          (allows Caddy to proxy to Arkfile on localhost:8443)
        - semanage fcontext -a -t httpd_config_t "/etc/caddy(/.*)?"
        - semanage fcontext -a -t httpd_var_lib_t "/var/lib/caddy(/.*)?"
        - semanage fcontext -a -t httpd_log_t "/var/log/caddy(/.*)?"
        - semanage fcontext -a -t httpd_exec_t "/usr/local/bin/caddy"
        - restorecon -R /etc/caddy /var/lib/caddy /var/log/caddy
        - restorecon /usr/local/bin/caddy
        - Log all SELinux changes made for auditability
    - If permissive or disabled: log status, skip SELinux steps

E. Verify Caddy can start and resolve the domain via DNS-01 challenge:
    - caddy validate --config /etc/caddy/Caddyfile
    - Start caddy, then poll https://<DOMAIN>/readyz for up to 90s
      (DNS-01 cert acquisition can take 30-60s on first run)
```

#### Caddyfile for Test Deployment (test.arkfile.net)

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

### Step 9: Setup SeaweedFS

```
- Run scripts/setup/05-setup-seaweedfs.sh
    - Downloads/configures SeaweedFS binary
    - Creates SeaweedFS data directories (/opt/arkfile/var/lib/seaweedfs/data)
    - Installs SeaweedFS systemd service
    - Sets ownership to arkfile:arkfile
```

### Step 10: Setup rqlite

```
- Run scripts/setup/06-setup-rqlite-build.sh [--force if requested]
    - Builds rqlite from source (Go, no CGO needed)
    - Installs rqlite binary
    - Installs rqlite systemd service
```

### Step 11: Start Services (Ordered)

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
    - Wait for readiness (poll https://localhost:8443/readyz, up to 30 seconds)
    - Verify: Arkfile responds with "status":"ready"

D. Start Caddy:
    - systemctl start caddy
    - systemctl enable caddy
    - Wait for certificate acquisition (may take 30-60 seconds for DNS-01)
    - Verify: curl https://test.arkfile.net/readyz returns "status":"ready"
```

### Step 12: Health Verification

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
    - seaweedfs: active
    - rqlite: active
    - arkfile: active
    - caddy: active

D. Ownership verification:
    - No root-owned files in /opt/arkfile
```

### Step 13: Admin Bootstrap Instructions

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
| **Purpose** | Local dev iteration (destroy + rebuild) | First-time test deployment |
| **Data handling** | NUKES all data, keys, database | Never destroys data (constructive only) |
| **TLS (public)** | Self-signed (localhost) | Let's Encrypt via Caddy + deSEC |
| **TLS (internal)** | Self-signed | Self-signed (same) |
| **Caddy** | Not used | Required (reverse proxy, public TLS) |
| **Domain** | localhost:8443 | test.arkfile.net (real domain) |
| **Admin account** | arkfile-dev-admin (auto-seeded) | Bootstrap flow (secure, no hardcoded creds) |
| **ADMIN_DEV_TEST_API_ENABLED** | true | false |
| **DEBUG_MODE** | true | false |
| **LOG_LEVEL** | debug | info |
| **WASM trace logging** | LIBOPAQUE_DEFINES="-DTRACE" | Unset (no trace) |
| **REQUIRE_APPROVAL** | true | true |
| **CORS_ALLOWED_ORIGINS** | https://localhost:8443 | https://test.arkfile.net |
| **Credentials** | Random (dev prefix) | Random (test prefix) |
| **Idempotent** | Yes (destructive reset) | No (first-time only; use separate update script) |

## Resolved Design Decisions

### 1. Caddy Build Strategy
DECIDED: Build on VPS using `xcaddy` (Go is already a prerequisite).
`go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`
`xcaddy build --with github.com/caddy-dns/desec`

### 2. Arkfile Internal TLS vs. Caddy-Only TLS
DECIDED: Keep Arkfile's internal TLS (defense in depth). Caddy uses `tls_insecure_skip_verify`
to proxy to self-signed internal certs on port 8443. If someone bypasses Caddy, Arkfile
still requires TLS. This is implemented in Step 8 (Caddy setup).

### 3. Firewall Configuration
DECIDED: Mandatory. Detects `firewalld` (RHEL-family) or `ufw` (Debian-family) and
opens only ports 22, 80, 443. Implemented as Step 1. No `--skip-firewall` flag -- a
VPS without a configured firewall is not acceptable.

### 4. Storage Backend
DECIDED: SeaweedFS local for initial deployment (simple, all data on the VPS, Apache 2.0).
External S3 support (Wasabi/B2) is future work via `--storage-backend` option.

### 5. Backup Strategy
DECIDED: Document manual backup procedures in the script output at completion. Automate
in a future iteration. At minimum, operators must:
- Back up the Master Key offline (ARKFILE_MASTER_KEY from /opt/arkfile/etc/secrets.env)
- Back up the rqlite database periodically (future: cron job)

### 6. Update/Redeploy Script
DECIDED: A separate `test-update.sh` script is needed for rebuilding and redeploying
without nuking data. This is out of scope for the current effort.

### 7. deSEC Token Storage
DECIDED: Store in `/opt/arkfile/etc/caddy-env` (owned by `caddy:arkfile`, mode 640),
referenced via `EnvironmentFile=` in caddy.service. Follows existing secrets-in-files
pattern used by secrets.env and rqlite-auth.json.

### 8. Caddyfile Template
DECIDED: Maintain `Caddyfile.test` in the repo root as a reusable template with `{DOMAIN}`
placeholder. test-deploy.sh uses `sed` to substitute the actual domain and writes the result
to `/etc/caddy/Caddyfile`.

## Stale Files Identified During Planning

These files contain outdated references and will be updated as part of this effort:

- `Caddyfile`: References `{$PROD_PORT}`/`{$TEST_PORT}`, cross-environment failover logic,
  and `health_uri /health` (should be `/readyz`). All stale.
- `Caddyfile.local`: Uses `health_uri /health` (should be `/readyz`), proxies localhost:8443
  to itself (broken self-referencing config), and CSP is missing `wasm-unsafe-eval` and
  `data: blob:`. Stale.
- `systemd/caddy.service`: References `arkfile@prod.service` and `arkfile@test.service`
  (template units that do not exist). Stale.

## Cleanup: What Else Should Change

### Update docs/setup.md
Update stale references to scripts, ports, endpoints, and configuration patterns.

### Fix Caddyfile and Caddyfile.local
Correct health endpoints (`/health` -> `/readyz`), fix CSP, remove stale cross-environment
failover logic from `Caddyfile`. Fix self-referencing proxy in `Caddyfile.local`.

### Fix systemd/caddy.service
Remove stale `Wants=arkfile@prod.service arkfile@test.service` references.
Update to `After=network-online.target` with `EnvironmentFile=/opt/arkfile/etc/caddy-env`.

## Implementation Priority

1. Write `scripts/test-deploy.sh` following this plan
2. Create `Caddyfile.test` template in repo root
3. Update `systemd/caddy.service` (remove stale template unit refs, add EnvironmentFile)
4. Fix stale `Caddyfile` and `Caddyfile.local` (health endpoints, CSP, remove stale logic)
5. Update `docs/setup.md` to reflect current state
6. Test on a fresh VPS with `test.arkfile.net` DNS configured
7. Document admin bootstrap walkthrough with real output
