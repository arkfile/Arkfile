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
- External S3-compatible storage backends via `--storage-backend`
  (Wasabi, Backblaze B2, Vultr Object Storage, Cloudflare R2, AWS S3,
  generic S3-compatible)
- rqlite as database (single-node)
- Security hardened (no debug mode, no dev test API, proper rate limiting)

**Not in scope (future work):**
- Container/Podman deployment (documented separately in `docs/wip/podman.md`)
- Multi-node rqlite clusters
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
5. **deSEC API token** for primary domain, e.g. `arkfile.net`, DNS management (see "About deSEC" below)
6. **The Arkfile repository** cloned to the VPS

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
    --acme-email <email>       (optional, Let's Encrypt expiration notices)
    --force-rebuild-all        (optional, rebuild C libraries)
    --force-rebuild-rqlite     (optional, rebuild rqlite)
    -h / --help
- Validate all required arguments are provided
- Detect OS family (debian/rhel) for package manager and firewall tooling
- Source build-config.sh for shared build paths
- Detect Go binary (find_go_binary from build-config.sh)
- Verify system dependencies are installed
- Detect this VPS's external IP (for example via `curl -s ifconfig.me`)
- Verify DNS resolution: test that $DOMAIN resolves to this machine's public IP
- Verify ports 80, 443 are not already in use by another service
- Confirm with user before proceeding
```

#### Step 0a: Existing Deployment Guard

Before making any changes, the script checks for signs of an existing deployment.

```
- Check if /opt/arkfile/etc/secrets.env already exists
- Check if the arkfile systemd service already exists or is active
- If either check indicates an existing deployment:
    - Warn the user this script is intended for first-time deployment
    - Explain that a future test-update.sh should be used for updates
    - Explain that service restarts should use systemctl restart
    - Require the operator to type REINSTALL to continue
- If the operator does not type REINSTALL exactly, exit cleanly without changes
```

This follows the same guard pattern already used by `scripts/local-deploy.sh`.

#### Step 0b: DNS Verification

To avoid deploying onto the wrong VPS or proceeding with stale DNS:

```
- Detect the VPS public IP using an external lookup
- Resolve the requested domain via dig +short
- Compare resolved A record to the detected public IP
- Hard-fail if they do not match
```

This is required before attempting Caddy certificate issuance.

### Storage Backend Selection

The script supports a default local storage mode and several external S3-compatible
providers.

#### Default: local SeaweedFS

If `--storage-backend` is omitted, the script defaults to:

```
--storage-backend local-seaweedfs
```

In this mode:
- SeaweedFS is installed locally on the VPS
- Arkfile connects to it using the generic S3 provider over localhost
- The endpoint is `http://localhost:9332`
- No interactive storage credential prompts are needed

#### External provider modes

If `--storage-backend` is set to one of the external options below, the script
prompts interactively for the required credentials and writes the matching env vars
to `secrets.env`.

Supported values:

```
local-seaweedfs
wasabi
backblaze
vultr
cloudflare-r2
aws-s3
generic-s3
```

##### Wasabi

Prompt for:

```
- S3 Region
- S3 Access Key
- S3 Secret Key
- S3 Bucket Name
```

The endpoint is derived automatically as:

```
https://s3.<region>.wasabi.com
```

Write to `secrets.env`:

```
STORAGE_PROVIDER=wasabi
S3_REGION=<region>
S3_ACCESS_KEY=<access-key>
S3_SECRET_KEY=<secret-key>
S3_BUCKET=<bucket>
```

##### Backblaze B2

Prompt for:

```
- Backblaze Endpoint
- Backblaze Key ID
- Backblaze Application Key
- Backblaze Bucket Name
```

Write to `secrets.env`:

```
STORAGE_PROVIDER=backblaze
BACKBLAZE_ENDPOINT=<endpoint>
BACKBLAZE_KEY_ID=<key-id>
BACKBLAZE_APPLICATION_KEY=<application-key>
BACKBLAZE_BUCKET_NAME=<bucket>
```

##### Vultr Object Storage

Prompt for:

```
- Region
- S3 Access Key
- S3 Secret Key
- S3 Bucket Name
```

The endpoint is derived automatically as:

```
https://<region>.vultrobjects.com
```

Write to `secrets.env`:

```
STORAGE_PROVIDER=vultr
S3_REGION=<region>
S3_ACCESS_KEY=<access-key>
S3_SECRET_KEY=<secret-key>
S3_BUCKET=<bucket>
```

##### Cloudflare R2

Prompt for:

```
- Cloudflare Endpoint
- Cloudflare Access Key ID
- Cloudflare Secret Access Key
- Cloudflare Bucket Name
```

Write to `secrets.env`:

```
STORAGE_PROVIDER=cloudflare-r2
CLOUDFLARE_ENDPOINT=<endpoint>
CLOUDFLARE_ACCESS_KEY_ID=<access-key-id>
CLOUDFLARE_SECRET_ACCESS_KEY=<secret-access-key>
CLOUDFLARE_BUCKET_NAME=<bucket>
```

##### AWS S3

Prompt for:

```
- AWS Region
- S3 Access Key
- S3 Secret Key
- S3 Bucket Name
```

No endpoint prompt is needed. The AWS SDK resolves the correct regional endpoint.

Write to `secrets.env`:

```
STORAGE_PROVIDER=aws-s3
S3_REGION=<region>
S3_ACCESS_KEY=<access-key>
S3_SECRET_KEY=<secret-key>
S3_BUCKET=<bucket>
```

##### Generic S3-compatible

Prompt for:

```
- S3 Endpoint URL
- S3 Region
- S3 Access Key
- S3 Secret Key
- S3 Bucket Name
- Force Path Style? (y/n, default: y)
```

For external providers, this endpoint should normally be HTTPS. For local
development-like custom targets, the operator can still provide an HTTP endpoint
explicitly in the URL.

Write to `secrets.env`:

```
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=<endpoint-url>
S3_REGION=<region>
S3_ACCESS_KEY=<access-key>
S3_SECRET_KEY=<secret-key>
S3_BUCKET=<bucket>
S3_FORCE_PATH_STYLE=<true|false>
```

#### Storage connectivity verification

After collecting credentials for any external backend (and after secrets.env and
the arkfile-admin binary are deployed), the script uses `arkfile-admin verify-storage`
to perform a full round-trip verification:

```
- Upload a 1 MB test object (all zeros) with a known SHA-256 hash
- Download the object back
- Verify the SHA-256 hash matches
- Delete the test object
- Hard-fail if any step fails
```

This reuses the same `storage.InitS3()` code path as the Arkfile server, so it
tests the exact configuration that will be used in production. The tool reads
storage config from secrets.env and requires no running Arkfile server.

Note: Secret keys (S3 secret keys, Backblaze app keys, etc.) are prompted with
hidden input (`read -s`) to avoid leaking credentials to terminal history or
shoulder-surfing.

#### Effect on the rest of the deployment flow

If an external S3 backend is selected:

```
- Skip SeaweedFS setup entirely
- Skip SeaweedFS service startup entirely
- Do not generate local SeaweedFS configuration files
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

### Step 4: Deploy Build Artifacts and Set Ownership

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
- Set ownership and permissions:
    - chown -R arkfile:arkfile /opt/arkfile
    - chmod 700 on all key directories (jwt, opaque, tls, backups, totp)
- Create and permission log directory:
    - mkdir -p /opt/arkfile/var/log
    - chown arkfile:arkfile, chmod 775
```

### Step 5: Generate secrets.env (Test Configuration)

NOTE: secrets.env MUST be written before Step 6 (master key generation),
because 03-setup-master-key.sh appends ARKFILE_MASTER_KEY to secrets.env.
Writing secrets.env after would overwrite the master key.

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

Also generate /opt/arkfile/etc/seaweedfs-s3.json with S3 credentials
(see docs/wip/swfs-now.md for format)

For external backends, write the storage section using the provider-specific
env vars collected in the Storage Backend Selection step instead. Examples:

    # Wasabi
    STORAGE_PROVIDER=wasabi
    S3_REGION=<region>
    S3_ACCESS_KEY=<access-key>
    S3_SECRET_KEY=<secret-key>
    S3_BUCKET=<bucket>

    # Backblaze B2
    STORAGE_PROVIDER=backblaze
    BACKBLAZE_ENDPOINT=<endpoint>
    BACKBLAZE_KEY_ID=<key-id>
    BACKBLAZE_APPLICATION_KEY=<application-key>
    BACKBLAZE_BUCKET_NAME=<bucket>

    # Cloudflare R2
    STORAGE_PROVIDER=cloudflare-r2
    CLOUDFLARE_ENDPOINT=<endpoint>
    CLOUDFLARE_ACCESS_KEY_ID=<access-key-id>
    CLOUDFLARE_SECRET_ACCESS_KEY=<secret-access-key>
    CLOUDFLARE_BUCKET_NAME=<bucket>

When an external backend is selected:

    - Do not generate /opt/arkfile/etc/seaweedfs-s3.json
    - Do not write localhost SeaweedFS credentials

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

### Step 6: Generate Cryptographic Material

```
- Generate Master Key:
    - Run scripts/setup/03-setup-master-key.sh
    - This appends ARKFILE_MASTER_KEY to the secrets.env written in Step 5
- Generate internal TLS certificates (for inter-service communication):
    - Run scripts/setup/04-setup-tls-certs.sh
    - These are self-signed certs for Arkfile<->rqlite internal TLS
    - Public-facing TLS is handled by Caddy + Let's Encrypt (Step 8)
- Set ownership and permissions:
    - chown -R arkfile:arkfile /opt/arkfile
    - chmod 700 on all key directories
- Verify ownership (no root-owned files in /opt/arkfile)
```

### Step 7: Verify External Storage (if applicable)

For external storage backends only (not local-seaweedfs), the script uses the
`arkfile-admin verify-storage` subcommand to perform a full round-trip test:

```
- Upload a 1 MB test object (all zeros) with a known SHA-256 hash
- Download the object back
- Verify the SHA-256 hash matches
- Delete the test object
- Hard-fail if any step fails
```

This uses the same `storage.InitS3()` code path as the Arkfile server, ensuring
the credentials and endpoint are correct before proceeding with service startup.

The `verify-storage` subcommand is implemented in `cmd/arkfile-admin/verify_storage.go`
and reads configuration from `/opt/arkfile/etc/secrets.env` (or `--secrets-env` override).
It can also be used as a standalone operational tool after deployment.

### Step 7a: Generate rqlite Auth File

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
    - If --acme-email is provided, also substitute {EMAIL}
    - If --acme-email is not provided, omit the email line entirely
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

#### Caddyfile for Test Deployment (`Caddyfile.test` template)

```caddy
{
    email {EMAIL}

    servers {
        protocols h1 h2 h3
        strict_sni_host
    }
}

{DOMAIN} {
    tls {
        dns desec {
            token {$DESEC_TOKEN}
        }
        protocols tls1.3
        must_staple
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
- `must_staple` is enabled for maximum TLS security
- If `--acme-email` is omitted, the `email` line is omitted from the rendered file
- No HTTP redirect block needed -- Caddy auto-redirects HTTP->HTTPS by default

### Step 9: Setup SeaweedFS

```
- Skip this step entirely if --storage-backend is not local-seaweedfs
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
    - Skip if using an external S3 backend
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
    - (Future work) TLS certificate validation via openssl s_client
    - (Future work) TLS 1.3 enforcement check
    - (Future work) OCSP stapling verification

C. Service status verification:
    - seaweedfs: active when using local-seaweedfs
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
DECIDED: Support both local SeaweedFS and external S3-compatible providers via
`--storage-backend`. Local SeaweedFS remains the default. External providers are
configured interactively and verified before continuing.

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

### 9. ACME Email
DECIDED: `--acme-email` is optional. If provided, the rendered Caddyfile includes the
global `email` directive so Let's Encrypt can send expiration notices. If omitted,
the email line is omitted entirely.

### 10. OCSP Must-Staple
DECIDED: Enable `must_staple` in `Caddyfile.test` for stronger TLS policy. Caddy
handles OCSP stapling automatically.

### 11. Storage Backend Selection
DECIDED: Prompt interactively for provider-specific credentials when
`--storage-backend` is not `local-seaweedfs`. Prompt names and env vars must match
what `storage/s3.go` actually reads.

### 12. Existing Deployment Guard
DECIDED: Reuse the `REINSTALL` confirmation pattern from `scripts/local-deploy.sh`
to guard against accidentally re-running first-time deployment on an existing system.

## Phase 0: Stale File Cleanup (Pre-work)

Before implementing `test-deploy.sh`, clean up the stale reference files so the repo
has a correct baseline.

### 0a. Fix `systemd/caddy.service`

- Remove stale `Wants=arkfile@prod.service arkfile@test.service`
- Change `After=network.target` to `After=network-online.target`
- Add `EnvironmentFile=/opt/arkfile/etc/caddy-env`
- Keep the existing security hardening directives

### 0b. Fix `Caddyfile`

- Remove stale cross-environment failover logic using `{$PROD_PORT}` and `{$TEST_PORT}`
- Change `health_uri /health` to `health_uri /readyz`
- Fix the outdated global `servers` syntax to match current Caddy v2 structure
- Remove `must_staple` from the generic shared template and keep it specific to
  `Caddyfile.test`
- Keep this file as a clean generic reference for future production deployment work

### 0c. Fix `Caddyfile.local`

- Fix the self-referencing proxy loop
- Change `health_uri /health` to `health_uri /readyz`
- Update CSP to include `'wasm-unsafe-eval'` and `data: blob:`
- Keep in mind this file is only a local reference and is not currently used by
  `local-deploy.sh`

### 0d. Confirm `scripts/setup/deploy.sh`

- Confirm it copies the corrected `systemd/caddy.service` into `/etc/systemd/system/`
- Check for any other stale Caddy-related assumptions

## Stale Files Identified During Planning

These files contain outdated references and will be updated as part of this effort:

- `Caddyfile`: References `{$PROD_PORT}`/`{$TEST_PORT}`, cross-environment failover logic,
  and `health_uri /health` (should be `/readyz`). All stale.
- `Caddyfile.local`: Uses `health_uri /health` (should be `/readyz`), proxies localhost:8443
  to itself (broken self-referencing config), and CSP is missing `wasm-unsafe-eval` and
  `data: blob:`. Stale.
- `systemd/caddy.service`: References `arkfile@prod.service` and `arkfile@test.service`
  (template units that do not exist). Stale.

## Implementation Status

1. [DONE] Phase 0 stale file cleanup (systemd/caddy.service, Caddyfile, Caddyfile.local)
2. [DONE] Create `Caddyfile.test` template in repo root
3. [DONE] Add `arkfile-admin verify-storage` subcommand (cmd/arkfile-admin/verify_storage.go)
4. [DONE] Write `scripts/test-deploy.sh` following this plan
5. Update `docs/setup.md` to reflect current state
6. Test on a fresh VPS with `test.arkfile.net` DNS configured
7. Document admin bootstrap walkthrough with real output
