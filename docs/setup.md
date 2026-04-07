# Arkfile Setup Guide

This guide provides comprehensive instructions for installing, configuring, and managing Arkfile. It covers everything from local development to production deployment.

## Table of Contents

1. [Local Dev Test Setup](#local-dev-test-setup)
2. [Architecture Overview](#architecture-overview)
3. [Deployment Methods](#deployment-methods)
4. [Production Deployment](#production-deployment)
5. [TLS Configuration](#tls-configuration)
6. [Administrative Validation](#administrative-validation)
7. [Maintenance and Operations](#maintenance-and-operations)
8. [Troubleshooting](#troubleshooting)

### Local Dev Test Setup

Run the following:

- `sudo ./scripts/dev-reset.sh` -- idempotent setup/reset of local dev testing environment (creates `arkfile-dev-admin` user)

- `./scripts/testing/e2e-test.sh` -- full, end-to-end functional test suite using Go CLI client utils

- Register a new user, e.g. `USERNAME00`, locally in the browser via: https://localhost:8443/ [Get Started]

- Approve the new user using the `arkfile-admin` Go CLI tool:

- Login as arkfile-dev-admin:

```
printf 'DevAdmin2025!SecureInitialPassword\n' | /opt/arkfile/bin/arkfile-admin \
  --server-url https://localhost:8443 --tls-insecure \
  login --username arkfile-dev-admin \
  --totp-secret "ARKFILEPKZBXCMJLGB5HM5D2GEVVU32D" \
  --save-session
```

Example output:

```
Enter admin password for arkfile-dev-admin: Admin login successful for user: arkfile-dev-admin
Session expires: 2026-04-04 16:04:04
Administrative privileges active
```

- Approve the new user and set a storage quota:

```
/opt/arkfile/bin/arkfile-admin \
  --server-url https://localhost:8443 --tls-insecure \
  approve-user --username USERNAME00 --storage "5GB"
```

Example output:

```
User USERNAME00 approved successfully
Storage limit set to: 5.0 GB
```

- Refresh the browser tab for your user with the 'pending approval'. You should now have full access locally in the browser.

- Alternatively, try logging in using `arkfile-client`:

- Log in as USERNAME00

```
printf 'MyFancyP@ssw0rd-123\n' | /opt/arkfile/bin/arkfile-client \
  --server-url https://localhost:8443 --tls-insecure \
  login --username USERNAME00 \
  --non-interactive \
  --totp-code 012345
```

Example output:

```
Login successful for user: USERNAME00
Session expires: 2026-05-05 17:05:05
```

- List files for USERNAME00

```
/opt/arkfile/bin/arkfile-client \
  --server-url https://localhost:8443 --tls-insecure
  list-files
```

Example output:

```
No files found.
```

## Architecture Overview

### System Components

Arkfile's architecture consists of a client-side web interface, a server-side Go application, and external services for storage and security. The client-side component uses WebAssembly for in-browser encryption and decryption. The server-side application handles user authentication, manages metadata, and interfaces with storage backends.

External services include S3-compatible object storage (SeaweedFS for self-hosted, or any external S3 provider), a distributed rqlite database for metadata, and a Caddy web server for TLS and reverse proxying.

### Directory Structure and Service Users

Arkfile uses a standardized directory structure with dedicated service users. The main application directory is `/opt/arkfile/`, containing subdirectories for binaries, configuration files, application data and logs.

The system operates with the `arkfile` user for running services, and the `arkfile` group for resource access. This separation enforces the principle of least privilege and isolates application resources.

### Storage Architecture

Arkfile supports multiple storage backends through a generic S3 interface (`STORAGE_PROVIDER=generic-s3`):

- **SeaweedFS** (default) - Local S3-compatible storage (Apache 2.0 license), single-node or clustered
- **Amazon S3** - AWS native object storage
- **Backblaze B2** - S3-compatible cloud storage
- **Wasabi** - S3-compatible cloud storage
- **Vultr Object Storage** - S3-compatible cloud storage
- **Cloudflare R2** - S3-compatible cloud storage
- **Any S3-compatible provider** - Works with any backend that implements the S3 API

Arkfile performs end-to-end encryption on the client-side before upload. The storage backend receives only opaque encrypted blobs and never sees plaintext file data. No server-side encryption is needed or used.

### Database Architecture

The system uses rqlite, a distributed SQLite database, for all metadata storage. This provides:
- Distributed consensus and replication
- SQLite compatibility with clustering
- High availability with automatic failover
- Consistent data across nodes

## Deployment Methods

Arkfile provides three deployment scripts for different use cases:

### dev-reset.sh (Development)

**Best for:** Local development and iterative testing

```bash
sudo ./scripts/dev-reset.sh
```

**What you get:**
- Working HTTPS interface at https://localhost:8443
- Local SeaweedFS storage (S3 gateway on port 9332, localhost only)
- Single-node rqlite database
- All cryptographic keys generated fresh
- Dev admin user (`arkfile-dev-admin`) auto-created
- Ready for immediate testing with `e2e-test.sh`

### local-deploy.sh (Self-Hosted Single Node)

**Best for:** Personal/small-team self-hosted deployments

```bash
sudo ./scripts/local-deploy.sh
```

**What you get:**
- Production-grade single-node deployment
- SeaweedFS local storage with proper data directories
- TLS certificates (self-signed or Let's Encrypt via Caddy)
- Admin bootstrap flow for first admin account creation
- Systemd services for all components

### test-deploy.sh (Beta/Staging)

**Best for:** Beta testing, staging environments, pre-production validation

```bash
sudo ./scripts/test-deploy.sh
```

**What you get:**
- Multi-user beta deployment
- External DNS and TLS via Caddy
- Comprehensive health checks and monitoring
- Production-equivalent security configuration

### Manual Step-by-Step Setup

**Best for:** Custom configurations, learning the system

```bash
# Foundation setup (users, directories, keys)
./scripts/setup/00-setup-foundation.sh

# Add services manually
sudo ./scripts/setup/05-setup-seaweedfs.sh
sudo ./scripts/setup/06-setup-rqlite-build.sh

# Build and deploy
./scripts/setup/build.sh
./scripts/setup/deploy.sh
```

## CRITICAL PRODUCTION SECURITY NOTICE

### Dev Admin Accounts
The following accounts are **DEVELOPMENT ONLY** and are automatically blocked in production:
- `arkfile-dev-admin`
- `admin.dev.user`
- `admin.demo.user`

### Production Deployment Checklist
- [ ] Set `ENVIRONMENT=production`
- [ ] Update `ADMIN_USERNAMES` with production admin accounts only
- [ ] Remove all dev admin accounts from environment variables
- [ ] Verify deployment scripts pass admin validation
- [ ] Test admin functionality with production accounts

## Production Deployment

### System Requirements

**Hardware Requirements:**
- **Minimum**: 2 vCPU, 4GB RAM, 20GB storage
- **Recommended**: 4 vCPU, 8GB RAM, 100GB SSD storage
- **High Load**: 8+ vCPU, 16GB+ RAM, 500GB+ NVMe storage

**Operating System Support:**
- **Linux**: Debian, Ubuntu, Alma/Rocky Linux, RHEL, Fedora, Alpine
- **BSD**: FreeBSD, OpenBSD
- **Architecture**: x86_64 (amd64)

**Network Requirements:**
- **Ports**: 8080 (HTTP), 8443 (HTTPS/TLS), 4001 (rqlite, localhost only), 9332 (SeaweedFS S3, localhost only)
- **Outbound**: Access to package repositories
- **DNS**: Proper FQDN resolution for TLS certificates

### Prerequisites

**Go Installation:**

**Option 1: Package Manager (Recommended)**
```bash
# Debian/Ubuntu
sudo apt update && sudo apt install golang-go

# Alpine Linux
sudo apk add go

# Alma/RHEL/Rocky Linux
sudo dnf install golang

# Fedora
sudo dnf install golang

# FreeBSD
sudo pkg install go

# OpenBSD
sudo pkg_add go

# Verify installation
go version
```

**Option 2: Manual Install (Latest Version)**
```bash
# Install Go 1.26.0 or later
wget https://go.dev/dl/go1.26.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz

# Add Go to PATH for manual installs
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

**Note:** Arkfile's build system automatically detects Go installations from package managers or manual installs. No PATH configuration needed for package manager installations.

**System Dependencies:**
```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y \
  curl wget git build-essential pkg-config cmake \
  sqlite3 openssl ca-certificates \
  libsodium-dev tar gzip

# RHEL 9 / AlmaLinux 9 / Rocky Linux 9 (EPEL required for libsodium-devel)
sudo dnf install -y epel-release
sudo dnf install -y \
  curl wget git gcc gcc-c++ make cmake pkgconf \
  sqlite openssl ca-certificates \
  libsodium-devel tar gzip

# Fedora (EPEL not needed)
sudo dnf install -y \
  curl wget git gcc gcc-c++ make cmake pkgconf \
  sqlite openssl ca-certificates \
  libsodium-devel tar gzip

# Alpine Linux
sudo apk add --no-cache \
  curl wget git gcc musl-dev make cmake pkgconf-dev \
  sqlite openssl ca-certificates \
  libsodium-dev libsodium-static tar gzip
```

**Development Dependencies (Optional):**
For development and TypeScript compilation, install additional dependencies:
```bash
# Install Bun (JavaScript runtime and bundler)
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc

# Verify Bun installation
bun --version
```

### Configuration

**Environment Configuration:**

Arkfile uses environment variables loaded from `/opt/arkfile/etc/secrets.env`. The deployment scripts (`dev-reset.sh`, `local-deploy.sh`, `test-deploy.sh`) generate this file automatically with appropriate values.

Key configuration variables:

```bash
# Storage Configuration (Generic S3 with local SeaweedFS)
STORAGE_PROVIDER=generic-s3
S3_ENDPOINT=http://localhost:9332
S3_ACCESS_KEY=arkfile-dev
S3_SECRET_KEY=<randomly-generated>
S3_BUCKET=arkfile-dev
S3_REGION=us-east-1
S3_FORCE_PATH_STYLE=true
S3_USE_SSL=false

# Database Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
RQLITE_USERNAME=<configured-user>
RQLITE_PASSWORD=<randomly-generated>

# TLS Configuration
TLS_ENABLED=true
TLS_PORT=8443
TLS_CERT_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.crt
TLS_KEY_FILE=/opt/arkfile/etc/keys/tls/arkfile/server.key
```

SeaweedFS S3 credentials are also stored in `/opt/arkfile/etc/seaweedfs-s3.json`, which is generated by the deployment scripts alongside `secrets.env`.

**External S3 Provider Configuration:**

For external S3-compatible providers, set `STORAGE_PROVIDER` and the appropriate credentials in `secrets.env`:

```bash
# Backblaze B2
STORAGE_PROVIDER=backblaze
BACKBLAZE_ENDPOINT=s3.us-west-002.backblazeb2.com
BACKBLAZE_KEY_ID=your-access-key
BACKBLAZE_APPLICATION_KEY=your-secret-key
BACKBLAZE_BUCKET_NAME=your-bucket

# Amazon S3
STORAGE_PROVIDER=aws-s3
AWS_REGION=us-west-2
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_S3_BUCKET_NAME=your-s3-bucket
```

## TLS Configuration

### Certificate Generation

**Development Certificates:**
```bash
# Generate self-signed certificates
sudo ./scripts/setup/04-setup-tls-certs.sh

# Validate certificates
./scripts/maintenance/validate-certificates.sh
```

**Production Certificates:**
```bash
# Set domain for production
export ARKFILE_DOMAIN=yourdomain.com
sudo -E ./scripts/setup/04-setup-tls-certs.sh
```

### Certificate Architecture

**Directory Structure:**
```
/opt/arkfile/etc/keys/tls/
├── ca/                     # Certificate Authority
├── arkfile/                # Main application certificates
├── rqlite/                 # Database TLS certificates
├── seaweedfs/              # Storage TLS certificates
└── backup/                 # Certificate backups
```

**Modern Cryptographic Standards:**
- **Key Algorithm**: ECDSA P-384 (secp384r1)
- **Signature Algorithm**: ECDSA-SHA384
- **TLS Protocols**: TLS 1.3 only (with X25519MLKEM768 post-quantum key exchange)
- **Cipher Suites**: AES-256-GCM, ChaCha20-Poly1305

### Certificate Management

**Certificate Renewal:**
```bash
# Automatic renewal (checks expiration)
./scripts/maintenance/renew-certificates.sh

# Force renewal of all certificates
./scripts/maintenance/renew-certificates.sh --force
```

**Certificate Validation:**
```bash
# Comprehensive validation
./scripts/maintenance/validate-certificates.sh

# Detailed certificate information
./scripts/maintenance/validate-certificates.sh --details
```

## Administrative Validation

### Post-Deployment Validation

**Automated Validation:**
```bash
# Quick health check
./scripts/maintenance/health-check.sh
```

**Manual Validation Steps:**

1. **System Health:**
```bash
# Check service status
sudo systemctl status arkfile
sudo systemctl status rqlite
sudo systemctl status seaweedfs

# Verify health endpoint
curl -sk https://localhost:8443/readyz | jq '.'
```

2. **Web Interface Access:**
   - Navigate to `https://localhost:8443`
   - Verify page loads with "Private File Vault" title
   - Check browser console for JavaScript errors

3. **User Registration Test:**
   - Click "Get Started" on web interface
   - Enter test credentials
   - Verify registration success and password meets requirements

4. **File Operations Test:**
   - Upload a test file
   - Verify file encryption (shows lock icon)
   - Download and verify content matches original

### Real-World User Flow Testing

**Complete User Workflow:**

1. **Create Test File:**
```bash
echo "Hello Arkfile! Test file for validation." > ~/test-file.txt
```

2. **Upload and Encrypt:**
   - Use web interface to upload file
   - Select "Use my account password"

3. **Download and Decrypt:**
   - Click download on uploaded file
   - Enter account password
   - Verify downloaded file matches original

4. **File Sharing Test:**
   - Click "Share" on uploaded file
   - Set a share password
   - Copy generated share link
   - Open incognito browser window
   - Visit share link, enter share password, verify file downloads

5. **TOTP Multi-Factor Authentication Test:**
   - Navigate to user settings or account page
   - Enable TOTP by scanning QR code with authenticator app
   - Complete TOTP setup by entering verification code
   - Log out and log back in to verify TOTP requirement
   - Test backup codes for account recovery

### Backend Verification

**Database Verification:**
```bash
# Check user count
curl -u "dev-user:$RQLITE_PASSWORD" \
  'http://localhost:4001/db/query?q=SELECT+COUNT(*)+FROM+users'
```

**Storage Verification:**
```bash
# Check SeaweedFS S3 gateway status
curl http://localhost:9332/status

# List storage objects
ls -la /opt/arkfile/var/lib/seaweedfs/data/
```

**Key Verification:**
```bash
# Verify OPAQUE server keys
ls -la /opt/arkfile/etc/keys/opaque/

# Check JWT keys
ls -la /opt/arkfile/etc/keys/jwt/current/
```

## Maintenance and Operations

### Regular Tasks

**Daily:**
```bash
# Health check
./scripts/maintenance/health-check.sh

# Check service logs
sudo journalctl -u arkfile --since "24 hours ago"
```

**Weekly:**
```bash
# Security audit
./scripts/maintenance/security-audit.sh

# Backup keys
./scripts/maintenance/backup-keys.sh
```

**Monthly:**
```bash
# System updates
sudo apt update && sudo apt upgrade

# Certificate validation
./scripts/maintenance/validate-certificates.sh

# Check for dependency updates
./scripts/maintenance/check-updates.sh
```

### Backup Procedures

**Database Backup:**
```bash
# Manual backup
curl -s http://localhost:4001/db/backup -o /opt/arkfile/backups/db-backup-$(date +%Y%m%d).db
```

**Key Backup:**
```bash
# Secure key backup
./scripts/maintenance/backup-keys.sh

# Verify backup integrity
tar -tzf /opt/arkfile/backups/keys-backup-$(date +%Y%m%d).tar.gz
```

### Monitoring

**Health Monitoring:**
```bash
# Readiness endpoint
curl -sk https://localhost:8443/readyz

# Health endpoint
curl -sk https://localhost:8443/health
```

**Log Monitoring:**
```bash
# Application logs
sudo journalctl -u arkfile -f

# Database logs
sudo journalctl -u rqlite -f

# Storage logs
sudo journalctl -u seaweedfs -f
```

## Troubleshooting

### Common Issues

**Service Won't Start:**
```bash
# Check service status
sudo systemctl status arkfile
sudo journalctl -u arkfile -f

# Check port availability
sudo ss -tlnp | grep -E '8080|8443'
```

**Database Connection Issues:**
```bash
# Test rqlite connectivity
curl http://localhost:4001/status

# Check database service
sudo systemctl status rqlite

# Verify database permissions
sudo -u arkfile ls -la /opt/arkfile/var/lib/rqlite/
```

**TLS Certificate Issues:**
```bash
# Validate certificates
./scripts/maintenance/validate-certificates.sh

# Check certificate expiration
openssl x509 -in /opt/arkfile/etc/keys/tls/arkfile/server.crt -noout -dates

# Test TLS connection
openssl s_client -connect localhost:8443
```

**File Upload/Download Issues:**
```bash
# Check SeaweedFS service
sudo systemctl status seaweedfs

# Verify storage is accessible
curl http://localhost:9332/status

# Check storage data directory
sudo -u arkfile ls -la /opt/arkfile/var/lib/seaweedfs/data/
```

### Performance Issues

**Resource Usage:**
```bash
# Monitor system resources
htop
df -h

# Check memory usage
free -h
```

**Database Performance:**
```bash
# Check database size
du -sh /opt/arkfile/var/lib/rqlite/
```

### Emergency Procedures

**Service Recovery:**
```bash
# Emergency restart
sudo systemctl stop arkfile
sudo systemctl start arkfile

# Check service health
./scripts/maintenance/health-check.sh
```

**Key Compromise Response:**
```bash
# Execute emergency procedures
./scripts/maintenance/emergency-procedures.sh

# Rotate JWT keys immediately
./scripts/maintenance/rotate-jwt-keys.sh --force
```

### Getting Help

**Debug Information:**
```bash
# Check system health
./scripts/maintenance/health-check.sh

# Validate deployment
./scripts/maintenance/validate-deployment.sh

# Review logs
sudo journalctl -u arkfile --since "1 hour ago"
```

**File Locations:**
- **Binary**: `/opt/arkfile/bin/arkfile`
- **Configuration**: `/opt/arkfile/etc/secrets.env`
- **S3 Auth**: `/opt/arkfile/etc/seaweedfs-s3.json`
- **Keys**: `/opt/arkfile/etc/keys/`
- **Data**: `/opt/arkfile/var/lib/`
- **Logs**: `/opt/arkfile/var/log/`

## Quick Reference

### Essential Commands

```bash
# Service management
sudo systemctl {start|stop|restart|status} arkfile

# Health checks
curl -sk https://localhost:8443/readyz
./scripts/maintenance/health-check.sh

# Security operations
./scripts/maintenance/security-audit.sh
./scripts/maintenance/backup-keys.sh
```

### Success Criteria

**System is ready when:**
- All services show "active (running)" status
- Health endpoint returns "ready" for all checks
- User can register with OPAQUE authentication
- File upload, encryption, and download work correctly
- File sharing links work in incognito mode
- Backend verification commands show expected data

For security details, see [Security Guide](security.md). For API integration, see [API Reference](api.md).
