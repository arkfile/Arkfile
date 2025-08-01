# Arkfile Setup Guide

This guide provides comprehensive instructions for installing, configuring, and managing Arkfile. It covers everything from quick testing to production deployment, ensuring a secure and reliable setup.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Installation Methods](#installation-methods)
4. [Production Deployment](#production-deployment)
5. [TLS Configuration](#tls-configuration)
6. [Administrative Validation](#administrative-validation)
7. [Maintenance and Operations](#maintenance-and-operations)
8. [Troubleshooting](#troubleshooting)

## Quick Start

### Just Want to Try Arkfile?

**Run this single command:**
```bash
./scripts/quick-start.sh
```

**What it does:**
- Sets up everything automatically
- Gives you a working web interface at http://localhost:8080
- Provides clear testing instructions
- Uses local MinIO and rqlite (no external dependencies)

**Time:** ~5 minutes  
**Requirements:** Linux with sudo access

### Alternative: Comprehensive Setup

For full system setup with complete validation:
```bash
./scripts/complete-setup-test.sh
```

When prompted, choose "COMPLETE" for full system setup. This will:
- Run complete test suite to validate functionality
- Create system users and directory structure
- Generate all required cryptographic keys
- Configure services and validate deployment

## Architecture Overview

### System Components

Arkfile's architecture consists of a client-side web interface, a server-side Go application, and external services for storage and security. The client-side component uses WebAssembly for in-browser encryption and decryption. The server-side application handles user authentication, manages metadata, and interfaces with storage backends.

External services include S3-compatible object storage, a distributed rqlite database cluster for metadata, and a Caddy web server for TLS and reverse proxying.

### Directory Structure and Service Users

Arkfile uses a standardized directory structure with dedicated service users. The main application directory is `/opt/arkfile/`, containing subdirectories for binaries, configuration files, application data, logs, and versioned releases.

The system operates with the `arkfile` user for running services, and the `arkfile` group for resource access. This separation enforces the principle of least privilege and isolates application resources.

### Storage Architecture

Arkfile supports multiple storage backends:
- **Local MinIO** - Filesystem-based storage for development
- **MinIO Cluster** - Distributed storage for production
- **External S3** - Backblaze B2, Wasabi, Vultr Object Storage
- **Self-hosted** - Any S3-compatible storage provider

### Database Architecture

The system uses rqlite, a distributed SQLite database, for all metadata storage. This provides:
- Distributed consensus and replication
- SQLite compatibility with clustering
- High availability with automatic failover
- Consistent data across nodes

## Installation Methods

### Method 1: Quick Start (Development/Testing)

**Best for:** First-time users, development, testing

```bash
# Single command setup
./scripts/quick-start.sh

# Check if everything is working
curl http://localhost:8080/health
```

**What you get:**
- Working web interface at http://localhost:8080
- Local MinIO storage
- Single-node rqlite database
- All required keys generated
- Ready for immediate testing

### Method 2: Integration Test (Complete Setup)

**Best for:** Production-ready installations, comprehensive validation

```bash
# Run comprehensive setup
./scripts/integration-test.sh

# When prompted, type "COMPLETE" for full system setup
```

**What you get:**
- Complete test suite validation (100+ tests)
- Production-ready configuration
- Comprehensive system validation
- Full administrative capabilities
- TLS certificates generated

### Method 3: Manual Step-by-Step

**Best for:** Custom configurations, learning the system

```bash
# Foundation setup (users, directories, keys)
./scripts/setup/00-setup-foundation.sh

# Add services manually
sudo ./scripts/setup/07-setup-minio.sh
sudo ./scripts/setup/08-setup-rqlite.sh

# Build and deploy
./scripts/setup/build.sh
./scripts/setup/deploy.sh prod
```

## Production Deployment

### System Requirements

**Hardware Requirements:**
- **Minimum**: 2 vCPU, 4GB RAM, 20GB storage
- **Recommended**: 4 vCPU, 8GB RAM, 100GB SSD storage
- **High Load**: 8+ vCPU, 16GB+ RAM, 500GB+ NVMe storage

NOTE: Storage needs vary based on storage backend; minio local/cluster modes require the most storage space.

**Operating System Support:**
- **Primary**: Debian 11/12/+, Ubuntu 20.04/22.04/+ LTS
- **RHEL-based**: AlmaLinux 8/9/+, Rocky Linux 8/9/+, RHEL 8/9/+, Fedora 41/42/+
- **Architecture**: x86_64 (amd64)

**Network Requirements:**
- **Ports**: 8080 (HTTP), 443 (HTTPS), 4001 (rqlite), 9000 (MinIO)
- **Outbound**: Access to package repositories
- **DNS**: Proper FQDN resolution for TLS certificates

### Prerequisites

**Go Installation:**
```bash
# Install Go 1.24.2 or later
wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

**System Dependencies:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y curl wget git build-essential sqlite3 openssl

# RHEL/AlmaLinux/Rocky
sudo dnf install -y curl wget git gcc make sqlite openssl
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

### Production Installation

**Option 1: Integration Test Script (Recommended)**

```bash
# Clone repository
cd /opt/arkfile
sudo -u arkfile git clone https://github.com/84adam/arkfile.git src
cd src

# Run comprehensive setup
sudo ./scripts/complete-setup-test.sh
# Type "COMPLETE" when prompted for full system setup
```

**Option 2: Manual Production Setup**

```bash
# Clone and build
cd /opt/arkfile
sudo -u arkfile git clone https://github.com/84adam/arkfile.git src
cd src
sudo -u arkfile ./scripts/setup/build.sh

# Install binary
sudo cp arkfile /opt/arkfile/bin/
sudo chown arkfile:arkfile /opt/arkfile/bin/arkfile

# Run setup
sudo -u arkfile ./scripts/deprecated/first-time-setup.sh
```

### Configuration

**Environment Configuration:**

Create `/etc/arkfile/config.yaml`:
```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"

database:
  driver: "rqlite"
  connection: "http://localhost:4001"
  max_connections: 25
  max_idle_connections: 5

storage:
  backend: "minio"
  endpoint: "localhost:9000"
  bucket_name: "arkfile-storage"
  key_id: "minioadmin"
  access_key: "minioadmin"
  use_ssl: false

security:
  max_file_size: "1073741824" # 1GB
  allowed_origins: ["https://your-domain.com"]
  rate_limit_requests: 100
  rate_limit_window: "1h"
  session_timeout: "24h"
```

**Storage Provider Configuration:**

For external S3-compatible providers:
```yaml
storage:
  backend: "backblaze"  # or "wasabi", "vultr"
  endpoint: "s3.us-west-002.backblazeb2.com"
  region: "us-west-002"
  bucket_name: "your-bucket"
  key_id: "your-access-key"
  access_key: "your-secret-key"
  use_ssl: true
```

## TLS Configuration

### Certificate Generation

**Development Certificates:**
```bash
# Generate self-signed certificates
sudo ./scripts/setup/05-setup-tls-certs.sh

# Validate certificates
./scripts/validate-certificates.sh
```

**Production Certificates:**
```bash
# Set domain for production
export ARKFILE_DOMAIN=yourdomain.com
sudo -E ./scripts/setup/05-setup-tls-certs.sh

# For Let's Encrypt (when available)
sudo ./scripts/setup/setup-letsencrypt.sh
```

### Certificate Architecture

**Directory Structure:**
```
/opt/arkfile/etc/keys/tls/
├── ca/                     # Certificate Authority
├── arkfile/                # Main application certificates
├── rqlite/                 # Database TLS certificates
├── minio/                  # Storage TLS certificates
└── backup/                 # Certificate backups
```

**Modern Cryptographic Standards:**
- **Key Algorithm**: ECDSA P-384 (secp384r1)
- **Signature Algorithm**: ECDSA-SHA384
- **TLS Protocols**: TLS 1.3 preferred, TLS 1.2 minimum
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
# Run comprehensive admin testing
./scripts/testing/admin-integration-test.sh

# Quick health check
./scripts/maintenance/health-check.sh
```

**Manual Validation Steps:**

1. **System Health:**
```bash
# Check service status
sudo systemctl status arkfile
sudo systemctl status rqlite
sudo systemctl status minio

# Verify health endpoint
curl -s http://localhost:8080/health | jq '.'
```

2. **Web Interface Access:**
   - Navigate to `http://localhost:8080`
   - Verify page loads with "Secure File Sharing" title
   - Check browser console for JavaScript errors

3. **User Registration Test:**
   - Click "Register" on web interface
   - Enter test credentials: `admin@test.local` / `AdminTest123!SecurePassword2025`
   - Verify registration success and password meets entropy requirements

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
   - Add password hint: "Test file"

3. **Download and Decrypt:**
   - Click download on uploaded file
   - Enter account password
   - Verify downloaded file matches original

4. **File Sharing Test:**
   - Click "Share" on uploaded file
   - Copy generated share link
   - Open incognito browser window
   - Visit share link and verify file downloads

5. **TOTP Multi-Factor Authentication Test:**
   - Navigate to user settings or account page
   - Enable TOTP by scanning QR code with authenticator app
   - Complete TOTP setup by entering verification code
   - Log out and log back in to verify TOTP requirement
   - Test backup codes for account recovery

### Backend Verification

**Database Verification:**
```bash
# Check user registration
rqlite -H localhost:4001 'SELECT email FROM users;'

# Verify file metadata
rqlite -H localhost:4001 'SELECT file_name, encrypted FROM files;'
```

**Storage Verification:**
```bash
# Check MinIO connectivity
curl -I http://localhost:9000/minio/health/ready

# List storage objects
ls -la /opt/arkfile/var/lib/storage/
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
./scripts/health-check.sh

# Check service logs
sudo journalctl -u arkfile --since "24 hours ago"
```

**Weekly:**
```bash
# Security audit
./scripts/maintenance/security-audit.sh

# Key rotation (automated via systemd timer)
sudo systemctl status arkfile-key-rotation.timer

# Backup keys
./scripts/maintenance/backup-keys.sh
```

**Monthly:**
```bash
# System updates
sudo apt update && sudo apt upgrade

# Performance benchmark
./scripts/testing/performance-benchmark.sh

# Certificate validation
./scripts/maintenance/validate-certificates.sh
```

### Backup Procedures

**Database Backup:**
```bash
# Manual backup
rqlite -H localhost:4001 '.backup /opt/arkfile/backups/db-backup-$(date +%Y%m%d).db'

# Automated backup (add to crontab)
0 2 * * * /opt/arkfile/scripts/maintenance/backup-keys.sh
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
# Health endpoint
curl -H "Accept: application/json" http://localhost:8080/health

# Service metrics
curl http://localhost:8080/metrics
```

**Log Monitoring:**
```bash
# Application logs
sudo journalctl -u arkfile -f

# Database logs
sudo journalctl -u rqlite -f

# Storage logs
sudo journalctl -u minio -f
```

## Troubleshooting

### Common Issues

**Service Won't Start:**
```bash
# Check service status
sudo systemctl status arkfile
sudo journalctl -u arkfile -f

# Verify configuration
sudo -u arkfile /opt/arkfile/bin/arkfile --config /etc/arkfile/config.yaml --validate

# Check port availability
sudo netstat -tlnp | grep :8080
```

**Database Connection Issues:**
```bash
# Test rqlite connectivity
rqlite -H localhost:4001 'SELECT 1'

# Check database service
sudo systemctl status rqlite

# Verify database permissions
sudo -u arkfile ls -la /opt/arkfile/var/lib/rqlite/
```

**TLS Certificate Issues:**
```bash
# Validate certificates
./scripts/validate-certificates.sh

# Check certificate expiration
openssl x509 -in /opt/arkfile/etc/keys/tls/arkfile/server-cert.pem -noout -dates

# Test TLS connection
openssl s_client -connect localhost:443 -servername yourdomain.com
```

**File Upload/Download Issues:**
```bash
# Check MinIO service
sudo systemctl status minio

# Verify storage permissions
sudo -u arkfile ls -la /opt/arkfile/var/lib/storage/

# Test MinIO connectivity
curl -I http://localhost:9000/minio/health/ready
```

### Performance Issues

**Resource Usage:**
```bash
# Monitor system resources
htop
df -h

# Check memory usage
free -h

# Review performance metrics
./scripts/performance-benchmark.sh
```

**Database Performance:**
```bash
# Check database size
du -sh /opt/arkfile/var/lib/rqlite/

# Monitor database queries
rqlite -H localhost:4001 '.timer on' 'SELECT COUNT(*) FROM users;'
```

### Emergency Procedures

**Service Recovery:**
```bash
# Emergency restart
sudo systemctl stop arkfile
sudo systemctl start arkfile

# Check service health
./scripts/health-check.sh
```

**Database Recovery:**
```bash
# Stop service
sudo systemctl stop arkfile

# Restore from backup
sudo -u arkfile cp /opt/arkfile/backups/db-backup-YYYYMMDD.db /opt/arkfile/var/lib/rqlite/

# Restart service
sudo systemctl start arkfile
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
# Generate debug report
./scripts/health-check.sh --debug

# Check system configuration
./scripts/maintenance/validate-deployment.sh

# Review logs
sudo journalctl -u arkfile --since "1 hour ago"
```

**Support Resources:**
- **Health Dashboard**: `http://localhost:8080/health`
- **Security Audit**: `./scripts/maintenance/security-audit.sh`
- **Performance Testing**: `./scripts/testing/performance-benchmark.sh`
- **Log Files**: `/var/log/arkfile/` and `sudo journalctl -u arkfile`

**File Locations:**
- **Binary**: `/opt/arkfile/bin/arkfile`
- **Configuration**: `/etc/arkfile/config.yaml`
- **Keys**: `/opt/arkfile/etc/keys/`
- **Data**: `/opt/arkfile/var/lib/`
- **Logs**: `/var/log/arkfile/`
- **Backups**: `/opt/arkfile/backups/`

## Quick Reference

### Essential Commands

```bash
# Service management
sudo systemctl {start|stop|restart|status} arkfile

# Health checks
curl http://localhost:8080/health
./scripts/health-check.sh

# Administrative testing
./scripts/testing/admin-integration-test.sh

# Security operations
./scripts/security-audit.sh
./scripts/backup-keys.sh
```

### Success Criteria

✅ **System is ready when:**
- All services show "active (running)" status
- Health endpoint returns "healthy" for all checks
- User can register with OPAQUE authentication
- File upload, encryption, and download work correctly
- File sharing links work in incognito mode
- Backend verification commands show expected data

For security details, see [Security Guide](security.md). For API integration, see [API Reference](api.md).
