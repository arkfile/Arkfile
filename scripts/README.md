# Arkfile Scripts Guide

This directory contains all the setup, maintenance, and testing scripts for Arkfile. This guide helps you understand which script to run for your specific needs.

## 🚀 New to Arkfile? Start Here

### One-Command Setup
```bash
./scripts/quick-start.sh
```
**What it does:** Sets up a complete working Arkfile system for testing/development
- Creates users, directories, and cryptographic keys
- Sets up local MinIO storage and rqlite database
- Starts all services and validates they're working
- Provides web interface URL and testing instructions

**Use this if:** You want to try Arkfile immediately without complex configuration.

## 📋 Script Categories

### Core Setup Scripts (Most Important)

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `quick-start.sh` | **Complete one-command setup with TLS** | First time trying Arkfile |
| `setup-foundation.sh` | Set up users, directories, keys only | Manual step-by-step setup |
| `integration-test.sh` | Full system testing with options | Validating deployment |
| `health-check.sh` | System health verification | Troubleshooting issues |
| `uninstall.sh` | **Interactive system removal** | Safely removing Arkfile |

### Infrastructure Setup Scripts

| Script | Purpose | Requires Sudo |
|--------|---------|---------------|
| `setup-users.sh` | Create arkfile system user/group | Yes |
| `setup-directories.sh` | Create directory structure | Yes |
| `setup-minio.sh` | Configure MinIO object storage | Yes |
| `setup-rqlite.sh` | Configure rqlite database | Yes |

### Security & Keys Scripts

| Script | Purpose | Requires Sudo |
|--------|---------|---------------|
| `setup-opaque-keys.sh` | Generate OPAQUE authentication keys | Yes |
| `setup-jwt-keys.sh` | Generate JWT signing keys | Yes |
| `setup-tls-certs.sh` | Generate TLS certificates | Yes |
| `backup-keys.sh` | Backup cryptographic keys | Yes |
| `rotate-jwt-keys.sh` | Rotate JWT signing keys | Yes |

### Testing Scripts

| Script | Purpose | Use Case |
|--------|---------|----------|
| `test-only.sh` | Run comprehensive test suite | Development/CI |
| `test-wasm.sh` | Test WebAssembly functionality | Development |
| `performance-benchmark.sh` | Performance testing | Optimization |
| `golden-test-preservation.sh` | Validate file format compatibility | Regression testing |

### Validation & Monitoring Scripts

| Script | Purpose | Use Case |
|--------|---------|----------|
| `validate-deployment.sh` | Full deployment validation | Production readiness |
| `validate-certificates.sh` | TLS certificate validation | Certificate management |
| `security-audit.sh` | Security configuration audit | Security compliance |
| `admin-validation-guide.sh` | Admin testing procedures | Training/validation |

### Build & Deployment Scripts

| Script | Purpose | Use Case |
|--------|---------|----------|
| `build.sh` | Build application and WebAssembly | Development/deployment |
| `deploy.sh` | Production deployment | Production systems |
| `rollback.sh` | Rollback to previous version | Emergency recovery |
| `download-minio.sh` | Download MinIO binary | Setup preparation |

### Maintenance Scripts

| Script | Purpose | Use Case |
|--------|---------|----------|
| `emergency-procedures.sh` | Emergency response procedures | Incident response |
| `renew-certificates.sh` | Renew TLS certificates | Certificate maintenance |
| `generate-keys.sh` | Generate various types of keys | Key management |
| `first-time-setup.sh` | Legacy setup script | Compatibility |

## 🎯 Common Scenarios

### I Want to Try Arkfile (Development/Testing)
```bash
./scripts/quick-start.sh
```

### I Need Production Deployment
```bash
# Step 1: Foundation
./scripts/setup-foundation.sh

# Step 2: Services  
sudo ./scripts/setup-minio.sh
sudo ./scripts/setup-rqlite.sh

# Step 3: Validate
./scripts/validate-deployment.sh
```

### I'm Setting Up CI/CD
```bash
./scripts/test-only.sh --skip-performance
./scripts/build.sh
./scripts/integration-test.sh
```

### Something's Not Working
```bash
./scripts/health-check.sh
./scripts/security-audit.sh
sudo journalctl -u arkfile -f
```

### I Need to Backup/Rotate Keys
```bash
./scripts/backup-keys.sh
./scripts/rotate-jwt-keys.sh
```

### I Want to Remove Arkfile
```bash
sudo ./scripts/uninstall.sh
```
**Note:** Interactive script with prompts for each component. Offers key backup before removal.

## 🔧 Script Options

Most scripts support help flags:
```bash
./scripts/script-name.sh --help
```

Common options:
- `--skip-tests` - Skip test execution
- `--skip-tls` - Skip TLS certificate generation
- `--force-rebuild` - Force rebuild even if exists
- `--verbose` - Detailed output

## ⚠️ Important Notes

### Sudo Requirements
Scripts that modify system configuration require sudo:
- User/group creation scripts
- Service setup scripts  
- Key management scripts

### File Permissions
All scripts maintain production-security file permissions:
- Private keys: 600 (owner read/write only)
- Directories: 750 (owner full, group read/execute)
- Public files: 644 (owner read/write, others read)

### Service Dependencies
Some scripts have dependencies:
- MinIO setup requires rqlite
- Application requires both MinIO and rqlite
- TLS certificates are optional for development

## 🆘 Getting Help

### Script-Specific Help
```bash
./scripts/script-name.sh --help
```

### System Status
```bash
./scripts/health-check.sh
sudo systemctl status arkfile
```

### Logs
```bash
sudo journalctl -u arkfile -f
sudo journalctl -u minio -f  
sudo journalctl -u rqlite -f
```

### Documentation
- [Setup Guide](../docs/setup.md) - Detailed setup instructions
- [Security Operations](../docs/security-operations.md) - Security procedures
- [Admin Testing Guide](../docs/admin-testing-guide.md) - Testing procedures

## 🔍 Quick Reference

**Just want it working?** → `./scripts/quick-start.sh`

**Production deployment?** → See [docs/deployment-guide.md](../docs/deployment-guide.md)

**Having issues?** → `./scripts/health-check.sh` and check logs

**Need to test?** → `./scripts/integration-test.sh` (choose COMPLETE mode)
