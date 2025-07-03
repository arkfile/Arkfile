# Quick-Start Script Fixes Summary

This document summarizes the fixes made to resolve the quick-start script issues and ensure a working demo deployment.

## Problems Identified

### 1. SystemD Service Configuration Mismatch
- **Issue**: Service templates expected `arknode1` user but only `arkfile` user existed
- **Root Cause**: Mixed single-user and cluster configurations

### 2. Missing Environment Configuration
- **Issue**: Services referenced `/opt/arkfile/etc/node1/secrets.env` which didn't exist
- **Root Cause**: No environment file generation in quick-start

### 3. Inconsistent Service Names
- **Issue**: Scripts used `minio@node1` and `rqlite@node1` inconsistently
- **Root Cause**: Cluster naming in single-node deployment

## Fixes Applied

### 1. SystemD Service Template Updates

**File: `systemd/minio@.service`**
- Changed `User=ark%i` → `User=arkfile`
- Changed `EnvironmentFile=/opt/arkfile/etc/%i/secrets.env` → `/opt/arkfile/etc/secrets.env`
- Simplified `ExecStart` for single-node mode (`:9000` and `:9001` instead of cluster config)

**File: `systemd/rqlite@.service`**
- Changed `User=ark%i` → `User=arkfile`
- Changed `EnvironmentFile=/opt/arkfile/etc/%i/secrets.env` → `/opt/arkfile/etc/secrets.env`
- Changed `WorkingDirectory=/opt/arkfile/var/lib/%i` → `/opt/arkfile/var/lib/database`
- Simplified `ExecStart` for single-node mode

### 2. Quick-Start Script Enhancements

**File: `scripts/quick-start.sh`**

**Added Security Warning:**
```bash
echo -e "${RED}⚠️  SECURITY WARNING - DEMO CONFIGURATION ⚠️${NC}"
echo -e "${YELLOW}This quick-start creates a demo system with default credentials.${NC}"
# ... with user confirmation prompt
```

**Added Demo Environment File Generation:**
```bash
sudo tee /opt/arkfile/etc/secrets.env > /dev/null << 'EOF'
# ⚠️  DEMO CONFIGURATION - NOT FOR PRODUCTION ⚠️
MINIO_ROOT_USER=arkfile-demo
MINIO_ROOT_PASSWORD=demo-password-change-me-for-production
LOCAL_STORAGE_PATH=/opt/arkfile/var/lib/minio/data
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
JWT_SECRET=demo-jwt-secret-change-for-production-use
# ... more demo configuration
EOF
```

**Fixed Service Names:**
- `minio@node1` → `minio@demo`
- `rqlite@node1` → `rqlite@demo`

### 3. Directory Structure Simplification

**File: `scripts/setup-minio.sh`**
- Removed multi-environment loop (`prod`/`test`)
- Single directory: `/opt/arkfile/var/lib/minio/data`
- Single owner: `arkfile:arkfile`

**File: `scripts/setup-rqlite.sh`**
- Added database directory creation: `/opt/arkfile/var/lib/database`

### 4. Test Script Updates

**File: `scripts/admin-integration-test.sh`**
- Updated all service references to use `@demo` instead of `@node1`
- Fixed troubleshooting commands to reference correct service names

## Demo Configuration Created

The quick-start now generates this demo environment:

```bash
# Demo Credentials (CHANGE FOR PRODUCTION!)
MINIO_ROOT_USER=arkfile-demo
MINIO_ROOT_PASSWORD=demo-password-change-me-for-production
JWT_SECRET=demo-jwt-secret-change-for-production-use
ADMIN_EMAILS=admin@arkfile.demo

# Single-Node Configuration
DATABASE_TYPE=rqlite
RQLITE_ADDRESS=http://localhost:4001
LOCAL_STORAGE_PATH=/opt/arkfile/var/lib/minio/data

# Demo Settings
REQUIRE_APPROVAL=false
ENABLE_REGISTRATION=true
DEBUG_MODE=true
```

## Result

### Before Fixes:
- ❌ `minio@node1` service failed (user `arknode1` didn't exist)
- ❌ `rqlite@node1` service failed (environment file missing)
- ❌ No working demo configuration

### After Fixes:
- ✅ Services use `arkfile` user (which exists)
- ✅ Single environment file with demo credentials
- ✅ Consistent `@demo` service naming
- ✅ Working single-node deployment
- ✅ Clear security warnings about demo nature
- ✅ Auto-generated environment configuration

## Usage

```bash
./scripts/quick-start.sh
# 1. Shows security warning and demo credentials
# 2. Prompts for user confirmation
# 3. Sets up foundation, services, and demo environment
# 4. Starts minio@demo, rqlite@demo, and arkfile services
# 5. Provides access URLs and next steps
```

## Production Notes

The quick-start script now prominently warns users that this creates a **DEMO SYSTEM** and provides clear guidance for production hardening:

- `./scripts/security-audit.sh`
- `./scripts/rotate-jwt-keys.sh`
- `./scripts/setup-tls-certs.sh --production`

This ensures users understand the difference between the quick demo and production deployment requirements.
