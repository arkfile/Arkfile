# Arkfile Production Deployment Guide

This guide provides comprehensive instructions for deploying Arkfile in production environments with enterprise-grade security and operational readiness.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Security Preparation](#security-preparation)
4. [Installation Process](#installation-process)
5. [Configuration](#configuration)
6. [Health Monitoring](#health-monitoring)
7. [Maintenance](#maintenance)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### Hardware Requirements

- **Minimum**: 2 vCPU, 4GB RAM, 20GB storage
- **Recommended**: 4 vCPU, 8GB RAM, 100GB SSD storage
- **High Load**: 8+ vCPU, 16GB+ RAM, 500GB+ NVMe storage

### Operating System Support

- **Primary**: Debian 11/12, Ubuntu 20.04/22.04 LTS
- **RHEL-based**: AlmaLinux 8/9, Rocky Linux 8/9, RHEL 8/9
- **Architecture**: x86_64 (amd64)

### Network Requirements

- **Ports**: 8080 (HTTP), 443 (HTTPS), 4001 (rqlite), 9000 (MinIO)
- **Outbound**: Access to package repositories, container registries
- **DNS**: Proper FQDN resolution for TLS certificates

## System Requirements

### Go Installation

```bash
# Install Go 1.21 or later
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### System Dependencies

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y curl wget git build-essential sqlite3 openssl

# RHEL/AlmaLinux/Rocky
sudo dnf install -y curl wget git gcc make sqlite openssl
```

### Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# firewalld (RHEL-based)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Security Preparation

### User Account Setup

```bash
# Create dedicated service account
sudo useradd -r -s /bin/false -d /opt/arkfile arkfile
sudo mkdir -p /opt/arkfile
sudo chown arkfile:arkfile /opt/arkfile

# Add admin user to arkfile group for management
sudo usermod -a -G arkfile $USER
```

### Directory Structure

```bash
# Create application directories
sudo mkdir -p /opt/arkfile/{bin,config,data,logs,keys,backups}
sudo mkdir -p /etc/arkfile/{keys,certs}
sudo mkdir -p /var/log/arkfile

# Set proper ownership and permissions
sudo chown -R arkfile:arkfile /opt/arkfile
sudo chown -R arkfile:arkfile /etc/arkfile
sudo chown -R arkfile:arkfile /var/log/arkfile

# Secure key directories
sudo chmod 700 /etc/arkfile/keys
sudo chmod 755 /etc/arkfile/certs
```

## Installation Process

### Option 1: Comprehensive Integration Test Script (Recommended)

The fastest way to set up a complete Arkfile system is using the comprehensive integration test script:

```bash
# Clone repository
cd /opt/arkfile
sudo -u arkfile git clone https://github.com/84adam/arkfile.git src
cd src

# Run comprehensive setup with full system configuration
sudo ./scripts/integration-test.sh

# When prompted, type "YES" to perform full system setup
# This will:
# - Run complete test suite (100+ tests)
# - Create arkfile system user and group
# - Set up directory structure with proper permissions
# - Generate OPAQUE server keys
# - Generate JWT signing keys  
# - Generate TLS certificates
# - Configure systemd services
# - Validate entire deployment
```

### Option 2: Manual Step-by-Step Setup

For more control over the installation process:

```bash
# Clone repository
cd /opt/arkfile
sudo -u arkfile git clone https://github.com/84adam/arkfile.git src
cd src

# Build application
sudo -u arkfile ./scripts/build.sh

# Install binary
sudo cp arkfile /opt/arkfile/bin/
sudo chown arkfile:arkfile /opt/arkfile/bin/arkfile
sudo chmod 755 /opt/arkfile/bin/arkfile
```

#### 2a. Run First-Time Setup

```bash
# Execute comprehensive setup script
sudo -u arkfile /opt/arkfile/src/scripts/first-time-setup.sh

# This script will:
# - Generate OPAQUE server keys
# - Create JWT signing keys
# - Generate TLS certificates
# - Set up database schema
# - Configure systemd services
```

#### 2b. Verify Installation

```bash
# Check setup validation
sudo -u arkfile /opt/arkfile/src/scripts/validate-deployment.sh

# Run health check
sudo -u arkfile /opt/arkfile/src/scripts/health-check.sh

# Test WASM functionality
sudo -u arkfile /opt/arkfile/src/scripts/test-wasm.sh
```

### Integration Test Script Features

The integration test script (`./scripts/integration-test.sh`) provides two modes:

#### Testing Mode (Default)
- Runs comprehensive test suite without system modifications
- Perfect for CI/CD and development validation
- Tests all functionality including OPAQUE, crypto, WebAssembly

#### Full Setup Mode (Production)
- Creates complete production-ready environment
- Requires explicit confirmation ("YES")
- Includes user creation, directory setup, key generation
- Validates entire system after setup

**Test Coverage:**
- **Unit Tests**: 100% pass rate across all modules
- **WebAssembly**: 14/14 tests across browser compatibility
- **Performance**: 1GB+ file operations validated
- **Format Compatibility**: 72/72 golden test vectors
- **Security**: OPAQUE authentication, Argon2ID, rate limiting

## Configuration

### Environment Configuration

Create `/etc/arkfile/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"

database:
  driver: "sqlite"
  connection: "/opt/arkfile/data/arkfile.db"
  max_connections: 25
  max_idle_connections: 5

key_management:
  key_directory: "/etc/arkfile/keys"
  jwt_key_path: "jwt_signing.key"
  opaque_key_path: "opaque_server.key"
  rotation_interval: "168h" # 7 days

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
  
deployment:
  environment: "production"
  data_directory: "/opt/arkfile/data"
  log_directory: "/var/log/arkfile"
  backup_directory: "/opt/arkfile/backups"
  
monitoring:
  health_check_interval: "30s"
  metrics_enabled: true
  log_level: "info"
```

### Systemd Service Configuration

The setup script creates systemd services. Verify with:

```bash
# Check service status
sudo systemctl status arkfile
sudo systemctl status rqlite@arkfile
sudo systemctl status minio@arkfile

# Enable for startup
sudo systemctl enable arkfile
sudo systemctl enable rqlite@arkfile
sudo systemctl enable minio@arkfile
```

### TLS Certificate Setup

For production, replace self-signed certificates:

```bash
# Using Let's Encrypt with Caddy (recommended)
sudo ./scripts/setup-tls-certs.sh --production --domain your-domain.com

# Or manually place certificates
sudo cp your-cert.pem /etc/arkfile/certs/arkfile.crt
sudo cp your-key.pem /etc/arkfile/certs/arkfile.key
sudo chown arkfile:arkfile /etc/arkfile/certs/*
sudo chmod 600 /etc/arkfile/certs/arkfile.key
```

## Health Monitoring

### Built-in Health Endpoints

Arkfile provides comprehensive health monitoring:

```bash
# Health check (comprehensive)
curl -H "Accept: application/json" http://localhost:8080/health

# Readiness check (quick)
curl http://localhost:8080/ready

# Liveness check (minimal)
curl http://localhost:8080/alive

# Prometheus metrics
curl http://localhost:8080/metrics
```

### Health Check Response

```json
{
  "status": "healthy",
  "timestamp": "2025-06-27T15:30:00Z",
  "version": "1.0.0",
  "uptime": "72h15m30s",
  "checks": {
    "database": {
      "name": "database",
      "status": "healthy",
      "message": "Database operational, 5 OPAQUE keys",
      "duration": "2ms"
    },
    "keys": {
      "name": "keys",
      "status": "healthy",
      "message": "All cryptographic keys available",
      "duration": "1ms"
    },
    "storage": {
      "name": "storage",
      "status": "healthy",
      "message": "Storage backend configured",
      "duration": "1ms"
    },
    "system": {
      "name": "system",
      "status": "healthy",
      "message": "System resources normal",
      "duration": "1ms"
    }
  },
  "system": {
    "go_version": "go1.21.5",
    "num_goroutine": 45,
    "num_cpu": 4,
    "memory": {
      "alloc": 15728640,
      "total_alloc": 45678900,
      "sys": 73400320,
      "num_gc": 12,
      "last_gc": "2025-06-27T15:29:45Z"
    }
  },
  "summary": {
    "total": 4,
    "healthy": 4,
    "degraded": 0,
    "unhealthy": 0
  }
}
```

### Monitoring Integration

#### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'arkfile'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

#### Grafana Dashboard

Key metrics to monitor:
- `arkfile_health_status` - Overall health status
- `arkfile_uptime_seconds` - Service uptime
- `arkfile_memory_bytes` - Memory usage
- `arkfile_goroutines` - Goroutine count
- `arkfile_checks_*` - Individual health check metrics

## Maintenance

### Regular Tasks

#### Daily

```bash
# Health check
sudo -u arkfile /opt/arkfile/src/scripts/health-check.sh

# Log rotation (handled by logrotate)
sudo logrotate -f /etc/logrotate.d/arkfile
```

#### Weekly

```bash
# Key rotation (automated, verify)
sudo systemctl status arkfile-key-rotation.timer

# Security audit
sudo -u arkfile /opt/arkfile/src/scripts/security-audit.sh

# Backup keys
sudo -u arkfile /opt/arkfile/src/scripts/backup-keys.sh
```

#### Monthly

```bash
# Update system packages
sudo apt update && sudo apt upgrade  # Debian/Ubuntu
sudo dnf update                      # RHEL-based

# Performance benchmark
sudo -u arkfile /opt/arkfile/src/scripts/performance-benchmark.sh

# Golden test validation
sudo -u arkfile /opt/arkfile/src/scripts/golden-test-preservation.sh --validate
```

### Backup Procedures

#### Database Backup

```bash
# Manual backup
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db ".backup /opt/arkfile/backups/arkfile-$(date +%Y%m%d).db"

# Automated backup (add to crontab)
0 2 * * * /opt/arkfile/src/scripts/backup-keys.sh
```

#### Key Backup

```bash
# Secure key backup
sudo -u arkfile /opt/arkfile/src/scripts/backup-keys.sh

# Verify backup integrity
sudo -u arkfile tar -tzf /opt/arkfile/backups/keys-backup-$(date +%Y%m%d).tar.gz
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check systemd status
sudo systemctl status arkfile
sudo journalctl -u arkfile -f

# Common fixes:
# 1. Check file permissions
sudo chown -R arkfile:arkfile /opt/arkfile /etc/arkfile /var/log/arkfile

# 2. Verify configuration
sudo -u arkfile /opt/arkfile/bin/arkfile --config /etc/arkfile/config.yaml --validate

# 3. Check port availability
sudo netstat -tlnp | grep :8080
```

#### Database Connection Issues

```bash
# Check database file
ls -la /opt/arkfile/data/arkfile.db
sqlite3 /opt/arkfile/data/arkfile.db ".tables"

# Recreate database schema
sudo -u arkfile sqlite3 /opt/arkfile/data/arkfile.db < /opt/arkfile/src/database/schema_extensions.sql
```

#### Key Loading Failures

```bash
# Verify key files
sudo -u arkfile ls -la /etc/arkfile/keys/

# Regenerate keys if corrupted
sudo -u arkfile /opt/arkfile/src/scripts/setup-opaque-keys.sh
sudo -u arkfile /opt/arkfile/src/scripts/setup-jwt-keys.sh
```

#### Performance Issues

```bash
# Monitor resource usage
htop
iotop
df -h

# Check memory leaks
sudo -u arkfile /opt/arkfile/src/scripts/performance-benchmark.sh

# Review logs for errors
sudo tail -f /var/log/arkfile/app.log
```

### Emergency Procedures

#### Service Recovery

```bash
# Emergency restart
sudo systemctl stop arkfile
sudo systemctl start arkfile
sudo systemctl status arkfile
```

#### Key Compromise Response

```bash
# Execute emergency procedures
sudo -u arkfile /opt/arkfile/src/scripts/emergency-procedures.sh

# Rotate all keys immediately
sudo -u arkfile /opt/arkfile/src/scripts/rotate-jwt-keys.sh --force
```

#### Database Recovery

```bash
# Restore from backup
sudo systemctl stop arkfile
sudo -u arkfile cp /opt/arkfile/backups/arkfile-YYYYMMDD.db /opt/arkfile/data/arkfile.db
sudo systemctl start arkfile
```

### Support and Logging

#### Log Locations

- Application logs: `/var/log/arkfile/app.log`
- Security events: `/var/log/arkfile/security.log`
- System logs: `journalctl -u arkfile`

#### Debug Mode

```bash
# Enable debug logging
sudo systemctl edit arkfile
# Add:
# [Service]
# Environment="LOG_LEVEL=debug"
sudo systemctl daemon-reload
sudo systemctl restart arkfile
```

#### Getting Help

1. Check logs for specific error messages
2. Run health check and deployment validation scripts
3. Review configuration against this guide
4. Consult security operations guide for security-related issues

---

## Quick Reference

### Essential Commands

```bash
# Service management
sudo systemctl {start|stop|restart|status} arkfile

# Health checks
curl http://localhost:8080/health
/opt/arkfile/src/scripts/health-check.sh

# Key operations
/opt/arkfile/src/scripts/backup-keys.sh
/opt/arkfile/src/scripts/rotate-jwt-keys.sh

# Validation
/opt/arkfile/src/scripts/validate-deployment.sh
/opt/arkfile/src/scripts/security-audit.sh
```

### File Locations

- **Binary**: `/opt/arkfile/bin/arkfile`
- **Config**: `/etc/arkfile/config.yaml`
- **Keys**: `/etc/arkfile/keys/`
- **Data**: `/opt/arkfile/data/`
- **Logs**: `/var/log/arkfile/`
- **Backups**: `/opt/arkfile/backups/`

For additional support, consult the [Security Operations Guide](security-operations.md) and [Emergency Procedures Guide](emergency-procedures.md).
