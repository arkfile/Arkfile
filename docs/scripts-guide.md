# Arkfile Scripts Guide

This guide covers all the scripts in the `scripts/` directory and explains how they work together to build, deploy, and maintain Arkfile.

## Quick Start

For new users, start with these main entry points:

- **`quick-start.sh`** - Complete setup and start in one command
- **`complete-setup-test.sh`** - Complete setup with comprehensive testing

## Directory Structure

```
scripts/
├── quick-start.sh                    # Main entry point for quick setup
├── complete-setup-test.sh            # Complete setup with testing
├── setup/                            # Setup and deployment scripts
│   ├── 00-setup-foundation.sh        # Foundation setup (users, dirs, keys)
│   ├── 01-setup-users.sh             # Create arkfile system user
│   ├── 02-setup-directories.sh       # Create directory structure
│   ├── 03-setup-opaque-keys.sh       # Generate OPAQUE server keys
│   ├── 04-setup-jwt-keys.sh          # Generate JWT signing keys
│   ├── 05-setup-tls-certs.sh         # Generate TLS certificates
│   ├── 06-setup-database.sh          # Set up database schema
│   ├── 07-setup-minio.sh             # Configure MinIO storage
│   ├── 08-setup-rqlite.sh            # Configure rqlite database
│   ├── build.sh                      # Build application
│   ├── deploy.sh                     # Deploy to production
│   ├── rollback.sh                   # Rollback deployment
│   └── uninstall.sh                  # Remove system installation
├── testing/                          # Testing and validation scripts
│   ├── test-only.sh                  # Run test suite
│   ├── test-wasm.sh                  # WebAssembly tests
│   ├── test-totp.sh                  # TOTP implementation tests
│   ├── performance-benchmark.sh      # Performance testing
│   ├── golden-test-preservation.sh   # Format compatibility tests
│   └── admin-integration-test.sh     # Admin integration tests
├── maintenance/                      # Maintenance and operational scripts
│   ├── health-check.sh               # System health monitoring
│   ├── security-audit.sh             # Security auditing
│   ├── backup-keys.sh                # Backup cryptographic keys
│   ├── rotate-jwt-keys.sh            # Rotate JWT signing keys
│   ├── renew-certificates.sh         # Renew TLS certificates
│   ├── check-updates.sh              # Check for updates
│   ├── update-dependencies.sh        # Update system dependencies
│   ├── update-go-deps.sh             # Update Go modules
│   ├── validate-deployment.sh        # Validate deployment
│   ├── validate-certificates.sh      # Validate TLS certificates
│   ├── admin-validation-guide.sh     # Interactive admin validation
│   ├── download-minio.sh             # Download MinIO binaries
│   └── emergency-procedures.sh       # Emergency response procedures
└── deprecated/                       # Legacy scripts (preserved for safety)
    ├── first-time-setup.sh           # Old setup script
    └── generate-keys.sh               # Old key generation script
```

## Script Categories

### Main Entry Points

#### `quick-start.sh`
**Purpose**: Get Arkfile running quickly with minimal configuration  
**Usage**: `./scripts/quick-start.sh`  
**What it does**:
- Stops any existing services
- Runs foundation setup (users, directories, keys)
- Sets up MinIO and rqlite
- Starts all services
- Provides web interface URL

#### `complete-setup-test.sh`
**Purpose**: Complete setup with comprehensive testing  
**Usage**: `./scripts/complete-setup-test.sh`  
**Options**:
- `FOUNDATION` - Foundation setup only
- `COMPLETE` - Complete working system
- Press Enter - Testing only

### Setup Scripts (Numbered Order)

The setup scripts are numbered to show their logical dependency order:

#### `00-setup-foundation.sh`
**Purpose**: Foundation infrastructure setup  
**Usage**: `./scripts/setup/00-setup-foundation.sh [--skip-tests] [--skip-tls]`  
**Dependencies**: None  
**Creates**: Users, directories, keys, certificates

#### `01-setup-users.sh`
**Purpose**: Create arkfile system user and group  
**Usage**: `sudo ./scripts/setup/01-setup-users.sh`  
**Dependencies**: None  
**Creates**: `arkfile` user and group

#### `02-setup-directories.sh`
**Purpose**: Create directory structure  
**Usage**: `sudo ./scripts/setup/02-setup-directories.sh`  
**Dependencies**: arkfile user  
**Creates**: `/opt/arkfile/` tree with proper permissions

#### `03-setup-opaque-keys.sh`
**Purpose**: Generate OPAQUE server keys  
**Usage**: `sudo ./scripts/setup/03-setup-opaque-keys.sh`  
**Dependencies**: Directories  
**Creates**: OPAQUE server private/public keys

#### `04-setup-jwt-keys.sh`
**Purpose**: Generate JWT signing keys  
**Usage**: `sudo ./scripts/setup/04-setup-jwt-keys.sh`  
**Dependencies**: Directories  
**Creates**: JWT signing keys with rotation capability

#### `05-setup-tls-certs.sh`
**Purpose**: Generate TLS certificates  
**Usage**: `sudo ./scripts/setup/05-setup-tls-certs.sh`  
**Dependencies**: Directories  
**Creates**: Self-signed TLS certificates

#### `06-setup-database.sh`
**Purpose**: Set up database schema  
**Usage**: `sudo ./scripts/setup/06-setup-database.sh`  
**Dependencies**: Database service running  
**Creates**: Database tables and indexes

#### `07-setup-minio.sh`
**Purpose**: Configure MinIO object storage  
**Usage**: `sudo ./scripts/setup/07-setup-minio.sh`  
**Dependencies**: Directories  
**Creates**: MinIO configuration and systemd service

#### `08-setup-rqlite.sh`
**Purpose**: Configure rqlite database  
**Usage**: `sudo ./scripts/setup/08-setup-rqlite.sh`  
**Dependencies**: Directories  
**Creates**: rqlite configuration and systemd service

#### Other Setup Scripts

- **`build.sh`** - Build application binary
- **`deploy.sh`** - Deploy to production environment
- **`rollback.sh`** - Rollback to previous deployment
- **`uninstall.sh`** - Remove system installation

### Testing Scripts

#### `test-only.sh`
**Purpose**: Run comprehensive test suite  
**Usage**: `./scripts/testing/test-only.sh [--skip-performance] [--skip-golden]`  
**Tests**: Unit tests, integration tests, security tests

#### `test-wasm.sh`
**Purpose**: Test WebAssembly functionality  
**Usage**: `./scripts/testing/test-wasm.sh`  
**Tests**: WASM crypto functions, browser compatibility

#### `test-totp.sh`
**Purpose**: Test TOTP implementation  
**Usage**: `./scripts/testing/test-totp.sh`  
**Tests**: TOTP generation, validation, backup codes

#### `performance-benchmark.sh`
**Purpose**: Performance testing and benchmarking  
**Usage**: `./scripts/testing/performance-benchmark.sh`  
**Tests**: Crypto performance, file I/O, memory usage

#### `golden-test-preservation.sh`
**Purpose**: Format compatibility testing  
**Usage**: `./scripts/testing/golden-test-preservation.sh --validate`  
**Tests**: Backward compatibility, format integrity

#### `admin-integration-test.sh`
**Purpose**: Administrative integration tests  
**Usage**: `./scripts/testing/admin-integration-test.sh`  
**Tests**: Admin workflows, system integration

### Maintenance Scripts

#### `health-check.sh`
**Purpose**: System health monitoring  
**Usage**: `./scripts/maintenance/health-check.sh [--quick] [--foundation]`  
**Checks**: Services, keys, certificates, database

#### `security-audit.sh`
**Purpose**: Security auditing and validation  
**Usage**: `./scripts/maintenance/security-audit.sh`  
**Audits**: Permissions, keys, certificates, configurations

#### `backup-keys.sh`
**Purpose**: Backup cryptographic keys  
**Usage**: `./scripts/maintenance/backup-keys.sh`  
**Backs up**: OPAQUE keys, JWT keys, TLS certificates

#### `rotate-jwt-keys.sh`
**Purpose**: Rotate JWT signing keys  
**Usage**: `./scripts/maintenance/rotate-jwt-keys.sh`  
**Rotates**: JWT signing keys with graceful transition

#### `renew-certificates.sh`
**Purpose**: Renew TLS certificates  
**Usage**: `./scripts/maintenance/renew-certificates.sh`  
**Renews**: TLS certificates before expiration

#### `check-updates.sh`
**Purpose**: Check for system updates  
**Usage**: `./scripts/maintenance/check-updates.sh`  
**Checks**: Go modules, dependencies, security updates

#### `update-dependencies.sh`
**Purpose**: Update system dependencies  
**Usage**: `./scripts/maintenance/update-dependencies.sh`  
**Updates**: System packages, security patches

#### `update-go-deps.sh`
**Purpose**: Update Go modules  
**Usage**: `./scripts/maintenance/update-go-deps.sh [--patch|--minor|--major]`  
**Updates**: Go dependencies with semantic versioning

#### `validate-deployment.sh`
**Purpose**: Validate deployment integrity  
**Usage**: `./scripts/maintenance/validate-deployment.sh [--production]`  
**Validates**: Configuration, services, security

#### `validate-certificates.sh`
**Purpose**: Validate TLS certificates  
**Usage**: `./scripts/maintenance/validate-certificates.sh`  
**Validates**: Certificate validity, chains, expiration

#### `admin-validation-guide.sh`
**Purpose**: Interactive admin validation  
**Usage**: `./scripts/maintenance/admin-validation-guide.sh`  
**Guides**: Manual testing, browser validation

#### `download-minio.sh`
**Purpose**: Download MinIO binaries  
**Usage**: `./scripts/maintenance/download-minio.sh`  
**Downloads**: Latest MinIO server and client

#### `emergency-procedures.sh`
**Purpose**: Emergency response procedures  
**Usage**: `./scripts/maintenance/emergency-procedures.sh`  
**Provides**: Service recovery, key restoration

## Usage Patterns

### New Installation
```bash
# Quick setup (recommended)
./scripts/quick-start.sh

# Or with testing
./scripts/complete-setup-test.sh
# Type "COMPLETE" when prompted
```

### Manual Setup
```bash
# Foundation first
./scripts/setup/00-setup-foundation.sh

# Then services
sudo ./scripts/setup/07-setup-minio.sh
sudo ./scripts/setup/08-setup-rqlite.sh

# Start services
sudo systemctl start arkfile
```

### Testing
```bash
# Run all tests
./scripts/testing/test-only.sh

# Performance testing
./scripts/testing/performance-benchmark.sh

# WebAssembly tests
./scripts/testing/test-wasm.sh
```

### Maintenance
```bash
# Health check
./scripts/maintenance/health-check.sh

# Security audit
./scripts/maintenance/security-audit.sh

# Backup keys
./scripts/maintenance/backup-keys.sh

# Check for updates
./scripts/maintenance/check-updates.sh
```

## Environment Variables

Many scripts support environment variables for customization:

### Testing Scripts
- `SKIP_TESTS=1` - Skip test execution
- `SKIP_WASM=1` - Skip WebAssembly tests
- `SKIP_PERFORMANCE=1` - Skip performance benchmarks
- `SKIP_GOLDEN=1` - Skip golden test preservation

### Setup Scripts
- `SKIP_TLS=1` - Skip TLS certificate generation
- `SKIP_DOWNLOAD=1` - Skip MinIO downloads
- `FORCE_REBUILD=1` - Force rebuild components

## Script Dependencies

### Prerequisites
- Go 1.24.2+ (for building)
- Node.js (for WebAssembly tests)
- Python 3 (for some maintenance scripts)
- curl (for health checks)
- sudo access (for system setup)

### Internal Dependencies
1. **Foundation** → Users → Directories → Keys
2. **Services** → MinIO, rqlite (can be parallel)
3. **Testing** → Built application
4. **Maintenance** → Running services

## Error Handling

All scripts include comprehensive error handling:

- **Exit codes**: 0 = success, 1 = failure
- **Logging**: Detailed output with timestamps
- **Validation**: Pre-flight checks before operations
- **Cleanup**: Automatic cleanup on failure
- **Recovery**: Rollback capabilities where applicable

## Security Considerations

- Scripts requiring sudo clearly document why
- Cryptographic operations are logged but not key material
- Temporary files are securely cleaned up
- File permissions are strictly enforced
- Network operations are validated

## Getting Help

- Each script supports `--help` flag
- Error messages include suggested solutions
- Documentation references are provided
- Emergency procedures are documented

## Contributing

When adding new scripts:

1. Place in appropriate directory (setup/testing/maintenance)
2. Follow naming conventions (numbered for setup scripts)
3. Include comprehensive error handling
4. Add usage documentation
5. Update this guide

## Deprecated Scripts

Scripts in `deprecated/` are preserved for safety but should not be used:

- `first-time-setup.sh` - Use `quick-start.sh` instead
- `generate-keys.sh` - Use individual key setup scripts

These will be removed in a future version after confirming no dependencies exist.
