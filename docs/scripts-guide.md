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
│   ├── 06-setup-totp-keys.sh         # Generate TOTP keys
│   ├── 07-setup-minio.sh             # Configure MinIO storage
│   ├── 08-setup-rqlite.sh            # Configure rqlite database
│   ├── build-libopaque.sh            # Build libopaque library
│   ├── build.sh                      # Build application
│   ├── deploy.sh                     # Deploy to production
│   └── uninstall.sh                  # Remove system installation
├── dev-reset.sh                      # Development environment reset
├── testing/                          # Testing and validation scripts
│   ├── admin-auth-test.sh            # Admin OPAQUE authentication + TOTP tests
│   ├── test-app-curl.sh              # Comprehensive application testing
│   ├── alpine-build-test.sh          # Alpine Linux compatibility testing
│   ├── security-test-suite.sh        # Consolidated security testing
│   ├── test-credits-system.sh        # Credits system testing
│   ├── test-share-workflow-complete.sh # Share workflow testing
│   ├── test-typescript.sh            # TypeScript testing suite
│   └── totp-generator.go             # Helper utility for TOTP (2FA) testing
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

#### `06-setup-totp-keys.sh`
**Purpose**: Generate TOTP master keys for 2FA functionality  
**Usage**: `sudo ./scripts/setup/06-setup-totp-keys.sh`  
**Dependencies**: Directories  
**Creates**: TOTP master keys for backup code generation and validation

**Note**: Database schema setup is now handled automatically by the arkfile application using the unified schema approach. The application reads `database/unified_schema.sql` and creates all tables, indexes, and triggers on startup. No separate database setup script is needed.

#### `07-setup-minio.sh`
**Purpose**: Configure MinIO object storage  
**Usage**: `sudo ./scripts/setup/07-setup-minio.sh`  
**Dependencies**: Directories  
**Creates**: MinIO configuration and systemd service

#### `08-setup-rqlite-build.sh`
**Purpose**: Build and configure rqlite database from source  
**Usage**: `sudo ./scripts/setup/08-setup-rqlite-build.sh`  
**Dependencies**: Directories, Go compiler  
**Creates**: rqlite binary (built from source), configuration, and systemd service

**Note**: This script builds rqlite from source to ensure compatibility and latest features. The older `08-setup-rqlite.sh` downloads pre-built binaries and is kept for compatibility but `08-setup-rqlite-build.sh` is now the recommended approach.

#### Other Setup Scripts

- **`build-libopaque.sh`** - Build libopaque cryptographic library with static linking support
- **`build.sh`** - Build application binary
- **`deploy.sh`** - Deploy to production environment
- **`uninstall.sh`** - Remove system installation

### Development Scripts

#### `dev-reset.sh`
**Purpose**: Reset development environment to clean state  
**Usage**: `./scripts/dev-reset.sh`  
**What it does**:
- Stops all Arkfile services
- Resets database to clean state
- Clears temporary files and logs
- Rebuilds application if needed
- Restarts services for fresh development session

### Testing Scripts

#### `admin-auth-test.sh`
**Purpose**: OPAQUE authentication and TOTP testing focused on admin functionality  
**Usage**: `./scripts/testing/admin-auth-test.sh`  
**Tests**: Admin registration, OPAQUE authentication, TOTP setup and validation

#### `test-app-curl.sh`
**Purpose**: Comprehensive application testing with OPAQUE authentication and TOTP  
**Location**: `./scripts/testing/test-app-curl.sh`  
**Usage**:
```bash
# Run full application test
./scripts/testing/test-app-curl.sh

# Debug mode  
./scripts/testing/test-app-curl.sh --debug
```

Tests complete user workflow: registration → TOTP setup → login → session management → cleanup.

#### `alpine-build-test.sh`
**Purpose**: Alpine Linux compatibility and static linking testing  
**Usage**: `./scripts/testing/alpine-build-test.sh [--clean] [--rebuild]`  
**Tests**: 
- Alpine Linux musl libc compatibility
- Static linking of libopaque with musl
- CGO compilation in Alpine environment
- Binary portability across distributions

**What it does**:
- Creates Alpine Linux container environment
- Builds static-linked arkfile binary
- Tests OPAQUE functionality in musl environment
- Validates cross-platform compatibility

#### `security-test-suite.sh`
**Purpose**: Consolidated security testing (replaces 4 individual security scripts)  
**Usage**: `./scripts/testing/security-test-suite.sh`  
**Tests**:
- **Security Headers**: Content Security Policy, XSS protection, frame options
- **Password Validation**: Entropy checking, pattern detection, strength requirements
- **Rate Limiting**: Progressive backoff, share isolation, brute force protection
- **Timing Protection**: Consistent response times, side-channel prevention

**Features**:
- Comprehensive security validation in single script
- Detailed test results with color-coded output
- Performance metrics and timing analysis
- Automated pass/fail criteria with exit codes

#### `totp-generator.go`
**Purpose**: Generate production-compatible TOTP codes for automated testing  
**Location**: `scripts/testing/totp-generator.go`  
**Usage**: Compiled automatically by master authentication script when needed

**Compilation & Command Line Usage**:
```bash
# Compile 
cd scripts/testing
go build -o totp-generator totp-generator.go

# Generate TOTP code for current time
./totp-generator JBSWY3DPEHPK3PXP

# Generate TOTP code for specific timestamp  
./totp-generator JBSWY3DPEHPK3PXP 1640995200

# Example with production-style secret
./totp-generator GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

#### `test-typescript.sh`
**Purpose**: Comprehensive TypeScript testing suite  
**Usage**: `./scripts/testing/test-typescript.sh [option]`  
**Options**:
- `type-check` - Run TypeScript type checking only
- `build` - Run build tests only
- `unit` - Run unit tests only
- `integration` - Run integration tests only
- `help` - Show help message
**Tests**: TypeScript compilation, Bun testing, build validation
**Prerequisites**: Bun runtime installed for client-side testing


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

#### `rotate-opaque-keys.sh` **OPAQUE KEY ROTATION** (WIP)
**Purpose**: Rotate OPAQUE server keys with user migration support  
**Location**: `./scripts/maintenance/rotate-opaque-keys.sh`  
**Rotates**: OPAQUE server keys; may require users to re-register(!)

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
sudo ./scripts/setup/08-setup-rqlite-build.sh

# Start services
sudo systemctl start arkfile
```

### Testing
```bash
# Comprehensive application testing
./scripts/testing/test-app-curl.sh

# Security testing suite
./scripts/testing/security-test-suite.sh

# Alpine Linux compatibility
./scripts/testing/alpine-build-test.sh

# TypeScript testing
./scripts/testing/test-typescript.sh
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
- `SKIP_PERFORMANCE=1` - Skip performance benchmarks
- `SKIP_GOLDEN=1` - Skip golden test preservation

### Setup Scripts
- `SKIP_TLS=1` - Skip TLS certificate generation
- `SKIP_DOWNLOAD=1` - Skip MinIO downloads
- `FORCE_REBUILD=1` - Force rebuild components

## Script Dependencies

### Prerequisites
- Go 1.26.0+ (for building)
- Bun (for WebAssembly tests and TypeScript compilation)
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
