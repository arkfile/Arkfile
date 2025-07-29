# Go Utilities Migration Project

## JWT Algorithm Migration to EdDSA/Ed25519

### Overview

Before implementing the Go utilities migration, Arkfile will undergo a critical security upgrade by migrating from HMAC-SHA256 (HS256) JWT tokens to EdDSA with Ed25519 signatures. This migration addresses fundamental security limitations of symmetric key JWT implementations and establishes a modern, auditable cryptographic foundation.

### Current State Analysis

**Current Implementation:**
- **Algorithm**: `jwt.SigningMethodHS256` (HMAC-SHA256)
- **Key Type**: Symmetric shared secret stored in `config.Security.JWTSecret`
- **Key Material**: Environment variable string converted to byte array
- **Security Issues**: Key distribution problems, algorithm confusion vulnerabilities, lack of proper key rotation

**Target Implementation:**
- **Algorithm**: `jwt.SigningMethodEdDSA` (Ed25519 signatures)
- **Key Type**: Asymmetric Ed25519 keypairs (32-byte private + 32-byte public keys)
- **Key Material**: PEM-encoded keys with 600 permissions, owned by `arkfile` user
- **Security Benefits**: No key distribution issues, immune to timing attacks, smallest signature size, fastest verification

### Migration Strategy

#### Phase 1: Core JWT Infrastructure Migration

**Key Generation System:**
- Generate Ed25519 keypairs using `crypto/ed25519.GenerateKey(crypto/rand.Reader)` 
- Leverage `/dev/urandom` through Go's `crypto/rand` package for cryptographically secure key generation
- Store keys in PEM format at `/opt/arkfile/etc/keys/jwt/private.pem` and `public.pem`
- Set file permissions to 600 for private keys, 644 for public keys, owned by `arkfile` user

**Application Code Updates:**
```go
// Current implementation:
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
return token.SignedString([]byte(config.GetConfig().Security.JWTSecret))

// New implementation:
token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
return token.SignedString(privateKey) // Ed25519 private key
```

**Backward Compatibility:**
- Dual-algorithm support during transition period
- Token validation accepts both HS256 and EdDSA during migration
- Gradual rollout with token refresh triggering algorithm migration
- Complete cutover after all active tokens expire (24-hour window)

#### Phase 2: Automated Key Rotation System

**Rotation Schedule:**
- **Recommended Interval**: 60 days (optimal balance of security and operational overhead)
- **Alternative Options**: 30 days (high-security environments) or 90 days (lower-risk scenarios)
- **Implementation**: Automated scheduling via systemd timers or Go-based cron system

**Key Rotation Process:**
1. **Pre-rotation Validation**: Verify current key integrity and system health
2. **Backup Creation**: Create encrypted backup of current keys with separate master key
3. **New Key Generation**: Generate fresh Ed25519 keypair using secure random generation
4. **Atomic Replacement**: Replace keys with minimal service downtime (< 1 second)
5. **Service Restart**: Graceful restart of arkfile service to load new keys
6. **Validation**: Comprehensive post-rotation testing and health verification
7. **Cleanup**: Archive old keys and update rotation logs

**Dual-Key Transition Support:**
- Maintain both old and new public keys during transition period
- Sign new tokens with new private key
- Validate existing tokens with appropriate public key (based on token metadata)
- Automatic migration of user sessions during natural token refresh cycles

#### Phase 3: Encrypted Backup and Recovery

**Backup Encryption:**
- Use `golang.org/x/crypto/nacl/secretbox` for authenticated encryption of key backups
- Generate separate master key for backup encryption (stored securely outside key directory)
- Create tamper-evident backup metadata with checksums and timestamps
- Implement backup integrity verification procedures

**Backup Storage:**
- Local encrypted backups: `/opt/arkfile/backups/jwt-keys/`
- Backup retention: 30 days of daily backups, 12 months of monthly backups
- Compressed and encrypted backup archives with detailed manifest files
- Support for remote backup destinations (S3-compatible storage)

**Recovery Procedures:**
- Emergency key restoration from encrypted backups
- Rollback capabilities with service coordination
- Key validation and health checking post-recovery
- Detailed incident logging and audit trails

#### Phase 4: Security Monitoring and Compliance

**Key Health Monitoring:**
- Automated key age monitoring with configurable alert thresholds
- Cryptographic validation of key integrity (mathematical correctness)
- File permission and ownership verification
- Key usage analytics and anomaly detection

**Audit and Compliance:**
- Comprehensive logging of all key operations (generation, rotation, backup, recovery)
- Tamper-resistant audit logs suitable for compliance requirements
- Integration with existing security event logging system
- Detailed reporting for security audits and compliance frameworks

**Emergency Procedures:**
- Immediate key rotation capabilities for security incidents
- User session invalidation and forced re-authentication
- Incident response documentation and communication templates
- Post-incident key validation and system hardening verification

### Implementation Dependencies

**Required Packages (All FOSS):**
- `crypto/ed25519` - Ed25519 key generation and operations (Go standard library)
- `crypto/rand` - Cryptographically secure random number generation (uses `/dev/urandom`)
- `crypto/x509` - PEM encoding/decoding for key storage (Go standard library)
- `github.com/golang-jwt/jwt/v5` - JWT library with EdDSA support (already included)
- `golang.org/x/crypto/nacl/secretbox` - Authenticated encryption for backups (already included)

**No External Dependencies:**
- Pure Go implementation using standard library and existing dependencies
- No C libraries, external cryptographic tools, or proprietary components required
- Compatible with existing build system and deployment processes

### Integration with Go Utilities Migration

**Setup Utility Integration:**
- `cmd/arkfile-setup` will include Ed25519 key generation during initial installation
- Migration detection and automatic upgrade from HMAC to EdDSA during system setup
- Validation of key infrastructure as part of system health checks

**Admin Utility Integration:**
- `cmd/arkfile-admin` will provide comprehensive key rotation and management commands
- Automated scheduling and monitoring of key rotation operations
- Backup management and recovery procedures
- Emergency key rotation capabilities

**Cryptocli Integration:**
- Extend existing `cmd/cryptocli` with Ed25519 key validation and diagnostic tools
- Key health checking and cryptographic validation utilities
- Integration with overall cryptographic infrastructure management

### Timeline and Milestones

**Week 1-2: JWT Migration Preparation**
- Update `auth/jwt.go` to support dual-algorithm validation
- Implement Ed25519 key generation and PEM storage utilities
- Create backward compatibility layer for smooth transition

**Week 3-4: Key Rotation Infrastructure**
- Implement automated key rotation logic with atomic replacement
- Create encrypted backup and recovery systems
- Build key health monitoring and validation systems

**Week 5-6: Integration and Testing**
- Integrate JWT migration with Go utilities development
- Comprehensive testing across all supported environments
- Security validation and penetration testing of new key infrastructure

**Week 7: Deployment and Migration**
- Gradual rollout with dual-algorithm support
- Monitor migration progress and system health
- Complete cutover to EdDSA-only mode

### Success Metrics

**Security Improvements:**
- Elimination of symmetric key distribution vulnerabilities
- Reduction in JWT signature verification time (Ed25519 performance advantage)
- Enhanced audit capabilities with asymmetric key operations
- Improved compliance posture with modern cryptographic standards

**Operational Benefits:**
- Automated key rotation reducing manual security maintenance
- Encrypted backup system providing disaster recovery capabilities
- Comprehensive monitoring reducing security incident response time
- Integration with Go utilities providing unified management interface

## Bash Script Migration Overview

This document outlines the plan to migrate Arkfile's bash-based setup and maintenance scripts to Go utilities, reducing script complexity while improving reliability, maintainability, and user experience.

## Current State Analysis

The Arkfile project currently contains 33 bash scripts that handle setup, maintenance, and testing operations. The primary pain points include:

- Fragmented setup process across 8 numbered scripts (01-08)
- Complex error handling and state management in bash
- Frequent need for complete uninstall/reinstall cycles during development
- Scattered configuration management across multiple scripts
- Limited rollback and recovery capabilities

## Migration Strategy

The migration will create focused Go utilities while keeping bash scripts only for operations that are more appropriate in shell environments (systemd service management, package installation, simple file operations).

### Target Architecture

Three main Go utilities will replace the majority of bash functionality:

1. **`cmd/arkfile-setup`** - Installation, configuration, and system management
2. **`cmd/arkfile-admin`** - General system administration and maintenance
3. **`cmd/cryptocli`** - Cryptographic operations (already exists, keep focused)

## Primary Focus: cmd/arkfile-setup

### Purpose and Scope

The arkfile-setup utility will be a comprehensive installation and configuration management tool that replaces scripts 01-08, portions of the build script, and quick-start functionality. It will provide a unified interface for complete system lifecycle management.

### Core Architecture

#### Main Entry Point
File: `cmd/arkfile-setup/main.go`

The main entry point will implement a CLI interface with subcommands for different operations:

```go
// Main commands
install    // Fresh installation
reinstall  // Various reinstall strategies  
uninstall  // Complete system removal
status     // System health and component status
repair     // Fix specific issues without full reinstall
```

#### Package Structure

```
cmd/arkfile-setup/
├── main.go              // CLI interface and command routing
├── config/
│   ├── config.go        // Configuration management
│   ├── defaults.go      // Default settings and paths
│   └── validation.go    // Configuration validation
├── state/
│   ├── state.go         // Installation state tracking
│   ├── persistence.go   // State file management
│   └── migration.go     // State migration from bash scripts
├── system/
│   ├── users.go         // User and group management
│   ├── directories.go   // Directory structure creation
│   ├── permissions.go   // File permission management
│   └── services.go      // Systemd service management
├── build/
│   ├── build.go         // Main build orchestration
│   ├── typescript.go    // TypeScript compilation
│   ├── wasm.go          // WebAssembly generation
│   ├── golang.go        // Go binary building
│   └── libraries.go     // C library compilation
├── crypto/
│   ├── keys.go          // Key generation and management
│   ├── certificates.go  // TLS certificate generation
│   └── validation.go    // Cryptographic validation
├── database/
│   ├── database.go      // Database setup and schema
│   ├── migration.go     // Database migration handling
│   └── connectivity.go  // Database connection testing
└── install/
    ├── install.go       // Installation orchestration
    ├── reinstall.go     // Reinstallation strategies
    ├── uninstall.go     // Uninstallation handling
    └── recovery.go      // Error recovery and rollback
```

### Detailed Component Implementation

#### User and Group Management (system/users.go)

Replaces: `scripts/setup/01-setup-users.sh`

The user management component will handle creation and management of the arkfile system user and group. This will use Go's os/user package combined with exec.Command for system operations.

Key functions:
- `CreateArkfileUser()` - Create the arkfile user with proper settings
- `CreateArkfileGroup()` - Create the arkfile group
- `ValidateUserSetup()` - Verify user and group configuration
- `CleanupUsers()` - Remove users during uninstall

Implementation approach:
The function will first check if the user/group already exists using the os/user package. If creation is needed, it will use exec.Command to run useradd/groupadd with appropriate flags. Error handling will include checking for conflicting users, validating home directory settings, and ensuring proper shell configuration (/sbin/nologin for security).

The user creation will include validation of the user ID range to ensure it falls within system user ranges, proper group membership assignment, and home directory creation with correct ownership. The implementation will also handle edge cases like existing users with different configurations by providing options to update or abort.

#### Directory Structure Creation (system/directories.go)

Replaces: `scripts/setup/02-setup-directories.sh`

The directory management component will create the complete /opt/arkfile directory tree with proper permissions and ownership. This will use Go's os.MkdirAll, os.Chown, and os.Chmod functions.

Key functions:
- `CreateDirectoryStructure()` - Create all required directories
- `SetDirectoryPermissions()` - Apply correct permissions and ownership
- `ValidateDirectoryStructure()` - Verify directory setup
- `CleanupDirectories()` - Remove directories during uninstall

Implementation approach:
The directory creation will be handled through a structured approach using a directory specification that defines the complete tree structure with permissions and ownership requirements. Each directory will be created atomically with proper error handling and rollback capabilities.

The implementation will include comprehensive validation of the created directory structure, including permission verification, ownership checks, and accessibility testing. The system will support both creation and verification modes, allowing it to detect and repair directory structure issues.

#### Build System Integration (build/build.go)

Replaces: `scripts/setup/build.sh`

The build system will coordinate compilation of TypeScript, WebAssembly, Go binaries, and C libraries. This represents the most complex part of the migration due to the multiple build technologies involved.

Key functions:
- `BuildComplete()` - Orchestrate complete build process
- `BuildTypeScript()` - Handle TypeScript compilation via Bun
- `BuildWebAssembly()` - Generate WebAssembly modules
- `BuildGoBinary()` - Compile main Go application
- `BuildCLibraries()` - Compile libopaque and liboprf

Implementation approach:
The build orchestration will use a pipeline approach where each build step has defined inputs, outputs, and dependencies. The TypeScript compilation will shell out to Bun but provide better progress reporting and error handling. The WebAssembly generation will use the Go toolchain directly through exec.Command.

The C library compilation will initially continue to use the existing build-libopaque.sh script but with enhanced error handling and progress reporting from the Go wrapper. Future iterations may move this compilation into Go using cgo compilation approaches.

Version management and caching will be implemented to avoid unnecessary rebuilds. The system will track file checksums and build timestamps to determine when components need rebuilding, significantly improving development iteration time.

#### Cryptographic Key Management (crypto/keys.go)

Replaces: `scripts/setup/03-setup-opaque-keys.sh` and `scripts/setup/04-setup-jwt-keys.sh`

The key management component will generate and manage all cryptographic keys used by the system, including OPAQUE server keys, JWT signing keys, and key rotation capabilities.

Key functions:
- `GenerateOPAQUEKeys()` - Generate OPAQUE server keypair and OPRF seed
- `GenerateJWTKeys()` - Generate JWT signing keypair with rotation support
- `ValidateKeys()` - Verify key integrity and proper permissions
- `BackupKeys()` - Create secure key backups
- `RotateKeys()` - Handle key rotation with migration support

Implementation approach:
The OPAQUE key generation will use the same libopaque library that the main application uses, ensuring consistency and eliminating the current placeholder approach. The implementation will properly generate the server private key, derive the public key, and create the OPRF seed using cryptographically secure random number generation.

JWT key generation will use Go's crypto/ed25519 package to generate Ed25519 keypairs (32-byte private keys, 32-byte public keys) for optimal security and performance. The keys will be stored in PEM format with proper file permissions (600 for private keys, 644 for public keys).

Key validation will include cryptographic verification that keys are mathematically valid, properly formatted, and have correct file permissions and ownership. The system will also support key backup and restore operations for disaster recovery scenarios.

#### OPAQUE Key Rotation System (crypto/rotation.go)

Replaces: `scripts/maintenance/rotate-opaque-keys.sh`

The OPAQUE key rotation component represents one of the most critical security operations in the system, as it affects all user authentication. The current bash script is only a template with TODO placeholders - the Go implementation will provide the complete functionality.

Key functions:
- `ValidateCurrentOPAQUESetup()` - Verify existing key integrity and system state
- `AssessUserMigrationImpact()` - Analyze user base and estimate migration complexity
- `GenerateRotationPlan()` - Create detailed migration plan with timeline estimates
- `PerformKeyRotation()` - Execute rotation using selected strategy
- `MonitorMigrationProgress()` - Track user migration during transition period
- `RollbackRotation()` - Emergency rollback to previous key state

Migration Strategies:
The system will implement four distinct rotation strategies, each with different user impact and complexity levels:

**Dual-Key Transition Strategy**: Maintains both old and new OPAQUE keys simultaneously, allowing existing users to continue authenticating with old keys while new registrations use new keys. This strategy requires database schema modifications to track key versions per user and application changes to support multiple active key sets. Users can be migrated gradually during password changes or through prompted re-authentication flows.

**Versioned Migration Strategy**: Implements a comprehensive key versioning system where multiple key versions remain active with automatic migration triggers. This provides the smoothest user experience but requires the most complex implementation, including version compatibility checking, automatic migration during password changes, and comprehensive progress tracking.

**Breaking Change Strategy**: Immediately replaces old keys with new keys, requiring all users to re-register. This is the simplest implementation but most disruptive to users. It includes comprehensive user notification systems, clear re-registration instructions, and temporary account suspension with recovery procedures.

**Plan-Only Strategy**: Analyzes the current system state and generates detailed migration plans without making any changes. This allows administrators to understand the scope and complexity of rotation before committing to execution.

Implementation approach:
The rotation system will implement sophisticated state analysis that examines current key validity, user account states, recent authentication activity, and system health before recommending appropriate strategies. User impact assessment will query the database to count total registered users, identify recently active users (last 30 days), and calculate estimated migration timelines based on historical user activity patterns.

The backup system will create comprehensive snapshots including current OPAQUE keys, complete database exports with user authentication data, application configuration files, and detailed restoration instructions. Backup integrity will be verified through cryptographic checksums and test restoration procedures.

New key generation will use the same libopaque library as the main application, ensuring cryptographic compatibility and security standards. The implementation will generate cryptographically secure server private keys, derive corresponding public keys, create new OPRF seeds, and validate all generated keys through comprehensive testing procedures.

The dual-key transition implementation will modify the authentication system to maintain multiple active key sets, update database schemas to track key versions per user account, implement intelligent key selection logic during authentication, and provide seamless migration paths for existing users.

Database schema modifications will include new tables for key version tracking, user migration status, authentication attempt logging with key version information, and migration progress metrics. The system will support rollback of schema changes through comprehensive migration scripts.

User communication systems will generate email templates for affected users explaining the rotation process, create in-app notification systems with clear instructions, prepare comprehensive FAQ documentation addressing common rotation questions, and establish support procedures for users experiencing migration issues.

Migration monitoring will track user re-registration rates, authentication success/failure rates correlated with key versions, generate detailed progress reports for administrators, implement alerting for migration issues or performance problems, and provide completion estimates based on current migration velocity.

The rollback system will provide emergency recovery capabilities including restoration of original key files from verified backups, reversion of database schema changes through tested rollback scripts, service restart procedures with original key configurations, comprehensive user notification of rollback events, and detailed incident reporting for post-mortem analysis.

Testing procedures will include comprehensive validation of new keys through test authentication flows, performance impact assessment comparing old and new key operations, compatibility verification with the existing cryptographic stack, and extensive security testing to ensure rotation maintains system security properties.

Error handling will provide detailed diagnostic information for rotation failures, automatic retry logic for transient errors during migration, comprehensive logging of all rotation operations and state changes, and clear remediation guidance for administrators when manual intervention is required.

The system will maintain detailed audit logs throughout the rotation process, including all key generation and replacement operations, user migration events and status changes, authentication attempts during the transition period, and administrative actions taken during the rotation process. These logs will be tamper-resistant and suitable for security compliance requirements.

#### TLS Certificate Management (crypto/certificates.go)

Replaces: `scripts/setup/05-setup-tls-certs.sh`

The certificate management component will generate and manage TLS certificates for internal service communication and HTTPS endpoints.

Key functions:
- `GenerateCACertificate()` - Create Certificate Authority for internal use
- `GenerateServiceCertificates()` - Create certificates for arkfile, minio, rqlite
- `ValidateCertificates()` - Verify certificate validity and chains
- `RenewCertificates()` - Handle certificate renewal before expiration

Implementation approach:
The certificate generation will use Go's crypto/x509 and crypto/tls packages to create self-signed certificates without depending on external OpenSSL tools. The implementation will create a local Certificate Authority and use it to sign service certificates, providing better trust chain management.

Certificate parameters will include appropriate subject names, key usage extensions, validity periods, and subject alternative names for service certificates. The system will support both development certificates (self-signed) and integration with external Certificate Authorities for production deployments.

#### Database Setup and Management (database/database.go)

Replaces: `scripts/setup/06-setup-database.sh`

The database component will handle database schema creation, migration, and connectivity testing using the same database libraries as the main application.

Key functions:
- `CreateDatabaseSchema()` - Create all required tables and indexes
- `MigrateDatabase()` - Handle database schema migrations
- `TestDatabaseConnectivity()` - Verify database accessibility
- `BackupDatabase()` - Create database backups during maintenance

Implementation approach:
The database setup will connect to rqlite using the same connection logic as the main application, ensuring consistency in database access patterns. Schema creation will execute the SQL statements from the existing schema files but with better error handling and transaction management.

Database migration support will be built-in from the start, allowing future schema changes to be applied automatically during system updates. The system will track applied migrations and provide rollback capabilities where possible.

#### Service Configuration (system/services.go)

Replaces: `scripts/setup/07-setup-minio.sh` and `scripts/setup/08-setup-rqlite.sh`

The service management component will handle systemd service configuration, service file creation, and service lifecycle management.

Key functions:
- `ConfigureMinIOService()` - Set up MinIO object storage service
- `ConfigureRqliteService()` - Set up rqlite database service
- `ConfigureArkfileService()` - Set up main application service
- `ValidateServices()` - Verify service configuration and status

Implementation approach:
Service configuration will use template-based service file generation, allowing for customization of service parameters while maintaining consistent service file structure. The implementation will validate service configurations before installation and provide detailed error reporting for service issues.

The system will integrate with systemd through either D-Bus interfaces or direct systemctl command execution, providing programmatic control over service lifecycle operations. Service dependency management will ensure services start in the correct order.

### Reinstall Functionality

The reinstall capability addresses the frequent need to recover from installation issues without complete system removal and rebuilding. Multiple reinstall strategies will be implemented based on the scope of problems encountered.

#### Reinstall Strategies

**Soft Reinstall**: Preserves user data, databases, and cryptographic keys while rebuilding binaries and reconfiguring services. This strategy is appropriate when the issue is related to corrupted binaries or service configuration problems but the underlying data and security infrastructure is intact.

**Hard Reinstall**: Preserves only cryptographic keys and user data while rebuilding everything else, including service configurations, directories, and system users. This strategy handles more serious system corruption while avoiding the need to regenerate security-critical cryptographic material.

**Complete Reinstall**: Equivalent to uninstall followed by fresh installation, useful when the system is in an unknown state or when security-related components may be compromised. This provides a clean slate while offering the option to preserve user data backups.

**Selective Reinstall**: Allows rebuilding specific components based on automated system analysis or manual selection. This strategy provides the most efficient recovery by only rebuilding components that are actually problematic.

#### Implementation Approach

The reinstall system will implement sophisticated state detection that analyzes the current installation and determines what components need to be rebuilt or reconfigured. This analysis will include checking binary integrity, service status, key file validity, database connectivity, and configuration file consistency.

The state detection will create a detailed report of system health that can be used to recommend the appropriate reinstall strategy. For example, if the arkfile binary is missing but services and keys are intact, only the build and deployment steps need to be repeated. If database connectivity is broken but database files exist, only the database configuration needs to be reset.

Progress reporting during reinstall operations will provide detailed feedback about which components are being rebuilt and why. The system will maintain audit logs of reinstall operations to help identify recurring issues and improve system reliability.

#### State Management

Installation state will be tracked using a comprehensive JSON-based state file stored at `/opt/arkfile/var/setup-state/installation.json`. This file will contain:

- Completion status of each installation step with timestamps
- Configuration parameters used for each component
- Checksums of key files and binaries
- Service configuration hashes
- Database schema version information
- Build artifact metadata

The state management system will support several key capabilities:

**Resume Interrupted Installations**: If an installation is interrupted by system failure or user cancellation, the state file allows the system to resume from the last completed step rather than starting over.

**Configuration Drift Detection**: By maintaining checksums and configuration hashes, the system can detect when manual changes have been made to the installation and recommend appropriate corrective actions.

**Incremental Updates**: When system components are updated, only the components that have actually changed need to be rebuilt or reconfigured, significantly reducing update time.

**Rollback Support**: The state file maintains enough information to support rollback operations, allowing failed updates or configurations to be reverted to previous working states.

### Command-Line Interface

The command-line interface will follow established patterns from the existing cryptocli tool while providing comprehensive functionality for system management.

#### Main Commands

**install**: Performs fresh installation of the complete Arkfile system. This command will check for existing installations and either abort or offer to remove them before proceeding. The installation process will be fully automated but with comprehensive progress reporting and the ability to pause/resume if needed.

**reinstall**: Implements the various reinstall strategies described above. The command will include options for strategy selection (--soft, --hard, --complete, --selective) and will default to automatic strategy selection based on system analysis. Interactive mode will allow users to review the analysis and confirm the recommended strategy.

**uninstall**: Provides complete system removal with comprehensive cleanup. This will implement the functionality currently provided by the uninstall.sh script but with better user interaction, more thorough cleanup, and improved backup capabilities.

**status**: Shows detailed system health information including component status, service health, key validity, database connectivity, and configuration consistency. The output will be structured to provide both summary information and detailed diagnostic data.

**repair**: Provides targeted fixes for specific issues without requiring full reinstallation. This command will include automated repair capabilities for common issues like permission problems, service configuration errors, and missing files.

#### Command Options

Each command will support comprehensive options for customization and control:

**Verbosity Control**: Multiple levels of output detail from quiet operation to comprehensive debugging information.

**Dry-Run Mode**: Allows users to see what operations would be performed without actually making changes to the system.

**Configuration Overrides**: Command-line options to override default configuration values for custom installations.

**Force Options**: Ability to override safety checks and warnings when necessary for automated deployments or recovery scenarios.

**Backup Control**: Options to control when and how backups are created during installation and maintenance operations.

### Error Handling and Recovery

Error handling throughout the system will be significantly improved over the current bash scripts. Each operation will be wrapped in comprehensive error handling with detailed error messages, suggested remediation steps, and automatic rollback capabilities where possible.

#### Error Recovery Strategies

**Automatic Rollback**: When an installation step fails, the system will automatically attempt to rollback to the previous stable state. This includes removing partially created users, cleaning up partially created directory structures, and restoring previous service configurations.

**Incremental Retry**: For operations that may fail due to temporary conditions (network issues, service unavailability), the system will implement intelligent retry logic with exponential backoff and maximum retry limits.

**Error Analysis**: When errors occur, the system will attempt to analyze the error condition and provide specific guidance on resolution. This includes checking for common issues like insufficient permissions, missing dependencies, or conflicting installations.

**Recovery Assistance**: For errors that cannot be automatically resolved, the system will provide detailed diagnostic information and step-by-step recovery instructions tailored to the specific error condition.

#### Logging and Auditing

Comprehensive logging will be implemented at multiple levels:

**Operation Logs**: Detailed logs of all installation and maintenance operations with timestamps, user context, and operation results. These logs will be structured to support both human reading and automated analysis.

**Error Logs**: Comprehensive error logging with stack traces, system state information, and suggested remediation steps. Error logs will be correlated with operation logs to provide complete context for troubleshooting.

**Audit Logs**: Security-focused logs that track all system modifications, user operations, and access patterns. These logs will be tamper-resistant and suitable for compliance requirements.

**Debug Logs**: Detailed debugging information that can be enabled for troubleshooting complex issues. Debug logs will include internal state information, external command outputs, and timing information.

### Configuration Management

Configuration management will be centralized through a unified configuration system that eliminates the current scattered approach where settings are distributed across multiple bash scripts with inconsistent naming conventions.

#### Configuration Sources

The configuration system will support multiple sources with a defined precedence order:

1. **Command-line flags** - Highest priority for one-time overrides
2. **Environment variables** - For container and systemd integration
3. **Configuration files** - For persistent local customization
4. **Defaults** - Built-in defaults for standard installations

#### Configuration Structure

The configuration will be organized into logical sections:

**System Configuration**: User names, group names, base directories, file permissions, and ownership settings.

**Service Configuration**: Port numbers, service dependencies, startup options, and resource limits for arkfile, minio, and rqlite services.

**Security Configuration**: Key sizes, certificate validity periods, encryption parameters, and security policy settings.

**Build Configuration**: Compiler options, build targets, optimization levels, and artifact locations.

**Network Configuration**: Interface bindings, TLS settings, proxy configurations, and firewall integration.

## Secondary Focus: cmd/arkfile-admin

### Purpose and Scope

The arkfile-admin utility will handle ongoing system administration, maintenance operations, and monitoring tasks that occur after initial installation. This utility will complement arkfile-setup by providing operational tools for running systems.

### Core Architecture

#### Main Entry Point
File: `cmd/arkfile-admin/main.go`

The admin utility will implement a CLI interface focused on operational tasks:

```go
// Main commands
health        // System health monitoring and diagnostics
backup        // Backup operations for keys, database, and configuration
restore       // Restore operations from backups
rotate-keys   // Cryptographic key rotation (OPAQUE and JWT)
update        // System updates and dependency management
monitor       // Real-time system monitoring and alerting
audit         // Security auditing and compliance reporting
clean         // System cleanup and maintenance tasks
```

#### Package Structure

```
cmd/arkfile-admin/
├── main.go              // CLI interface and command routing
├── health/
│   ├── health.go        // System health checking
│   ├── diagnostics.go   // Diagnostic reporting
│   └── monitoring.go    // Real-time monitoring
├── backup/
│   ├── backup.go        // Backup orchestration
│   ├── keys.go          // Key backup operations
│   ├── database.go      // Database backup operations
│   └── restore.go       // Restore operations
├── rotation/
│   ├── rotation.go      // Key rotation orchestration
│   ├── opaque.go        // OPAQUE key rotation (from rotate-opaque-keys.sh)
│   ├── jwt.go           // JWT key rotation
│   └── certificates.go  // Certificate rotation
├── maintenance/
│   ├── update.go        // System updates
│   ├── cleanup.go       // System cleanup
│   └── optimization.go  // Performance optimization
└── audit/
    ├── audit.go         // Security auditing
    ├── compliance.go    // Compliance reporting
    └── logging.go       // Audit log management
```

### Key Administrative Components

#### Key Rotation Management (rotation/)

The rotation package will provide comprehensive key and certificate rotation capabilities for all cryptographic material used by Arkfile:

##### OPAQUE Key Rotation (rotation/opaque.go)

Replaces: `scripts/maintenance/rotate-opaque-keys.sh`

This component implements the complete functionality outlined in the rotate-opaque-keys.sh script, providing a production-ready key rotation system:

Key functions:
- `ValidateCurrentSetup()` - Comprehensive validation of current OPAQUE key infrastructure
- `AssessUserImpact()` - Database queries to count users and assess migration complexity
- `CreateRotationBackup()` - Complete system backup before rotation begins
- `GenerateNewKeys()` - Cryptographically secure new key generation
- `ExecuteRotationStrategy()` - Implementation of selected rotation strategy
- `MonitorProgress()` - Real-time migration progress tracking
- `HandleRollback()` - Emergency rollback procedures

The implementation will provide all four rotation strategies from the bash script with full functionality:

**Dual-Key Transition**: Complete implementation including database schema modifications, application updates to support multiple key versions, gradual user migration with progress tracking, and seamless fallback to old keys during transition.

**Versioned Migration**: Full key versioning system with automatic migration triggers, version compatibility checking, migration during password changes, and comprehensive progress tracking with completion estimates.

**Breaking Change**: Immediate key replacement with user notification systems, comprehensive re-registration procedures, temporary account suspension with recovery mechanisms, and detailed user communication workflows.

**Plan-Only**: Detailed analysis and planning without system changes, including user impact assessment, timeline estimation, resource requirement analysis, and comprehensive migration planning documentation.

##### JWT Key Rotation (rotation/jwt.go)

Replaces: `scripts/maintenance/rotate-jwt-keys.sh`

The JWT key rotation component provides secure rotation of EdDSA/Ed25519 JWT signing keys with minimal service disruption:

Key functions:
- `CheckKeyStatus()` - Analyze current JWT key age and recommend rotation timeline
- `CreateKeyBackup()` - Backup current JWT keys with timestamped archives
- `GenerateNewJWTKeys()` - Generate new Ed25519 keypairs using secure random generation
- `TestNewKeys()` - Validate new keys through test JWT signing operations
- `PerformAtomicRotation()` - Replace keys with minimal service downtime
- `RollbackKeys()` - Emergency rollback to previous key backup
- `ValidateRotation()` - Post-rotation verification and health checks

Implementation approach:
The JWT rotation system will implement sophisticated timing analysis that recommends rotation schedules based on key age (60-day rotation recommended as optimal balance, with warnings at 45 days and errors at 90 days). The system will provide automatic backup creation with compressed archives and detailed manifests for recovery procedures.

Key generation will use Ed25519 keypairs (32-byte private keys, 32-byte public keys) with comprehensive validation including cryptographic correctness verification, PEM format validation, and test JWT signing/verification to ensure keys work correctly before deployment.

The atomic rotation process will minimize service disruption by stopping the arkfile service briefly during key replacement, implementing proper file permissions (600 for private keys, 644 for public keys) and arkfile user ownership, and providing detailed progress reporting throughout the rotation process.

Rollback capabilities will support restoration from any timestamped backup, with automatic detection of the most recent backup if no specific timestamp is provided, and comprehensive verification that restored Ed25519 keys work correctly with the EdDSA JWT implementation.

**Migration from HMAC to EdDSA:**
The rotation system will include special migration logic to handle the transition from the current HMAC-SHA256 implementation to EdDSA/Ed25519, including dual-algorithm support during the transition period and automatic detection of which key type is currently in use.

##### Certificate Rotation (rotation/certificates.go)

Replaces: `scripts/maintenance/renew-certificates.sh`

The certificate rotation component handles TLS certificate renewal for all services with automated expiration monitoring:

Key functions:
- `CheckCertificateExpiry()` - Monitor certificate expiration across all services
- `PlanCertificateRenewal()` - Analyze which certificates need renewal and create execution plan
- `BackupCertificates()` - Create comprehensive backup of current certificate infrastructure
- `RenewCertificates()` - Generate new certificates using existing CA or create new CA if needed
- `RestartAffectedServices()` - Coordinate service restarts to use new certificates
- `ValidateRenewal()` - Post-renewal validation and health checking
- `RollbackCertificates()` - Emergency restoration from backups

Implementation approach:
The certificate renewal system will implement intelligent expiration monitoring with configurable warning thresholds (30 days default), supporting both individual certificate renewal and complete CA rotation when the CA certificate is expiring.

Certificate generation will support multiple algorithms (ECDSA preferred, RSA as fallback) with proper subject alternative names, key usage extensions, and validity periods. The system will maintain certificate metadata for tracking and provide detailed certificate information reporting.

Service coordination will handle the complex dependencies between certificate renewal and service restarts, ensuring services are restarted in the correct order (database first, then storage, then application), with health checking to verify services start correctly with new certificates.

Emergency rollback capabilities will restore entire certificate infrastructures from backups, with verification that all services can load the restored certificates correctly.

##### Emergency Key Rotation (rotation/emergency.go)

Replaces: Emergency rotation functionality from `scripts/maintenance/emergency-procedures.sh`

The emergency rotation component provides rapid key rotation capabilities for security incidents:

Key functions:
- `ExecuteEmergencyRotation()` - Rotate all cryptographic keys immediately
- `SuspendUserSessions()` - Invalidate all active user sessions and tokens
- `NotifyEmergencyRotation()` - Send emergency notifications to administrators and users
- `GenerateIncidentReport()` - Create detailed incident documentation
- `VerifySecurityPosture()` - Validate system security after emergency rotation

Implementation approach:
Emergency rotation will provide rapid replacement of all cryptographic material (OPAQUE keys, JWT keys, and TLS certificates) in a coordinated sequence that maintains system security while minimizing service disruption.

The system will implement automatic user session invalidation, requiring all users to re-authenticate after emergency rotation, with clear notification of the security event and instructions for users.

Incident reporting will generate comprehensive documentation of the emergency rotation event, including timelines, actions taken, services affected, and post-incident verification results.

### Complete Key Rotation Coverage Analysis

Based on the analysis of existing scripts and the security requirements of Arkfile, the Go utilities plan provides comprehensive coverage of all necessary key rotation functions:

#### Covered Key Types and Rotation Scenarios

**1. OPAQUE Server Keys** - Fully covered with sophisticated migration strategies
- Server private/public keypair rotation
- OPRF seed rotation
- User migration coordination
- Database schema modifications for key versioning

**2. JWT Signing Keys** - Complete implementation with production-ready features
- RSA keypair rotation with configurable key sizes
- Atomic rotation with minimal service downtime
- Backup and rollback capabilities
- Integration with service restart procedures

**3. TLS Certificates** - Comprehensive certificate lifecycle management
- Certificate Authority rotation
- Service certificate renewal (arkfile, minio, rqlite)
- Automated expiration monitoring
- Service coordination for certificate deployment

**4. Emergency Rotation** - Coordinated rotation of all cryptographic material
- Simultaneous rotation of all key types
- User session invalidation
- Incident documentation and reporting

#### Additional Key Types Considered

After reviewing Arkfile's architecture and comparing with industry best practices, the following additional key types were evaluated but determined to be either not applicable or covered by existing categories:

**Database Encryption Keys**: Not currently used by Arkfile as rqlite handles encryption at the transport layer via TLS certificates (already covered).

**Storage Encryption Keys**: MinIO handles object encryption through its own key management system, with TLS certificates covering transport security (already covered).

**Session Encryption Keys**: Handled through JWT tokens with regular JWT key rotation (already covered).

**API Keys**: Not currently implemented in Arkfile's architecture, but would be covered by the general key rotation framework if added in the future.

**TOTP Secrets**: Individual user TOTP secrets are managed per-user and don't require system-wide rotation. The TOTP validation system uses standard libraries without system-wide keys.

#### Missing Components Identified and Added

During this analysis, one critical component was identified as missing from the original bash scripts but essential for production deployments:

**Automated Key Rotation Scheduling**: The Go utilities plan includes automated scheduling capabilities that are missing from the current bash script approach:
- Configurable rotation schedules based on key age
- Automated monitoring and alerting for key expiration
- Integration with system cron or systemd timers
- Automated backup verification and cleanup

This will be implemented in `cmd/arkfile-admin` with a `schedule` subcommand that can configure and monitor automated rotation schedules for all key types.

#### Security Best Practices Integration

The Go utilities plan incorporates security best practices that are missing from the current bash implementation:

**Key Derivation Function Updates**: While not requiring separate keys, the system should support updating KDF parameters (Argon2id settings) used for password hashing. This will be included in the security audit functionality.

**Cryptographic Algorithm Migration**: Support for migrating between cryptographic algorithms (e.g., RSA to ECDSA for certificates) will be included in the certificate rotation system.

**Hardware Security Module Integration**: Framework for future HSM integration for key storage, while maintaining compatibility with file-based key storage for development and smaller deployments.

#### Validation of Complete Coverage

The proposed Go utilities provide complete coverage of all cryptographic key rotation requirements for Arkfile:

✅ **User Authentication Keys**: OPAQUE keys with sophisticated migration strategies
✅ **Service Authentication Keys**: JWT keys with minimal-downtime rotation
✅ **Transport Security Keys**: TLS certificates with automated renewal
✅ **Emergency Security Response**: Coordinated rotation of all keys
✅ **Operational Continuity**: Backup, rollback, and recovery procedures
✅ **Compliance and Auditing**: Comprehensive logging and incident reporting
✅ **Automated Management**: Scheduling and monitoring capabilities

This represents a significant improvement over the current bash script approach, which has incomplete implementations (OPAQUE rotation is only a template) and lacks automation capabilities.

#### System Health Monitoring (health/health.go)

Comprehensive system health monitoring that goes beyond basic status checks:

Key functions:
- `CheckSystemHealth()` - Complete system health assessment
- `ValidateServices()` - Service status and configuration validation
- `TestConnectivity()` - Database and network connectivity testing
- `MonitorPerformance()` - Performance metrics collection and analysis
- `GenerateHealthReport()` - Detailed health reporting with recommendations
- `AlertOnIssues()` - Automated alerting for critical issues

The implementation will provide detailed diagnostics for all system components, performance monitoring with baseline comparisons, predictive maintenance recommendations, and integration with external monitoring systems.

#### Backup and Restore Operations (backup/backup.go)

Comprehensive backup and restore capabilities for operational continuity:

Key functions:
- `CreateSystemBackup()` - Complete system state backup
- `BackupCryptographicKeys()` - Secure key backup with encryption
- `BackupDatabase()` - Database backup with consistency verification
- `BackupConfiguration()` - Configuration file backup and versioning
- `RestoreFromBackup()` - Complete system restoration procedures
- `ValidateBackups()` - Backup integrity verification

The implementation will support automated backup scheduling, incremental backup strategies, encrypted backup storage, remote backup destinations, and comprehensive restore testing.

### Integration and Migration

The migration from bash scripts to Go utilities will be designed to maintain compatibility with existing installations while providing a smooth transition path.

#### Backward Compatibility

The system will detect installations created by the existing bash scripts and automatically migrate them to the new state management system. This includes:

**State Detection**: Analyzing existing installations to determine their current state and configuration.

**Configuration Migration**: Converting bash script variables and configurations to the new unified configuration format.

**Key Preservation**: Ensuring that existing cryptographic keys are properly integrated into the new key management system.

**Service Integration**: Adopting existing systemd services and configurations into the new service management framework.

#### Migration Strategy

The migration will be implemented as a non-destructive process that preserves all existing functionality while adding the benefits of the new system:

**Gradual Migration**: Components can be migrated individually, allowing for testing and validation at each step.

**Rollback Capability**: The ability to rollback to bash script management if issues are encountered during migration.

**Parallel Operation**: During the transition period, both bash scripts and Go utilities can coexist, allowing for gradual adoption.

**Validation**: Comprehensive validation that the migrated system provides identical functionality to the original bash script installation.

### Testing Strategy

Comprehensive testing will be implemented to ensure the Go utilities provide reliable operation across different environments and installation scenarios.

#### Unit Testing

Individual components will have comprehensive unit tests covering:

**Component Functionality**: All major functions within each package will have complete test coverage.

**Error Conditions**: Tests for all error conditions and edge cases to ensure proper error handling.

**Configuration Validation**: Tests for configuration parsing, validation, and error reporting.

**State Management**: Tests for state file operations, corruption recovery, and concurrent access handling.

#### Integration Testing

End-to-end testing will validate complete installation workflows:

**Fresh Installation**: Complete installation testing in clean environments using containerized testing platforms.

**Reinstall Scenarios**: Testing all reinstall strategies with various system corruption scenarios.

**Migration Testing**: Validation that bash script installations can be successfully migrated to Go utility management.

**Service Integration**: Testing integration with systemd, database systems, and external services.

#### Compatibility Testing

Testing will ensure compatibility across different environments:

**Operating System Variations**: Testing on different Linux distributions and versions.

**System Configuration Variations**: Testing with different system users, directory layouts, and permission schemes.

**Hardware Variations**: Testing on different hardware platforms and resource constraints.

**Network Variations**: Testing with different network configurations, firewall settings, and proxy environments.

### Implementation Timeline

The implementation will be structured in phases to provide incremental value while maintaining system stability.

#### Phase 1: Core Infrastructure (Weeks 1-3)

**Project Setup**: Create the cmd/arkfile-setup project structure with basic CLI framework.

**Configuration System**: Implement the unified configuration management system.

**State Management**: Create the installation state tracking and persistence system.

**Basic Commands**: Implement basic status and validation commands for testing the infrastructure.

#### Phase 2: System Management (Weeks 4-6)

**User Management**: Implement the user and group creation functionality (replacing 01-setup-users.sh).

**Directory Management**: Implement the directory structure creation and validation (replacing 02-setup-directories.sh).

**Permission Management**: Implement comprehensive permission and ownership management.

**Testing**: Complete unit and integration testing for system management components.

#### Phase 3: Cryptographic Components (Weeks 7-9)

**Key Generation**: Implement OPAQUE and JWT key generation (replacing 03-setup-opaque-keys.sh and 04-setup-jwt-keys.sh).

**Certificate Management**: Implement TLS certificate generation and management (replacing 05-setup-tls-certs.sh).

**Security Validation**: Implement cryptographic validation and security auditing capabilities.

**Testing**: Comprehensive security testing and validation of cryptographic components.

#### Phase 4: Service and Database Management (Weeks 10-12)

**Database Setup**: Implement database schema creation and migration (replacing 06-setup-database.sh).

**Service Configuration**: Implement minio and rqlite service setup (replacing 07-setup-minio.sh and 08-setup-rqlite.sh).

**Service Integration**: Implement systemd integration and service lifecycle management.

**Testing**: End-to-end testing of complete service stack.

#### Phase 5: Build System Integration (Weeks 13-15)

**Build Orchestration**: Implement the complete build system coordination (replacing build.sh).

**TypeScript Integration**: Implement TypeScript compilation integration with Bun.

**WebAssembly Integration**: Implement WebAssembly generation and deployment.

**C Library Integration**: Implement libopaque and liboprf compilation integration.

#### Phase 6: Installation and Reinstall (Weeks 16-18)

**Installation Orchestration**: Implement complete installation workflow coordination.

**Reinstall Strategies**: Implement all reinstall strategies (soft, hard, complete, selective).

**Uninstall Integration**: Implement comprehensive uninstall functionality.

**Migration Support**: Implement migration from bash script installations.

#### Phase 7: Testing and Documentation (Weeks 19-21)

**Comprehensive Testing**: Complete testing across all supported environments and scenarios.

**Documentation**: Complete user documentation, API documentation, and troubleshooting guides.

**Performance Optimization**: Optimize installation and reinstall performance.

**Security Audit**: Complete security review and penetration testing of the installation system.

### Success Metrics

The success of the migration will be measured against several key metrics:

**Script Reduction**: Reduce the number of bash scripts from 33 to approximately 8-10, with the majority of complex logic moved to Go.

**Installation Time**: Reduce fresh installation time by at least 30% through better parallelization and caching.

**Reinstall Efficiency**: Reduce reinstall time by 60-80% through selective component rebuilding and better state management.

**Error Recovery**: Achieve 95% automatic recovery rate for common installation issues through improved error handling and rollback capabilities.

**User Experience**: Improve user experience through better progress reporting, clearer error messages, and more reliable operation.

**Maintainability**: Improve code maintainability through unified codebase, comprehensive testing, and better documentation.

### Conclusion

The migration from bash scripts to Go utilities represents a significant improvement in the Arkfile installation and maintenance experience. By consolidating complex bash logic into well-structured Go code, the system will provide better reliability, maintainability, and user experience while significantly reducing the complexity of common operations like reinstallation and system recovery.

The phased implementation approach ensures that the migration can proceed incrementally with thorough testing at each stage, minimizing risk while providing immediate benefits as each phase is completed. The comprehensive state management and reinstall capabilities will address the current pain points around development iteration and system recovery, making Arkfile much more pleasant to work with during development and deployment.

The resulting system will provide a solid foundation for future enhancements while maintaining the security and reliability requirements that are critical for a file sharing and storage system handling sensitive user data.
