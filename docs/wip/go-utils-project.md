# Go Utilities Migration Project

## Overview

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

JWT key generation will use Go's crypto/rsa package to generate RSA keypairs with appropriate key sizes (minimum 2048 bits, preferably 4096 bits for long-term security). The keys will be stored in PEM format with proper file permissions (600 for private keys, 644 for public keys).

Key validation will include cryptographic verification that keys are mathematically valid, properly formatted, and have correct file permissions and ownership. The system will also support key backup and restore operations for disaster recovery scenarios.

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
