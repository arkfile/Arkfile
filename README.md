# Arkfile

*s3-style encrypted file sharing and backup*

## High-Level Architecture

### Components

1. **Client-Side**
   - Web interface for user interaction
   - WebAssembly (WASM) module for client-side encryption/decryption
   - JavaScript for WASM interaction and API calls

2. **Server-Side**
   - Go HTTP server (Echo framework)
   - JWT authentication
   - SQLite database with at-rest encryption
   - S3-compatible object storage (via MinIO client)

3. **External Services**
   - S3-compatible storage providers (Backblaze B2, Wasabi, or Vultr)
   - Caddy web server for TLS and reverse proxy

### Security Features

- Client-side encryption using quantum-resistant SHAKE-256 for key derivation
- Choice between account password or file-specific password for encryption
- SHA-256 checksums for file integrity verification
- Database encryption at rest
- Password hints stored separately from encrypted files
- JWT-based authentication
- TLS encryption for all traffic
- Strong password requirements with real-time strength validation

## Directory Structure

```
/opt/arkfile/
├── bin/                  # Application binaries
├── etc/                  # Configuration
│   ├── prod/             # Production configuration
│   └── test/             # Test configuration
├── var/
│   ├── lib/              # Application data
│   │   ├── prod/         # Production data
│   │   └── test/         # Test data
│   ├── log/              # Log files
│   └── run/              # Runtime files
├── webroot/              # Static files and WASM
└── releases/             # Versioned releases
    ├── YYYYMMDD_HHMMSS/  # Timestamped releases
    └── current -> ...    # Symlink to current release
```

## Service Users

The application uses dedicated service accounts for improved security:

- **arkadmin**: Main service account for application management
- **arkprod**: Production environment service account
- **arktest**: Test environment service account
- **arkfile**: Primary service group

## Key Files and Their Purposes

1. **`main.go`**
   - Application entry point
   - Server setup and routing
   - Middleware configuration

2. **`client/main.go`**
   - Client-side encryption/decryption logic
   - WASM-based file processing

3. **`handlers/handlers.go`**
   - HTTP request handlers
   - File upload/download logic
   - User authentication handlers

4. **`storage/minio.go`**
   - S3-compatible storage integration
   - File storage operations with multiple provider support

5. **`auth/jwt.go`**
   - JWT token generation and validation
   - Authentication middleware

6. **`database/database.go`**
   - Database connection setup
   - Schema creation
   - File metadata storage
   - Database encryption handling

7. **`crypto/database.go`**
   - Database encryption/decryption
   - NaCl/SecretBox implementation
   - Key management utilities

## Environment Variables

Environment-specific variables are stored in `/opt/arkfile/etc/<env>/secrets.env`:

```
# S3-Compatible Storage Configuration
STORAGE_PROVIDER=...  # backblaze, wasabi, or vultr
S3_ENDPOINT=...       # Required for Backblaze
S3_REGION=...         # Required for Wasabi/Vultr
S3_ACCESS_KEY_ID=... 
S3_SECRET_KEY=...
S3_BUCKET_NAME=...

# Other Configuration
JWT_SECRET=...
DB_ENCRYPTION_KEY=...
VULTR_API_KEY=...    # For Caddy DNS challenges
PROD_PORT=...        # e.g. 8080
TEST_PORT=...        # e.g. 8081
CADDY_EMAIL=...
```

## Storage Provider Support

The application supports multiple S3-compatible storage providers:

1. **Backblaze B2**
   - Set `STORAGE_PROVIDER=backblaze`
   - Requires manual endpoint configuration
   - Server-side encryption included

2. **Wasabi**
   - Set `STORAGE_PROVIDER=wasabi`
   - Requires region configuration
   - Server-side encryption included
   - Note: 90-day minimum storage duration policy

3. **Vultr Object Storage**
   - Set `STORAGE_PROVIDER=vultr`
   - Requires region configuration
   - Server-side encryption included
   - Potential cost benefits when used with Vultr hosting

## Build and Deployment

1. **Initial Setup**
   ```bash
   # Setup service users and directories
   ./scripts/setup-users.sh
   ./scripts/setup-directories.sh

   # Generate encryption keys for environments
   ./scripts/generate-keys.sh
   ```

2. **Build Process**
   ```bash
   # Build for all environments
   ./scripts/build.sh
   ```

3. **Deployment**
   ```bash
   # Deploy to production
   ./scripts/deploy.sh prod

   # Deploy to test environment
   ./scripts/deploy.sh test
   ```

4. **Rollback (if needed)**
   ```bash
   # Rollback production
   ./scripts/rollback.sh prod

   # Rollback test environment
   ./scripts/rollback.sh test
   ```

## Deployment Features

- **Versioned Releases**: Each deployment creates a timestamped release
- **Zero-Downtime Deployments**: Smooth service transitions
- **Easy Rollbacks**: Quick recovery from problematic deployments
- **Environment Isolation**: Separate prod/test configurations
- **Release Management**: Maintains last 5 releases for safety

## Security Layers

1. **Transport Security**
   - TLS via Caddy
   - HTTPS enforcement

2. **Data Security**
   - Zero-knowledge client-side encryption for files using:
     - Quantum-resistant SHAKE-256 for key derivation (10,000 iterations)
     - Version byte for future cryptographic agility
     - SHA-256 checksums for integrity verification
   - Choice between account-based or file-specific passwords
   - Database encryption at rest using NaCl/SecretBox
   - Password hints stored separately from encrypted files
   - Automatic encryption/decryption during service lifecycle

3. **Authentication**
   - JWT-based auth
   - Secure password storage

4. **Authorization**
   - File access control
   - User permissions

5. **Service Security**
   - Dedicated service accounts
   - Principle of least privilege
   - Systemd security directives
   - Environment isolation

## Key Management

1. **Encryption Keys**
   - Each environment requires unique encryption keys
   - Generate keys using `./scripts/generate-keys.sh`
   - Store keys securely in environment-specific config files
   - Keys are 32-byte hex-encoded strings
   - Database automatically encrypted at shutdown and decrypted at startup

2. **Key Security**
   - Never reuse keys between environments
   - Store backups of keys securely
   - Rotate keys periodically (requires database re-encryption)
   - Keys are required for database access
   - Loss of keys makes database unrecoverable

3. **Environment Separation**
   - Production and test environments use separate keys
   - Each environment has its own encrypted database
   - Keys stored in environment-specific secret files
   - Different service users for different environments

## Monitoring and Maintenance

1. **Service Management**
   ```bash
   # Check service status
   systemctl status arkfile@prod
   systemctl status arkfile@test

   # View logs
   journalctl -u arkfile@prod -f
   journalctl -u arkfile@test -f
   ```

2. **Release Management**
   - Releases are automatically cleaned up (keeping last 5)
   - Each release is versioned and timestamped
   - Rollback markers track deployment history

3. **Database Management**
   - Databases are automatically encrypted at shutdown
   - Only decrypted while service is running
   - Encrypted databases have .enc extension
   - Each environment maintains separate encrypted database

---

## Support & Security

For questions, comments or support, either file an issue on GitHub, or during alpha testing stage, you can email `arkfile [at] pm [dot] me`.

For security issues, please email first and allow time to review the findings before creating a GitHub issue: `arkfile [at] pm [dot] me`.

(Do not include sensitive or personal information in any public GitHub issue.)

---

*make yourself an ark of cypress wood*
